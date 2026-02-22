import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { enforceCommandPolicy } from '../command-policy.js';

export type CommandOptions = { cwd?: string; env?: NodeJS.ProcessEnv };

export function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

export async function runCommand(command: string, args: string[], options: CommandOptions = {}) {
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommand' });
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: 'inherit',
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
      }
    });
  });
}

export async function runCommandLogged(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; logDir: string; label: string }
) {
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommandLogged' });
  ensureDir(options.logDir);
  const safeLabel = options.label.replace(/[^a-z0-9._-]/gi, '_');
  const stdoutPath = path.join(options.logDir, `${safeLabel}.stdout.log`);
  const stderrPath = path.join(options.logDir, `${safeLabel}.stderr.log`);
  const header = `\n# ${new Date().toISOString()} ${command} ${args.join(' ')}\n`;
  fs.appendFileSync(stdoutPath, header);
  fs.appendFileSync(stderrPath, header);

  await new Promise<void>((resolve, reject) => {
    const stdoutStream = fs.createWriteStream(stdoutPath, { flags: 'a' });
    const stderrStream = fs.createWriteStream(stderrPath, { flags: 'a' });
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => {
      stdoutStream.write(chunk);
      process.stdout.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrStream.write(chunk);
      process.stderr.write(chunk);
    });
    child.on('error', (error) => {
      stdoutStream.end();
      stderrStream.end();
      reject(error);
    });
    child.on('close', (code) => {
      stdoutStream.end();
      stderrStream.end();
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
      }
    });
  });
}

export async function runCommandLoggedWithRetry(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; logDir: string; label: string },
  retryOptions: {
    retries: number;
    log?: (message: string) => void;
    onRetry?: (attempt: number, error: Error) => Promise<void>;
  }
) {
  const maxAttempts = Math.max(1, 1 + retryOptions.retries);
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt += 1;
    try {
      await runCommandLogged(command, args, options);
      return;
    } catch (error) {
      if (attempt >= maxAttempts) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      retryOptions.log?.(`retrying ${options.label} (attempt ${attempt}/${maxAttempts - 1}) after error: ${message}`);
      if (retryOptions.onRetry && error instanceof Error) {
        await retryOptions.onRetry(attempt, error);
      }
    }
  }
}

export function readCommandLogTail(logDir: string, label: string, stream: 'stdout' | 'stderr', maxBytes = 128 * 1024): string {
  const safeLabel = label.replace(/[^a-z0-9._-]/gi, '_');
  const filePath = path.join(logDir, `${safeLabel}.${stream}.log`);
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw) return '';
    return raw.length > maxBytes ? raw.slice(raw.length - maxBytes) : raw;
  } catch {
    return '';
  }
}

export function detectMissingRegistryManifest(logDir: string, label: string): { matched: boolean; imageRef: string } {
  const stderrTail = readCommandLogTail(logDir, label, 'stderr');
  if (!stderrTail) {
    return { matched: false, imageRef: '' };
  }
  const hasManifestNotFound = /manifests\/sha256:[0-9a-f]{64}\s+not found/i.test(stderrTail);
  const hasResolveMetadataFailure = /failed to resolve source metadata for\s+.+?:\s+failed to copy/i.test(stderrTail);
  if (!hasManifestNotFound || !hasResolveMetadataFailure) {
    return { matched: false, imageRef: '' };
  }
  const imageMatch = stderrTail.match(/failed to resolve source metadata for\s+(.+?)(?::\s+failed to copy)/i);
  return {
    matched: true,
    imageRef: imageMatch?.[1]?.trim() || '',
  };
}

export async function runCommandCapture(command: string, args: string[], options: CommandOptions = {}) {
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommandCapture' });
  return await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${args.join(' ')} failed: ${stderr || stdout}`));
      }
    });
  });
}

export async function runCommandCaptureWithStatus(
  command: string,
  args: string[],
  options: CommandOptions = {},
) {
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommandCaptureWithStatus' });
  return await new Promise<{ stdout: string; stderr: string; code: number }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ stdout, stderr, code: typeof code === 'number' ? code : 0 });
    });
  });
}

export function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function generateSecretHex(bytes: number) {
  return crypto.randomBytes(bytes).toString('hex');
}
