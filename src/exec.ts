import fs from 'fs';
import { spawn } from 'child_process';
import { enforceCommandPolicy } from './command-policy.js';

export type CommandResult = {
  code: number;
  stdout: string;
  stderr: string;
};

const DEFAULT_TIMEOUT_MS = Number(process.env.MZ_RUNBOOK_TIMEOUT_MS || 15000);
type CommandOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
};

export function runCommand(
  command: string,
  args: string[],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  options: CommandOptions = {},
): Promise<CommandResult> {
  return new Promise((resolve) => {
    enforceCommandPolicy(command, args, { source: 'exec.runCommand' });
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: options.cwd,
      env: options.env,
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

export function runCommandToFile(
  command: string,
  args: string[],
  stdoutPath: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  options: CommandOptions = {},
): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    enforceCommandPolicy(command, args, { source: 'exec.runCommandToFile' });
    const stdoutStream = fs.createWriteStream(stdoutPath, { flags: 'w' });
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: options.cwd,
      env: options.env,
    });
    let stderr = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdoutStream.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      stdoutStream.end();
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      stdoutStream.end();
      resolve({ code: code ?? 1, stderr });
    });
  });
}
