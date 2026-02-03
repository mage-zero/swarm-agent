import { spawn } from 'child_process';

export type CommandResult = {
  code: number;
  stdout: string;
  stderr: string;
};

const DEFAULT_TIMEOUT_MS = Number(process.env.MZ_RUNBOOK_TIMEOUT_MS || 15000);

export function runCommand(command: string, args: string[], timeoutMs = DEFAULT_TIMEOUT_MS): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
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

