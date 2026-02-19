import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/exec.js', () => ({
  runCommand: vi.fn(),
}));

import { runCommand } from '../src/exec.js';
import { ensureCloudSwarmRepo } from '../src/upgrade-migrations.js';

const runCommandMock = vi.mocked(runCommand);

describe('ensureCloudSwarmRepo', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    runCommandMock.mockReset();
    for (const dir of tempDirs.splice(0, tempDirs.length)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('clones a missing checkout using the cloud-swarm deploy key SSH command', async () => {
    runCommandMock.mockResolvedValue({ code: 0, stdout: '', stderr: '' });

    const cloudSwarmDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-cloud-swarm-'));
    tempDirs.push(cloudSwarmDir);

    await ensureCloudSwarmRepo(cloudSwarmDir);

    expect(runCommandMock).toHaveBeenCalledTimes(1);
    const [command, args, timeout, options] = runCommandMock.mock.calls[0]!;
    expect(command).toBe('git');
    expect(args).toEqual(['clone', 'git@github.com:mage-zero/cloud-swarm.git', cloudSwarmDir]);
    expect(timeout).toBe(180_000);
    expect(options?.env?.GIT_SSH_COMMAND).toContain('ssh -i /opt/mage-zero/keys/cloud-swarm-deploy');
  });

  it('fetches existing checkouts from the configured SSH repo URL', async () => {
    runCommandMock.mockResolvedValue({ code: 0, stdout: '', stderr: '' });

    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-cloud-swarm-'));
    const cloudSwarmDir = path.join(root, 'repo');
    fs.mkdirSync(path.join(cloudSwarmDir, '.git'), { recursive: true });
    tempDirs.push(root);

    await ensureCloudSwarmRepo(cloudSwarmDir);

    expect(runCommandMock).toHaveBeenCalledTimes(2);
    const [fetchCommand, fetchArgs, fetchTimeout, fetchOptions] = runCommandMock.mock.calls[0]!;
    expect(fetchCommand).toBe('git');
    expect(fetchArgs).toEqual([
      '-C',
      cloudSwarmDir,
      'fetch',
      '--prune',
      'git@github.com:mage-zero/cloud-swarm.git',
      '+refs/heads/main:refs/remotes/origin/main',
    ]);
    expect(fetchTimeout).toBe(120_000);
    expect(fetchOptions?.env?.GIT_SSH_COMMAND).toContain('-o IdentitiesOnly=yes');

    const [checkoutCommand, checkoutArgs] = runCommandMock.mock.calls[1]!;
    expect(checkoutCommand).toBe('git');
    expect(checkoutArgs).toEqual(['-C', cloudSwarmDir, 'checkout', '-B', 'main', 'origin/main', '--force']);
  });
});
