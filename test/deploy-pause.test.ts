import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const originalEnv = { ...process.env };
const tempDirs: string[] = [];

describe('deploy pause controls', () => {
  afterEach(() => {
    process.env = { ...originalEnv };
    vi.resetModules();
    for (const dir of tempDirs.splice(0, tempDirs.length)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('writes and clears deploy pause marker using configured file path', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-deploy-pause-'));
    tempDirs.push(tempDir);
    const pauseFile = path.join(tempDir, 'meta', 'deploy-paused');

    process.env.MZ_DEPLOY_META_DIR = path.join(tempDir, 'meta');
    process.env.MZ_DEPLOY_PAUSE_FILE = pauseFile;

    const deployPause = await import('../src/deploy-pause.js');

    expect(deployPause.getDeployPauseFilePath()).toBe(pauseFile);
    expect(deployPause.isDeployPaused()).toBe(false);
    expect(deployPause.readDeployPausedAt()).toBeNull();

    const paused = deployPause.setDeployPaused(true);
    expect(paused.paused).toBe(true);
    expect(paused.path).toBe(pauseFile);
    expect(fs.existsSync(pauseFile)).toBe(true);
    expect(deployPause.isDeployPaused()).toBe(true);
    expect(deployPause.readDeployPausedAt()).toBe(paused.paused_at);

    const resumed = deployPause.setDeployPaused(false);
    expect(resumed).toEqual({ paused: false, paused_at: null, path: pauseFile });
    expect(deployPause.isDeployPaused()).toBe(false);
    expect(deployPause.readDeployPausedAt()).toBeNull();
  });

  it('returns null paused_at when marker file is unreadable or missing', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-deploy-pause-'));
    tempDirs.push(tempDir);
    const pauseFile = path.join(tempDir, 'meta', 'deploy-paused');

    process.env.MZ_DEPLOY_META_DIR = path.join(tempDir, 'meta');
    process.env.MZ_DEPLOY_PAUSE_FILE = pauseFile;

    const deployPause = await import('../src/deploy-pause.js');
    expect(deployPause.readDeployPausedAt()).toBeNull();
  });
});
