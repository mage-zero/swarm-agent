import fs from 'fs';
import path from 'path';

const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_META_DIR = process.env.MZ_DEPLOY_META_DIR || path.join(DEPLOY_QUEUE_DIR, 'meta');
const DEPLOY_PAUSE_FILE = process.env.MZ_DEPLOY_PAUSE_FILE || path.join(DEPLOY_META_DIR, 'deploy-paused');

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

export function getDeployPauseFilePath() {
  return DEPLOY_PAUSE_FILE;
}

export function isDeployPaused(): boolean {
  return fs.existsSync(DEPLOY_PAUSE_FILE);
}

export function setDeployPaused(paused: boolean): { paused: boolean; paused_at: string | null; path: string } {
  ensureDir(DEPLOY_META_DIR);
  if (paused) {
    const pausedAt = new Date().toISOString();
    fs.writeFileSync(DEPLOY_PAUSE_FILE, `${pausedAt}\n`);
    return { paused: true, paused_at: pausedAt, path: DEPLOY_PAUSE_FILE };
  }
  try {
    fs.unlinkSync(DEPLOY_PAUSE_FILE);
  } catch {
    // ignore
  }
  return { paused: false, paused_at: null, path: DEPLOY_PAUSE_FILE };
}

export function readDeployPausedAt(): string | null {
  try {
    const raw = fs.readFileSync(DEPLOY_PAUSE_FILE, 'utf8').trim();
    return raw || null;
  } catch {
    return null;
  }
}

