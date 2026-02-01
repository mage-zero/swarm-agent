import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { buildSignature } from './node-hmac.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_WORK_DIR = process.env.MZ_DEPLOY_WORK_DIR || path.join(DEPLOY_QUEUE_DIR, 'work');
const DEPLOY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_SKEW_SECONDS = 300;
const NONCE_TTL_MS = 10 * 60 * 1000;

const nonceCache = new Map<string, number>();

function readNodeFile(name: string): string {
  try {
    return fs.readFileSync(path.join(NODE_DIR, name), 'utf8').trim();
  } catch {
    return '';
  }
}

function timingSafeEquals(a: string, b: string) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function pruneNonceCache() {
  const now = Date.now();
  for (const [key, expiresAt] of nonceCache.entries()) {
    if (expiresAt <= now) {
      nonceCache.delete(key);
    }
  }
}

async function validateRequest(request: Request): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const nodeIdHeader = (request.headers.get('X-MZ-Node-Id') || '').trim();
  const timestamp = (request.headers.get('X-MZ-Timestamp') || '').trim();
  const nonce = (request.headers.get('X-MZ-Nonce') || '').trim();
  const signature = (request.headers.get('X-MZ-Signature') || '').trim();

  if (!timestamp || !nonce || !signature || !nodeIdHeader) {
    return { ok: false, status: 401, error: 'missing_hmac_headers' };
  }

  const nodeId = readNodeFile('node-id');
  if (!nodeId || nodeId !== nodeIdHeader) {
    return { ok: false, status: 403, error: 'invalid_node' };
  }

  const secret = readNodeFile('node-secret');
  if (!secret) {
    return { ok: false, status: 500, error: 'missing_node_secret' };
  }

  const timestampInt = Number.parseInt(timestamp, 10);
  if (!timestampInt || Math.abs(Date.now() / 1000 - timestampInt) > MAX_SKEW_SECONDS) {
    return { ok: false, status: 401, error: 'timestamp_out_of_range' };
  }

  pruneNonceCache();
  if (nonceCache.has(nonce)) {
    return { ok: false, status: 409, error: 'nonce_reused' };
  }
  nonceCache.set(nonce, Date.now() + NONCE_TTL_MS);

  const bodyText = await request.clone().text();
  const url = new URL(request.url);
  const expected = buildSignature(request.method, url.pathname, url.search.slice(1), timestamp, nonce, bodyText, secret);
  if (!timingSafeEquals(expected, signature)) {
    return { ok: false, status: 401, error: 'signature_invalid' };
  }

  return { ok: true };
}

export async function handleDeployLogsBundle(c: { req: { raw: Request; param: (name: string) => string } }) {
  const request = c.req.raw;
  const validated = await validateRequest(request);
  if (!validated.ok) {
    return { status: validated.status, body: { error: validated.error } } as const;
  }

  const deploymentId = String(c.req.param('deploymentId') || '').trim();
  if (!deploymentId || !DEPLOY_ID.test(deploymentId)) {
    return { status: 400, body: { error: 'invalid_deployment_id' } } as const;
  }

  const logDir = path.join(DEPLOY_WORK_DIR, deploymentId, 'logs');
  if (!fs.existsSync(logDir)) {
    return { status: 404, body: { error: 'logs_not_found', log_dir: logDir } } as const;
  }

  const files = fs.readdirSync(logDir).filter((name) => name.endsWith('.log'));
  if (!files.length) {
    return { status: 404, body: { error: 'logs_empty', log_dir: logDir } } as const;
  }

  // Stream a tar.gz of the logs directory.
  const filename = `deploy-${deploymentId}-logs.tar.gz`;
  const child = spawn('tar', ['-cz', '-C', logDir, '.'], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', () => {
    // best-effort; keep quiet to avoid noisy logs
  });

  const headers: Record<string, string> = {
    'Content-Type': 'application/gzip',
    'Content-Disposition': `attachment; filename=\"${filename}\"`,
    'X-MZ-Deployment-Id': deploymentId,
    'X-MZ-Log-Dir': logDir,
    'X-MZ-Log-File-Count': String(files.length),
    'X-MZ-Log-Nonce': crypto.randomUUID(),
  };

  return { status: 200, stream: child.stdout, headers } as const;
}

