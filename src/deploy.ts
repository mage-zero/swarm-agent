import crypto from 'crypto';
import fs from 'fs';
import { spawn, spawnSync } from 'child_process';
import { isSwarmManager } from './status.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_SCRIPT = process.env.MZ_DEPLOY_SCRIPT || '';
const CLOUD_SWARM_KEY_PATH = process.env.MZ_CLOUD_SWARM_KEY_PATH || '/opt/mage-zero/keys/cloud-swarm-deploy';
const MAX_SKEW_SECONDS = 300;
const NONCE_TTL_MS = 10 * 60 * 1000;

const nonceCache = new Map<string, number>();

type DeployPayload = {
  artifact?: string;
  stack_id?: number;
  environment_id?: number;
  repository?: string;
  ref?: string;
};

function readNodeFile(name: string) {
  try {
    return fs.readFileSync(`${NODE_DIR}/${name}`, 'utf8').trim();
  } catch {
    return '';
  }
}

function pruneNonceCache() {
  const now = Date.now();
  for (const [key, expiresAt] of nonceCache.entries()) {
    if (expiresAt <= now) {
      nonceCache.delete(key);
    }
  }
}

function buildSignature(
  method: string,
  path: string,
  query: string,
  timestamp: string,
  nonce: string,
  body: string,
  secret: string
) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [
    method.toUpperCase(),
    path,
    query,
    timestamp,
    nonce,
    bodyHash,
  ].join('\n');
  return crypto.createHmac('sha256', secret).update(stringToSign).digest('base64');
}

function timingSafeEquals(a: string, b: string) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function ensureQueueDir() {
  if (!fs.existsSync(DEPLOY_QUEUE_DIR)) {
    fs.mkdirSync(DEPLOY_QUEUE_DIR, { recursive: true });
  }
}

function enqueueDeployment(payload: DeployPayload, deploymentId: string) {
  ensureQueueDir();
  const target = `${DEPLOY_QUEUE_DIR}/${deploymentId}.json`;
  fs.writeFileSync(target, JSON.stringify({ id: deploymentId, queued_at: new Date().toISOString(), payload }, null, 2));
}

export async function handleDeployArtifact(c: { req: { raw: Request; header: (name: string) => string | undefined } }) {
  const validated = await validateRequest(c);
  if ('status' in validated) {
    return validated;
  }

  if (!(await isSwarmManager())) {
    return { status: 403, body: { error: 'not_manager' } } as const;
  }

  let payload: DeployPayload | null = null;
  try {
    const bodyText = await c.req.raw.clone().text();
    payload = JSON.parse(bodyText);
  } catch {
    payload = null;
  }

  const artifact = (payload?.artifact || '').trim();
  if (!artifact) {
    return { status: 400, body: { error: 'missing_artifact' } } as const;
  }

  const deploymentId = crypto.randomUUID();
  enqueueDeployment(payload ?? {}, deploymentId);

  if (DEPLOY_SCRIPT && fs.existsSync(DEPLOY_SCRIPT)) {
    spawn(DEPLOY_SCRIPT, [artifact], {
      stdio: 'ignore',
      detached: true,
      env: process.env,
    }).unref();
  }

  return {
    status: 202,
    body: {
      deployment_id: deploymentId,
      status: 'queued',
      artifact,
    },
  } as const;
}

export async function handleDeployKey(c: { req: { raw: Request; header: (name: string) => string | undefined } }) {
  const validated = await validateRequest(c);
  if ('status' in validated) {
    return validated;
  }

  if (!(await isSwarmManager())) {
    return { status: 403, body: { error: 'not_manager' } } as const;
  }

  const keyPath = CLOUD_SWARM_KEY_PATH;
  const pubPath = `${keyPath}.pub`;
  ensureQueueDir();

  if (!fs.existsSync(keyPath) || !fs.existsSync(pubPath)) {
    const dir = keyPath.split('/').slice(0, -1).join('/') || '.';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    spawnSync('ssh-keygen', ['-t', 'ed25519', '-a', '64', '-N', '', '-f', keyPath, '-C', 'mz-cloud-swarm'], {
      stdio: 'ignore',
    });
  }

  if (fs.existsSync(keyPath)) {
    fs.chmodSync(keyPath, 0o600);
  }

  const publicKey = fs.readFileSync(pubPath, 'utf8').trim();
  if (!publicKey) {
    return { status: 500, body: { error: 'missing_public_key' } } as const;
  }

  return {
    status: 200,
    body: { public_key: publicKey, key_path: keyPath },
  } as const;
}

async function validateRequest(c: { req: { raw: Request; header: (name: string) => string | undefined } }) {
  const request = c.req.raw;
  const nodeIdHeader = (c.req.header('X-MZ-Node-Id') || '').trim();
  const timestamp = (c.req.header('X-MZ-Timestamp') || '').trim();
  const nonce = (c.req.header('X-MZ-Nonce') || '').trim();
  const signature = (c.req.header('X-MZ-Signature') || '').trim();

  if (!timestamp || !nonce || !signature || !nodeIdHeader) {
    return { status: 401, body: { error: 'missing_hmac_headers' } } as const;
  }

  const nodeId = readNodeFile('node-id');
  if (!nodeId || nodeId !== nodeIdHeader) {
    return { status: 403, body: { error: 'invalid_node' } } as const;
  }

  const secret = readNodeFile('node-secret');
  if (!secret) {
    return { status: 500, body: { error: 'missing_node_secret' } } as const;
  }

  const timestampInt = Number.parseInt(timestamp, 10);
  if (!timestampInt || Math.abs(Date.now() / 1000 - timestampInt) > MAX_SKEW_SECONDS) {
    return { status: 401, body: { error: 'timestamp_out_of_range' } } as const;
  }

  pruneNonceCache();
  if (nonceCache.has(nonce)) {
    return { status: 409, body: { error: 'nonce_reused' } } as const;
  }
  nonceCache.set(nonce, Date.now() + NONCE_TTL_MS);

  const bodyText = await request.clone().text();
  const url = new URL(request.url);
  const expected = buildSignature(request.method, url.pathname, url.search.slice(1), timestamp, nonce, bodyText, secret);
  if (!timingSafeEquals(expected, signature)) {
    return { status: 401, body: { error: 'signature_invalid' } } as const;
  }

  return { ok: true } as const;
}
