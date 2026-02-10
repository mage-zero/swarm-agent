import fs from 'fs';
import path from 'path';
import { buildSignature } from './node-hmac.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_WORK_DIR = process.env.MZ_DEPLOY_WORK_DIR || path.join(DEPLOY_QUEUE_DIR, 'work');
const DEPLOY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RUNBOOK_ID = /^[a-z0-9][a-z0-9_-]{1,63}$/i;
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

function safeReadJson(filePath: string): { ok: true; data: Record<string, unknown> } | { ok: false; error: string } {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object') {
      return { ok: false, error: 'invalid_json' };
    }
    return { ok: true, data: parsed };
  } catch {
    return { ok: false, error: 'unreadable' };
  }
}

export async function handleDeployProgress(c: { req: { raw: Request; param: (name: string) => string } }) {
  const request = c.req.raw;
  const validated = await validateRequest(request);
  if (!validated.ok) {
    return { status: validated.status, body: { error: validated.error } } as const;
  }

  const deploymentId = String(c.req.param('deploymentId') || '').trim();
  if (!deploymentId || !DEPLOY_ID.test(deploymentId)) {
    return { status: 400, body: { error: 'invalid_deployment_id' } } as const;
  }

  const progressPath = path.join(DEPLOY_WORK_DIR, deploymentId, 'progress.json');
  if (!fs.existsSync(progressPath)) {
    return { status: 404, body: { error: 'progress_not_found', progress_path: progressPath } } as const;
  }

  const read = safeReadJson(progressPath);
  if (!read.ok) {
    return { status: 500, body: { error: 'progress_unreadable', progress_path: progressPath } } as const;
  }
  return { status: 200, body: { deployment_id: deploymentId, progress: read.data } } as const;
}

export async function handleRunbookProgress(c: { req: { raw: Request; query: (name: string) => string | undefined | null } }) {
  const request = c.req.raw;
  const validated = await validateRequest(request);
  if (!validated.ok) {
    return { status: validated.status, body: { error: validated.error } } as const;
  }

  const runbookId = String(c.req.query('runbook') || '').trim();
  if (!runbookId || !RUNBOOK_ID.test(runbookId)) {
    return { status: 400, body: { error: 'invalid_runbook' } } as const;
  }

  const environmentId = Number.parseInt(String(c.req.query('environment_id') || '0'), 10) || 0;
  const limitRaw = Number.parseInt(String(c.req.query('limit') || '1'), 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(10, Math.max(1, limitRaw)) : 1;
  const activeOnly = String(c.req.query('active_only') || '').trim() === '1';

  const scanRoots = [
    DEPLOY_WORK_DIR,
    path.join(DEPLOY_WORK_DIR, 'runbooks'),
  ];

  const runs: Array<Record<string, unknown>> = [];
  for (const root of scanRoots) {
    let entries: string[] = [];
    try {
      entries = fs.readdirSync(root);
    } catch {
      entries = [];
    }

    for (const deploymentId of entries) {
      if (!DEPLOY_ID.test(deploymentId)) continue;
      const progressPath = path.join(root, deploymentId, 'progress.json');
      if (!fs.existsSync(progressPath)) continue;

      const read = safeReadJson(progressPath);
      if (!read.ok) continue;
      const data = read.data;

      const fileRunbook = String((data as any)?.runbook_id || '').trim();
      if (!fileRunbook) continue;
      if (fileRunbook !== runbookId) continue;

      const fileEnvId = Number((data as any)?.environment_id ?? 0) || 0;
      if (environmentId && fileEnvId !== environmentId) continue;

      const status = String((data as any)?.status || '').trim();
      if (activeOnly && status !== 'running') continue;

      // Include the id we matched on, even if the file is missing it for some reason.
      (data as any).deployment_id = String((data as any).deployment_id || deploymentId);

      runs.push(data);
    }
  }

  runs.sort((a, b) => {
    const aUpdated = Date.parse(String((a as any)?.updated_at || '')) || 0;
    const bUpdated = Date.parse(String((b as any)?.updated_at || '')) || 0;
    return bUpdated - aUpdated;
  });

  return { status: 200, body: { runbook: runbookId, runs: runs.slice(0, limit) } } as const;
}
