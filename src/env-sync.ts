import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import { readConfig } from './status.js';

type EnvironmentRecord = {
  environment_id?: number;
  name?: string;
  stack_id?: number;
  hostname?: string;
  db_backup_bucket?: string;
  media_bucket?: string;
};

type R2Credentials = {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  endpoint: string;
  region?: string;
};

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
const ENV_STATE_DIR = process.env.MZ_ENV_STATE_DIR || '/etc/magezero/env-sync';
const R2_CRED_DIR = process.env.MZ_R2_CRED_DIR || '/opt/mage-zero/r2';
const SYNC_INTERVAL_MS = Number(process.env.MZ_ENV_SYNC_INTERVAL_MS || 60000);

let cachedDockerApiVersion: string | null = null;
let cachedDockerApiVersionAt = 0;

function readNodeFile(filename: string) {
  try {
    return fs.readFileSync(`${NODE_DIR}/${filename}`, 'utf8').trim();
  } catch {
    return '';
  }
}

function ensureStateDir() {
  if (!fs.existsSync(ENV_STATE_DIR)) {
    fs.mkdirSync(ENV_STATE_DIR, { recursive: true });
  }
}

function ensureR2Dir() {
  if (!fs.existsSync(R2_CRED_DIR)) {
    fs.mkdirSync(R2_CRED_DIR, { recursive: true });
  }
}

function getR2CredPath(environmentId: number) {
  return `${R2_CRED_DIR}/env-${environmentId}.json`;
}

function writeR2CredFile(environmentId: number, backups: R2Credentials, media: R2Credentials) {
  ensureR2Dir();
  const payload = {
    environment_id: environmentId,
    backups,
    media,
    updated_at: new Date().toISOString(),
  };
  const target = getR2CredPath(environmentId);
  fs.writeFileSync(target, JSON.stringify(payload, null, 2), 'utf8');
  fs.chmodSync(target, 0o600);
}

function getEnvMarkerPath(environmentId: number) {
  return `${ENV_STATE_DIR}/env-${environmentId}-r2.done`;
}

function getEnvPendingPath(environmentId: number) {
  return `${ENV_STATE_DIR}/env-${environmentId}-r2.pending`;
}

function hasEnvMarker(environmentId: number): boolean {
  return fs.existsSync(getEnvMarkerPath(environmentId));
}

function hasEnvPending(environmentId: number): boolean {
  return fs.existsSync(getEnvPendingPath(environmentId));
}

function writeEnvMarker(environmentId: number) {
  ensureStateDir();
  fs.writeFileSync(getEnvMarkerPath(environmentId), `${new Date().toISOString()}\n`, 'utf8');
}

function writeEnvPending(environmentId: number) {
  ensureStateDir();
  fs.writeFileSync(getEnvPendingPath(environmentId), `${new Date().toISOString()}\n`, 'utf8');
}

function clearEnvMarker(environmentId: number) {
  try {
    fs.unlinkSync(getEnvMarkerPath(environmentId));
  } catch {
    // ignore
  }
}

function clearEnvPending(environmentId: number) {
  try {
    fs.unlinkSync(getEnvPendingPath(environmentId));
  } catch {
    // ignore
  }
}

function buildSignature(method: string, path: string, query: string, timestamp: string, nonce: string, body: string, secret: string) {
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

function buildNodeHeaders(method: string, path: string, query: string, body: string, nodeId: string, nodeSecret: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const signature = buildSignature(method, path, query, timestamp, nonce, body, nodeSecret);

  return {
    'X-MZ-Node-Id': nodeId,
    'X-MZ-Timestamp': timestamp,
    'X-MZ-Nonce': nonce,
    'X-MZ-Signature': signature,
  };
}

async function dockerRequest(method: string, path: string, body?: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath: DOCKER_SOCKET,
        path,
        method,
        headers: {
          Host: 'docker',
          Connection: 'close',
          ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}),
        },
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          if (!raw) {
            resolve(null);
            return;
          }
          try {
            resolve(JSON.parse(raw));
          } catch (err) {
            reject(err);
          }
        });
      },
    );

    req.on('timeout', () => req.destroy(new Error('Docker socket timeout')));
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

async function getDockerApiVersion(): Promise<string> {
  if (cachedDockerApiVersion && Date.now() - cachedDockerApiVersionAt < 5 * 60 * 1000) {
    return cachedDockerApiVersion;
  }

  const fallback = process.env.DOCKER_API_VERSION || 'v1.41';
  const normalizedFallback = fallback.startsWith('v') ? fallback : `v${fallback}`;

  try {
    const versionInfo = await dockerRequest('GET', '/version');
    if (versionInfo && versionInfo.ApiVersion) {
      cachedDockerApiVersion = `v${String(versionInfo.ApiVersion).replace(/^v/, '')}`;
      cachedDockerApiVersionAt = Date.now();
      return cachedDockerApiVersion;
    }
  } catch {
    // ignore
  }

  return normalizedFallback;
}

async function isSwarmManager(): Promise<boolean> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return false;
  }

  try {
    const info = await dockerRequest('GET', '/info');
    return Boolean(info?.Swarm?.ControlAvailable);
  } catch {
    // ignore and retry with versioned path
  }

  try {
    const apiVersion = await getDockerApiVersion();
    const info = await dockerRequest('GET', `/${apiVersion}/info`);
    return Boolean(info?.Swarm?.ControlAvailable);
  } catch {
    return false;
  }
}

async function listSecretNames(): Promise<Set<string>> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return new Set();
  }
  const apiVersion = await getDockerApiVersion();
  const response = await dockerRequest('GET', `/${apiVersion}/secrets`);
  const secrets = Array.isArray(response?.Secrets) ? response.Secrets : [];
  return new Set(secrets.map((secret: { Spec?: { Name?: string } }) => secret?.Spec?.Name).filter(Boolean));
}

async function createSecret(name: string, value: string, labels: Record<string, string>) {
  const apiVersion = await getDockerApiVersion();
  const payload = JSON.stringify({
    Name: name,
    Data: Buffer.from(value, 'utf8').toString('base64'),
    Labels: labels,
  });
  await dockerRequest('POST', `/${apiVersion}/secrets/create`, payload);
}

async function ensureSecret(name: string, value: string, labels: Record<string, string>, existing: Set<string>) {
  if (existing.has(name)) {
    return;
  }
  await createSecret(name, value, labels);
  existing.add(name);
}

async function fetchJson(baseUrl: string, path: string, method: string, body: string | null, nodeId: string, nodeSecret: string) {
  const url = new URL(path, baseUrl);
  const query = url.search ? url.search.slice(1) : '';
  const bodyPayload = body ?? '';
  const headers = buildNodeHeaders(method, url.pathname, query, bodyPayload, nodeId, nodeSecret);

  const response = await fetch(url.toString(), {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...headers,
    },
    body: bodyPayload || undefined,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`mz-control request failed: ${response.status} - ${errorBody}`);
  }

  return response.json() as Promise<any>;
}

async function syncEnvironmentCredentials() {
  const config = readConfig();
  const stackId = Number(config.stack_id ?? 0);
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');

  if (!stackId || !baseUrl || !nodeId || !nodeSecret) {
    return;
  }
  if (!(await isSwarmManager())) {
    return;
  }

  const envPayload = await fetchJson(
    baseUrl,
    `/v1/agent/stack/${stackId}/environments`,
    'GET',
    null,
    nodeId,
    nodeSecret,
  );
  const environments = Array.isArray(envPayload?.environments) ? envPayload.environments as EnvironmentRecord[] : [];
  if (!environments.length) {
    return;
  }

  const existingSecrets = await listSecretNames();

  for (const environment of environments) {
    const environmentId = Number(environment.environment_id ?? 0);
    if (!environmentId) {
      continue;
    }
    if (hasEnvPending(environmentId)) {
      continue;
    }

    const backupBucket = String(environment.db_backup_bucket ?? '').trim();
    const mediaBucket = String(environment.media_bucket ?? '').trim();
    if (!backupBucket || !mediaBucket) {
      continue;
    }

    const backupAccessName = `mz-env-${environmentId}-r2-backups-access-key`;
    const backupSecretName = `mz-env-${environmentId}-r2-backups-secret-key`;
    const mediaAccessName = `mz-env-${environmentId}-r2-media-access-key`;
    const mediaSecretName = `mz-env-${environmentId}-r2-media-secret-key`;

    const hasAllSecrets =
      existingSecrets.has(backupAccessName)
      && existingSecrets.has(backupSecretName)
      && existingSecrets.has(mediaAccessName)
      && existingSecrets.has(mediaSecretName);
    const hasCredFile = fs.existsSync(getR2CredPath(environmentId));

    if (hasAllSecrets && hasCredFile) {
      if (!hasEnvMarker(environmentId)) {
        writeEnvMarker(environmentId);
      }
      continue;
    }

    if (hasEnvMarker(environmentId)) {
      clearEnvMarker(environmentId);
    }

    writeEnvPending(environmentId);
    try {
      const creds = await fetchJson(
        baseUrl,
        `/v1/agent/environment/${environmentId}/r2-credentials`,
        'POST',
        JSON.stringify({ environment_id: environmentId }),
        nodeId,
        nodeSecret,
      ) as { backups?: R2Credentials; media?: R2Credentials };

      if (!creds?.backups || !creds?.media) {
        continue;
      }

      const labels = {
        'mz.environment_id': String(environmentId),
        'mz.stack_id': String(stackId),
        'mz.managed': 'true',
      };

      await ensureSecret(backupAccessName, creds.backups.accessKeyId, labels, existingSecrets);
      await ensureSecret(backupSecretName, creds.backups.secretAccessKey, labels, existingSecrets);
      await ensureSecret(mediaAccessName, creds.media.accessKeyId, labels, existingSecrets);
      await ensureSecret(mediaSecretName, creds.media.secretAccessKey, labels, existingSecrets);

      writeR2CredFile(environmentId, creds.backups, creds.media);
      writeEnvMarker(environmentId);
    } finally {
      clearEnvPending(environmentId);
    }
  }
}

export function startEnvironmentSync() {
  if (process.env.MZ_ENV_SYNC_ENABLED === '0') {
    return;
  }
  const intervalMs = Number.isFinite(SYNC_INTERVAL_MS) && SYNC_INTERVAL_MS > 0
    ? SYNC_INTERVAL_MS
    : 60000;

  void syncEnvironmentCredentials().catch(() => null);
  setInterval(() => {
    void syncEnvironmentCredentials().catch(() => null);
  }, intervalMs);
}
