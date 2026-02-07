import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { presignS3Url } from './r2-presign.js';
import { enforceCommandPolicy } from './command-policy.js';

type AddonDeployPayload = {
  stack_id?: number;
  environment_id?: number;
  repository?: string;
  ref?: string;
  slug?: string;
  artifact_key?: string;
  image_tag?: string;
};

type DeploymentRecord = {
  id?: string;
  queued_at?: string;
  payload?: AddonDeployPayload;
};

type R2Credentials = {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  endpoint: string;
  region?: string;
};

type R2CredFile = {
  environment_id?: number;
  backups?: R2Credentials;
  media?: R2Credentials;
  updated_at?: string;
};

type PlannerResourceSpec = {
  limits: { cpu_cores: number; memory_bytes: number };
  reservations: { cpu_cores: number; memory_bytes: number };
};

type StoredTuningProfilesLike = {
  base?: { updated_at?: string; created_at?: string; resources?: { services?: Record<string, PlannerResourceSpec> } };
  approved?: Array<{ updated_at?: string; created_at?: string; resources?: { services?: Record<string, PlannerResourceSpec> } }>;
};

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const TUNING_PROFILE_PATH = process.env.MZ_TUNING_PROFILE_PATH || `${NODE_DIR}/tuning-profiles.json`;
const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

const ADDON_QUEUE_DIR = process.env.MZ_ADDON_QUEUE_DIR || '/opt/mage-zero/addons';
const ADDON_WORK_DIR = process.env.MZ_ADDON_WORK_DIR || path.join(ADDON_QUEUE_DIR, 'work');
const R2_CRED_DIR = process.env.MZ_R2_CRED_DIR || '/opt/mage-zero/r2';
const SECRET_VERSION = process.env.MZ_SECRET_VERSION || '1';
const ADDON_INTERVAL_MS = Number(process.env.MZ_ADDON_WORKER_INTERVAL_MS || 5000);
const FETCH_TIMEOUT_MS = Number(process.env.MZ_ADDON_FETCH_TIMEOUT_MS || process.env.MZ_FETCH_TIMEOUT_MS || 10 * 60 * 1000);
const DOCKER_PUSH_TIMEOUT_MS = Number(process.env.MZ_DOCKER_PUSH_TIMEOUT_MS || 30 * 60 * 1000);
const DOCKER_LOAD_TIMEOUT_MS = Number(process.env.MZ_DOCKER_LOAD_TIMEOUT_MS || 10 * 60 * 1000);
const REGISTRY_HOST = process.env.REGISTRY_HOST || 'registry';
const REGISTRY_PORT = process.env.REGISTRY_PORT || '5000';
const REGISTRY_PUSH_HOST = process.env.REGISTRY_PUSH_HOST || '127.0.0.1';
const DEPLOY_RECORD_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i;

let processing = false;

const DEFAULT_ADDON_RESOURCES: PlannerResourceSpec = {
  limits: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
  reservations: { cpu_cores: 0.1, memory_bytes: 128 * MIB },
};

function log(message: string, meta: Record<string, unknown> = {}) {
  const payload = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
  console.log(`[addon-worker] ${message}${payload}`);
}

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function getProcessingDir() {
  return path.join(ADDON_QUEUE_DIR, 'processing');
}

function getCompletedDir() {
  return path.join(ADDON_QUEUE_DIR, 'completed');
}

function getFailedDir() {
  return path.join(ADDON_QUEUE_DIR, 'failed');
}

function listQueuedRecords(): string[] {
  if (!fs.existsSync(ADDON_QUEUE_DIR)) {
    return [];
  }
  const entries = fs.readdirSync(ADDON_QUEUE_DIR);
  const files = entries.filter((entry) => DEPLOY_RECORD_FILENAME.test(entry));
  return files
    .map((name) => ({ name, mtimeMs: fs.statSync(path.join(ADDON_QUEUE_DIR, name)).mtimeMs }))
    .sort((a, b) => a.mtimeMs - b.mtimeMs)
    .map((item) => item.name);
}

function moveToDir(filePath: string, dir: string) {
  ensureDir(dir);
  const base = path.basename(filePath);
  fs.renameSync(filePath, path.join(dir, base));
}

function readR2CredFile(environmentId: number): R2CredFile | null {
  try {
    const raw = fs.readFileSync(`${R2_CRED_DIR}/env-${environmentId}.json`, 'utf8');
    return JSON.parse(raw) as R2CredFile;
  } catch {
    return null;
  }
}

function parseIsoDate(value: unknown): number {
  if (typeof value !== 'string' || !value.trim()) {
    return 0;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function loadStoredTuningProfiles(): StoredTuningProfilesLike | null {
  try {
    if (!fs.existsSync(TUNING_PROFILE_PATH)) {
      return null;
    }
    const raw = fs.readFileSync(TUNING_PROFILE_PATH, 'utf8').trim();
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as StoredTuningProfilesLike;
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function resolveActiveProfileFromStored(stored: StoredTuningProfilesLike | null) {
  if (!stored) {
    return null;
  }
  const base = stored.base || null;
  const approved = Array.isArray(stored.approved) ? stored.approved : [];
  if (approved.length === 0) {
    return base;
  }
  const sorted = [...approved].sort((a, b) => {
    const aTime = parseIsoDate(a.updated_at) || parseIsoDate(a.created_at);
    const bTime = parseIsoDate(b.updated_at) || parseIsoDate(b.created_at);
    return bTime - aTime;
  });
  return sorted[0] || base;
}

function formatCpuCores(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid CPU cores value: ${value}`);
  }
  return String(value);
}

function formatMemoryBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    throw new Error(`Invalid memory bytes value: ${bytes}`);
  }
  if (bytes % GIB === 0) {
    return `${bytes / GIB}G`;
  }
  if (bytes % MIB === 0) {
    return `${bytes / MIB}M`;
  }
  return String(Math.round(bytes));
}

function resolveAddonResourceSpec(slug: string): PlannerResourceSpec {
  const stored = loadStoredTuningProfiles();
  const active = resolveActiveProfileFromStored(stored);
  const serviceKey = `addon-${slug}`;
  const fromProfile = active?.resources?.services?.[serviceKey];
  const candidate = fromProfile && typeof fromProfile === 'object' ? fromProfile : null;
  const normalized = candidate || DEFAULT_ADDON_RESOURCES;
  try {
    formatCpuCores(normalized.limits.cpu_cores);
    formatCpuCores(normalized.reservations.cpu_cores);
    formatMemoryBytes(normalized.limits.memory_bytes);
    formatMemoryBytes(normalized.reservations.memory_bytes);
    return normalized;
  } catch {
    return DEFAULT_ADDON_RESOURCES;
  }
}

type RunOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
};

function runCommand(command: string, args: string[], options: RunOptions = {}): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    enforceCommandPolicy(command, args, { source: 'addon-worker.runCommand' });
    const child = spawn(command, args, { cwd: options.cwd, env: options.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timeoutMs = options.timeoutMs || 0;
    const timer = timeoutMs ? setTimeout(() => child.kill('SIGKILL'), timeoutMs) : null;
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${args.join(' ')} failed with code ${code}\n${stderr || stdout}`.trim()));
      }
    });
  });
}

async function dockerServiceExists(name: string) {
  try {
    await runCommand('docker', ['service', 'inspect', name], { timeoutMs: 5000 });
    return true;
  } catch {
    return false;
  }
}

function stackServiceName(environmentId: number, service: string) {
  return `mz-env-${environmentId}_${service}`;
}

function parseDockerLoadOutput(output: string) {
  const lines = output.split('\n').map((line) => line.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i];
    const match = line.match(/^Loaded image:\s+(.+)$/i);
    if (match) return match[1].trim();
    const matchId = line.match(/^Loaded image ID:\s+(.+)$/i);
    if (matchId) return matchId[1].trim();
  }
  return '';
}

async function downloadArtifact(creds: R2Credentials, objectKey: string, targetPath: string) {
  const url = presignS3Url({
    method: 'GET',
    endpoint: creds.endpoint,
    bucket: creds.bucket,
    key: objectKey,
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    region: creds.region || 'auto',
    expiresIn: 3600,
  });
  await runCommand('curl', ['-fsSL', '--max-time', String(Math.ceil(FETCH_TIMEOUT_MS / 1000)), url, '-o', targetPath], {
    timeoutMs: FETCH_TIMEOUT_MS + 5000,
  });
}

async function deployAddon(record: DeploymentRecord, deploymentId: string) {
  const payload = record.payload || {};
  const environmentId = Number(payload.environment_id ?? 0) || 0;
  const slug = String(payload.slug ?? '').trim();
  const artifactKey = String(payload.artifact_key ?? '').replace(/^\/+/, '');
  if (!environmentId || !slug || !artifactKey) {
    throw new Error('Invalid addon deployment record payload');
  }

  const resources = resolveAddonResourceSpec(slug);

  const imageTag = (payload.image_tag || deploymentId).toString().trim().slice(0, 64) || deploymentId.slice(0, 12);
  const stackName = `mz-env-${environmentId}`;
  const serviceName = `${stackName}_addon-${slug}`;
  const imageRepo = `mz-addon-${environmentId}-${slug}`;
  const pushRef = `${REGISTRY_PUSH_HOST}:${REGISTRY_PORT}/${imageRepo}:${imageTag}`;
  const serviceRef = `${REGISTRY_HOST}:${REGISTRY_PORT}/${imageRepo}:${imageTag}`;

  const workDir = path.join(ADDON_WORK_DIR, deploymentId);
  ensureDir(workDir);
  const imageTar = path.join(workDir, 'image.tar');

  log('starting', { deployment_id: deploymentId, environment_id: environmentId, slug, artifact_key: artifactKey });

  const r2 = readR2CredFile(environmentId);
  const creds = r2?.backups;
  if (!creds?.accessKeyId || !creds.secretAccessKey || !creds.bucket || !creds.endpoint) {
    throw new Error('Missing R2 backups credentials for environment');
  }

  log('downloading artifact', { object_key: artifactKey });
  await downloadArtifact(creds, artifactKey, imageTar);
  log('artifact downloaded', { path: imageTar });

  log('docker load');
  const loadResult = await runCommand('docker', ['load', '-i', imageTar], { timeoutMs: DOCKER_LOAD_TIMEOUT_MS })
    .catch((error) => {
      throw new Error(`docker load failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  const loadedRef = parseDockerLoadOutput(`${loadResult.stdout}\n${loadResult.stderr}`);
  if (!loadedRef) {
    throw new Error('Unable to determine loaded image reference');
  }
  log('image loaded', { loaded_ref: loadedRef });

  log('tag + push', { push_ref: pushRef, service_ref: serviceRef });
  await runCommand('docker', ['tag', loadedRef, pushRef], { timeoutMs: 30_000 });
  await runCommand('docker', ['push', pushRef], { timeoutMs: DOCKER_PUSH_TIMEOUT_MS });

  const dbSecretName = `mz_db_password_v${SECRET_VERSION}`;
  const rabbitSecretName = `mz_rabbitmq_password_v${SECRET_VERSION}`;
  const dbHost = stackServiceName(environmentId, 'proxysql');
  const rabbitHost = stackServiceName(environmentId, 'rabbitmq');

  const baseLabels = [
    `com.docker.stack.namespace=${stackName}`,
    'mz.addon=true',
    `mz.addon.slug=${slug}`,
    ...(payload.repository ? [`mz.addon.repository=${payload.repository}`] : []),
    ...(payload.ref ? [`mz.addon.ref=${payload.ref}`] : []),
    `mz.addon.image=${serviceRef}`,
  ];

  const baseEnv = [
    `APP_ENV=prod`,
    `MZ_ENVIRONMENT_ID=${environmentId}`,
    `MZ_STACK_ID=${payload.stack_id || ''}`.trim(),
    `MZ_DB_HOST=${dbHost}`,
    'MZ_DB_PORT=6033',
    'MZ_DB_NAME=magento',
    'MZ_DB_USER=magento',
    'MZ_DB_PASSWORD_FILE=/run/secrets/db_password',
    `MZ_RABBITMQ_HOST=${rabbitHost}`,
    'MZ_RABBITMQ_PORT=5672',
    'MZ_RABBITMQ_USER=magento',
    'MZ_RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password',
    `DB_HOST=${dbHost}`,
    'DB_PORT=6033',
    'DB_NAME=magento',
    'DB_USER=magento',
    'DB_PASSWORD_FILE=/run/secrets/db_password',
    `RABBITMQ_HOST=${rabbitHost}`,
    'RABBITMQ_PORT=5672',
    'RABBITMQ_USER=magento',
    'RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password',
  ].filter((value) => !value.endsWith('='));

  const exists = await dockerServiceExists(serviceName);
  if (!exists) {
    log('creating service', { service: serviceName });
    await runCommand('docker', [
      'service',
      'create',
      '--name',
      serviceName,
      '--replicas',
      '1',
      '--restart-condition',
      'on-failure',
      '--update-order',
      'start-first',
      '--update-failure-action',
      'rollback',
      '--rollback-order',
      'stop-first',
      '--log-driver',
      'json-file',
      '--log-opt',
      'max-size=10m',
      '--log-opt',
      'max-file=3',
      '--limit-cpu',
      formatCpuCores(resources.limits.cpu_cores),
      '--limit-memory',
      formatMemoryBytes(resources.limits.memory_bytes),
      '--reserve-cpu',
      formatCpuCores(resources.reservations.cpu_cores),
      '--reserve-memory',
      formatMemoryBytes(resources.reservations.memory_bytes),
      ...baseLabels.flatMap((item) => ['--label', item]),
      '--network',
      'mz-backend',
      '--network',
      'mz-infrastructure',
      '--secret',
      `source=${dbSecretName},target=db_password`,
      '--secret',
      `source=${rabbitSecretName},target=rabbitmq_password`,
      ...baseEnv.flatMap((item) => ['--env', item]),
      serviceRef,
    ], { timeoutMs: 120_000 });
  } else {
    log('updating service', { service: serviceName });
    await runCommand('docker', [
      'service',
      'update',
      '--image',
      serviceRef,
      '--limit-cpu',
      formatCpuCores(resources.limits.cpu_cores),
      '--limit-memory',
      formatMemoryBytes(resources.limits.memory_bytes),
      '--reserve-cpu',
      formatCpuCores(resources.reservations.cpu_cores),
      '--reserve-memory',
      formatMemoryBytes(resources.reservations.memory_bytes),
      ...baseLabels.flatMap((item) => ['--label-add', item]),
      serviceName,
    ], { timeoutMs: 120_000 });
  }

  log('done', { deployment_id: deploymentId, service: serviceName, image: serviceRef });
}

async function processNext() {
  ensureDir(ADDON_QUEUE_DIR);
  ensureDir(ADDON_WORK_DIR);
  ensureDir(getProcessingDir());
  ensureDir(getCompletedDir());
  ensureDir(getFailedDir());

  const next = listQueuedRecords()[0];
  if (!next) {
    return;
  }

  const from = path.join(ADDON_QUEUE_DIR, next);
  const processingPath = path.join(getProcessingDir(), next);
  try {
    fs.renameSync(from, processingPath);
  } catch {
    return;
  }

  const deploymentId = next.replace(/\.json$/i, '');
  let record: DeploymentRecord | null = null;
  try {
    record = JSON.parse(fs.readFileSync(processingPath, 'utf8')) as DeploymentRecord;
  } catch (error) {
    log('invalid record json', { deployment_id: deploymentId, error: error instanceof Error ? error.message : String(error) });
    moveToDir(processingPath, getFailedDir());
    return;
  }

  try {
    await deployAddon(record, deploymentId);
    moveToDir(processingPath, getCompletedDir());
  } catch (error) {
    log('failed', { deployment_id: deploymentId, error: error instanceof Error ? error.message : String(error) });
    try {
      ensureDir(getFailedDir());
      const failureNote = path.join(getFailedDir(), `${deploymentId}.error.txt`);
      fs.writeFileSync(failureNote, `${new Date().toISOString()}\n${error instanceof Error ? error.stack || error.message : String(error)}\n`);
    } catch {
      // ignore
    }
    moveToDir(processingPath, getFailedDir());
  }
}

export function startAddonWorker() {
  setInterval(() => {
    if (processing) {
      return;
    }
    processing = true;
    processNext()
      .catch((error) => {
        log('loop error', { error: error instanceof Error ? error.message : String(error) });
      })
      .finally(() => {
        processing = false;
      });
  }, ADDON_INTERVAL_MS);

  // Run one tick immediately.
  if (!processing) {
    processing = true;
    processNext()
      .catch((error) => {
        log('loop error', { error: error instanceof Error ? error.message : String(error) });
      })
      .finally(() => {
        processing = false;
      });
  }
}
