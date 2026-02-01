import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import { isDeployPaused } from './deploy-pause.js';
import { presignS3Url } from './r2-presign.js';
import { buildCapacityPayload, buildPlannerPayload, isSwarmManager, readConfig } from './status.js';

type DeployPayload = {
  artifact?: string;
  stack_id?: number;
  environment_id?: number;
  repository?: string;
  ref?: string;
};

type DeploymentRecord = {
  id?: string;
  queued_at?: string;
  payload?: DeployPayload;
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

type EnvironmentSecrets = {
  crypt_key?: string;
  graphql_id_salt?: string;
};

type AppSelection = { flavor?: string; version?: string };
type ApplicationSelections = {
  php?: string;
  varnish?: string;
  database?: AppSelection;
  search?: AppSelection;
  cache?: AppSelection;
  queue?: AppSelection;
};

type EnvironmentRecord = {
  environment_id?: number;
  stack_id?: number;
  hostname?: string;
  environment_hostname?: string;
  environment_type?: string;
  db_backup_bucket?: string;
  db_backup_object?: string;
  application_selections?: ApplicationSelections;
  environment_secrets?: EnvironmentSecrets | null;
};

type PlannerResourceSpec = {
  limits: {
    cpu_cores: number;
    memory_bytes: number;
  };
  reservations: {
    cpu_cores: number;
    memory_bytes: number;
  };
};

type PlannerResources = Record<string, PlannerResourceSpec>;

type PlannerConfigChange = {
  service: string;
  changes: Record<string, number | string>;
};

type PlannerTuningProfileLike = {
  id?: string;
  config_changes?: PlannerConfigChange[];
};

type PlannerTuningPayloadLike = {
  active_profile_id?: string;
  base_profile?: PlannerTuningProfileLike;
  recommended_profile?: PlannerTuningProfileLike;
  incremental_profile?: PlannerTuningProfileLike;
  approved_profiles?: PlannerTuningProfileLike[];
};

type DeployHistoryEntry = {
  artifacts: string[];
  imageTags: string[];
  updated_at?: string;
};

type DeployHistory = Record<string, DeployHistoryEntry>;

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_WORK_DIR = process.env.MZ_DEPLOY_WORK_DIR || '/opt/mage-zero/deployments/work';
const DEPLOY_HISTORY_FILE = process.env.MZ_DEPLOY_HISTORY_FILE || path.join(DEPLOY_QUEUE_DIR, 'meta', 'history.json');
const LEGACY_DEPLOY_HISTORY_FILE = path.join(DEPLOY_QUEUE_DIR, 'history.json');
const DEPLOY_RECORD_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i;
const DEPLOY_RETAIN_COUNT = Math.max(1, Number(process.env.MZ_DEPLOY_RETAIN_COUNT || 2));
const DEPLOY_FAILED_RETAIN_COUNT = Math.max(0, Number(process.env.MZ_DEPLOY_FAILED_RETAIN_COUNT || 3));
const DEPLOY_CLEANUP_ENABLED = (process.env.MZ_DEPLOY_CLEANUP_ENABLED || '1') !== '0';
const REGISTRY_CLEANUP_ENABLED = (process.env.MZ_REGISTRY_CLEANUP_ENABLED || '1') !== '0';
const REGISTRY_CLEANUP_HOST = process.env.MZ_REGISTRY_CLEANUP_HOST || process.env.REGISTRY_PUSH_HOST || '127.0.0.1';
const REGISTRY_CLEANUP_PORT = process.env.MZ_REGISTRY_CLEANUP_PORT || process.env.REGISTRY_PORT || '5000';
const DEPLOY_MIN_FREE_GB = Number(process.env.MZ_DEPLOY_MIN_FREE_GB || 15);
const REGISTRY_GC_ENABLED = (process.env.MZ_REGISTRY_GC_ENABLED || '0') === '1';
const REGISTRY_GC_SCRIPT = process.env.MZ_REGISTRY_GC_SCRIPT
  || path.join(process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm', 'scripts/registry-gc.sh');
const SHUTDOWN_GRACE_MS = Number(process.env.MZ_SHUTDOWN_GRACE_MS || 10 * 60 * 1000);
const CLOUD_SWARM_DIR = process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm';
const CLOUD_SWARM_REPO = process.env.MZ_CLOUD_SWARM_REPO || 'git@github.com:mage-zero/cloud-swarm.git';
const CLOUD_SWARM_KEY_PATH = process.env.MZ_CLOUD_SWARM_KEY_PATH || '/opt/mage-zero/keys/cloud-swarm-deploy';
const R2_CRED_DIR = process.env.MZ_R2_CRED_DIR || '/opt/mage-zero/r2';
const STACK_MASTER_KEY_PATH = process.env.MZ_STACK_MASTER_KEY_PATH || '/etc/magezero/stack_master_ssh';
const DEFAULT_DB_BACKUP_OBJECT = process.env.MZ_DB_BACKUP_OBJECT || 'provisioning-database.sql.zst.age';
const SECRET_VERSION = process.env.MZ_SECRET_VERSION || '1';
const DEPLOY_INTERVAL_MS = Number(process.env.MZ_DEPLOY_WORKER_INTERVAL_MS || 5000);
const FETCH_TIMEOUT_MS = Number(process.env.MZ_FETCH_TIMEOUT_MS || 30000);
const MIB = 1024 * 1024;
const GIB = 1024 * 1024 * 1024;

const RESOURCE_ENV_MAP = [
  { service: 'varnish', prefix: 'MZ_VARNISH' },
  { service: 'nginx', prefix: 'MZ_NGINX' },
  { service: 'php-fpm', prefix: 'MZ_PHP_FPM' },
  { service: 'php-fpm-admin', prefix: 'MZ_PHP_FPM_ADMIN' },
  { service: 'cron', prefix: 'MZ_CRON' },
  { service: 'database', prefix: 'MZ_DATABASE' },
  { service: 'database-replica', prefix: 'MZ_DATABASE_REPLICA' },
  { service: 'proxysql', prefix: 'MZ_PROXYSQL' },
  { service: 'opensearch', prefix: 'MZ_OPENSEARCH' },
  { service: 'redis-cache', prefix: 'MZ_REDIS_CACHE' },
  { service: 'redis-session', prefix: 'MZ_REDIS_SESSION' },
  { service: 'rabbitmq', prefix: 'MZ_RABBITMQ' },
] as const;

let processing = false;
let currentDeploymentPath: string | null = null;
let shutdownRequested = false;
let shutdownTimer: NodeJS.Timeout | null = null;
let processingWaiters: Array<() => void> = [];

function waitForProcessingDone() {
  if (!processing) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    processingWaiters.push(resolve);
  });
}

function notifyProcessingDone() {
  for (const resolve of processingWaiters) {
    resolve();
  }
  processingWaiters = [];
}

function getProcessingDir() {
  return path.join(DEPLOY_QUEUE_DIR, 'processing');
}

function readNodeFile(name: string): string {
  try {
    return fs.readFileSync(path.join(NODE_DIR, name), 'utf8').trim();
  } catch {
    return '';
  }
}

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function inferRepositoryFromArtifactKey(artifactKey: string) {
  const normalized = artifactKey.replace(/^\/+/, '');
  const parts = normalized.split('/');
  const buildsIndex = parts.indexOf('builds');
  if (buildsIndex >= 0 && parts.length > buildsIndex + 2) {
    return `${parts[buildsIndex + 1]}/${parts[buildsIndex + 2]}`;
  }
  return '';
}

function readDeploymentHistory(): DeployHistory {
  const candidates = [DEPLOY_HISTORY_FILE, LEGACY_DEPLOY_HISTORY_FILE];
  for (const file of candidates) {
    if (!file) continue;
    try {
      if (!fs.existsSync(file)) continue;
      const raw = fs.readFileSync(file, 'utf8');
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        continue;
      }
      const history = parsed as DeployHistory;
      if (file === LEGACY_DEPLOY_HISTORY_FILE && DEPLOY_HISTORY_FILE !== LEGACY_DEPLOY_HISTORY_FILE) {
        try {
          ensureDir(path.dirname(DEPLOY_HISTORY_FILE));
          fs.writeFileSync(DEPLOY_HISTORY_FILE, JSON.stringify(history, null, 2));
          fs.unlinkSync(LEGACY_DEPLOY_HISTORY_FILE);
        } catch {
          // ignore migration failures
        }
      }
      return history;
    } catch {
      continue;
    }
  }
  return {};
}

function writeDeploymentHistory(history: DeployHistory) {
  ensureDir(path.dirname(DEPLOY_HISTORY_FILE));
  fs.writeFileSync(DEPLOY_HISTORY_FILE, JSON.stringify(history, null, 2));
}

function updateDeploymentHistory(
  history: DeployHistory,
  key: string,
  artifactKey: string,
  imageTag: string
) {
  const existing = history[key] || { artifacts: [], imageTags: [] };
  const artifacts = [artifactKey, ...existing.artifacts.filter((item) => item !== artifactKey)];
  const imageTags = [imageTag, ...existing.imageTags.filter((item) => item !== imageTag)];
  const keepArtifacts = artifacts.slice(0, DEPLOY_RETAIN_COUNT);
  const keepImageTags = imageTags.slice(0, DEPLOY_RETAIN_COUNT);
  const removedArtifacts = artifacts.slice(DEPLOY_RETAIN_COUNT);
  const removedImageTags = imageTags.slice(DEPLOY_RETAIN_COUNT);
  history[key] = {
    artifacts: keepArtifacts,
    imageTags: keepImageTags,
    updated_at: new Date().toISOString(),
  };
  return { keepArtifacts, keepImageTags, removedArtifacts, removedImageTags };
}

function parseImageReference(reference: string) {
  const withoutDigest = reference.split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const lastColon = withoutDigest.lastIndexOf(':');
  if (lastColon > lastSlash) {
    return {
      repository: withoutDigest.slice(0, lastColon),
      tag: withoutDigest.slice(lastColon + 1),
    };
  }
  return { repository: withoutDigest, tag: '' };
}

function stripRegistryHost(repository: string) {
  const parts = repository.split('/');
  if (parts.length > 1 && (parts[0].includes('.') || parts[0].includes(':') || parts[0] === 'registry' || parts[0] === 'localhost')) {
    return parts.slice(1).join('/');
  }
  return repository;
}

function getRegistryHost(repository: string) {
  const parts = repository.split('/');
  if (parts.length > 1 && (parts[0].includes('.') || parts[0].includes(':') || parts[0] === 'registry' || parts[0] === 'localhost')) {
    return parts[0];
  }
  return '';
}

async function getFreeSpaceGb(target: string) {
  try {
    const { stdout } = await runCommandCapture('df', ['-Pm', target]);
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) {
      return null;
    }
    const parts = lines[1].trim().split(/\s+/);
    if (parts.length < 4) {
      return null;
    }
    const availableMb = Number(parts[3]);
    if (!Number.isFinite(availableMb)) {
      return null;
    }
    return availableMb / 1024;
  } catch {
    return null;
  }
}

async function listStackImageTags(stackName: string) {
  const { stdout } = await runCommandCapture('docker', [
    'service',
    'ls',
    '--filter',
    `label=com.docker.stack.namespace=${stackName}`,
    '--format',
    '{{.Image}}',
  ]);
  const tags = new Set<string>();
  const repos = new Set<string>();
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parsed = parseImageReference(trimmed);
    if (parsed.tag) {
      tags.add(parsed.tag);
    }
    if (parsed.repository) {
      repos.add(parsed.repository);
    }
  }
  return { tags, repositories: repos };
}

async function cleanupWorkDirs(keepArtifactBases: Set<string>) {
  if (!fs.existsSync(DEPLOY_WORK_DIR)) {
    return;
  }
  const entries = fs.readdirSync(DEPLOY_WORK_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(DEPLOY_WORK_DIR, entry.name));
  for (const dir of entries) {
    let files: string[] = [];
    try {
      files = fs.readdirSync(dir);
    } catch {
      continue;
    }
    const buildArtifacts = files.filter((file) => file.startsWith('build-') && file.endsWith('.tar.zst'));
    if (!buildArtifacts.length) {
      continue;
    }
    const hasKeep = buildArtifacts.some((file) => keepArtifactBases.has(file));
    if (!hasKeep) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  }
}

function cleanupFailedWorkDirs() {
  if (DEPLOY_FAILED_RETAIN_COUNT <= 0) {
    return;
  }
  if (!fs.existsSync(DEPLOY_WORK_DIR) || !fs.existsSync(path.join(DEPLOY_QUEUE_DIR, 'failed'))) {
    return;
  }
  const failedDir = path.join(DEPLOY_QUEUE_DIR, 'failed');
  const failedIds = new Set<string>();
  for (const entry of fs.readdirSync(failedDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    if (!DEPLOY_RECORD_FILENAME.test(entry.name)) continue;
    failedIds.add(path.basename(entry.name, '.json'));
  }
  if (!failedIds.size) {
    return;
  }

  const candidates = fs.readdirSync(DEPLOY_WORK_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && failedIds.has(entry.name))
    .map((entry) => {
      const dirPath = path.join(DEPLOY_WORK_DIR, entry.name);
      const marker = path.join(failedDir, `${entry.name}.json`);
      let mtimeMs = 0;
      try {
        mtimeMs = fs.statSync(marker).mtimeMs;
      } catch {
        try {
          mtimeMs = fs.statSync(dirPath).mtimeMs;
        } catch {
          mtimeMs = 0;
        }
      }
      return { id: entry.name, dirPath, mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  const remove = candidates.slice(DEPLOY_FAILED_RETAIN_COUNT);
  for (const item of remove) {
    try {
      fs.rmSync(item.dirPath, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

async function deleteR2Object(creds: R2Credentials, objectKey: string) {
  const normalizedKey = objectKey.replace(/^\/+/, '');
  const url = presignS3Url({
    method: 'DELETE',
    endpoint: creds.endpoint,
    bucket: creds.bucket,
    key: normalizedKey,
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    region: creds.region || 'auto',
    expiresIn: 3600,
  });
  await runCommand('curl', ['-fsSL', '-X', 'DELETE', url]);
}

async function cleanupLocalImages(
  environmentId: number,
  keepImageTags: Set<string>,
  stackName: string
) {
  const prefix = `env-${environmentId}-`;
  const running = await listStackImageTags(stackName);
  for (const tag of running.tags) {
    keepImageTags.add(tag);
  }
  const { stdout } = await runCommandCapture('docker', ['image', 'ls', '--format', '{{.Repository}} {{.Tag}}']);
  const removals: Array<{ repo: string; tag: string }> = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [repo, tag] = trimmed.split(/\s+/);
    if (!repo || !tag || tag === '<none>') continue;
    if (!tag.startsWith(prefix)) continue;
    if (keepImageTags.has(tag)) continue;
    removals.push({ repo, tag });
  }
  for (const removal of removals) {
    try {
      await runCommand('docker', ['image', 'rm', '-f', `${removal.repo}:${removal.tag}`]);
    } catch {
      // ignore
    }
  }
  return removals;
}

async function cleanupRegistryImages(removals: Array<{ repo: string; tag: string }>) {
  if (!REGISTRY_CLEANUP_ENABLED || !removals.length) {
    return;
  }
  const registryBase = `http://${REGISTRY_CLEANUP_HOST}:${REGISTRY_CLEANUP_PORT}`;
  for (const removal of removals) {
    const repoHost = getRegistryHost(removal.repo);
    if (repoHost && ![REGISTRY_CLEANUP_HOST, 'registry', 'localhost', '127.0.0.1'].includes(repoHost)) {
      continue;
    }
    const repoName = stripRegistryHost(removal.repo);
    if (!repoName) continue;
    try {
      const { stdout } = await runCommandCapture('curl', [
        '-fsSI',
        '-H',
        'Accept: application/vnd.docker.distribution.manifest.v2+json',
        `${registryBase}/v2/${repoName}/manifests/${removal.tag}`,
      ]);
      const digestLine = stdout.split('\n').find((line) => line.toLowerCase().startsWith('docker-content-digest:'));
      if (!digestLine) continue;
      const digest = digestLine.split(':').slice(1).join(':').trim();
      if (!digest) continue;
      await runCommand('curl', ['-fsSL', '-X', 'DELETE', `${registryBase}/v2/${repoName}/manifests/${digest}`]);
    } catch {
      // ignore registry cleanup failures
    }
  }
}

async function runRegistryGc() {
  if (!REGISTRY_GC_ENABLED) {
    return;
  }
  if (!fs.existsSync(REGISTRY_GC_SCRIPT)) {
    console.warn(`registry gc script not found: ${REGISTRY_GC_SCRIPT}`);
    return;
  }
  try {
    await runCommand('bash', [REGISTRY_GC_SCRIPT]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`registry gc failed: ${message}`);
  }
}

async function cleanupDeploymentResources(params: {
  environmentId: number;
  repository: string;
  artifactKey: string;
  mageVersion: string;
  stackName: string;
  r2: R2CredFile;
}) {
  const history = readDeploymentHistory();
  const normalizedArtifactKey = params.artifactKey.replace(/^\/+/, '');
  const repo = params.repository || inferRepositoryFromArtifactKey(normalizedArtifactKey) || 'unknown';
  const key = `env:${params.environmentId}:${repo}`;
  const { keepArtifacts, keepImageTags, removedArtifacts, removedImageTags } = updateDeploymentHistory(
    history,
    key,
    normalizedArtifactKey,
    params.mageVersion
  );
  writeDeploymentHistory(history);

  if (!DEPLOY_CLEANUP_ENABLED) {
    return;
  }

  const keepArtifactBases = new Set(keepArtifacts.map((item) => path.basename(item)));
  await cleanupWorkDirs(keepArtifactBases);

  if (params.r2?.backups) {
    for (const objectKey of removedArtifacts) {
      try {
        await deleteR2Object(params.r2.backups, objectKey);
      } catch {
        // ignore cleanup errors
      }
    }
  }

  if (DEPLOY_MIN_FREE_GB > 0) {
    const freeGb = (await getFreeSpaceGb('/var/lib/docker')) ?? (await getFreeSpaceGb('/')) ?? null;
    if (freeGb !== null && freeGb >= DEPLOY_MIN_FREE_GB) {
      return;
    }
  }

  const keepImageTagSet = new Set(keepImageTags);
  const removedImageTagSet = new Set(removedImageTags);
  const removals = await cleanupLocalImages(params.environmentId, keepImageTagSet, params.stackName);
  if (removedImageTagSet.size) {
    const filtered = removals.filter((item) => removedImageTagSet.has(item.tag));
    await cleanupRegistryImages(filtered);
    await runRegistryGc();
  }
}

function listQueueFiles(): string[] {
  if (!fs.existsSync(DEPLOY_QUEUE_DIR)) {
    return [];
  }
  return fs.readdirSync(DEPLOY_QUEUE_DIR, { withFileTypes: true })
    .filter((entry) => entry.isFile() && DEPLOY_RECORD_FILENAME.test(entry.name))
    .map((entry) => path.join(DEPLOY_QUEUE_DIR, entry.name))
    .sort((a, b) => a.localeCompare(b));
}

function claimNextDeployment(): string | null {
  const files = listQueueFiles();
  if (!files.length) {
    return null;
  }

  ensureDir(DEPLOY_QUEUE_DIR);
  const processingDir = getProcessingDir();
  ensureDir(processingDir);

  const source = files[0];
  const target = path.join(processingDir, path.basename(source));
  try {
    fs.renameSync(source, target);
    return target;
  } catch {
    return null;
  }
}

function recoverProcessingQueue() {
  const processingDir = getProcessingDir();
  if (!fs.existsSync(processingDir)) {
    return;
  }
  const entries = fs.readdirSync(processingDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && DEPLOY_RECORD_FILENAME.test(entry.name))
    .map((entry) => entry.name);
  for (const entry of entries) {
    const source = path.join(processingDir, entry);
    const target = path.join(DEPLOY_QUEUE_DIR, entry);
    try {
      fs.renameSync(source, target);
      console.warn(`requeued deployment ${entry} after restart`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`failed to requeue ${entry}: ${message}`);
    }
  }
}

function requeueCurrentDeployment() {
  if (!currentDeploymentPath) {
    return;
  }
  try {
    const target = path.join(DEPLOY_QUEUE_DIR, path.basename(currentDeploymentPath));
    if (fs.existsSync(currentDeploymentPath)) {
      fs.renameSync(currentDeploymentPath, target);
    }
  } catch {
    // best effort; recoverProcessingQueue will retry on next boot
  }
}

async function initiateShutdown(signal: string) {
  if (shutdownRequested) {
    return;
  }
  shutdownRequested = true;
  console.warn(`shutdown requested (${signal}); draining deploy worker`);
  if (!processing) {
    process.exit(0);
    return;
  }
  shutdownTimer = setTimeout(() => {
    console.warn('shutdown timeout reached; requeueing active deployment');
    requeueCurrentDeployment();
    process.exit(0);
  }, Number.isFinite(SHUTDOWN_GRACE_MS) && SHUTDOWN_GRACE_MS > 0 ? SHUTDOWN_GRACE_MS : 0);
  await waitForProcessingDone();
  if (shutdownTimer) {
    clearTimeout(shutdownTimer);
    shutdownTimer = null;
  }
  process.exit(0);
}

async function runCommand(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  // TODO: Harden command execution with an allowlist or explicit wrappers before production.
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: 'inherit',
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
      }
    });
  });
}

async function runCommandLogged(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; logDir: string; label: string }
) {
  ensureDir(options.logDir);
  const safeLabel = options.label.replace(/[^a-z0-9._-]/gi, '_');
  const stdoutPath = path.join(options.logDir, `${safeLabel}.stdout.log`);
  const stderrPath = path.join(options.logDir, `${safeLabel}.stderr.log`);
  const header = `\n# ${new Date().toISOString()} ${command} ${args.join(' ')}\n`;
  fs.appendFileSync(stdoutPath, header);
  fs.appendFileSync(stderrPath, header);

  await new Promise<void>((resolve, reject) => {
    const stdoutStream = fs.createWriteStream(stdoutPath, { flags: 'a' });
    const stderrStream = fs.createWriteStream(stderrPath, { flags: 'a' });
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => {
      stdoutStream.write(chunk);
      process.stdout.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrStream.write(chunk);
      process.stderr.write(chunk);
    });
    child.on('error', (error) => {
      stdoutStream.end();
      stderrStream.end();
      reject(error);
    });
    child.on('close', (code) => {
      stdoutStream.end();
      stderrStream.end();
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
      }
    });
  });
}

async function runCommandCapture(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  return await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${args.join(' ')} failed: ${stderr || stdout}`));
      }
    });
  });
}

async function runCommandCaptureWithStatus(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
) {
  return await new Promise<{ stdout: string; stderr: string; code: number }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ stdout, stderr, code: typeof code === 'number' ? code : 0 });
    });
  });
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function generateSecretHex(bytes: number) {
  return crypto.randomBytes(bytes).toString('hex');
}

function assertRequiredEnv(env: NodeJS.ProcessEnv, keys: string[]) {
  const missing = keys.filter((key) => !env[key]);
  if (missing.length) {
    throw new Error(`Missing required environment values: ${missing.join(', ')}`);
  }
}

function assertNoLatestImages(stackConfig: string) {
  const latestLines = stackConfig
    .split('\n')
    .filter((line) => line.trim().startsWith('image:') && line.includes(':latest'));
  if (latestLines.length) {
    throw new Error(`Stack config resolved to :latest images: ${latestLines.join(' | ')}`);
  }
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

function buildPlannerResourceEnv(resources: PlannerResources) {
  const env: Record<string, string> = {};
  for (const entry of RESOURCE_ENV_MAP) {
    const resource = resources[entry.service];
    if (!resource) {
      throw new Error(`Planner missing resource sizing for ${entry.service}`);
    }
    env[`${entry.prefix}_LIMIT_CPUS`] = formatCpuCores(resource.limits.cpu_cores);
    env[`${entry.prefix}_LIMIT_MEMORY`] = formatMemoryBytes(resource.limits.memory_bytes);
    env[`${entry.prefix}_RESERVE_CPUS`] = formatCpuCores(resource.reservations.cpu_cores);
    env[`${entry.prefix}_RESERVE_MEMORY`] = formatMemoryBytes(resource.reservations.memory_bytes);
  }
  return env;
}

function formatMemoryMiB(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    throw new Error(`Invalid memory bytes value: ${bytes}`);
  }
  return String(Math.max(1, Math.round(bytes / MIB)));
}

function resolveActiveProfile(tuning: PlannerTuningPayloadLike | null | undefined): PlannerTuningProfileLike | null {
  if (!tuning) {
    return null;
  }
  const activeId = tuning.active_profile_id;
  const approved = Array.isArray(tuning.approved_profiles) ? tuning.approved_profiles : [];
  if (activeId) {
    const fromApproved = approved.find((profile) => profile?.id === activeId);
    if (fromApproved) {
      return fromApproved;
    }
    if (tuning.recommended_profile?.id === activeId) {
      return tuning.recommended_profile;
    }
    if (tuning.incremental_profile?.id === activeId) {
      return tuning.incremental_profile;
    }
    if (tuning.base_profile?.id === activeId) {
      return tuning.base_profile;
    }
  }
  return tuning.base_profile || approved[0] || tuning.recommended_profile || null;
}

function buildConfigEnv(configChanges: PlannerConfigChange[]): Record<string, string> {
  const env: Record<string, string> = {};
  const seen = new Set<string>();

  const setEnv = (key: string, value: string) => {
    if (!seen.has(key)) {
      env[key] = value;
      seen.add(key);
    }
  };

  for (const change of configChanges) {
    const service = String(change?.service || '');
    const changes = change?.changes || {};
    for (const [key, rawValue] of Object.entries(changes)) {
      if (rawValue === null || rawValue === undefined) {
        continue;
      }
      if (service === 'php-fpm' || service === 'php-fpm-admin') {
        switch (key) {
          case 'php.memory_limit':
            if (Number(rawValue) > 0) {
              setEnv('MZ_PHP_MEMORY_LIMIT', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'opcache.memory_consumption':
            if (Number(rawValue) > 0) {
              setEnv('MZ_OPCACHE_MEMORY_CONSUMPTION', formatMemoryMiB(Number(rawValue)));
            }
            break;
          case 'opcache.interned_strings_buffer':
            if (Number(rawValue) > 0) {
              setEnv('MZ_OPCACHE_INTERNED_STRINGS_BUFFER', formatMemoryMiB(Number(rawValue)));
            }
            break;
          case 'opcache.max_accelerated_files':
            setEnv('MZ_OPCACHE_MAX_ACCELERATED_FILES', String(rawValue));
            break;
          case 'fpm.pm.max_children':
            setEnv('MZ_FPM_PM_MAX_CHILDREN', String(rawValue));
            break;
          case 'fpm.pm.start_servers':
            setEnv('MZ_FPM_PM_START_SERVERS', String(rawValue));
            break;
          case 'fpm.pm.min_spare_servers':
            setEnv('MZ_FPM_PM_MIN_SPARE_SERVERS', String(rawValue));
            break;
          case 'fpm.pm.max_spare_servers':
            setEnv('MZ_FPM_PM_MAX_SPARE_SERVERS', String(rawValue));
            break;
          case 'fpm.pm.max_requests':
            setEnv('MZ_FPM_PM_MAX_REQUESTS', String(rawValue));
            break;
          case 'fpm.request_terminate_timeout':
            setEnv('MZ_FPM_REQUEST_TERMINATE_TIMEOUT', String(rawValue));
            break;
          default:
            break;
        }
      } else if (service === 'database' || service === 'database-replica') {
        switch (key) {
          case 'innodb_buffer_pool_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_INNODB_BUFFER_POOL_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'innodb_log_file_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_INNODB_LOG_FILE_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'max_connections':
            setEnv('MZ_DB_MAX_CONNECTIONS', String(rawValue));
            break;
          case 'tmp_table_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_TMP_TABLE_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'max_heap_table_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_MAX_HEAP_TABLE_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'thread_cache_size':
            setEnv('MZ_DB_THREAD_CACHE_SIZE', String(rawValue));
            break;
          case 'query_cache_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_QUERY_CACHE_SIZE', formatMemoryBytes(Number(rawValue)));
            } else {
              setEnv('MZ_DB_QUERY_CACHE_SIZE', '0');
            }
            break;
          default:
            break;
        }
      }
    }
  }

  return env;
}

const RESOURCE_ENV_KEYS = RESOURCE_ENV_MAP.flatMap((entry) => [
  `${entry.prefix}_LIMIT_CPUS`,
  `${entry.prefix}_LIMIT_MEMORY`,
  `${entry.prefix}_RESERVE_CPUS`,
  `${entry.prefix}_RESERVE_MEMORY`,
]);

async function ensureDockerSecret(secretName: string, value: string, workDir: string) {
  if (!value) {
    throw new Error(`Missing secret value for ${secretName}`);
  }
  try {
    await runCommandCapture('docker', ['secret', 'inspect', secretName]);
    return;
  } catch {
    // secret missing
  }

  ensureDir(workDir);
  const secretPath = path.join(workDir, `${secretName}.secret`);
  fs.writeFileSync(secretPath, value, { mode: 0o600 });
  try {
    await runCommand('docker', ['secret', 'create', secretName, secretPath]);
  } finally {
    try {
      fs.unlinkSync(secretPath);
    } catch {
      // ignore cleanup failure
    }
  }
}

function readR2CredFile(environmentId: number): R2CredFile | null {
  try {
    const raw = fs.readFileSync(path.join(R2_CRED_DIR, `env-${environmentId}.json`), 'utf8');
    return JSON.parse(raw) as R2CredFile;
  } catch {
    return null;
  }
}

function buildSignature(method: string, pathName: string, query: string, timestamp: string, nonce: string, body: string, secret: string) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [
    method.toUpperCase(),
    pathName,
    query,
    timestamp,
    nonce,
    bodyHash,
  ].join('\n');
  return crypto.createHmac('sha256', secret).update(stringToSign).digest('base64');
}

function buildNodeHeaders(method: string, pathName: string, query: string, body: string, nodeId: string, secret: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const signature = buildSignature(method, pathName, query, timestamp, nonce, body, secret);
  return {
    'X-MZ-Node-Id': nodeId,
    'X-MZ-Timestamp': timestamp,
    'X-MZ-Nonce': nonce,
    'X-MZ-Signature': signature,
  };
}

async function fetchJson(baseUrl: string, pathName: string, method: string, body: string | null, nodeId: string, nodeSecret: string) {
  const url = new URL(pathName, baseUrl);
  const query = url.search ? url.search.slice(1) : '';
  const payload = body ?? '';
  const headers = buildNodeHeaders(method, url.pathname, query, payload, nodeId, nodeSecret);
  const controller = new AbortController();
  const timeoutMs = Number.isFinite(FETCH_TIMEOUT_MS) && FETCH_TIMEOUT_MS > 0 ? FETCH_TIMEOUT_MS : 30000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...headers,
      },
      body: payload || undefined,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`mz-control request failed: ${response.status} - ${errorBody}`);
  }

  return response.json() as Promise<any>;
}

async function fetchEnvironmentRecord(stackId: number, environmentId: number, baseUrl: string, nodeId: string, nodeSecret: string) {
  const payload = await fetchJson(
    baseUrl,
    `/v1/agent/stack/${stackId}/environments`,
    'GET',
    null,
    nodeId,
    nodeSecret,
  );
  const environments = Array.isArray(payload?.environments) ? payload.environments as EnvironmentRecord[] : [];
  return environments.find((env) => Number(env.environment_id ?? 0) === environmentId) || null;
}

function normalizeSelectionFlavor(flavor: string | undefined, fallback: string): string {
  return (flavor || fallback).toLowerCase();
}

function resolveVersionEnv(selections: ApplicationSelections | undefined) {
  const phpVersion = selections?.php || '';
  const varnishVersion = selections?.varnish || '';
  const databaseFlavor = normalizeSelectionFlavor(selections?.database?.flavor, 'mariadb');
  const databaseVersion = selections?.database?.version || '';
  const searchFlavor = normalizeSelectionFlavor(selections?.search?.flavor, 'opensearch');
  const searchVersion = selections?.search?.version || '';
  const cacheFlavor = normalizeSelectionFlavor(selections?.cache?.flavor, 'redis');
  const cacheVersion = selections?.cache?.version || '';
  const queueFlavor = normalizeSelectionFlavor(selections?.queue?.flavor, 'rabbitmq');
  const queueVersion = selections?.queue?.version || '';

  const mappedDb = databaseFlavor === 'mysql' ? 'mariadb' : databaseFlavor;
  const mappedSearch = searchFlavor === 'elasticsearch' ? 'opensearch' : searchFlavor;
  const mappedCache = cacheFlavor === 'valkey' ? 'redis' : cacheFlavor;
  const mappedQueue = queueFlavor === 'activemq-artemis' ? 'rabbitmq' : queueFlavor;

  return {
    phpVersion,
    varnishVersion,
    mariadbVersion: mappedDb === 'mariadb' ? databaseVersion : '',
    opensearchVersion: mappedSearch === 'opensearch' ? searchVersion : '',
    redisVersion: mappedCache === 'redis' ? cacheVersion : '',
    rabbitmqVersion: mappedQueue === 'rabbitmq' ? queueVersion : '',
  };
}

function readVersionDefaults(): Record<string, string> {
  const file = path.join(CLOUD_SWARM_DIR, 'config/versions.env');
  if (!fs.existsSync(file)) {
    return {};
  }
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const output: Record<string, string> = {};
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const idx = trimmed.indexOf('=');
    if (idx === -1) {
      continue;
    }
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (key && value) {
      output[key] = value;
    }
  }
  return output;
}

function resolveImageTag(artifactKey: string, ref: string, deploymentId: string) {
  const base = path.basename(artifactKey);
  const match = base.match(/-([0-9a-f]{7,40})\.tar\.zst$/);
  if (match) {
    return match[1].slice(0, 12);
  }
  if (ref.startsWith('refs/heads/')) {
    return ref.split('/').pop() || ref;
  }
  if (ref) {
    return ref.slice(0, 12);
  }
  return deploymentId.slice(0, 8);
}

async function ensureCloudSwarmRepo() {
  ensureDir(path.dirname(CLOUD_SWARM_DIR));
  const repoExists = fs.existsSync(path.join(CLOUD_SWARM_DIR, '.git'));
  const gitEnv = {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${CLOUD_SWARM_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
  };

  if (!repoExists) {
    await runCommand('git', ['clone', CLOUD_SWARM_REPO, CLOUD_SWARM_DIR], { env: gitEnv });
    return;
  }

  await runCommand('git', ['-C', CLOUD_SWARM_DIR, 'fetch', '--prune'], { env: gitEnv });
  // Treat the cloud-swarm checkout as an ephemeral build toolchain:
  // always force it to match `origin/main` so local modifications can't break deploys.
  await runCommand('git', ['-C', CLOUD_SWARM_DIR, 'checkout', '-B', 'main', 'origin/main', '--force'], { env: gitEnv });
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
  await runCommand('curl', ['-fsSL', url, '-o', targetPath]);
}

async function extractArtifact(archivePath: string, targetDir: string) {
  ensureDir(targetDir);
  await runCommand('tar', ['-I', 'zstd -d', '-xf', archivePath, '-C', targetDir]);
}

async function stripDefiners(inputPath: string, outputPath: string) {
  await new Promise<void>((resolve, reject) => {
    const input = fs.createReadStream(inputPath, 'utf8');
    const output = fs.createWriteStream(outputPath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input, crlfDelay: Infinity });

    rl.on('line', (line) => {
      const cleaned = line
        .replace(/DEFINER=`[^`]+`@`[^`]+`/g, '')
        .replace(/DEFINER=[^ ]+ /g, '');
      output.write(`${cleaned}\n`);
    });
    rl.on('close', () => {
      output.end();
      resolve();
    });
    rl.on('error', reject);
  });
}

async function waitForContainer(stackName: string, serviceName: string, timeoutMs: number) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const { stdout } = await runCommandCapture('docker', [
      'ps',
      '--filter',
      `name=${stackName}_${serviceName}`,
      '--format',
      '{{.ID}}',
    ]);
    const id = stdout.trim().split('\n')[0] || '';
    if (id) {
      return id;
    }
    await delay(2000);
  }
  throw new Error(`Timed out waiting for ${serviceName} container`);
}

async function findLocalContainer(stackName: string, serviceName: string) {
  const { stdout } = await runCommandCapture('docker', [
    'ps',
    '--filter',
    `name=${stackName}_${serviceName}`,
    '--format',
    '{{.ID}}',
  ]);
  return stdout.trim().split('\n')[0] || '';
}

async function waitForDatabase(containerId: string, timeoutMs: number) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await runCommandCapture('docker', [
        'exec',
        containerId,
        'sh',
        '-c',
        'mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -e "SELECT 1" >/dev/null 2>&1',
      ]);
      return;
    } catch {
      await delay(3000);
    }
  }
  throw new Error('Database did not become ready in time');
}

async function waitForProxySql(containerId: string, stackName: string, timeoutMs: number) {
  const start = Date.now();
  let currentId = containerId;
  const probe = [
    '$host=getenv("MZ_DB_HOST") ?: "proxysql";',
    '$port=(int)(getenv("MZ_DB_PORT") ?: 6033);',
    '$fp=@fsockopen($host,$port,$errno,$errstr,1);',
    'if(!$fp){fwrite(STDERR,$errstr ?: "connect failed"); exit(1);} fclose($fp);',
  ].join(' ');
  while (Date.now() - start < timeoutMs) {
    try {
      await runCommandCapture('docker', ['exec', currentId, 'php', '-r', probe]);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('No such container') || message.includes('is not running')) {
        try {
          currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
        } catch {
          // ignore; retry with previous container id
        }
      }
      await delay(2000);
    }
  }
  throw new Error('ProxySQL did not become ready in time');
}

async function waitForRedisCache(containerId: string, stackName: string, timeoutMs: number) {
  const start = Date.now();
  let currentId = containerId;
  const probe = [
    '$host="redis-cache";',
    '$port=6379;',
    '$fp=@fsockopen($host,$port,$errno,$errstr,1);',
    'if(!$fp){fwrite(STDERR,$errstr ?: "connect failed"); exit(1);} fclose($fp);',
  ].join(' ');
  while (Date.now() - start < timeoutMs) {
    try {
      await runCommandCapture('docker', ['exec', currentId, 'php', '-r', probe]);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('No such container') || message.includes('is not running')) {
        try {
          currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
        } catch {
          // ignore; retry with previous container id
        }
      }
      await delay(2000);
    }
  }
  throw new Error('Redis cache did not become ready in time');
}

async function restoreDatabase(
  containerId: string,
  encryptedPath: string,
  workDir: string,
  dbName: string
) {
  const decryptedPath = path.join(workDir, 'db.sql.zst');
  const sqlPath = path.join(workDir, 'db.sql');
  const sanitizedPath = path.join(workDir, 'db.sanitized.sql');

  await runCommand('age', ['-d', '-i', STACK_MASTER_KEY_PATH, '-o', decryptedPath, encryptedPath]);
  await runCommand('zstd', ['-d', '-f', '-o', sqlPath, decryptedPath]);
  await stripDefiners(sqlPath, sanitizedPath);

  await runCommand('docker', ['cp', sanitizedPath, `${containerId}:/tmp/mz-restore.sql`]);
  const safeDbName = dbName.replace(/`/g, '``');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    [
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -e "CREATE DATABASE IF NOT EXISTS \\\`${safeDbName}\\\`;"`,
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" --database="${safeDbName}" < /tmp/mz-restore.sql`,
    ].join(' && '),
  ]);
}

async function syncDatabaseUser(containerId: string, dbName: string, dbUser: string) {
  const safeDbName = dbName.replace(/`/g, '``');
  const safeDbUser = dbUser.replace(/'/g, "''");
  const grantStatement =
    'GRANT ALL PRIVILEGES ON ' +
    safeDbName +
    ".* TO '" +
    safeDbUser +
    "'@'%'; FLUSH PRIVILEGES;";
  const dbPassRef = '${DB_PASS}';
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    [
      'set -e',
      'DB_PASS="$(cat /run/secrets/db_password)"',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -e "CREATE USER IF NOT EXISTS '${safeDbUser}'@'%' IDENTIFIED BY '${dbPassRef}';"`,
      `mariadb -uroot -p"$ROOT_PASS" -e "ALTER USER '${safeDbUser}'@'%' IDENTIFIED BY '${dbPassRef}';"`,
      `mariadb -uroot -p"$ROOT_PASS" -e "${grantStatement}"`,
    ].join(' && '),
  ]);
}

async function syncReplicationUser(containerId: string, replicaUser: string) {
  const safeReplicaUser = replicaUser.replace(/'/g, "''");
  const grantStatement =
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO '" +
    safeReplicaUser +
    "'@'%'; FLUSH PRIVILEGES;";
  const passRef = '${REPL_PASS}';
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    [
      'set -e',
      'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -e "CREATE USER IF NOT EXISTS '${safeReplicaUser}'@'%' IDENTIFIED BY '${passRef}';"`,
      `mariadb -uroot -p"$ROOT_PASS" -e "ALTER USER '${safeReplicaUser}'@'%' IDENTIFIED BY '${passRef}';"`,
      `mariadb -uroot -p"$ROOT_PASS" -e "${grantStatement}"`,
    ].join(' && '),
  ]);
}

async function configureReplica(containerId: string, masterHost: string, replicaUser: string) {
  const safeMasterHost = masterHost.replace(/'/g, "''");
  const safeReplicaUser = replicaUser.replace(/'/g, "''");
  const passRef = '${REPL_PASS}';
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    [
      'set -e',
      'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -e "CHANGE MASTER TO MASTER_HOST='${safeMasterHost}', MASTER_PORT=3306, MASTER_USER='${safeReplicaUser}', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos;"`,
      'mariadb -uroot -p"$ROOT_PASS" -e "START SLAVE;"',
    ].join(' && '),
  ]);
}

async function runDatabaseCommandWithRetry(
  stackName: string,
  containerId: string,
  command: string,
  timeoutMs = 60 * 1000
): Promise<string> {
  try {
    await runCommand('docker', ['exec', containerId, 'sh', '-c', command]);
    return containerId;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`db command failed on ${containerId}: ${message}`);
  }

  const refreshedId = await waitForContainer(stackName, 'database', timeoutMs);
  if (refreshedId !== containerId) {
    await waitForDatabase(refreshedId, timeoutMs);
  }
  await runCommand('docker', ['exec', refreshedId, 'sh', '-c', command]);
  return refreshedId;
}

async function setSearchEngine(
  stackName: string,
  containerId: string,
  dbName: string,
  engine: string
): Promise<string> {
  const safeDbName = dbName.replace(/`/g, '``');
  const command = `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/engine', '${engine}') ON DUPLICATE KEY UPDATE value=VALUES(value);"`;
  return runDatabaseCommandWithRetry(stackName, containerId, command);
}

function escapeSqlValue(value: string): string {
  return value.replace(/'/g, "''");
}

async function databaseHasTables(containerId: string, dbName: string): Promise<boolean> {
  const safeSchema = escapeSqlValue(dbName);
  const result = await runCommandCapture('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `ROOT_PASS="$(cat /run/secrets/db_root_password)"; mariadb -uroot -p"$ROOT_PASS" -N -s -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${safeSchema}'"`,
  ]);
  const count = Number(result.stdout.trim());
  if (!Number.isFinite(count)) {
    throw new Error(`Unable to determine table count for schema ${dbName}`);
  }
  return count > 0;
}

async function setFullPageCacheConfig(containerId: string, dbName: string, ttlSeconds: number) {
  const safeDbName = dbName.replace(/`/g, '``');
  const ttl = Number.isFinite(ttlSeconds) ? Math.max(60, Math.floor(ttlSeconds)) : 86400;
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/caching_application', '2') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/ttl', '${ttl}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`,
  ]);
}

async function setVarnishConfig(
  containerId: string,
  dbName: string,
  backendHost: string,
  backendPort: string,
  accessList: string,
  gracePeriod: string
) {
  const safeDbName = dbName.replace(/`/g, '``');
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/backend_host', '${backendHost}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/backend_port', '${backendPort}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/access_list', '${accessList}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/grace_period', '${gracePeriod}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`,
  ]);
}

async function setBaseUrls(containerId: string, dbName: string, baseUrl: string) {
  const safeDbName = dbName.replace(/`/g, '``');
  const normalized = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/unsecure/base_url', '${normalized}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/base_url', '${normalized}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/use_in_frontend', '1') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/use_in_adminhtml', '1') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`,
  ]);
}

async function setOpensearchSystemConfig(
  stackName: string,
  containerId: string,
  dbName: string,
  host: string,
  port: string,
  timeout: string
): Promise<string> {
  const safeDbName = dbName.replace(/`/g, '``');
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_hostname', '${host}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_port', '${port}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_timeout', '${timeout}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  const command = `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`;
  return runDatabaseCommandWithRetry(stackName, containerId, command);
}

const MAGENTO_DB_OVERRIDE_ENV = {
  MZ_DB_HOST: 'database',
  MZ_DB_PORT: '3306',
};

function buildDockerEnvArgs(env: Record<string, string> | undefined) {
  if (!env) {
    return [] as string[];
  }
  const args: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    args.push('-e', `${key}=${value}`);
  }
  return args;
}

async function ensureMagentoEnvWrapper(containerId: string) {
  const command = [
    'set -e;',
    'if [ -f /var/www/html/magento/app/etc/env.php ]; then',
    '  if [ ! -f /var/www/html/magento/app/etc/env.base.php ]; then',
    '    cp /var/www/html/magento/app/etc/env.php /var/www/html/magento/app/etc/env.base.php;',
    '  elif ! grep -q "env.base.php" /var/www/html/magento/app/etc/env.php; then',
    '    cp /var/www/html/magento/app/etc/env.php /var/www/html/magento/app/etc/env.base.php;',
    '  fi;',
    '  cp /usr/local/share/mz-env.php /var/www/html/magento/app/etc/env.php;',
    '  chown www-data:www-data /var/www/html/magento/app/etc/env.php /var/www/html/magento/app/etc/env.base.php;',
    'fi',
  ].join(' ');
  const result = await runCommandCaptureWithStatus('docker', ['exec', '--user', 'root', containerId, 'sh', '-c', command]);
  if (result.code !== 0) {
    const output = (result.stderr || result.stdout || '').trim();
    throw new Error(`env.php wrapper failed (exit ${result.code}): ${output || 'unknown error'}`);
  }
}

async function ensureMagentoEnvWrapperWithRetry(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
) {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      await ensureMagentoEnvWrapper(currentId);
      return currentId;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('is not running') || message.includes('No such container') || message.includes('exited with code 128')) {
        log(`env.php wrapper retry ${attempt}: ${message}`);
        currentId = await waitForContainer(stackName, 'php-fpm-admin', 5 * 60 * 1000);
        continue;
      }
      throw error;
    }
  }
  return currentId;
}

async function runMagentoCommandCapture(
  containerId: string,
  command: string,
  env: Record<string, string> = MAGENTO_DB_OVERRIDE_ENV,
) {
  const envArgs = buildDockerEnvArgs(env);
  return await runCommandCapture('docker', ['exec', ...envArgs, containerId, 'sh', '-c', command]);
}

async function runMagentoCommandWithStatus(
  containerId: string,
  command: string,
  env: Record<string, string> = MAGENTO_DB_OVERRIDE_ENV,
) {
  const envArgs = buildDockerEnvArgs(env);
  return await runCommandCaptureWithStatus('docker', ['exec', ...envArgs, containerId, 'sh', '-c', command]);
}

type HttpProbeResult = {
  url: string;
  status: number;
  ok: boolean;
  detail?: string;
};

async function probeHttpViaBackendNetwork(
  url: string,
  hostHeader: string | undefined,
  timeoutSeconds: number,
): Promise<HttpProbeResult> {
  const args = [
    'run',
    '--rm',
    '--network',
    'mz-backend',
    'curlimages/curl:8.5.0',
    '-sS',
    '-o',
    '/dev/null',
    '-w',
    '%{http_code}',
    '-m',
    String(timeoutSeconds),
  ];
  if (hostHeader) {
    args.push('-H', `Host: ${hostHeader}`);
  }
  args.push(url);

  const result = await runCommandCaptureWithStatus('docker', args);
  const raw = (result.stdout || '').trim();
  const status = Number(raw);
  const stderr = (result.stderr || '').trim();

  if (!Number.isFinite(status)) {
    return {
      url,
      status: 0,
      ok: false,
      detail: stderr || `unexpected curl output: ${raw || '(empty)'}`,
    };
  }

  return {
    url,
    status,
    ok: status >= 200 && status < 400,
    detail: stderr || undefined,
  };
}

async function runPostDeploySmokeChecks(
  stackName: string,
  envHostname: string,
  log: (message: string) => void,
) {
  const hostHeader = envHostname.trim() || undefined;
  const checks: Array<{ name: string; url: string; timeoutSeconds: number; expectStatus?: number }> = [
    { name: 'nginx.mz-healthz', url: 'http://nginx/mz-healthz', timeoutSeconds: 10, expectStatus: 200 },
    { name: 'varnish.mz-healthz', url: 'http://varnish/mz-healthz', timeoutSeconds: 10, expectStatus: 200 },
    { name: 'nginx.health_check.php', url: 'http://nginx/health_check.php', timeoutSeconds: 30, expectStatus: 200 },
    // Root path can redirect (302) to https://<hostname>/, so accept any 2xx/3xx.
    { name: 'varnish.root', url: 'http://varnish/', timeoutSeconds: 30 },
  ];

  log('running post-deploy smoke checks');
  const deadline = Date.now() + 3 * 60 * 1000;
  let lastSummary = '';

  while (Date.now() < deadline) {
    const results: HttpProbeResult[] = [];
    for (const check of checks) {
      const result = await probeHttpViaBackendNetwork(check.url, hostHeader, check.timeoutSeconds);
      const ok = check.expectStatus ? result.status === check.expectStatus : result.ok;
      results.push({ ...result, ok });
    }

    const failed = results
      .map((result, index) => ({ result, spec: checks[index] }))
      .filter(({ result, spec }) => {
        const expected = spec.expectStatus;
        if (expected) {
          return result.status !== expected;
        }
        return !result.ok;
      });

    if (!failed.length) {
      log('post-deploy smoke checks passed');
      return;
    }

    lastSummary = failed
      .map(({ result, spec }) => {
        const expected = spec.expectStatus ? String(spec.expectStatus) : '2xx/3xx';
        const detail = result.detail ? ` (${result.detail})` : '';
        return `${spec.name} expected ${expected} got ${result.status}${detail}`;
      })
      .join('; ');

    log(`post-deploy smoke checks not ready: ${lastSummary}`);
    await delay(5000);
  }

  throw new Error(`Post-deploy smoke checks failed: ${lastSummary || 'unknown error'}`);
}

async function enforceMagentoPerformance(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
) {
  log('ensuring Magento production mode + caches');
  const checkScript = [
    'set -e;',
    'test -f /var/www/html/magento/app/etc/env.php;',
    'test -f /var/www/html/magento/app/etc/env.base.php;',
    'grep -q "env.base.php" /var/www/html/magento/app/etc/env.php;',
    'grep -q "MAGE_MODE" /var/www/html/magento/app/etc/env.php;',
    'grep -q "cache_types" /var/www/html/magento/app/etc/env.php;',
  ].join(' ');
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(currentId, checkScript);
    if (result.code === 0) {
      log('Magento production mode + caches confirmed');
      return;
    }
    const output = (result.stderr || result.stdout || '').trim();
    if (!output || output.includes('No such container') || output.includes('is not running')) {
      log(`performance check retry ${attempt}: ${output || `exit ${result.code}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 5 * 60 * 1000);
      await delay(3000);
      continue;
    }
    throw new Error(`Magento performance config not set: ${output}`);
  }
  throw new Error('Magento performance config not set: unknown error');
}

async function runSetupUpgradeWithRetry(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
) {
  const maxAttempts = 3;
  let lastError: Error | null = null;
  let adminContainerId = containerId;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      adminContainerId = await ensureMagentoEnvWrapperWithRetry(adminContainerId, stackName, log);
      const result = await runMagentoCommandWithStatus(
        adminContainerId,
        'php bin/magento setup:upgrade --keep-generated',
      );
      if (result.code === 0) {
        return { warning: false };
      }
      const output = (result.stderr || result.stdout || '').trim();
      if (result.code === 137) {
        return { warning: true, message: 'setup:upgrade killed (OOM); continuing deploy' };
      }
      if (output && output.includes('OpenSearch') && output.includes('default website')) {
        return { warning: true, message: output };
      }
      throw new Error(`setup:upgrade failed (exit ${result.code}): ${output}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (
        message.includes('Connection refused')
        || message.includes('is not running')
        || message.includes('Connection to Redis')
        || message.includes('redis-cache')
      ) {
        lastError = error instanceof Error ? error : new Error(message);
        log(`setup:upgrade attempt ${attempt} failed: ${message}`);
        await delay(5000);
        adminContainerId = await waitForContainer(stackName, 'php-fpm-admin', 5 * 60 * 1000);
        await waitForRedisCache(adminContainerId, stackName, 5 * 60 * 1000);
        continue;
      }
      throw error;
    }
  }
  throw lastError || new Error('setup:upgrade failed after retries');
}

async function reportDeploymentStatus(
  baseUrl: string,
  nodeId: string,
  nodeSecret: string,
  payload: { deployment_id: string; environment_id: number; status: string; message?: string }
) {
  const body = JSON.stringify(payload);
  const url = new URL('/v1/deploy/status', baseUrl);
  const headers = buildNodeHeaders('POST', url.pathname, url.search.slice(1), body, nodeId, nodeSecret);
  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...headers,
    },
    body,
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`mz-control status update failed: ${response.status} - ${errorBody}`);
  }
}

async function processDeployment(recordPath: string) {
  const raw = fs.readFileSync(recordPath, 'utf8');
  const record = JSON.parse(raw) as DeploymentRecord;
  const deploymentId = record.id || path.basename(recordPath, '.json');
  const payload = record.payload || {};
  const artifactKey = String(payload.artifact || '').trim();
  const stackId = Number(payload.stack_id ?? 0);
  const environmentId = Number(payload.environment_id ?? 0);
  const ref = String(payload.ref || '').trim();
  const logPrefix = `[deploy ${deploymentId}]`;
  const log = (message: string) => {
    console.log(`${logPrefix} ${message}`);
  };

  if (!artifactKey || !stackId || !environmentId) {
    throw new Error('Deployment payload missing artifact/stack/environment');
  }
  log(`start stack=${stackId} env=${environmentId} artifact=${artifactKey}`);

  const config = readConfig();
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!baseUrl || !nodeId || !nodeSecret) {
    throw new Error('Missing mz-control base URL or node credentials');
  }

  await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
    deployment_id: deploymentId,
    environment_id: environmentId,
    status: 'deploying',
  });
  log('reported deploying status');

  await ensureCloudSwarmRepo();
  log('cloud-swarm repo updated');

  const envRecord = await fetchEnvironmentRecord(stackId, environmentId, baseUrl, nodeId, nodeSecret);
  if (!envRecord) {
    throw new Error(`Environment ${environmentId} not found in stack ${stackId}`);
  }
  log('fetched environment record');
  const selections = envRecord?.application_selections;
  const versions = resolveVersionEnv(selections);
  const searchEngine = process.env.MZ_SEARCH_ENGINE || 'opensearch';
  const opensearchHost = process.env.MZ_OPENSEARCH_HOST || 'opensearch';
  const opensearchPort = process.env.MZ_OPENSEARCH_PORT || '9200';
  const opensearchTimeout = process.env.MZ_OPENSEARCH_TIMEOUT || '15';

  const r2 = readR2CredFile(environmentId);
  if (!r2?.backups) {
    throw new Error('Missing R2 backup credentials');
  }

  const objectKey = String(envRecord?.db_backup_object || DEFAULT_DB_BACKUP_OBJECT).replace(/^\/+/, '');
  const workDir = path.join(DEPLOY_WORK_DIR, deploymentId);
  ensureDir(workDir);

  const artifactPath = path.join(workDir, path.basename(artifactKey));
  log('downloading build artifact');
  await downloadArtifact(r2.backups, artifactKey, artifactPath);
  log('downloaded build artifact');

  const logDir = path.join(workDir, 'logs');
  ensureDir(logDir);

  const imageTag = resolveImageTag(artifactKey, ref, deploymentId);
  const mageVersion = `env-${environmentId}-${imageTag}`;
  const defaultVersions = readVersionDefaults();
  const overrideVersions: Record<string, string> = {};
  if (versions.phpVersion) overrideVersions.PHP_VERSION = versions.phpVersion;
  if (versions.varnishVersion) overrideVersions.VARNISH_VERSION = versions.varnishVersion;
  if (versions.mariadbVersion) overrideVersions.MARIADB_VERSION = versions.mariadbVersion;
  if (versions.opensearchVersion) overrideVersions.OPENSEARCH_VERSION = versions.opensearchVersion;
  if (versions.redisVersion) overrideVersions.REDIS_VERSION = versions.redisVersion;
  if (versions.rabbitmqVersion) overrideVersions.RABBITMQ_VERSION = versions.rabbitmqVersion;

  const planner = await buildPlannerPayload();
  const plannerResources = planner?.resources?.services;
  if (!plannerResources) {
    throw new Error('Planner did not provide resource sizing');
  }
  const plannerResourceEnv = buildPlannerResourceEnv(plannerResources);
  const tuningPayload = planner?.tuning as PlannerTuningPayloadLike | undefined;
  const activeProfile = resolveActiveProfile(tuningPayload);
  const configEnv = buildConfigEnv(activeProfile?.config_changes || []);

  const replicaUser = 'replica';
  let replicaHost = 'database';
  let replicaEnabled = false;
  const envTypeRaw = String(envRecord?.environment_type || '').trim().toLowerCase();
  const envEligible = envTypeRaw === ''
    ? true
    : ['production', 'performance', 'staging'].includes(envTypeRaw);
  try {
    const capacity = await buildCapacityPayload();
    const readyNodes = (capacity.nodes || []).filter(
      (node) => node.status === 'ready' && node.availability === 'active',
    );
    const hasReplicaLabel = readyNodes.some((node) => node.labels?.database_replica === 'true');
    replicaEnabled = envEligible && hasReplicaLabel && readyNodes.length > 1;
    if (replicaEnabled) {
      replicaHost = 'database-replica';
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`capacity unavailable; defaulting replica host to database (${message})`);
  }

  const envVars: NodeJS.ProcessEnv = {
    ...process.env,
    ...defaultVersions,
    ...overrideVersions,
    ...plannerResourceEnv,
    ...configEnv,
    REGISTRY_HOST: 'registry',
    REGISTRY_PUSH_HOST: '127.0.0.1',
    REGISTRY_PORT: '5000',
    SECRET_VERSION,
    MAGE_VERSION: mageVersion,
    MYSQL_DATABASE: process.env.MYSQL_DATABASE || 'magento',
    MYSQL_USER: process.env.MYSQL_USER || 'magento',
    MZ_DB_HOST: 'proxysql',
    MZ_DB_PORT: '6033',
    MZ_PROXYSQL_DB_HOST: 'database',
    MZ_PROXYSQL_DB_REPLICA_HOST: replicaHost,
    MZ_PROXYSQL_DB_PORT: '3306',
    MZ_MARIADB_MASTER_HOST: 'database',
    MZ_REPLICATION_USER: replicaUser,
    MZ_DATABASE_REPLICA_REPLICAS: replicaEnabled ? '1' : '0',
    MZ_SEARCH_ENGINE: searchEngine,
    MZ_OPENSEARCH_HOST: opensearchHost,
    MZ_OPENSEARCH_PORT: opensearchPort,
    MZ_OPENSEARCH_TIMEOUT: opensearchTimeout,
  };
  assertRequiredEnv(envVars, [
    'MAGE_VERSION',
    'VARNISH_VERSION',
    'MARIADB_VERSION',
    'PROXYSQL_VERSION',
    'OPENSEARCH_VERSION',
    'REDIS_VERSION',
    'RABBITMQ_VERSION',
    'PHP_VERSION',
    'NGINX_VERSION',
    ...RESOURCE_ENV_KEYS,
  ]);
  const renderedStack = await runCommandCapture('docker', [
    'stack',
    'config',
    '-c',
    path.join(CLOUD_SWARM_DIR, 'stacks/magento.yml'),
  ], { env: envVars });
  assertNoLatestImages(renderedStack.stdout);

  const secrets = envRecord?.environment_secrets ?? null;
  const envHostname = String(envRecord?.environment_hostname || envRecord?.hostname || '').trim();
  const envBaseUrl = envHostname ? `https://${envHostname.replace(/^https?:\/\//, '').replace(/\/+$/, '')}` : '';
  const dbSecretName = `mz_db_password_v${SECRET_VERSION}`;
  const dbRootSecretName = `mz_db_root_password_v${SECRET_VERSION}`;
  const dbReplicationSecretName = `mz_db_replication_password_v${SECRET_VERSION}`;
  const rabbitSecretName = `mz_rabbitmq_password_v${SECRET_VERSION}`;
  const mageSecretName = `mz_mage_crypto_key_v${SECRET_VERSION}`;

  log('ensuring docker secrets');
  await ensureDockerSecret(dbSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(dbRootSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(dbReplicationSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(rabbitSecretName, generateSecretHex(24), workDir);

  if (!secrets?.crypt_key) {
    throw new Error('Missing Magento crypt key for environment');
  }
  await ensureDockerSecret(mageSecretName, secrets.crypt_key, workDir);
  log('docker secrets ready');

  await runCommandLogged(
    'bash',
    [path.join(CLOUD_SWARM_DIR, 'scripts/build-services.sh')],
    { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-services' }
  );
  log('built base services');
  await runCommandLogged(
    'bash',
    [path.join(CLOUD_SWARM_DIR, 'scripts/build-magento.sh'), artifactPath],
    { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-magento' }
  );
  log('built magento images');

  const stackName = `mz-env-${environmentId}`;
  await runCommandLogged('docker', [
    'stack',
    'deploy',
    '--with-registry-auth',
    '-c',
    path.join(CLOUD_SWARM_DIR, 'stacks/magento.yml'),
    stackName,
  ], { env: envVars, logDir, label: 'stack-deploy' });
  log('stack deployed');

  let dbContainerId = await waitForContainer(stackName, 'database', 5 * 60 * 1000);
  await waitForDatabase(dbContainerId, 5 * 60 * 1000);

  const dbName = envVars.MYSQL_DATABASE || 'magento';
  const hasTables = await databaseHasTables(dbContainerId, dbName);
  if (hasTables) {
    log('database already populated; skipping restore');
  } else {
    const encryptedBackupPath = path.join(workDir, path.basename(objectKey));
    await downloadArtifact(r2.backups, objectKey, encryptedBackupPath);
    await restoreDatabase(dbContainerId, encryptedBackupPath, workDir, dbName);
    log('database restored');
  }
  await syncDatabaseUser(
    dbContainerId,
    dbName,
    envVars.MYSQL_USER || 'magento'
  );
  log('database user synced');
  await syncReplicationUser(dbContainerId, replicaUser);
  log('replication user synced');
  if (envBaseUrl) {
    await setBaseUrls(dbContainerId, envVars.MYSQL_DATABASE || 'magento', envBaseUrl);
    log(`base URLs set to ${envBaseUrl}`);
  }

  if (replicaHost === 'database-replica') {
    try {
      const replicaContainerId = await waitForContainer(stackName, 'database-replica', 5 * 60 * 1000);
      await waitForDatabase(replicaContainerId, 5 * 60 * 1000);
      await configureReplica(replicaContainerId, 'database', replicaUser);
      log('replica configured');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log(`replica setup skipped: ${message}`);
    }
  }

  let adminContainerId = await waitForContainer(stackName, 'php-fpm-admin', 5 * 60 * 1000);
  const webContainerId = await findLocalContainer(stackName, 'php-fpm');
  const writePathCommand = 'mkdir -p /var/www/html/magento/var/log /var/www/html/magento/var/report /var/www/html/magento/var/session /var/www/html/magento/var/cache /var/www/html/magento/var/page_cache /var/www/html/magento/var/tmp /var/www/html/magento/var/export /var/www/html/magento/var/import /var/www/html/magento/pub/media && chmod -R 0777 /var/www/html/magento/var/log /var/www/html/magento/var/report /var/www/html/magento/var/session /var/www/html/magento/var/cache /var/www/html/magento/var/page_cache /var/www/html/magento/var/tmp /var/www/html/magento/var/export /var/www/html/magento/var/import /var/www/html/magento/pub/media';
  try {
    await runCommand('docker', [
      'exec',
      '--user',
      'root',
      adminContainerId,
      'sh',
      '-c',
      writePathCommand,
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`php-fpm-admin write path setup failed: ${message}`);
    try {
      const refreshedAdminId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      if (refreshedAdminId && refreshedAdminId !== adminContainerId) {
        adminContainerId = refreshedAdminId;
        await runCommand('docker', [
          'exec',
          '--user',
          'root',
          adminContainerId,
          'sh',
          '-c',
          writePathCommand,
        ]);
        log('php-fpm-admin write path setup retry succeeded');
      }
    } catch (retryError) {
      const retryMessage = retryError instanceof Error ? retryError.message : String(retryError);
      log(`php-fpm-admin write path setup retry skipped: ${retryMessage}`);
    }
  }
  if (!webContainerId) {
    log('php-fpm container not on manager; skipping write path setup');
  } else {
    await runCommand('docker', [
      'exec',
      '--user',
      'root',
      webContainerId,
      'sh',
      '-c',
      writePathCommand,
    ]).catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      log(`php-fpm write path setup skipped: ${message}`);
    });
  }
  let upgradeWarning = false;
  dbContainerId = await setOpensearchSystemConfig(
    stackName,
    dbContainerId,
    envVars.MYSQL_DATABASE || 'magento',
    opensearchHost,
    opensearchPort,
    opensearchTimeout
  );
  dbContainerId = await setSearchEngine(stackName, dbContainerId, envVars.MYSQL_DATABASE || 'magento', 'mysql');
  await waitForProxySql(adminContainerId, stackName, 5 * 60 * 1000);
  await waitForRedisCache(adminContainerId, stackName, 5 * 60 * 1000);
  adminContainerId = await ensureMagentoEnvWrapperWithRetry(adminContainerId, stackName, log);
  try {
    const upgradeResult = await runSetupUpgradeWithRetry(adminContainerId, stackName, log);
    upgradeWarning = upgradeResult.warning;
    if (upgradeWarning && upgradeResult.message) {
      console.warn(`${logPrefix} setup:upgrade warning: ${upgradeResult.message}`);
    }
  } catch (error) {
    throw error;
  } finally {
    dbContainerId = await setSearchEngine(stackName, dbContainerId, envVars.MYSQL_DATABASE || 'magento', searchEngine);
  }
  if (!upgradeWarning) {
    await setFullPageCacheConfig(
      dbContainerId,
      envVars.MYSQL_DATABASE || 'magento',
      86400,
    );
    await setVarnishConfig(
      dbContainerId,
      envVars.MYSQL_DATABASE || 'magento',
      'nginx',
      '80',
      'localhost,127.0.0.1,nginx,php-fpm,php-fpm-admin,varnish',
      '300',
    );
  }
  adminContainerId = await ensureMagentoEnvWrapperWithRetry(adminContainerId, stackName, log);
  await enforceMagentoPerformance(adminContainerId, stackName, log);
  log('magento upgrade complete');

  if (envHostname) {
    await runPostDeploySmokeChecks(stackName, envHostname, log);
  } else {
    log('post-deploy smoke checks skipped: no environment hostname available');
  }

  await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
    deployment_id: deploymentId,
    environment_id: environmentId,
    status: 'active',
  });

  try {
    await cleanupDeploymentResources({
      environmentId,
      repository: String(payload.repository || ''),
      artifactKey,
      mageVersion,
      stackName,
      r2,
    });
    log('cleanup complete');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`cleanup skipped: ${message}`);
  }
}

async function handleDeploymentFile(recordPath: string) {
  const failedDir = path.join(DEPLOY_QUEUE_DIR, 'failed');
  ensureDir(failedDir);
  try {
    await processDeployment(recordPath);
    fs.unlinkSync(recordPath);
  } catch (error) {
    const failedRecord = {
      error: error instanceof Error ? error.message : String(error),
      failed_at: new Date().toISOString(),
    };
    const failedPath = path.join(failedDir, path.basename(recordPath));
    const payload = fs.existsSync(recordPath) ? fs.readFileSync(recordPath, 'utf8') : '{}';
    let existing: Record<string, unknown> = {};
    try {
      existing = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      existing = {};
    }
    const merged = { ...existing, ...failedRecord } as Record<string, any>;
    fs.writeFileSync(failedPath, JSON.stringify(merged, null, 2));
    try {
      fs.unlinkSync(recordPath);
    } catch {
      // ignore
    }
    cleanupFailedWorkDirs();

    const config = readConfig();
    const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
    const nodeId = readNodeFile('node-id');
    const nodeSecret = readNodeFile('node-secret');
    const environmentId = Number(merged?.payload?.environment_id ?? 0);
    if (baseUrl && nodeId && nodeSecret && environmentId) {
      try {
        await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
          deployment_id: merged?.id || path.basename(recordPath, '.json'),
          environment_id: environmentId,
          status: 'failed',
          message: failedRecord.error,
        });
      } catch {
        // ignore secondary failures
      }
    }

    console.error('deploy.worker.failed', failedRecord);
  }
}

async function tick() {
  if (processing) {
    return;
  }
  if (shutdownRequested) {
    return;
  }
  if (isDeployPaused()) {
    return;
  }
  if (!(await isSwarmManager())) {
    return;
  }
  const next = claimNextDeployment();
  if (!next) {
    return;
  }
  processing = true;
  currentDeploymentPath = next;
  try {
    await handleDeploymentFile(next);
  } finally {
    processing = false;
    currentDeploymentPath = null;
    notifyProcessingDone();
  }
}

export function startDeploymentWorker() {
  if (process.env.MZ_DEPLOY_WORKER_ENABLED === '0') {
    return;
  }
  ensureDir(DEPLOY_QUEUE_DIR);
  ensureDir(DEPLOY_WORK_DIR);
  recoverProcessingQueue();
  process.on('SIGTERM', () => {
    void initiateShutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    void initiateShutdown('SIGINT');
  });
  void tick();
  setInterval(() => {
    void tick();
  }, Number.isFinite(DEPLOY_INTERVAL_MS) && DEPLOY_INTERVAL_MS > 1000 ? DEPLOY_INTERVAL_MS : 5000);
}
