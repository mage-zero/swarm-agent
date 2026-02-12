import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import { isDeployPaused } from './deploy-pause.js';
import { buildCapacityPayload, buildPlannerPayload, isSwarmManager, readConfig } from './status.js';
import { enforceCommandPolicy } from './command-policy.js';
import { parseListObjectsV2Xml } from './r2-list.js';

type DeployPayload = {
  artifact?: string;
  stack_id?: number;
  environment_id?: number;
  repository?: string;
  ref?: string;
  rollback_of?: string | null;
};

type DeploymentRecord = {
  id?: string;
  queued_at?: string;
  payload?: DeployPayload;
};

type R2PresignContext = {
  baseUrl: string;
  nodeId: string;
  nodeSecret: string;
  environmentId: number;
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
const DEPLOY_SMOKE_AUTO_HEAL_ENABLED = (process.env.MZ_DEPLOY_SMOKE_AUTO_HEAL_ENABLED || '1') !== '0';
const DEPLOY_SMOKE_AUTO_HEAL_ROUNDS = Math.max(0, Number(process.env.MZ_DEPLOY_SMOKE_AUTO_HEAL_ROUNDS || 1));
const DEPLOY_SMOKE_AUTO_ROLLBACK_ENABLED = (process.env.MZ_DEPLOY_SMOKE_AUTO_ROLLBACK_ENABLED || '0') === '1';
const RELEASE_COHORT_GATE_ENABLED = (process.env.MZ_RELEASE_COHORT_GATE_ENABLED || '1') !== '0';
const RELEASE_COHORT_GATE_TIMEOUT_MS = Math.max(10_000, Number(process.env.MZ_RELEASE_COHORT_GATE_TIMEOUT_MS || 5 * 60 * 1000));
const RELEASE_COHORT_LABEL_KEY = process.env.MZ_RELEASE_COHORT_LABEL_KEY || 'mz.release.cohort';
const RELEASE_COHORT_LABEL_VALUE = process.env.MZ_RELEASE_COHORT_LABEL_VALUE || 'magento';
const REGISTRY_CLEANUP_ENABLED = (process.env.MZ_REGISTRY_CLEANUP_ENABLED || '1') !== '0';
// Registry cleanup should hit the host-published registry port by default.
// Do not couple cleanup to REGISTRY_PUSH_HOST because Buildx pushes can occur
// from inside the BuildKit container (where loopback/service DNS differ).
const REGISTRY_CLEANUP_HOST = process.env.MZ_REGISTRY_CLEANUP_HOST || '127.0.0.1';
const REGISTRY_CLEANUP_PORT = process.env.MZ_REGISTRY_CLEANUP_PORT || '5000';
const DEPLOY_MIN_FREE_GB = Number(process.env.MZ_DEPLOY_MIN_FREE_GB || 15);
const DEPLOY_AGGRESSIVE_PRUNE_ENABLED = (process.env.MZ_DEPLOY_AGGRESSIVE_PRUNE_ENABLED || '1') !== '0';
const DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB = Number(
  process.env.MZ_DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB || DEPLOY_MIN_FREE_GB
);
const DEPLOY_ABORT_MIN_FREE_GB = Number(process.env.MZ_DEPLOY_ABORT_MIN_FREE_GB || 5);
const DEPLOY_BUILD_RETRIES = Math.max(0, Number(process.env.MZ_DEPLOY_BUILD_RETRIES || 1));
const REGISTRY_GC_ENABLED = (process.env.MZ_REGISTRY_GC_ENABLED || '0') === '1';
const REGISTRY_GC_SCRIPT = process.env.MZ_REGISTRY_GC_SCRIPT
  || path.join(process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm', 'scripts/registry-gc.sh');
const SHUTDOWN_GRACE_MS = Number(process.env.MZ_SHUTDOWN_GRACE_MS || 10 * 60 * 1000);
const CLOUD_SWARM_DIR = process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm';
const CLOUD_SWARM_REPO = process.env.MZ_CLOUD_SWARM_REPO || 'git@github.com:mage-zero/cloud-swarm.git';
const CLOUD_SWARM_KEY_PATH = process.env.MZ_CLOUD_SWARM_KEY_PATH || '/opt/mage-zero/keys/cloud-swarm-deploy';
const STACK_MASTER_KEY_PATH = process.env.MZ_STACK_MASTER_KEY_PATH || '/etc/magezero/stack_master_ssh';
const STACK_MASTER_PUBLIC_KEY_PATH = process.env.MZ_STACK_MASTER_PUBLIC_KEY_PATH || '/etc/magezero/stack_master_ssh.pub';
const DEFAULT_DB_BACKUP_OBJECT = process.env.MZ_DB_BACKUP_OBJECT || 'provisioning-database.sql.zst.age';
const SECRET_VERSION = process.env.MZ_SECRET_VERSION || '1';
const DEPLOY_INTERVAL_MS = Number(process.env.MZ_DEPLOY_WORKER_INTERVAL_MS || 5000);
const FETCH_TIMEOUT_MS = Number(process.env.MZ_FETCH_TIMEOUT_MS || 30000);
const MIB = 1024 * 1024;
const GIB = 1024 * 1024 * 1024;

type DeployProgressStepStatus = 'pending' | 'running' | 'ok' | 'failed' | 'skipped';
type DeployProgressStep = {
  index: number;
  id: string;
  label: string;
  status: DeployProgressStepStatus;
  started_at?: string;
  finished_at?: string;
  took_ms?: number;
  detail?: string;
  error?: string;
};
type DeployProgressState = {
  runbook_id: string;
  deployment_id: string;
  environment_id: number;
  status: 'running' | 'ok' | 'failed';
  started_at: string;
  updated_at: string;
  current?: {
    index: number;
    total: number;
    id: string;
    label: string;
    started_at: string;
    detail?: string;
  };
  steps: DeployProgressStep[];
  last_error?: string;
};

function writeJsonAtomic(filePath: string, payload: unknown) {
  try {
    const dir = path.dirname(filePath);
    ensureDir(dir);
    const tmp = `${filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
    fs.renameSync(tmp, filePath);
  } catch {
    // best-effort; do not fail deploy on progress logging issues
  }
}

function nowIso() {
  return new Date().toISOString();
}

class DeployProgress {
  private state: DeployProgressState;
  private progressPath: string;

  constructor(
    progressPath: string,
    runbookId: string,
    deploymentId: string,
    environmentId: number,
    steps: Array<{ id: string; label: string }>
  ) {
    this.progressPath = progressPath;
    const startedAt = nowIso();
    this.state = {
      runbook_id: runbookId,
      deployment_id: deploymentId,
      environment_id: environmentId,
      status: 'running',
      started_at: startedAt,
      updated_at: startedAt,
      steps: steps.map((s, idx) => ({
        index: idx + 1,
        id: s.id,
        label: s.label,
        status: 'pending',
      })),
    };
    this.flush();
  }

  private flush() {
    this.state.updated_at = nowIso();
    writeJsonAtomic(this.progressPath, this.state);
  }

  private findStep(id: string) {
    return this.state.steps.find((s) => s.id === id) || null;
  }

  start(id: string, detail?: string) {
    const step = this.findStep(id);
    if (!step) return;
    if (step.status === 'ok' || step.status === 'failed' || step.status === 'skipped') {
      return;
    }
    step.status = 'running';
    step.started_at = nowIso();
    if (detail) step.detail = detail;
    this.state.current = {
      index: step.index,
      total: this.state.steps.length,
      id: step.id,
      label: step.label,
      started_at: step.started_at,
      detail: step.detail,
    };
    this.flush();
  }

  detail(id: string, detail: string) {
    const step = this.findStep(id);
    if (!step || step.status !== 'running') return;
    step.detail = detail;
    if (this.state.current && this.state.current.id === id) {
      this.state.current.detail = detail;
    }
    this.flush();
  }

  ok(id: string, detail?: string) {
    const step = this.findStep(id);
    if (!step) return;
    if (step.status === 'ok') return;
    if (detail) step.detail = detail;
    step.status = 'ok';
    step.finished_at = nowIso();
    if (step.started_at) {
      const took = Date.parse(step.finished_at) - Date.parse(step.started_at);
      if (Number.isFinite(took)) step.took_ms = Math.max(0, took);
    }
    if (this.state.current && this.state.current.id === id) {
      delete this.state.current;
    }
    this.flush();
  }

  skipped(id: string, reason: string) {
    const step = this.findStep(id);
    if (!step) return;
    step.status = 'skipped';
    step.detail = reason;
    step.finished_at = nowIso();
    if (this.state.current && this.state.current.id === id) {
      delete this.state.current;
    }
    this.flush();
  }

  fail(id: string, error: string) {
    const step = this.findStep(id);
    if (step) {
      step.status = 'failed';
      step.error = error;
      step.finished_at = nowIso();
      if (step.started_at) {
        const took = Date.parse(step.finished_at) - Date.parse(step.started_at);
        if (Number.isFinite(took)) step.took_ms = Math.max(0, took);
      }
    }
    this.state.status = 'failed';
    this.state.last_error = error;
    if (this.state.current && this.state.current.id === id) {
      this.state.current.detail = error;
    }
    this.flush();
  }

  doneOk() {
    this.state.status = 'ok';
    delete this.state.current;
    this.flush();
  }
}

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
  { service: 'mailhog', prefix: 'MZ_MAILHOG' },
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

function inferCommitShaFromArtifactKey(artifactKey: string): string {
  if (!artifactKey) return '';

  let key = artifactKey.trim();
  try {
    if (key.startsWith('http://') || key.startsWith('https://')) {
      const url = new URL(key);
      key = url.pathname.replace(/^\/+/, '');
    }
  } catch {
    // ignore URL parse failures; treat as object key
  }

  key = key.replace(/^\/+/, '');
  const file = key.split('/').pop() || '';
  const match =
    file.match(/^([0-9a-f]{7,64})\.tar(?:\.(?:zst|gz|bz2|xz))?$/i) ||
    file.match(/[-_]([0-9a-f]{7,64})\.tar(?:\.(?:zst|gz|bz2|xz))?$/i);
  return match ? match[1] : '';
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

async function getDeployFreeSpaceGb(): Promise<number | null> {
  return (await getFreeSpaceGb('/var/lib/docker')) ?? (await getFreeSpaceGb('/')) ?? null;
}

async function ensureMinimumFreeSpace(stage: string) {
  if (!DEPLOY_ABORT_MIN_FREE_GB || DEPLOY_ABORT_MIN_FREE_GB <= 0) {
    return;
  }
  const freeGb = await getDeployFreeSpaceGb();
  if (freeGb === null) {
    console.warn(`cleanup: ${stage}: free space unknown; skipping minimum-free check`);
    return;
  }
  if (freeGb < DEPLOY_ABORT_MIN_FREE_GB) {
    throw new Error(
      `Insufficient disk space (${freeGb}GB) for deploy ${stage}; minimum ${DEPLOY_ABORT_MIN_FREE_GB}GB required`
    );
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

async function deleteR2Object(r2: R2PresignContext, objectKey: string) {
  const normalizedKey = objectKey.replace(/^\/+/, '');
  const url = await presignR2ObjectUrl(r2, 'DELETE', normalizedKey, 3600);
  const { stdout } = await runCommandCapture('curl', ['-sS', '-o', '/dev/null', '-w', '%{http_code}', '-X', 'DELETE', url]);
  const code = Number(String(stdout || '').trim());
  if (code >= 200 && code < 300) {
    return;
  }
  // Treat missing objects as idempotent deletes.
  if (code === 404) {
    return;
  }
  throw new Error(`R2 delete failed: http ${code || 'unknown'} (${normalizedKey})`);
}

async function listR2ObjectsV2(r2: R2PresignContext, prefix: string): Promise<Array<{ key: string; lastModified: string }>> {
  const normalizedPrefix = prefix.replace(/^\/+/, '');
  const objects: Array<{ key: string; lastModified: string }> = [];
  let token: string | undefined;
  let guard = 0;
  while (guard < 50) {
    guard += 1;
    const url = await presignR2ListUrl(r2, normalizedPrefix, token, 1000, 3600);

    const marker = 'MZ_HTTP_CODE:';
    const { stdout } = await runCommandCapture('curl', ['-sS', '-w', `\\n${marker}%{http_code}`, url]);
    const out = String(stdout || '');
    const idx = out.lastIndexOf(marker);
    const body = idx === -1 ? out : out.slice(0, Math.max(0, idx - 1));
    const codeRaw = idx === -1 ? '' : out.slice(idx + marker.length).trim();
    const code = Number(codeRaw);
    if (code < 200 || code >= 300) {
      throw new Error(`R2 list failed: http ${code || 'unknown'}`);
    }

    const parsed = parseListObjectsV2Xml(body);
    objects.push(...parsed.objects);
    if (!parsed.isTruncated) {
      break;
    }
    token = parsed.nextContinuationToken || undefined;
    if (!token) {
      break;
    }
  }
  return objects;
}

async function enforceBuildArtifactRetentionInR2(params: {
  r2: R2PresignContext;
  artifactKey: string;
  keepArtifacts: string[];
  retainCount: number;
}) {
  const normalizedArtifactKey = params.artifactKey.replace(/^\/+/, '');
  if (!normalizedArtifactKey.startsWith('builds/') || !normalizedArtifactKey.endsWith('.tar.zst')) {
    return;
  }

  const prefix = `${path.posix.dirname(normalizedArtifactKey)}/`;
  let listed: Array<{ key: string; lastModified: string }> = [];
  try {
    listed = await listR2ObjectsV2(params.r2, prefix);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup: r2 list failed for ${prefix}: ${message}`);
    return;
  }

  const candidates = listed
    .map((item) => ({
      key: String(item.key || '').replace(/^\/+/, ''),
      lastModified: String(item.lastModified || ''),
      mtimeMs: Date.parse(String(item.lastModified || '')) || 0,
    }))
    .filter((item) => item.key.startsWith(prefix))
    .filter((item) => item.key.endsWith('.tar.zst'))
    .filter((item) => path.posix.basename(item.key).startsWith('build-'));

  if (candidates.length <= params.retainCount) {
    return;
  }

  const keepSet = new Set(
    params.keepArtifacts
      .map((key) => String(key || '').replace(/^\/+/, '').trim())
      .filter((key) => key.startsWith(prefix))
      .filter((key) => key.endsWith('.tar.zst'))
  );

  // If history is missing/partial, keep newest objects by LastModified to ensure we keep at least N.
  if (keepSet.size < params.retainCount) {
    const sorted = [...candidates].sort((a, b) => b.mtimeMs - a.mtimeMs);
    for (const item of sorted) {
      if (keepSet.size >= params.retainCount) break;
      keepSet.add(item.key);
    }
  }

  const deletions = candidates
    .map((item) => item.key)
    .filter((key) => !keepSet.has(key))
    .sort((a, b) => a.localeCompare(b));

  if (!deletions.length) {
    return;
  }

  console.warn(`cleanup: r2 builds retention prefix=${prefix} keep=${keepSet.size} delete=${deletions.length}`);
  for (const key of deletions) {
    try {
      await deleteR2Object(params.r2, key);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`cleanup: r2 delete failed for ${key}: ${message}`);
    }
  }
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

async function maybeAggressivePrune(stage: string) {
  if (!DEPLOY_AGGRESSIVE_PRUNE_ENABLED || DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB <= 0) {
    return;
  }
  const freeGb = await getDeployFreeSpaceGb();
  if (freeGb === null) {
    console.warn(`cleanup: ${stage}: free space unknown; skipping aggressive prune`);
    return;
  }
  if (freeGb >= DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB) {
    return;
  }

  console.warn(
    `cleanup: ${stage}: free space ${freeGb}GB < ${DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB}GB; running docker prune`
  );
  try {
    await runCommand('docker', ['system', 'prune', '-a', '--volumes', '-f']);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup: docker system prune failed: ${message}`);
  }
  try {
    await runCommand('docker', ['builder', 'prune', '-a', '-f']);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup: docker builder prune failed: ${message}`);
  }

  const afterGb = await getDeployFreeSpaceGb();
  if (afterGb !== null) {
    console.warn(`cleanup: ${stage}: free space now ${afterGb}GB`);
  }
}

async function cleanupDeploymentResources(params: {
  environmentId: number;
  repository: string;
  artifactKey: string;
  mageVersion: string;
  stackName: string;
  r2: R2PresignContext;
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

  for (const objectKey of removedArtifacts) {
    try {
      await deleteR2Object(params.r2, objectKey);
    } catch {
      // ignore cleanup errors
    }
  }

  // Builds uploaded to R2 under `builds/<owner>/<repo>/` can accumulate if history is lost or
  // uploads happen without deploy completion. After a successful deploy, enforce a hard cap of
  // `DEPLOY_RETAIN_COUNT` build artifacts in the build prefix (current + previous by default).
  await enforceBuildArtifactRetentionInR2({
    r2: params.r2,
    artifactKey: normalizedArtifactKey,
    keepArtifacts,
    retainCount: DEPLOY_RETAIN_COUNT,
  });

  const keepImageTagSet = new Set(keepImageTags);
  const removedImageTagSet = new Set(removedImageTags);
  const removals = await cleanupLocalImages(params.environmentId, keepImageTagSet, params.stackName);
  if (removedImageTagSet.size) {
    const filtered = removals.filter((item) => removedImageTagSet.has(item.tag));
    await cleanupRegistryImages(filtered);
    await runRegistryGc();
  }

  await maybeAggressivePrune('post-deploy');
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
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommand' });
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
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommandLogged' });
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

async function runCommandLoggedWithRetry(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; logDir: string; label: string },
  retryOptions: {
    retries: number;
    log?: (message: string) => void;
    onRetry?: (attempt: number, error: Error) => Promise<void>;
  }
) {
  const maxAttempts = Math.max(1, 1 + retryOptions.retries);
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt += 1;
    try {
      await runCommandLogged(command, args, options);
      return;
    } catch (error) {
      if (attempt >= maxAttempts) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      retryOptions.log?.(`retrying ${options.label} (attempt ${attempt}/${maxAttempts - 1}) after error: ${message}`);
      if (retryOptions.onRetry && error instanceof Error) {
        await retryOptions.onRetry(attempt, error);
      }
    }
  }
}

async function runCommandCapture(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommandCapture' });
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
  enforceCommandPolicy(command, args, { source: 'deploy-worker.runCommandCaptureWithStatus' });
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

/**
 * Migrate a global (non-env-scoped) secret to a per-environment secret by
 * reading the current value from a running container.  Returns true if the
 * per-env secret already exists or was successfully created.  Returns false
 * when no running container is available (fresh deploy – caller should fall
 * through to ensureDockerSecret which generates a new random value).
 */
async function migrateGlobalSecret(
  stackName: string,
  containerService: string,
  secretFileName: string,
  newSecretName: string,
  workDir: string,
): Promise<boolean> {
  try {
    await runCommandCapture('docker', ['secret', 'inspect', newSecretName]);
    return true; // already exists
  } catch {
    // not yet created
  }

  // Try to read the current value from a running container.
  let containerId: string | undefined;
  try {
    const { stdout } = await runCommandCapture('docker', [
      'ps', '--filter', `name=${stackName}_${containerService}`, '--format', '{{.ID}}',
    ]);
    containerId = stdout.trim().split('\n')[0] || undefined;
  } catch {
    // no running container
  }
  if (!containerId) return false;

  let value: string;
  try {
    const { stdout } = await runCommandCapture('docker', [
      'exec', containerId, 'cat', `/run/secrets/${secretFileName}`,
    ]);
    value = stdout.trim();
  } catch {
    return false;
  }
  if (!value) return false;

  ensureDir(workDir);
  const secretPath = path.join(workDir, `${newSecretName}.secret`);
  fs.writeFileSync(secretPath, value, { mode: 0o600 });
  try {
    await runCommand('docker', ['secret', 'create', newSecretName, secretPath]);
  } finally {
    try { fs.unlinkSync(secretPath); } catch { /* ignore */ }
  }
  return true;
}

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

async function presignR2ObjectUrl(
  r2: R2PresignContext,
  method: 'PUT' | 'GET' | 'DELETE',
  objectKey: string,
  expiresIn: number,
) {
  const payload = JSON.stringify({
    bucket: 'backups',
    method,
    object_key: objectKey,
    expires_in: expiresIn,
  });
  const response = await fetchJson(
    r2.baseUrl,
    `/v1/agent/environment/${r2.environmentId}/r2-presign`,
    'POST',
    payload,
    r2.nodeId,
    r2.nodeSecret,
  );
  const url = String((response as any)?.url || '').trim();
  if (!url) {
    throw new Error('mz-control r2-presign did not return url');
  }
  return url;
}

async function presignR2ListUrl(
  r2: R2PresignContext,
  prefix: string,
  continuationToken: string | undefined,
  maxKeys: number,
  expiresIn: number,
) {
  const payload = JSON.stringify({
    bucket: 'backups',
    method: 'LIST',
    prefix,
    max_keys: maxKeys,
    ...(continuationToken ? { continuation_token: continuationToken } : {}),
    expires_in: expiresIn,
  });
  const response = await fetchJson(
    r2.baseUrl,
    `/v1/agent/environment/${r2.environmentId}/r2-presign`,
    'POST',
    payload,
    r2.nodeId,
    r2.nodeSecret,
  );
  const url = String((response as any)?.url || '').trim();
  if (!url) {
    throw new Error('mz-control r2-presign did not return url');
  }
  return url;
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

async function downloadArtifact(r2: R2PresignContext, objectKeyOrUrl: string, targetPath: string) {
  const source = String(objectKeyOrUrl || '').trim();
  if (!source) {
    throw new Error('Missing R2 object key');
  }
  const normalizedKey = source.replace(/^\/+/, '');
  const url = source.startsWith('http://') || source.startsWith('https://')
    ? source
    : await presignR2ObjectUrl(r2, 'GET', normalizedKey, 3600);

  await runCommand('curl', ['-fsSL', url, '-o', targetPath]);
}

async function validateLocalArtifactArchive(artifactPath: string): Promise<boolean> {
  if (!fs.existsSync(artifactPath)) {
    return false;
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(artifactPath);
  } catch {
    return false;
  }
  if (!stat.isFile() || stat.size <= 0) {
    return false;
  }

  try {
    await runCommandCapture('zstd', ['-tq', artifactPath]);
    return true;
  } catch {
    return false;
  }
}

function listLocalArtifactCandidates(artifactFileName: string, currentWorkDir: string): string[] {
  if (!artifactFileName || !fs.existsSync(DEPLOY_WORK_DIR)) {
    return [];
  }

  const currentResolved = path.resolve(currentWorkDir);
  const candidates: Array<{ fullPath: string; mtimeMs: number }> = [];
  const entries = fs.readdirSync(DEPLOY_WORK_DIR, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const dirPath = path.join(DEPLOY_WORK_DIR, entry.name);
    if (path.resolve(dirPath) === currentResolved) {
      continue;
    }
    const candidate = path.join(dirPath, artifactFileName);
    if (!fs.existsSync(candidate)) {
      continue;
    }
    try {
      const stat = fs.statSync(candidate);
      if (!stat.isFile() || stat.size <= 0) {
        continue;
      }
      candidates.push({ fullPath: candidate, mtimeMs: stat.mtimeMs });
    } catch {
      continue;
    }
  }

  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return candidates.map((item) => item.fullPath);
}

async function tryReuseLocalArtifact(
  artifactFileName: string,
  currentWorkDir: string,
  targetPath: string,
  log: (message: string) => void
): Promise<{ sourcePath: string } | null> {
  const candidates = listLocalArtifactCandidates(artifactFileName, currentWorkDir);
  for (const sourcePath of candidates) {
    const valid = await validateLocalArtifactArchive(sourcePath);
    if (!valid) {
      log(`local artifact candidate invalid, skipping: ${sourcePath}`);
      continue;
    }
    fs.copyFileSync(sourcePath, targetPath);
    return { sourcePath };
  }
  return null;
}

async function uploadArtifact(r2: R2PresignContext, objectKey: string, sourcePath: string) {
  const normalizedKey = objectKey.replace(/^\/+/, '');
  const url = await presignR2ObjectUrl(r2, 'PUT', normalizedKey, 3600);
  await runCommand('curl', ['-fsSL', '-X', 'PUT', '-T', sourcePath, url]);
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
    '$host=getenv("MZ_REDIS_CACHE_HOST") ?: "redis-cache";',
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name');
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name');
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  const safeEngine = escapeSqlValue(String(engine || ''));
  const command = `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/engine', '${safeEngine}') ON DUPLICATE KEY UPDATE value=VALUES(value);"`;
  return runDatabaseCommandWithRetry(stackName, containerId, command);
}

function escapeSqlValue(value: string): string {
  return value.replace(/'/g, "''");
}

function assertSafeIdentifier(value: string, label: string) {
  const trimmed = String(value || '').trim();
  if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
    throw new Error(`Unsafe ${label} value: ${value}`);
  }
  return trimmed;
}

async function databaseHasTables(containerId: string, dbName: string): Promise<boolean> {
  assertSafeIdentifier(dbName, 'database name');
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  const safeBackendHost = escapeSqlValue(String(backendHost || ''));
  const safeBackendPort = escapeSqlValue(String(backendPort || ''));
  const safeAccessList = escapeSqlValue(String(accessList || ''));
  const safeGrace = escapeSqlValue(String(gracePeriod || ''));
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/backend_host', '${safeBackendHost}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/backend_port', '${safeBackendPort}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/access_list', '${safeAccessList}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'system/full_page_cache/varnish/grace_period', '${safeGrace}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  const normalized = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const safeNormalized = escapeSqlValue(normalized);
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/unsecure/base_url', '${safeNormalized}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/base_url', '${safeNormalized}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
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

async function setSecureOffloaderConfig(containerId: string, dbName: string) {
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/offloader_header', 'X-Forwarded-Proto') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/offloader_header_value', 'https') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
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
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  const safeHost = escapeSqlValue(String(host || ''));
  const safePort = escapeSqlValue(String(port || ''));
  const safeTimeout = escapeSqlValue(String(timeout || ''));
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_hostname', '${safeHost}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_port', '${safePort}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_timeout', '${safeTimeout}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  const command = `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`;
  return runDatabaseCommandWithRetry(stackName, containerId, command);
}

function buildMagentoDbOverrideEnv(stackName: string): Record<string, string> {
  return {
    MZ_DB_HOST: `${stackName}_database`,
    MZ_DB_PORT: '3306',
  };
}

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

function resolveStackMasterPublicKeyPath(): string | null {
  const candidates = [
    STACK_MASTER_PUBLIC_KEY_PATH,
    `${STACK_MASTER_KEY_PATH}.pub`,
    path.join(NODE_DIR, 'stack_master_ssh.pub'),
  ];
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function runMagentoCommandCapture(
  containerId: string,
  stackName: string,
  command: string,
  env: Record<string, string> = buildMagentoDbOverrideEnv(stackName),
) {
  const envArgs = buildDockerEnvArgs(env);
  return await runCommandCapture('docker', ['exec', ...envArgs, containerId, 'sh', '-c', command]);
}

async function runMagentoCommandWithStatus(
  containerId: string,
  stackName: string,
  command: string,
  env: Record<string, string> = buildMagentoDbOverrideEnv(stackName),
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

type PostDeploySmokeCheckResult = {
  name: string;
  url: string;
  expected: string;
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
) : Promise<{ ok: true; results: PostDeploySmokeCheckResult[] } | { ok: false; results: PostDeploySmokeCheckResult[]; summary: string }> {
  const hostHeader = envHostname.trim() || undefined;
  const checks: Array<{ name: string; url: string; timeoutSeconds: number; expectStatus?: number }> = [
    { name: 'nginx.mz-healthz', url: `http://${stackName}_nginx/mz-healthz`, timeoutSeconds: 10, expectStatus: 200 },
    { name: 'varnish.mz-healthz', url: `http://${stackName}_varnish/mz-healthz`, timeoutSeconds: 10, expectStatus: 200 },
    { name: 'nginx.health_check.php', url: `http://${stackName}_nginx/health_check.php`, timeoutSeconds: 30, expectStatus: 200 },
    // Root path can redirect (302) to https://<hostname>/, so accept any 2xx/3xx.
    { name: 'varnish.root', url: `http://${stackName}_varnish/`, timeoutSeconds: 30 },
  ];

  log('running post-deploy smoke checks');
  const deadline = Date.now() + 3 * 60 * 1000;
  let lastSummary = '';
  let lastResults: PostDeploySmokeCheckResult[] = [];

  while (Date.now() < deadline) {
    const results: PostDeploySmokeCheckResult[] = [];
    for (const check of checks) {
      const result = await probeHttpViaBackendNetwork(check.url, hostHeader, check.timeoutSeconds);
      const ok = check.expectStatus ? result.status === check.expectStatus : result.ok;
      results.push({
        name: check.name,
        url: check.url,
        expected: check.expectStatus ? String(check.expectStatus) : '2xx/3xx',
        status: result.status,
        ok,
        detail: result.detail,
      });
    }
    lastResults = results;

    const failed = results
      .filter((result) => !result.ok);

    if (!failed.length) {
      log('post-deploy smoke checks passed');
      return { ok: true, results };
    }

    lastSummary = failed
      .map((result) => {
        const detail = result.detail ? ` (${result.detail})` : '';
        return `${result.name} expected ${result.expected} got ${result.status}${detail}`;
      })
      .join('; ');

    log(`post-deploy smoke checks not ready: ${lastSummary}`);
    await delay(5000);
  }

  return { ok: false, results: lastResults, summary: lastSummary || 'unknown error' };
}

type ServiceUpdateStatus = {
  state: string;
  started_at: string;
  completed_at: string;
  message: string;
};

type ServiceInspectSummary = {
  name: string;
  image: string;
  labels: Record<string, string>;
  replicas: number | null;
};

type ServiceTaskRow = {
  id: string;
  name: string;
  node: string;
  desired_state: string;
  current_state: string;
  error: string;
  image: string;
};

async function inspectServiceUpdateStatus(serviceName: string): Promise<ServiceUpdateStatus | null> {
  const result = await runCommandCaptureWithStatus('docker', ['service', 'inspect', serviceName, '--format', '{{json .UpdateStatus}}']);
  if (result.code !== 0) {
    return null;
  }
  const raw = (result.stdout || '').trim();
  if (!raw || raw === '<no value>' || raw === 'null') {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as any;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const state = String(parsed.State || '').trim();
    const startedAt = String(parsed.StartedAt || '').trim();
    const completedAt = String(parsed.CompletedAt || '').trim();
    const message = String(parsed.Message || '').trim();
    if (!state && !message) {
      return null;
    }
    return { state, started_at: startedAt, completed_at: completedAt, message };
  } catch {
    return null;
  }
}

async function resumePausedServiceUpdate(serviceName: string, log: (message: string) => void): Promise<boolean> {
  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const state = (updateStatus?.state || '').toLowerCase();
  if (!state.includes('pause')) {
    return true;
  }
  log(`service update paused: ${serviceName} (${updateStatus?.state || 'paused'})${updateStatus?.message ? ` ${updateStatus.message}` : ''}`);
  const resume = await runCommandCaptureWithStatus('docker', [
    'service',
    'update',
    '--update-failure-action',
    'continue',
    serviceName,
  ]);
  const output = (resume.stderr || resume.stdout || '').trim();
  log(`service update resume: ${serviceName} exit=${resume.code}${output ? ` ${output}` : ''}`);
  return resume.code === 0;
}

async function inspectServiceImage(serviceName: string): Promise<string | null> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'inspect',
    serviceName,
    '--format',
    '{{.Spec.TaskTemplate.ContainerSpec.Image}}',
  ]);
  if (result.code !== 0) {
    return null;
  }
  return (result.stdout || '').trim() || null;
}

function parseDockerJsonLines(raw: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        out.push(parsed);
      }
    } catch {
      continue;
    }
  }
  return out;
}

async function listStackServices(stackName: string): Promise<string[]> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'ls',
    '--filter',
    `label=com.docker.stack.namespace=${stackName}`,
    '--format',
    '{{.Name}}',
  ]);
  if (result.code !== 0) {
    return [];
  }
  return result.stdout.split('\n').map((line) => line.trim()).filter(Boolean);
}

function parseReplicasFromServiceInspect(mode: any): number | null {
  const replicas = mode?.Replicated?.Replicas;
  if (typeof replicas === 'number' && Number.isFinite(replicas)) {
    return replicas;
  }
  if (typeof replicas === 'string' && replicas.trim() && Number.isFinite(Number(replicas))) {
    return Number(replicas);
  }
  return null;
}

async function inspectServices(serviceNames: string[]): Promise<ServiceInspectSummary[]> {
  if (!serviceNames.length) return [];
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'inspect',
    ...serviceNames,
    '--format',
    '{{json .}}',
  ]);
  if (result.code !== 0) {
    return [];
  }
  return parseDockerJsonLines(result.stdout)
    .map((row) => {
      const spec = (row as any).Spec || {};
      const name = String(spec?.Name || '').trim();
      const image = String(spec?.TaskTemplate?.ContainerSpec?.Image || '').trim();
      const labelsRaw = spec?.Labels && typeof spec.Labels === 'object' ? spec.Labels : {};
      const labels: Record<string, string> = {};
      for (const [key, value] of Object.entries(labelsRaw as Record<string, unknown>)) {
        labels[String(key)] = String(value ?? '');
      }
      const replicas = parseReplicasFromServiceInspect(spec?.Mode);
      return { name, image, labels, replicas };
    })
    .filter((entry) => entry.name !== '');
}

async function listServiceTasksWithImages(serviceName: string): Promise<ServiceTaskRow[]> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'ps',
    serviceName,
    '--no-trunc',
    '--format',
    '{{json .}}',
  ]);
  if (result.code !== 0) {
    return [];
  }
  return parseDockerJsonLines(result.stdout)
    .map((row) => {
      const id = String((row as any).ID || '').trim();
      const name = String((row as any).Name || '').trim();
      const node = String((row as any).Node || '').trim();
      const desiredState = String((row as any).DesiredState || '').trim();
      const currentState = String((row as any).CurrentState || '').trim();
      const error = String((row as any).Error || '').trim();
      const image = String((row as any).Image || '').trim();
      return { id, name, node, desired_state: desiredState, current_state: currentState, error, image };
    })
    .filter((task) => task.id !== '' && task.name !== '');
}

function summarizeReleaseServiceState(tasks: ServiceTaskRow[], expectedTag: string): {
  ok: boolean;
  desired_running: number;
  running: number;
  images_ok: boolean;
  issues: string[];
} {
  const desiredRunning = tasks.filter((t) => t.desired_state.toLowerCase() === 'running');
  const running = desiredRunning.filter((t) => t.current_state.startsWith('Running'));
  const imagesOk = running.length > 0 && running.every((t) => parseImageReference(t.image).tag === expectedTag);
  const nonRunning = desiredRunning.filter((t) => !t.current_state.startsWith('Running'));
  const issues: string[] = [];
  for (const task of nonRunning.slice(0, 5)) {
    const suffix = task.error ? ` (${task.error})` : '';
    issues.push(`${task.name} on ${task.node || '(unknown)'}: ${task.current_state}${suffix}`.trim());
  }
  if (desiredRunning.length === 0) {
    issues.push('No tasks desired to be Running.');
  }
  if (!imagesOk && running.length) {
    const mismatched = running
      .filter((t) => parseImageReference(t.image).tag !== expectedTag)
      .slice(0, 5)
      .map((t) => `${t.name} image=${parseImageReference(t.image).tag || '(none)'}`);
    if (mismatched.length) {
      issues.push(`Image tag mismatch: ${mismatched.join(', ')}`);
    }
  }
  const ok = desiredRunning.length > 0 && nonRunning.length === 0 && imagesOk;
  return {
    ok,
    desired_running: desiredRunning.length,
    running: running.length,
    images_ok: imagesOk,
    issues,
  };
}

async function resolveReleaseCohortServices(stackName: string): Promise<string[]> {
  const stackServices = await listStackServices(stackName);
  if (!stackServices.length) {
    return [];
  }
  const inspected = await inspectServices(stackServices);
  const labelled = inspected
    .filter((svc) => String(svc.labels?.[RELEASE_COHORT_LABEL_KEY] || '').trim() === RELEASE_COHORT_LABEL_VALUE)
    .map((svc) => svc.name)
    .filter(Boolean)
    .sort();
  if (labelled.length) {
    return labelled;
  }
  const fallback = ['nginx', 'php-fpm', 'php-fpm-admin', 'cron']
    .map((svc) => `${stackName}_${svc}`)
    .filter((name) => stackServices.includes(name));
  return fallback;
}

async function captureReleaseCohortSnapshot(services: string[]): Promise<{
  tags_by_service: Record<string, string>;
  tag: string | null;
  images_by_service: Record<string, string>;
}> {
  const inspected = await inspectServices(services);
  const tagsByService: Record<string, string> = {};
  const imagesByService: Record<string, string> = {};
  const tagSet = new Set<string>();
  for (const svc of inspected) {
    const image = String(svc.image || '').trim();
    if (!image) continue;
    imagesByService[svc.name] = image;
    const tag = parseImageReference(image).tag || '';
    if (tag) {
      tagsByService[svc.name] = tag;
      tagSet.add(tag);
    }
  }
  const tag = tagSet.size === 1 ? Array.from(tagSet)[0] : null;
  return { tags_by_service: tagsByService, tag, images_by_service: imagesByService };
}

async function waitForReleaseCohort(expectedTag: string, services: string[], log: (message: string) => void, timeoutMs: number): Promise<{
  ok: boolean;
  summary: string;
  snapshot: Record<string, unknown>;
}> {
  const startedAt = Date.now();
  let lastSummary = '';
  let lastSnapshot: Record<string, unknown> = {};
  const resumed = new Set<string>();
  while (Date.now() - startedAt < timeoutMs) {
    const snapshot: Record<string, unknown> = {};
    const issues: string[] = [];
    for (const serviceName of services) {
      const image = await inspectServiceImage(serviceName);
      const specTag = image ? parseImageReference(image).tag : '';
      const updateStatus = await inspectServiceUpdateStatus(serviceName);
      const state = (updateStatus?.state || '').toLowerCase();
      const tasks = await listServiceTasksWithImages(serviceName);
      const taskSummary = summarizeReleaseServiceState(tasks, expectedTag);
      snapshot[serviceName] = {
        spec_tag: specTag || null,
        update_status: updateStatus,
        tasks: {
          desired_running: taskSummary.desired_running,
          running: taskSummary.running,
          images_ok: taskSummary.images_ok,
          issues: taskSummary.issues,
        },
      };

      const updatePaused = state.includes('pause');
      const updateRolledBack = state.includes('rollback');
      if (updatePaused) {
        issues.push(`${serviceName} update=${updateStatus?.state || 'unknown'}`);
        if (!resumed.has(serviceName)) {
          resumed.add(serviceName);
          const ok = await resumePausedServiceUpdate(serviceName, log);
          if (ok) {
            log(`release cohort: resumed paused update for ${serviceName}`);
          }
        }
        continue;
      }
      if (updateRolledBack && specTag !== expectedTag) {
        issues.push(`${serviceName} update=${updateStatus?.state || 'unknown'}`);
        continue;
      }
      if (specTag !== expectedTag) {
        issues.push(`${serviceName} tag=${specTag || '(none)'}`);
        continue;
      }
      if (!taskSummary.ok) {
        issues.push(`${serviceName} tasks not ready`);
        continue;
      }
    }
    lastSnapshot = snapshot;
    if (issues.length === 0) {
      return { ok: true, summary: 'release cohort ready', snapshot };
    }
    lastSummary = issues.join('; ');
    log(`release cohort not ready: ${lastSummary}`);
    await delay(3000);
  }
  return { ok: false, summary: lastSummary || 'release cohort not ready', snapshot: lastSnapshot };
}

async function rollbackReleaseCohort(services: string[], log: (message: string) => void): Promise<Record<string, unknown>> {
  const snapshot: Record<string, unknown> = {};
  for (const serviceName of services) {
    let result = await runCommandCaptureWithStatus('docker', ['service', 'update', '--rollback', serviceName]);
    const output = `${result.stderr || ''}\n${result.stdout || ''}`.toLowerCase();
    if (result.code !== 0 && (output.includes('update paused') || output.includes('paused'))) {
      await resumePausedServiceUpdate(serviceName, log);
      result = await runCommandCaptureWithStatus('docker', ['service', 'update', '--rollback', serviceName]);
    }
    snapshot[serviceName] = {
      ok: result.code === 0,
      exit_code: result.code,
      output: (result.stderr || result.stdout || '').trim() || null,
    };
  }
  return snapshot;
}

async function tryForceUpdateService(serviceName: string, log: (message: string) => void): Promise<boolean> {
  let result = await runCommandCaptureWithStatus('docker', ['service', 'update', '--force', serviceName]);
  if (result.code !== 0) {
    const output = `${result.stderr || ''}\n${result.stdout || ''}`.toLowerCase();
    if (output.includes('update paused') || output.includes('paused')) {
      await resumePausedServiceUpdate(serviceName, log);
      result = await runCommandCaptureWithStatus('docker', ['service', 'update', '--force', serviceName]);
    }
  }

  if (result.code === 0) {
    log(`forced update: ${serviceName}`);
    return true;
  }
  const output = (result.stderr || result.stdout || '').trim();
  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const updateText = updateStatus
    ? ` update=${updateStatus.state}${updateStatus.message ? ` (${updateStatus.message})` : ''}`
    : '';
  log(`forced update failed: ${serviceName} (exit ${result.code})${updateText} ${output}`);
  return false;
}

async function captureServicePs(serviceName: string): Promise<string[]> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'ps',
    serviceName,
    '--no-trunc',
    '--format',
    '{{.Node}}|{{.CurrentState}}|{{.Error}}',
  ]);
  const out = (result.stdout || result.stderr || '').trim();
  if (result.code !== 0) {
    return [out ? `error: ${out}` : `error: exit ${result.code}`];
  }
  return out.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 10);
}

function writeJsonFileBestEffort(filePath: string, payload: unknown) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2));
  } catch {
    // ignore write failures
  }
}

function enqueueDeploymentRecord(payload: DeployPayload, deploymentId: string) {
  ensureDir(DEPLOY_QUEUE_DIR);
  const target = path.join(DEPLOY_QUEUE_DIR, `${deploymentId}.json`);
  writeJsonFileBestEffort(target, { id: deploymentId, queued_at: new Date().toISOString(), payload });
}

function chooseLastKnownGoodArtifact(environmentId: number, repository: string): string | null {
  const history = readDeploymentHistory();
  const key = `env:${environmentId}:${repository}`;
  const entry = history[key];
  const artifacts = Array.isArray(entry?.artifacts) ? entry.artifacts : [];
  const artifact = String(artifacts[0] || '').trim();
  return artifact || null;
}

async function autoHealPostDeploySmokeFailure(params: {
  stackName: string;
  envHostname: string;
  recordPath: string;
  record: Record<string, unknown>;
  initial: { summary: string; results: PostDeploySmokeCheckResult[] };
  log: (message: string) => void;
}): Promise<{ ok: true; results: PostDeploySmokeCheckResult[] } | { ok: false; summary: string; results: PostDeploySmokeCheckResult[] }> {
  const run = {
    id: crypto.randomUUID(),
    started_at: new Date().toISOString(),
    initial: params.initial,
    rounds: [] as Array<Record<string, unknown>>,
  };

  const failingNames = new Set(params.initial.results.filter((r) => !r.ok).map((r) => r.name));
  const shouldRestartNginx = Array.from(failingNames).some((name) => name.startsWith('nginx.'));
  const shouldRestartVarnish = Array.from(failingNames).some((name) => name.startsWith('varnish.'));
  const shouldRestartPhpFpm = failingNames.has('nginx.health_check.php');

  const restartTargets = new Set<string>();
  if (shouldRestartNginx || failingNames.size === 0) restartTargets.add(`${params.stackName}_nginx`);
  if (shouldRestartVarnish || failingNames.size === 0) restartTargets.add(`${params.stackName}_varnish`);
  if (shouldRestartPhpFpm) restartTargets.add(`${params.stackName}_php-fpm`);

  for (let round = 1; round <= DEPLOY_SMOKE_AUTO_HEAL_ROUNDS; round += 1) {
    params.log(`auto-heal: round ${round}/${DEPLOY_SMOKE_AUTO_HEAL_ROUNDS}`);
    const actions: string[] = [];
    for (const serviceName of Array.from(restartTargets)) {
      const ok = await tryForceUpdateService(serviceName, params.log);
      actions.push(`${ok ? 'updated' : 'failed'}:${serviceName}`);
      await delay(1000);
    }

    await delay(5000);

    const verified = await runPostDeploySmokeChecks(params.stackName, params.envHostname, params.log);
    const psSummary: Record<string, unknown> = {};
    for (const serviceName of Array.from(restartTargets)) {
      psSummary[serviceName] = await captureServicePs(serviceName);
    }

    run.rounds.push({
      round,
      actions,
      verified_ok: verified.ok,
      verified_summary: verified.ok ? null : verified.summary,
      verified_results: verified.results,
      service_ps: psSummary,
      captured_at: new Date().toISOString(),
    });

    params.record.post_deploy_auto_heal = run;
    writeJsonFileBestEffort(params.recordPath, params.record);

    if (verified.ok) {
      params.log('auto-heal: post-deploy verification passed');
      return verified;
    }
  }

  const last = run.rounds[run.rounds.length - 1] as Record<string, unknown> | undefined;
  const summary = typeof last?.verified_summary === 'string' ? String(last.verified_summary) : params.initial.summary;
  const results = (last?.verified_results as PostDeploySmokeCheckResult[] | undefined) || params.initial.results;
  params.log('auto-heal: exhausted rounds; still failing');
  return { ok: false, summary, results };
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
    const result = await runMagentoCommandWithStatus(currentId, stackName, checkScript);
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
        stackName,
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

async function setMagentoMaintenanceMode(
  containerId: string,
  stackName: string,
  mode: 'enable' | 'disable',
  log: (message: string) => void,
) {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(
      currentId,
      stackName,
      `php bin/magento maintenance:${mode} --no-interaction`,
    );
    if (result.code === 0) {
      log(`maintenance:${mode} ok`);
      return currentId;
    }
    const output = (result.stderr || result.stdout || '').trim();
    if (!output || output.includes('No such container') || output.includes('is not running')) {
      log(`maintenance:${mode} retry ${attempt}: ${output || `exit ${result.code}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      await delay(2000);
      continue;
    }
    throw new Error(`maintenance:${mode} failed (exit ${result.code}): ${output}`);
  }
  return currentId;
}

async function runSetupDbStatus(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
): Promise<{ needed: boolean; exitCode: number; output: string; containerId: string }> {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(currentId, stackName, 'php bin/magento setup:db:status');
    const output = (result.stderr || result.stdout || '').trim();
    const exitCode = result.code;
    if (exitCode === 0) {
      return { needed: false, exitCode, output, containerId: currentId };
    }
    if (exitCode === 1 || exitCode === 2) {
      return { needed: true, exitCode, output, containerId: currentId };
    }
    if (output && output.toLowerCase().includes('setup:upgrade is required')) {
      return { needed: true, exitCode, output, containerId: currentId };
    }
    if (!output || output.includes('No such container') || output.includes('is not running')) {
      log(`setup:db:status retry ${attempt}: ${output || `exit ${exitCode}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      await delay(2000);
      continue;
    }
    log(`setup:db:status unexpected exit=${exitCode}: ${output}`);
    return { needed: true, exitCode, output, containerId: currentId };
  }
  return { needed: true, exitCode: 1, output: 'setup:db:status retries exhausted', containerId: currentId };
}

async function flushMagentoCache(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
) {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(currentId, stackName, 'php bin/magento cache:flush');
    if (result.code === 0) {
      log('cache:flush ok');
      return currentId;
    }
    const output = (result.stderr || result.stdout || '').trim();
    if (!output || output.includes('No such container') || output.includes('is not running')) {
      log(`cache:flush retry ${attempt}: ${output || `exit ${result.code}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      await delay(2000);
      continue;
    }
    throw new Error(`cache:flush failed (exit ${result.code}): ${output}`);
  }
  return currentId;
}

async function backupDatabasePreUpgrade(params: {
  dbContainerId: string;
  dbName: string;
  r2: R2PresignContext;
  objectKey: string;
  log: (message: string) => void;
}) {
  const publicKeyPath = resolveStackMasterPublicKeyPath();
  if (!publicKeyPath) {
    throw new Error('Missing stack master public key for backup encryption.');
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '').replace('T', '_').replace('Z', 'Z');
  const workDir = path.join(DEPLOY_WORK_DIR, `db-backup-${timestamp}`);
  ensureDir(workDir);
  const dumpPath = path.join(workDir, 'db.sql');
  const zstPath = `${dumpPath}.zst`;
  const agePath = `${zstPath}.age`;
  const containerTmp = '/tmp/mz-pre-upgrade.sql';

  try {
    const safeDbName = assertSafeIdentifier(params.dbName, 'database name');
    const dumpCmd = [
      // `sh` on some distros is `dash`, which doesn't support `set -o pipefail`.
      // We don't use pipes here, so `-eu` is sufficient.
      'set -eu',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb-dump -uroot -p\"$ROOT_PASS\" --single-transaction --quick --routines --events --triggers --hex-blob --databases ${safeDbName} > ${containerTmp}`,
    ].join(' && ');
    await runCommand('docker', ['exec', params.dbContainerId, 'sh', '-lc', dumpCmd]);
    await runCommand('docker', ['cp', `${params.dbContainerId}:${containerTmp}`, dumpPath]);
    await runCommand('docker', ['exec', params.dbContainerId, 'sh', '-lc', `rm -f ${containerTmp} || true`]).catch(() => {});

    await runCommand('zstd', ['-19', '-f', '-o', zstPath, dumpPath]);
    await runCommand('age', ['-R', publicKeyPath, '-o', agePath, zstPath]);
    await uploadArtifact(params.r2, params.objectKey, agePath);
    params.log(`db backup uploaded: ${params.objectKey}`);
  } finally {
    for (const filePath of [dumpPath, zstPath, agePath]) {
      try {
        if (fs.existsSync(filePath)) fs.rmSync(filePath, { force: true });
      } catch {
        // ignore
      }
    }
    try {
      if (fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

async function reportDeploymentStatus(
  baseUrl: string,
  nodeId: string,
  nodeSecret: string,
  payload: { deployment_id: string; environment_id: number; status: string; message?: string; deployed_commit_sha?: string }
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
  const repository = String(payload.repository || '').trim() || inferRepositoryFromArtifactKey(artifactKey);
  const ref = String(payload.ref || '').trim();
  const logPrefix = `[deploy ${deploymentId}]`;
  const log = (message: string) => {
    console.log(`${logPrefix} ${message}`);
  };

  if (!artifactKey || !stackId || !environmentId) {
    throw new Error('Deployment payload missing artifact/stack/environment');
  }
  log(`start stack=${stackId} env=${environmentId} artifact=${artifactKey}`);
  const stackName = `mz-env-${environmentId}`;
  const recordMeta = record as unknown as Record<string, unknown>;

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

  await maybeAggressivePrune('pre-deploy');
  await ensureMinimumFreeSpace('pre-deploy');

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
  const opensearchHost = process.env.MZ_OPENSEARCH_HOST || `${stackName}_opensearch`;
  const opensearchPort = process.env.MZ_OPENSEARCH_PORT || '9200';
  const opensearchTimeout = process.env.MZ_OPENSEARCH_TIMEOUT || '15';

  const r2: R2PresignContext = { baseUrl, nodeId, nodeSecret, environmentId };

  const objectKey = String(envRecord?.db_backup_object || DEFAULT_DB_BACKUP_OBJECT).replace(/^\/+/, '');
  const workDir = path.join(DEPLOY_WORK_DIR, deploymentId);
  ensureDir(workDir);
  const progress = new DeployProgress(
    path.join(workDir, 'progress.json'),
    'deploy',
    deploymentId,
    environmentId,
    [
      { id: 'download_artifact', label: 'Download build artifact' },
      { id: 'build_images', label: 'Build images' },
      { id: 'deploy_stack', label: 'Deploy stack' },
      { id: 'db_prepare', label: 'Prepare database' },
      { id: 'app_prepare', label: 'Prepare application runtime' },
      { id: 'magento_steps', label: 'Run Magento deploy steps' },
      { id: 'smoke_checks', label: 'Post-deploy smoke checks' },
      { id: 'verify', label: 'Verify services' },
      { id: 'finalize', label: 'Finalize deploy' },
    ],
  );

  const artifactFileName = path.basename(artifactKey);
  const artifactPath = path.join(workDir, artifactFileName);
  progress.start('download_artifact');
  if (await validateLocalArtifactArchive(artifactPath)) {
    log(`reusing local artifact in work dir: ${artifactPath}`);
    progress.ok('download_artifact', 'Reused local artifact from current work dir');
  } else {
    const reused = await tryReuseLocalArtifact(artifactFileName, workDir, artifactPath, log);
    if (reused) {
      log(`reused local artifact from previous deployment: ${reused.sourcePath}`);
      progress.ok('download_artifact', `Reused local artifact from ${reused.sourcePath}`);
    } else {
      log('downloading build artifact from R2');
      await downloadArtifact(r2, artifactKey, artifactPath);
      log('downloaded build artifact from R2');
      progress.ok('download_artifact');
    }
  }

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

  const stackService = (service: string) => `${stackName}_${service}`;

  const replicaUser = 'replica';
  let replicaServiceName: 'database' | 'database-replica' = 'database';
  let replicaEnabled = false;
  const envTypeRaw = String(envRecord?.environment_type || '').trim().toLowerCase();
  const envHostname = String(envRecord?.environment_hostname || envRecord?.hostname || '').trim();
  const envHostnameOnly = envHostname
    ? envHostname.replace(/^https?:\/\//, '').split('/')[0]?.replace(/\/+$/, '') || ''
    : '';
  const mailCatcherEnabled = ['non-production', 'development', 'staging', 'performance'].includes(envTypeRaw);
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
      replicaServiceName = 'database-replica';
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`capacity unavailable; defaulting replica host to database (${message})`);
  }

  const registryHost = process.env.REGISTRY_HOST || '127.0.0.1';
  const registryPushHost = process.env.REGISTRY_PUSH_HOST || registryHost;
  const registryPullHost = process.env.REGISTRY_PULL_HOST || registryHost;
  const registryCacheHost = process.env.REGISTRY_CACHE_HOST || registryPullHost;
  const registryPort = process.env.REGISTRY_PORT || '5000';
  const registryCachePort = process.env.REGISTRY_CACHE_PORT || registryPort;
  const buildxNetwork = process.env.BUILDX_NETWORK || 'host';

  const envVars: NodeJS.ProcessEnv = {
    ...process.env,
    ...defaultVersions,
    ...overrideVersions,
    ...plannerResourceEnv,
    ...configEnv,
    // Default to pushing directly from Buildx to reduce local-disk pressure.
    // Can be overridden for local/dev usage.
    BUILDX_OUTPUT: process.env.BUILDX_OUTPUT || 'push',
    BUILDX_NETWORK: buildxNetwork,
    REGISTRY_HOST: registryHost,
    REGISTRY_PUSH_HOST: registryPushHost,
    REGISTRY_PULL_HOST: registryPullHost,
    REGISTRY_CACHE_HOST: registryCacheHost,
    REGISTRY_PORT: registryPort,
    REGISTRY_CACHE_PORT: registryCachePort,
    SECRET_VERSION,
    MZ_ENV_ID: String(environmentId),
    MAGE_VERSION: mageVersion,
    MYSQL_DATABASE: process.env.MYSQL_DATABASE || 'magento',
    MYSQL_USER: process.env.MYSQL_USER || 'magento',
    MZ_DB_HOST: stackService('proxysql'),
    MZ_DB_PORT: '6033',
    MZ_PROXYSQL_DB_HOST: stackService('database'),
    MZ_PROXYSQL_DB_REPLICA_HOST: stackService(replicaServiceName),
    MZ_PROXYSQL_DB_PORT: '3306',
    MZ_MARIADB_MASTER_HOST: stackService('database'),
    MZ_REPLICATION_USER: replicaUser,
    MZ_DATABASE_REPLICA_REPLICAS: replicaEnabled ? '1' : '0',
    MZ_RABBITMQ_HOST: stackService('rabbitmq'),
    MZ_REDIS_CACHE_HOST: stackService('redis-cache'),
    MZ_REDIS_SESSION_HOST: stackService('redis-session'),
    MZ_VARNISH_HOST: stackService('varnish'),
    MZ_PHP_FPM_HOST: stackService('php-fpm'),
    MZ_PHP_FPM_ADMIN_HOST: stackService('php-fpm-admin'),
    MZ_VARNISH_BACKEND_HOST: stackService('nginx'),
    MZ_VARNISH_BACKEND_PORT: '80',
    MZ_SEARCH_ENGINE: searchEngine,
    MZ_OPENSEARCH_HOST: opensearchHost,
    MZ_OPENSEARCH_PORT: opensearchPort,
    MZ_OPENSEARCH_TIMEOUT: opensearchTimeout,
    MZ_MAILHOG_REPLICAS: mailCatcherEnabled ? '1' : '0',
    SMTP_HOST: mailCatcherEnabled ? stackService('mailhog') : (process.env.SMTP_HOST || ''),
    SMTP_PORT: mailCatcherEnabled ? '1025' : (process.env.SMTP_PORT || ''),
    SMTP_TLS: mailCatcherEnabled ? 'off' : (process.env.SMTP_TLS || ''),
    SMTP_AUTH_USER: mailCatcherEnabled ? '' : (process.env.SMTP_AUTH_USER || ''),
    SMTP_AUTH_PASSWORD: mailCatcherEnabled ? '' : (process.env.SMTP_AUTH_PASSWORD || ''),
    SMTP_FROM_ADDRESS: process.env.SMTP_FROM_ADDRESS || (envHostnameOnly ? `no-reply@${envHostnameOnly}` : ''),
    SMTP_FROM_HOSTNAME: process.env.SMTP_FROM_HOSTNAME || envHostnameOnly,
  };
  assertRequiredEnv(envVars, [
    'MAGE_VERSION',
    'VARNISH_VERSION',
    'MARIADB_VERSION',
    'PROXYSQL_VERSION',
    'OPENSEARCH_VERSION',
    'REDIS_VERSION',
    'RABBITMQ_VERSION',
    'MAILHOG_VERSION',
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
  const envBaseUrl = envHostname ? `https://${envHostname.replace(/^https?:\/\//, '').replace(/\/+$/, '')}` : '';
  const dbSecretName = `mz_env_${environmentId}_db_password_v${SECRET_VERSION}`;
  const dbRootSecretName = `mz_env_${environmentId}_db_root_password_v${SECRET_VERSION}`;
  const dbReplicationSecretName = `mz_env_${environmentId}_db_replication_password_v${SECRET_VERSION}`;
  const rabbitSecretName = `mz_env_${environmentId}_rabbitmq_password_v${SECRET_VERSION}`;
  const mageSecretName = `mz_env_${environmentId}_mage_crypto_key_v${SECRET_VERSION}`;

  log('ensuring docker secrets');
  // Migrate existing global secrets to per-env secrets for already-deployed environments.
  await migrateGlobalSecret(stackName, 'database', 'db_password', dbSecretName, workDir);
  await migrateGlobalSecret(stackName, 'database', 'db_root_password', dbRootSecretName, workDir);
  await migrateGlobalSecret(stackName, 'database', 'db_replication_password', dbReplicationSecretName, workDir);
  await migrateGlobalSecret(stackName, 'rabbitmq', 'rabbitmq_password', rabbitSecretName, workDir);
  await ensureDockerSecret(dbSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(dbRootSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(dbReplicationSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(rabbitSecretName, generateSecretHex(24), workDir);

  if (!secrets?.crypt_key) {
    throw new Error('Missing Magento crypt key for environment');
  }
  await ensureDockerSecret(mageSecretName, secrets.crypt_key, workDir);
  log('docker secrets ready');

  progress.start('build_images');
  await runCommandLoggedWithRetry(
    'bash',
    [path.join(CLOUD_SWARM_DIR, 'scripts/build-services.sh')],
    { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-services' },
    {
      retries: DEPLOY_BUILD_RETRIES,
      log,
      onRetry: async () => {
        await maybeAggressivePrune('build-services-retry');
        await ensureMinimumFreeSpace('build-services-retry');
      },
    }
  );
  log('built base services');
  await runCommandLoggedWithRetry(
    'bash',
    [path.join(CLOUD_SWARM_DIR, 'scripts/build-magento.sh'), artifactPath],
    { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-magento' },
    {
      retries: DEPLOY_BUILD_RETRIES,
      log,
      onRetry: async () => {
        await maybeAggressivePrune('build-magento-retry');
        await ensureMinimumFreeSpace('build-magento-retry');
      },
    }
  );
  log('built magento images');
  progress.ok('build_images');

  const cohortServicesPre = await resolveReleaseCohortServices(stackName);
  const cohortSnapshotPre = await captureReleaseCohortSnapshot(cohortServicesPre);
  recordMeta.release_cohort = {
    label_key: RELEASE_COHORT_LABEL_KEY,
    label_value: RELEASE_COHORT_LABEL_VALUE,
    services: cohortServicesPre,
    previous_tag: cohortSnapshotPre.tag,
    previous_tags_by_service: cohortSnapshotPre.tags_by_service,
    previous_images_by_service: cohortSnapshotPre.images_by_service,
    captured_at: new Date().toISOString(),
  };
  writeJsonFileBestEffort(recordPath, recordMeta);

  progress.start('deploy_stack');
  await runCommandLogged('docker', [
    'stack',
    'deploy',
    '--with-registry-auth',
    '-c',
    path.join(CLOUD_SWARM_DIR, 'stacks/magento.yml'),
    stackName,
  ], { env: envVars, logDir, label: 'stack-deploy' });
  log('stack deployed');

  if (RELEASE_COHORT_GATE_ENABLED) {
    progress.detail('deploy_stack', 'Waiting for Swarm services to converge');
    const cohortServices = await resolveReleaseCohortServices(stackName);
    if (!cohortServices.length) {
      log('release cohort gate skipped: no cohort services found');
    } else {
      log(`release cohort gate: waiting for ${cohortServices.length} services to converge to ${mageVersion}`);
      const gate = await waitForReleaseCohort(mageVersion, cohortServices, log, RELEASE_COHORT_GATE_TIMEOUT_MS);
      recordMeta.release_cohort_gate = {
        ok: gate.ok,
        expected_tag: mageVersion,
        services: cohortServices,
        summary: gate.summary,
        snapshot: gate.snapshot,
        checked_at: new Date().toISOString(),
      };
      writeJsonFileBestEffort(recordPath, recordMeta);

      if (!gate.ok) {
        log('release cohort gate failed; rolling back cohort');
        const rollbackIssued = await rollbackReleaseCohort(cohortServices, log);
        const rollbackTargetTag = cohortSnapshotPre.tag;

        let rollbackGate: { ok: boolean; summary: string; snapshot: Record<string, unknown> } | null = null;
        if (rollbackTargetTag) {
          log(`release cohort rollback: waiting for services to converge to previous tag ${rollbackTargetTag}`);
          rollbackGate = await waitForReleaseCohort(rollbackTargetTag, cohortServices, log, RELEASE_COHORT_GATE_TIMEOUT_MS);
        } else {
          const post = await captureReleaseCohortSnapshot(cohortServices);
          if (post.tag) {
            log(`release cohort rollback: previous tag unknown, observed tag ${post.tag}; waiting for convergence`);
            rollbackGate = await waitForReleaseCohort(post.tag, cohortServices, log, RELEASE_COHORT_GATE_TIMEOUT_MS);
          }
        }

        recordMeta.release_cohort_rollback = {
          issued_at: new Date().toISOString(),
          issued: rollbackIssued,
          expected_tag: rollbackTargetTag,
          gate: rollbackGate,
        };
        writeJsonFileBestEffort(recordPath, recordMeta);

        const rollbackNote = rollbackTargetTag ? `Rolled back to ${rollbackTargetTag}.` : 'Rollback attempted.';
        throw new Error(`Release cohort did not converge to ${mageVersion}: ${gate.summary}. ${rollbackNote}`);
      }
    }
  }
  progress.ok('deploy_stack');

  progress.start('db_prepare');
  let dbContainerId = await waitForContainer(stackName, 'database', 5 * 60 * 1000);
  await waitForDatabase(dbContainerId, 5 * 60 * 1000);

  const dbName = envVars.MYSQL_DATABASE || 'magento';
  const hasTables = await databaseHasTables(dbContainerId, dbName);
  if (hasTables) {
    log('database already populated; skipping restore');
    progress.detail('db_prepare', 'Database already populated; skipping restore');
  } else {
    progress.detail('db_prepare', 'Restoring database from provisioning backup');
    const encryptedBackupPath = path.join(workDir, path.basename(objectKey));
    await downloadArtifact(r2, objectKey, encryptedBackupPath);
    await restoreDatabase(dbContainerId, encryptedBackupPath, workDir, dbName);
    await setSecureOffloaderConfig(dbContainerId, dbName);
    log('database restored');
    log('secure offloader config applied');
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
  progress.ok('db_prepare');

  progress.start('app_prepare');
  if (replicaServiceName === 'database-replica') {
    try {
      const replicaContainerId = await waitForContainer(stackName, 'database-replica', 5 * 60 * 1000);
      await waitForDatabase(replicaContainerId, 5 * 60 * 1000);
      await configureReplica(replicaContainerId, stackService('database'), replicaUser);
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
  progress.ok('app_prepare');

  progress.start('magento_steps');
  const dbStatus = await runSetupDbStatus(adminContainerId, stackName, log);
  adminContainerId = dbStatus.containerId;
  recordMeta.magento_setup_db_status = {
    exit_code: dbStatus.exitCode,
    needed: dbStatus.needed,
    output: dbStatus.output || null,
    checked_at: new Date().toISOString(),
  };
  writeJsonFileBestEffort(recordPath, recordMeta);

  let maintenanceEnabled = false;
  try {
    if (!dbStatus.needed) {
      log('setup:upgrade not required; flushing cache only');
      progress.detail('magento_steps', 'setup:upgrade not required; flushing cache');
      adminContainerId = await flushMagentoCache(adminContainerId, stackName, log);
    } else {
      log('setup:upgrade required; enabling maintenance + pre-upgrade DB backup');
      progress.detail('magento_steps', 'setup:upgrade required; enabling maintenance + DB backup');
      adminContainerId = await setMagentoMaintenanceMode(adminContainerId, stackName, 'enable', log);
      maintenanceEnabled = true;

      const prevArtifactKey = repository ? chooseLastKnownGoodArtifact(environmentId, repository) : null;
      const prevTag = inferCommitShaFromArtifactKey(prevArtifactKey || '') || 'unknown';
      const safeRepo = (repository || 'unknown-repo').replace(/[^A-Za-z0-9_.\\/-]/g, '_');
      const backupObjectKey = `db-backups/env-${environmentId}/${safeRepo}/pre-upgrade/${prevTag}-${deploymentId.slice(0, 8)}.sql.zst.age`;

      await backupDatabasePreUpgrade({
        dbContainerId,
        dbName: envVars.MYSQL_DATABASE || 'magento',
        r2,
        objectKey: backupObjectKey,
        log,
      });
      recordMeta.pre_upgrade_db_backup = {
        bucket: String(envRecord?.db_backup_bucket || ''),
        object_key: backupObjectKey,
        previous_artifact: prevArtifactKey || null,
        previous_tag: prevTag,
        created_at: new Date().toISOString(),
      };
      writeJsonFileBestEffort(recordPath, recordMeta);

      const upgradeResult = await runSetupUpgradeWithRetry(adminContainerId, stackName, log);
      upgradeWarning = upgradeResult.warning;
      if (upgradeWarning && upgradeResult.message) {
        console.warn(`${logPrefix} setup:upgrade warning: ${upgradeResult.message}`);
      }
      progress.detail('magento_steps', 'setup:upgrade complete; flushing cache');
      adminContainerId = await flushMagentoCache(adminContainerId, stackName, log);
    }
  } finally {
    dbContainerId = await setSearchEngine(stackName, dbContainerId, envVars.MYSQL_DATABASE || 'magento', searchEngine);
    if (maintenanceEnabled) {
      try {
        progress.detail('magento_steps', 'Disabling maintenance mode');
        adminContainerId = await setMagentoMaintenanceMode(adminContainerId, stackName, 'disable', log);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log(`maintenance:disable failed: ${message}`);
      }
    }
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
      stackService('nginx'),
      '80',
      `localhost,127.0.0.1,${stackService('nginx')},${stackService('php-fpm')},${stackService('php-fpm-admin')},${stackService('varnish')}`,
      '300',
    );
  }
  adminContainerId = await ensureMagentoEnvWrapperWithRetry(adminContainerId, stackName, log);
  await enforceMagentoPerformance(adminContainerId, stackName, log);
  log('magento deploy steps complete');
  progress.ok('magento_steps');

  if (envHostname) {
    progress.start('smoke_checks');
    const smoke = await runPostDeploySmokeChecks(stackName, envHostname, log);
    if (!smoke.ok) {
      const recordState = record as unknown as Record<string, unknown>;
      const servicePs = {
        [`${stackName}_nginx`]: await captureServicePs(`${stackName}_nginx`),
        [`${stackName}_varnish`]: await captureServicePs(`${stackName}_varnish`),
        [`${stackName}_php-fpm`]: await captureServicePs(`${stackName}_php-fpm`),
      };
      recordState.post_deploy_smoke_checks = {
        ok: false,
        summary: smoke.summary,
        results: smoke.results,
        service_ps: servicePs,
        captured_at: new Date().toISOString(),
      };
      writeJsonFileBestEffort(recordPath, recordState);

      if (DEPLOY_SMOKE_AUTO_HEAL_ENABLED && DEPLOY_SMOKE_AUTO_HEAL_ROUNDS > 0) {
        log('post-deploy smoke checks failed; attempting auto-heal');
        progress.detail('smoke_checks', 'Smoke checks failed; attempting auto-heal');
        const healed = await autoHealPostDeploySmokeFailure({
          stackName,
          envHostname,
          recordPath,
          record: recordState,
          initial: { summary: smoke.summary, results: smoke.results },
          log,
        });
        if (healed.ok) {
          recordState.post_deploy_smoke_checks = {
            ok: true,
            recovered_from: smoke.summary,
            results: healed.results,
            recovered_at: new Date().toISOString(),
          };
          writeJsonFileBestEffort(recordPath, recordState);
        } else {
          recordState.post_deploy_smoke_checks = {
            ok: false,
            summary: healed.summary,
            results: healed.results,
            captured_at: new Date().toISOString(),
          };
          writeJsonFileBestEffort(recordPath, recordState);

          if (!payload.rollback_of && DEPLOY_SMOKE_AUTO_ROLLBACK_ENABLED) {
            const repository = String(payload.repository || '').trim() || inferRepositoryFromArtifactKey(artifactKey);
            const lastGood = repository ? chooseLastKnownGoodArtifact(environmentId, repository) : null;
            if (repository && lastGood && lastGood.replace(/^\/+/, '') !== artifactKey.replace(/^\/+/, '')) {
              const rollbackDeploymentId = crypto.randomUUID();
              enqueueDeploymentRecord({
                artifact: lastGood,
                stack_id: stackId,
                environment_id: environmentId,
                repository,
                ref: ref || undefined,
                rollback_of: artifactKey,
              }, rollbackDeploymentId);
              recordState.post_deploy_auto_rollback = {
                queued_deployment_id: rollbackDeploymentId,
                artifact: lastGood,
                repository,
                queued_at: new Date().toISOString(),
              };
              writeJsonFileBestEffort(recordPath, recordState);
              throw new Error(`Post-deploy smoke checks failed: ${healed.summary}. Auto-rollback queued (${rollbackDeploymentId}).`);
            }
          }

          throw new Error(`Post-deploy smoke checks failed: ${healed.summary}`);
        }
      } else {
        throw new Error(`Post-deploy smoke checks failed: ${smoke.summary}`);
      }
    }
    progress.ok('smoke_checks');
  } else {
    log('post-deploy smoke checks skipped: no environment hostname available');
    progress.skipped('smoke_checks', 'No environment hostname available');
  }

  // Detect silent Swarm rollbacks / paused updates (otherwise smoke checks can pass on old tasks).
  log('verifying deployed service images + update states');
  progress.start('verify');
  const recordState = record as unknown as Record<string, unknown>;
  const verifyTargets = [
    { service: `${stackName}_nginx`, expected_tag: mageVersion },
    { service: `${stackName}_php-fpm`, expected_tag: mageVersion },
    { service: `${stackName}_php-fpm-admin`, expected_tag: mageVersion },
    { service: `${stackName}_cron`, expected_tag: mageVersion },
  ];
  const verifySnapshot: Record<string, unknown> = {};
  const failures: string[] = [];
  for (const target of verifyTargets) {
    const image = await inspectServiceImage(target.service);
    const updateStatus = await inspectServiceUpdateStatus(target.service);
    const tasks = await listServiceTasksWithImages(target.service);
    const taskSummary = summarizeReleaseServiceState(tasks, target.expected_tag);
    verifySnapshot[target.service] = {
      image,
      update_status: updateStatus,
      tasks: {
        desired_running: taskSummary.desired_running,
        running: taskSummary.running,
        images_ok: taskSummary.images_ok,
        issues: taskSummary.issues,
      },
    };

    if (!image || !image.includes(`:${target.expected_tag}`)) {
      failures.push(`${target.service} image mismatch`);
    }
    if (!taskSummary.ok) {
      failures.push(`${target.service} tasks not aligned`);
    }
    const state = (updateStatus?.state || '').toLowerCase();
    if (state.includes('pause') || (state.includes('rollback') && (!image || !image.includes(`:${target.expected_tag}`)))) {
      failures.push(`${target.service} update=${updateStatus?.state || 'unknown'}`);
    }
  }
  recordState.post_deploy_image_verification = {
    ok: failures.length === 0,
    failures,
    services: verifySnapshot,
    verified_at: new Date().toISOString(),
  };
  writeJsonFileBestEffort(recordPath, recordState);
  if (failures.length) {
    progress.fail('verify', failures.join('; '));
    throw new Error(`Deploy verification failed: ${failures.join('; ')}.`);
  }
  progress.ok('verify');

  progress.start('finalize');
  await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
    deployment_id: deploymentId,
    environment_id: environmentId,
    status: 'active',
    deployed_commit_sha: (
      inferCommitShaFromArtifactKey(artifactKey)
      || (/^[0-9a-f]{7,64}$/i.test(ref) ? ref : '')
      || undefined
    ),
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
  progress.ok('finalize');
  progress.doneOk();
}

async function cleanupFailedArtifact(record: Record<string, any>) {
  try {
    const payload = (record?.payload || {}) as Record<string, any>;
    const environmentId = Number(payload.environment_id ?? 0) || 0;
    const rawArtifact = String(payload.artifact || '').trim();
    if (!environmentId || !rawArtifact) {
      return;
    }

    if (rawArtifact.startsWith('http://') || rawArtifact.startsWith('https://')) {
      console.warn('cleanup skip: artifact is a URL (expected object key)');
      return;
    }

    const normalizedArtifactKey = rawArtifact.replace(/^\/+/, '');
    const repository = String(payload.repository || '').trim() || inferRepositoryFromArtifactKey(normalizedArtifactKey) || 'unknown';
    const history = readDeploymentHistory();
    const key = `env:${environmentId}:${repository}`;
    const entry = history[key] || { artifacts: [] };
    const keepSet = new Set(
      (Array.isArray(entry.artifacts) ? entry.artifacts : [])
        .map((item) => String(item || '').replace(/^\/+/, '').trim())
        .filter(Boolean)
    );

    if (keepSet.has(normalizedArtifactKey)) {
      return;
    }

    const config = readConfig();
    const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
    const nodeId = readNodeFile('node-id');
    const nodeSecret = readNodeFile('node-secret');
    if (!baseUrl || !nodeId || !nodeSecret) {
      console.warn('cleanup skip: missing mz-control base URL or node credentials');
      return;
    }

    const r2: R2PresignContext = { baseUrl, nodeId, nodeSecret, environmentId };
    await deleteR2Object(r2, normalizedArtifactKey);
    console.warn(`cleanup: deleted failed artifact ${normalizedArtifactKey}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup failed artifact error: ${message}`);
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
    await cleanupFailedArtifact(merged);
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
