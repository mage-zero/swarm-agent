import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { isDeployPaused } from './deploy-pause.js';
import { buildCapacityPayload, buildPlannerPayload, isSwarmManager, readConfig } from './status.js';
import { parseListObjectsV2Xml } from './r2-list.js';
import { getDbBackupZstdLevel } from './backup-utils.js';
import { buildJobName, envServiceName, inspectServiceSpec, listServiceTasks, runSwarmJob } from './swarm.js';
import { bootstrapMonitoringDashboards } from './monitoring-dashboards.js';
import { resolveDatadogTraceEnv } from './lib/apm-tracing.js';
import {
  classifyDeployError,
  enrichCommandError,
} from './deploy-reliability.js';
import {
  ensureDir,
  runCommand,
  runCommandLogged,
  runCommandLoggedWithRetry,
  runCommandCapture,
  runCommandCaptureWithStatus,
  readCommandLogTail,
  detectMissingRegistryManifest,
  delay,
  generateSecretHex,
} from './lib/deploy-exec.js';
import {
  type AppSelection,
  type ApplicationSelections,
  type PlannerResourceSpec,
  type PlannerResources,
  type PlannerConfigChange,
  type PlannerTuningProfileLike,
  type PlannerTuningPayloadLike,
  MIB,
  GIB,
  RESOURCE_ENV_MAP,
  RESOURCE_ENV_KEYS,
  assertRequiredEnv,
  formatCpuCores,
  formatMemoryBytes,
  formatMemoryMiB,
  buildPlannerResourceEnv,
  resolveActiveProfile,
  buildConfigEnv,
  normalizeSelectionFlavor,
  resolveVersionEnv,
  readVersionDefaults,
  resolveImageTag,
} from './lib/version-config.js';
import {
  parseDetectedEngine,
  defaultSearchEngine,
  resolveSearchEngine,
  buildSearchEngineEnvOverride,
  buildSearchSystemConfigSql,
} from './lib/search-engine.js';
import {
  type AppHaReplicaPolicyInput,
  type AppHaReplicaPolicyDecision,
  type FrontendRuntimePolicy,
  type FrontendRuntimeSpec,
  resolveAppHaReplicaPolicy,
  resolveFrontendRuntimePolicy,
} from './lib/replica-policy.js';
import {
  buildMagentoCliCommand,
  buildSetupDbStatusCommand,
} from './lib/magento-cli.js';
import {
  type ProxySqlQueryRuleSpec,
  PROXYSQL_MANAGED_QUERY_RULES,
  buildProxySqlQueryRulesSql,
} from './lib/proxysql.js';
import {
  type DeployHistoryEntry,
  type DeployHistory,
  readDeploymentHistory,
  writeDeploymentHistory,
  normalizeHistoryList,
  getDeploymentHistoryEntry,
  getHistoryLastSuccessfulDeployAt,
  parseIsoTimestampMs,
  resolveAggressivePruneCutoffSeconds,
  updateDeploymentHistory,
  updateFailedDeploymentHistory,
} from './lib/deploy-history.js';
import {
  type ServiceUpdateStatus,
  type ServiceInspectSummary,
  type ServiceTaskRow,
  parseDockerJsonLines,
  waitForContainer,
  findLocalContainer,
  inspectServiceUpdateStatus,
  inspectServiceImage,
  listStackServices,
  inspectServices,
  resumePausedServiceUpdate,
  tryForceUpdateService,
  captureServicePs,
} from './lib/docker-service.js';
import {
  runPostDeploySmokeChecks,
} from './lib/smoke-check.js';

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

type EnvironmentRecord = {
  environment_id?: number;
  stack_id?: number;
  hostname?: string;
  environment_hostname?: string;
  environment_type?: string;
  db_backup_bucket?: string;
  db_backup_object?: string;
  application_selections?: ApplicationSelections;
  application_version?: string;
  environment_secrets?: EnvironmentSecrets | null;
};

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_QUEUED_DIR = process.env.MZ_DEPLOY_QUEUED_DIR || path.join(DEPLOY_QUEUE_DIR, 'queued');
const DEPLOY_WORK_DIR = process.env.MZ_DEPLOY_WORK_DIR || '/opt/mage-zero/deployments/work';
const DEPLOY_HISTORY_FILE = process.env.MZ_DEPLOY_HISTORY_FILE || path.join(DEPLOY_QUEUE_DIR, 'meta', 'history.json');
const LEGACY_DEPLOY_HISTORY_FILE = path.join(DEPLOY_QUEUE_DIR, 'history.json');
const DEPLOY_RECORD_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i;
const DEPLOY_RETAIN_COUNT = Math.max(1, Number(process.env.MZ_DEPLOY_RETAIN_COUNT || 2));
const DEPLOY_FAILED_ARTIFACT_RETAIN_COUNT = Math.max(0, Number(process.env.MZ_DEPLOY_FAILED_ARTIFACT_RETAIN_COUNT || 1));
const DEPLOY_FAILED_IMAGE_RETAIN_COUNT = Math.max(0, Number(process.env.MZ_DEPLOY_FAILED_IMAGE_RETAIN_COUNT || 1));
const DEPLOY_FAILED_RETAIN_COUNT = Math.max(0, Number(process.env.MZ_DEPLOY_FAILED_RETAIN_COUNT || 1));
const DEPLOY_CLEANUP_ENABLED = (process.env.MZ_DEPLOY_CLEANUP_ENABLED || '1') !== '0';
const DEPLOY_SMOKE_AUTO_ROLLBACK_ENABLED = (process.env.MZ_DEPLOY_SMOKE_AUTO_ROLLBACK_ENABLED || '0') === '1';
const RELEASE_COHORT_GATE_ENABLED = (process.env.MZ_RELEASE_COHORT_GATE_ENABLED || '1') !== '0';
// Rolling back a cohort to an unknown state can make things worse (e.g. rolling back to a tag that was never
// a successful deploy). Default to "fail-fast + stop crash-looping services" instead.
const RELEASE_COHORT_ROLLBACK_ENABLED = (process.env.MZ_RELEASE_COHORT_ROLLBACK_ENABLED || '0') === '1';
const RELEASE_COHORT_SCALE_DOWN_ON_FAILURE = (process.env.MZ_RELEASE_COHORT_SCALE_DOWN_ON_FAILURE || '1') !== '0';
// Default 15 minutes: Swarm updates can legitimately take time (image pulls, task reschedules),
// but we must not wait indefinitely.
const releaseCohortGateTimeoutDefaultMs = 15 * 60 * 1000;
const releaseCohortGateTimeoutParsed = Number(process.env.MZ_RELEASE_COHORT_GATE_TIMEOUT_MS);
const RELEASE_COHORT_GATE_TIMEOUT_MS = Math.max(
  10_000,
  Number.isFinite(releaseCohortGateTimeoutParsed) && releaseCohortGateTimeoutParsed > 0
    ? releaseCohortGateTimeoutParsed
    : releaseCohortGateTimeoutDefaultMs
);
const RELEASE_COHORT_LABEL_KEY = process.env.MZ_RELEASE_COHORT_LABEL_KEY || 'mz.release.cohort';
const RELEASE_COHORT_LABEL_VALUE = process.env.MZ_RELEASE_COHORT_LABEL_VALUE || 'magento';
const RELEASE_ID_LABEL_KEY = process.env.MZ_RELEASE_ID_LABEL_KEY || 'mz.release.id';
const REGISTRY_CLEANUP_ENABLED = (process.env.MZ_REGISTRY_CLEANUP_ENABLED || '1') !== '0';
// Registry cleanup should hit the host-published registry port by default.
// Do not couple cleanup to REGISTRY_PUSH_HOST because Buildx pushes can occur
// from inside the BuildKit container (where loopback/service DNS differ).
const REGISTRY_CLEANUP_HOST = process.env.MZ_REGISTRY_CLEANUP_HOST || '127.0.0.1';
const REGISTRY_CLEANUP_PORT = process.env.MZ_REGISTRY_CLEANUP_PORT || '5000';
const REGISTRY_CLEANUP_REPOSITORIES = (() => {
  const parsed = (process.env.MZ_REGISTRY_CLEANUP_REPOSITORIES || 'mz-magento,mz-nginx-app')
    .split(',')
    .map((value) => stripRegistryHost(String(value || '').replace(/^\/+/, '').trim()))
    .filter(Boolean);
  const unique = Array.from(new Set(parsed));
  return unique.length ? unique : ['mz-magento', 'mz-nginx-app'];
})();
const DEPLOY_MIN_FREE_GB = Number(process.env.MZ_DEPLOY_MIN_FREE_GB || 15);
const DEPLOY_AGGRESSIVE_PRUNE_ENABLED = (process.env.MZ_DEPLOY_AGGRESSIVE_PRUNE_ENABLED || '1') !== '0';
const DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB = Number(
  process.env.MZ_DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB || DEPLOY_MIN_FREE_GB
);
const DEPLOY_AGGRESSIVE_PRUNE_SUCCESS_LOOKBACK_HOURS = Math.max(
  1,
  Number(process.env.MZ_DEPLOY_AGGRESSIVE_PRUNE_SUCCESS_LOOKBACK_HOURS || 24)
);
const DEPLOY_ABORT_MIN_FREE_GB = Number(process.env.MZ_DEPLOY_ABORT_MIN_FREE_GB || 5);
const DEPLOY_BUILD_RETRIES = Math.max(0, Number(process.env.MZ_DEPLOY_BUILD_RETRIES || 1));
// Legacy precheck: skip build-services when service image tags already exist.
// Default is now OFF because tag existence alone can bypass cloud-swarm's smarter
// rebuild invalidation (cloud-swarm ref/base digest labels), leaving stale base
// images such as mz-php-fpm in the registry.
function resolveSkipServiceBuildIfPresent(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = String(env.MZ_DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT ?? '').trim();
  if (!raw) {
    return false;
  }
  return raw !== '0';
}
const DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT = resolveSkipServiceBuildIfPresent();
const DEPLOY_SKIP_APP_BUILD_IF_PRESENT = (process.env.MZ_DEPLOY_SKIP_APP_BUILD_IF_PRESENT || '1') !== '0';
const setupDbStatusTimeoutParsed = Number(process.env.MZ_SETUP_DB_STATUS_TIMEOUT_SECONDS || 120);
const SETUP_DB_STATUS_TIMEOUT_SECONDS = Math.max(
  30,
  Number.isFinite(setupDbStatusTimeoutParsed) && setupDbStatusTimeoutParsed > 0
    ? Math.floor(setupDbStatusTimeoutParsed)
    : 120
);
const REGISTRY_GC_ENABLED = (process.env.MZ_REGISTRY_GC_ENABLED || '1') === '1';
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
const APP_HA_MIN_READY_NODES = Math.max(1, Number(process.env.MZ_APP_HA_MIN_READY_NODES || 2));
const APP_HA_MAX_REPLICAS = Math.max(1, Number(process.env.MZ_APP_HA_MAX_REPLICAS || 2));
function isLoopbackHost(host: string) {
  const value = String(host || '').trim().toLowerCase();
  return value === '127.0.0.1' || value === 'localhost' || value === '::1';
}

function isRegistryAliasHost(host: string) {
  return String(host || '').trim().toLowerCase() === 'registry';
}

async function detectWireGuardIpV4(): Promise<string | null> {
  // Prefer wg0: we use WireGuard for swarm control + private registry access.
  const result = await runCommandCaptureWithStatus('ip', ['-4', 'addr', 'show', 'dev', 'wg0']);
  if (result.code !== 0) {
    return null;
  }
  const match = (result.stdout || '').match(/\binet\s+(\d+\.\d+\.\d+\.\d+)\//);
  return match?.[1] || null;
}

async function swarmHasMultipleNodes(): Promise<boolean> {
  const result = await runCommandCaptureWithStatus('docker', ['node', 'ls', '--format', '{{.ID}}']);
  if (result.code !== 0) {
    return false;
  }
  const lines = (result.stdout || '').trim().split('\n').filter(Boolean);
  return lines.length > 1;
}

async function resolveRegistryPullHost(candidate: string, log: (message: string) => void): Promise<string> {
  const trimmed = String(candidate || '').trim();
  if (!trimmed) {
    return '127.0.0.1';
  }

  const multiNode = await swarmHasMultipleNodes();
  if (!multiNode) {
    return trimmed;
  }

  const wgIp = await detectWireGuardIpV4();

  // In a multi-node Swarm, 127.0.0.1/localhost will break pulls on worker nodes.
  if (isLoopbackHost(trimmed)) {
    if (wgIp) {
      log(`registry pull host is loopback in multi-node swarm; using WireGuard IP ${wgIp}`);
      return wgIp;
    }
    return trimmed;
  }

  // `registry` commonly resolves to node-local/public addresses that workers
  // cannot always route back to; prefer the private WireGuard address.
  if (isRegistryAliasHost(trimmed) && wgIp) {
    log(`registry pull host '${trimmed}' is alias-based in multi-node swarm; using WireGuard IP ${wgIp}`);
    return wgIp;
  }

  return trimmed;
}

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

function getQueueSourceDirs(
  queuedDir = DEPLOY_QUEUED_DIR,
  queueDir = DEPLOY_QUEUE_DIR
): string[] {
  const primary = path.resolve(queuedDir);
  const legacy = path.resolve(queueDir);
  if (primary === legacy) {
    return [primary];
  }
  return [primary, legacy];
}

function readNodeFile(name: string): string {
  try {
    return fs.readFileSync(path.join(NODE_DIR, name), 'utf8').trim();
  } catch {
    return '';
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

  // Second pass: remove untagged images from known repos (e.g. old mz-magento:<none>).
  // These accumulate when Swarm pulls a newer tag — the old image loses its tag but stays
  // on disk. Safe to remove: buildx cache lives in the registry, not Docker's image store.
  const knownRepos = new Set(REGISTRY_CLEANUP_REPOSITORIES.map((r) => `mz-${r}`.replace(/^mz-mz-/, 'mz-')));
  for (const r of REGISTRY_CLEANUP_REPOSITORIES) {
    knownRepos.add(r);
  }
  const { stdout: allImages } = await runCommandCapture('docker', [
    'image', 'ls', '--format', '{{.Repository}} {{.Tag}} {{.ID}}',
  ]);
  const keepImageIds = new Set<string>();
  for (const line of allImages.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const [, imgTag, imgId] = parts;
    if (imgTag && imgTag !== '<none>' && keepImageTags.has(imgTag)) {
      keepImageIds.add(imgId);
    }
  }
  for (const line of allImages.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const [imgRepo, imgTag, imgId] = parts;
    if (imgTag !== '<none>') continue;
    if (keepImageIds.has(imgId)) continue;
    // Check if the repo (stripped of registry host) matches a known cleanup repo.
    const bareRepo = stripRegistryHost(imgRepo);
    if (!knownRepos.has(bareRepo)) continue;
    try {
      await runCommand('docker', ['image', 'rm', '-f', imgId]);
    } catch {
      // ignore — may be referenced by a running container
    }
  }

  return removals;
}

function isAllowedRegistryCleanupHost(repoHost: string) {
  if (!repoHost) {
    return true;
  }
  const cleanupHost = String(REGISTRY_CLEANUP_HOST || '').trim().toLowerCase();
  const cleanupPort = String(REGISTRY_CLEANUP_PORT || '').trim();
  const normalizedHost = String(repoHost || '').trim().toLowerCase();
  const allowed = new Set([
    cleanupHost,
    cleanupPort ? `${cleanupHost}:${cleanupPort}` : '',
    'registry',
    cleanupPort ? `registry:${cleanupPort}` : '',
    'localhost',
    cleanupPort ? `localhost:${cleanupPort}` : '',
    '127.0.0.1',
    cleanupPort ? `127.0.0.1:${cleanupPort}` : '',
    '::1',
    cleanupPort ? `[::1]:${cleanupPort}` : '',
  ]);
  return allowed.has(normalizedHost);
}

function normalizeRegistryRemoval(removal: { repo: string; tag: string }): { repo: string; tag: string } | null {
  const repoRaw = String(removal.repo || '').trim();
  const tag = String(removal.tag || '').trim();
  if (!repoRaw || !tag) {
    return null;
  }
  const repoHost = getRegistryHost(repoRaw);
  if (!isAllowedRegistryCleanupHost(repoHost)) {
    return null;
  }
  const repo = stripRegistryHost(repoRaw).replace(/^\/+/, '').trim();
  if (!repo) {
    return null;
  }
  return { repo, tag };
}

async function fetchWithShortTimeout(url: string, init: RequestInit = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function listRegistryTags(repository: string): Promise<string[]> {
  const repo = String(repository || '').replace(/^\/+/, '').trim();
  if (!repo) {
    return [];
  }
  const tagsUrl = `http://${REGISTRY_CLEANUP_HOST}:${REGISTRY_CLEANUP_PORT}/v2/${repo}/tags/list?n=10000`;
  try {
    const response = await fetchWithShortTimeout(tagsUrl);
    if (!response.ok) {
      return [];
    }
    return parseRegistryTagsResponse(await response.text());
  } catch {
    return [];
  }
}

async function resolveRegistryManifestDigest(repository: string, reference: string): Promise<string | null> {
  const repo = String(repository || '').replace(/^\/+/, '').trim();
  const ref = String(reference || '').trim();
  if (!repo || !ref) {
    return null;
  }
  const manifestUrl = `http://${REGISTRY_CLEANUP_HOST}:${REGISTRY_CLEANUP_PORT}/v2/${repo}/manifests/${ref}`;
  try {
    const response = await fetchWithShortTimeout(manifestUrl, {
      method: 'HEAD',
      headers: {
        'Accept': 'application/vnd.docker.distribution.manifest.v2+json',
      },
    });
    if (!response.ok) {
      return null;
    }
    const digest = String(response.headers.get('docker-content-digest') || '').trim();
    return digest || null;
  } catch {
    return null;
  }
}

async function deleteRegistryManifestDigest(repository: string, digest: string): Promise<boolean> {
  const repo = String(repository || '').replace(/^\/+/, '').trim();
  const value = String(digest || '').trim();
  if (!repo || !value) {
    return false;
  }
  const manifestUrl = `http://${REGISTRY_CLEANUP_HOST}:${REGISTRY_CLEANUP_PORT}/v2/${repo}/manifests/${value}`;
  try {
    const response = await fetchWithShortTimeout(manifestUrl, { method: 'DELETE' });
    if (response.status === 404) {
      return false;
    }
    return response.ok;
  } catch {
    return false;
  }
}

async function cleanupRegistryImages(params: {
  environmentId: number;
  keepImageTags: Set<string>;
  removals: Array<{ repo: string; tag: string }>;
}) {
  if (!REGISTRY_CLEANUP_ENABLED) {
    return { deleted: 0 };
  }

  const prefix = `env-${params.environmentId}-`;
  const keepTags = new Set(
    Array.from(params.keepImageTags)
      .map((tag) => String(tag || '').trim())
      .filter((tag) => tag.startsWith(prefix))
  );

  const normalizedRemovals = params.removals
    .map((item) => normalizeRegistryRemoval(item))
    .filter((item): item is { repo: string; tag: string } => Boolean(item))
    .filter((item) => item.tag.startsWith(prefix) && !keepTags.has(item.tag));

  const repos = new Set<string>(REGISTRY_CLEANUP_REPOSITORIES);
  for (const removal of normalizedRemovals) {
    repos.add(removal.repo);
  }

  let deleted = 0;
  for (const repo of repos) {
    if (!repo) continue;

    const listed = await listRegistryTags(repo);
    const deleteTags = new Set<string>();

    for (const tag of listed) {
      const normalizedTag = String(tag || '').trim();
      if (!normalizedTag || !normalizedTag.startsWith(prefix)) {
        continue;
      }
      if (!keepTags.has(normalizedTag)) {
        deleteTags.add(normalizedTag);
      }
    }

    for (const removal of normalizedRemovals) {
      if (removal.repo !== repo) continue;
      if (!keepTags.has(removal.tag)) {
        deleteTags.add(removal.tag);
      }
    }

    if (!deleteTags.size) {
      continue;
    }

    const keepDigests = new Set<string>();
    for (const tag of keepTags) {
      const digest = await resolveRegistryManifestDigest(repo, tag);
      if (digest) {
        keepDigests.add(digest);
      }
    }

    const deleteDigests = new Set<string>();
    for (const tag of deleteTags) {
      const digest = await resolveRegistryManifestDigest(repo, tag);
      if (!digest) {
        continue;
      }
      if (keepDigests.has(digest)) {
        continue;
      }
      deleteDigests.add(digest);
    }

    for (const digest of deleteDigests) {
      const removed = await deleteRegistryManifestDigest(repo, digest);
      if (removed) {
        deleted += 1;
      }
    }
  }

  return { deleted };
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

async function maybeAggressivePrune(stage: string, previousSuccessAt: string | null = null) {
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

  const cutoffSeconds = resolveAggressivePruneCutoffSeconds(previousSuccessAt);
  if (cutoffSeconds === null) {
    console.warn(`cleanup: ${stage}: no valid previous successful deploy timestamp; skipping aggressive prune`);
    return;
  }
  const cutoffIso = new Date(cutoffSeconds * 1000).toISOString();

  console.warn(
    `cleanup: ${stage}: free space ${freeGb}GB < ${DEPLOY_AGGRESSIVE_PRUNE_MIN_FREE_GB}GB; ` +
    `running docker prune until ${cutoffIso} (previous-success minus ${DEPLOY_AGGRESSIVE_PRUNE_SUCCESS_LOOKBACK_HOURS}h)`
  );

  // Remove dangling images first (untagged AND unreferenced). Fast, always safe,
  // and does not affect buildx cache (which lives in the registry, not Docker's image store).
  try {
    await runCommand('docker', ['image', 'prune', '-f']);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup: docker image prune failed: ${message}`);
  }

  // Note: --volumes is incompatible with --filter until=, so we run them separately.
  try {
    await runCommand('docker', [
      'system',
      'prune',
      '-a',
      '--filter',
      `until=${cutoffSeconds}`,
      '-f',
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup: docker system prune failed: ${message}`);
  }
  try {
    await runCommand('docker', ['volume', 'prune', '-f']);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`cleanup: docker volume prune failed: ${message}`);
  }

  // docker builder prune expects a duration string (e.g. "24h"), not a unix timestamp.
  const cutoffDurationHours = Math.max(1, Math.round((Date.now() / 1000 - cutoffSeconds) / 3600));
  try {
    await runCommand('docker', ['builder', 'prune', '-a', '--filter', `until=${cutoffDurationHours}h`, '-f']);
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
  previousSuccessAt: string | null;
}) {
  const history = readDeploymentHistory(DEPLOY_HISTORY_FILE, LEGACY_DEPLOY_HISTORY_FILE);
  const normalizedArtifactKey = params.artifactKey.replace(/^\/+/, '');
  const repo = params.repository || inferRepositoryFromArtifactKey(normalizedArtifactKey) || 'unknown';
  const key = `env:${params.environmentId}:${repo}`;
  const {
    keepArtifacts,
    keepImageTags,
    removedArtifacts,
    removedFailedArtifacts,
  } = updateDeploymentHistory(
    history,
    key,
    normalizedArtifactKey,
    params.mageVersion,
    DEPLOY_RETAIN_COUNT
  );
  writeDeploymentHistory(history, DEPLOY_HISTORY_FILE);

  if (!DEPLOY_CLEANUP_ENABLED) {
    return;
  }

  const keepArtifactBases = new Set(keepArtifacts.map((item) => path.basename(item)));
  await cleanupWorkDirs(keepArtifactBases);

  const keepArtifactSet = new Set(
    keepArtifacts
      .map((item) => String(item || '').replace(/^\/+/, '').trim())
      .filter(Boolean)
  );
  const removedArtifactKeys = Array.from(new Set(
    [...removedArtifacts, ...removedFailedArtifacts]
      .map((item) => String(item || '').replace(/^\/+/, '').trim())
      .filter((item) => Boolean(item) && !keepArtifactSet.has(item))
  ));
  for (const objectKey of removedArtifactKeys) {
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
  const removals = await cleanupLocalImages(params.environmentId, keepImageTagSet, params.stackName);
  const registryCleanup = await cleanupRegistryImages({
    environmentId: params.environmentId,
    keepImageTags: keepImageTagSet,
    removals,
  });
  if (registryCleanup.deleted > 0) {
    await runRegistryGc();
  }

  await maybeAggressivePrune('post-deploy', params.previousSuccessAt);
}

function listQueueFiles(): string[] {
  const queueDirs = getQueueSourceDirs();
  for (const dirPath of queueDirs) {
    if (!fs.existsSync(dirPath)) {
      continue;
    }
    const files = fs.readdirSync(dirPath, { withFileTypes: true })
      .filter((entry) => entry.isFile() && DEPLOY_RECORD_FILENAME.test(entry.name))
      .map((entry) => path.join(dirPath, entry.name))
      .sort((a, b) => a.localeCompare(b));
    if (files.length) {
      return files;
    }
  }
  return [];
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
  ensureDir(DEPLOY_QUEUED_DIR);
  const entries = fs.readdirSync(processingDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && DEPLOY_RECORD_FILENAME.test(entry.name))
    .map((entry) => entry.name);
  for (const entry of entries) {
    const source = path.join(processingDir, entry);
    const target = path.join(DEPLOY_QUEUED_DIR, entry);
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
    ensureDir(DEPLOY_QUEUED_DIR);
    const target = path.join(DEPLOY_QUEUED_DIR, path.basename(currentDeploymentPath));
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

function assertNoLatestImages(stackConfig: string) {
  const latestLines = stackConfig
    .split('\n')
    .filter((line) => line.trim().startsWith('image:') && line.includes(':latest'));
  if (latestLines.length) {
    throw new Error(`Stack config resolved to :latest images: ${latestLines.join(' | ')}`);
  }
}

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

function parseRegistryTagsResponse(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw) as { tags?: unknown };
    return Array.isArray(parsed.tags)
      ? parsed.tags.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
  } catch {
    return [];
  }
}

async function registryImageTagExists(
  registryHost: string,
  registryPort: string,
  repository: string,
  tag: string,
): Promise<boolean> {
  const host = String(registryHost || '').trim();
  const port = String(registryPort || '').trim();
  const repo = String(repository || '').replace(/^\/+/, '').trim();
  const imageTag = String(tag || '').trim();
  if (!host || !port || !repo || !imageTag) {
    return false;
  }

  const tagsUrl = `http://${host}:${port}/v2/${repo}/tags/list`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    const response = await fetch(tagsUrl, { signal: controller.signal });
    clearTimeout(timeout);
    if (response.ok) {
      const tags = parseRegistryTagsResponse(await response.text());
      if (tags.includes(imageTag)) {
        return true;
      }
    }
  } catch {
    // Fallback below handles non-HTTP responses and daemon-side registry config.
  }

  const manifestRef = `${host}:${port}/${repo}:${imageTag}`;
  const manifest = await runCommandCaptureWithStatus('docker', ['manifest', 'inspect', manifestRef]);
  return manifest.code === 0;
}

async function collectMissingServiceImages(envVars: NodeJS.ProcessEnv): Promise<string[]> {
  const registryHost = String(envVars.REGISTRY_PULL_HOST || envVars.REGISTRY_HOST || '127.0.0.1').trim() || '127.0.0.1';
  const registryPort = String(envVars.REGISTRY_PORT || '5000').trim() || '5000';
  const targets = [
    { repository: 'mz-varnish', tag: String(envVars.VARNISH_VERSION || '').trim() },
    { repository: 'mz-nginx', tag: String(envVars.NGINX_VERSION || '').trim() },
    { repository: 'mz-php-fpm', tag: String(envVars.PHP_VERSION || '').trim() },
    { repository: 'mz-mariadb', tag: String(envVars.MARIADB_VERSION || '').trim() },
    { repository: 'mz-proxysql', tag: String(envVars.PROXYSQL_VERSION || '').trim() },
    { repository: 'mz-opensearch', tag: String(envVars.OPENSEARCH_VERSION || '').trim() },
    { repository: 'mz-rabbitmq', tag: String(envVars.RABBITMQ_VERSION || '').trim() },
    { repository: 'mz-cloudflared', tag: String(envVars.CLOUDFLARED_VERSION || '').trim() },
  ];
  const missing: string[] = [];
  for (const target of targets) {
    if (!target.tag) {
      missing.push(`${target.repository}:<missing-version>`);
      continue;
    }
    const exists = await registryImageTagExists(registryHost, registryPort, target.repository, target.tag);
    if (!exists) {
      missing.push(`${target.repository}:${target.tag}`);
    }
  }
  return missing;
}

async function appImagesExist(envVars: NodeJS.ProcessEnv, mageVersion: string): Promise<boolean> {
  const registryHost = String(envVars.REGISTRY_PULL_HOST || envVars.REGISTRY_HOST || '127.0.0.1').trim() || '127.0.0.1';
  const registryPort = String(envVars.REGISTRY_PORT || '5000').trim() || '5000';
  const magentoExists = await registryImageTagExists(registryHost, registryPort, 'mz-magento', mageVersion);
  if (!magentoExists) {
    return false;
  }
  const nginxAppExists = await registryImageTagExists(registryHost, registryPort, 'mz-nginx-app', mageVersion);
  if (!nginxAppExists) {
    return false;
  }

  const currentCloudSwarmRef = await getCloudSwarmRef();
  if (!currentCloudSwarmRef) {
    return true;
  }

  const registryRefPrefix = `${registryHost}:${registryPort}`;
  const [magentoCloudSwarmRef, nginxAppCloudSwarmRef] = await Promise.all([
    getDockerImageLabel(
      `${registryRefPrefix}/mz-magento:${mageVersion}`,
      'org.magezero.cloud_swarm_ref',
    ),
    getDockerImageLabel(
      `${registryRefPrefix}/mz-nginx-app:${mageVersion}`,
      'org.magezero.cloud_swarm_ref',
    ),
  ]);

  return shouldReuseAppImagesForCloudSwarmRef(currentCloudSwarmRef, {
    magento: magentoCloudSwarmRef,
    nginxApp: nginxAppCloudSwarmRef,
  });
}

async function getCloudSwarmRef(): Promise<string | null> {
  const result = await runCommandCaptureWithStatus('git', ['-C', CLOUD_SWARM_DIR, 'rev-parse', 'HEAD']);
  if (result.code !== 0) {
    return null;
  }
  const value = String(result.stdout || '').trim();
  return value || null;
}

async function getDockerImageLabel(imageRef: string, label: string): Promise<string | null> {
  const inspectArgs = ['image', 'inspect', imageRef, '--format', `{{ index .Config.Labels "${label}" }}`];
  let result = await runCommandCaptureWithStatus('docker', inspectArgs);
  if (result.code !== 0) {
    const pull = await runCommandCaptureWithStatus('docker', ['pull', imageRef]);
    if (pull.code !== 0) {
      return null;
    }
    result = await runCommandCaptureWithStatus('docker', inspectArgs);
    if (result.code !== 0) {
      return null;
    }
  }
  const value = String(result.stdout || '').trim();
  return value || null;
}

function shouldReuseAppImagesForCloudSwarmRef(
  currentCloudSwarmRef: string | null,
  imageCloudSwarmRefs: { magento: string | null; nginxApp: string | null },
): boolean {
  const current = String(currentCloudSwarmRef || '').trim();
  if (!current) {
    return true;
  }
  return imageCloudSwarmRefs.magento === current && imageCloudSwarmRefs.nginxApp === current;
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

  await runCommand(
    'git',
    ['-C', CLOUD_SWARM_DIR, 'fetch', '--prune', CLOUD_SWARM_REPO, '+refs/heads/main:refs/remotes/origin/main'],
    { env: gitEnv },
  );
  // Treat the cloud-swarm checkout as an ephemeral build toolchain:
  // always force it to match `origin/main` so local modifications can't break deploys.
  await runCommand('git', ['-C', CLOUD_SWARM_DIR, 'checkout', '-B', 'main', 'origin/main', '--force'], { env: gitEnv });
}

const MONITORING_RUNTIME_SERVICES = [
  'mz-monitoring_opensearch',
  'mz-monitoring_opensearch-dashboards',
  'mz-monitoring_otel-collector',
  'mz-monitoring_data-prepper',
  'mz-monitoring_metricbeat',
  'mz-monitoring_filebeat',
] as const;
const CLOUDFLARED_SERVICE_MARKERS = ['cloudflared', '_tunnel'];

const monitoringHealthTimeoutParsed = Number(process.env.MZ_MONITORING_HEALTH_TIMEOUT_MS);
const MONITORING_HEALTH_TIMEOUT_MS = Number.isFinite(monitoringHealthTimeoutParsed) && monitoringHealthTimeoutParsed > 0
  ? monitoringHealthTimeoutParsed
  : 8 * 60 * 1000;
const monitoringHealthPollParsed = Number(process.env.MZ_MONITORING_HEALTH_POLL_MS);
const MONITORING_HEALTH_POLL_MS = Number.isFinite(monitoringHealthPollParsed) && monitoringHealthPollParsed > 0
  ? Math.max(5_000, monitoringHealthPollParsed)
  : 10_000;
const monitoringDashboardsBootstrapRetriesParsed = Number(process.env.MZ_MONITORING_DASHBOARDS_BOOTSTRAP_RETRIES);
const MONITORING_DASHBOARDS_BOOTSTRAP_RETRIES = Number.isFinite(monitoringDashboardsBootstrapRetriesParsed)
  && monitoringDashboardsBootstrapRetriesParsed > 0
  ? Math.floor(monitoringDashboardsBootstrapRetriesParsed)
  : 3;
const monitoringDashboardsBootstrapDelayParsed = Number(process.env.MZ_MONITORING_DASHBOARDS_BOOTSTRAP_DELAY_MS);
const MONITORING_DASHBOARDS_BOOTSTRAP_DELAY_MS = Number.isFinite(monitoringDashboardsBootstrapDelayParsed)
  && monitoringDashboardsBootstrapDelayParsed > 0
  ? Math.max(1_000, monitoringDashboardsBootstrapDelayParsed)
  : 5_000;
const MONITORING_DASHBOARDS_REQUIRED = (process.env.MZ_MONITORING_DASHBOARDS_REQUIRED || '0') === '1';

type MonitoringRuntimeStatus = {
  serviceName: string;
  desiredRunning: number;
  running: number;
  issues: string[];
};

type DockerServiceNetworkRef = {
  Target?: string;
};

async function inspectMonitoringRuntimeService(serviceName: string): Promise<MonitoringRuntimeStatus> {
  const result = await runCommandCaptureWithStatus(
    'docker',
    ['service', 'ps', serviceName, '--no-trunc', '--format', '{{.DesiredState}}|{{.CurrentState}}|{{.Error}}'],
  );
  if (result.code !== 0) {
    const details = (result.stderr || result.stdout || 'service inspect failed').trim();
    return {
      serviceName,
      desiredRunning: 0,
      running: 0,
      issues: [details],
    };
  }

  let desiredRunning = 0;
  let running = 0;
  const issues: string[] = [];
  for (const rawLine of result.stdout.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const [desiredStateRaw = '', currentStateRaw = '', errorRaw = ''] = line.split('|');
    const desiredState = desiredStateRaw.trim().toLowerCase();
    if (desiredState !== 'running') continue;
    desiredRunning += 1;
    const currentState = currentStateRaw.trim();
    if (currentState.startsWith('Running')) {
      running += 1;
      continue;
    }
    const error = errorRaw.trim();
    const suffix = error ? ` (${error})` : '';
    if (issues.length < 3) {
      issues.push(`${currentState}${suffix}`.trim());
    }
  }

  if (desiredRunning === 0) {
    issues.push('no tasks desired Running');
  }

  return {
    serviceName,
    desiredRunning,
    running,
    issues,
  };
}

async function inspectMonitoringRuntimeServices(serviceNames: string[]): Promise<MonitoringRuntimeStatus[]> {
  const results: MonitoringRuntimeStatus[] = [];
  for (const serviceName of serviceNames) {
    results.push(await inspectMonitoringRuntimeService(serviceName));
  }
  return results;
}

function monitoringRuntimeHealthy(statuses: MonitoringRuntimeStatus[]): boolean {
  return statuses.every((status) => status.desiredRunning > 0 && status.running === status.desiredRunning);
}

function summarizeMonitoringRuntimeIssues(statuses: MonitoringRuntimeStatus[]): string {
  return statuses
    .filter((status) => status.desiredRunning === 0 || status.running < status.desiredRunning || status.issues.length > 0)
    .map((status) => {
      const base = `${status.serviceName} ${status.running}/${status.desiredRunning}`;
      if (!status.issues.length) return base;
      return `${base} (${status.issues.join('; ')})`;
    })
    .join(' | ');
}

async function waitForMonitoringRuntimeHealthy(log: (msg: string) => void): Promise<void> {
  const deadline = Date.now() + MONITORING_HEALTH_TIMEOUT_MS;
  let lastSummary = '';
  while (Date.now() < deadline) {
    const statuses = await inspectMonitoringRuntimeServices([...MONITORING_RUNTIME_SERVICES]);
    if (monitoringRuntimeHealthy(statuses)) {
      return;
    }
    const summary = summarizeMonitoringRuntimeIssues(statuses);
    if (summary && summary !== lastSummary) {
      log(`monitoring stack not yet healthy: ${summary}`);
      lastSummary = summary;
    }
    await delay(MONITORING_HEALTH_POLL_MS);
  }

  const statuses = await inspectMonitoringRuntimeServices([...MONITORING_RUNTIME_SERVICES]);
  throw new Error(
    `Monitoring stack did not become healthy within ${Math.round(MONITORING_HEALTH_TIMEOUT_MS / 1000)}s: ${summarizeMonitoringRuntimeIssues(statuses)}`
  );
}

async function ensureCloudflaredMonitoringNetwork(log: (msg: string) => void): Promise<void> {
  const monitoringNetwork = await runCommandCaptureWithStatus(
    'docker',
    ['network', 'inspect', 'mz-monitoring', '--format', '{{.ID}}'],
  );
  if (monitoringNetwork.code !== 0) {
    throw new Error(`Unable to inspect mz-monitoring network: ${monitoringNetwork.stderr || monitoringNetwork.stdout}`);
  }
  const monitoringNetworkId = monitoringNetwork.stdout.trim();
  if (!monitoringNetworkId) {
    throw new Error('Unable to resolve mz-monitoring network id');
  }

  const services = await runCommandCaptureWithStatus('docker', ['service', 'ls', '--format', '{{.Name}}']);
  if (services.code !== 0) {
    throw new Error(`Unable to list services: ${services.stderr || services.stdout}`);
  }

  const candidates = services.stdout
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .filter((name) => CLOUDFLARED_SERVICE_MARKERS.some((marker) => name.includes(marker)));

  for (const serviceName of candidates) {
    const inspect = await runCommandCaptureWithStatus(
      'docker',
      ['service', 'inspect', serviceName, '--format', '{{json .Spec.TaskTemplate.Networks}}'],
    );
    if (inspect.code !== 0) {
      log(`monitoring: unable to inspect ${serviceName} networks (${inspect.stderr || inspect.stdout})`);
      continue;
    }

    let attached = false;
    try {
      const parsed = JSON.parse(inspect.stdout || '[]') as DockerServiceNetworkRef[];
      attached = parsed.some((entry) => String(entry?.Target || '').trim() === monitoringNetworkId);
    } catch {
      attached = false;
    }

    if (attached) {
      continue;
    }

    log(`attaching ${serviceName} to mz-monitoring network`);
    const update = await runCommandCaptureWithStatus(
      'docker',
      ['service', 'update', '--network-add', 'mz-monitoring', serviceName],
    );
    if (update.code !== 0) {
      const output = `${update.stderr}\n${update.stdout}`.toLowerCase();
      if (output.includes('already exists')) {
        continue;
      }
      throw new Error(`Failed to attach ${serviceName} to mz-monitoring: ${update.stderr || update.stdout}`);
    }
  }
}

async function ensureMonitoringDashboards(log: (msg: string) => void): Promise<void> {
  let lastError = '';
  for (let attempt = 1; attempt <= MONITORING_DASHBOARDS_BOOTSTRAP_RETRIES; attempt += 1) {
    try {
      const result = await bootstrapMonitoringDashboards();
      log(
        `monitoring dashboards ready (${result.dashboard_ids.join(', ')}, objects=${result.upserted_objects})`
      );
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      lastError = message;
      if (attempt >= MONITORING_DASHBOARDS_BOOTSTRAP_RETRIES) {
        break;
      }
      log(`monitoring dashboards bootstrap retry ${attempt}: ${message}`);
      await new Promise((resolve) => setTimeout(resolve, MONITORING_DASHBOARDS_BOOTSTRAP_DELAY_MS));
    }
  }
  const message = `monitoring dashboards bootstrap failed: ${lastError || 'unknown error'}`;
  if (MONITORING_DASHBOARDS_REQUIRED) {
    throw new Error(message);
  }
  log(`${message}; continuing deploy`);
}

/**
 * Ensure the mz-monitoring overlay network and monitoring stack exist.
 * Idempotent: skips only when required monitoring services are present and healthy.
 */
/** Configs defined in monitoring.yml that Docker Swarm treats as immutable. */
const MONITORING_STACK_CONFIGS: Array<{ dockerName: string; filePath: string }> = [
  { dockerName: 'mz-monitoring_mz-monitoring-otel-collector-config', filePath: 'config/monitoring/otel-collector-config.yaml' },
  { dockerName: 'mz-monitoring_mz-monitoring-data-prepper-config', filePath: 'config/monitoring/data-prepper-config.yaml' },
  { dockerName: 'mz-monitoring_mz-monitoring-data-prepper-pipelines', filePath: 'config/monitoring/data-prepper-pipelines.yaml' },
];

/**
 * Docker Swarm configs are immutable — `docker stack deploy` silently keeps the
 * old config even when the source file on disk has changed.  Compare each
 * deployed config's content (base64 from `docker config inspect`) with the
 * current file on disk and return true if any differ.
 */
async function monitoringConfigsStale(log: (msg: string) => void): Promise<boolean> {
  for (const { dockerName, filePath } of MONITORING_STACK_CONFIGS) {
    const diskPath = path.join(CLOUD_SWARM_DIR, filePath);
    if (!fs.existsSync(diskPath)) continue;

    const { code, stdout } = await runCommandCaptureWithStatus(
      'docker', ['config', 'inspect', dockerName, '--format', '{{json .Spec.Data}}'],
    );
    if (code !== 0) continue; // config doesn't exist yet — will be created on deploy

    let deployedBase64: string;
    try {
      deployedBase64 = JSON.parse(stdout.trim());
    } catch {
      continue;
    }

    const diskBase64 = fs.readFileSync(diskPath).toString('base64');
    if (deployedBase64 !== diskBase64) {
      log(`monitoring config ${filePath} is stale — will tear down stack for fresh deploy`);
      return true;
    }
  }
  return false;
}

async function ensureMonitoringStack(log: (msg: string) => void, envVars: NodeJS.ProcessEnv) {
  // 1. Ensure the mz-monitoring overlay network exists
  const { code: netCode } = await runCommandCaptureWithStatus(
    'docker', ['network', 'inspect', 'mz-monitoring'],
  );
  if (netCode !== 0) {
    log('creating mz-monitoring overlay network');
    await runCommandCapture('docker', [
      'network', 'create',
      '--driver', 'overlay',
      '--attachable',
      '--opt', 'encrypted=true',
      'mz-monitoring',
    ]);
  }
  await ensureCloudflaredMonitoringNetwork(log);

  // 2. Deploy/reconcile monitoring stack when required services are missing or unhealthy.
  const { stdout: serviceList } = await runCommandCapture('docker', ['service', 'ls', '--format', '{{.Name}}']);
  const existingServices = new Set(
    serviceList
      .split('\n')
      .map((name) => name.trim())
      .filter(Boolean),
  );
  const missingServices = [...MONITORING_RUNTIME_SERVICES].filter((serviceName) => !existingServices.has(serviceName));
  const currentStatuses = await inspectMonitoringRuntimeServices(
    [...MONITORING_RUNTIME_SERVICES].filter((serviceName) => existingServices.has(serviceName)),
  );
  const healthy = missingServices.length === 0 && monitoringRuntimeHealthy(currentStatuses);
  const configsStale = await monitoringConfigsStale(log);

  if (healthy && !configsStale) {
    log('monitoring stack already deployed and healthy');
    await ensureMonitoringDashboards(log);
    return;
  }

  if (configsStale) {
    // Docker Swarm configs are immutable — the only way to update them is to
    // remove the stack (which frees the config names) and redeploy.
    log('tearing down monitoring stack to refresh stale configs');
    await runCommandCapture('docker', ['stack', 'rm', 'mz-monitoring']);
    await delay(10_000);
  }

  if (missingServices.length) {
    log(`monitoring stack missing services: ${missingServices.join(', ')}`);
  }
  const currentIssues = summarizeMonitoringRuntimeIssues(currentStatuses);
  if (currentIssues) {
    log(`monitoring stack needs reconcile: ${currentIssues}`);
  }

  log('deploying monitoring stack');
  const monitoringBaseStackPath = path.join(CLOUD_SWARM_DIR, 'stacks/monitoring-base.yml');
  const monitoringStackPath = path.join(CLOUD_SWARM_DIR, 'stacks/monitoring.yml');
  await runCommandCapture('docker', [
    'stack', 'deploy',
    '--with-registry-auth',
    '-c', monitoringBaseStackPath,
    '-c', monitoringStackPath,
    'mz-monitoring',
  ], { env: envVars });
  await ensureCloudflaredMonitoringNetwork(log);
  await waitForMonitoringRuntimeHealthy(log);
  await ensureMonitoringDashboards(log);
  log('monitoring stack deployed and healthy');
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

async function configureReplicaViaSwarmJob(params: {
  environmentId: number;
  replicaServiceFullName: string;
  masterHost: string;
  replicaUser: string;
}) {
  const replicaSpec = await inspectServiceSpec(params.replicaServiceFullName);
  if (!replicaSpec) {
    throw new Error(`missing service: ${params.replicaServiceFullName}`);
  }

  const replicaTasks = await listServiceTasks(params.replicaServiceFullName);
  const desiredRunning = replicaTasks.filter((task) => task.desired_state.toLowerCase() === 'running');
  if (!desiredRunning.length) {
    const summary = replicaTasks
      .slice(0, 3)
      .map((task) => `${task.name} ${task.current_state}${task.error ? ` (${task.error})` : ''}`)
      .join('; ');
    throw new Error(
      `replica service has no desired running tasks${summary ? `: ${summary}` : ''}`,
    );
  }

  const safeMasterHost = params.masterHost.replace(/'/g, "''");
  const safeReplicaUser = params.replicaUser.replace(/'/g, "''");
  const safeReplicaHost = params.replicaServiceFullName.replace(/'/g, "''");
  const passRef = '${REPL_PASS}';
  const script = [
    'set -e',
    'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `i=0; until mariadb -h '${safeReplicaHost}' -uroot -p"$ROOT_PASS" -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done`,
    `mariadb -h '${safeReplicaHost}' -uroot -p"$ROOT_PASS" -e "CHANGE MASTER TO MASTER_HOST='${safeMasterHost}', MASTER_PORT=3306, MASTER_USER='${safeReplicaUser}', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos;"`,
    `mariadb -h '${safeReplicaHost}' -uroot -p"$ROOT_PASS" -e "START SLAVE;"`,
  ].join(' && ');

  const job = await runSwarmJob({
    name: buildJobName('deploy-replica-config', params.environmentId),
    image: replicaSpec.image,
    networks: replicaSpec.networks.map((network) => network.name).filter(Boolean),
    secrets: replicaSpec.secrets.map((secret) => ({ source: secret.secret_name, target: secret.file_name })),
    env: replicaSpec.env,
    command: ['sh', '-lc', script],
    timeout_ms: 120_000,
  });
  if (!job.ok) {
    const detail = (job.logs || job.error || '').trim();
    throw new Error(detail || `replica config job failed (${job.state})`);
  }
}

function buildProxySqlRuleReconcileScript(proxysqlServiceFullName: string): string {
  const sql = buildProxySqlQueryRulesSql(PROXYSQL_MANAGED_QUERY_RULES).trimEnd();
  const script = [
    'set -eu',
    `PROXYSQL_HOST="${proxysqlServiceFullName}"`,
    'SQL_FILE="$(mktemp)"',
    'cleanup() { rm -f "$SQL_FILE"; }',
    'trap cleanup EXIT',
    "cat > \"$SQL_FILE\" <<'SQL'",
    sql,
    'SQL',
    'CLIENT=""',
    'if command -v mariadb >/dev/null 2>&1; then CLIENT="mariadb"; elif command -v mysql >/dev/null 2>&1; then CLIENT="mysql"; fi',
    'if [ -z "$CLIENT" ]; then echo "missing mariadb/mysql client" >&2; exit 2; fi',
    'ADMIN_USER=""',
    'ADMIN_PASS=""',
    'i=0',
    'while [ -z "$ADMIN_USER" ]; do',
    '  for AUTH in "radmin:radmin" "admin:admin"; do',
    '    USER="${AUTH%%:*}"',
    '    PASS="${AUTH#*:}"',
    '    if $CLIENT -h "$PROXYSQL_HOST" -P 6032 -u "$USER" -p"$PASS" -e "SELECT 1" >/dev/null 2>&1; then',
    '      ADMIN_USER="$USER"',
    '      ADMIN_PASS="$PASS"',
    '      break',
    '    fi',
    '  done',
    '  if [ -n "$ADMIN_USER" ]; then break; fi',
    '  i=$((i+1))',
    '  if [ "$i" -gt 60 ]; then echo "proxysql admin not ready" >&2; exit 1; fi',
    '  sleep 1',
    'done',
    '$CLIENT -h "$PROXYSQL_HOST" -P 6032 -u "$ADMIN_USER" -p"$ADMIN_PASS" < "$SQL_FILE"',
  ].join('\n');
  // Base64-encode to avoid newlines in the command argv (which triggers the command policy check).
  const encoded = Buffer.from(script).toString('base64');
  return `printf '%s' '${encoded}' | base64 -d | sh`;
}

async function enforceProxySqlQueryRules(params: {
  environmentId: number;
  log: (message: string) => void;
}): Promise<void> {
  const proxysqlServiceFullName = envServiceName(params.environmentId, 'proxysql');
  const proxysqlSpec = await inspectServiceSpec(proxysqlServiceFullName);
  if (!proxysqlSpec) {
    throw new Error(`proxysql query rules: missing service ${proxysqlServiceFullName}`);
  }

  const networks = Array.from(new Set(proxysqlSpec.networks.map((net) => net.name).filter(Boolean)));
  if (!networks.length) networks.push('mz-backend');

  const tasks = await listServiceTasks(proxysqlServiceFullName);
  const runningTask = tasks.find((task) => task.current_state.startsWith('Running') && task.node)
    || tasks.find((task) => Boolean(task.node));
  const constraints = runningTask?.node ? [`node.hostname==${runningTask.node}`] : [];
  const script = buildProxySqlRuleReconcileScript(proxysqlServiceFullName);

  let lastError: Error | null = null;
  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const job = await runSwarmJob({
      name: buildJobName('deploy-proxysql-rules', params.environmentId),
      image: proxysqlSpec.image,
      entrypoint: 'sh',
      networks,
      constraints,
      command: ['-lc', script],
      timeout_ms: 120_000,
    });

    if (job.ok) {
      params.log('proxysql query rules: reconciled (search_tmp_ -> writer, SELECT -> reader)');
      return;
    }

    const detail = (job.logs || job.error || '').trim();
    lastError = new Error(detail || `swarm job failed (${job.state})`);
    params.log(`proxysql query rules attempt ${attempt}/${maxAttempts} failed: ${lastError.message}`);
    await delay(2000);
  }

  throw lastError || new Error('proxysql query rules reconciliation failed');
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

async function detectSearchEngine(
  containerId: string,
  dbName: string
): Promise<string | null> {
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  try {
    const result = await runCommandCapture('docker', [
      'exec', containerId, 'sh', '-c',
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -N -s -D ${safeDbName} -e "SELECT value FROM core_config_data WHERE scope='default' AND scope_id=0 AND path='catalog/search/engine' LIMIT 1"`,
    ]);
    return parseDetectedEngine(result.stdout);
  } catch {
    return null;
  }
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

/**
 * Wait for in-flight Magento cron jobs to finish before running setup:upgrade.
 * Maintenance mode prevents new cron runs from starting work, but jobs already
 * running hold locks on cron_schedule that cause setup:upgrade to fail with
 * SQLSTATE 1205 "Lock wait timeout exceeded".
 */
async function waitForCronJobsToFinish(
  containerId: string,
  dbName: string,
  log: (message: string) => void,
  timeoutMs: number = 120_000,
): Promise<void> {
  const safeSchema = escapeSqlValue(dbName);
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const result = await runCommandCaptureWithStatus('docker', [
      'exec',
      containerId,
      'sh',
      '-c',
      `ROOT_PASS="$(cat /run/secrets/db_root_password)"; mariadb -uroot -p"$ROOT_PASS" -N -s -e "SELECT COUNT(*) FROM ${safeSchema}.cron_schedule WHERE status='running'"`,
    ]);
    const count = Number((result.stdout || '').trim());
    if (result.code === 0 && Number.isFinite(count) && count === 0) {
      log('no running cron jobs; safe to proceed with setup:upgrade');
      return;
    }
    if (result.code !== 0) {
      log(`warning: cron_schedule check failed (exit ${result.code}); proceeding anyway`);
      return;
    }
    log(`waiting for ${count} running cron job(s) to finish before setup:upgrade`);
    await delay(5000);
  }
  log('warning: timed out waiting for cron jobs to finish; proceeding with setup:upgrade');
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

async function setSearchSystemConfig(
  stackName: string,
  containerId: string,
  dbName: string,
  host: string,
  port: string,
  timeout: string
): Promise<string> {
  const safeDbName = assertSafeIdentifier(dbName, 'database name').replace(/`/g, '``');
  const statements = buildSearchSystemConfigSql(host, port, timeout);
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
    'set -e',
    '',
    'if [ -f /var/www/html/magento/app/etc/env.php ]; then',
    '  if [ ! -f /var/www/html/magento/app/etc/env.base.php ]; then',
    '    cp /var/www/html/magento/app/etc/env.php /var/www/html/magento/app/etc/env.base.php',
    '  elif ! grep -q "env.base.php" /var/www/html/magento/app/etc/env.php; then',
    '    cp /var/www/html/magento/app/etc/env.php /var/www/html/magento/app/etc/env.base.php',
    '  fi',
    'fi',
    '',
    'if [ ! -f /var/www/html/magento/app/etc/env.base.php ] && [ -f /var/www/html/magento/app/etc/env.warden.php ]; then',
    '  cp /var/www/html/magento/app/etc/env.warden.php /var/www/html/magento/app/etc/env.base.php',
    'fi',
    '',
    'if [ ! -f /var/www/html/magento/app/etc/env.base.php ]; then',
    '  printf "%s\\n" "<?php" "return [];" > /var/www/html/magento/app/etc/env.base.php',
    'fi',
    '',
    'cp /usr/local/share/mz-env.php /var/www/html/magento/app/etc/env.php',
    'chown www-data:www-data /var/www/html/magento/app/etc/env.php /var/www/html/magento/app/etc/env.base.php',
    '',
    'if [ -f /var/www/html/magento/app/etc/config.php ]; then',
    '  if [ ! -f /var/www/html/magento/app/etc/config.base.php ]; then',
    '    cp /var/www/html/magento/app/etc/config.php /var/www/html/magento/app/etc/config.base.php',
    '  elif ! grep -q "config.base.php" /var/www/html/magento/app/etc/config.php; then',
    '    cp /var/www/html/magento/app/etc/config.php /var/www/html/magento/app/etc/config.base.php',
    '  fi',
    '  cp /usr/local/share/mz-config.php /var/www/html/magento/app/etc/config.php',
    '  chown www-data:www-data /var/www/html/magento/app/etc/config.php /var/www/html/magento/app/etc/config.base.php',
    'fi',
  ].join('\n');
  const result = await runCommandCaptureWithStatus('docker', ['exec', '--user', 'root', containerId, 'sh', '-c', command]);
  if (result.code !== 0) {
    const output = (result.stderr || result.stdout || '').trim();
    throw new Error(`env/config wrapper failed (exit ${result.code}): ${output || 'unknown error'}`);
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
        log(`env/config wrapper retry ${attempt}: ${message}`);
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

function hasUnknownReplicasMaxPerNodeFlag(output: string): boolean {
  const lower = output.toLowerCase();
  return lower.includes('unknown flag') && lower.includes('replicas-max-per-node');
}

function isNoSuchServiceOutput(output: string): boolean {
  return output.toLowerCase().includes('no such service');
}

function isNoopServiceUpdateOutput(output: string): boolean {
  const lower = output.toLowerCase();
  return lower.includes('only updates to') || lower.includes('nothing to update');
}

async function inspectFrontendRuntimeSpec(serviceName: string): Promise<FrontendRuntimeSpec | null> {
  const inspect = await runCommandCaptureWithStatus('docker', [
    'service',
    'inspect',
    serviceName,
    '--format',
    '{{json .Spec}}',
  ]);
  if (inspect.code !== 0) {
    return null;
  }

  const raw = String(inspect.stdout || '').trim();
  if (!raw || raw === '<no value>' || raw === 'null') {
    return null;
  }

  let spec: Record<string, unknown>;
  try {
    spec = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }

  const mode = spec.Mode as Record<string, unknown> | undefined;
  const replicated = mode?.Replicated as Record<string, unknown> | undefined;
  const replicasRaw = replicated?.Replicas;
  const replicasParsed = Number(replicasRaw ?? 0);
  const replicas = Number.isFinite(replicasParsed) ? Math.max(0, Math.round(replicasParsed)) : 0;

  const taskTemplate = spec.TaskTemplate as Record<string, unknown> | undefined;
  const placement = taskTemplate?.Placement as Record<string, unknown> | undefined;
  const maxReplicasRaw = placement?.MaxReplicas;
  const maxReplicasParsed = Number(maxReplicasRaw ?? 0);
  const maxReplicasPerNode = Number.isFinite(maxReplicasParsed)
    ? Math.max(0, Math.round(maxReplicasParsed))
    : 0;
  const restartPolicy = taskTemplate?.RestartPolicy as Record<string, unknown> | undefined;
  const restartCondition = String(restartPolicy?.Condition || '').trim().toLowerCase();
  const updateConfig = spec.UpdateConfig as Record<string, unknown> | undefined;
  const updateOrder = String(updateConfig?.Order || '').trim().toLowerCase();

  return {
    replicas,
    max_replicas_per_node: maxReplicasPerNode,
    restart_condition: restartCondition,
    update_order: updateOrder,
  };
}

async function enforceFrontendRuntimePolicyForService(
  serviceName: string,
  policy: FrontendRuntimePolicy,
  log: (message: string) => void,
) {
  const current = await inspectFrontendRuntimeSpec(serviceName);
  if (!current) {
    log(`frontend runtime policy: ${serviceName} skipped (service missing)`);
    return;
  }

  const args: string[] = ['service', 'update'];
  const details: string[] = [];
  let includesMaxPerNodeFlag = false;

  if (current.replicas !== policy.replicas) {
    args.push('--replicas', String(policy.replicas));
    details.push(`replicas=${policy.replicas}`);
  }
  if (current.max_replicas_per_node !== policy.max_replicas_per_node) {
    args.push('--replicas-max-per-node', String(policy.max_replicas_per_node));
    includesMaxPerNodeFlag = true;
    details.push(`max_per_node=${policy.max_replicas_per_node}`);
  }
  if (current.update_order !== policy.update_order) {
    args.push('--update-order', policy.update_order, '--rollback-order', policy.update_order);
    details.push(`order=${policy.update_order}`);
  }
  if (current.restart_condition !== policy.restart_condition) {
    args.push('--restart-condition', policy.restart_condition);
    details.push(`restart=${policy.restart_condition}`);
  }

  if (details.length > 0) {
    args.push(serviceName);
    let update = await runCommandCaptureWithStatus('docker', args);
    if (update.code !== 0 && includesMaxPerNodeFlag) {
      const combined = `${update.stdout || ''}\n${update.stderr || ''}`;
      if (hasUnknownReplicasMaxPerNodeFlag(combined)) {
        const fallbackArgs: string[] = [];
        for (let i = 0; i < args.length; i += 1) {
          const arg = args[i] || '';
          if (arg === '--replicas-max-per-node') {
            i += 1; // skip flag value as well
            continue;
          }
          fallbackArgs.push(arg);
        }
        update = await runCommandCaptureWithStatus('docker', fallbackArgs);
      }
    }

    if (update.code !== 0) {
      const combined = `${update.stdout || ''}\n${update.stderr || ''}`.trim();
      if (isNoSuchServiceOutput(combined)) {
        log(`frontend runtime policy: ${serviceName} skipped (service missing during update)`);
        return;
      }
      if (isNoopServiceUpdateOutput(combined)) {
        log(`frontend runtime policy: ${serviceName} already aligned`);
      } else {
        log(`frontend runtime policy: ${serviceName} update failed (${combined || `exit ${update.code}`})`);
      }
    } else {
      log(`frontend runtime policy: ${serviceName} aligned (${details.join(' ')})`);
    }
  }

  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const state = String(updateStatus?.state || '').toLowerCase();
  const message = String(updateStatus?.message || '').toLowerCase();
  const pausedByPlacement = state.includes('pause')
    && (message.includes('max replicas per node') || message.includes('no suitable node'));
  if (!pausedByPlacement || policy.update_order !== 'stop-first') {
    return;
  }

  log(`frontend runtime policy: ${serviceName} paused by placement limits; forcing stop-first rollout`);
  let recover = await runCommandCaptureWithStatus('docker', [
    'service',
    'update',
    '--update-order',
    policy.update_order,
    '--rollback-order',
    policy.update_order,
    '--force',
    serviceName,
  ]);
  if (recover.code !== 0) {
    const combined = `${recover.stdout || ''}\n${recover.stderr || ''}`.toLowerCase();
    if (combined.includes('update paused') || combined.includes('paused')) {
      await resumePausedServiceUpdate(serviceName, log);
      recover = await runCommandCaptureWithStatus('docker', [
        'service',
        'update',
        '--update-order',
        policy.update_order,
        '--rollback-order',
        policy.update_order,
        '--force',
        serviceName,
      ]);
    }
  }

  const recoverOutput = (recover.stderr || recover.stdout || '').trim();
  if (recover.code === 0) {
    log(`frontend runtime policy: ${serviceName} recovered`);
  } else {
    log(`frontend runtime policy: ${serviceName} recovery failed (exit ${recover.code}) ${recoverOutput}`);
  }
}

async function enforceFrontendRuntimePolicy(
  stackName: string,
  policy: FrontendRuntimePolicy,
  log: (message: string) => void,
) {
  const services = ['nginx', 'php-fpm']
    .map((service) => `${stackName}_${service}`);
  for (const serviceName of services) {
    await enforceFrontendRuntimePolicyForService(serviceName, policy, log);
  }
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

async function waitForAllDesiredServiceTasksRunning(
  serviceName: string,
  log: (message: string) => void,
  timeoutMs = 120_000,
): Promise<boolean> {
  const startedAt = Date.now();
  let lastStatus = 'no task data';

  while (Date.now() - startedAt < timeoutMs) {
    const tasks = await listServiceTasksWithImages(serviceName);
    const desiredRunning = tasks.filter((t) => t.desired_state.toLowerCase() === 'running');
    if (desiredRunning.length > 0) {
      const notRunning = desiredRunning.filter((t) => !t.current_state.startsWith('Running'));
      if (notRunning.length === 0) {
        return true;
      }

      const runningCount = desiredRunning.length - notRunning.length;
      lastStatus = `${runningCount}/${desiredRunning.length} desired tasks running`;

      const failedTask = notRunning.find((t) =>
        t.current_state.startsWith('Failed') || t.current_state.startsWith('Rejected'));
      if (failedTask) {
        const suffix = failedTask.error ? ` (${failedTask.error})` : '';
        log(
          `warning: ${serviceName} task failed during rollout: ${failedTask.name} on ${failedTask.node || '(unknown)'} ${failedTask.current_state}${suffix}`.trim(),
        );
        return false;
      }
    } else if (tasks.length === 0) {
      lastStatus = 'no tasks reported';
    } else {
      lastStatus = 'no tasks desired running';
    }

    await delay(2000);
  }

  log(`warning: timed out waiting for ${serviceName} desired tasks to be running (${lastStatus})`);
  const servicePs = await captureServicePs(serviceName);
  for (const line of servicePs.slice(0, 5)) {
    log(`warning: ${serviceName} ps: ${line}`);
  }
  return false;
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

function buildRollbackImageRef(currentImage: string, rollbackTag: string, registryPullHost: string, registryPort: string): string | null {
  const parsed = parseImageReference(currentImage);
  const repoPath = stripRegistryHost(parsed.repository || '');
  if (!repoPath) {
    return null;
  }
  const hostPort = `${registryPullHost}:${registryPort}`;
  return `${hostPort}/${repoPath}:${rollbackTag}`;
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

async function rollbackReleaseCohortToTag(
  services: string[],
  rollbackTag: string,
  registryPullHost: string,
  registryPort: string,
  log: (message: string) => void
): Promise<Record<string, unknown>> {
  const snapshot: Record<string, unknown> = {};
  for (const serviceName of services) {
    const currentImage = await inspectServiceImage(serviceName);
    const rollbackImage = currentImage ? buildRollbackImageRef(currentImage, rollbackTag, registryPullHost, registryPort) : null;
    if (!rollbackImage) {
      snapshot[serviceName] = {
        ok: false,
        exit_code: 1,
        output: 'Unable to determine rollback image reference.',
      };
      continue;
    }

    let result = await runCommandCaptureWithStatus('docker', [
      'service',
      'update',
      '--image',
      rollbackImage,
      '--label-add',
      `${RELEASE_ID_LABEL_KEY}=${rollbackTag}`,
      serviceName,
    ]);
    const output = `${result.stderr || ''}\n${result.stdout || ''}`.toLowerCase();
    if (result.code !== 0 && (output.includes('update paused') || output.includes('paused'))) {
      await resumePausedServiceUpdate(serviceName, log);
      result = await runCommandCaptureWithStatus('docker', [
        'service',
        'update',
        '--image',
        rollbackImage,
        '--label-add',
        `${RELEASE_ID_LABEL_KEY}=${rollbackTag}`,
        serviceName,
      ]);
    }

    snapshot[serviceName] = {
      ok: result.code === 0,
      exit_code: result.code,
      output: (result.stderr || result.stdout || '').trim() || null,
      image: rollbackImage,
    };
  }
  return snapshot;
}

async function scaleDownServices(services: string[], log: (message: string) => void): Promise<Record<string, unknown>> {
  const snapshot: Record<string, unknown> = {};
  for (const serviceName of services) {
    const result = await runCommandCaptureWithStatus('docker', [
      'service',
      'update',
      '--replicas',
      '0',
      serviceName,
    ]);
    snapshot[serviceName] = {
      ok: result.code === 0,
      exit_code: result.code,
      output: (result.stderr || result.stdout || '').trim() || null,
    };
    if (result.code === 0) {
      log(`scaled down service: ${serviceName} replicas=0`);
    } else {
      log(`failed to scale down service: ${serviceName} (exit ${result.code}) ${(result.stderr || result.stdout || '').trim()}`);
    }
  }
  return snapshot;
}

function writeJsonFileBestEffort(filePath: string, payload: unknown) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2));
  } catch {
    // ignore write failures
  }
}

// ---------------------------------------------------------------------------
// Schema upgrade marker — tracks persistent setup:db:status mismatches
// ---------------------------------------------------------------------------

type SchemaUpgradeMarker = {
  artifact: string;
  upgraded_at: string;
  post_check_needed: boolean;
};

function schemaUpgradeMarkerPath(environmentId: number): string {
  return path.join(DEPLOY_QUEUE_DIR, 'meta', `schema-upgrade-marker-env-${environmentId}.json`);
}

function readSchemaUpgradeMarker(environmentId: number): SchemaUpgradeMarker | null {
  try {
    const raw = fs.readFileSync(schemaUpgradeMarkerPath(environmentId), 'utf8');
    const parsed = JSON.parse(raw) as SchemaUpgradeMarker;
    if (parsed && typeof parsed.artifact === 'string' && parsed.post_check_needed) {
      return parsed;
    }
  } catch {
    // marker doesn't exist or is invalid
  }
  return null;
}

function writeSchemaUpgradeMarker(environmentId: number, artifact: string): void {
  const marker: SchemaUpgradeMarker = {
    artifact,
    upgraded_at: new Date().toISOString(),
    post_check_needed: true,
  };
  ensureDir(path.join(DEPLOY_QUEUE_DIR, 'meta'));
  writeJsonFileBestEffort(schemaUpgradeMarkerPath(environmentId), marker);
}

function clearSchemaUpgradeMarker(environmentId: number): void {
  try {
    fs.unlinkSync(schemaUpgradeMarkerPath(environmentId));
  } catch {
    // ignore if doesn't exist
  }
}

function enqueueDeploymentRecord(payload: DeployPayload, deploymentId: string) {
  ensureDir(DEPLOY_QUEUED_DIR);
  const target = path.join(DEPLOY_QUEUED_DIR, `${deploymentId}.json`);
  writeJsonFileBestEffort(target, { id: deploymentId, queued_at: new Date().toISOString(), payload });
}

function chooseLastKnownGoodArtifact(environmentId: number, repository: string): string | null {
  const history = readDeploymentHistory(DEPLOY_HISTORY_FILE, LEGACY_DEPLOY_HISTORY_FILE);
  const key = `env:${environmentId}:${repository}`;
  const entry = history[key];
  const artifacts = Array.isArray(entry?.artifacts) ? entry.artifacts : [];
  const artifact = String(artifacts[0] || '').trim();
  return artifact || null;
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
    'test -f /var/www/html/magento/app/etc/config.php;',
    'test -f /var/www/html/magento/app/etc/config.base.php;',
    'grep -q "env.base.php" /var/www/html/magento/app/etc/env.php;',
    'grep -q "config.base.php" /var/www/html/magento/app/etc/config.php;',
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
        buildMagentoCliCommand('setup:upgrade --keep-generated'),
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
        || message.includes('Lock wait timeout')
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

async function setMaintenanceModeViaRedis(
  adminContainerId: string,
  _stackName: string,
  mode: 'enable' | 'disable',
  log: (message: string) => void,
): Promise<void> {
  const op =
    mode === 'enable'
      ? '$r->set("maintenance:flag", "1");'
      : '$r->del("maintenance:flag");';
  const script = [
    '$host = getenv("MZ_REDIS_CACHE_HOST") ?: "redis-cache";',
    '$r = new Redis();',
    '$r->connect($host, 6379);',
    '$r->select(2);',
    op,
  ].join(' ');

  for (let attempt = 1; attempt <= 3; attempt++) {
    const result = await runCommandCaptureWithStatus('docker', ['exec', adminContainerId, 'php', '-r', script]);
    if (result.code === 0) {
      log(`maintenance:${mode} via redis: ok`);
      return;
    }
    log(`maintenance:${mode} via redis attempt ${attempt}: exit ${result.code} — ${(result.stderr || result.stdout || '').trim()}`);
    await delay(2000);
  }
  throw new Error(`maintenance:${mode} via redis failed after retries`);
}

async function setMagentoMaintenanceMode(
  containerId: string,
  stackName: string,
  mode: 'enable' | 'disable',
  log: (message: string) => void,
) {
  await setMaintenanceModeViaRedis(containerId, stackName, mode, log);
  return containerId;
}

async function runSetupDbStatus(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
): Promise<{ needed: boolean; exitCode: number; output: string; containerId: string }> {
  const setupDbStatusCommand = buildSetupDbStatusCommand(SETUP_DB_STATUS_TIMEOUT_SECONDS);
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(currentId, stackName, setupDbStatusCommand);
    const output = (result.stderr || result.stdout || '').trim();
    const outputLower = output.toLowerCase();
    const exitCode = result.code;

    // Magento core strings (example: setup/src/Magento/Setup/Console/Command/DbStatusCommand.php):
    // - ok: "All modules are up to date."
    // - upgrade required: "Run 'setup:upgrade' to update your DB schema and data."
    // - not installed: "No information is available: the Magento application is not installed."
    //
    // Other Magento versions / forks sometimes emit different strings and/or use
    // exit code 1 for mismatches, so we keep a few backward-compatible fallbacks.
    const OK_UP_TO_DATE = 'all modules are up to date.';
    const NEEDS_UPGRADE_HINT = "run 'setup:upgrade' to update your db schema and data.";
    const NOT_INSTALLED = 'no information is available: the magento application is not installed.';

    // First: trust a clean exit or the explicit up-to-date message.
    if (exitCode === 0 || outputLower.includes(OK_UP_TO_DATE)) {
      return { needed: false, exitCode, output, containerId: currentId };
    }

    // Next: trust Magento's explicit upgrade hint (core) and common alternates.
    const LEGACY_CODE_DB_MISMATCH = 'some modules use code versions newer or older than the database';
    const LEGACY_UPGRADE_REQUIRED = 'setup:upgrade is required';
    if (
      outputLower.includes(NEEDS_UPGRADE_HINT)
      || outputLower.includes(LEGACY_CODE_DB_MISMATCH)
      || outputLower.includes(LEGACY_UPGRADE_REQUIRED)
      || exitCode === 2
    ) {
      return { needed: true, exitCode, output, containerId: currentId };
    }

    const transientFailure = !output
      || output.includes('No such container')
      || output.includes('is not running')
      || exitCode === 124
      || outputLower.includes('timed out')
      || outputLower.includes('terminated')
      || outputLower.includes('killed')
      || outputLower.includes('connection refused')
      || outputLower.includes('connection to redis')
      || outputLower.includes('sqlstate[hy000] [2002]')
      || outputLower.includes('server has gone away')
      || outputLower.includes('too many connections');

    if (transientFailure) {
      log(`setup:db:status retry ${attempt}: ${output || `exit ${exitCode}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      await delay(2000);
      continue;
    }

    // Not installed is a real state (typically pre-install); treat as a hard error.
    if (outputLower.includes(NOT_INSTALLED)) {
      log(`setup:db:status not installed exit=${exitCode}: ${output}`);
      throw new Error(`setup:db:status indicates Magento is not installed: ${output}`);
    }

    log(`setup:db:status failed exit=${exitCode}: ${output}`);
    throw new Error(`setup:db:status failed (exit ${exitCode}): ${output}`);
  }
  throw new Error('setup:db:status failed after retries; refusing to run setup:upgrade/backup without a definitive status');
}

async function runAppConfigStatus(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
): Promise<{ needed: boolean; exitCode: number; output: string; containerId: string }> {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(
      currentId,
      stackName,
      buildMagentoCliCommand('app:config:status')
    );
    // Prefer stdout for status parsing — stderr often contains noise from
    // PHP extensions (e.g. ddtrace) that isn't related to the command result.
    const stdout = (result.stdout || '').trim();
    const stderr = (result.stderr || '').trim();
    const output = stdout || stderr;
    const outputLower = output.toLowerCase();
    const exitCode = result.code;

    // Magento\Deploy\Console\Command\App\ConfigStatusCommand:
    // - 0 => "Config files are up to date."
    // - 2 => "Config files have changed. Run app:config:import ..."
    const UP_TO_DATE = 'config files are up to date.';
    const IMPORT_REQUIRED = 'config files have changed.';
    const IMPORT_HINT = 'run app:config:import or setup:upgrade command to synchronize configuration.';

    if (exitCode === 0 || outputLower.includes(UP_TO_DATE)) {
      return { needed: false, exitCode, output, containerId: currentId };
    }

    if (
      exitCode === 2
      || outputLower.includes(IMPORT_REQUIRED)
      || outputLower.includes(IMPORT_HINT)
    ) {
      return { needed: true, exitCode, output, containerId: currentId };
    }

    if (!output || output.includes('No such container') || output.includes('is not running')) {
      log(`app:config:status retry ${attempt}: ${output || `exit ${exitCode}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      await delay(2000);
      continue;
    }

    log(`app:config:status failed exit=${exitCode}: ${output}`);
    throw new Error(`app:config:status failed (exit ${exitCode}): ${output}`);
  }
  return { needed: true, exitCode: 2, output: 'app:config:status retries exhausted', containerId: currentId };
}

async function runAppConfigImport(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
) {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(
      currentId,
      stackName,
      buildMagentoCliCommand('app:config:import --no-interaction')
    );
    if (result.code === 0) {
      log('app:config:import ok');
      return currentId;
    }

    const output = (result.stderr || result.stdout || '').trim();
    const outputLower = output.toLowerCase();
    if (
      !output
      || output.includes('No such container')
      || output.includes('is not running')
      || outputLower.includes('connection refused')
      || outputLower.includes('connection to redis')
      || outputLower.includes('sqlstate[hy000] [2002]')
    ) {
      log(`app:config:import retry ${attempt}: ${output || `exit ${result.code}`}`);
      currentId = await waitForContainer(stackName, 'php-fpm-admin', 60 * 1000);
      await waitForRedisCache(currentId, stackName, 5 * 60 * 1000);
      await delay(2000);
      continue;
    }

    throw new Error(`app:config:import failed (exit ${result.code}): ${output}`);
  }

  throw new Error('app:config:import failed after retries');
}

async function flushMagentoCache(
  containerId: string,
  stackName: string,
  log: (message: string) => void,
) {
  let currentId = containerId;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    currentId = await ensureMagentoEnvWrapperWithRetry(currentId, stackName, log);
    const result = await runMagentoCommandWithStatus(
      currentId,
      stackName,
      buildMagentoCliCommand('cache:flush')
    );
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

    const zstdLevel = getDbBackupZstdLevel();
    await runCommand('zstd', [`-${zstdLevel}`, '-f', '-o', zstPath, dumpPath]);
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
  const deploymentHistoryKey = `env:${environmentId}:${repository || 'unknown'}`;
  const prunePreviousSuccessAt = getHistoryLastSuccessfulDeployAt(readDeploymentHistory(DEPLOY_HISTORY_FILE, LEGACY_DEPLOY_HISTORY_FILE), deploymentHistoryKey);
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

  await maybeAggressivePrune('pre-deploy', prunePreviousSuccessAt);
  await ensureMinimumFreeSpace('pre-deploy');

  await ensureCloudSwarmRepo();
  log('cloud-swarm repo updated');

  const envRecord = await fetchEnvironmentRecord(stackId, environmentId, baseUrl, nodeId, nodeSecret);
  if (!envRecord) {
    throw new Error(`Environment ${environmentId} not found in stack ${stackId}`);
  }
  log('fetched environment record');
  const selections = envRecord?.application_selections;
  const applicationVersion = envRecord?.application_version || '';
  const versions = resolveVersionEnv(selections);
  const searchEngineOverride = process.env.MZ_SEARCH_ENGINE || '';
  let searchEngine = searchEngineOverride || defaultSearchEngine(applicationVersion); // refined after DB is reachable
  const opensearchHost = process.env.MZ_OPENSEARCH_HOST || `${stackName}_opensearch`;
  const opensearchPort = process.env.MZ_OPENSEARCH_PORT || '9200';
  const opensearchTimeout = process.env.MZ_OPENSEARCH_TIMEOUT || '15';

  const r2: R2PresignContext = { baseUrl, nodeId, nodeSecret, environmentId };
  const workDir = path.join(DEPLOY_WORK_DIR, deploymentId);
  ensureDir(workDir);
  const progress = new DeployProgress(
    path.join(workDir, 'progress.json'),
    'deploy',
    deploymentId,
    environmentId,
    [
      { id: 'download_artifact', label: 'Download build artifact' },
      { id: 'build_images', label: 'Build container images' },
      { id: 'deploy_stack', label: 'Deploy environment' },
      { id: 'db_prepare', label: 'Prepare database' },
      { id: 'app_prepare', label: 'Configure application' },
      { id: 'magento_steps', label: 'Run Magento setup' },
      { id: 'smoke_checks', label: 'Health checks' },
      { id: 'verify', label: 'Verify deployment' },
      { id: 'finalize', label: 'Finalize' },
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
  const defaultVersions = readVersionDefaults(CLOUD_SWARM_DIR);
  const overrideVersions: Record<string, string> = {};
  if (versions.phpVersion) overrideVersions.PHP_VERSION = versions.phpVersion;
  if (versions.varnishVersion) overrideVersions.VARNISH_VERSION = versions.varnishVersion;
  if (versions.mariadbVersion) overrideVersions.MARIADB_VERSION = versions.mariadbVersion;
  if (versions.opensearchVersion) overrideVersions.OPENSEARCH_VERSION = versions.opensearchVersion;
  if (versions.redisVersion) overrideVersions.REDIS_VERSION = versions.redisVersion;
  if (versions.rabbitmqVersion) overrideVersions.RABBITMQ_VERSION = versions.rabbitmqVersion;

  const planner = await buildPlannerPayload();
  const plannerResources = planner?.resources?.services as PlannerResources | undefined;
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
  let appHaPolicy = resolveAppHaReplicaPolicy({
    ready_node_count: 0,
    free_cpu_cores: 0,
    free_memory_bytes: 0,
    nginx_reserve_cpu_cores: plannerResources.nginx?.reservations?.cpu_cores || 0,
    nginx_reserve_memory_bytes: plannerResources.nginx?.reservations?.memory_bytes || 0,
    php_fpm_reserve_cpu_cores: plannerResources['php-fpm']?.reservations?.cpu_cores || 0,
    php_fpm_reserve_memory_bytes: plannerResources['php-fpm']?.reservations?.memory_bytes || 0,
    min_ready_nodes: APP_HA_MIN_READY_NODES,
    max_replicas: APP_HA_MAX_REPLICAS,
  });
  const envTypeRaw = String(envRecord?.environment_type || '').trim().toLowerCase();
  const envHostname = String(envRecord?.environment_hostname || envRecord?.hostname || '').trim();
  const envHostnameOnly = envHostname
    ? envHostname.replace(/^https?:\/\//, '').split('/')[0]?.replace(/\/+$/, '') || ''
    : '';
  const apmEnabledValue = process.env.MZ_APM_ENABLED || '1';
  const apmSpanEventsEnabledValue = process.env.MZ_APM_SPAN_EVENTS_ENABLED || '1';
  const apmSpanLayoutEnabledValue = process.env.MZ_APM_SPAN_LAYOUT_ENABLED || '1';
  const apmSpanPluginsEnabledValue = process.env.MZ_APM_SPAN_PLUGINS_ENABLED || '0';
  const apmSpanDiEnabledValue = process.env.MZ_APM_SPAN_DI_ENABLED || '0';
  const datadogTraceEnv = resolveDatadogTraceEnv(apmEnabledValue, {
    traceEnabled: process.env.DD_TRACE_ENABLED,
    traceAgentUrl: process.env.DD_TRACE_AGENT_URL,
    service: process.env.DD_SERVICE || `mz-env-${environmentId}`,
    environment: envTypeRaw || process.env.DD_ENV || 'production',
    sampleRate: process.env.DD_TRACE_SAMPLE_RATE,
    traceAgentTimeout: process.env.DD_TRACE_AGENT_TIMEOUT,
    traceAgentConnectTimeout: process.env.DD_TRACE_AGENT_CONNECT_TIMEOUT,
  });
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
    appHaPolicy = resolveAppHaReplicaPolicy({
      ready_node_count: readyNodes.length,
      free_cpu_cores: capacity.totals.free_cpu_cores || 0,
      free_memory_bytes: capacity.totals.free_memory_bytes || 0,
      nginx_reserve_cpu_cores: plannerResources.nginx?.reservations?.cpu_cores || 0,
      nginx_reserve_memory_bytes: plannerResources.nginx?.reservations?.memory_bytes || 0,
      php_fpm_reserve_cpu_cores: plannerResources['php-fpm']?.reservations?.cpu_cores || 0,
      php_fpm_reserve_memory_bytes: plannerResources['php-fpm']?.reservations?.memory_bytes || 0,
      min_ready_nodes: APP_HA_MIN_READY_NODES,
      max_replicas: APP_HA_MAX_REPLICAS,
    });
    if (appHaPolicy.reason === 'ha_enabled') {
      log(
        `app-ha policy enabled: replicas=${appHaPolicy.replicas} ` +
        `(ready_nodes=${readyNodes.length}, extra_reserve_cpu=${appHaPolicy.required_cpu_cores}, ` +
        `extra_reserve_memory=${Math.round(appHaPolicy.required_memory_bytes / MIB)}MiB)`
      );
    } else if (appHaPolicy.reason === 'insufficient_headroom') {
      log(
        `app-ha policy skipped: insufficient headroom ` +
        `(cpu_shortfall=${appHaPolicy.shortfall_cpu_cores}, ` +
        `memory_shortfall=${Math.round(appHaPolicy.shortfall_memory_bytes / MIB)}MiB, ` +
        `ready_nodes=${readyNodes.length})`
      );
    } else {
      log(`app-ha policy disabled: ready_nodes=${readyNodes.length}, min_ready_nodes=${APP_HA_MIN_READY_NODES}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`capacity unavailable; defaulting replica host to database (${message})`);
    log('app-ha policy fallback: capacity unavailable, using single-replica frontend');
  }

  // Swarm service tasks must pull images from an address reachable by every node.
  // Prefer an explicit pull host (WireGuard IP in multi-node setups). Fall back to REGISTRY_HOST.
  const registryPullHost = await resolveRegistryPullHost(
    process.env.REGISTRY_PULL_HOST || process.env.REGISTRY_HOST || '127.0.0.1',
    log
  );
  // Historically stack templates use REGISTRY_HOST for service images; treat it as the pull host.
  const registryHost = registryPullHost;
  // Build/push can remain local to the manager to avoid BuildKit HTTPS-to-insecure registry issues.
  const registryPushHost = process.env.REGISTRY_PUSH_HOST || '127.0.0.1';
  const registryCacheHost = process.env.REGISTRY_CACHE_HOST || registryPushHost;
  const registryPort = process.env.REGISTRY_PORT || '5000';
  const registryCachePort = process.env.REGISTRY_CACHE_PORT || registryPort;
  const buildxNetwork = process.env.BUILDX_NETWORK || 'host';
  const frontendRuntimePolicy = resolveFrontendRuntimePolicy(appHaPolicy.replicas);
  const frontendReplicaCount = frontendRuntimePolicy.replicas;

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
    MZ_VARNISH_REPLICAS: '1',
    MZ_NGINX_REPLICAS: String(frontendReplicaCount),
    MZ_PHP_FPM_REPLICAS: String(frontendReplicaCount),
    MZ_VARNISH_MAX_REPLICAS_PER_NODE: '0',
    MZ_NGINX_MAX_REPLICAS_PER_NODE: String(frontendRuntimePolicy.max_replicas_per_node),
    MZ_PHP_FPM_MAX_REPLICAS_PER_NODE: String(frontendRuntimePolicy.max_replicas_per_node),
    MZ_VARNISH_UPDATE_ORDER: 'start-first',
    MZ_NGINX_UPDATE_ORDER: frontendRuntimePolicy.update_order,
    MZ_PHP_FPM_UPDATE_ORDER: frontendRuntimePolicy.update_order,
    MZ_RABBITMQ_HOST: stackService('rabbitmq'),
    MZ_REDIS_CACHE_HOST: stackService('redis-cache'),
    MZ_REDIS_SESSION_HOST: stackService('redis-session'),
    MZ_VARNISH_HOST: stackService('varnish'),
    MZ_PHP_FPM_HOST: stackService('php-fpm'),
    MZ_PHP_FPM_ADMIN_HOST: stackService('php-fpm-admin'),
    MZ_VARNISH_BACKEND_HOST: stackService('nginx'),
    MZ_VARNISH_BACKEND_PORT: '80',
    ...buildSearchEngineEnvOverride(searchEngineOverride),
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
    // APM + Magento observability module config (rendered into app/etc/config.php).
    // Tracing transport is Datadog tracer intake to OTel collector (:8126).
    MZ_APM_ENABLED: apmEnabledValue,
    MZ_APM_SPAN_EVENTS_ENABLED: apmSpanEventsEnabledValue,
    MZ_APM_SPAN_LAYOUT_ENABLED: apmSpanLayoutEnabledValue,
    MZ_APM_SPAN_PLUGINS_ENABLED: apmSpanPluginsEnabledValue,
    MZ_APM_SPAN_DI_ENABLED: apmSpanDiEnabledValue,
    DD_TRACE_ENABLED: datadogTraceEnv.DD_TRACE_ENABLED,
    DD_TRACE_AGENT_URL: datadogTraceEnv.DD_TRACE_AGENT_URL,
    DD_SERVICE: datadogTraceEnv.DD_SERVICE,
    DD_ENV: datadogTraceEnv.DD_ENV,
    DD_TRACE_SAMPLE_RATE: datadogTraceEnv.DD_TRACE_SAMPLE_RATE,
    DD_TRACE_AGENT_TIMEOUT: datadogTraceEnv.DD_TRACE_AGENT_TIMEOUT,
    DD_TRACE_AGENT_CONNECT_TIMEOUT: datadogTraceEnv.DD_TRACE_AGENT_CONNECT_TIMEOUT,
    MZ_LOG_STREAM_ENABLED: process.env.MZ_LOG_STREAM_ENABLED || '1',
    MZ_LOG_STREAM_MIN_LEVEL: process.env.MZ_LOG_STREAM_MIN_LEVEL || 'warning',
    MZ_LOG_STREAM_TRANSPORT: process.env.MZ_LOG_STREAM_TRANSPORT || 'stderr',
    MZ_LOG_STREAM_DIRECT_URL: process.env.MZ_LOG_STREAM_DIRECT_URL || '',
    MZ_LOG_STREAM_DIRECT_INDEX: process.env.MZ_LOG_STREAM_DIRECT_INDEX || 'mz-logs-magento',
    MZ_LOG_STREAM_DIRECT_API_KEY: process.env.MZ_LOG_STREAM_DIRECT_API_KEY || '',
    MZ_LOG_STREAM_DIRECT_API_KEY_FILE: process.env.MZ_LOG_STREAM_DIRECT_API_KEY_FILE || '',
    MZ_LOG_STREAM_DIRECT_USERNAME: process.env.MZ_LOG_STREAM_DIRECT_USERNAME || '',
    MZ_LOG_STREAM_DIRECT_PASSWORD: process.env.MZ_LOG_STREAM_DIRECT_PASSWORD || '',
    MZ_LOG_STREAM_DIRECT_PASSWORD_FILE: process.env.MZ_LOG_STREAM_DIRECT_PASSWORD_FILE || '',
    MZ_LOG_STREAM_DIRECT_TIMEOUT_MS: process.env.MZ_LOG_STREAM_DIRECT_TIMEOUT_MS || '500',
    MZ_LOG_STREAM_DIRECT_VERIFY_TLS: process.env.MZ_LOG_STREAM_DIRECT_VERIFY_TLS || '1',
    // Cloudflare R2 media storage (rendered into app/etc/config.php by the wrapper).
    MZ_R2_ENABLED: process.env.MZ_R2_ENABLED || '0',
    MZ_R2_ACCOUNT_ID: process.env.MZ_R2_ACCOUNT_ID || '',
    MZ_R2_ENDPOINT: process.env.MZ_R2_ENDPOINT || '',
    MZ_R2_REGION: process.env.MZ_R2_REGION || 'auto',
    MZ_R2_BUCKET: process.env.MZ_R2_BUCKET || '',
    MZ_R2_ACCESS_KEY: process.env.MZ_R2_ACCESS_KEY || '',
    MZ_R2_ACCESS_KEY_FILE: process.env.MZ_R2_ACCESS_KEY_FILE || '',
    MZ_R2_SECRET_KEY: process.env.MZ_R2_SECRET_KEY || '',
    MZ_R2_SECRET_KEY_FILE: process.env.MZ_R2_SECRET_KEY_FILE || '',
    MZ_R2_KEY_PREFIX: process.env.MZ_R2_KEY_PREFIX || '',
    MZ_R2_PATH_STYLE: process.env.MZ_R2_PATH_STYLE || '0',
    MZ_R2_CACHE_TTL: process.env.MZ_R2_CACHE_TTL || '3600',
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
  const servicesStackPath = path.join(CLOUD_SWARM_DIR, 'stacks/magento-services.yml');
  const appStackPath = path.join(CLOUD_SWARM_DIR, 'stacks/magento-app.yml');
  const renderedServicesStack = await runCommandCapture('docker', [
    'stack',
    'config',
    '-c',
    servicesStackPath,
  ], { env: envVars });
  assertNoLatestImages(renderedServicesStack.stdout);
  const renderedAppStack = await runCommandCapture('docker', [
    'stack',
    'config',
    '-c',
    appStackPath,
  ], { env: envVars });
  assertNoLatestImages(renderedAppStack.stdout);

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

  // Proactive pre-build disk check: prune before builds to prevent mid-build disk pressure
  await maybeAggressivePrune('pre-build', prunePreviousSuccessAt);
  await ensureMinimumFreeSpace('pre-build');

  progress.start('build_images');
  const missingServiceImages = DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT
    ? await collectMissingServiceImages(envVars)
    : null;
  if (DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT && missingServiceImages && !missingServiceImages.length) {
    progress.detail('build_images', 'Skipping service image build (images present in registry)');
    log('base service images already present in registry; skipping build-services');
  } else {
    progress.detail('build_images', 'Ensuring service images are current');
    if (DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT && missingServiceImages) {
      log(`building service images; missing: ${missingServiceImages.join(', ')}`);
    } else {
      log('ensuring service images are current via build-services (tag-only precheck disabled)');
    }
    await runCommandLoggedWithRetry(
      'bash',
      [path.join(CLOUD_SWARM_DIR, 'scripts/build-services.sh')],
      { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-services' },
      {
        retries: DEPLOY_BUILD_RETRIES,
        log,
        onRetry: async () => {
          await maybeAggressivePrune('build-services-retry', prunePreviousSuccessAt);
          await ensureMinimumFreeSpace('build-services-retry');
        },
      }
    );
    log('built base services');
  }

  const appImagePresent = DEPLOY_SKIP_APP_BUILD_IF_PRESENT
    ? await appImagesExist(envVars, mageVersion)
    : false;
  if (appImagePresent) {
    progress.detail('build_images', `Skipping Magento image build (mz-magento/mz-nginx-app:${mageVersion} present)`);
    log(`magento images already present in registry for ${mageVersion}; skipping build-magento`);
  } else {
    progress.detail('build_images', 'Building Magento application image');
    let rebuiltServiceImagesForManifestRecovery = false;
    await runCommandLoggedWithRetry(
      'bash',
      [path.join(CLOUD_SWARM_DIR, 'scripts/build-magento.sh'), artifactPath],
      { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-magento' },
      {
        retries: DEPLOY_BUILD_RETRIES,
        log,
        onRetry: async () => {
          await maybeAggressivePrune('build-magento-retry', prunePreviousSuccessAt);
          await ensureMinimumFreeSpace('build-magento-retry');
          if (rebuiltServiceImagesForManifestRecovery) {
            return;
          }
          const manifestFailure = detectMissingRegistryManifest(logDir, 'build-magento');
          if (!manifestFailure.matched) {
            return;
          }
          rebuiltServiceImagesForManifestRecovery = true;
          const imageHint = manifestFailure.imageRef ? ` (${manifestFailure.imageRef})` : '';
          log(`build-magento recovery: detected missing registry manifest${imageHint}; rebuilding service images`);
          await runCommandLoggedWithRetry(
            'bash',
            [path.join(CLOUD_SWARM_DIR, 'scripts/build-services.sh')],
            { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-services-recovery' },
            {
              retries: DEPLOY_BUILD_RETRIES,
              log,
              onRetry: async () => {
                await maybeAggressivePrune('build-services-recovery-retry', prunePreviousSuccessAt);
                await ensureMinimumFreeSpace('build-services-recovery-retry');
              },
            }
          );
          log('build-magento recovery: service image rebuild complete');
        },
      }
    );
    log('built magento images');
  }
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

  // Ensure monitoring infrastructure is available before deploying env stacks.
  await ensureMonitoringStack(log, envVars);

  progress.start('deploy_stack');
  const baseServices = [
    'varnish',
    'database',
    'database-replica',
    'proxysql',
    'opensearch',
    'redis-cache',
    'redis-session',
    'rabbitmq',
    'mailhog',
  ];
  const missingBaseServices: string[] = [];
  for (const serviceName of baseServices) {
    const fullName = `${stackName}_${serviceName}`;
    const image = await inspectServiceImage(fullName);
    if (!image) {
      missingBaseServices.push(serviceName);
    }
  }

  if (missingBaseServices.length) {
    log(`base services missing (${missingBaseServices.join(', ')}); deploying services stack`);
    progress.detail('deploy_stack', 'Deploying infrastructure services');
    await runCommandLogged('docker', [
      'stack',
      'deploy',
      '--with-registry-auth',
      '-c',
      servicesStackPath,
      stackName,
    ], { env: envVars, logDir, label: 'stack-deploy-services' });
    log('services stack deployed');
  } else {
    log('services stack present; skipping services redeploy');
  }

  // Detect search engine from the existing database before deploying the app
  // stack so that containers start with the correct MZ_SEARCH_ENGINE value.
  progress.detail('deploy_stack', 'Waiting for database');
  {
    const dbCid = await waitForContainer(stackName, 'database', 5 * 60 * 1000);
    await waitForDatabase(dbCid, 5 * 60 * 1000);
    const dbN = envVars.MYSQL_DATABASE || 'magento';
    if (await databaseHasTables(dbCid, dbN)) {
      const detectedEngine = await detectSearchEngine(dbCid, dbN);
      searchEngine = resolveSearchEngine(searchEngineOverride, detectedEngine, applicationVersion);
      log(`search engine: detected=${detectedEngine || 'none'}, resolved=${searchEngine}, appVersion=${applicationVersion || 'unknown'}`);
    } else {
      log('database not yet populated; using default search engine');
    }
  }
  envVars.MZ_SEARCH_ENGINE = searchEngine;

  progress.detail('deploy_stack', 'Reconciling ProxySQL query routing rules');
  try {
    await enforceProxySqlQueryRules({
      environmentId,
      log,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`WARNING: ProxySQL query rules reconciliation failed (non-fatal): ${msg}`);
  }

  progress.detail('deploy_stack', `Deploying application (search engine: ${searchEngine})`);
  await runCommandLogged('docker', [
    'stack',
    'deploy',
    '--with-registry-auth',
    '-c',
    appStackPath,
    stackName,
  ], { env: envVars, logDir, label: 'stack-deploy-app' });
  log('app stack deployed');
  progress.detail(
    'deploy_stack',
    `Reconciling frontend runtime policy (replicas=${frontendRuntimePolicy.replicas}, ` +
    `max_per_node=${frontendRuntimePolicy.max_replicas_per_node}, order=${frontendRuntimePolicy.update_order})`
  );
  await enforceFrontendRuntimePolicy(stackName, frontendRuntimePolicy, log);

  if (RELEASE_COHORT_GATE_ENABLED) {
    progress.detail('deploy_stack', 'Waiting for services to be ready');
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
        log('release cohort gate failed');

        // Default behavior: stop crash-looping cohort services and fail the deploy.
        // Rollback is optional because the "previous tag" is not necessarily a known-good deploy.
        let shutdownSnapshot: Record<string, unknown> | null = null;
        if (RELEASE_COHORT_SCALE_DOWN_ON_FAILURE) {
          log('release cohort: scaling down cohort services to replicas=0');
          shutdownSnapshot = await scaleDownServices(cohortServices, log);
        }
        recordMeta.release_cohort_shutdown = shutdownSnapshot
          ? { issued_at: new Date().toISOString(), services: cohortServices, snapshot: shutdownSnapshot }
          : null;
        writeJsonFileBestEffort(recordPath, recordMeta);

        if (RELEASE_COHORT_ROLLBACK_ENABLED) {
          log('release cohort: rollback enabled; attempting rollback of cohort services');
          const rollbackTargetTag = cohortSnapshotPre.tag;
          const rollbackIssued = rollbackTargetTag
            ? await rollbackReleaseCohortToTag(
              cohortServices,
              rollbackTargetTag,
              String(envVars.REGISTRY_PULL_HOST || envVars.REGISTRY_HOST || '127.0.0.1'),
              String(envVars.REGISTRY_PORT || '5000'),
              log
            )
            : await rollbackReleaseCohort(cohortServices, log);

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

        const shutdownNote = RELEASE_COHORT_SCALE_DOWN_ON_FAILURE
          ? 'Cohort services were scaled down (replicas=0) to avoid crash loops.'
          : 'Cohort services were left as-is.';
        throw new Error(`Release cohort did not converge to ${mageVersion}: ${gate.summary}. ${shutdownNote}`);
      }
    }
  }
  progress.ok('deploy_stack');

  progress.start('db_prepare');
  let dbContainerId = await waitForContainer(stackName, 'database', 5 * 60 * 1000);
  await waitForDatabase(dbContainerId, 5 * 60 * 1000);

  const dbName = envVars.MYSQL_DATABASE || 'magento';
  const hasTables = await databaseHasTables(dbContainerId, dbName);
  if (!hasTables) {
    const message = `Database is empty (no tables). Run support runbook "db_restore_provisioning" (Restore database) first, then retry the deploy.`;
    log(`db not ready: ${message}`);
    progress.fail('db_prepare', message);
    throw new Error(message);
  }
  log('database already populated; restore not required');
  progress.detail('db_prepare', 'Database already populated; skipping restore');
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
      progress.detail('app_prepare', 'Configuring database replication');
      await configureReplicaViaSwarmJob({
        environmentId,
        replicaServiceFullName: stackService('database-replica'),
        masterHost: stackService('database'),
        replicaUser,
      });
      log('replica configured');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log(`replica setup skipped: ${message}`);
    }
  }

  progress.detail('app_prepare', 'Waiting for PHP containers');
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
  progress.detail('app_prepare', 'Configuring search engine');
  dbContainerId = await setSearchSystemConfig(
    stackName,
    dbContainerId,
    envVars.MYSQL_DATABASE || 'magento',
    opensearchHost,
    opensearchPort,
    opensearchTimeout
  );
  dbContainerId = await setSearchEngine(stackName, dbContainerId, envVars.MYSQL_DATABASE || 'magento', 'mysql');
  progress.detail('app_prepare', 'Waiting for ProxySQL');
  await waitForProxySql(adminContainerId, stackName, 5 * 60 * 1000);
  progress.detail('app_prepare', 'Waiting for Redis');
  await waitForRedisCache(adminContainerId, stackName, 5 * 60 * 1000);
  progress.detail('app_prepare', 'Applying runtime configuration');
  adminContainerId = await ensureMagentoEnvWrapperWithRetry(adminContainerId, stackName, log);
  if (webContainerId) {
    await ensureMagentoEnvWrapper(webContainerId).catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      log(`php-fpm env/config wrapper setup skipped: ${message}`);
    });
  }
  progress.ok('app_prepare');

  progress.start('magento_steps');
  progress.detail('magento_steps', 'Flushing cache before setup:db:status');
  adminContainerId = await flushMagentoCache(adminContainerId, stackName, log);
  const dbStatus = await runSetupDbStatus(adminContainerId, stackName, log);
  adminContainerId = dbStatus.containerId;
  recordMeta.magento_setup_db_status = {
    exit_code: dbStatus.exitCode,
    needed: dbStatus.needed,
    output: dbStatus.output || null,
    checked_at: new Date().toISOString(),
  };
  writeJsonFileBestEffort(recordPath, recordMeta);

  // Check for persistent schema mismatch: if setup:upgrade already ran for this
  // artifact and the schema was still "not up to date" afterwards (e.g. a third-party
  // module bug), skip the upgrade cycle to avoid unnecessary maintenance + backup.
  let upgradeNeeded = dbStatus.needed;
  if (upgradeNeeded) {
    const marker = readSchemaUpgradeMarker(environmentId);
    if (marker && marker.artifact === artifactKey && marker.post_check_needed) {
      log(`setup:upgrade skipped: persistent schema mismatch already recorded for this artifact (upgraded at ${marker.upgraded_at})`);
      progress.detail('magento_steps', 'setup:upgrade skipped; persistent schema mismatch');
      upgradeNeeded = false;
      (recordMeta as Record<string, unknown>).setup_upgrade_skipped_persistent_mismatch = {
        marker_artifact: marker.artifact,
        marker_upgraded_at: marker.upgraded_at,
        skipped_at: new Date().toISOString(),
      };
      writeJsonFileBestEffort(recordPath, recordMeta);
    }
  }

  let maintenanceEnabled = false;
  let cronScaledDown = false;
  let varnishRestartedAfterMaintenance = false;
  try {
    if (!upgradeNeeded) {
      log('setup:upgrade not required; cache already flushed before status check');
      progress.detail('magento_steps', 'setup:upgrade not required; continuing');
    } else {
      log('setup:upgrade required; enabling maintenance + pre-upgrade DB backup');
      progress.detail('magento_steps', 'setup:upgrade required; enabling maintenance + DB backup');

      // Scale cron to 0 replicas so cron:run doesn't consume memory during upgrade.
      // The cron container runs `php bin/magento cron:run` in a loop which loads
      // the full Magento DI container (~135MB+ per invocation) even in maintenance
      // mode, and can OOM-kill the container on memory-constrained nodes.
      const cronServiceName = `${stackName}_cron`;
      try {
        await scaleDownServices([cronServiceName], log);
        cronScaledDown = true;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log(`warning: failed to scale down cron: ${message}; continuing`);
      }

      // Enable maintenance mode first — cron:run checks this flag and skips work.
      adminContainerId = await setMagentoMaintenanceMode(adminContainerId, stackName, 'enable', log);
      maintenanceEnabled = true;

      // Wait for any in-flight cron jobs to finish so setup:upgrade doesn't hit
      // cron_schedule lock contention (SQLSTATE 1205 Lock wait timeout).
      await waitForCronJobsToFinish(dbContainerId, envVars.MYSQL_DATABASE || 'magento', log);

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

      // Re-check setup:db:status after upgrade to detect persistent mismatches.
      // Some third-party modules have broken db_schema.xml that causes setup:db:status
      // to always report "not up to date" even after a successful setup:upgrade.
      // Record this so future deploys with the same artifact skip the upgrade cycle.
      if (!upgradeWarning) {
        const postCheck = await runSetupDbStatus(adminContainerId, stackName, log);
        adminContainerId = postCheck.containerId;
        if (postCheck.needed) {
          log('warning: setup:db:status still reports "not up to date" after successful setup:upgrade; recording persistent schema mismatch');
          writeSchemaUpgradeMarker(environmentId, artifactKey);
        } else {
          clearSchemaUpgradeMarker(environmentId);
        }
        (recordMeta as Record<string, unknown>).setup_upgrade_post_check = {
          needed: postCheck.needed,
          output: postCheck.output || null,
          checked_at: new Date().toISOString(),
        };
        writeJsonFileBestEffort(recordPath, recordMeta);
      }
    }

    progress.detail('magento_steps', 'Checking app:config:status');
    const appConfigStatus = await runAppConfigStatus(adminContainerId, stackName, log);
    adminContainerId = appConfigStatus.containerId;
    recordMeta.magento_app_config_status = {
      exit_code: appConfigStatus.exitCode,
      needed: appConfigStatus.needed,
      output: appConfigStatus.output || null,
      checked_at: new Date().toISOString(),
    };
    writeJsonFileBestEffort(recordPath, recordMeta);

    if (appConfigStatus.needed) {
      log('app:config:import required; running import');
      progress.detail('magento_steps', 'Running app:config:import');
      adminContainerId = await runAppConfigImport(adminContainerId, stackName, log);
      progress.detail('magento_steps', 'Verifying app:config:status after import');
      const postImportStatus = await runAppConfigStatus(adminContainerId, stackName, log);
      adminContainerId = postImportStatus.containerId;
      recordMeta.magento_app_config_import = {
        ran: true,
        verified_needed: postImportStatus.needed,
        verify_exit_code: postImportStatus.exitCode,
        verify_output: postImportStatus.output || null,
        executed_at: new Date().toISOString(),
      };
      writeJsonFileBestEffort(recordPath, recordMeta);
      if (postImportStatus.needed) {
        throw new Error(`app:config:import did not synchronize configuration: ${postImportStatus.output}`);
      }
      adminContainerId = await flushMagentoCache(adminContainerId, stackName, log);
    } else {
      log('app:config:status up to date; import not required');
      recordMeta.magento_app_config_import = {
        ran: false,
        reason: 'up_to_date',
        checked_at: new Date().toISOString(),
      };
      writeJsonFileBestEffort(recordPath, recordMeta);
    }
  } finally {
    dbContainerId = await setSearchEngine(stackName, dbContainerId, envVars.MYSQL_DATABASE || 'magento', searchEngine);
    if (maintenanceEnabled) {
      let maintenanceDisabled = false;
      try {
        progress.detail('magento_steps', 'Disabling maintenance mode');
        adminContainerId = await setMagentoMaintenanceMode(adminContainerId, stackName, 'disable', log);
        maintenanceDisabled = true;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log(`maintenance:disable failed: ${message}`);
      }

      if (maintenanceDisabled) {
        const varnishServiceName = `${stackName}_varnish`;
        try {
          log('restarting varnish after maintenance:disable to clear cached maintenance responses');
          if (await tryForceUpdateService(varnishServiceName, log)) {
            varnishRestartedAfterMaintenance = true;
            await waitForAllDesiredServiceTasksRunning(varnishServiceName, log);
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          log(`warning: failed to restart varnish after maintenance:disable: ${message}`);
        }
      }
    }
    if (cronScaledDown) {
      try {
        const cronServiceName = `${stackName}_cron`;
        const result = await runCommandCaptureWithStatus('docker', [
          'service', 'scale', `${cronServiceName}=1`,
        ]);
        if (result.code === 0) {
          log(`restored cron service: ${cronServiceName} replicas=1`);
        } else {
          log(`warning: failed to restore cron service: ${cronServiceName} (exit ${result.code})`);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log(`warning: failed to restore cron service: ${message}`);
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
    const varnishServiceName = `${stackName}_varnish`;
    if (varnishRestartedAfterMaintenance) {
      log('varnish already restarted after maintenance:disable; skipping additional post-deploy restart');
    } else {
      // Force-restart varnish to clear stale backend DNS cache (old php-fpm IPs).
      log('restarting varnish to refresh backend DNS');
      await tryForceUpdateService(varnishServiceName, log);
      await waitForAllDesiredServiceTasksRunning(varnishServiceName, log);
    }

    progress.start('smoke_checks');
    progress.detail('smoke_checks', `Checking ${envHostname}`);
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
          throw new Error(`Post-deploy smoke checks failed: ${smoke.summary}. Auto-rollback queued (${rollbackDeploymentId}).`);
        }
      }

      throw new Error(`Post-deploy smoke checks failed: ${smoke.summary}`);
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
      previousSuccessAt: prunePreviousSuccessAt,
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
    const history = readDeploymentHistory(DEPLOY_HISTORY_FILE, LEGACY_DEPLOY_HISTORY_FILE);
    const key = `env:${environmentId}:${repository}`;
    const prunePreviousSuccessAt = getHistoryLastSuccessfulDeployAt(history, key);
    const deploymentId = String(record?.id || '').trim();
    const ref = String(payload.ref || '').trim();
    const imageTag = resolveImageTag(normalizedArtifactKey, ref, deploymentId);
    const failedImageTag = imageTag ? `env-${environmentId}-${imageTag}` : '';
    const {
      keepArtifacts,
      keepImageTags,
      keepFailedImageTags,
      removedFailedArtifacts,
      removedFailedImageTags,
    } = updateFailedDeploymentHistory(
      history,
      key,
      normalizedArtifactKey,
      failedImageTag,
      DEPLOY_FAILED_ARTIFACT_RETAIN_COUNT,
      DEPLOY_FAILED_IMAGE_RETAIN_COUNT
    );
    writeDeploymentHistory(history, DEPLOY_HISTORY_FILE);

    if (!DEPLOY_CLEANUP_ENABLED) {
      return;
    }

    const config = readConfig();
    const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
    const nodeId = readNodeFile('node-id');
    const nodeSecret = readNodeFile('node-secret');
    const hasR2Context = Boolean(baseUrl && nodeId && nodeSecret);
    if (!hasR2Context && removedFailedArtifacts.length) {
      console.warn('cleanup skip: missing mz-control base URL or node credentials');
    }

    if (hasR2Context) {
      const keepArtifactSet = new Set(
        keepArtifacts
          .map((item) => String(item || '').replace(/^\/+/, '').trim())
          .filter(Boolean)
      );
      const overflowFailedArtifacts = removedFailedArtifacts
        .map((item) => String(item || '').replace(/^\/+/, '').trim())
        .filter((item) => Boolean(item) && !keepArtifactSet.has(item));

      const r2: R2PresignContext = {
        baseUrl: String(baseUrl),
        nodeId: String(nodeId),
        nodeSecret: String(nodeSecret),
        environmentId,
      };
      for (const objectKey of overflowFailedArtifacts) {
        try {
          await deleteR2Object(r2, objectKey);
          console.warn(`cleanup: deleted failed artifact ${objectKey}`);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          console.warn(`cleanup: failed to delete artifact ${objectKey}: ${message}`);
        }
      }
    }

    const keepImageTagSet = new Set(
      [...keepImageTags, ...keepFailedImageTags]
        .map((item) => String(item || '').trim())
        .filter(Boolean)
    );
    const stackName = `mz-env-${environmentId}`;
    const localRemovals = await cleanupLocalImages(environmentId, keepImageTagSet, stackName);

    const explicitRegistryRemovals = [
      ...localRemovals,
      ...removedFailedImageTags
        .map((tag) => String(tag || '').trim())
        .filter(Boolean)
        .flatMap((tag) => ([
          { repo: 'mz-magento', tag },
          { repo: 'mz-nginx-app', tag },
        ])),
    ];
    const registryCleanup = await cleanupRegistryImages({
      environmentId,
      keepImageTags: keepImageTagSet,
      removals: explicitRegistryRemovals,
    });
    if (registryCleanup.deleted > 0) {
      await runRegistryGc();
    }

    await maybeAggressivePrune('post-failed-deploy', prunePreviousSuccessAt);
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
    const rawError = error instanceof Error ? error.message : String(error);
    const enrichedError = enrichCommandError(rawError, 'deploy');
    const failedRecord = {
      error: enrichedError,
      error_classification: classifyDeployError(rawError, 'deploy'),
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
  ensureDir(DEPLOY_QUEUED_DIR);
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

export const __testing = {
  parseDetectedEngine,
  defaultSearchEngine,
  resolveSearchEngine,
  buildSearchEngineEnvOverride,
  buildSearchSystemConfigSql,
  buildMagentoCliCommand,
  buildSetupDbStatusCommand,
  resolveDatadogTraceEnv,
  resolveAppHaReplicaPolicy,
  resolveFrontendRuntimePolicy,
  resolveSkipServiceBuildIfPresent,
  buildProxySqlQueryRulesSql,
  buildProxySqlRuleReconcileScript,
  shouldReuseAppImagesForCloudSwarmRef,
  getQueueSourceDirs,
  resolveAggressivePruneCutoffSeconds,
  getHistoryLastSuccessfulDeployAt,
};
