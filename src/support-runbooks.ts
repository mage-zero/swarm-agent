import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { buildNodeHeaders, buildSignature } from './node-hmac.js';
import { approveTuningProfile, buildPlannerPayload, readConfig } from './status.js';
import { getDeployPauseFilePath, isDeployPaused, readDeployPausedAt, setDeployPaused } from './deploy-pause.js';
import { runCommand, runCommandToFile } from './exec.js';
import { getDbBackupZstdLevel } from './backup-utils.js';
import {
  buildJobName,
  envServiceName,
  findEnvironmentService,
  getServiceTaskNode,
  inspectServiceSpec,
  inspectServiceUpdateStatus,
  listEnvironmentServices,
  listServiceTasks,
  pickNetworkName,
  pickSecretName,
  runSwarmJob,
  summarizeServiceTasks,
  waitForServiceNotRunning,
  waitForServiceRunning,
} from './swarm.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_QUEUED_DIR = process.env.MZ_DEPLOY_QUEUED_DIR || path.join(DEPLOY_QUEUE_DIR, 'queued');
const DEPLOY_FAILED_DIR = path.join(DEPLOY_QUEUE_DIR, 'failed');
const DEPLOY_PROCESSING_DIR = path.join(DEPLOY_QUEUE_DIR, 'processing');
const DEPLOY_WORK_DIR = path.join(DEPLOY_QUEUE_DIR, 'work');
const DEPLOY_META_DIR = path.join(DEPLOY_QUEUE_DIR, 'meta');
const DEPLOY_HISTORY_FILE = process.env.MZ_DEPLOY_HISTORY_FILE || path.join(DEPLOY_META_DIR, 'history.json');
const DEPLOY_RECORD_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i;
const DEPLOY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STACK_MASTER_PUBLIC_KEY_PATH = process.env.MZ_STACK_MASTER_PUBLIC_KEY_PATH || '/etc/magezero/stack_master_ssh.pub';
const STACK_MASTER_KEY_PATH = process.env.MZ_STACK_MASTER_KEY_PATH || '/etc/magezero/stack_master_ssh';
const DEFAULT_DB_RESTORE_OBJECT = process.env.MZ_DB_BACKUP_OBJECT || 'provisioning-database.sql.zst.age';
const SCD_DB_SNAPSHOT_PROFILE = 'scd-minimal-v1';
const SCD_DB_SNAPSHOT_TABLES = ['core_config_data', 'store', 'store_group', 'store_website', 'theme', 'translation'] as const;
const SCD_DB_SNAPSHOT_OPTIONAL_TABLES = new Set<string>(['translation']);
const SCD_DB_SNAPSHOT_PAYLOAD_BEGIN = 'MZ_SCD_DB_SNAPSHOT_PAYLOAD_BEGIN';
const SCD_DB_SNAPSHOT_PAYLOAD_END = 'MZ_SCD_DB_SNAPSHOT_PAYLOAD_END';
const DEFAULT_SCD_DB_REDACT_PATH_PATTERNS = [
  '~(?:^|/)(?:password|passwd)(?:$|/)~i',
  '~(?:^|/)(?:secret|secret_key|client_secret)(?:$|/)~i',
  '~(?:^|/)(?:token|access_token|refresh_token)(?:$|/)~i',
  '~(?:^|/)(?:api_key|access_key|private_key)(?:$|/)~i',
  '~(?:^|/)(?:license_key|serial|signature)(?:$|/)~i',
] as const;
const DEFAULT_SCD_DB_REDACT_VALUE_PATTERNS = [
  // Magento encrypted payloads are commonly base64-like strings with enough length/entropy.
  '~^[A-Za-z0-9+/]{32,}={0,2}$~',
] as const;

type RunbookDefinition = {
  id: string;
  name: string;
  description: string;
  safe: boolean;
  supports_remediation: boolean;
};

type RunbookResult = {
  runbook_id: string;
  status: 'ok' | 'warning' | 'failed';
  summary: string;
  observations: string[];
  data?: Record<string, unknown>;
  remediation?: {
    attempted: boolean;
    actions: string[];
  };
};

type RunbookProgressStep = {
  index: number;
  id: string;
  label: string;
  status: 'pending' | 'running' | 'ok' | 'failed' | 'skipped';
  started_at?: string;
  finished_at?: string;
  took_ms?: number;
  detail?: string;
  error?: string;
};

type RunbookProgressState = {
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
  steps: RunbookProgressStep[];
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
    // best-effort; do not fail runbooks on progress logging issues
  }
}

function nowIso() {
  return new Date().toISOString();
}

class RunbookProgress {
  private state: RunbookProgressState;
  private progressPath: string;

  constructor(
    progressPath: string,
    runbookId: string,
    runId: string,
    environmentId: number,
    steps: Array<{ id: string; label: string }>
  ) {
    this.progressPath = progressPath;
    const startedAt = nowIso();
    this.state = {
      runbook_id: runbookId,
      deployment_id: runId,
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

  static create(runbookId: string, environmentId: number, steps: Array<{ id: string; label: string }>) {
    const runId = crypto.randomUUID();
    const progressPath = path.join(DEPLOY_WORK_DIR, 'runbooks', runId, 'progress.json');
    return new RunbookProgress(progressPath, runbookId, runId, environmentId, steps);
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

type R2PresignContext = {
  baseUrl: string;
  nodeId: string;
  nodeSecret: string;
  stackId: number;
  environmentId: number;
};

type EnvironmentRecord = {
  environment_id?: number;
  db_backup_bucket?: string;
  db_backup_object?: string;
  environment_hostname?: string;
  hostname?: string;
};

const RUNBOOKS: RunbookDefinition[] = [
  {
    id: 'disk_usage_summary',
    name: 'Disk usage summary',
    description: 'Show disk usage and Docker storage usage on the node.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'swarm_capacity_summary',
    name: 'Swarm capacity summary',
    description: 'Inspect Swarm node resource capacity and task placement errors for the environment.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'swarm_tuning_profile_summary',
    name: 'Swarm tuning profile summary',
    description: 'Propose a tuning profile from planner data that can be approved for deploys or applied immediately.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'swarm_tuning_profile_apply',
    name: 'Apply swarm tuning profile',
    description: 'Approve a tuning profile and optionally apply resource changes to live environment services.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_replication_status',
    name: 'Database replication status',
    description: 'Inspect primary/replica roles and replication lag for the environment.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'db_replica_enable',
    name: 'Enable database replica placement',
    description: 'Ensure database-replica runs on a different node and is replicating (replica-required).',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_failover',
    name: 'Fail over database to replica',
    description: 'Planned switchover: enable maintenance, promote replica to writer, and demote primary to replica.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_failback',
    name: 'Fail back database to primary',
    description: 'Planned switchover: enable maintenance, promote primary to writer, and demote replica.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_replica_repair',
    name: 'Repair database replica replication',
    description: 'Check if database-replica container is running and repair replication configuration if it is not replicating.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_replica_reseed',
    name: 'Reseed database replica from primary',
    description: 'Destructive rebuild: wipe replica data and reseed from primary using a logical GTID snapshot, then start replication.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_restore_provisioning',
    name: 'Restore database (provisioning)',
    description: 'Restore the Magento database from the configured provisioning backup object in R2. Use before the first code deploy.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'php_fpm_health',
    name: 'PHP-FPM health check',
    description: 'Check php-fpm container status and health.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'varnish_ready',
    name: 'Varnish readiness check',
    description: 'Check Varnish container status and reachability.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'gateway_update_summary',
    name: 'Gateway update summary',
    description: 'Inspect Swarm update status (paused/rollback) for nginx/varnish/php-fpm services.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'http_smoke_check',
    name: 'HTTP smoke check',
    description: 'Run quick deploy-style HTTP smoke checks against nginx/varnish over the backend network.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'magento_var_permissions',
    name: 'Magento var permissions check',
    description: 'Verify Magento var directories are writable and fix if needed.',
    safe: true,
    supports_remediation: true,
  },
  {
    id: 'magento_media_permissions',
    name: 'Magento media permissions check',
    description: 'Verify Magento pub/media (including CAPTCHA) is writable and fix if needed.',
    safe: true,
    supports_remediation: true,
  },
  {
    id: 'proxysql_ready',
    name: 'ProxySQL readiness check',
    description: 'Check ProxySQL container status and readiness.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'dns_cloudflared_ingress',
    name: 'Cloudflared ingress check',
    description: 'Check Cloudflared tunnel container status.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'container_restart_summary',
    name: 'Container restart summary',
    description: 'Summarize restarts and unhealthy containers.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_failure_summary',
    name: 'Last deploy failure summary',
    description: 'Show the most recent deploy failure for the environment (if any).',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_active_summary',
    name: 'Active deploy summary',
    description: 'Show the currently processing deploy (if any) for the environment.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_log_excerpt',
    name: 'Deploy log excerpt',
    description: 'Return a small excerpt from deploy logs (build-services/build-magento/stack-deploy) for a specific deployment.',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_pause_status',
    name: 'Deploy worker pause status',
    description: 'Check whether the deploy worker is paused (break-glass).',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_pause',
    name: 'Pause deploy worker',
    description: 'Pause the deploy worker so no new deploys start (break-glass).',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_resume',
    name: 'Resume deploy worker',
    description: 'Resume the deploy worker (break-glass).',
    safe: true,
    supports_remediation: false,
  },
  {
    id: 'deploy_rollback_previous',
    name: 'Rollback to previous (last-known-good) artefact',
    description: 'Queue a deploy using the previous retained artefact for this environment (break-glass).',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'deploy_retry_latest',
    name: 'Retry latest failed deploy',
    description: 'Queue a redeploy using the payload from the latest failed deployment record for this environment.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'magento_maintenance_enable',
    name: 'Enable Magento maintenance mode',
    description: 'Enable Magento maintenance mode (break-glass).',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'magento_maintenance_disable',
    name: 'Disable Magento maintenance mode',
    description: 'Disable Magento maintenance mode (break-glass).',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'proxysql_restart',
    name: 'Restart ProxySQL service',
    description: 'Restart the ProxySQL service for the environment.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'cloudflared_restart',
    name: 'Restart Cloudflared service',
    description: 'Restart the Cloudflared service for the environment.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'varnish_restart',
    name: 'Restart Varnish service',
    description: 'Restart the Varnish service for the environment.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'environment_teardown',
    name: 'Environment teardown',
    description: 'Backup the database, upload to R2, and remove the environment stack + volumes.',
    safe: false,
    supports_remediation: true,
  },
  {
    id: 'db_backup',
    name: 'Database backup',
    description: 'Create an encrypted logical database backup (mysqldump) and upload it to R2.',
    safe: false,
    supports_remediation: true,
  },
];

function resolveStackMasterPublicKeyPath(): string | null {
  const candidates = [
    STACK_MASTER_PUBLIC_KEY_PATH,
    path.join(NODE_DIR, 'stack_master_ssh.pub'),
  ];
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function formatTimestamp(date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}_${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`;
}

async function uploadArtifact(r2: R2PresignContext, objectKey: string, sourcePath: string): Promise<void> {
  const normalizedKey = objectKey.replace(/^\/+/, '');
  const url = await presignR2ObjectUrl(r2, 'PUT', normalizedKey, 3600);
  const result = await runCommand('curl', ['-fsSL', '-X', 'PUT', '-T', sourcePath, url], 120_000);
  if (result.code !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(detail ? `R2 upload failed: ${detail}` : 'R2 upload failed');
  }
}

async function findServiceContainerId(serviceName: string): Promise<string | null> {
  const result = await runCommand(
    'docker',
    ['ps', '--filter', `label=com.docker.swarm.service.name=${serviceName}`, '--format', '{{.ID}}'],
    12_000
  );
  if (result.code !== 0) return null;
  const id = result.stdout.split('\n').map((line) => line.trim()).filter(Boolean)[0];
  return id || null;
}

async function waitForEnvironmentServicesGone(environmentId: number, timeoutMs = 120_000): Promise<{ ok: boolean; remaining: string[] }> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const services = await listEnvironmentServices(environmentId);
    if (!services.length) {
      return { ok: true, remaining: [] };
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  const remaining = await listEnvironmentServices(environmentId);
  return { ok: false, remaining: remaining.map((service) => service.name) };
}

async function removeEnvironmentVolumes(environmentId: number): Promise<{ removed: string[]; failed: string[] }> {
  const prefix = `mz-env-${environmentId}_`;
  const result = await runCommand('docker', ['volume', 'ls', '--format', '{{.Name}}'], 12_000);
  if (result.code !== 0) {
    return { removed: [], failed: [] };
  }
  const volumes = result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((name) => name.startsWith(prefix));
  const removed: string[] = [];
  const failed: string[] = [];
  for (const volume of volumes) {
    const rm = await runCommand('docker', ['volume', 'rm', '-f', volume], 30_000);
    if (rm.code === 0) {
      removed.push(volume);
    } else {
      failed.push(volume);
    }
  }
  return { removed, failed };
}

function readNodeFile(filename: string): string {
  try {
    return fs.readFileSync(`${NODE_DIR}/${filename}`, 'utf8').trim();
  } catch {
    return '';
  }
}

function timingSafeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function validateNodeRequest(request: Request): Promise<boolean> {
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!nodeId || !nodeSecret) {
    return false;
  }
  const headerNodeId = (request.headers.get('X-MZ-Node-Id') || '').trim();
  const timestamp = (request.headers.get('X-MZ-Timestamp') || '').trim();
  const nonce = (request.headers.get('X-MZ-Nonce') || '').trim();
  const signature = (request.headers.get('X-MZ-Signature') || '').trim();
  if (!headerNodeId || !timestamp || !nonce || !signature) {
    return false;
  }
  if (headerNodeId !== nodeId) {
    return false;
  }
  const timestampInt = Number.parseInt(timestamp, 10);
  if (!timestampInt || Math.abs(Date.now() / 1000 - timestampInt) > 300) {
    return false;
  }
  const url = new URL(request.url);
  const pathName = url.pathname;
  const query = url.search ? url.search.slice(1) : '';
  const body = await request.clone().text();
  const expected = buildSignature(request.method, pathName, query, timestamp, nonce, body, nodeSecret);
  return timingSafeEquals(expected, signature);
}

function resolveR2Context(environmentId: number): R2PresignContext | null {
  const config = readConfig();
  const baseUrl = String((config as Record<string, unknown>).mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const stackId = Number((config as Record<string, unknown>).stack_id ?? 0) || 0;
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!baseUrl || !stackId || !nodeId || !nodeSecret) {
    return null;
  }
  return { baseUrl, nodeId, nodeSecret, stackId, environmentId };
}

async function fetchJson(baseUrl: string, pathName: string, method: string, body: string | null, nodeId: string, nodeSecret: string, timeoutMs = 30_000) {
  const url = new URL(pathName, baseUrl);
  const query = url.search ? url.search.slice(1) : '';
  const payload = body ?? '';
  const headers = buildNodeHeaders(method, url.pathname, query, payload, nodeId, nodeSecret);

  const controller = new AbortController();
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

async function fetchEnvironmentRecord(r2: R2PresignContext): Promise<EnvironmentRecord | null> {
  const payload = await fetchJson(
    r2.baseUrl,
    `/v1/agent/stack/${r2.stackId}/environments`,
    'GET',
    null,
    r2.nodeId,
    r2.nodeSecret,
  );
  const environments = Array.isArray(payload?.environments) ? payload.environments as EnvironmentRecord[] : [];
  return environments.find((env) => Number(env.environment_id ?? 0) === r2.environmentId) || null;
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

function escapeForShellDoubleQuotes(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, ' ');
}

function quoteShell(value: string) {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

async function dbQueryScalar(environmentId: number, host: string, sql: string, timeoutMs = 60_000): Promise<string | null> {
  const safeSql = escapeForShellDoubleQuotes(sql);
  const script = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `HOST="${host}"`,
    `SQL="${safeSql}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h "$HOST" -N -B -e "$SQL" 2>/dev/null || echo ""',
  ].join(' && ');
  const job = await runDatabaseJob(environmentId, 'db-q', script, { timeout_ms: timeoutMs });
  if (!job.ok) return null;
  const line = job.logs.split('\n').map((l) => l.trim()).filter(Boolean)[0] || '';
  return line || null;
}

async function dbExecSql(environmentId: number, host: string, sql: string, opts?: { include_replication_secret?: boolean; timeout_ms?: number }): Promise<boolean> {
  const safeSql = escapeForShellDoubleQuotes(sql);
  const script = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `HOST="${host}"`,
    `SQL="${safeSql}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h "$HOST" -e "$SQL"',
  ].join(' && ');
  const job = await runDatabaseJob(environmentId, 'db-exec', script, opts);
  return job.ok;
}

async function dbGetReadOnly(environmentId: number, host: string): Promise<boolean | null> {
  const value = await dbQueryScalar(environmentId, host, 'SELECT @@GLOBAL.read_only;');
  if (value === '0') return false;
  if (value === '1') return true;
  return null;
}

async function dbSetReadOnly(environmentId: number, host: string, enabled: boolean): Promise<boolean> {
  const value = enabled ? 1 : 0;
  return dbExecSql(environmentId, host, `SET GLOBAL read_only=${value};`);
}

type SlaveStatus = Record<string, string>;

function parseSlaveStatus(raw: string): SlaveStatus | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const out: Record<string, string> = {};
  for (const line of trimmed.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key) out[key] = value;
  }
  return Object.keys(out).length ? out : null;
}

type DbReplicationProbe = {
  primary: {
    read_only: boolean | null;
    gtid_binlog_pos: string | null;
    gtid_current_pos: string | null;
    magento_table_count: number | null;
    slave_status: SlaveStatus | null;
  };
  replica: {
    read_only: boolean | null;
    gtid_slave_pos: string | null;
    gtid_current_pos: string | null;
    magento_table_count: number | null;
    slave_status: SlaveStatus | null;
  };
};

function parseBooleanInt(value: string | null): boolean | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (trimmed === '0') return false;
  if (trimmed === '1') return true;
  return null;
}

function parseOptionalInt(value: string | null): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const parsed = Number.parseInt(trimmed, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function extractBetweenMarkers(lines: string[], startMarker: string, endMarker: string): string {
  const startIndex = lines.findIndex((line) => line.trim() === startMarker);
  if (startIndex === -1) return '';
  const endIndex = lines.findIndex((line, idx) => idx > startIndex && line.trim() === endMarker);
  if (endIndex === -1) return '';
  return lines.slice(startIndex + 1, endIndex).join('\n');
}

function parseDbReplicationProbe(rawLogs: string): DbReplicationProbe | null {
  if (!rawLogs.trim()) return null;
  const lines = rawLogs.split('\n');
  const values = new Map<string, string>();
  for (const line of lines) {
    const trimmed = line.trim();
    const idx = trimmed.indexOf('=');
    if (idx <= 0) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (!key) continue;
    values.set(key, value);
  }

  const primarySlaveRaw = extractBetweenMarkers(lines, 'PRIMARY_SLAVE_STATUS_BEGIN', 'PRIMARY_SLAVE_STATUS_END');
  const replicaSlaveRaw = extractBetweenMarkers(lines, 'REPLICA_SLAVE_STATUS_BEGIN', 'REPLICA_SLAVE_STATUS_END');

  return {
    primary: {
      read_only: parseBooleanInt(values.get('PRIMARY_READ_ONLY') ?? null),
      gtid_binlog_pos: (values.get('PRIMARY_GTID_BINLOG_POS') ?? '').trim() || null,
      gtid_current_pos: (values.get('PRIMARY_GTID_CURRENT_POS') ?? '').trim() || null,
      magento_table_count: parseOptionalInt(values.get('PRIMARY_MAGENTO_TABLES') ?? null),
      slave_status: parseSlaveStatus(primarySlaveRaw),
    },
    replica: {
      read_only: parseBooleanInt(values.get('REPLICA_READ_ONLY') ?? null),
      gtid_slave_pos: (values.get('REPLICA_GTID_SLAVE_POS') ?? '').trim() || null,
      gtid_current_pos: (values.get('REPLICA_GTID_CURRENT_POS') ?? '').trim() || null,
      magento_table_count: parseOptionalInt(values.get('REPLICA_MAGENTO_TABLES') ?? null),
      slave_status: parseSlaveStatus(replicaSlaveRaw),
    },
  };
}

async function dbGetSlaveStatus(environmentId: number, host: string, timeoutMs = 60_000): Promise<SlaveStatus | null> {
  const script = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `HOST="${host}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h "$HOST" -e "SHOW SLAVE STATUS\\\\G" 2>/dev/null | grep -E "^[[:space:]]*(Master_Host|Slave_IO_Running|Slave_SQL_Running|Seconds_Behind_Master|Last_IO_Errno|Last_IO_Error|Last_SQL_Errno|Last_SQL_Error|Using_Gtid|Gtid_IO_Pos|Slave_SQL_Running_State):" || true',
  ].join(' && ');
  const job = await runDatabaseJob(environmentId, 'db-slave', script, { timeout_ms: timeoutMs });
  if (!job.ok) return null;
  return parseSlaveStatus(job.logs);
}

async function dbWaitForReplicaCaughtUp(environmentId: number, host: string, timeoutMs = 120_000): Promise<{ ok: boolean; lagSeconds: number | null; note?: string }> {
  const timeoutSeconds = Math.max(10, Math.floor(timeoutMs / 1000));
  const script = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `HOST="${host}"`,
    `TIMEOUT="${timeoutSeconds}"`,
    'started="$(date +%s)"',
    'while [ $(( $(date +%s) - started )) -lt "$TIMEOUT" ]; do',
    '  raw="$(mariadb -uroot -p"$ROOT_PASS" -h "$HOST" -e "SHOW SLAVE STATUS\\\\G" 2>/dev/null || true)"',
    '  if [ -z "$raw" ]; then echo "NOT_CONFIGURED=1"; exit 2; fi',
    '  io="$(echo "$raw" | awk -F: \'/Slave_IO_Running:/{gsub(/^[ \\t]+/,\"\",$2); print $2; exit}\')"',
    '  sql="$(echo "$raw" | awk -F: \'/Slave_SQL_Running:/{gsub(/^[ \\t]+/,\"\",$2); print $2; exit}\')"',
    '  lag="$(echo "$raw" | awk -F: \'/Seconds_Behind_Master:/{gsub(/^[ \\t]+/,\"\",$2); print $2; exit}\')"',
    '  echo "IO=${io} SQL=${sql} LAG=${lag}"',
    '  if [ "$io" = "Yes" ] && [ "$sql" = "Yes" ] && [ "$lag" = "0" ]; then echo "CAUGHT_UP=1"; exit 0; fi',
    '  sleep 2',
    'done',
    'echo "TIMEOUT=1"',
    'exit 1',
  ].join('\n');

  const job = await runDatabaseJob(environmentId, 'db-wait', script, { timeout_ms: timeoutMs + 30_000 });
  if (job.ok) {
    return { ok: true, lagSeconds: 0 };
  }

  if (job.logs.includes('NOT_CONFIGURED=1')) {
    return { ok: false, lagSeconds: null, note: 'replica not configured (no slave status)' };
  }

  const lastLag = job.logs
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('IO='))
    .slice(-1)[0] || '';
  const lagMatch = lastLag.match(/\bLAG=([0-9]+)\b/);
  const lagSeconds = lagMatch ? Number.parseInt(lagMatch[1], 10) : null;
  return { ok: false, lagSeconds: Number.isFinite(lagSeconds as number) ? lagSeconds : null, note: 'timeout waiting for replica catch-up' };
}

async function dbStopAndResetSlave(environmentId: number, host: string): Promise<boolean> {
  const script = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `HOST="${host}"`,
    'SQL="STOP SLAVE; RESET SLAVE ALL;"',
    'if mariadb -uroot -p"$ROOT_PASS" -h "$HOST" -e "$SQL" >/tmp/out 2>&1; then exit 0; fi',
    'out="$(cat /tmp/out || true)"',
    'echo "$out"',
    'echo "$out" | tr "\\n" " " | grep -qiE "no slave|not a slave|slave thread|error 1198" && exit 0',
    'exit 1',
  ].join('\n');
  const job = await runDatabaseJob(environmentId, 'db-reset', script, { timeout_ms: 90_000 });
  return job.ok;
}

async function dbConfigureAsReplica(environmentId: number, replicaHost: string, masterHost: string, replicaUser: string): Promise<boolean> {
  const safeMasterHost = masterHost.replace(/'/g, "''");
  const safeUser = replicaUser.replace(/'/g, "''");
  const passRef = '${REPL_PASS}';
  const sql = `CHANGE MASTER TO MASTER_HOST='${safeMasterHost}', MASTER_PORT=3306, MASTER_USER='${safeUser}', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;
  const safeSql = escapeForShellDoubleQuotes(sql);
  const script = [
    'set -e',
    'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `HOST="${replicaHost}"`,
    `SQL="${safeSql}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h "$HOST" -e "$SQL"',
  ].join(' && ');
  const job = await runDatabaseJob(environmentId, 'db-config', script, { include_replication_secret: true, timeout_ms: 90_000 });
  return job.ok;
}

async function scaleEnvironmentService(environmentId: number, serviceName: string, replicas: number): Promise<{ ok: boolean; note?: string }> {
  const target = `mz-env-${environmentId}_${serviceName}=${replicas}`;
  const result = await runCommand('docker', ['service', 'scale', target], 60_000);
  if (result.code !== 0) {
    return { ok: false, note: result.stderr.trim() || result.stdout.trim() || `failed to scale ${target}` };
  }
  return { ok: true };
}

async function runDatabaseJob(
  environmentId: number,
  jobPrefix: string,
  script: string,
  opts?: { include_replication_secret?: boolean; timeout_ms?: number }
): Promise<{ ok: boolean; logs: string; state: string; error?: string; details?: string[] }> {
  const databaseService = `mz-env-${environmentId}_database`;
  const spec = await inspectServiceSpec(databaseService);
  if (!spec) {
    return {
      ok: false,
      state: 'missing_service',
      logs: '',
      error: `database service not found (${databaseService})`,
    };
  }

  const networkName = pickNetworkName(spec, 'database');
  if (!networkName) {
    return {
      ok: false,
      state: 'missing_network',
      logs: '',
      error: 'unable to resolve database network',
    };
  }

  const rootSecret = pickSecretName(spec, 'db_root_password');
  if (!rootSecret) {
    return {
      ok: false,
      state: 'missing_secret',
      logs: '',
      error: 'db_root_password secret not found on database service',
    };
  }

  const secrets: Array<{ source: string; target: string }> = [{ source: rootSecret, target: 'db_root_password' }];
  if (opts?.include_replication_secret) {
    const replSecret = pickSecretName(spec, 'db_replication_password');
    if (!replSecret) {
      return {
        ok: false,
        state: 'missing_secret',
        logs: '',
        error: 'db_replication_password secret not found on database service',
      };
    }
    secrets.push({ source: replSecret, target: 'db_replication_password' });
  }

  const jobName = buildJobName(jobPrefix, environmentId);
  const result = await runSwarmJob({
    name: jobName,
    image: spec.image,
    networks: [networkName],
    secrets,
    command: ['sh', '-lc', script],
    timeout_ms: opts?.timeout_ms,
  });

  return {
    ok: result.ok,
    logs: result.logs,
    state: result.state,
    error: result.error,
    details: result.details,
  };
}

function buildDbProbeScript(environmentId: number) {
  const primary = `mz-env-${environmentId}_database`;
  const replica = `mz-env-${environmentId}_database-replica`;
  return [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    `primary="${primary}"`,
    `replica="${replica}"`,
    'query() { mariadb -uroot -p"$ROOT_PASS" -h "$1" -N -B -e "$2" 2>/dev/null || echo ""; }',
    'queryraw() { mariadb -uroot -p"$ROOT_PASS" -h "$1" -e "$2" 2>/dev/null || true; }',
    'echo "PRIMARY_READ_ONLY=$(query "$primary" "SELECT @@GLOBAL.read_only;")"',
    'echo "REPLICA_READ_ONLY=$(query "$replica" "SELECT @@GLOBAL.read_only;")"',
    'echo "PRIMARY_GTID_BINLOG_POS=$(query "$primary" "SELECT @@GLOBAL.gtid_binlog_pos;")"',
    'echo "PRIMARY_GTID_CURRENT_POS=$(query "$primary" "SELECT @@GLOBAL.gtid_current_pos;")"',
    'echo "REPLICA_GTID_SLAVE_POS=$(query "$replica" "SELECT @@GLOBAL.gtid_slave_pos;")"',
    'echo "REPLICA_GTID_CURRENT_POS=$(query "$replica" "SELECT @@GLOBAL.gtid_current_pos;")"',
    'echo "PRIMARY_MAGENTO_TABLES=$(query "$primary" "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\\"magento\\";")"',
    'echo "REPLICA_MAGENTO_TABLES=$(query "$replica" "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\\"magento\\";")"',
    'echo "PRIMARY_SLAVE_STATUS_BEGIN"',
    'queryraw "$primary" "SHOW SLAVE STATUS\\\\G" | grep -E "^[[:space:]]*(Master_Host|Slave_IO_Running|Slave_SQL_Running|Seconds_Behind_Master|Last_IO_Errno|Last_IO_Error|Last_SQL_Errno|Last_SQL_Error|Using_Gtid|Gtid_IO_Pos|Slave_SQL_Running_State):" || true',
    'echo "PRIMARY_SLAVE_STATUS_END"',
    'echo "REPLICA_SLAVE_STATUS_BEGIN"',
    'queryraw "$replica" "SHOW SLAVE STATUS\\\\G" | grep -E "^[[:space:]]*(Master_Host|Slave_IO_Running|Slave_SQL_Running|Seconds_Behind_Master|Last_IO_Errno|Last_IO_Error|Last_SQL_Errno|Last_SQL_Error|Using_Gtid|Gtid_IO_Pos|Slave_SQL_Running_State):" || true',
    'echo "REPLICA_SLAVE_STATUS_END"',
  ].join(' && ');
}

type SwarmNodeCapacity = {
  id: string;
  hostname: string;
  labels: Record<string, string>;
  availability: string;
  status: string;
  role: string;
  manager_status: string;
  resources: {
    nano_cpus: number | null;
    memory_bytes: number | null;
    cpu_cores: number | null;
    memory_gb: number | null;
  };
};

function parseNodeResourceStats(raw: string): SwarmNodeCapacity['resources'] {
  let nanoCpus: number | null = null;
  let memoryBytes: number | null = null;
  try {
    const parsed = JSON.parse(String(raw || '').trim() || '{}') as Record<string, unknown>;
    const nano = Number(parsed.NanoCPUs ?? parsed.nano_cpus ?? 0);
    const memory = Number(parsed.MemoryBytes ?? parsed.memory_bytes ?? 0);
    if (Number.isFinite(nano) && nano > 0) nanoCpus = nano;
    if (Number.isFinite(memory) && memory > 0) memoryBytes = memory;
  } catch {
    nanoCpus = null;
    memoryBytes = null;
  }
  const cpuCores = nanoCpus !== null ? Math.round((nanoCpus / 1_000_000_000) * 100) / 100 : null;
  const memoryGb = memoryBytes !== null ? Math.round((memoryBytes / (1024 ** 3)) * 100) / 100 : null;
  return {
    nano_cpus: nanoCpus,
    memory_bytes: memoryBytes,
    cpu_cores: cpuCores,
    memory_gb: memoryGb,
  };
}

function hasCapacityPlacementSignal(value: string): boolean {
  const lower = String(value || '').toLowerCase();
  if (!lower) return false;
  return (
    lower.includes('insufficient resources')
    || lower.includes('no suitable node')
    || lower.includes('insufficient memory')
    || lower.includes('insufficient cpu')
    || lower.includes('out of memory')
  );
}

async function getNodeLabels(): Promise<Array<{ id: string; hostname: string; labels: Record<string, string>; availability: string; status: string; role: string }>> {
  const ls = await runCommand('docker', ['node', 'ls', '--format', '{{.ID}}|{{.Hostname}}|{{.Status}}|{{.Availability}}|{{.ManagerStatus}}'], 12_000);
  if (ls.code !== 0) return [];
  const nodes = ls.stdout.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
    const [id, hostname, status, availability, managerStatus] = line.split('|');
    const role = managerStatus && managerStatus.trim() !== '' ? 'manager' : 'worker';
    return { id: id.trim(), hostname: (hostname || '').trim(), status: (status || '').trim(), availability: (availability || '').trim(), role };
  });
  const out: Array<{ id: string; hostname: string; labels: Record<string, string>; availability: string; status: string; role: string }> = [];
  for (const node of nodes) {
    const inspect = await runCommand('docker', ['node', 'inspect', node.id, '--format', '{{json .Spec.Labels}}'], 12_000);
    let labels: Record<string, string> = {};
    try {
      const parsed = JSON.parse(inspect.stdout.trim() || '{}') as Record<string, string>;
      if (parsed && typeof parsed === 'object') labels = parsed;
    } catch {
      labels = {};
    }
    out.push({ ...node, labels });
  }
  return out;
}

async function getSwarmNodeCapacities(): Promise<SwarmNodeCapacity[]> {
  const ls = await runCommand('docker', ['node', 'ls', '--format', '{{.ID}}|{{.Hostname}}|{{.Status}}|{{.Availability}}|{{.ManagerStatus}}'], 12_000);
  if (ls.code !== 0) return [];
  const nodes = ls.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, hostname, status, availability, managerStatus] = line.split('|');
      const managerState = (managerStatus || '').trim();
      const role = managerState !== '' ? 'manager' : 'worker';
      return {
        id: (id || '').trim(),
        hostname: (hostname || '').trim(),
        status: (status || '').trim(),
        availability: (availability || '').trim(),
        manager_status: managerState,
        role,
      };
    })
    .filter((node) => node.id && node.hostname);

  const out: SwarmNodeCapacity[] = [];
  for (const node of nodes) {
    const labelsInspect = await runCommand('docker', ['node', 'inspect', node.id, '--format', '{{json .Spec.Labels}}'], 12_000);
    const resourcesInspect = await runCommand('docker', ['node', 'inspect', node.id, '--format', '{{json .Description.Resources}}'], 12_000);

    let labels: Record<string, string> = {};
    try {
      const parsed = JSON.parse(labelsInspect.stdout.trim() || '{}') as Record<string, string>;
      if (parsed && typeof parsed === 'object') labels = parsed;
    } catch {
      labels = {};
    }

    out.push({
      ...node,
      labels,
      resources: parseNodeResourceStats(resourcesInspect.stdout),
    });
  }
  return out;
}

async function updateNodeLabel(nodeId: string, labelKey: string, labelValue: string | null): Promise<boolean> {
  const args = ['node', 'update'];
  if (labelValue === null) {
    args.push('--label-rm', labelKey);
  } else {
    args.push('--label-add', `${labelKey}=${labelValue}`);
  }
  args.push(nodeId);
  const result = await runCommand('docker', args, 20_000);
  return result.code === 0;
}

async function queryProxySqlHostgroups(environmentId: number): Promise<Array<{ hostgroup: number; hostname: string; status: string }>> {
  const proxysqlService = `mz-env-${environmentId}_proxysql`;
  const proxysqlSpec = await inspectServiceSpec(proxysqlService);
  if (!proxysqlSpec) return [];
  const networkName = pickNetworkName(proxysqlSpec) || 'mz-backend';

  const dbSpec = await inspectServiceSpec(`mz-env-${environmentId}_database`);
  const clientImage = dbSpec?.image || 'mariadb:11';

  const sql = 'SELECT hostgroup_id,hostname,status FROM runtime_mysql_servers ORDER BY hostgroup_id,hostname;';
  const safeSql = escapeForShellDoubleQuotes(sql);
  const command = [
    'set -e',
    `HOST="${proxysqlService}"`,
    `SQL="${safeSql}"`,
    'CLIENT=""',
    'if command -v mariadb >/dev/null 2>&1; then CLIENT="mariadb"; elif command -v mysql >/dev/null 2>&1; then CLIENT="mysql"; fi',
    'if [ -z "$CLIENT" ]; then echo "missing mariadb/mysql client" >&2; exit 2; fi',
    '$CLIENT -h "$HOST" -P 6032 -u admin -padmin -N -B -e "$SQL"',
  ].join(' && ');

  const result = await runCommand('docker', [
    'run',
    '--rm',
    '--network',
    networkName,
    '--entrypoint',
    'sh',
    clientImage,
    '-lc',
    command,
  ], 12_000);
  if (result.code !== 0) return [];

  return parseProxySqlHostgroups(result.stdout);
}

async function waitForProxySqlWriter(environmentId: number, writerHost: string, timeoutMs = 30_000): Promise<boolean> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const rows = await queryProxySqlHostgroups(environmentId);
    const writer = rows.find((row) => row.hostgroup === 10 && row.hostname === writerHost);
    if (writer) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function parseProxySqlHostgroups(raw: string): Array<{ hostgroup: number; hostname: string; status: string }> {
  return raw
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const [hg, hostname, status] = line.split(/\s+/);
      return { hostgroup: Number(hg || 0), hostname: String(hostname || ''), status: String(status || '') };
    })
    .filter((row) => Number.isFinite(row.hostgroup) && row.hostgroup > 0 && row.hostname !== '');
}

type ScdDbSnapshotPayload = {
  profile: string;
  environment_id: number;
  generated_at: string;
  root_path: string;
  included_tables: string[];
  skipped_tables: string[];
  row_counts: Record<string, number>;
  redaction: {
    path_patterns: string[];
    value_patterns: string[];
    redacted_rows: number;
    redacted_rows_by_path: number;
    redacted_rows_by_value: number;
  };
  sql_gz_sha256: string;
  sql_gz_base64: string;
};

function normalizeScdDbRedactPathPatterns(input: unknown): string[] {
  const fromInput = Array.isArray(input)
    ? input.filter((value): value is string => typeof value === 'string').map((value) => value.trim()).filter(Boolean)
    : [];
  const unique = new Set<string>([...DEFAULT_SCD_DB_REDACT_PATH_PATTERNS, ...fromInput]);
  const valid: string[] = [];
  for (const pattern of unique) {
    try {
      // Validate the supplied PCRE pattern locally before passing it into the PHP exporter.
      void new RegExp(pattern.replace(/^~|~[a-z]*$/gi, ''));
      valid.push(pattern);
    } catch {
      // Ignore invalid caller-supplied patterns. Defaults are known-good.
    }
  }
  return valid.length ? valid : Array.from(DEFAULT_SCD_DB_REDACT_PATH_PATTERNS);
}

function normalizeScdDbRedactValuePatterns(input: unknown): string[] {
  const fromInput = Array.isArray(input)
    ? input.filter((value): value is string => typeof value === 'string').map((value) => value.trim()).filter(Boolean)
    : [];
  const unique = new Set<string>([...DEFAULT_SCD_DB_REDACT_VALUE_PATTERNS, ...fromInput]);
  const valid: string[] = [];
  for (const pattern of unique) {
    try {
      void new RegExp(pattern.replace(/^~|~[a-z]*$/gi, ''));
      valid.push(pattern);
    } catch {
      // Ignore invalid caller-supplied patterns. Defaults are known-good.
    }
  }
  return valid.length ? valid : Array.from(DEFAULT_SCD_DB_REDACT_VALUE_PATTERNS);
}

function parseScdDbSnapshotPayload(logs: string): ScdDbSnapshotPayload | null {
  const startIdx = logs.indexOf(SCD_DB_SNAPSHOT_PAYLOAD_BEGIN);
  if (startIdx === -1) return null;
  const endIdx = logs.indexOf(SCD_DB_SNAPSHOT_PAYLOAD_END, startIdx + SCD_DB_SNAPSHOT_PAYLOAD_BEGIN.length);
  if (endIdx === -1) return null;
  const payloadText = logs
    .slice(startIdx + SCD_DB_SNAPSHOT_PAYLOAD_BEGIN.length, endIdx)
    .replace(/^\s+|\s+$/g, '');
  if (!payloadText) return null;
  try {
    const parsed = JSON.parse(payloadText) as ScdDbSnapshotPayload;
    if (!parsed || typeof parsed !== 'object') return null;
    if (typeof parsed.sql_gz_base64 !== 'string' || !parsed.sql_gz_base64) return null;
    if (!Array.isArray(parsed.included_tables)) return null;
    if (!parsed.redaction || typeof parsed.redaction !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

function buildScdDbSnapshotExporterScript(environmentId: number, input: Record<string, unknown>): string {
  const profile = String(input.profile ?? SCD_DB_SNAPSHOT_PROFILE).trim() || SCD_DB_SNAPSHOT_PROFILE;
  const redactPathPatterns = normalizeScdDbRedactPathPatterns(input.redact_path_patterns);
  const redactValuePatterns = normalizeScdDbRedactValuePatterns(input.redact_value_patterns);
  const config = {
    profile,
    environment_id: environmentId,
    tables: Array.from(SCD_DB_SNAPSHOT_TABLES),
    optional_tables: Array.from(SCD_DB_SNAPSHOT_OPTIONAL_TABLES),
    redact_path_patterns: redactPathPatterns,
    redact_value_patterns: redactValuePatterns,
    payload_begin: SCD_DB_SNAPSHOT_PAYLOAD_BEGIN,
    payload_end: SCD_DB_SNAPSHOT_PAYLOAD_END,
  };
  const cfgB64 = Buffer.from(JSON.stringify(config), 'utf8').toString('base64');
  return [
    `export MZ_SCD_DB_SNAPSHOT_CFG_B64='${cfgB64}'`,
    "cat > /tmp/mz-scd-db-snapshot.php <<'PHP'",
    "<?php",
    "error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);",
    "$cfg = json_decode(base64_decode((string)getenv('MZ_SCD_DB_SNAPSHOT_CFG_B64')), true);",
    "if (!is_array($cfg)) { fwrite(STDERR, 'invalid config'.PHP_EOL); exit(2); }",
    "$roots = [];",
    "$envRoot = trim((string)getenv('MZ_MAGENTO_BASE_DIR'));",
    "if ($envRoot !== '') { $roots[] = $envRoot; }",
    "$roots[] = '/var/www/html/magento';",
    "$roots[] = '/var/www/html';",
    "$roots = array_values(array_unique($roots));",
    "$root = '';",
    "foreach ($roots as $candidate) { if (is_dir($candidate . '/app/etc')) { $root = $candidate; break; } }",
    "$dbSecret = '/run/secrets/db_password';",
    "$host = (string)(getenv('MZ_DB_HOST') ?: '');",
    "$port = (int)(getenv('MZ_DB_PORT') ?: 3306);",
    "$dbname = (string)(getenv('MZ_DB_NAME') ?: 'magento');",
    "$user = (string)(getenv('MZ_DB_USER') ?: 'magento');",
    "$pass = '';",
    "if (is_file($dbSecret)) { $pass = trim((string)@file_get_contents($dbSecret)); }",
    "$envPath = $root !== '' ? rtrim($root, '/') . '/app/etc/env.php' : '';",
    "if ($envPath !== '' && is_file($envPath)) {",
    "  $env = require $envPath;",
    "  if (!is_array($env)) { fwrite(STDERR, 'invalid env.php'.PHP_EOL); exit(4); }",
    "  $db = $env['db']['connection']['default'] ?? [];",
    "  if (is_array($db)) {",
    "    $host = (string)($db['host'] ?? $host);",
    "    $portRaw = (string)($db['port'] ?? '');",
    "    if ($portRaw !== '' && ctype_digit($portRaw)) { $port = (int)$portRaw; }",
    "    $dbname = (string)($db['dbname'] ?? $dbname);",
    "    $user = (string)($db['username'] ?? $user);",
    "    $passRaw = (string)($db['password'] ?? '');",
    "    if ($passRaw !== '') { $pass = $passRaw; }",
    "  }",
    "}",
    "if ($host !== '' && preg_match('/^(.+):(\\d+)$/', $host, $m)) {",
    "  $host = (string)$m[1];",
    "  if ($port <= 0 || $port === 3306) { $port = (int)$m[2]; }",
    "}",
    "if ($host === '' || $user === '') { fwrite(STDERR, 'db connection missing (host/user)'.PHP_EOL); exit(5); }",
    "$dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port ?: 3306, $dbname);",
    "$options = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC];",
    "if (defined('PDO::MYSQL_ATTR_INIT_COMMAND')) { $options[PDO::MYSQL_ATTR_INIT_COMMAND] = 'SET NAMES utf8mb4'; }",
    "$pdo = new PDO($dsn, $user, $pass, $options);",
    "$tables = array_values(array_filter(array_map('strval', (array)($cfg['tables'] ?? []))));",
    "$optional = array_fill_keys(array_values(array_filter(array_map('strval', (array)($cfg['optional_tables'] ?? [])))), true);",
    "$pathPatterns = array_values(array_filter(array_map('strval', (array)($cfg['redact_path_patterns'] ?? []))));",
    "$valuePatterns = array_values(array_filter(array_map('strval', (array)($cfg['redact_value_patterns'] ?? []))));",
    "$tableExists = function(string $table) use ($pdo): bool {",
    "  $stmt = $pdo->prepare('SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1');",
    "  $stmt->execute([$table]);",
    "  return (bool)$stmt->fetchColumn();",
    "};",
    "$matchesAnyPattern = function(string $value, array $patternList): bool {",
    "  foreach ($patternList as $pattern) { if (@preg_match($pattern, $value)) { if (preg_match($pattern, $value)) return true; } }",
    "  return false;",
    "};",
    "$isSensitivePath = function(string $path) use ($matchesAnyPattern, $pathPatterns): bool {",
    "  return $matchesAnyPattern($path, $pathPatterns);",
    "};",
    "$isSensitiveValue = function($value) use ($matchesAnyPattern, $valuePatterns): bool {",
    "  if ($value === null) return false;",
    "  if (!is_scalar($value)) return false;",
    "  return $matchesAnyPattern((string)$value, $valuePatterns);",
    "};",
    "$sqlValue = function($value) use ($pdo): string {",
    "  if ($value === null) return 'NULL';",
    "  if (is_bool($value)) return $value ? '1' : '0';",
    "  if (is_int($value) || is_float($value)) return (string)$value;",
    "  return $pdo->quote((string)$value);",
    "};",
    "$lines = [];",
    "$lines[] = 'SET FOREIGN_KEY_CHECKS=0;';",
    "$included = []; $skipped = []; $rowCounts = []; $redacted = 0; $redactedByPath = 0; $redactedByValue = 0;",
    "foreach ($tables as $table) {",
    "  if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) continue;",
    "  if (!$tableExists($table)) { if (isset($optional[$table])) { $skipped[] = $table; continue; } throw new RuntimeException('Missing required table: ' . $table); }",
    "  $createRow = $pdo->query('SHOW CREATE TABLE `'.$table.'`')->fetch(PDO::FETCH_ASSOC);",
    "  if (!is_array($createRow) || !isset($createRow['Create Table'])) throw new RuntimeException('SHOW CREATE TABLE failed for ' . $table);",
    "  $lines[] = 'DROP TABLE IF EXISTS `'.$table.'`;';",
    "  $lines[] = rtrim((string)$createRow['Create Table']) . ';';",
    "  $orderBy = '';",
    "  if ($table === 'core_config_data' && $tableExists('core_config_data')) { $orderBy = ' ORDER BY `config_id`'; }",
    "  elseif ($table === 'store_website') { $orderBy = ' ORDER BY `website_id`'; }",
    "  elseif ($table === 'store_group') { $orderBy = ' ORDER BY `group_id`'; }",
    "  elseif ($table === 'store') { $orderBy = ' ORDER BY `store_id`'; }",
    "  elseif ($table === 'theme') { $orderBy = ' ORDER BY `theme_id`'; }",
    "  $stmt = $pdo->query('SELECT * FROM `'.$table.'`' . $orderBy);",
    "  $count = 0;",
    "  while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {",
    "    $cols = []; $vals = [];",
    "    $redactRow = false;",
    "    $redactBy = '';",
    "    if ($table === 'core_config_data') {",
    "      $rowPath = (string)($row['path'] ?? '');",
    "      if ($isSensitivePath($rowPath)) { $redactRow = true; $redactBy = 'path'; }",
    "      elseif ($isSensitiveValue($row['value'] ?? null)) { $redactRow = true; $redactBy = 'value'; }",
    "    }",
    "    foreach ($row as $col => $val) {",
    "      $cols[] = '`' . str_replace('`', '``', (string)$col) . '`';",
    "      if ($table === 'core_config_data' && $col === 'value' && $redactRow) {",
    "        $val = '';",
    "        $redacted++;",
    "        if ($redactBy === 'path') { $redactedByPath++; }",
    "        elseif ($redactBy === 'value') { $redactedByValue++; }",
    "      }",
    "      $vals[] = $sqlValue($val);",
    "    }",
    "    $lines[] = 'INSERT INTO `'.$table.'` (' . implode(', ', $cols) . ') VALUES (' . implode(', ', $vals) . ');';",
    "    $count++;",
    "  }",
    "  $rowCounts[$table] = $count;",
    "  $included[] = $table;",
    "}",
    "$lines[] = 'SET FOREIGN_KEY_CHECKS=1;';",
    "$sql = implode(PHP_EOL, $lines) . PHP_EOL;",
    "$gz = gzencode($sql, 9);",
    "if ($gz === false) { fwrite(STDERR, 'gzencode failed'.PHP_EOL); exit(6); }",
    "$payload = [",
    "  'profile' => (string)($cfg['profile'] ?? 'scd-minimal-v1'),",
    "  'environment_id' => (int)($cfg['environment_id'] ?? 0),",
    "  'generated_at' => gmdate('c'),",
    "  'root_path' => $root,",
    "  'included_tables' => array_values($included),",
    "  'skipped_tables' => array_values($skipped),",
    "  'row_counts' => $rowCounts,",
    "  'redaction' => [",
    "    'path_patterns' => $pathPatterns,",
    "    'value_patterns' => $valuePatterns,",
    "    'redacted_rows' => $redacted,",
    "    'redacted_rows_by_path' => $redactedByPath,",
    "    'redacted_rows_by_value' => $redactedByValue,",
    "  ],",
    "  'sql_gz_sha256' => hash('sha256', $gz),",
    "  'sql_gz_base64' => base64_encode($gz),",
    "];",
    "echo (string)($cfg['payload_begin'] ?? 'MZ_SCD_DB_SNAPSHOT_PAYLOAD_BEGIN') . PHP_EOL;",
    "echo json_encode($payload, JSON_UNESCAPED_SLASHES) . PHP_EOL;",
    "echo (string)($cfg['payload_end'] ?? 'MZ_SCD_DB_SNAPSHOT_PAYLOAD_END') . PHP_EOL;",
    "PHP",
    'php /tmp/mz-scd-db-snapshot.php',
  ].join('\n');
}

async function runServiceJob(
  environmentId: number,
  serviceName: string,
  jobPrefix: string,
  script: string,
  opts?: {
    constrain_to_service_node?: boolean;
    timeout_ms?: number;
  }
): Promise<{ ok: boolean; logs: string; state: string; error?: string; details?: string[]; service?: string; node?: string }> {
  const serviceFullName = envServiceName(environmentId, serviceName);
  const spec = await inspectServiceSpec(serviceFullName);
  if (!spec) {
    return { ok: false, state: 'missing_service', logs: '', error: `service not found (${serviceFullName})` };
  }

  const networks = Array.from(new Set(spec.networks.map((net) => net.name).filter(Boolean)));
  if (!networks.length) networks.push('mz-backend');

  const secrets = spec.secrets.map((secret) => ({ source: secret.secret_name, target: secret.file_name }));
  const mounts = spec.mounts.map((mount) => ({
    type: mount.type,
    source: mount.source,
    target: mount.target,
    read_only: mount.read_only,
  }));

  let node: string | null = null;
  if (opts?.constrain_to_service_node !== false) {
    node = await getServiceTaskNode(environmentId, serviceName);
  }
  const constraints = node ? [`node.hostname==${node}`] : [];

  const jobName = buildJobName(jobPrefix, environmentId);
  const result = await runSwarmJob({
    name: jobName,
    image: spec.image,
    networks,
    secrets,
    mounts,
    env: spec.env,
    constraints,
    command: ['sh', '-lc', script],
    timeout_ms: opts?.timeout_ms,
  });

  return {
    ok: result.ok,
    logs: result.logs,
    state: result.state,
    error: result.error,
    details: result.details,
    service: serviceFullName,
    node: node || undefined,
  };
}

async function runPhpFpmHealth(environmentId: number): Promise<RunbookResult> {
  const serviceName = envServiceName(environmentId, 'php-fpm');
  const tasks = await listServiceTasks(serviceName);
  if (!tasks.length) {
    return {
      runbook_id: 'php_fpm_health',
      status: 'failed',
      summary: 'php-fpm service not found or has no tasks.',
      observations: [`Missing tasks for ${serviceName}`],
    };
  }

  const summary = summarizeServiceTasks(tasks);
  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const updateState = updateStatus?.state ? updateStatus.state.toLowerCase() : '';
  const updatePaused = updateState.includes('pause');
  const updateRolledBack = updateState.includes('rollback');
  const observations: string[] = [
    `Service: ${serviceName}`,
    `Tasks: running=${summary.running}/${summary.desired_running} total=${summary.total}`,
    updateStatus ? `Update: ${updateStatus.state || 'unknown'}${updateStatus.message ? ` (${updateStatus.message})` : ''}` : '',
    summary.nodes.length ? `Nodes: ${summary.nodes.join(', ')}` : '',
    ...summary.issues.map((line) => `Issue: ${line}`),
  ].filter(Boolean);

  const spec = await inspectServiceSpec(serviceName);
  const networkName = spec ? pickNetworkName(spec) || 'mz-backend' : 'mz-backend';
  const probe = await runCommand('docker', [
    'run',
    '--rm',
    '--network',
    networkName,
    'alpine:3.19',
    'sh',
    '-lc',
    `nc -z -w2 ${serviceName} 9000`,
  ], 8000);
  const probeOk = probe.code === 0;
  observations.push(`Probe: ${probeOk ? 'tcp/9000 reachable' : 'tcp/9000 NOT reachable'} (network=${networkName})`);

  const ready = summary.ok && probeOk;
  return {
    runbook_id: 'php_fpm_health',
    status: updatePaused
      ? 'failed'
      : ready
        ? updateRolledBack ? 'warning' : 'ok'
        : summary.ok ? 'warning' : 'failed',
    summary: updatePaused
      ? 'php-fpm update is paused due to a task failure.'
      : ready
        ? updateRolledBack
          ? 'php-fpm ready (but last update rolled back).'
          : 'php-fpm ready.'
        : summary.ok
          ? 'php-fpm running but probe failed.'
          : 'php-fpm is not running cleanly.',
    observations,
    data: {
      service: serviceName,
      tasks: tasks.slice(0, 10),
      probe: { ok: probeOk, exit_code: probe.code },
      update_status: updateStatus || null,
    },
  };
}

async function runVarnishReady(environmentId: number): Promise<RunbookResult> {
  const serviceName = envServiceName(environmentId, 'varnish');
  const tasks = await listServiceTasks(serviceName);
  if (!tasks.length) {
    return {
      runbook_id: 'varnish_ready',
      status: 'failed',
      summary: 'Varnish service not found or has no tasks.',
      observations: [`Missing tasks for ${serviceName}`],
    };
  }

  const summary = summarizeServiceTasks(tasks);
  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const updateState = updateStatus?.state ? updateStatus.state.toLowerCase() : '';
  const updatePaused = updateState.includes('pause');
  const updateRolledBack = updateState.includes('rollback');
  const observations: string[] = [
    `Service: ${serviceName}`,
    `Tasks: running=${summary.running}/${summary.desired_running} total=${summary.total}`,
    updateStatus ? `Update: ${updateStatus.state || 'unknown'}${updateStatus.message ? ` (${updateStatus.message})` : ''}` : '',
    summary.nodes.length ? `Nodes: ${summary.nodes.join(', ')}` : '',
    ...summary.issues.map((line) => `Issue: ${line}`),
  ].filter(Boolean);

  const spec = await inspectServiceSpec(serviceName);
  const networkName = spec ? pickNetworkName(spec) || 'mz-backend' : 'mz-backend';
  const varnishUrl = `http://${serviceName}/mz-healthz`;
  const probe = await runCommand('docker', [
    'run',
    '--rm',
    '--network',
    networkName,
    'curlimages/curl:8.5.0',
    'curl',
    '-fsS',
    '--max-time',
    '5',
    varnishUrl,
  ], 10_000);
  const probeOk = probe.code === 0;
  observations.push(`Probe: ${probeOk ? 'OK' : 'FAILED'} ${varnishUrl} (network=${networkName})`);
  if (!probeOk && probe.stderr.trim()) {
    observations.push(`Probe stderr: ${tailLines(probe.stderr.trim(), 10)}`);
  }

  const finalReady = summary.ok && probeOk;
  return {
    runbook_id: 'varnish_ready',
    status: updatePaused
      ? 'failed'
      : finalReady
        ? updateRolledBack ? 'warning' : 'ok'
        : summary.ok ? 'warning' : 'failed',
    summary: updatePaused
      ? 'Varnish update is paused due to a task failure.'
      : finalReady
        ? updateRolledBack
          ? 'Varnish ready (but last update rolled back).'
          : 'Varnish ready.'
        : summary.ok
          ? 'Varnish running but probe failed.'
          : 'Varnish is not running cleanly.',
    observations,
    data: {
      service: serviceName,
      tasks: tasks.slice(0, 10),
      probe: { ok: probeOk, exit_code: probe.code },
      update_status: updateStatus || null,
    },
  };
}

async function runGatewayUpdateSummary(environmentId: number): Promise<RunbookResult> {
  const services = [
    { label: 'Nginx', name: envServiceName(environmentId, 'nginx') },
    { label: 'Varnish', name: envServiceName(environmentId, 'varnish') },
    { label: 'PHP-FPM', name: envServiceName(environmentId, 'php-fpm') },
    { label: 'PHP-FPM Admin', name: envServiceName(environmentId, 'php-fpm-admin') },
  ];

  const observations: string[] = [];
  const data: Record<string, unknown> = { services: [] as any[] };

  let pausedCount = 0;
  let rollbackCount = 0;
  let failingCount = 0;

  for (const service of services) {
    const tasks = await listServiceTasks(service.name);
    const taskSummary = summarizeServiceTasks(tasks);
    const updateStatus = await inspectServiceUpdateStatus(service.name);
    const updateState = updateStatus?.state ? updateStatus.state.toLowerCase() : '';
    const updatePaused = updateState.includes('pause');
    const updateRolledBack = updateState.includes('rollback');

    if (updatePaused) pausedCount += 1;
    if (!updatePaused && updateRolledBack) rollbackCount += 1;
    if (!taskSummary.ok || updatePaused) failingCount += 1;

    observations.push(`${service.label}: tasks running=${taskSummary.running}/${taskSummary.desired_running} total=${taskSummary.total}`);
    if (updateStatus) {
      observations.push(`- update: ${updateStatus.state || 'unknown'}${updateStatus.message ? ` (${updateStatus.message})` : ''}`);
    }
    for (const issue of taskSummary.issues.slice(0, 3)) {
      observations.push(`- issue: ${issue}`);
    }

    (data.services as any[]).push({
      label: service.label,
      service: service.name,
      tasks: tasks.slice(0, 8),
      update_status: updateStatus || null,
      summary: taskSummary,
    });
  }

  const status: RunbookResult['status'] = pausedCount > 0
    ? 'failed'
    : failingCount > 0 || rollbackCount > 0
      ? 'warning'
      : 'ok';

  const summaryParts: string[] = [];
  if (pausedCount > 0) summaryParts.push(`Paused updates: ${pausedCount}`);
  if (rollbackCount > 0) summaryParts.push(`Recent rollbacks: ${rollbackCount}`);
  if (failingCount > 0 && pausedCount === 0) summaryParts.push(`Unhealthy services: ${failingCount}`);
  const summary = summaryParts.length
    ? `Gateway update issues detected. ${summaryParts.join(', ')}.`
    : 'Gateway services look healthy.';

  return {
    runbook_id: 'gateway_update_summary',
    status,
    summary,
    observations,
    data,
  };
}

type HttpSmokeCheckSpec = {
  name: string;
  url: string;
  expect_status?: number;
};

async function runHttpSmokeCheck(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const hostnameRaw = typeof input.hostname === 'string' ? input.hostname.trim() : '';
  const hostHeader = hostnameRaw || undefined;

  const timeoutSecondsRaw = typeof input.timeout_seconds === 'number' ? input.timeout_seconds : Number(input.timeout_seconds ?? NaN);
  const timeoutSeconds = Number.isFinite(timeoutSecondsRaw)
    ? Math.min(15, Math.max(2, Math.floor(timeoutSecondsRaw)))
    : 5;

  const connectTimeoutRaw = typeof input.connect_timeout_seconds === 'number'
    ? input.connect_timeout_seconds
    : Number(input.connect_timeout_seconds ?? NaN);
  const connectTimeoutSeconds = Number.isFinite(connectTimeoutRaw)
    ? Math.min(10, Math.max(1, Math.floor(connectTimeoutRaw)))
    : 2;

  const stackPrefix = `mz-env-${environmentId}_`;
  const checks: HttpSmokeCheckSpec[] = [
    { name: 'nginx.mz-healthz', url: `http://${stackPrefix}nginx/mz-healthz`, expect_status: 200 },
    { name: 'varnish.mz-healthz', url: `http://${stackPrefix}varnish/mz-healthz`, expect_status: 200 },
    { name: 'nginx.health_check.php', url: `http://${stackPrefix}nginx/health_check.php`, expect_status: 200 },
    { name: 'varnish.root', url: `http://${stackPrefix}varnish/` },
  ];

  const args: string[] = [
    'run',
    '--rm',
    '--network',
    'mz-backend',
    'curlimages/curl:8.5.0',
  ];

  const baseCurlArgs = [
    '-sS',
    '-o',
    '/dev/null',
    '--connect-timeout',
    String(connectTimeoutSeconds),
    '-m',
    String(timeoutSeconds),
  ];

  for (let index = 0; index < checks.length; index += 1) {
    const check = checks[index];
    if (index > 0) {
      args.push('--next');
    }
    args.push(
      ...baseCurlArgs,
      '-w',
      `${check.name} %{http_code}\\n`
    );
    if (hostHeader) {
      args.push('-H', `Host: ${hostHeader}`);
    }
    args.push(check.url);
  }

  const result = await runCommand('docker', args, 25_000);
  const observations: string[] = [];
  if (hostHeader) {
    observations.push(`Host header: ${hostHeader}`);
  }
  observations.push(`Probe timeouts: connect=${connectTimeoutSeconds}s total=${timeoutSeconds}s per request`);

  const rawLines = (result.stdout || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const statusByName = new Map<string, number>();
  for (const line of rawLines) {
    const match = line.match(/^(\S+)\s+(\d{3})$/);
    if (!match) continue;
    statusByName.set(match[1], Number(match[2]));
  }

  const failures: string[] = [];
  const dataChecks: Array<{ name: string; url: string; status: number; ok: boolean }> = [];
  for (const check of checks) {
    const status = statusByName.get(check.name) ?? 0;
    const ok = check.expect_status
      ? status === check.expect_status
      : status >= 200 && status < 400;
    dataChecks.push({ name: check.name, url: check.url, status, ok });
    observations.push(`${check.name}: ${status || 0}`);
    if (!ok) {
      const expected = check.expect_status ? String(check.expect_status) : '2xx/3xx';
      failures.push(`${check.name} expected ${expected} got ${status || 0}`);
    }
  }

  if (result.stderr?.trim()) {
    observations.push(`Probe stderr: ${result.stderr.trim()}`);
  }

  const ok = result.code === 0 && failures.length === 0;
  const status = ok ? 'ok' : failures.length ? 'warning' : 'failed';
  const summary = ok
    ? 'HTTP smoke checks passed.'
    : failures.length
      ? `HTTP smoke checks failed: ${failures.join('; ')}`
      : 'HTTP smoke checks could not be completed.';

  return {
    runbook_id: 'http_smoke_check',
    status,
    summary,
    observations,
    data: {
      checks: dataChecks,
      docker_exit_code: result.code,
    },
  };
}

async function runVarPermissions(environmentId: number): Promise<RunbookResult> {
  const actions: string[] = [];
  const checkScript = 'test -w /var/www/html/var && test -w /var/www/html/var/log && test -w /var/www/html/var/report';
  const check = await runServiceJob(environmentId, 'php-fpm', 'var-perms-check', checkScript, { timeout_ms: 60_000 });
  if (check.ok) {
    return {
      runbook_id: 'magento_var_permissions',
      status: 'ok',
      summary: 'Magento var directories are writable.',
      observations: [
        'Permissions check passed.',
        check.node ? `Node: ${check.node}` : '',
      ].filter(Boolean),
      data: { service: check.service || envServiceName(environmentId, 'php-fpm') },
      remediation: { attempted: false, actions },
    };
  }

  const fix = await runServiceJob(
    environmentId,
    'php-fpm',
    'var-perms-fix',
    'chown -R www-data:www-data /var/www/html/var && chmod -R g+rwX /var/www/html/var',
    { timeout_ms: 120_000 }
  );
  actions.push('Applied chown/chmod to /var/www/html/var');

  const recheck = await runServiceJob(environmentId, 'php-fpm', 'var-perms-recheck', checkScript, { timeout_ms: 60_000 });
  const resolved = recheck.ok;
  return {
    runbook_id: 'magento_var_permissions',
    status: resolved ? 'ok' : 'warning',
    summary: resolved ? 'Permissions fixed.' : 'Permissions still failing after remediation.',
    observations: [
      resolved ? 'Var directories are now writable.' : 'Permissions check still failing.',
      fix.node ? `Node: ${fix.node}` : '',
      fix.ok ? '' : `Fix failed: ${fix.error || fix.state}`,
      fix.logs.trim() ? `Fix logs: ${tailLines(fix.logs.trim(), 20)}` : '',
    ].filter(Boolean),
    data: { service: fix.service || envServiceName(environmentId, 'php-fpm') },
    remediation: { attempted: true, actions },
  };
}

async function runMediaPermissions(environmentId: number): Promise<RunbookResult> {
  const actions: string[] = [];
  const hasAdmin = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm-admin')));
  const targetService = hasAdmin ? 'php-fpm-admin' : 'php-fpm';

  const base = '/var/www/html/magento/pub/media';
  const checkScript = `test -w ${base} && test -w ${base}/captcha`;
  const check = await runServiceJob(environmentId, targetService, 'media-perms-check', checkScript, { timeout_ms: 60_000 });
  if (check.ok) {
    return {
      runbook_id: 'magento_media_permissions',
      status: 'ok',
      summary: 'Magento pub/media is writable.',
      observations: [
        'Permissions check passed.',
        `Service: ${envServiceName(environmentId, targetService)}`,
        check.node ? `Node: ${check.node}` : '',
      ].filter(Boolean),
      data: { service: check.service || envServiceName(environmentId, targetService) },
      remediation: { attempted: false, actions },
    };
  }

  const fix = await runServiceJob(
    environmentId,
    targetService,
    'media-perms-fix',
    `mkdir -p ${base}/captcha/admin && chown -R www-data:www-data ${base} && chmod -R 775 ${base}`,
    { timeout_ms: 120_000 }
  );
  actions.push('Applied mkdir/chown/chmod to /var/www/html/magento/pub/media');

  const recheck = await runServiceJob(environmentId, targetService, 'media-perms-recheck', checkScript, { timeout_ms: 60_000 });
  const resolved = recheck.ok;
  return {
    runbook_id: 'magento_media_permissions',
    status: resolved ? 'ok' : 'warning',
    summary: resolved ? 'Permissions fixed.' : 'Permissions still failing after remediation.',
    observations: [
      resolved ? 'pub/media is now writable.' : 'Permissions check still failing.',
      `Service: ${envServiceName(environmentId, targetService)}`,
      fix.node ? `Node: ${fix.node}` : '',
      fix.ok ? '' : `Fix failed: ${fix.error || fix.state}`,
      fix.logs.trim() ? `Fix logs: ${tailLines(fix.logs.trim(), 20)}` : '',
    ].filter(Boolean),
    data: { service: fix.service || envServiceName(environmentId, targetService) },
    remediation: { attempted: true, actions },
  };
}

async function runProxySqlReady(environmentId: number): Promise<RunbookResult> {
  const serviceName = `mz-env-${environmentId}_proxysql`;
  const spec = await inspectServiceSpec(serviceName);
  if (!spec) {
    return {
      runbook_id: 'proxysql_ready',
      status: 'failed',
      summary: 'ProxySQL service not found.',
      observations: [`Missing service: ${serviceName}`],
    };
  }

  const node = await getServiceTaskNode(environmentId, 'proxysql');
  const observations = node ? [`Task node: ${node}`] : [];

  const rows = await queryProxySqlHostgroups(environmentId);
  if (!rows.length) {
    return {
      runbook_id: 'proxysql_ready',
      status: 'warning',
      summary: 'ProxySQL is running but admin readiness is unconfirmed.',
      observations: [...observations, 'Unable to query ProxySQL admin interface (6032) over the overlay network.'],
      data: { service: spec, task_node: node },
    };
  }

  const onlineCount = rows.filter((row) => row.status.toUpperCase() === 'ONLINE').length;
  const ok = onlineCount > 0;
  return {
    runbook_id: 'proxysql_ready',
    status: ok ? 'ok' : 'warning',
    summary: ok ? 'ProxySQL ready (has ONLINE backends).' : 'ProxySQL running but no ONLINE backends.',
    observations: [
      ...observations,
      `Backends: ONLINE=${onlineCount} total=${rows.length}`,
    ],
    data: { service: spec, task_node: node, hostgroups: rows },
  };
}

async function runCloudflared(environmentId: number): Promise<RunbookResult> {
  const services = await listEnvironmentServices(environmentId);
  const matches = services.filter((entry) => entry.name.includes('cloudflared') || entry.name.includes('_tunnel'));
  if (!matches.length) {
    return {
      runbook_id: 'dns_cloudflared_ingress',
      status: 'failed',
      summary: 'Cloudflared service not found.',
      observations: ['No cloudflared service matched for this environment.'],
    };
  }

  const observations: string[] = [];
  let ok = true;
  for (const service of matches) {
    const tasks = await listServiceTasks(service.name);
    const summary = summarizeServiceTasks(tasks);
    observations.push(
      `Service: ${service.name} (${service.replicas || 'replicas unknown'})`,
      `Tasks: running=${summary.running}/${summary.desired_running} total=${summary.total}`,
      summary.nodes.length ? `Nodes: ${summary.nodes.join(', ')}` : ''
    );
    for (const issue of summary.issues) {
      observations.push(`Issue: ${issue}`);
    }
    ok = ok && summary.ok;
  }
  return {
    runbook_id: 'dns_cloudflared_ingress',
    status: ok ? 'ok' : 'warning',
    summary: ok ? 'Cloudflared ingress appears healthy.' : 'Cloudflared ingress has task issues.',
    observations: observations.filter(Boolean),
    data: { services: matches },
  };
}

function parseCurrentStateAgeSeconds(currentState: string): number | null {
  const trimmed = currentState.trim();
  const exact = trimmed.match(/^Running\s+(\d+)\s+(second|minute|hour|day)s?\s+ago/i);
  if (exact) {
    const n = Number.parseInt(exact[1], 10);
    if (!Number.isFinite(n)) return null;
    const unit = exact[2].toLowerCase();
    if (unit === 'second') return n;
    if (unit === 'minute') return n * 60;
    if (unit === 'hour') return n * 3600;
    if (unit === 'day') return n * 86400;
  }
  const about = trimmed.match(/^Running\s+about\s+an?\s+(minute|hour)\s+ago/i);
  if (about) {
    const unit = about[1].toLowerCase();
    return unit === 'hour' ? 3600 : 60;
  }
  return null;
}

async function runRestartSummary(environmentId: number): Promise<RunbookResult> {
  const services = await listEnvironmentServices(environmentId);
  const issues: string[] = [];
  const recentlyStarted: string[] = [];

  for (const service of services) {
    const tasks = await listServiceTasks(service.name);
    const summary = summarizeServiceTasks(tasks);
    if (!summary.ok) {
      for (const issue of summary.issues) {
        issues.push(`${service.name}: ${issue}`);
      }
    }
    for (const task of tasks) {
      const ageSeconds = parseCurrentStateAgeSeconds(task.current_state);
      if (ageSeconds !== null && ageSeconds < 600) {
        recentlyStarted.push(`${task.name} on ${task.node || '(unknown node)'}: ${task.current_state}`);
      }
    }
  }

  const ok = issues.length === 0 && recentlyStarted.length === 0;
  const observations: string[] = [
    `Services checked: ${services.length}`,
    issues.length ? `Non-running tasks: ${issues.length}` : 'No non-running tasks detected.',
    recentlyStarted.length ? `Recently started tasks (<10m): ${recentlyStarted.length}` : 'No recently started tasks detected (<10m).',
    ...issues.slice(0, 10),
    ...recentlyStarted.slice(0, 10),
  ];
  return {
    runbook_id: 'container_restart_summary',
    status: ok ? 'ok' : 'warning',
    summary: ok ? 'No restart issues detected.' : 'Potential restart/health issues detected.',
    observations,
    data: { services_checked: services.length, issues_count: issues.length, recently_started_count: recentlyStarted.length },
  };
}

function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

async function runDeployFailureSummary(environmentId: number): Promise<RunbookResult> {
  if (!fs.existsSync(DEPLOY_FAILED_DIR)) {
    return {
      runbook_id: 'deploy_failure_summary',
      status: 'ok',
      summary: 'No failed deploy records directory found.',
      observations: [`Expected path: ${DEPLOY_FAILED_DIR}`],
    };
  }

  const files = fs.readdirSync(DEPLOY_FAILED_DIR).filter((name) => name.endsWith('.json'));
  let best: { deploymentId: string; failedAt: string; failedAtMs: number; error: string; record: Record<string, unknown> } | null = null;

  for (const file of files) {
    const fullPath = path.join(DEPLOY_FAILED_DIR, file);
    let raw = '';
    try {
      raw = fs.readFileSync(fullPath, 'utf8');
    } catch {
      continue;
    }
    const parsed = safeJsonParse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      continue;
    }
    const record = parsed as Record<string, unknown>;
    const payload = (record.payload && typeof record.payload === 'object' && !Array.isArray(record.payload))
      ? (record.payload as Record<string, unknown>)
      : null;
    const envId = Number(payload?.environment_id ?? 0);
    if (!envId || envId !== environmentId) {
      continue;
    }

    const failedAt = String(record.failed_at ?? '').trim();
    const failedAtMs = failedAt ? Date.parse(failedAt) : 0;
    const deploymentId = String(record.id ?? path.basename(file, '.json')).trim() || path.basename(file, '.json');
    const error = String(record.error ?? '').trim();

    if (!best || failedAtMs > best.failedAtMs) {
      best = { deploymentId, failedAt, failedAtMs, error, record };
    }
  }

  if (!best) {
    return {
      runbook_id: 'deploy_failure_summary',
      status: 'ok',
      summary: 'No failed deploy records found for this environment.',
      observations: [`Scanned ${files.length} record(s) in ${DEPLOY_FAILED_DIR}`],
    };
  }

  const observations = [
    best.failedAt ? `Failed at: ${best.failedAt}` : 'Failed at: (unknown)',
    best.error ? `Error: ${best.error}` : 'Error: (missing error message)',
  ];

  return {
    runbook_id: 'deploy_failure_summary',
    status: 'warning',
    summary: best.error
      ? `Most recent deploy failed (${best.deploymentId}): ${best.error}`
      : `Most recent deploy failed (${best.deploymentId}).`,
    observations,
    data: {
      deployment_id: best.deploymentId,
      failed_at: best.failedAt || null,
      error: best.error || null,
      record: best.record,
    },
  };
}

async function runServiceRestart(
  environmentId: number,
  includes: string | string[],
  runbookId: string,
  label: string
): Promise<RunbookResult> {
  const patterns = Array.isArray(includes) ? includes : [includes];
  let service = null as Awaited<ReturnType<typeof findEnvironmentService>> | null;
  for (const pattern of patterns) {
    service = await findEnvironmentService(environmentId, pattern);
    if (service) break;
  }
  if (!service) {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: `${label} service not found.`,
      observations: [`No ${label} service matched for this environment.`],
      remediation: { attempted: false, actions: [] },
    };
  }
  const actions: string[] = [];
  const beforeStatus = await inspectServiceUpdateStatus(service.name);
  if (beforeStatus?.state && beforeStatus.state.toLowerCase().includes('pause')) {
    const resume = await runCommand('docker', ['service', 'update', '--update-failure-action', 'continue', service.name]);
    actions.push(resume.code === 0 ? `Resumed paused update for ${service.name}` : `Failed to resume paused update for ${service.name}`);
  }

  let result = await runCommand('docker', ['service', 'update', '--force', service.name]);
  if (result.code !== 0) {
    const output = `${result.stderr || ''}\n${result.stdout || ''}`.toLowerCase();
    if (output.includes('update paused') || output.includes('paused')) {
      const resume = await runCommand('docker', ['service', 'update', '--update-failure-action', 'continue', service.name]);
      actions.push(resume.code === 0 ? `Resumed paused update for ${service.name}` : `Failed to resume paused update for ${service.name}`);
      result = await runCommand('docker', ['service', 'update', '--force', service.name]);
    }
  }

  if (result.code === 0) {
    actions.push(`Forced update for ${service.name}`);
  } else {
    actions.push(`Failed to force update ${service.name}`);
  }

  const afterStatus = await inspectServiceUpdateStatus(service.name);
  const tasks = await listServiceTasks(service.name);
  const taskSummary = summarizeServiceTasks(tasks);
  const paused = afterStatus?.state ? afterStatus.state.toLowerCase().includes('pause') : false;
  return {
    runbook_id: runbookId,
    status: result.code === 0 ? 'ok' : paused ? 'failed' : 'warning',
    summary: result.code === 0
      ? `${label} restart triggered.`
      : paused
        ? `${label} update is paused due to a task failure.`
        : `${label} restart failed.`,
    observations: [
      `Service: ${service.name} (${service.replicas || 'replicas unknown'})`,
      afterStatus ? `Update: ${afterStatus.state || 'unknown'}${afterStatus.message ? ` (${afterStatus.message})` : ''}` : '',
      `Tasks: running=${taskSummary.running}/${taskSummary.desired_running} total=${taskSummary.total}`,
      ...taskSummary.issues.map((line) => `Issue: ${line}`),
      result.stderr ? `stderr: ${result.stderr.trim()}` : '',
    ].filter(Boolean),
    data: { service, update_status: afterStatus || null, tasks: tasks.slice(0, 10) },
    remediation: { attempted: true, actions },
  };
}

export async function listRunbooks() {
  return RUNBOOKS;
}

export async function executeRunbook(request: Request): Promise<RunbookResult | { error: string; status: number }> {
  const authorized = await validateNodeRequest(request);
  if (!authorized) {
    return { error: 'unauthorized', status: 401 };
  }
  const body = await request.json().catch(() => null) as {
    runbook_id?: string;
    environment_id?: number;
    input?: Record<string, unknown>;
  } | null;
  const runbookId = String(body?.runbook_id || '').trim();
  const environmentId = Number(body?.environment_id || 0);
  const input = (body?.input && typeof body.input === 'object' && !Array.isArray(body.input))
    ? (body.input as Record<string, unknown>)
    : {};
  if (!runbookId || !environmentId) {
    return { error: 'missing_parameters', status: 400 };
  }
  switch (runbookId) {
    case 'disk_usage_summary':
      return runDiskUsageSummary();
    case 'swarm_capacity_summary':
      return runSwarmCapacitySummary(environmentId);
    case 'swarm_tuning_profile_summary':
      return runSwarmTuningProfileSummary(environmentId);
    case 'swarm_tuning_profile_apply':
      return runSwarmTuningProfileApply(environmentId, input);
    case 'db_replication_status':
      return runDbReplicationStatus(environmentId);
    case 'db_replica_enable':
      return runDbReplicaEnable(environmentId);
    case 'db_failover':
      return runDbSwitchRole(environmentId, 'to_replica');
    case 'db_failback':
      return runDbSwitchRole(environmentId, 'to_primary');
    case 'db_replica_repair':
      return runDbReplicaRepair(environmentId);
    case 'db_replica_reseed':
      return runDbReplicaReseed(environmentId);
    case 'php_fpm_health':
      return runPhpFpmHealth(environmentId);
    case 'varnish_ready':
      return runVarnishReady(environmentId);
    case 'gateway_update_summary':
      return runGatewayUpdateSummary(environmentId);
    case 'http_smoke_check':
      return runHttpSmokeCheck(environmentId, input);
    case 'magento_var_permissions':
      return runVarPermissions(environmentId);
    case 'magento_media_permissions':
      return runMediaPermissions(environmentId);
    case 'proxysql_ready':
      return runProxySqlReady(environmentId);
    case 'dns_cloudflared_ingress':
      return runCloudflared(environmentId);
    case 'container_restart_summary':
      return runRestartSummary(environmentId);
    case 'deploy_failure_summary':
      return runDeployFailureSummary(environmentId);
    case 'deploy_active_summary':
      return runDeployActiveSummary(environmentId);
    case 'deploy_log_excerpt':
      return runDeployLogExcerpt(environmentId, input);
    case 'deploy_pause_status':
      return runDeployPauseStatus();
    case 'deploy_pause':
      return runDeployPause();
    case 'deploy_resume':
      return runDeployResume();
    case 'deploy_rollback_previous':
      return runDeployRollbackPrevious(environmentId, input);
    case 'deploy_retry_latest':
      return runDeployRetryLatest(environmentId);
    case 'magento_maintenance_enable':
      return runMagentoMaintenance(environmentId, 'enable');
    case 'magento_maintenance_disable':
      return runMagentoMaintenance(environmentId, 'disable');
    case 'db_backup':
      return runDbBackup(environmentId, input);
    case 'db_restore_provisioning':
      return runDbRestoreProvisioning(environmentId, input);
    case 'magento_scd_db_snapshot':
      return runMagentoScdDbSnapshot(environmentId, input);
    case 'environment_teardown':
      return runEnvironmentTeardown(environmentId, input);
    case 'proxysql_restart':
      return runServiceRestart(environmentId, '_proxysql', 'proxysql_restart', 'ProxySQL');
    case 'cloudflared_restart':
      return runServiceRestart(environmentId, ['cloudflared', '_tunnel'], 'cloudflared_restart', 'Cloudflared');
    case 'varnish_restart':
      return runServiceRestart(environmentId, '_varnish', 'varnish_restart', 'Varnish');
    default:
      return { error: 'unknown_runbook', status: 404 };
  }
}

function normalizeDbRestoreObjectKey(environmentId: number, raw: string): string | null {
  const key = String(raw || '').trim().replace(/^\/+/, '');
  if (!key) return null;
  if (key.includes('..')) return null;
  if (!/^[a-zA-Z0-9._/-]+$/.test(key)) return null;
  if (key === DEFAULT_DB_RESTORE_OBJECT) return key;
  const prefix = `db-backups/env-${environmentId}/`;
  if (!key.startsWith(prefix)) return null;
  return key;
}

async function waitForLocalContainer(stackName: string, serviceName: string, timeoutMs: number): Promise<string> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = await runCommand('docker', [
      'ps',
      '--filter',
      `name=${stackName}_${serviceName}`,
      '--format',
      '{{.ID}}',
    ], 12_000);
    const id = (result.code === 0 ? result.stdout : '').trim().split('\n')[0] || '';
    if (id) return id;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Timed out waiting for ${serviceName} container on this node`);
}

async function waitForDatabase(containerId: string, timeoutMs: number) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = await runCommand('docker', [
      'exec',
      containerId,
      'sh',
      '-c',
      'mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -e "SELECT 1" >/dev/null 2>&1',
    ], 12_000);
    if (result.code === 0) return;
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error('Database did not become ready in time');
}

async function databaseHasTables(containerId: string, dbName: string): Promise<boolean> {
  const safeName = String(dbName || '').trim() || 'magento';
  const result = await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -N -s -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${safeName.replace(/'/g, "''")}'" 2>/dev/null || echo 0`,
  ], 30_000);
  if (result.code !== 0) return false;
  const count = Number.parseInt(result.stdout.trim().split('\n')[0] || '0', 10);
  return Number.isFinite(count) && count > 0;
}

async function downloadR2Object(r2: R2PresignContext, objectKey: string, targetPath: string) {
  const url = await presignR2ObjectUrl(r2, 'GET', objectKey, 3600);
  const result = await runCommand('curl', ['-fsSL', url, '-o', targetPath], 10 * 60_000);
  if (result.code !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || 'Failed to download backup from R2');
  }
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

async function runMagentoScdDbSnapshot(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const runbookId = 'magento_scd_db_snapshot';
  const script = buildScdDbSnapshotExporterScript(environmentId, input);
  const preferredService = String(input.service_name ?? '').trim();
  const servicesToTry = preferredService
    ? [preferredService, 'php-fpm-admin', 'php-fpm']
    : ['php-fpm-admin', 'php-fpm'];
  const seen = new Set<string>();
  const orderedServices = servicesToTry.filter((name) => {
    const normalized = String(name || '').trim();
    if (!normalized || seen.has(normalized)) return false;
    seen.add(normalized);
    return true;
  });

  let lastFailure: { service: string; job?: Awaited<ReturnType<typeof runServiceJob>> } | null = null;
  for (const service of orderedServices) {
    const job = await runServiceJob(environmentId, service, 'scd-db-snapshot', script, { timeout_ms: 10 * 60_000 });
    if (!job.ok) {
      lastFailure = { service, job };
      continue;
    }
    const payload = parseScdDbSnapshotPayload(job.logs || '');
    if (!payload) {
      lastFailure = { service, job };
      continue;
    }
    const rowCounts = payload.row_counts || {};
    const rowCountSummary = Object.entries(rowCounts)
      .map(([table, count]) => `${table}=${Number(count || 0)}`)
      .join(', ');
    return {
      runbook_id: runbookId,
      status: 'ok',
      summary: `Generated sanitized SCD DB snapshot via ${service}.`,
      observations: [
        `Service: ${service}`,
        `Profile: ${payload.profile || SCD_DB_SNAPSHOT_PROFILE}`,
        `Included tables: ${(payload.included_tables || []).join(', ') || '(none)'}`,
        payload.skipped_tables?.length ? `Skipped optional tables: ${payload.skipped_tables.join(', ')}` : '',
        rowCountSummary ? `Row counts: ${rowCountSummary}` : '',
        `Redacted core_config_data rows: ${Number(payload.redaction?.redacted_rows ?? 0)}`,
        `Redacted by path: ${Number(payload.redaction?.redacted_rows_by_path ?? 0)}`,
        `Redacted by value: ${Number(payload.redaction?.redacted_rows_by_value ?? 0)}`,
        `sql.gz sha256: ${payload.sql_gz_sha256 || ''}`,
      ].filter(Boolean),
      data: payload as unknown as Record<string, unknown>,
    };
  }

  const failureLogs = String(lastFailure?.job?.logs || '').trim();
  const failureDetail = [
    `Tried services: ${orderedServices.join(', ')}`,
    lastFailure?.service ? `Last service: ${lastFailure.service}` : '',
    lastFailure?.job?.error ? `Last error: ${lastFailure.job.error}` : '',
    lastFailure?.job?.state ? `Last state: ${lastFailure.job.state}` : '',
    failureLogs ? `Last logs (tail): ${tailLines(failureLogs, 20)}` : '',
  ].filter(Boolean);
  return {
    runbook_id: runbookId,
    status: 'failed',
    summary: 'Failed to generate SCD DB snapshot.',
    observations: failureDetail,
  };
}

async function runDbRestoreProvisioning(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const runbookId = 'db_restore_provisioning';
  const observations: string[] = [];
  const actions: string[] = [];
  const progress = RunbookProgress.create(runbookId, environmentId, [
    { id: 'validate', label: 'Validate inputs' },
    { id: 'wait_db', label: 'Wait for database' },
    { id: 'check', label: 'Check database state' },
    { id: 'download', label: 'Download backup from R2' },
    { id: 'decrypt', label: 'Decrypt backup' },
    { id: 'decompress', label: 'Decompress backup' },
    { id: 'sanitize', label: 'Sanitize SQL (strip definers)' },
    { id: 'import', label: 'Import SQL into database' },
    { id: 'secure_offloader', label: 'Apply secure offloader config' },
    { id: 'verify', label: 'Verify restored database' },
  ]);

  progress.start('validate');
  if (!fs.existsSync(STACK_MASTER_KEY_PATH)) {
    progress.fail('validate', 'Missing stack master private key for decrypt.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Missing stack master private key for decrypt.',
      observations: [`Expected: ${STACK_MASTER_KEY_PATH}`],
    };
  }
  const r2 = resolveR2Context(environmentId);
  if (!r2) {
    progress.fail('validate', 'Missing mz-control connection details for R2 presign.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Missing mz-control connection details for R2 presign.',
      observations: [
        `Expected: ${path.join(NODE_DIR, 'node-id')}`,
        `Expected: ${path.join(NODE_DIR, 'node-secret')}`,
        `Expected: ${path.join(NODE_DIR, 'config.json')} with stack_id + mz_control_base_url (or env var MZ_CONTROL_BASE_URL)`,
      ],
    };
  }
  const envRecord = await fetchEnvironmentRecord(r2).catch(() => null);
  const inputObject = typeof input.backup_object === 'string' ? input.backup_object.trim() : '';
  const rawKey = inputObject || String(envRecord?.db_backup_object || '').trim() || DEFAULT_DB_RESTORE_OBJECT;
  const objectKey = normalizeDbRestoreObjectKey(environmentId, rawKey);
  if (!objectKey) {
    progress.fail('validate', 'Invalid backup object key.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Invalid backup object key.',
      observations: [
        `Received: ${String(rawKey || '(empty)')}`,
        `Allowed: ${DEFAULT_DB_RESTORE_OBJECT}`,
        `Allowed prefix: db-backups/env-${environmentId}/...`,
      ],
    };
  }
  progress.ok('validate');

  progress.start('wait_db');
  const stackName = `mz-env-${environmentId}`;
  let dbContainerId: string;
  try {
    dbContainerId = await waitForLocalContainer(stackName, 'database', 5 * 60_000);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    progress.fail('wait_db', message);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database container not found on this node.',
      observations: [
        message,
        'Note: This runbook currently requires the database task to be running on the same node as swarm-agent.',
      ],
    };
  }
  try {
    await waitForDatabase(dbContainerId, 5 * 60_000);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    progress.fail('wait_db', message);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database did not become ready in time.',
      observations: [message],
    };
  }
  progress.ok('wait_db');

  const dbName = 'magento';
  progress.start('check');
  const alreadyPopulated = await databaseHasTables(dbContainerId, dbName);
  if (alreadyPopulated) {
    progress.ok('check', 'Database already populated; restore not required.');
    return {
      runbook_id: runbookId,
      status: 'ok',
      summary: 'Database already populated; restore not required.',
      observations: [
        `Database: ${dbName}`,
        `Backup object (unused): ${objectKey}`,
      ],
    };
  }
  progress.ok('check', 'Database empty; proceeding with restore.');

  ensureDir(path.join(DEPLOY_WORK_DIR, 'runbooks'));
  const workDir = fs.mkdtempSync(path.join(DEPLOY_WORK_DIR, 'runbooks', `db-restore-env-${environmentId}-`));
  const encryptedPath = path.join(workDir, path.basename(objectKey));
  const decryptedPath = path.join(workDir, 'db.sql.zst');
  const sqlPath = path.join(workDir, 'db.sql');
  const sanitizedPath = path.join(workDir, 'db.sanitized.sql');

  progress.start('download');
  await downloadR2Object(r2, objectKey, encryptedPath);
  actions.push(`downloaded:${objectKey}`);
  progress.ok('download');

  progress.start('decrypt');
  {
    const result = await runCommand('age', ['-d', '-i', STACK_MASTER_KEY_PATH, '-o', decryptedPath, encryptedPath], 10 * 60_000);
    if (result.code !== 0) {
      const message = result.stderr.trim() || result.stdout.trim() || 'age decrypt failed';
      progress.fail('decrypt', message);
      return { runbook_id: runbookId, status: 'failed', summary: 'Decrypt failed.', observations: [message] };
    }
  }
  progress.ok('decrypt');

  progress.start('decompress');
  {
    const result = await runCommand('zstd', ['-d', '-f', '-o', sqlPath, decryptedPath], 30 * 60_000);
    if (result.code !== 0) {
      const message = result.stderr.trim() || result.stdout.trim() || 'zstd decompress failed';
      progress.fail('decompress', message);
      return { runbook_id: runbookId, status: 'failed', summary: 'Decompress failed.', observations: [message] };
    }
  }
  progress.ok('decompress');

  progress.start('sanitize');
  await stripDefiners(sqlPath, sanitizedPath);
  progress.ok('sanitize');

  progress.start('import');
  {
    const cp = await runCommand('docker', ['cp', sanitizedPath, `${dbContainerId}:/tmp/mz-restore.sql`], 5 * 60_000);
    if (cp.code !== 0) {
      const message = cp.stderr.trim() || cp.stdout.trim() || 'docker cp failed';
      progress.fail('import', message);
      return { runbook_id: runbookId, status: 'failed', summary: 'Import failed.', observations: [message] };
    }
    const importCmd = [
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -e "CREATE DATABASE IF NOT EXISTS ${dbName};"`,
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" --database="${dbName}" < /tmp/mz-restore.sql`,
    ].join(' && ');
    const imp = await runCommand('docker', ['exec', dbContainerId, 'sh', '-c', importCmd], 60 * 60_000);
    if (imp.code !== 0) {
      const message = imp.stderr.trim() || imp.stdout.trim() || 'database import failed';
      progress.fail('import', message);
      return { runbook_id: runbookId, status: 'failed', summary: 'Import failed.', observations: [message] };
    }
  }
  progress.ok('import');

  progress.start('secure_offloader');
  {
    const statements = [
      `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/offloader_header', 'X-Forwarded-Proto') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
      `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/offloader_header_value', 'https') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    ].join('; ');
    const cmd = `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${dbName} -e "${statements};"`;
    const res = await runCommand('docker', ['exec', dbContainerId, 'sh', '-c', cmd], 5 * 60_000);
    if (res.code !== 0) {
      const message = res.stderr.trim() || res.stdout.trim() || 'secure offloader config failed';
      progress.fail('secure_offloader', message);
      return { runbook_id: runbookId, status: 'failed', summary: 'Secure offloader config failed.', observations: [message] };
    }
  }
  progress.ok('secure_offloader');

  progress.start('verify');
  const restored = await databaseHasTables(dbContainerId, dbName);
  if (!restored) {
    progress.fail('verify', 'Database still appears empty after import.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database restore did not complete successfully.',
      observations: [
        `Database: ${dbName}`,
        `Backup object: ${objectKey}`,
      ],
    };
  }
  observations.push(`Database restored into ${dbName}.`);
  observations.push(`Backup object: ${objectKey}`);
  progress.ok('verify');

  return {
    runbook_id: runbookId,
    status: 'ok',
    summary: 'Database restored.',
    observations,
    remediation: { attempted: true, actions },
  };
}

async function runDbBackup(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const runbookId = 'db_backup';
  const actions: string[] = [];
  const observations: string[] = [];
  const progress = RunbookProgress.create(runbookId, environmentId, [
    { id: 'validate', label: 'Validate inputs' },
    { id: 'maintenance_on', label: 'Enable maintenance mode' },
    { id: 'cron_pause', label: 'Pause cron' },
    { id: 'dump', label: 'Dump database' },
    { id: 'compress', label: 'Compress backup' },
    { id: 'encrypt', label: 'Encrypt backup' },
    { id: 'upload', label: 'Upload to R2' },
    { id: 'cron_resume', label: 'Resume cron' },
    { id: 'maintenance_off', label: 'Disable maintenance mode' },
  ]);

  progress.start('validate');
  const method = String(input.method ?? 'mysqldump').trim().toLowerCase() || 'mysqldump';
  if (method !== 'mysqldump') {
    progress.fail('validate', `Unsupported backup method: ${method}`);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Unsupported backup method.',
      observations: ['Supported methods: mysqldump', `Requested: ${method}`],
    };
  }
  progress.ok('validate');

  const r2 = resolveR2Context(environmentId);
  if (!r2) {
    progress.fail('validate', 'Missing mz-control connection details for R2 presign.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Missing mz-control connection details for R2 presign.',
      observations: [
        `Expected: ${path.join(NODE_DIR, 'node-id')}`,
        `Expected: ${path.join(NODE_DIR, 'node-secret')}`,
        `Expected: ${path.join(NODE_DIR, 'config.json')} with stack_id + mz_control_base_url (or env var MZ_CONTROL_BASE_URL)`,
      ],
    };
  }
  const envRecord = await fetchEnvironmentRecord(r2).catch(() => null);
  const backupBucket = String(envRecord?.db_backup_bucket || '').trim();

  const publicKeyPath = resolveStackMasterPublicKeyPath();
  if (!publicKeyPath) {
    progress.fail('validate', 'Missing stack master public key for encryption.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Missing stack master public key for encryption.',
      observations: [
        `Checked: ${STACK_MASTER_PUBLIC_KEY_PATH}`,
        `Checked: ${path.join(NODE_DIR, 'stack_master_ssh.pub')}`,
      ],
    };
  }

  const backupObjectRaw = typeof input.backup_object === 'string' ? input.backup_object.trim() : '';
  // Keep "latest" in R2 by default. (Local history retention is planned separately.)
  const backupObjectDefault = `db-backups/env-${environmentId}/latest.sql.zst.age`;
  const backupObject = (backupObjectRaw || backupObjectDefault).replace(/^\/+/, '');

  const dbServiceName = envServiceName(environmentId, 'database');
  const dbReplicaServiceName = envServiceName(environmentId, 'database-replica');
  const dbSpec = await inspectServiceSpec(dbServiceName);
  if (!dbSpec) {
    progress.fail('validate', `Database service missing: ${dbServiceName}`);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database service not found; backup aborted.',
      observations: [`Service missing: ${dbServiceName}`],
    };
  }

  const dbName = String(dbSpec.env.MYSQL_DATABASE || 'magento').trim() || 'magento';

  // Best-effort: put the site into maintenance mode and pause cron to reduce writes.
  progress.start('maintenance_on');
  const maintenance = await runMagentoMaintenance(environmentId, 'enable');
  actions.push('Enabled Magento maintenance mode');
  observations.push(...maintenance.observations.map((line) => `Maintenance: ${line}`));
  if (maintenance.status !== 'ok') {
    progress.fail('maintenance_on', 'Failed to enable maintenance mode; backup aborted.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Failed to enable maintenance mode; backup aborted.',
      observations,
      remediation: { attempted: true, actions },
    };
  }
  progress.ok('maintenance_on');

  progress.start('cron_pause');
  const cronDown = await scaleEnvironmentService(environmentId, 'cron', 0);
  actions.push(cronDown.ok ? 'Scaled cron service to 0' : `Failed to scale cron service: ${cronDown.note || ''}`.trim());
  progress.ok('cron_pause', cronDown.ok ? '' : 'Failed to scale cron service to 0');

  const timestamp = formatTimestamp();
  const workDir = path.join(DEPLOY_WORK_DIR, `db-backup-${environmentId}-${timestamp}`);
  ensureDir(workDir);
  const dumpPath = path.join(workDir, `db-${timestamp}.sql`);
  const zstPath = `${dumpPath}.zst`;
  const agePath = `${zstPath}.age`;

  let uploaded = false;
  let dumpSource = '';
  try {
    progress.start('dump');
    // Prefer dumping from the current writer if we can detect it and it is local.
    // NOTE: This currently uses docker exec on the local node. If the database container
    // is scheduled on a different node, this will fail. In that case, we should migrate
    // this runbook to use a dedicated backup job image that can run on the DB node.
    const primaryHost = dbServiceName;
    const replicaHost = await inspectServiceSpec(dbReplicaServiceName) ? dbReplicaServiceName : '';
    const primaryReadOnly = await dbGetReadOnly(environmentId, primaryHost);
    const primarySlave = await dbGetSlaveStatus(environmentId, primaryHost);
    const replicaReadOnly = replicaHost ? await dbGetReadOnly(environmentId, replicaHost) : null;
    const replicaSlave = replicaHost ? await dbGetSlaveStatus(environmentId, replicaHost) : null;

    let targetService = dbServiceName;
    if (primaryReadOnly === false && !primarySlave) {
      targetService = dbServiceName;
    } else if (replicaHost && replicaReadOnly === false && !replicaSlave) {
      targetService = dbReplicaServiceName;
    }

    const containerId = await findServiceContainerId(targetService);
    if (!containerId && targetService !== dbServiceName) {
      // Fallback to primary service if we chose replica but cannot exec it locally.
      const fallback = await findServiceContainerId(dbServiceName);
      if (fallback) {
        dumpSource = dbServiceName;
        const dumpInner = [
          // `sh` on some distros is `dash`, which doesn't support `set -o pipefail`.
          // We don't use pipes here, so `-eu` is sufficient.
          'set -eu',
          'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
          `mariadb-dump -uroot -p\"$ROOT_PASS\" --single-transaction --quick --routines --events --triggers --hex-blob --databases ${quoteShell(
            dbName
          )}`,
        ].join(' && ');
        const dumpResult = await runCommandToFile('docker', ['exec', fallback, 'sh', '-c', dumpInner], dumpPath, 15 * 60_000);
        if (dumpResult.code !== 0) {
          const output = (dumpResult.stderr || '').trim();
          throw new Error(output ? `Database dump failed: ${output}` : 'Database dump failed.');
        }
      } else {
        throw new Error(`Database container not found on this node (service: ${targetService}).`);
      }
    } else if (!containerId) {
      throw new Error(`Database container not found on this node (service: ${targetService}).`);
    } else {
      dumpSource = targetService;
      const dumpInner = [
        // `sh` on some distros is `dash`, which doesn't support `set -o pipefail`.
        // We don't use pipes here, so `-eu` is sufficient.
        'set -eu',
        'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
        `mariadb-dump -uroot -p\"$ROOT_PASS\" --single-transaction --quick --routines --events --triggers --hex-blob --databases ${quoteShell(
          dbName
        )}`,
      ].join(' && ');
      const dumpResult = await runCommandToFile('docker', ['exec', containerId, 'sh', '-c', dumpInner], dumpPath, 15 * 60_000);
      if (dumpResult.code !== 0) {
        const output = (dumpResult.stderr || '').trim();
        throw new Error(output ? `Database dump failed: ${output}` : 'Database dump failed.');
      }
    }
    progress.ok('dump', dumpSource ? `Source: ${dumpSource}` : '');

    progress.start('compress');
    const zstdLevel = getDbBackupZstdLevel();
    const zstdResult = await runCommand('zstd', [`-${zstdLevel}`, '-f', '-o', zstPath, dumpPath], 15 * 60_000);
    if (zstdResult.code !== 0) {
      const output = (zstdResult.stderr || zstdResult.stdout || '').trim();
      throw new Error(output ? `zstd failed: ${output}` : 'zstd failed.');
    }
    progress.ok('compress');

    progress.start('encrypt');
    const ageResult = await runCommand('age', ['-R', publicKeyPath, '-o', agePath, zstPath], 2 * 60_000);
    if (ageResult.code !== 0) {
      const output = (ageResult.stderr || ageResult.stdout || '').trim();
      throw new Error(output ? `age encryption failed: ${output}` : 'age encryption failed.');
    }
    progress.ok('encrypt');

    progress.start('upload');
    await uploadArtifact(r2, backupObject, agePath);
    uploaded = true;
    actions.push(backupBucket ? `Uploaded backup to ${backupBucket}/${backupObject}` : `Uploaded backup to ${backupObject}`);
    progress.ok('upload');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    observations.push(message);
    progress.fail(progressStateForDbBackupFailure(message), message);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database backup failed.',
      observations,
      remediation: { attempted: true, actions },
      data: {
        method,
        db: { name: dbName, dump_source: dumpSource || null },
        backup_bucket: backupBucket,
        backup_object: backupObject,
      },
    };
  } finally {
    // Always try to re-enable cron and disable maintenance mode.
    progress.start('cron_resume');
    const cronUp = await scaleEnvironmentService(environmentId, 'cron', 1);
    actions.push(cronUp.ok ? 'Scaled cron service to 1' : `Failed to scale cron service: ${cronUp.note || ''}`.trim());
    progress.ok('cron_resume', cronUp.ok ? '' : 'Failed to scale cron service to 1');

    progress.start('maintenance_off');
    const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
    actions.push('Disabled Magento maintenance mode');
    observations.push(...maintenanceOff.observations.map((line) => `Maintenance: ${line}`));
    progress.ok('maintenance_off', maintenanceOff.status === 'ok' ? '' : 'Failed to disable maintenance mode');

    // Cleanup working files
    for (const filePath of [dumpPath, zstPath, agePath]) {
      try {
        if (fs.existsSync(filePath)) {
          fs.rmSync(filePath, { force: true });
        }
      } catch {
        // ignore cleanup failures
      }
    }
    try {
      if (fs.existsSync(workDir)) {
        fs.rmSync(workDir, { recursive: true, force: true });
      }
    } catch {
      // ignore cleanup failures
    }
  }

  if (uploaded) {
    progress.doneOk();
  }
  return {
    runbook_id: runbookId,
    status: uploaded ? 'ok' : 'warning',
    summary: uploaded ? 'Database backup uploaded to R2.' : 'Database backup completed with warnings.',
    observations,
    remediation: { attempted: true, actions },
    data: {
      method,
      db: { name: dbName, dump_source: dumpSource || null },
      backup_bucket: backupBucket,
      backup_object: backupObject,
    },
  };
}

function progressStateForDbBackupFailure(message: string): string {
  const lower = message.toLowerCase();
  if (lower.includes('maintenance')) return 'maintenance_on';
  if (lower.includes('cron')) return 'cron_pause';
  if (lower.includes('zstd')) return 'compress';
  if (lower.includes('age')) return 'encrypt';
  if (lower.includes('upload') || lower.includes('r2')) return 'upload';
  if (lower.includes('dump') || lower.includes('database')) return 'dump';
  return 'dump';
}

async function runDiskUsageSummary(): Promise<RunbookResult> {
  const df = await runCommand('df', ['-h', '/'], 8000);
  const dockerDf = await runCommand('docker', ['system', 'df'], 12000);

  const dfOut = (df.stdout || df.stderr || '').trim();
  const dockerOut = (dockerDf.stdout || dockerDf.stderr || '').trim();
  const usageLine = dfOut.split('\n').slice(-1)[0] || '';
  const status = usageLine.includes('100%') ? 'warning' : 'ok';

  return {
    runbook_id: 'disk_usage_summary',
    status,
    summary: 'Disk usage collected.',
    observations: [
      usageLine ? `Filesystem: ${usageLine}` : 'Filesystem usage unavailable.',
      dockerOut ? 'Docker usage included.' : 'Docker usage unavailable.',
    ],
    data: {
      df: dfOut,
      docker_system_df: dockerOut,
    },
  };
}

async function runSwarmCapacitySummary(environmentId: number): Promise<RunbookResult> {
  const nodes = await getSwarmNodeCapacities();
  const services = await listEnvironmentServices(environmentId);

  const taskIssues: string[] = [];
  let capacityIssueCount = 0;

  for (const service of services) {
    const tasks = await listServiceTasks(service.name);
    for (const task of tasks) {
      const state = String(task.current_state || '').trim();
      const error = String(task.error || '').trim();
      const stateLower = state.toLowerCase();
      const relevantState = stateLower.startsWith('pending') || stateLower.startsWith('rejected') || stateLower.startsWith('failed');
      const capacitySignal = hasCapacityPlacementSignal(`${state} ${error}`);
      if (!relevantState && !capacitySignal) {
        continue;
      }
      if (capacitySignal) {
        capacityIssueCount += 1;
      }
      if (taskIssues.length < 25) {
        const suffix = error ? ` (${error})` : '';
        taskIssues.push(`${service.name}: ${task.name} on ${task.node || '(unknown node)'}: ${state}${suffix}`);
      }
    }
  }

  const diskSummary = await runDiskUsageSummary();
  const managerUsageLine = String((diskSummary.data?.df as string || '').split('\n').slice(-1)[0] || '').trim();

  const observations: string[] = [
    `Nodes inspected: ${nodes.length}`,
    ...nodes.map((node) => {
      const cpuText = node.resources.cpu_cores !== null ? `${node.resources.cpu_cores} cores` : 'unknown CPU';
      const memoryText = node.resources.memory_gb !== null ? `${node.resources.memory_gb} GB` : 'unknown memory';
      const managerText = node.manager_status ? ` manager=${node.manager_status}` : '';
      return `${node.hostname} (${node.role}) status=${node.status}/${node.availability} resources=${cpuText}, ${memoryText}${managerText}`;
    }),
    capacityIssueCount > 0
      ? `Capacity-related task issues: ${capacityIssueCount}`
      : 'No capacity-related task issues detected.',
    managerUsageLine ? `Manager root filesystem: ${managerUsageLine}` : 'Manager root filesystem usage unavailable.',
  ];

  const status: RunbookResult['status'] = capacityIssueCount > 0
    ? 'warning'
    : nodes.length === 0
      ? 'failed'
      : 'ok';

  return {
    runbook_id: 'swarm_capacity_summary',
    status,
    summary: capacityIssueCount > 0
      ? 'Detected task placement failures consistent with capacity pressure.'
      : 'No capacity placement failures detected from current task state.',
    observations,
    data: {
      environment_id: environmentId,
      nodes,
      capacity_issue_count: capacityIssueCount,
      task_issues: taskIssues,
      manager_disk: diskSummary.data || {},
    },
  };
}

type TuningProfileType = 'tuning' | 'capacity_change';

type TuningResourceSpec = {
  limits: { cpu_cores: number; memory_bytes: number };
  reservations: { cpu_cores: number; memory_bytes: number };
};

type TuningServiceApplyResult = {
  service: string;
  service_name: string;
  status: 'updated' | 'skipped' | 'failed';
  detail: string;
  update_state?: string;
  update_message?: string;
};

function normalizeProfileType(value: unknown): TuningProfileType {
  const lower = String(value || '').trim().toLowerCase();
  if (lower === 'capacity_change') {
    return 'capacity_change';
  }
  return 'tuning';
}

function parseBooleanInput(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  const lower = String(value || '').trim().toLowerCase();
  if (!lower) return fallback;
  if (['1', 'true', 'yes', 'y', 'on'].includes(lower)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(lower)) return false;
  return fallback;
}

function shouldSkipLiveTuningApply(params: {
  profileType: TuningProfileType;
  applyNow: boolean;
  forceApply: boolean;
  capacityIssueCount: number;
}): boolean {
  if (!params.applyNow) return false;
  if (params.profileType !== 'tuning') return false;
  if (params.forceApply) return false;
  return params.capacityIssueCount <= 0;
}

function formatCpuCoresForServiceUpdate(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`invalid_cpu_cores:${value}`);
  }
  const normalized = Math.round(value * 100) / 100;
  return String(normalized);
}

function formatMemoryBytesForServiceUpdate(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    throw new Error(`invalid_memory_bytes:${bytes}`);
  }
  const MIB = 1024 * 1024;
  const GIB = 1024 * MIB;
  if (bytes % GIB === 0) {
    return `${bytes / GIB}G`;
  }
  if (bytes % MIB === 0) {
    return `${bytes / MIB}M`;
  }
  return String(Math.round(bytes));
}

function toTuningResourceSpec(value: unknown): TuningResourceSpec | null {
  if (!value || typeof value !== 'object') return null;
  const limits = (value as Record<string, unknown>).limits as Record<string, unknown> | undefined;
  const reservations = (value as Record<string, unknown>).reservations as Record<string, unknown> | undefined;
  const limitCpu = Number(limits?.cpu_cores ?? 0);
  const limitMem = Number(limits?.memory_bytes ?? 0);
  const reserveCpu = Number(reservations?.cpu_cores ?? 0);
  const reserveMem = Number(reservations?.memory_bytes ?? 0);
  if (!Number.isFinite(limitCpu) || limitCpu <= 0) return null;
  if (!Number.isFinite(limitMem) || limitMem <= 0) return null;
  if (!Number.isFinite(reserveCpu) || reserveCpu <= 0) return null;
  if (!Number.isFinite(reserveMem) || reserveMem <= 0) return null;
  return {
    limits: {
      cpu_cores: limitCpu,
      memory_bytes: Math.round(limitMem),
    },
    reservations: {
      cpu_cores: reserveCpu,
      memory_bytes: Math.round(reserveMem),
    },
  };
}

function summarizePlannerProfile(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null;
  const profile = value as Record<string, unknown>;
  const resources = (profile.resources && typeof profile.resources === 'object')
    ? (profile.resources as Record<string, unknown>)
    : null;
  const services = (resources?.services && typeof resources.services === 'object')
    ? (resources.services as Record<string, unknown>)
    : {};
  const adjustments = (profile.adjustments && typeof profile.adjustments === 'object')
    ? (profile.adjustments as Record<string, unknown>)
    : {};
  return {
    id: String(profile.id || ''),
    status: String(profile.status || ''),
    strategy: String(profile.strategy || ''),
    summary: String(profile.summary || ''),
    confidence: Number(profile.confidence || 0) || 0,
    updated_at: String(profile.updated_at || profile.created_at || ''),
    service_count: Object.keys(services).length,
    adjustment_count: Object.keys(adjustments).length,
  };
}

function summarizeCapacityChangeProfile(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null;
  const profile = value as Record<string, unknown>;
  return {
    id: String(profile.id || ''),
    status: String(profile.status || ''),
    strategy: String(profile.strategy || ''),
    change: String(profile.change || ''),
    summary: String(profile.summary || ''),
    ready: Boolean(profile.ready),
    updated_at: String(profile.updated_at || profile.created_at || ''),
  };
}

function buildSuggestedApplyInputFromPlanner(planner: Record<string, unknown>): Record<string, unknown> | null {
  const tuning = (planner.tuning && typeof planner.tuning === 'object')
    ? (planner.tuning as Record<string, unknown>)
    : {};
  const incremental = (tuning.incremental_profile && typeof tuning.incremental_profile === 'object')
    ? (tuning.incremental_profile as Record<string, unknown>)
    : null;
  const recommended = (tuning.recommended_profile && typeof tuning.recommended_profile === 'object')
    ? (tuning.recommended_profile as Record<string, unknown>)
    : null;

  const incrementalId = String(incremental?.id || '').trim();
  if (incrementalId) {
    return { profile_type: 'tuning', profile_id: incrementalId, apply_now: true };
  }
  const recommendedId = String(recommended?.id || '').trim();
  if (recommendedId) {
    return { profile_type: 'tuning', profile_id: recommendedId, apply_now: true };
  }

  const capacityChange = (planner.capacity_change && typeof planner.capacity_change === 'object')
    ? (planner.capacity_change as Record<string, unknown>)
    : {};
  const capacityRecommended = (capacityChange.recommended_profile && typeof capacityChange.recommended_profile === 'object')
    ? (capacityChange.recommended_profile as Record<string, unknown>)
    : null;
  const capacityReady = Boolean(capacityRecommended?.ready);
  const capacityId = String(capacityRecommended?.id || '').trim();
  if (capacityId && capacityReady) {
    return { profile_type: 'capacity_change', profile_id: capacityId, apply_now: false };
  }
  return null;
}

async function applyTuningResourcesToEnvironment(
  environmentId: number,
  resourcesByService: Record<string, unknown>,
): Promise<{
  updated: number;
  skipped: number;
  failed: number;
  results: TuningServiceApplyResult[];
}> {
  const services = await listEnvironmentServices(environmentId);
  const serviceNames = new Set(services.map((service) => service.name));
  const results: TuningServiceApplyResult[] = [];
  let updated = 0;
  let skipped = 0;
  let failed = 0;

  for (const [service, rawSpec] of Object.entries(resourcesByService || {})) {
    const serviceName = envServiceName(environmentId, service);
    const spec = toTuningResourceSpec(rawSpec);
    if (!spec) {
      skipped += 1;
      results.push({
        service,
        service_name: serviceName,
        status: 'skipped',
        detail: 'Skipped: invalid or missing resource spec.',
      });
      continue;
    }
    if (!serviceNames.has(serviceName)) {
      skipped += 1;
      results.push({
        service,
        service_name: serviceName,
        status: 'skipped',
        detail: 'Skipped: service is not present in this environment.',
      });
      continue;
    }

    const args = [
      'service',
      'update',
      '--limit-cpu',
      formatCpuCoresForServiceUpdate(spec.limits.cpu_cores),
      '--limit-memory',
      formatMemoryBytesForServiceUpdate(spec.limits.memory_bytes),
      '--reserve-cpu',
      formatCpuCoresForServiceUpdate(spec.reservations.cpu_cores),
      '--reserve-memory',
      formatMemoryBytesForServiceUpdate(spec.reservations.memory_bytes),
      serviceName,
    ];
    const updatedResult = await runCommand('docker', args, 45_000);
    if (updatedResult.code !== 0) {
      failed += 1;
      results.push({
        service,
        service_name: serviceName,
        status: 'failed',
        detail: updatedResult.stderr.trim() || updatedResult.stdout.trim() || 'docker service update failed',
      });
      continue;
    }

    updated += 1;
    const updateState = await inspectServiceUpdateStatus(serviceName);
    results.push({
      service,
      service_name: serviceName,
      status: 'updated',
      detail: 'Service resource update triggered.',
      update_state: updateState?.state || '',
      update_message: updateState?.message || '',
    });
  }

  return { updated, skipped, failed, results };
}

async function runSwarmTuningProfileSummary(environmentId: number): Promise<RunbookResult> {
  let planner: Record<string, unknown>;
  try {
    planner = await buildPlannerPayload() as unknown as Record<string, unknown>;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      runbook_id: 'swarm_tuning_profile_summary',
      status: 'failed',
      summary: 'Unable to build planner payload for tuning recommendations.',
      observations: [message || 'Planner payload generation failed.'],
      data: { environment_id: environmentId },
    };
  }

  const tuning = (planner.tuning && typeof planner.tuning === 'object')
    ? (planner.tuning as Record<string, unknown>)
    : {};
  const capacityChange = (planner.capacity_change && typeof planner.capacity_change === 'object')
    ? (planner.capacity_change as Record<string, unknown>)
    : {};

  const activeProfileId = String(tuning.active_profile_id || '').trim();
  const baseProfile = summarizePlannerProfile(tuning.base_profile);
  const recommendedProfile = summarizePlannerProfile(tuning.recommended_profile);
  const incrementalProfile = summarizePlannerProfile(tuning.incremental_profile);
  const capacityRecommended = summarizeCapacityChangeProfile(capacityChange.recommended_profile);
  const suggestedApplyInput = buildSuggestedApplyInputFromPlanner(planner);

  const observations: string[] = [
    activeProfileId
      ? `Active tuning profile: ${activeProfileId}`
      : 'Active tuning profile: base',
    recommendedProfile
      ? `Recommended tuning profile: ${String(recommendedProfile.id || '')} (${String(recommendedProfile.summary || 'no summary')})`
      : 'No recommended tuning profile currently available.',
    incrementalProfile
      ? `Incremental tuning profile: ${String(incrementalProfile.id || '')} (${String(incrementalProfile.summary || 'no summary')})`
      : 'No incremental tuning profile currently available.',
    capacityRecommended
      ? `Capacity change recommendation: ${String(capacityRecommended.id || '')} (${String(capacityRecommended.summary || 'no summary')})`
      : 'No capacity change recommendation currently available.',
    suggestedApplyInput
      ? `Suggested apply input: ${JSON.stringify(suggestedApplyInput)}`
      : 'No apply-ready profile suggestion at this time.',
  ];

  return {
    runbook_id: 'swarm_tuning_profile_summary',
    status: suggestedApplyInput ? 'warning' : 'ok',
    summary: suggestedApplyInput
      ? 'Tuning/capacity profile proposal available for approval and apply.'
      : 'No apply-ready tuning or capacity-change profile currently available.',
    observations,
    data: {
      environment_id: environmentId,
      tuning: {
        active_profile_id: activeProfileId || String(baseProfile?.id || 'base'),
        base_profile: baseProfile,
        recommended_profile: recommendedProfile,
        incremental_profile: incrementalProfile,
      },
      capacity_change: {
        recommended_profile: capacityRecommended,
      },
      suggested_apply_input: suggestedApplyInput,
    },
  };
}

async function runSwarmTuningProfileApply(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const rawType = String(input.profile_type || '').trim().toLowerCase();
  const explicitType = rawType === 'tuning' || rawType === 'capacity_change';
  let profileType: TuningProfileType = normalizeProfileType(rawType);
  let profileId = String(input.profile_id || '').trim();

  let suggestedInput: Record<string, unknown> | null = null;
  if (!profileId) {
    try {
      const planner = await buildPlannerPayload() as unknown as Record<string, unknown>;
      suggestedInput = buildSuggestedApplyInputFromPlanner(planner);
      if (!explicitType && suggestedInput?.profile_type) {
        profileType = normalizeProfileType(suggestedInput.profile_type);
      }
      if (suggestedInput && (!explicitType || normalizeProfileType(suggestedInput.profile_type) === profileType)) {
        profileId = String(suggestedInput.profile_id || '').trim();
      }
    } catch {
      // Ignore planner errors here; we'll fail with missing profile_id below.
    }
  }

  if (!profileId) {
    return {
      runbook_id: 'swarm_tuning_profile_apply',
      status: 'failed',
      summary: 'Missing profile_id and no apply-ready profile was found.',
      observations: [
        'Run swarm_tuning_profile_summary first to get suggested_apply_input.',
      ],
      data: {
        environment_id: environmentId,
        profile_type: profileType,
        suggested_apply_input: suggestedInput,
      },
    };
  }

  const applyNowDefault = profileType === 'tuning';
  const applyNow = parseBooleanInput(input.apply_now, applyNowDefault);
  const forceApply = parseBooleanInput(input.force_apply, false);
  const approval = approveTuningProfile(profileId, profileType);
  if (approval.status !== 200) {
    const detail = JSON.stringify(approval.body || {});
    return {
      runbook_id: 'swarm_tuning_profile_apply',
      status: approval.status === 409 ? 'warning' : 'failed',
      summary: `Unable to approve ${profileType} profile ${profileId}.`,
      observations: [
        `Approval status: ${approval.status}`,
        detail,
      ],
      data: {
        environment_id: environmentId,
        profile_type: profileType,
        profile_id: profileId,
        approval: approval.body,
      },
    };
  }

  if (profileType === 'capacity_change') {
    return {
      runbook_id: 'swarm_tuning_profile_apply',
      status: 'ok',
      summary: `Approved capacity change profile ${profileId}.`,
      observations: [
        'Capacity change approval was recorded.',
        'Capacity change execution (node add/remove) is handled by provisioning workflows.',
      ],
      data: {
        environment_id: environmentId,
        profile_type: profileType,
        profile_id: profileId,
        apply_now: false,
        approval: approval.body,
      },
      remediation: {
        attempted: true,
        actions: [`Approved capacity_change profile ${profileId}`],
      },
    };
  }

  if (!applyNow) {
    return {
      runbook_id: 'swarm_tuning_profile_apply',
      status: 'ok',
      summary: `Approved tuning profile ${profileId}.`,
      observations: [
        'Profile approved and set as active for subsequent deploys.',
        'apply_now=false: no live service updates were executed.',
      ],
      data: {
        environment_id: environmentId,
        profile_type: profileType,
        profile_id: profileId,
        apply_now: false,
        force_apply: forceApply,
        approval: approval.body,
      },
      remediation: {
        attempted: true,
        actions: [`Approved tuning profile ${profileId}`],
      },
    };
  }

  const capacitySummary = await runSwarmCapacitySummary(environmentId);
  const capacityIssueCountRaw = Number((capacitySummary.data as Record<string, unknown> | undefined)?.capacity_issue_count || 0);
  const capacityIssueCount = Number.isFinite(capacityIssueCountRaw) ? capacityIssueCountRaw : 0;
  if (shouldSkipLiveTuningApply({
    profileType,
    applyNow,
    forceApply,
    capacityIssueCount,
  })) {
    return {
      runbook_id: 'swarm_tuning_profile_apply',
      status: 'warning',
      summary: `Approved tuning profile ${profileId}, but skipped live apply (no capacity pressure detected).`,
      observations: [
        `Capacity issues detected: ${capacityIssueCount}`,
        'force_apply=false: skipping live service updates to avoid unnecessary rollout churn.',
      ],
      data: {
        environment_id: environmentId,
        profile_type: profileType,
        profile_id: profileId,
        apply_now: false,
        force_apply: false,
        approval: approval.body,
        capacity_precheck: {
          status: capacitySummary.status,
          summary: capacitySummary.summary,
          capacity_issue_count: capacityIssueCount,
        },
        skipped_apply_reason: 'no_capacity_pressure',
      },
      remediation: {
        attempted: true,
        actions: [`Approved tuning profile ${profileId}`],
      },
    };
  }

  const approvedProfile = (approval.body.approved_profile && typeof approval.body.approved_profile === 'object')
    ? (approval.body.approved_profile as Record<string, unknown>)
    : {};
  const approvedResources = (approvedProfile.resources && typeof approvedProfile.resources === 'object')
    ? (approvedProfile.resources as Record<string, unknown>)
    : {};
  const resourcesByService = (approvedResources.services && typeof approvedResources.services === 'object')
    ? (approvedResources.services as Record<string, unknown>)
    : {};

  const applyResult = await applyTuningResourcesToEnvironment(environmentId, resourcesByService);
  const status: RunbookResult['status'] = applyResult.failed > 0
    ? (applyResult.updated > 0 ? 'warning' : 'failed')
    : (applyResult.updated > 0 ? 'ok' : 'warning');

  const observations: string[] = [
    `Services updated: ${applyResult.updated}`,
    `Services skipped: ${applyResult.skipped}`,
    `Services failed: ${applyResult.failed}`,
    ...applyResult.results.slice(0, 30).map((entry) => {
      const statePart = entry.update_state ? ` update=${entry.update_state}` : '';
      const msgPart = entry.update_message ? ` (${entry.update_message})` : '';
      return `${entry.service_name}: ${entry.status}${statePart} - ${entry.detail}${msgPart}`;
    }),
  ];

  return {
    runbook_id: 'swarm_tuning_profile_apply',
    status,
    summary: `Approved tuning profile ${profileId} and applied live service updates.`,
    observations,
    data: {
      environment_id: environmentId,
      profile_type: profileType,
      profile_id: profileId,
      apply_now: true,
      force_apply: forceApply,
      approval: approval.body,
      capacity_precheck: {
        status: capacitySummary.status,
        summary: capacitySummary.summary,
        capacity_issue_count: capacityIssueCount,
      },
      apply_result: applyResult,
    },
    remediation: {
      attempted: true,
      actions: [
        `Approved tuning profile ${profileId}`,
        `Applied resource updates to ${applyResult.updated} services`,
      ],
    },
  };
}

async function runDbReplicationStatus(environmentId: number): Promise<RunbookResult> {
  const observations: string[] = [];
  const data: Record<string, unknown> = {};

  const primaryNode = await getServiceTaskNode(environmentId, 'database');
  const replicaNode = await getServiceTaskNode(environmentId, 'database-replica');
  if (primaryNode) observations.push(`Primary node: ${primaryNode}`);
  if (replicaNode) observations.push(`Replica node: ${replicaNode}`);
  if (primaryNode && replicaNode && primaryNode === replicaNode) {
    observations.push('Warning: primary and replica are co-located on the same node.');
  }

  // Run a short-lived Swarm job that connects over the overlay network so we can diagnose
  // even when containers are placed on other nodes.
  const job = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(environmentId), { timeout_ms: 60_000 });
  data.probe_job = { ok: job.ok, state: job.state };
  if (!job.ok) {
    observations.push(`Probe failed: ${job.error || job.state}`);
    if (job.details?.length) observations.push(`Probe task: ${job.details[0]}`);
    return {
      runbook_id: 'db_replication_status',
      status: 'failed',
      summary: 'Unable to probe DB replication over network.',
      observations,
      data,
    };
  }

  const probe = parseDbReplicationProbe(job.logs);
  if (!probe) {
    observations.push('Probe returned no parseable output.');
    return {
      runbook_id: 'db_replication_status',
      status: 'failed',
      summary: 'DB probe did not return usable data.',
      observations,
      data,
    };
  }
  data.probe = probe;

  const primaryReadOnly = probe.primary.read_only;
  const primarySlave = probe.primary.slave_status;
  observations.push(`Primary read_only: ${primaryReadOnly === null ? 'unknown' : primaryReadOnly ? 'ON' : 'OFF'}`);
  observations.push(`Primary replication: ${primarySlave ? 'configured' : 'not configured'}`);
  if (probe.primary.gtid_binlog_pos) observations.push(`Primary gtid_binlog_pos: ${probe.primary.gtid_binlog_pos}`);
  if (probe.primary.gtid_current_pos) observations.push(`Primary gtid_current_pos: ${probe.primary.gtid_current_pos}`);
  if (probe.primary.magento_table_count !== null) observations.push(`Primary magento tables: ${probe.primary.magento_table_count}`);

  const replicaReadOnly = probe.replica.read_only;
  const replicaSlave = probe.replica.slave_status;
  observations.push(`Replica read_only: ${replicaReadOnly === null ? 'unknown' : replicaReadOnly ? 'ON' : 'OFF'}`);
  observations.push(`Replica replication: ${replicaSlave ? 'configured' : 'not configured'}`);
  if (probe.replica.gtid_slave_pos) observations.push(`Replica gtid_slave_pos: ${probe.replica.gtid_slave_pos}`);
  if (probe.replica.gtid_current_pos) observations.push(`Replica gtid_current_pos: ${probe.replica.gtid_current_pos}`);
  if (probe.replica.magento_table_count !== null) observations.push(`Replica magento tables: ${probe.replica.magento_table_count}`);

  const ioRunning = (replicaSlave?.Slave_IO_Running || '').toLowerCase();
  const sqlRunning = (replicaSlave?.Slave_SQL_Running || '').toLowerCase();
  const lagRaw = replicaSlave?.Seconds_Behind_Master ?? '';
  const lagSeconds = lagRaw === '' || String(lagRaw).toUpperCase() === 'NULL'
    ? null
    : Number.parseInt(String(lagRaw), 10);
  if (replicaSlave) {
    observations.push(`Replica threads: IO=${replicaSlave.Slave_IO_Running || '(unknown)'} SQL=${replicaSlave.Slave_SQL_Running || '(unknown)'}`);
    observations.push(`Replica lag: ${lagSeconds === null ? '(unknown)' : `${lagSeconds}s`}`);
    const lastSql = (replicaSlave.Last_SQL_Error || '').trim();
    const lastIo = (replicaSlave.Last_IO_Error || '').trim();
    if (lastSql) observations.push(`Replica Last_SQL_Error: ${lastSql}`);
    if (lastIo) observations.push(`Replica Last_IO_Error: ${lastIo}`);
  }

  const lastSqlErrno = (replicaSlave?.Last_SQL_Errno || '').trim();
  const lastSqlErrorLower = (replicaSlave?.Last_SQL_Error || '').toLowerCase();
  const hasOutOfOrderGtid =
    lastSqlErrno === '1950' ||
    lastSqlErrorLower.includes('out-of-order') ||
    lastSqlErrorLower.includes('gtid strict mode');
  if (hasOutOfOrderGtid) {
    data.recommended_fix = {
      runbook_id: 'db_replica_reseed',
      reason: 'gtid_out_of_order',
    };
    observations.push('Recommended fix: db_replica_reseed (destructive; wipes replica data). db_replica_repair is unlikely to fix GTID out-of-order under gtid_strict_mode.');
  }

  const writer = (primaryReadOnly === false && !primarySlave)
    ? 'database'
    : (replicaReadOnly === false && !replicaSlave)
      ? 'database-replica'
      : '(unknown)';
  observations.push(`Writer (best-effort): ${writer}`);

  const replicaHealthy = Boolean(replicaSlave) && ioRunning === 'yes' && sqlRunning === 'yes';
  const status = writer === '(unknown)' || !replicaHealthy ? 'warning' : 'ok';
  const summary = replicaSlave
    ? `DB topology: writer=${writer}, replica=${replicaHealthy ? 'healthy' : 'broken'}`
    : `DB topology: writer=${writer}, replica=missing`;

  return {
    runbook_id: 'db_replication_status',
    status,
    summary,
    observations,
    data,
  };
}

async function runDbReplicaEnable(environmentId: number): Promise<RunbookResult> {
  const actions: string[] = [];
  const observations: string[] = [];

  const nodes = await getNodeLabels();
  const ready = nodes.filter(
    (node) => node.status.toLowerCase() === 'ready' && node.availability.toLowerCase() === 'active',
  );
  if (ready.length < 2) {
    return {
      runbook_id: 'db_replica_enable',
      status: 'failed',
      summary: 'Replica requires at least 2 ready nodes.',
      observations: [`Ready nodes: ${ready.length}`],
      remediation: { attempted: false, actions: [] },
      data: { ready_nodes: ready.map((n) => ({ id: n.id, hostname: n.hostname })) },
    };
  }

  const dbNode = ready.find((node) => node.labels.database === 'true') || null;
  if (!dbNode) {
    return {
      runbook_id: 'db_replica_enable',
      status: 'failed',
      summary: 'No database=true node label found.',
      observations: ['Database placement requires one node labelled database=true.'],
      remediation: { attempted: false, actions: [] },
      data: { nodes: ready.map((n) => ({ id: n.id, hostname: n.hostname, labels: n.labels })) },
    };
  }

  const existingReplicaNode = ready.find((node) => node.labels.database_replica === 'true') || null;
  let targetReplicaNode = existingReplicaNode;

  if (!targetReplicaNode || targetReplicaNode.id === dbNode.id) {
    const candidates = ready.filter((node) => node.id !== dbNode.id);
    // Prefer a worker node for replica placement.
    targetReplicaNode = candidates.find((node) => node.role === 'worker') || candidates[0] || null;
  }

  if (!targetReplicaNode) {
    return {
      runbook_id: 'db_replica_enable',
      status: 'failed',
      summary: 'Unable to choose a replica node.',
      observations: ['No suitable node available for database_replica=true.'],
      remediation: { attempted: false, actions: [] },
    };
  }

  if (existingReplicaNode && existingReplicaNode.id !== targetReplicaNode.id) {
    const removed = await updateNodeLabel(existingReplicaNode.id, 'database_replica', null);
    actions.push(removed
      ? `Removed database_replica label from ${existingReplicaNode.hostname || existingReplicaNode.id}`
      : `Failed to remove database_replica label from ${existingReplicaNode.hostname || existingReplicaNode.id}`);
  }
  if (!existingReplicaNode || existingReplicaNode.id !== targetReplicaNode.id) {
    const added = await updateNodeLabel(targetReplicaNode.id, 'database_replica', 'true');
    actions.push(added
      ? `Set database_replica=true on ${targetReplicaNode.hostname || targetReplicaNode.id}`
      : `Failed to set database_replica=true on ${targetReplicaNode.hostname || targetReplicaNode.id}`);
  }

  // Ensure the replica service is running (deploy may have set replicas=0 when no label existed).
  const scale = await scaleEnvironmentService(environmentId, 'database-replica', 1);
  actions.push(scale.ok ? 'Scaled database-replica service to 1' : `Failed to scale database-replica: ${scale.note || ''}`.trim());

  const primaryNode = await getServiceTaskNode(environmentId, 'database');
  const replicaNode = await getServiceTaskNode(environmentId, 'database-replica');
  if (primaryNode) observations.push(`Primary node: ${primaryNode}`);
  if (replicaNode) observations.push(`Replica node: ${replicaNode}`);
  if (primaryNode && replicaNode && primaryNode === replicaNode) {
    observations.push('Warning: primary and replica are still co-located; check node labels.');
  }

  const replicaService = `mz-env-${environmentId}_database-replica`;
  const running = await waitForServiceRunning(replicaService, 5 * 60_000);
  if (!running.ok) {
    return {
      runbook_id: 'db_replica_enable',
      status: 'failed',
      summary: 'Replica service did not start.',
      observations: [...observations, `Replica state: ${running.state || ''} ${running.note || ''}`.trim()],
      remediation: { attempted: true, actions },
    };
  }

  // Probe current status and decide next steps.
  const beforeJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(environmentId), { timeout_ms: 60_000 });
  const before = beforeJob.ok ? parseDbReplicationProbe(beforeJob.logs) : null;
  const beforeSlave = before?.replica.slave_status || null;
  const beforeIo = (beforeSlave?.Slave_IO_Running || '').toLowerCase();
  const beforeSql = (beforeSlave?.Slave_SQL_Running || '').toLowerCase();
  const beforeErrno = (beforeSlave?.Last_SQL_Errno || '').trim();
  const beforeErr = (beforeSlave?.Last_SQL_Error || '').toLowerCase();
  const hasOutOfOrderGtid =
    beforeErrno === '1950' ||
    beforeErr.includes('out-of-order') ||
    beforeErr.includes('gtid strict mode');

  if (before) {
    observations.push(`Replica magento tables: ${before.replica.magento_table_count === null ? 'unknown' : before.replica.magento_table_count}`);
    if (beforeSlave) {
      observations.push(`Replica threads: IO=${beforeSlave.Slave_IO_Running || '(unknown)'} SQL=${beforeSlave.Slave_SQL_Running || '(unknown)'}`);
      const lastSql = (beforeSlave.Last_SQL_Error || '').trim();
      if (lastSql) observations.push(`Replica Last_SQL_Error: ${lastSql}`);
    } else {
      observations.push('Replica slave status: not configured.');
    }
  } else if (!beforeJob.ok) {
    observations.push(`Replica probe failed: ${beforeJob.error || beforeJob.state}`);
  }

  // If replication is blocked by GTID strict-mode ordering, recommend reseed.
  if (hasOutOfOrderGtid) {
    observations.push('Replica is blocked by GTID strict-mode ordering; use db_replica_reseed.');
    return {
      runbook_id: 'db_replica_enable',
      status: 'warning',
      summary: 'Replica placement enabled but replica requires reseed.',
      observations,
      remediation: { attempted: true, actions },
      data: {
        db_node: dbNode.hostname || dbNode.id,
        replica_node: targetReplicaNode.hostname || targetReplicaNode.id,
        primary_task_node: primaryNode,
        replica_task_node: replicaNode,
      },
    };
  }

  // Best-effort: ensure replication is configured and read_only is ON.
  const primaryHost = `mz-env-${environmentId}_database`;
  const replicaHost = `mz-env-${environmentId}_database-replica`;
  const passRef = '${REPL_PASS}';
  const ensureReplicaUserSql = [
    `CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    `ALTER USER 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';",
    'FLUSH PRIVILEGES;',
  ].join(' ');
  const changeMasterSql = `CHANGE MASTER TO MASTER_HOST='${primaryHost}', MASTER_PORT=3306, MASTER_USER='replica', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;

  if (!beforeSlave || beforeIo !== 'yes' || beforeSql !== 'yes') {
    const configScript = [
      'set -e',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
      `i=0; until mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "primary not ready" >&2; exit 1; fi; sleep 1; done`,
      `i=0; until mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done`,
      `mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "${escapeForShellDoubleQuotes(ensureReplicaUserSql)}"`,
      // Grant SLAVE MONITOR so ProxySQL monitor can run SHOW SLAVE STATUS to check replication lag.
      `mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "GRANT SLAVE MONITOR ON *.* TO 'magento'@'%';"`,
      `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "${escapeForShellDoubleQuotes(changeMasterSql)}"`,
      `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "SET GLOBAL read_only=1;" || true`,
      'echo "CONFIGURED=1"',
    ].join(' && ');
    const configJob = await runDatabaseJob(environmentId, 'db-enable', configScript, { include_replication_secret: true, timeout_ms: 120_000 });
    actions.push(configJob.ok ? 'Configured replication on database-replica' : 'Failed to configure replication on database-replica');
    if (!configJob.ok) {
      observations.push(`Configuration job failed: ${configJob.error || configJob.state}`);
    }
  }

  const afterJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(environmentId), { timeout_ms: 60_000 });
  const after = afterJob.ok ? parseDbReplicationProbe(afterJob.logs) : null;
  const afterSlave = after?.replica.slave_status || null;
  const afterIo = (afterSlave?.Slave_IO_Running || '').toLowerCase();
  const afterSql = (afterSlave?.Slave_SQL_Running || '').toLowerCase();
  const lagRaw = afterSlave?.Seconds_Behind_Master ?? '';
  const lagSeconds = lagRaw === '' || String(lagRaw).toUpperCase() === 'NULL'
    ? null
    : Number.parseInt(String(lagRaw), 10);
  if (afterSlave) {
    observations.push(`Replica lag: ${lagSeconds === null ? '(unknown)' : `${lagSeconds}s`}`);
  }

  const ok = Boolean(afterSlave) && afterIo === 'yes' && afterSql === 'yes' && (!primaryNode || !replicaNode || primaryNode !== replicaNode);
  return {
    runbook_id: 'db_replica_enable',
    status: ok ? 'ok' : 'warning',
    summary: ok ? 'Replica placement enabled.' : 'Replica placement partially configured.',
    observations,
    remediation: { attempted: true, actions },
    data: {
      db_node: dbNode.hostname || dbNode.id,
      replica_node: targetReplicaNode.hostname || targetReplicaNode.id,
      primary_task_node: primaryNode,
      replica_task_node: replicaNode,
      replica_lag_seconds: lagSeconds,
    },
  };
}

async function runDbReplicaRepair(environmentId: number): Promise<RunbookResult> {
  const actions: string[] = [];
  const observations: string[] = [];
  const data: Record<string, unknown> = {};

  const primaryNode = await getServiceTaskNode(environmentId, 'database');
  const replicaNode = await getServiceTaskNode(environmentId, 'database-replica');
  if (primaryNode) observations.push(`Primary node: ${primaryNode}`);
  if (replicaNode) observations.push(`Replica node: ${replicaNode}`);
  if (primaryNode && replicaNode && primaryNode === replicaNode) {
    observations.push('Warning: primary and replica are co-located on the same node.');
  }

  // Initial probe.
  const probeJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(environmentId), { timeout_ms: 60_000 });
  data.before_probe_job = { ok: probeJob.ok, state: probeJob.state };
  if (!probeJob.ok) {
    observations.push(`Probe failed: ${probeJob.error || probeJob.state}`);
    return {
      runbook_id: 'db_replica_repair',
      status: 'failed',
      summary: 'Unable to probe replica status.',
      observations,
      data,
      remediation: { attempted: false, actions: [] },
    };
  }

  const before = parseDbReplicationProbe(probeJob.logs);
  if (!before) {
    observations.push('Probe returned no parseable output.');
    return {
      runbook_id: 'db_replica_repair',
      status: 'failed',
      summary: 'Replica probe did not return usable data.',
      observations,
      data,
      remediation: { attempted: false, actions: [] },
    };
  }
  data.before = before;

  const replicaSlave = before.replica.slave_status;
  const replicaIoRunning = (replicaSlave?.Slave_IO_Running || '').toLowerCase();
  const replicaSqlRunning = (replicaSlave?.Slave_SQL_Running || '').toLowerCase();
  const lastSqlErrno = (replicaSlave?.Last_SQL_Errno || '').trim();
  const lastSqlError = (replicaSlave?.Last_SQL_Error || '').toLowerCase();
  const hasOutOfOrderGtid =
    lastSqlErrno === '1950' ||
    lastSqlError.includes('out-of-order') ||
    lastSqlError.includes('gtid strict mode');

  if (replicaSlave && replicaIoRunning === 'yes' && replicaSqlRunning === 'yes') {
    observations.push('Replica replication: IO and SQL threads running.');
    return {
      runbook_id: 'db_replica_repair',
      status: 'ok',
      summary: 'Replica is running and replication looks healthy. No repair needed.',
      observations,
      data,
      remediation: { attempted: false, actions: [] },
    };
  }

  // If the replica is unseeded (no Magento tables) and stuck on a GTID strict-mode error,
  // changing master/RESET SLAVE will not fix it; it needs a reseed snapshot first.
  if (hasOutOfOrderGtid) {
    const tables = before.replica.magento_table_count;
    if (tables === 0) {
      observations.push('Replica appears unseeded (0 Magento tables) and is blocked by GTID strict-mode ordering.');
    } else if (tables !== null) {
      observations.push(`Replica has ${tables} Magento tables but is blocked by GTID strict-mode ordering.`);
    } else {
      observations.push('Replica is blocked by GTID strict-mode ordering.');
    }
    observations.push('db_replica_repair is unlikely to resolve GTID out-of-order under gtid_strict_mode; use db_replica_reseed to rebuild the replica from a fresh snapshot of the primary.');
    return {
      runbook_id: 'db_replica_repair',
      status: 'failed',
      summary: 'Replica requires reseed (GTID out-of-order).',
      observations,
      data,
      remediation: { attempted: false, actions: [] },
    };
  }

  // Attempt a non-destructive repair: ensure replication user, then reset + configure replication on replica.
  const primaryHost = `mz-env-${environmentId}_database`;
  const replicaHost = `mz-env-${environmentId}_database-replica`;
  const passRef = '${REPL_PASS}';
  const ensureReplicaUserSql = [
    `CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    `ALTER USER 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';",
    'FLUSH PRIVILEGES;',
  ].join(' ');
  const changeMasterSql = `CHANGE MASTER TO MASTER_HOST='${primaryHost}', MASTER_PORT=3306, MASTER_USER='replica', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;

  const repairScript = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
    `i=0; until mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "primary not ready" >&2; exit 1; fi; sleep 1; done`,
    `i=0; until mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done`,
    `mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "${escapeForShellDoubleQuotes(ensureReplicaUserSql)}"`,
    // Grant SLAVE MONITOR so ProxySQL monitor can run SHOW SLAVE STATUS to check replication lag.
    `mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "GRANT SLAVE MONITOR ON *.* TO 'magento'@'%';"`,
    `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "STOP SLAVE; RESET SLAVE ALL;" || true`,
    `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "${escapeForShellDoubleQuotes(changeMasterSql)}"`,
    `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "SET GLOBAL read_only=1;" || true`,
    'echo "REPAIR_ATTEMPTED=1"',
  ].join(' && ');

  const repairJob = await runDatabaseJob(environmentId, 'db-repair', repairScript, { include_replication_secret: true, timeout_ms: 120_000 });
  actions.push('Reset and reconfigured replication on database-replica');
  data.repair_job = { ok: repairJob.ok, state: repairJob.state };
  if (!repairJob.ok) {
    observations.push(`Repair job failed: ${repairJob.error || repairJob.state}`);
    if (repairJob.details?.length) observations.push(`Repair task: ${repairJob.details[0]}`);
    return {
      runbook_id: 'db_replica_repair',
      status: 'warning',
      summary: 'Replica repair attempted but job failed.',
      observations,
      data,
      remediation: { attempted: true, actions },
    };
  }

  // Probe after repair.
  const afterJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(environmentId), { timeout_ms: 60_000 });
  data.after_probe_job = { ok: afterJob.ok, state: afterJob.state };
  const after = afterJob.ok ? parseDbReplicationProbe(afterJob.logs) : null;
  if (after) data.after = after;

  const afterSlave = after?.replica.slave_status || null;
  const afterIo = (afterSlave?.Slave_IO_Running || '').toLowerCase();
  const afterSql = (afterSlave?.Slave_SQL_Running || '').toLowerCase();
  const repairedOk = Boolean(afterSlave) && afterIo === 'yes' && afterSql === 'yes';
  if (afterSlave) {
    observations.push(`Replica threads: IO=${afterSlave.Slave_IO_Running || '(unknown)'} SQL=${afterSlave.Slave_SQL_Running || '(unknown)'}`);
    const lastSql = (afterSlave.Last_SQL_Error || '').trim();
    if (lastSql) observations.push(`Replica Last_SQL_Error: ${lastSql}`);
  } else if (!afterJob.ok) {
    observations.push('Post-repair probe failed.');
  } else {
    observations.push('Post-repair probe did not return slave status.');
  }

  return {
    runbook_id: 'db_replica_repair',
    status: repairedOk ? 'ok' : 'warning',
    summary: repairedOk ? 'Replica replication repaired.' : 'Replica repair attempted but replica is still unhealthy.',
    observations,
    data,
    remediation: { attempted: true, actions },
  };
}

async function runDbReplicaReseed(environmentId: number): Promise<RunbookResult> {
  const actions: string[] = [];
  const observations: string[] = [];
  const data: Record<string, unknown> = {};

  const primaryService = `mz-env-${environmentId}_database`;
  const replicaService = `mz-env-${environmentId}_database-replica`;
  const replicaSpec = await inspectServiceSpec(replicaService);
  if (!replicaSpec) {
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Replica service not found.',
      observations: [`Missing service: ${replicaService}`],
      remediation: { attempted: false, actions: [] },
    };
  }

  // Best-effort node placement notes.
  const primaryNode = await getServiceTaskNode(environmentId, 'database');
  const replicaTaskNode = await getServiceTaskNode(environmentId, 'database-replica');
  if (primaryNode) observations.push(`Primary node: ${primaryNode}`);
  if (replicaTaskNode) observations.push(`Replica node: ${replicaTaskNode}`);

  // If the replica is currently scaled to 0, try to infer the intended node via labels.
  let replicaNode = replicaTaskNode;
  if (!replicaNode) {
    const nodes = await getNodeLabels();
    replicaNode = nodes.find((node) => node.labels.database_replica === 'true')?.hostname || null;
    if (replicaNode) {
      observations.push(`Replica node (from database_replica label): ${replicaNode}`);
    }
  }

  if (!replicaNode) {
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Unable to resolve replica node.',
      observations: [...observations, 'No running replica task and no database_replica=true node label found.'],
      remediation: { attempted: false, actions: [] },
    };
  }

  const replicaDataMount = replicaSpec.mounts.find((mount) => mount.target === '/var/lib/mysql' && mount.type === 'volume') || null;
  if (!replicaDataMount) {
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Replica data volume not found.',
      observations: [...observations, 'database-replica service has no /var/lib/mysql volume mount.'],
      remediation: { attempted: false, actions: [] },
    };
  }

  observations.push('Warning: this runbook wipes the replica data volume and rebuilds it from primary.');

  // Stop replica service to release the volume.
  const scaleDown = await scaleEnvironmentService(environmentId, 'database-replica', 0);
  actions.push(scaleDown.ok ? 'Scaled database-replica service to 0' : `Failed to scale database-replica to 0: ${scaleDown.note || ''}`.trim());
  if (!scaleDown.ok) {
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Failed to scale replica down.',
      observations,
      remediation: { attempted: true, actions },
    };
  }

  const drained = await waitForServiceNotRunning(replicaService, 180_000);
  if (!drained.ok) {
    observations.push(`Replica service did not stop cleanly: ${drained.note || ''}`.trim());
  }

  // Wipe the replica volume on the node where it lives.
  const wipeJob = await runSwarmJob({
    name: buildJobName('db-wipe', environmentId),
    image: replicaSpec.image,
    constraints: [`node.hostname==${replicaNode}`],
    mounts: [{ type: 'volume', source: replicaDataMount.source, target: '/var/lib/mysql' }],
    command: [
      'sh',
      '-lc',
      'set -e; rm -rf /var/lib/mysql/* /var/lib/mysql/.[!.]* /var/lib/mysql/..?*; echo "WIPED=1"',
    ],
    timeout_ms: 10 * 60_000,
  });
  data.wipe_job = { ok: wipeJob.ok, state: wipeJob.state };
  actions.push(wipeJob.ok ? `Wiped replica volume (${replicaDataMount.source}) on ${replicaNode}` : `Failed to wipe replica volume on ${replicaNode}`);
  if (!wipeJob.ok) {
    observations.push(`Wipe job failed: ${wipeJob.error || wipeJob.state}`);
    if (wipeJob.details?.length) observations.push(`Wipe task: ${wipeJob.details[0]}`);
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Replica volume wipe failed.',
      observations,
      data,
      remediation: { attempted: true, actions },
    };
  }

  // Restart replica service.
  const scaleUp = await scaleEnvironmentService(environmentId, 'database-replica', 1);
  actions.push(scaleUp.ok ? 'Scaled database-replica service to 1' : `Failed to scale database-replica to 1: ${scaleUp.note || ''}`.trim());
  if (!scaleUp.ok) {
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Failed to scale replica up.',
      observations,
      data,
      remediation: { attempted: true, actions },
    };
  }

  const running = await waitForServiceRunning(replicaService, 5 * 60_000);
  if (!running.ok) {
    observations.push(`Replica service did not reach Running: ${running.state || ''} ${running.note || ''}`.trim());
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Replica did not start after wipe.',
      observations,
      data,
      remediation: { attempted: true, actions },
    };
  }

  // Seed replica via logical snapshot with GTID position; import with sql_log_bin=0 so we don't generate local GTIDs.
  const primaryHost = `mz-env-${environmentId}_database`;
  const replicaHost = `mz-env-${environmentId}_database-replica`;
  const passRef = '${REPL_PASS}';
  const ensureReplicaUserSql = [
    `CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    `ALTER USER 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';",
    'FLUSH PRIVILEGES;',
  ].join(' ');
  const changeMasterSql = `CHANGE MASTER TO MASTER_HOST='${primaryHost}', MASTER_PORT=3306, MASTER_USER='replica', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;

  const seedScript = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
    // Wait for primary + replica to accept connections.
    `i=0; until mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 60 ]; then echo "primary not ready" >&2; exit 1; fi; sleep 1; done`,
    `i=0; until mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 60 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done`,
    // Stop any auto-started replication from the init script before importing.
    `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "STOP SLAVE; RESET SLAVE ALL;" || true`,
    // Ensure replication user exists on primary.
    `mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "${escapeForShellDoubleQuotes(ensureReplicaUserSql)}"`,
    // Grant SLAVE MONITOR so ProxySQL monitor can run SHOW SLAVE STATUS to check replication lag.
    // Granted on primary so it's captured in the --all-databases dump below.
    `mariadb -uroot -p"$ROOT_PASS" -h ${primaryHost} -e "GRANT SLAVE MONITOR ON *.* TO 'magento'@'%';"`,
    // Import snapshot (no binlogging) so replica GTID sequence does not jump ahead of primary.
    `mariadb-dump -uroot -p"$ROOT_PASS" -h ${primaryHost} --single-transaction --quick --routines --events --triggers --hex-blob --gtid --master-data=1 --all-databases | mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} --init-command="SET SESSION sql_log_bin=0;"`,
    // Configure and start replication.
    `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "${escapeForShellDoubleQuotes(changeMasterSql)}"`,
    `mariadb -uroot -p"$ROOT_PASS" -h ${replicaHost} -e "SET GLOBAL read_only=1;" || true`,
    'echo "SEEDED=1"',
  ].join(' && ');

  const seedJob = await runDatabaseJob(environmentId, 'db-seed', seedScript, { include_replication_secret: true, timeout_ms: 30 * 60_000 });
  data.seed_job = { ok: seedJob.ok, state: seedJob.state };
  actions.push(seedJob.ok ? 'Seeded replica from primary snapshot' : 'Replica seed failed');
  if (!seedJob.ok) {
    observations.push(`Seed job failed: ${seedJob.error || seedJob.state}`);
    if (seedJob.details?.length) observations.push(`Seed task: ${seedJob.details[0]}`);
    return {
      runbook_id: 'db_replica_reseed',
      status: 'failed',
      summary: 'Replica reseed failed.',
      observations,
      data,
      remediation: { attempted: true, actions },
    };
  }

  // Final probe.
  const finalProbeJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(environmentId), { timeout_ms: 60_000 });
  data.after_probe_job = { ok: finalProbeJob.ok, state: finalProbeJob.state };
  const after = finalProbeJob.ok ? parseDbReplicationProbe(finalProbeJob.logs) : null;
  if (after) data.after = after;

  const afterSlave = after?.replica.slave_status || null;
  const afterIo = (afterSlave?.Slave_IO_Running || '').toLowerCase();
  const afterSql = (afterSlave?.Slave_SQL_Running || '').toLowerCase();
  const ok = Boolean(afterSlave) && afterIo === 'yes' && afterSql === 'yes' && (after?.replica.magento_table_count || 0) > 0;

  if (after) {
    observations.push(`Replica magento tables: ${after.replica.magento_table_count === null ? 'unknown' : after.replica.magento_table_count}`);
    if (afterSlave) {
      observations.push(`Replica threads: IO=${afterSlave.Slave_IO_Running || '(unknown)'} SQL=${afterSlave.Slave_SQL_Running || '(unknown)'}`);
      const lastSql = (afterSlave.Last_SQL_Error || '').trim();
      if (lastSql) observations.push(`Replica Last_SQL_Error: ${lastSql}`);
      const lagRaw = afterSlave.Seconds_Behind_Master ?? '';
      const lagSeconds = lagRaw === '' || String(lagRaw).toUpperCase() === 'NULL'
        ? null
        : Number.parseInt(String(lagRaw), 10);
      observations.push(`Replica lag: ${lagSeconds === null ? '(unknown)' : `${lagSeconds}s`}`);
    } else {
      observations.push('Replica slave status: not available after reseed.');
    }
  } else if (!finalProbeJob.ok) {
    observations.push('Post-reseed probe failed.');
  }

  return {
    runbook_id: 'db_replica_reseed',
    status: ok ? 'ok' : 'warning',
    summary: ok ? 'Replica reseeded and replication started.' : 'Replica reseed completed but replication is not healthy yet.',
    observations,
    data,
    remediation: { attempted: true, actions },
  };
}

type DbSwitchDirection = 'to_replica' | 'to_primary';

async function runDbSwitchRole(environmentId: number, direction: DbSwitchDirection): Promise<RunbookResult> {
  const actions: string[] = [];
  const observations: string[] = [];

  const fromService = direction === 'to_replica' ? 'database' : 'database-replica';
  const toService = direction === 'to_replica' ? 'database-replica' : 'database';

  const fromHost = envServiceName(environmentId, fromService);
  const toHost = envServiceName(environmentId, toService);
  const fromTasks = await listServiceTasks(fromHost);
  const toTasks = await listServiceTasks(toHost);
  if (!fromTasks.length || !toTasks.length) {
    return {
      runbook_id: direction === 'to_replica' ? 'db_failover' : 'db_failback',
      status: 'failed',
      summary: 'Database services not found or have no tasks.',
      observations: [
        fromTasks.length ? `Found ${fromService}: ${fromHost}` : `Missing tasks for ${fromHost}`,
        toTasks.length ? `Found ${toService}: ${toHost}` : `Missing tasks for ${toHost}`,
      ],
      remediation: { attempted: false, actions: [] },
    };
  }

  const desiredWriterHost = toHost;
  const runbookId = direction === 'to_replica' ? 'db_failover' : 'db_failback';

  // Quick no-op check.
  const toReadOnly = await dbGetReadOnly(environmentId, toHost);
  const toSlave = await dbGetSlaveStatus(environmentId, toHost);
  if (toReadOnly === false && !toSlave) {
    return {
      runbook_id: runbookId,
      status: 'ok',
      summary: `Database already writing on ${desiredWriterHost}.`,
      observations: [
        `${toService} is already read_only=OFF and not configured as a replica.`,
      ],
      remediation: { attempted: false, actions: [] },
      data: { writer: desiredWriterHost },
    };
  }

  // Maintenance mode + pause cron to quiesce writes.
  const maintenance = await runMagentoMaintenance(environmentId, 'enable');
  actions.push('Enabled Magento maintenance mode');
  observations.push(...maintenance.observations.map((line) => `Maintenance: ${line}`));
  if (maintenance.status !== 'ok') {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Failed to enable maintenance mode; aborting switchover.',
      observations,
      remediation: { attempted: true, actions },
      data: { direction, writer_target: desiredWriterHost },
    };
  }

  const cronDown = await scaleEnvironmentService(environmentId, 'cron', 0);
  actions.push(cronDown.ok ? 'Scaled cron service to 0' : `Failed to scale cron service: ${cronDown.note || ''}`.trim());

  // Demote current writer (fromService) to read-only before we wait for catch-up.
  const roSet = await dbSetReadOnly(environmentId, fromHost, true);
  actions.push(roSet ? `Set ${fromService} read_only=ON` : `Failed to set ${fromService} read_only=ON`);

  // Ensure the target (toService) is caught up before promotion.
  const caughtUp = await dbWaitForReplicaCaughtUp(environmentId, toHost, 180_000);
  observations.push(caughtUp.ok ? 'Replica catch-up: OK' : `Replica catch-up: ${caughtUp.note || 'not caught up'}`);
  if (!caughtUp.ok) {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Replica is not caught up; aborting switchover to avoid data loss.',
      observations,
      remediation: { attempted: true, actions },
      data: { direction, writer_target: desiredWriterHost },
    };
  }

  // Promote target to writer.
  const stopReplica = await dbStopAndResetSlave(environmentId, toHost);
  actions.push(stopReplica ? `Stopped replication on ${toService}` : `Failed to stop replication on ${toService}`);
  const rw = await dbSetReadOnly(environmentId, toHost, false);
  actions.push(rw ? `Set ${toService} read_only=OFF` : `Failed to set ${toService} read_only=OFF`);

  // Configure the old writer as a replica of the new writer.
  const cleaned = await dbStopAndResetSlave(environmentId, fromHost);
  actions.push(cleaned ? `Cleared replication state on ${fromService}` : `Failed to clear replication state on ${fromService}`);
  const configured = await dbConfigureAsReplica(environmentId, fromHost, desiredWriterHost, 'replica');
  actions.push(configured ? `Configured ${fromService} as replica of ${desiredWriterHost}` : `Failed to configure ${fromService} replication`);
  const roAgain = await dbSetReadOnly(environmentId, fromHost, true);
  actions.push(roAgain ? `Set ${fromService} read_only=ON` : `Failed to set ${fromService} read_only=ON`);

  // Wait for ProxySQL to see the new writer hostgroup (best-effort).
  const proxysqlOk = await waitForProxySqlWriter(environmentId, desiredWriterHost, 45_000);
  observations.push(proxysqlOk
    ? `ProxySQL: writer now ${desiredWriterHost}`
    : `ProxySQL: writer not confirmed as ${desiredWriterHost} (may still converge)`);

  // Resume cron and disable maintenance mode.
  const cronUp = await scaleEnvironmentService(environmentId, 'cron', 1);
  actions.push(cronUp.ok ? 'Scaled cron service to 1' : `Failed to scale cron service: ${cronUp.note || ''}`.trim());

  const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
  actions.push('Disabled Magento maintenance mode');
  observations.push(...maintenanceOff.observations.map((line) => `Maintenance: ${line}`));

  return {
    runbook_id: runbookId,
    status: proxysqlOk ? 'ok' : 'warning',
    summary: `Switchover complete. Writer is now ${desiredWriterHost}.`,
    observations,
    remediation: { attempted: true, actions },
    data: {
      direction,
      writer: desiredWriterHost,
      proxysql_writer_confirmed: proxysqlOk,
    },
  };
}

function safeReadJsonFile(filePath: string): Record<string, unknown> | null {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = safeJsonParse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function runDeployActiveSummary(environmentId: number): Promise<RunbookResult> {
  if (!fs.existsSync(DEPLOY_PROCESSING_DIR)) {
    return {
      runbook_id: 'deploy_active_summary',
      status: 'ok',
      summary: 'No processing deploy directory found.',
      observations: [`Expected path: ${DEPLOY_PROCESSING_DIR}`],
    };
  }

  const entries = fs.readdirSync(DEPLOY_PROCESSING_DIR)
    .filter((name) => DEPLOY_RECORD_FILENAME.test(name))
    .map((name) => ({ name, fullPath: path.join(DEPLOY_PROCESSING_DIR, name) }))
    .map((entry) => {
      try {
        const stat = fs.statSync(entry.fullPath);
        return { ...entry, mtimeMs: stat.mtimeMs, mtimeIso: stat.mtime.toISOString(), size: stat.size };
      } catch {
        return { ...entry, mtimeMs: 0, mtimeIso: '', size: 0 };
      }
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  for (const entry of entries) {
    const record = safeReadJsonFile(entry.fullPath);
    if (!record) {
      continue;
    }
    const payload = (record.payload && typeof record.payload === 'object' && !Array.isArray(record.payload))
      ? (record.payload as Record<string, unknown>)
      : null;
    const envId = Number(payload?.environment_id ?? 0);
    if (envId !== environmentId) {
      continue;
    }

    const deploymentId = String(record.id ?? path.basename(entry.name, '.json')).trim() || path.basename(entry.name, '.json');
    const queuedAt = String(record.queued_at ?? '').trim();
    const ageSeconds = entry.mtimeMs ? Math.max(0, Math.floor((Date.now() - entry.mtimeMs) / 1000)) : null;

    return {
      runbook_id: 'deploy_active_summary',
      status: 'warning',
      summary: `Deploy is in progress (${deploymentId}).`,
      observations: [
        `Queued at: ${queuedAt || '(unknown)'}`,
        `Processing file mtime: ${entry.mtimeIso || '(unknown)'}${ageSeconds !== null ? ` (${ageSeconds}s ago)` : ''}`,
        `Artifact: ${String(payload?.artifact ?? '').trim() || '(unknown)'}`,
      ],
      data: {
        deployment_id: deploymentId,
        queued_at: queuedAt || null,
        processing_mtime: entry.mtimeIso || null,
        processing_age_seconds: ageSeconds,
        payload,
      },
    };
  }

  return {
    runbook_id: 'deploy_active_summary',
    status: 'ok',
    summary: 'No active deploy found for this environment.',
    observations: [`Scanned ${entries.length} processing record(s) in ${DEPLOY_PROCESSING_DIR}`],
  };
}

function tailLines(text: string, count: number): string {
  const lines = text.split(/\r?\n/);
  if (count <= 0) return '';
  return lines.slice(Math.max(0, lines.length - count)).join('\n');
}

type DeployHistoryEntry = { artifacts: string[]; imageTags: string[]; updated_at?: string };
type DeployHistory = Record<string, DeployHistoryEntry>;
type DeployState = 'queued' | 'processing' | 'failed';
type DeployStateRecord = {
  state: DeployState;
  deploymentId: string;
  atMs: number;
  atIso: string;
  record: Record<string, unknown>;
  sourcePath: string;
};

function deployStatePriority(state: DeployState): number {
  if (state === 'processing') return 3;
  if (state === 'queued') return 2;
  return 1;
}

function pickLatestDeploymentState(records: DeployStateRecord[]): DeployStateRecord | null {
  if (!records.length) {
    return null;
  }

  const sorted = [...records].sort((a, b) => {
    if (b.atMs !== a.atMs) {
      return b.atMs - a.atMs;
    }
    const byState = deployStatePriority(b.state) - deployStatePriority(a.state);
    if (byState !== 0) {
      return byState;
    }
    return b.deploymentId.localeCompare(a.deploymentId);
  });
  return sorted[0] || null;
}

function safeReadDeployHistory(): DeployHistory {
  try {
    if (!fs.existsSync(DEPLOY_HISTORY_FILE)) {
      return {};
    }
    const raw = fs.readFileSync(DEPLOY_HISTORY_FILE, 'utf8');
    const parsed = safeJsonParse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }
    return parsed as DeployHistory;
  } catch {
    return {};
  }
}

function parseRecordTimestamp(
  record: Record<string, unknown>,
  fallbackMs: number,
  fields: string[]
): { atMs: number; atIso: string } {
  for (const field of fields) {
    const raw = String(record[field] ?? '').trim();
    if (!raw) {
      continue;
    }
    const parsed = Date.parse(raw);
    if (Number.isFinite(parsed) && parsed > 0) {
      return { atMs: parsed, atIso: raw };
    }
  }

  if (Number.isFinite(fallbackMs) && fallbackMs > 0) {
    return { atMs: fallbackMs, atIso: new Date(fallbackMs).toISOString() };
  }

  return { atMs: 0, atIso: '' };
}

function collectDeploymentStateRecords(params: {
  dirPath: string;
  state: DeployState;
  environmentId: number;
  filenamePattern: RegExp;
  timestampFields: string[];
}): DeployStateRecord[] {
  const { dirPath, state, environmentId, filenamePattern, timestampFields } = params;
  if (!fs.existsSync(dirPath)) {
    return [];
  }

  const out: DeployStateRecord[] = [];
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !filenamePattern.test(entry.name)) {
      continue;
    }

    const fullPath = path.join(dirPath, entry.name);
    const record = safeReadJsonFile(fullPath);
    if (!record) {
      continue;
    }
    const payload = (record.payload && typeof record.payload === 'object' && !Array.isArray(record.payload))
      ? (record.payload as Record<string, unknown>)
      : null;
    const envId = Number(payload?.environment_id ?? 0);
    if (!envId || envId !== environmentId) {
      continue;
    }

    let mtimeMs = 0;
    try {
      mtimeMs = fs.statSync(fullPath).mtimeMs;
    } catch {
      mtimeMs = 0;
    }
    const ts = parseRecordTimestamp(record, mtimeMs, timestampFields);
    const deploymentId = String(record.id ?? path.basename(entry.name, '.json')).trim() || path.basename(entry.name, '.json');
    out.push({
      state,
      deploymentId,
      atMs: ts.atMs,
      atIso: ts.atIso,
      record,
      sourcePath: fullPath,
    });
  }

  out.sort((a, b) => b.atMs - a.atMs);
  return out;
}

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function enqueueDeploymentRecord(payload: Record<string, unknown>, deploymentId: string) {
  ensureDir(DEPLOY_QUEUED_DIR);
  const target = path.join(DEPLOY_QUEUED_DIR, `${deploymentId}.json`);
  fs.writeFileSync(
    target,
    JSON.stringify({ id: deploymentId, queued_at: new Date().toISOString(), payload }, null, 2),
  );
}

async function runDeployPauseStatus(): Promise<RunbookResult> {
  const paused = isDeployPaused();
  const pausedAt = paused ? readDeployPausedAt() : null;
  const filePath = getDeployPauseFilePath();
  return {
    runbook_id: 'deploy_pause_status',
    status: paused ? 'warning' : 'ok',
    summary: paused ? 'Deploy worker is paused.' : 'Deploy worker is not paused.',
    observations: [
      `Paused: ${paused ? 'true' : 'false'}`,
      pausedAt ? `Paused at: ${pausedAt}` : '',
      `File: ${filePath}`,
    ].filter(Boolean),
    data: { paused, paused_at: pausedAt, file: filePath },
  };
}

async function runDeployPause(): Promise<RunbookResult> {
  const status = setDeployPaused(true);
  return {
    runbook_id: 'deploy_pause',
    status: 'ok',
    summary: 'Deploy worker paused.',
    observations: [
      'Paused: true',
      status.paused_at ? `Paused at: ${status.paused_at}` : '',
      `File: ${status.path}`,
    ].filter(Boolean),
    remediation: { attempted: true, actions: ['Paused deploy worker'] },
    data: status,
  };
}

async function runDeployResume(): Promise<RunbookResult> {
  const status = setDeployPaused(false);
  return {
    runbook_id: 'deploy_resume',
    status: 'ok',
    summary: 'Deploy worker resumed.',
    observations: [
      'Paused: false',
      `File: ${status.path}`,
    ],
    remediation: { attempted: true, actions: ['Resumed deploy worker'] },
    data: status,
  };
}

async function runDeployRollbackPrevious(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const repository = String(input.repository ?? '').trim();
  const ref = String(input.ref ?? '').trim();
  const stackId = Number(input.stack_id ?? 0);

  if (!repository || !ref || !stackId) {
    return {
      runbook_id: 'deploy_rollback_previous',
      status: 'failed',
      summary: 'Missing required input for rollback.',
      observations: ['Expected input: { repository, ref, stack_id }'],
    };
  }

  const history = safeReadDeployHistory();
  const key = `env:${environmentId}:${repository}`;
  const entry = history[key];
  const artifacts = Array.isArray(entry?.artifacts) ? entry.artifacts : [];
  const targetArtifact = String(artifacts[1] || '').trim();
  if (!targetArtifact) {
    return {
      runbook_id: 'deploy_rollback_previous',
      status: 'failed',
      summary: 'No previous retained artefact available for rollback.',
      observations: [
        `Key: ${key}`,
        `History file: ${DEPLOY_HISTORY_FILE}`,
        `Artifacts retained: ${artifacts.length}`,
      ],
      data: { key, artifacts },
    };
  }

  const deploymentId = crypto.randomUUID();
  enqueueDeploymentRecord({
    artifact: targetArtifact,
    stack_id: stackId,
    environment_id: environmentId,
    repository,
    ref,
    rollback_of: String(artifacts[0] || '') || null,
  }, deploymentId);

  return {
    runbook_id: 'deploy_rollback_previous',
    status: 'warning',
    summary: `Rollback queued (deployment ${deploymentId}).`,
    observations: [
      `Repository: ${repository}`,
      `Ref: ${ref}`,
      `Using artefact: ${targetArtifact}`,
    ],
    remediation: { attempted: true, actions: ['Queued rollback deploy using previous artefact'] },
    data: { deployment_id: deploymentId, artifact: targetArtifact, key, history_updated_at: entry?.updated_at || null },
  };
}

async function runDeployRetryLatest(environmentId: number): Promise<RunbookResult> {
  const processing = collectDeploymentStateRecords({
    dirPath: DEPLOY_PROCESSING_DIR,
    state: 'processing',
    environmentId,
    filenamePattern: DEPLOY_RECORD_FILENAME,
    timestampFields: ['updated_at', 'queued_at'],
  });
  const queued = collectDeploymentStateRecords({
    dirPath: DEPLOY_QUEUED_DIR,
    state: 'queued',
    environmentId,
    filenamePattern: DEPLOY_RECORD_FILENAME,
    timestampFields: ['queued_at', 'updated_at'],
  });
  const queuedLegacy = path.resolve(DEPLOY_QUEUED_DIR) === path.resolve(DEPLOY_QUEUE_DIR)
    ? []
    : collectDeploymentStateRecords({
      dirPath: DEPLOY_QUEUE_DIR,
      state: 'queued',
      environmentId,
      filenamePattern: DEPLOY_RECORD_FILENAME,
      timestampFields: ['queued_at', 'updated_at'],
    });
  const queuedCombined = [...queued, ...queuedLegacy]
    .sort((a, b) => b.atMs - a.atMs || b.deploymentId.localeCompare(a.deploymentId));
  const failed = collectDeploymentStateRecords({
    dirPath: DEPLOY_FAILED_DIR,
    state: 'failed',
    environmentId,
    filenamePattern: /\.json$/i,
    timestampFields: ['failed_at', 'updated_at', 'queued_at'],
  });

  const latest = pickLatestDeploymentState([...processing, ...queuedCombined, ...failed]);
  if (!latest) {
    return {
      runbook_id: 'deploy_retry_latest',
      status: 'failed',
      summary: 'Cannot retry: latest deployment status is not failed.',
      observations: [`No failed deployment records found for environment ${environmentId}.`],
      data: { latest_status: 'none' },
    };
  }

  if (latest.state !== 'failed') {
    return {
      runbook_id: 'deploy_retry_latest',
      status: 'failed',
      summary: `Cannot retry: latest deployment status is ${latest.state}.`,
      observations: [
        `Deployment: ${latest.deploymentId}`,
        `${latest.state === 'queued' ? 'Queued' : 'Updated'} at: ${latest.atIso || '(unknown)'}`,
      ],
      data: {
        latest_status: latest.state,
        deployment_id: latest.deploymentId,
      },
    };
  }

  const payload = (latest.record.payload && typeof latest.record.payload === 'object' && !Array.isArray(latest.record.payload))
    ? (latest.record.payload as Record<string, unknown>)
    : null;
  const artifact = String(payload?.artifact ?? '').trim();
  const stackId = Number(payload?.stack_id ?? 0);
  const repository = String(payload?.repository ?? '').trim();
  const ref = String(payload?.ref ?? '').trim();

  if (!artifact || !stackId) {
    return {
      runbook_id: 'deploy_retry_latest',
      status: 'failed',
      summary: 'Cannot retry: failed deployment payload is incomplete.',
      observations: [
        `Source deployment: ${latest.deploymentId}`,
        `Missing fields:${!artifact ? ' artifact' : ''}${!stackId ? ' stack_id' : ''}`.trim(),
      ],
      data: {
        latest_status: 'failed',
        deployment_id: latest.deploymentId,
      },
    };
  }

  const queuedDeploymentId = crypto.randomUUID();
  const retryPayload: Record<string, unknown> = {
    artifact,
    stack_id: stackId,
    environment_id: environmentId,
    retry_of: latest.deploymentId,
  };
  if (repository) {
    retryPayload.repository = repository;
  }
  if (ref) {
    retryPayload.ref = ref;
  }
  enqueueDeploymentRecord(retryPayload, queuedDeploymentId);

  return {
    runbook_id: 'deploy_retry_latest',
    status: 'warning',
    summary: `Deploy retry queued (${queuedDeploymentId}) from failed deployment ${latest.deploymentId}.`,
    observations: [
      'Latest status: failed',
      `Failed at: ${latest.atIso || '(unknown)'}`,
      `Artifact: ${artifact}`,
    ],
    remediation: { attempted: true, actions: ['Queued deploy retry from latest failed deployment'] },
    data: {
      latest_status: 'failed',
      source_deployment_id: latest.deploymentId,
      source_failed_at: latest.atIso || null,
      queued_deployment_id: queuedDeploymentId,
      artifact,
      stack_id: stackId,
      repository: repository || null,
      ref: ref || null,
    },
  };
}

async function runMagentoMaintenance(environmentId: number, mode: 'enable' | 'disable'): Promise<RunbookResult> {
  const runbookId = mode === 'enable' ? 'magento_maintenance_enable' : 'magento_maintenance_disable';
  // Important: maintenance mode is represented by a flag file under `var/`.
  // In this stack, `var/` is tmpfs and therefore NOT shared between php-fpm and php-fpm-admin.
  // To ensure the storefront actually enters maintenance mode, we must apply the flag on php-fpm
  // (and best-effort mirror it on php-fpm-admin).
  const hasFrontend = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm')));
  const hasAdmin = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm-admin')));
  const services: Array<'php-fpm' | 'php-fpm-admin'> = [];
  if (hasFrontend) services.push('php-fpm');
  if (hasAdmin) services.push('php-fpm-admin');
  if (!services.length) {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'php-fpm service not found.',
      observations: [
        `Missing service: ${envServiceName(environmentId, 'php-fpm')}`,
        `Missing service: ${envServiceName(environmentId, 'php-fpm-admin')}`,
      ],
    };
  }

  const cmd = mode === 'enable'
    ? 'bin/magento maintenance:enable --no-interaction'
    : 'bin/magento maintenance:disable --no-interaction';

  const observations: string[] = [];
  const results: Array<{ service: string; ok: boolean; state: string; node?: string; logs?: string; error?: string }> = [];

  for (const service of services) {
    const serviceFullName = envServiceName(environmentId, service);
    const job = await runServiceJob(environmentId, service, `maintenance-${mode}`, `cd /var/www/html/magento && ${cmd}`, { timeout_ms: 90_000 });
    results.push({
      service: serviceFullName,
      ok: job.ok,
      state: job.state,
      node: job.node,
      logs: job.logs,
      error: job.error,
    });
    observations.push(
      `Service: ${serviceFullName}`,
      job.node ? `Node: ${job.node}` : '',
      job.logs.trim() ? `Logs: ${tailLines(job.logs.trim(), 30)}` : '',
      job.ok ? '' : `Error: ${job.error || job.state}`,
    );
  }

  const frontend = results.find((r) => r.service === envServiceName(environmentId, 'php-fpm')) || results[0];
  const admin = results.find((r) => r.service === envServiceName(environmentId, 'php-fpm-admin'));
  const ok = Boolean(frontend?.ok);
  const warning = ok && admin && !admin.ok;

  return {
    runbook_id: runbookId,
    status: ok ? (warning ? 'warning' : 'ok') : 'failed',
    summary: ok ? `Magento maintenance mode ${mode}d.` : `Magento maintenance mode ${mode} failed.`,
    observations: observations.filter(Boolean),
    remediation: { attempted: true, actions: [`Magento maintenance:${mode}`] },
    data: {
      ok,
      services: results.map((r) => ({ service: r.service, ok: r.ok, state: r.state, node: r.node })),
    },
  };
}

async function runMagentoCommand(
  environmentId: number,
  command: string,
  jobPrefix: string,
  timeoutMs = 90_000,
  target: 'auto' | 'php-fpm' | 'php-fpm-admin' = 'auto'
): Promise<{ ok: boolean; logs: string; error?: string; state: string; service: string; node?: string }> {
  const hasFrontend = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm')));
  const hasAdmin = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm-admin')));
  let targetService: 'php-fpm' | 'php-fpm-admin';
  if (target === 'php-fpm') {
    targetService = hasFrontend ? 'php-fpm' : (hasAdmin ? 'php-fpm-admin' : 'php-fpm');
  } else if (target === 'php-fpm-admin') {
    targetService = hasAdmin ? 'php-fpm-admin' : (hasFrontend ? 'php-fpm' : 'php-fpm-admin');
  } else {
    targetService = hasAdmin ? 'php-fpm-admin' : 'php-fpm';
  }
  const serviceFullName = envServiceName(environmentId, targetService);
  if (!(await inspectServiceSpec(serviceFullName))) {
    return {
      ok: false,
      logs: '',
      error: `Missing service: ${serviceFullName}`,
      state: 'missing_service',
      service: serviceFullName,
    };
  }

  const job = await runServiceJob(
    environmentId,
    targetService,
    jobPrefix,
    `cd /var/www/html/magento && ${command}`,
    { timeout_ms: timeoutMs }
  );

  return {
    ok: job.ok,
    logs: job.logs || '',
    error: job.error,
    state: job.state,
    service: job.service || serviceFullName,
    node: job.node,
  };
}

async function runEnvironmentTeardown(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const runbookId = 'environment_teardown';
  const observations: string[] = [];
  const actions: string[] = [];
  const progress = RunbookProgress.create(runbookId, environmentId, [
    { id: 'precheck', label: 'Pre-flight checks' },
    { id: 'maintenance_on', label: 'Enable maintenance mode' },
    { id: 'cache_flush', label: 'Flush Magento cache' },
    { id: 'maintenance_confirm', label: 'Confirm maintenance mode' },
    { id: 'dump', label: 'Dump database' },
    { id: 'compress', label: 'Compress backup' },
    { id: 'encrypt', label: 'Encrypt backup' },
    { id: 'upload', label: 'Upload to R2' },
    { id: 'stack_rm', label: 'Remove environment stack' },
    { id: 'wait_services', label: 'Wait for services to stop' },
    { id: 'remove_volumes', label: 'Remove volumes' },
  ]);

  progress.start('precheck');
  const activeDeploy = await runDeployActiveSummary(environmentId);
  if (activeDeploy.status === 'warning') {
    progress.fail('precheck', 'Deploy is active; teardown aborted.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Deploy is active; teardown aborted.',
      observations: activeDeploy.observations,
    };
  }
  progress.ok('precheck');

  progress.start('maintenance_on');
  const maintenance = await runMagentoMaintenance(environmentId, 'enable');
  observations.push(`Maintenance: ${maintenance.summary}`);
  observations.push(...maintenance.observations.map((line) => `Maintenance: ${line}`));
  if (maintenance.status !== 'ok') {
    progress.fail('maintenance_on', 'Failed to enable maintenance mode; teardown aborted.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Failed to enable maintenance mode; teardown aborted.',
      observations,
    };
  }
  progress.ok('maintenance_on');

  progress.start('cache_flush');
  const cacheFlush = await runMagentoCommand(environmentId, 'php bin/magento cache:flush --no-interaction', 'cache-flush', 120_000);
  observations.push(`Cache flush: ${cacheFlush.ok ? 'ok' : 'failed'}`);
  if (cacheFlush.logs.trim()) {
    observations.push(`Cache flush logs: ${tailLines(cacheFlush.logs.trim(), 20)}`);
  }
  if (!cacheFlush.ok) {
    progress.fail('cache_flush', 'Cache flush failed; teardown aborted.');
    const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Cache flush failed; teardown aborted.',
      observations: [
        ...observations,
        cacheFlush.error ? `Cache flush error: ${cacheFlush.error}` : '',
        `Maintenance: ${maintenanceOff.summary}`,
        ...maintenanceOff.observations.map((line) => `Maintenance: ${line}`),
      ].filter(Boolean),
    };
  }
  progress.ok('cache_flush');

  progress.start('maintenance_confirm');
  // Confirm storefront maintenance mode (php-fpm), not just php-fpm-admin.
  const maintenanceStatus = await runMagentoCommand(environmentId, 'php bin/magento maintenance:status --no-interaction', 'maintenance-status', 60_000, 'php-fpm');
  const maintenanceOutput = maintenanceStatus.logs.toLowerCase();
  const maintenanceEnabled = maintenanceStatus.ok
    && maintenanceOutput.includes('enabled')
    && !maintenanceOutput.includes('disabled');
  observations.push(`Maintenance status: ${maintenanceEnabled ? 'enabled' : 'not enabled'}`);
  if (!maintenanceStatus.ok || !maintenanceEnabled) {
    progress.fail('maintenance_confirm', 'Maintenance mode not confirmed; teardown aborted.');
    const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Maintenance mode not confirmed; teardown aborted.',
      observations: [
        ...observations,
        maintenanceStatus.logs.trim() ? `Maintenance status logs: ${tailLines(maintenanceStatus.logs.trim(), 20)}` : '',
        maintenanceStatus.error ? `Maintenance status error: ${maintenanceStatus.error}` : '',
        `Maintenance: ${maintenanceOff.summary}`,
        ...maintenanceOff.observations.map((line) => `Maintenance: ${line}`),
      ].filter(Boolean),
    };
  }
  progress.ok('maintenance_confirm');

  const r2 = resolveR2Context(environmentId);
  if (!r2) {
    progress.fail('precheck', 'Missing mz-control connection details for R2 presign.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Missing mz-control connection details for R2 presign.',
      observations: [
        `Expected: ${path.join(NODE_DIR, 'node-id')}`,
        `Expected: ${path.join(NODE_DIR, 'node-secret')}`,
        `Expected: ${path.join(NODE_DIR, 'config.json')} with stack_id + mz_control_base_url (or env var MZ_CONTROL_BASE_URL)`,
      ],
    };
  }
  const envRecord = await fetchEnvironmentRecord(r2).catch(() => null);
  const backupBucket = String(envRecord?.db_backup_bucket || '').trim();

  const backupObjectRaw = typeof input.backup_object === 'string' ? input.backup_object.trim() : '';
  const backupObject = (backupObjectRaw || 'provisioning-database.sql.zst.age').replace(/^\/+/, '');

  const publicKeyPath = resolveStackMasterPublicKeyPath();
  if (!publicKeyPath) {
    progress.fail('precheck', 'Missing stack master public key for encryption.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Missing stack master public key for encryption.',
      observations: [
        `Checked: ${STACK_MASTER_PUBLIC_KEY_PATH}`,
        `Checked: ${path.join(NODE_DIR, 'stack_master_ssh.pub')}`,
      ],
    };
  }

  const dbServiceName = envServiceName(environmentId, 'database');
  const dbSpec = await inspectServiceSpec(dbServiceName);
  if (!dbSpec) {
    progress.fail('dump', `Database service missing: ${dbServiceName}`);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database service not found; backup aborted.',
      observations: [`Service missing: ${dbServiceName}`],
    };
  }

  const dbName = String(dbSpec.env.MYSQL_DATABASE || 'magento').trim() || 'magento';
  const containerId = await findServiceContainerId(dbServiceName);
  if (!containerId) {
    progress.fail('dump', 'Database container not running; backup aborted.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database container not running; backup aborted.',
      observations: [`Service: ${dbServiceName}`],
    };
  }

  const timestamp = formatTimestamp();
  const workDir = path.join(DEPLOY_WORK_DIR, `teardown-${environmentId}-${timestamp}`);
  ensureDir(workDir);
  const dumpPath = path.join(workDir, `db-${timestamp}.sql`);
  const zstPath = `${dumpPath}.zst`;
  const agePath = `${zstPath}.age`;

  try {
    progress.start('dump');
    const dumpInner = [
      // `sh` on some distros is `dash`, which doesn't support `set -o pipefail`.
      // We don't use pipes here, so `-eu` is sufficient.
      'set -eu',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb-dump -uroot -p"$ROOT_PASS" --single-transaction --quick --routines --events --triggers --hex-blob --databases ${quoteShell(
        dbName
      )}`,
    ].join(' && ');
    const dumpResult = await runCommandToFile('docker', ['exec', containerId, 'sh', '-c', dumpInner], dumpPath, 10 * 60_000);
    if (dumpResult.code !== 0) {
      const output = (dumpResult.stderr || '').trim();
      throw new Error(output ? `Database dump failed: ${output}` : 'Database dump failed.');
    }
    progress.ok('dump');

    progress.start('compress');
    const zstdLevel = getDbBackupZstdLevel();
    const zstdResult = await runCommand('zstd', [`-${zstdLevel}`, '-f', '-o', zstPath, dumpPath], 10 * 60_000);
    if (zstdResult.code !== 0) {
      const output = (zstdResult.stderr || zstdResult.stdout || '').trim();
      throw new Error(output ? `zstd failed: ${output}` : 'zstd failed.');
    }
    progress.ok('compress');

    progress.start('encrypt');
    const ageResult = await runCommand('age', ['-R', publicKeyPath, '-o', agePath, zstPath], 60_000);
    if (ageResult.code !== 0) {
      const output = (ageResult.stderr || ageResult.stdout || '').trim();
      throw new Error(output ? `age encryption failed: ${output}` : 'age encryption failed.');
    }
    progress.ok('encrypt');

    progress.start('upload');
    await uploadArtifact(r2, backupObject, agePath);
    actions.push(backupBucket ? `Uploaded backup to ${backupBucket}/${backupObject}` : `Uploaded backup to ${backupObject}`);
    progress.ok('upload');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
    progress.fail(progressStateForDbBackupFailure(message), 'Database backup failed; teardown aborted.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database backup failed; teardown aborted.',
      observations: [
        message,
        `Maintenance: ${maintenanceOff.summary}`,
        ...maintenanceOff.observations.map((line) => `Maintenance: ${line}`),
      ],
    };
  } finally {
    for (const filePath of [dumpPath, zstPath, agePath]) {
      try {
        if (fs.existsSync(filePath)) {
          fs.rmSync(filePath, { force: true });
        }
      } catch {
        // ignore cleanup failures
      }
    }
  }

  const stackName = `mz-env-${environmentId}`;
  progress.start('stack_rm');
  const stackRemove = await runCommand('docker', ['stack', 'rm', stackName], 60_000);
  if (stackRemove.code === 0) {
    actions.push(`Removed stack ${stackName}`);
  } else {
    const output = (stackRemove.stderr || stackRemove.stdout || '').trim();
    const missing = output.toLowerCase().includes('nothing found') || output.toLowerCase().includes('not found');
    if (!missing) {
      progress.fail('stack_rm', 'Failed to remove environment stack.');
      return {
        runbook_id: runbookId,
        status: 'failed',
        summary: 'Failed to remove environment stack.',
        observations: [output || `stack rm failed for ${stackName}`],
      };
    }
    observations.push(`Stack ${stackName} already removed.`);
  }
  progress.ok('stack_rm');

  progress.start('wait_services');
  const wait = await waitForEnvironmentServicesGone(environmentId, 180_000);
  if (!wait.ok) {
    progress.fail('wait_services', 'Environment services did not stop in time.');
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Environment services did not stop in time.',
      observations: wait.remaining.length ? [`Remaining services: ${wait.remaining.join(', ')}`] : [],
    };
  }
  actions.push('All environment services removed.');
  progress.ok('wait_services');

  progress.start('remove_volumes');
  const volumes = await removeEnvironmentVolumes(environmentId);
  if (volumes.removed.length) {
    actions.push(`Removed volumes: ${volumes.removed.join(', ')}`);
  }
  if (volumes.failed.length) {
    observations.push(`Failed to remove volumes: ${volumes.failed.join(', ')}`);
  }
  if (volumes.failed.length) {
    progress.fail('remove_volumes', `Failed to remove some volumes: ${volumes.failed.join(', ')}`);
  } else {
    progress.ok('remove_volumes');
    progress.doneOk();
  }

  const status: RunbookResult['status'] = volumes.failed.length ? 'warning' : 'ok';
  return {
    runbook_id: runbookId,
    status,
    summary: 'Environment teardown completed.',
    observations,
    data: {
      backup_bucket: backupBucket,
      backup_object: backupObject,
      removed_volumes: volumes.removed,
      failed_volumes: volumes.failed,
    },
    remediation: { attempted: true, actions },
  };
}

async function runDeployLogExcerpt(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const deploymentId = String(input.deployment_id ?? '').trim();
  const step = String(input.step ?? 'build-magento').trim() || 'build-magento';
  const stream = String(input.stream ?? 'stderr').trim() || 'stderr';
  const lines = Math.min(200, Math.max(20, Number(input.lines ?? 120) || 120));

  if (!deploymentId || !DEPLOY_ID.test(deploymentId)) {
    return {
      runbook_id: 'deploy_log_excerpt',
      status: 'failed',
      summary: 'Invalid or missing deployment_id.',
      observations: ['Expected a UUID deployment_id.'],
    };
  }

  const allowedSteps = new Set(['build-services', 'build-magento', 'stack-deploy']);
  const allowedStreams = new Set(['stdout', 'stderr']);
  const safeStep = allowedSteps.has(step) ? step : 'build-magento';
  const safeStream = allowedStreams.has(stream) ? stream : 'stderr';
  const logFile = path.join(DEPLOY_WORK_DIR, deploymentId, 'logs', `${safeStep}.${safeStream}.log`);

  if (!fs.existsSync(logFile)) {
    return {
      runbook_id: 'deploy_log_excerpt',
      status: 'failed',
      summary: 'Deploy log file not found.',
      observations: [
        `Env: ${environmentId}`,
        `Deployment: ${deploymentId}`,
        `Expected log: ${logFile}`,
      ],
    };
  }

  let raw = '';
  try {
    raw = fs.readFileSync(logFile, 'utf8');
  } catch {
    return {
      runbook_id: 'deploy_log_excerpt',
      status: 'failed',
      summary: 'Unable to read deploy log file.',
      observations: [`Log: ${logFile}`],
    };
  }

  const excerpt = tailLines(raw, lines);
  const observations = [
    `Log: ${logFile}`,
    `Tail lines: ${lines}`,
  ];

  return {
    runbook_id: 'deploy_log_excerpt',
    status: 'ok',
    summary: `Returned ${lines} line(s) from ${safeStep}.${safeStream}.`,
    observations,
    data: {
      deployment_id: deploymentId,
      step: safeStep,
      stream: safeStream,
      lines,
      excerpt,
    },
  };
}

export async function handleServiceRestart(request: Request): Promise<{ error?: string; status?: number; success?: boolean; service?: string; message?: string }> {
  const authorized = await validateNodeRequest(request);
  if (!authorized) {
    return { error: 'unauthorized', status: 401 };
  }
  const body = await request.json().catch(() => null) as {
    service_name?: string;
    environment_id?: number;
  } | null;
  const serviceName = String(body?.service_name || '').trim();
  const environmentId = Number(body?.environment_id || 0);
  if (!serviceName || !environmentId) {
    return { error: 'missing service_name or environment_id', status: 400 };
  }
  const service = await findEnvironmentService(environmentId, serviceName);
  if (!service) {
    return { error: `Service matching "${serviceName}" not found for environment ${environmentId}.`, status: 404 };
  }
  const result = await runCommand('docker', ['service', 'update', '--force', service.id]);
  if (result.code !== 0) {
    return { error: `Failed to restart ${service.name}: ${result.stderr?.trim() || 'unknown error'}`, status: 500 };
  }
  return { success: true, service: service.name, message: `Restart triggered for ${service.name}.` };
}

export function createRunbookToken(): string {
  return crypto.randomUUID();
}

export const __testing = {
  parseSlaveStatus,
  parseDbReplicationProbe,
  buildDbProbeScript,
  parseProxySqlHostgroups,
  parseScdDbSnapshotPayload,
  normalizeScdDbRedactPathPatterns,
  normalizeScdDbRedactValuePatterns,
  buildScdDbSnapshotExporterScript,
  parseNodeResourceStats,
  hasCapacityPlacementSignal,
  normalizeProfileType,
  shouldSkipLiveTuningApply,
  buildSuggestedApplyInputFromPlanner,
  pickLatestDeploymentState,
};
