import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { buildNodeHeaders, buildSignature } from './node-hmac.js';
import { readConfig } from './status.js';
import { getDeployPauseFilePath, isDeployPaused, readDeployPausedAt, setDeployPaused } from './deploy-pause.js';
import { runCommand, runCommandToFile } from './exec.js';
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
const DEPLOY_FAILED_DIR = path.join(DEPLOY_QUEUE_DIR, 'failed');
const DEPLOY_PROCESSING_DIR = path.join(DEPLOY_QUEUE_DIR, 'processing');
const DEPLOY_WORK_DIR = path.join(DEPLOY_QUEUE_DIR, 'work');
const DEPLOY_META_DIR = path.join(DEPLOY_QUEUE_DIR, 'meta');
const DEPLOY_HISTORY_FILE = process.env.MZ_DEPLOY_HISTORY_FILE || path.join(DEPLOY_META_DIR, 'history.json');
const DEPLOY_RECORD_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i;
const DEPLOY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STACK_MASTER_PUBLIC_KEY_PATH = process.env.MZ_STACK_MASTER_PUBLIC_KEY_PATH || '/etc/magezero/stack_master_ssh.pub';

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
    case 'magento_maintenance_enable':
      return runMagentoMaintenance(environmentId, 'enable');
    case 'magento_maintenance_disable':
      return runMagentoMaintenance(environmentId, 'disable');
    case 'db_backup':
      return runDbBackup(environmentId, input);
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

async function runDbBackup(environmentId: number, input: Record<string, unknown>): Promise<RunbookResult> {
  const runbookId = 'db_backup';
  const actions: string[] = [];
  const observations: string[] = [];

  const method = String(input.method ?? 'mysqldump').trim().toLowerCase() || 'mysqldump';
  if (method !== 'mysqldump') {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Unsupported backup method.',
      observations: ['Supported methods: mysqldump', `Requested: ${method}`],
    };
  }

  const r2 = resolveR2Context(environmentId);
  if (!r2) {
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
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Database service not found; backup aborted.',
      observations: [`Service missing: ${dbServiceName}`],
    };
  }

  const dbName = String(dbSpec.env.MYSQL_DATABASE || 'magento').trim() || 'magento';

  // Best-effort: put the site into maintenance mode and pause cron to reduce writes.
  const maintenance = await runMagentoMaintenance(environmentId, 'enable');
  actions.push('Enabled Magento maintenance mode');
  observations.push(...maintenance.observations.map((line) => `Maintenance: ${line}`));
  if (maintenance.status !== 'ok') {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Failed to enable maintenance mode; backup aborted.',
      observations,
      remediation: { attempted: true, actions },
    };
  }

  const cronDown = await scaleEnvironmentService(environmentId, 'cron', 0);
  actions.push(cronDown.ok ? 'Scaled cron service to 0' : `Failed to scale cron service: ${cronDown.note || ''}`.trim());

  const timestamp = formatTimestamp();
  const workDir = path.join(DEPLOY_WORK_DIR, `db-backup-${environmentId}-${timestamp}`);
  ensureDir(workDir);
  const dumpPath = path.join(workDir, `db-${timestamp}.sql`);
  const zstPath = `${dumpPath}.zst`;
  const agePath = `${zstPath}.age`;

  let uploaded = false;
  let dumpSource = '';
  try {
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
          'set -euo pipefail',
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
        'set -euo pipefail',
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

    const zstdResult = await runCommand('zstd', ['-19', '-f', '-o', zstPath, dumpPath], 15 * 60_000);
    if (zstdResult.code !== 0) {
      const output = (zstdResult.stderr || zstdResult.stdout || '').trim();
      throw new Error(output ? `zstd failed: ${output}` : 'zstd failed.');
    }

    const ageResult = await runCommand('age', ['-R', publicKeyPath, '-o', agePath, zstPath], 2 * 60_000);
    if (ageResult.code !== 0) {
      const output = (ageResult.stderr || ageResult.stdout || '').trim();
      throw new Error(output ? `age encryption failed: ${output}` : 'age encryption failed.');
    }

    await uploadArtifact(r2, backupObject, agePath);
    uploaded = true;
    actions.push(backupBucket ? `Uploaded backup to ${backupBucket}/${backupObject}` : `Uploaded backup to ${backupObject}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    observations.push(message);
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
    const cronUp = await scaleEnvironmentService(environmentId, 'cron', 1);
    actions.push(cronUp.ok ? 'Scaled cron service to 1' : `Failed to scale cron service: ${cronUp.note || ''}`.trim());

    const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
    actions.push('Disabled Magento maintenance mode');
    observations.push(...maintenanceOff.observations.map((line) => `Maintenance: ${line}`));

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

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function enqueueDeploymentRecord(payload: Record<string, unknown>, deploymentId: string) {
  ensureDir(DEPLOY_QUEUE_DIR);
  const target = path.join(DEPLOY_QUEUE_DIR, `${deploymentId}.json`);
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

async function runMagentoMaintenance(environmentId: number, mode: 'enable' | 'disable'): Promise<RunbookResult> {
  const runbookId = mode === 'enable' ? 'magento_maintenance_enable' : 'magento_maintenance_disable';
  const hasAdmin = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm-admin')));
  const targetService = hasAdmin ? 'php-fpm-admin' : 'php-fpm';
  const serviceFullName = envServiceName(environmentId, targetService);
  if (!(await inspectServiceSpec(serviceFullName))) {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'php-fpm service not found.',
      observations: [`Missing service: ${serviceFullName}`],
    };
  }

  const cmd = mode === 'enable'
    ? 'bin/magento maintenance:enable --no-interaction'
    : 'bin/magento maintenance:disable --no-interaction';

  const job = await runServiceJob(environmentId, targetService, `maintenance-${mode}`, `cd /var/www/html/magento && ${cmd}`, { timeout_ms: 90_000 });
  const ok = job.ok;
  return {
    runbook_id: runbookId,
    status: ok ? 'ok' : 'failed',
    summary: ok ? `Magento maintenance mode ${mode}d.` : `Magento maintenance mode ${mode} failed.`,
    observations: [
      `Service: ${serviceFullName}`,
      job.node ? `Node: ${job.node}` : '',
      job.logs.trim() ? `Logs: ${tailLines(job.logs.trim(), 30)}` : '',
      ok ? '' : `Error: ${job.error || job.state}`,
    ].filter(Boolean),
    remediation: { attempted: true, actions: [`Magento maintenance:${mode}`] },
    data: { service: serviceFullName, ok, state: job.state },
  };
}

async function runMagentoCommand(
  environmentId: number,
  command: string,
  jobPrefix: string,
  timeoutMs = 90_000
): Promise<{ ok: boolean; logs: string; error?: string; state: string; service: string; node?: string }> {
  const hasAdmin = Boolean(await inspectServiceSpec(envServiceName(environmentId, 'php-fpm-admin')));
  const targetService = hasAdmin ? 'php-fpm-admin' : 'php-fpm';
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

  const activeDeploy = await runDeployActiveSummary(environmentId);
  if (activeDeploy.status === 'warning') {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Deploy is active; teardown aborted.',
      observations: activeDeploy.observations,
    };
  }

  const maintenance = await runMagentoMaintenance(environmentId, 'enable');
  observations.push(`Maintenance: ${maintenance.summary}`);
  observations.push(...maintenance.observations.map((line) => `Maintenance: ${line}`));
  if (maintenance.status !== 'ok') {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Failed to enable maintenance mode; teardown aborted.',
      observations,
    };
  }

  const cacheFlush = await runMagentoCommand(environmentId, 'php bin/magento cache:flush --no-interaction', 'cache-flush', 120_000);
  observations.push(`Cache flush: ${cacheFlush.ok ? 'ok' : 'failed'}`);
  if (cacheFlush.logs.trim()) {
    observations.push(`Cache flush logs: ${tailLines(cacheFlush.logs.trim(), 20)}`);
  }
  if (!cacheFlush.ok) {
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

  const maintenanceStatus = await runMagentoCommand(environmentId, 'php bin/magento maintenance:status --no-interaction', 'maintenance-status', 60_000);
  const maintenanceOutput = maintenanceStatus.logs.toLowerCase();
  const maintenanceEnabled = maintenanceStatus.ok
    && maintenanceOutput.includes('enabled')
    && !maintenanceOutput.includes('disabled');
  observations.push(`Maintenance status: ${maintenanceEnabled ? 'enabled' : 'not enabled'}`);
  if (!maintenanceStatus.ok || !maintenanceEnabled) {
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

  const r2 = resolveR2Context(environmentId);
  if (!r2) {
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
    const dumpInner = [
      'set -euo pipefail',
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

    const zstdResult = await runCommand('zstd', ['-19', '-f', '-o', zstPath, dumpPath], 10 * 60_000);
    if (zstdResult.code !== 0) {
      const output = (zstdResult.stderr || zstdResult.stdout || '').trim();
      throw new Error(output ? `zstd failed: ${output}` : 'zstd failed.');
    }

    const ageResult = await runCommand('age', ['-R', publicKeyPath, '-o', agePath, zstPath], 60_000);
    if (ageResult.code !== 0) {
      const output = (ageResult.stderr || ageResult.stdout || '').trim();
      throw new Error(output ? `age encryption failed: ${output}` : 'age encryption failed.');
    }

    await uploadArtifact(r2, backupObject, agePath);
    actions.push(backupBucket ? `Uploaded backup to ${backupBucket}/${backupObject}` : `Uploaded backup to ${backupObject}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const maintenanceOff = await runMagentoMaintenance(environmentId, 'disable');
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
  const stackRemove = await runCommand('docker', ['stack', 'rm', stackName], 60_000);
  if (stackRemove.code === 0) {
    actions.push(`Removed stack ${stackName}`);
  } else {
    const output = (stackRemove.stderr || stackRemove.stdout || '').trim();
    const missing = output.toLowerCase().includes('nothing found') || output.toLowerCase().includes('not found');
    if (!missing) {
      return {
        runbook_id: runbookId,
        status: 'failed',
        summary: 'Failed to remove environment stack.',
        observations: [output || `stack rm failed for ${stackName}`],
      };
    }
    observations.push(`Stack ${stackName} already removed.`);
  }

  const wait = await waitForEnvironmentServicesGone(environmentId, 180_000);
  if (!wait.ok) {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'Environment services did not stop in time.',
      observations: wait.remaining.length ? [`Remaining services: ${wait.remaining.join(', ')}`] : [],
    };
  }
  actions.push('All environment services removed.');

  const volumes = await removeEnvironmentVolumes(environmentId);
  if (volumes.removed.length) {
    actions.push(`Removed volumes: ${volumes.removed.join(', ')}`);
  }
  if (volumes.failed.length) {
    observations.push(`Failed to remove volumes: ${volumes.failed.join(', ')}`);
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
};
