import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { buildSignature } from './node-hmac.js';
import { getDeployPauseFilePath, isDeployPaused, readDeployPausedAt, setDeployPaused } from './deploy-pause.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DOCKER_TIMEOUT_MS = Number(process.env.MZ_RUNBOOK_TIMEOUT_MS || 15000);
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_FAILED_DIR = path.join(DEPLOY_QUEUE_DIR, 'failed');
const DEPLOY_PROCESSING_DIR = path.join(DEPLOY_QUEUE_DIR, 'processing');
const DEPLOY_WORK_DIR = path.join(DEPLOY_QUEUE_DIR, 'work');
const DEPLOY_META_DIR = path.join(DEPLOY_QUEUE_DIR, 'meta');
const DEPLOY_HISTORY_FILE = process.env.MZ_DEPLOY_HISTORY_FILE || path.join(DEPLOY_META_DIR, 'history.json');
const DEPLOY_RECORD_FILENAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/i;
const DEPLOY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
];

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

function runCommand(command: string, args: string[], timeoutMs = DOCKER_TIMEOUT_MS): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

type SwarmServiceSecret = {
  file_name: string;
  secret_name: string;
};

type SwarmServiceNetwork = {
  name: string;
  aliases: string[];
};

type SwarmServiceMount = {
  type: string;
  source: string;
  target: string;
  read_only: boolean;
};

type SwarmServiceSpecSummary = {
  service_name: string;
  image: string;
  networks: SwarmServiceNetwork[];
  secrets: SwarmServiceSecret[];
  mounts: SwarmServiceMount[];
};

const networkNameCache = new Map<string, string>();

async function getNetworkName(networkId: string): Promise<string | null> {
  const cached = networkNameCache.get(networkId);
  if (cached) return cached;
  const result = await runCommand('docker', ['network', 'inspect', networkId, '--format', '{{.Name}}'], 12_000);
  if (result.code !== 0) return null;
  const name = result.stdout.trim();
  if (!name) return null;
  networkNameCache.set(networkId, name);
  return name;
}

async function inspectServiceSpec(serviceName: string): Promise<SwarmServiceSpecSummary | null> {
  const result = await runCommand('docker', ['service', 'inspect', serviceName, '--format', '{{json .}}'], 12_000);
  if (result.code !== 0) return null;
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = JSON.parse(result.stdout.trim()) as Record<string, unknown>;
  } catch {
    parsed = null;
  }
  if (!parsed || typeof parsed !== 'object') return null;

  const spec = (parsed as any).Spec as Record<string, unknown> | undefined;
  const task = (spec as any)?.TaskTemplate as Record<string, unknown> | undefined;
  const containerSpec = (task as any)?.ContainerSpec as Record<string, unknown> | undefined;
  const image = String((containerSpec as any)?.Image || '').trim();
  if (!image) return null;

  const networksRaw = Array.isArray((task as any)?.Networks) ? (task as any).Networks as Array<Record<string, unknown>> : [];
  const networks: SwarmServiceNetwork[] = [];
  for (const entry of networksRaw) {
    const targetId = String((entry as any)?.Target || '').trim();
    const aliases = Array.isArray((entry as any)?.Aliases) ? (entry as any).Aliases.map((a: unknown) => String(a || '').trim()).filter(Boolean) : [];
    if (!targetId) continue;
    const networkName = await getNetworkName(targetId);
    if (!networkName) continue;
    networks.push({ name: networkName, aliases });
  }

  const secretsRaw = Array.isArray((containerSpec as any)?.Secrets) ? (containerSpec as any).Secrets as Array<Record<string, unknown>> : [];
  const secrets: SwarmServiceSecret[] = [];
  for (const entry of secretsRaw) {
    const file = (entry as any)?.File as Record<string, unknown> | undefined;
    const fileName = String((file as any)?.Name || '').trim();
    const secretName = String((entry as any)?.SecretName || '').trim();
    if (!fileName || !secretName) continue;
    secrets.push({ file_name: fileName, secret_name: secretName });
  }

  const mountsRaw = Array.isArray((containerSpec as any)?.Mounts) ? (containerSpec as any).Mounts as Array<Record<string, unknown>> : [];
  const mounts: SwarmServiceMount[] = [];
  for (const entry of mountsRaw) {
    const type = String((entry as any)?.Type || '').trim();
    const source = String((entry as any)?.Source || '').trim();
    const target = String((entry as any)?.Target || '').trim();
    const readOnly = Boolean((entry as any)?.ReadOnly);
    if (!type || !source || !target) continue;
    mounts.push({ type, source, target, read_only: readOnly });
  }

  return {
    service_name: serviceName,
    image,
    networks,
    secrets,
    mounts,
  };
}

type SwarmJobOptions = {
  name: string;
  image: string;
  command: string[];
  networks?: string[];
  secrets?: Array<{ source: string; target: string }>;
  mounts?: Array<{ type: string; source: string; target: string; read_only?: boolean }>;
  env?: Record<string, string>;
  constraints?: string[];
  timeout_ms?: number;
};

async function runSwarmJob(options: SwarmJobOptions): Promise<{ ok: boolean; state: string; logs: string; error?: string; details?: string[] }> {
  const timeoutMs = options.timeout_ms ?? 5 * 60_000;
  const args: string[] = [
    'service',
    'create',
    '--quiet',
    '--name',
    options.name,
    '--restart-condition',
    'none',
    '--mode',
    'replicated-job',
    '--replicas',
    '1',
  ];

  for (const network of options.networks || []) {
    args.push('--network', network);
  }

  for (const secret of options.secrets || []) {
    args.push('--secret', `source=${secret.source},target=${secret.target}`);
  }

  for (const mount of options.mounts || []) {
    const readOnly = mount.read_only ? ',readonly' : '';
    args.push('--mount', `type=${mount.type},src=${mount.source},dst=${mount.target}${readOnly}`);
  }

  for (const [key, value] of Object.entries(options.env || {})) {
    args.push('--env', `${key}=${value}`);
  }

  for (const constraint of options.constraints || []) {
    args.push('--constraint', constraint);
  }

  args.push(options.image, ...options.command);

  const created = await runCommand('docker', args, 30_000);
  if (created.code !== 0) {
    return {
      ok: false,
      state: 'create_failed',
      logs: '',
      error: created.stderr.trim() || created.stdout.trim() || 'failed to create swarm job',
    };
  }

  const startedAt = Date.now();
  const details: string[] = [];
  let finalState = 'unknown';
  while (Date.now() - startedAt < timeoutMs) {
    const ps = await runCommand('docker', ['service', 'ps', options.name, '--no-trunc', '--format', '{{.CurrentState}}|{{.Error}}'], 12_000);
    const lines = ps.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
    if (lines.length) {
      details.splice(0, details.length, ...lines.slice(0, 5));
      const [stateRaw] = (lines[0] || '').split('|');
      const stateWord = (stateRaw || '').trim().split(' ')[0] || '';
      if (stateWord) {
        finalState = stateWord;
      }
      if (stateWord === 'Complete' || stateWord === 'Failed' || stateWord === 'Rejected') {
        break;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  const logResult = await runCommand('docker', ['service', 'logs', options.name, '--raw', '--no-task-ids'], 30_000);
  const logs = (logResult.stdout || logResult.stderr || '').trim();

  await runCommand('docker', ['service', 'rm', options.name], 12_000);

  const ok = finalState === 'Complete';
  if (!ok && finalState === 'unknown') {
    return {
      ok: false,
      state: 'timeout',
      logs,
      error: `swarm job timed out after ${timeoutMs}ms`,
      details,
    };
  }

  return {
    ok,
    state: finalState,
    logs,
    error: ok ? undefined : `swarm job ended with state: ${finalState}`,
    details,
  };
}

async function listEnvironmentContainers(environmentId: number) {
  const filter = `name=mz-env-${environmentId}_`;
  const result = await runCommand('docker', ['ps', '--filter', filter, '--format', '{{.ID}}|{{.Names}}|{{.Status}}']);
  const entries = result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, name, status] = line.split('|');
      return { id, name, status };
    });
  return entries;
}

async function listEnvironmentServices(environmentId: number) {
  const result = await runCommand('docker', ['service', 'ls', '--format', '{{.ID}}|{{.Name}}|{{.Replicas}}']);
  const entries = result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, name, replicas] = line.split('|');
      return { id, name, replicas };
    })
    .filter((entry) => entry.name.includes(`mz-env-${environmentId}_`));
  return entries;
}

async function findContainer(environmentId: number, includes: string) {
  const containers = await listEnvironmentContainers(environmentId);
  return containers.find((entry) => entry.name.includes(includes));
}

async function findService(environmentId: number, includes: string) {
  const services = await listEnvironmentServices(environmentId);
  return services.find((entry) => entry.name.includes(includes));
}

async function findContainerForService(environmentId: number, serviceName: string) {
  return findContainer(environmentId, `_${serviceName}.`);
}

function deriveHealth(status: string) {
  const lower = status.toLowerCase();
  if (lower.includes('unhealthy')) return 'unhealthy';
  if (lower.includes('healthy')) return 'healthy';
  if (lower.includes('up')) return 'up';
  return 'down';
}

function escapeForShellDoubleQuotes(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, ' ');
}

async function runMariaDb(containerId: string, sql: string, timeoutMs = 60_000) {
  const safeSql = escapeForShellDoubleQuotes(sql);
  return runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-lc',
    [
      'set -e',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -N -B -e "${safeSql}"`,
    ].join(' && '),
  ], timeoutMs);
}

async function runMariaDbRaw(containerId: string, sql: string, timeoutMs = 60_000) {
  const safeSql = escapeForShellDoubleQuotes(sql);
  return runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-lc',
    [
      'set -e',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -e "${safeSql}"`,
    ].join(' && '),
  ], timeoutMs);
}

async function getReadOnly(containerId: string): Promise<boolean | null> {
  const result = await runMariaDb(containerId, 'SELECT @@GLOBAL.read_only;');
  if (result.code !== 0) return null;
  const value = result.stdout.trim();
  if (value === '0') return false;
  if (value === '1') return true;
  return null;
}

async function setReadOnly(containerId: string, enabled: boolean): Promise<boolean> {
  const value = enabled ? 1 : 0;
  const result = await runMariaDbRaw(containerId, `SET GLOBAL read_only=${value};`);
  return result.code === 0;
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

async function getSlaveStatus(containerId: string): Promise<SlaveStatus | null> {
  const result = await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-lc',
    [
      'set -e',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      // SHOW SLAVE STATUS returns 0 rows when not configured; \G makes it easier to parse.
      'mariadb -uroot -p"$ROOT_PASS" -e "SHOW SLAVE STATUS\\G" || true',
    ].join(' && '),
  ], 60_000);
  if (result.code !== 0) {
    return null;
  }
  return parseSlaveStatus(result.stdout);
}

async function waitForReplicaCaughtUp(replicaId: string, timeoutMs = 120_000): Promise<{ ok: boolean; lagSeconds: number | null; note?: string }> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const status = await getSlaveStatus(replicaId);
    if (!status) {
      return { ok: false, lagSeconds: null, note: 'replica not configured (no slave status)' };
    }
    const ioRunning = status.Slave_IO_Running || '';
    const sqlRunning = status.Slave_SQL_Running || '';
    const secondsRaw = status.Seconds_Behind_Master ?? '';
    const lag = secondsRaw === '' || secondsRaw.toUpperCase() === 'NULL' ? null : Number.parseInt(secondsRaw, 10);
    const lagOk = lag === 0;
    const runningOk = ioRunning.toLowerCase() === 'yes' && sqlRunning.toLowerCase() === 'yes';
    if (runningOk && lagOk) {
      return { ok: true, lagSeconds: lag };
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { ok: false, lagSeconds: null, note: 'timeout waiting for replica catch-up' };
}

async function stopAndResetSlave(containerId: string): Promise<boolean> {
  const result = await runMariaDbRaw(containerId, 'STOP SLAVE; RESET SLAVE ALL;');
  if (result.code === 0) return true;
  const stderr = (result.stderr || '').toLowerCase();
  if (
    stderr.includes('no slave')
    || stderr.includes('not a slave')
    || stderr.includes('slave thread')
    || stderr.includes('error 1198')
  ) {
    return true;
  }
  return false;
}

async function configureAsReplica(containerId: string, masterHost: string, replicaUser: string): Promise<boolean> {
  const safeHost = masterHost.replace(/'/g, "''");
  const safeUser = replicaUser.replace(/'/g, "''");
  const passRef = '${REPL_PASS}';
  const sql = `CHANGE MASTER TO MASTER_HOST='${safeHost}', MASTER_PORT=3306, MASTER_USER='${safeUser}', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;
  const safeSql = escapeForShellDoubleQuotes(sql);
  const result = await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-lc',
    [
      'set -e',
      'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -e "${safeSql}"`,
    ].join(' && '),
  ], 90_000);
  return result.code === 0;
}

async function scaleEnvironmentService(environmentId: number, serviceName: string, replicas: number): Promise<{ ok: boolean; note?: string }> {
  const target = `mz-env-${environmentId}_${serviceName}=${replicas}`;
  const result = await runCommand('docker', ['service', 'scale', target], 60_000);
  if (result.code !== 0) {
    return { ok: false, note: result.stderr.trim() || result.stdout.trim() || `failed to scale ${target}` };
  }
  return { ok: true };
}

async function getServiceTaskNode(environmentId: number, serviceName: string): Promise<string | null> {
  const service = `mz-env-${environmentId}_${serviceName}`;
  const result = await runCommand('docker', ['service', 'ps', service, '--no-trunc', '--format', '{{.Node}}|{{.CurrentState}}'], 12_000);
  if (result.code !== 0) return null;
  const lines = result.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  const running = lines.find((line) => line.includes('|Running')) || lines[0] || '';
  const node = running.split('|')[0]?.trim() || '';
  return node || null;
}

function pickSecretName(spec: SwarmServiceSpecSummary, fileName: string): string | null {
  const match = spec.secrets.find((entry) => entry.file_name === fileName);
  return match?.secret_name || null;
}

function pickNetworkName(spec: SwarmServiceSpecSummary, requiredAlias?: string): string | null {
  if (requiredAlias) {
    const match = spec.networks.find((net) => net.aliases.includes(requiredAlias));
    if (match?.name) return match.name;
  }
  return spec.networks[0]?.name || null;
}

function buildJobName(prefix: string, environmentId: number) {
  const suffix = crypto.randomBytes(3).toString('hex');
  const raw = `mz-rb-${prefix}-${environmentId}-${suffix}`.toLowerCase();
  return raw.replace(/[^a-z0-9-]/g, '-').slice(0, 63);
}

async function waitForServiceRunning(serviceFullName: string, timeoutMs = 180_000): Promise<{ ok: boolean; state?: string; note?: string }> {
  const startedAt = Date.now();
  let lastState = '';
  while (Date.now() - startedAt < timeoutMs) {
    const ps = await runCommand('docker', ['service', 'ps', serviceFullName, '--no-trunc', '--format', '{{.CurrentState}}|{{.Error}}'], 12_000);
    if (ps.code === 0) {
      const lines = ps.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
      const state = (lines.find((l) => l.includes('Running')) || lines[0] || '').split('|')[0]?.trim() || '';
      lastState = state || lastState;
      if (state.startsWith('Running')) {
        return { ok: true, state };
      }
      if (state.startsWith('Failed') || state.startsWith('Rejected')) {
        const errorText = (lines[0] || '').split('|')[1]?.trim() || '';
        return { ok: false, state, note: errorText || 'service task failed' };
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { ok: false, state: lastState || undefined, note: `timeout after ${timeoutMs}ms` };
}

async function waitForServiceNotRunning(serviceFullName: string, timeoutMs = 120_000): Promise<{ ok: boolean; note?: string }> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const ps = await runCommand('docker', ['service', 'ps', serviceFullName, '--no-trunc', '--format', '{{.CurrentState}}'], 12_000);
    if (ps.code === 0) {
      const lines = ps.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
      const hasRunning = lines.some((line) => line.startsWith('Running'));
      if (!hasRunning) return { ok: true };
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { ok: false, note: `timeout after ${timeoutMs}ms` };
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

function buildDbProbeScript() {
  return [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    'primary="database"',
    'replica="database-replica"',
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
  const container = await findContainerForService(environmentId, 'proxysql');
  if (!container) return [];
  const result = await runCommand('docker', [
    'exec',
    container.id,
    'sh',
    '-lc',
    'mysql -h 127.0.0.1 -P 6032 -u admin -padmin -N -B -e "SELECT hostgroup_id,hostname,status FROM runtime_mysql_servers ORDER BY hostgroup_id,hostname;" 2>/dev/null || true',
  ], 12_000);
  if (result.code !== 0) return [];
  return result.stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const [hg, hostname, status] = line.split(/\s+/);
      return { hostgroup: Number(hg || 0), hostname: String(hostname || ''), status: String(status || '') };
    })
    .filter((row) => Number.isFinite(row.hostgroup) && row.hostgroup > 0 && row.hostname !== '');
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

async function runPhpFpmHealth(environmentId: number): Promise<RunbookResult> {
  const container = await findContainer(environmentId, '_php-fpm');
  if (!container) {
    return {
      runbook_id: 'php_fpm_health',
      status: 'failed',
      summary: 'php-fpm container not found.',
      observations: ['No php-fpm container matched for this environment.'],
    };
  }
  const health = deriveHealth(container.status);
  const ok = health === 'healthy' || health === 'up';
  return {
    runbook_id: 'php_fpm_health',
    status: ok ? 'ok' : 'warning',
    summary: `php-fpm status: ${container.status}`,
    observations: [`Container ${container.name} is ${container.status}`],
    data: { container },
  };
}

async function runVarnishReady(environmentId: number): Promise<RunbookResult> {
  const container = await findContainer(environmentId, '_varnish');
  if (!container) {
    return {
      runbook_id: 'varnish_ready',
      status: 'failed',
      summary: 'Varnish container not found.',
      observations: ['No varnish container matched for this environment.'],
    };
  }

  const health = deriveHealth(container.status);
  const ok = health === 'healthy' || health === 'up';
  const observations: string[] = [`Container ${container.name} is ${container.status}`];
  let probe = null as null | { code: number; stdout: string; stderr: string };

  // Best-effort probe: from php-fpm container, hit Varnish /mz-healthz if curl/wget exists.
  const probeContainer = await findContainer(environmentId, '_php-fpm');
  if (probeContainer) {
    probe = await runCommand('docker', [
      'exec',
      probeContainer.id,
      'sh',
      '-lc',
      "if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 5 http://varnish/mz-healthz >/dev/null; exit $?; fi; if command -v wget >/dev/null 2>&1; then wget -qO- --timeout=5 http://varnish/mz-healthz >/dev/null; exit $?; fi; exit 0",
    ], 8000);
    if (probe.code === 0) {
      observations.push('Probe: http://varnish/mz-healthz reachable from php-fpm.');
    } else {
      observations.push('Probe: http://varnish/mz-healthz not reachable from php-fpm.');
      if (probe.stderr?.trim()) {
        observations.push(`Probe stderr: ${probe.stderr.trim()}`);
      }
    }
  } else {
    observations.push('Probe skipped: php-fpm container not found.');
  }

  const finalOk = ok && (!probe || probe.code === 0);
  return {
    runbook_id: 'varnish_ready',
    status: finalOk ? 'ok' : ok ? 'warning' : 'failed',
    summary: finalOk ? `Varnish status: ${container.status}` : `Varnish not ready: ${container.status}`,
    observations,
    data: { container, probe: probe ? { code: probe.code } : null },
  };
}

async function runVarPermissions(environmentId: number): Promise<RunbookResult> {
  const container = await findContainer(environmentId, '_php-fpm');
  if (!container) {
    return {
      runbook_id: 'magento_var_permissions',
      status: 'failed',
      summary: 'php-fpm container not found.',
      observations: ['Unable to locate php-fpm container to inspect permissions.'],
    };
  }
  const checkCmd = ['exec', container.id, 'sh', '-lc', 'test -w /var/www/html/var && test -w /var/www/html/var/log && test -w /var/www/html/var/report'];
  const checkResult = await runCommand('docker', checkCmd);
  const actions: string[] = [];
  if (checkResult.code === 0) {
    return {
      runbook_id: 'magento_var_permissions',
      status: 'ok',
      summary: 'Magento var directories are writable.',
      observations: ['Permissions check passed.'],
      data: { container: container.name },
      remediation: { attempted: false, actions },
    };
  }

  const fixCmd = [
    'exec',
    container.id,
    'sh',
    '-lc',
    'chown -R www-data:www-data /var/www/html/var && chmod -R g+rwX /var/www/html/var',
  ];
  const fixResult = await runCommand('docker', fixCmd);
  actions.push('Applied chown/chmod to /var/www/html/var');

  const recheck = await runCommand('docker', checkCmd);
  const resolved = recheck.code === 0;
  return {
    runbook_id: 'magento_var_permissions',
    status: resolved ? 'ok' : 'warning',
    summary: resolved ? 'Permissions fixed.' : 'Permissions still failing after remediation.',
    observations: [
      resolved ? 'Var directories are now writable.' : 'Permissions check still failing.',
      fixResult.stderr ? `Remediation stderr: ${fixResult.stderr.trim()}` : '',
    ].filter(Boolean),
    data: { container: container.name },
    remediation: { attempted: true, actions },
  };
}

async function runMediaPermissions(environmentId: number): Promise<RunbookResult> {
  const container = (await findContainer(environmentId, '_php-fpm-admin')) ?? (await findContainer(environmentId, '_php-fpm'));
  if (!container) {
    return {
      runbook_id: 'magento_media_permissions',
      status: 'failed',
      summary: 'php-fpm container not found.',
      observations: ['Unable to locate php-fpm container to inspect permissions.'],
    };
  }

  const base = '/var/www/html/magento/pub/media';
  const checkCmd = ['exec', container.id, 'sh', '-lc', `test -w ${base} && test -w ${base}/captcha`];
  const checkResult = await runCommand('docker', checkCmd);
  const actions: string[] = [];
  if (checkResult.code === 0) {
    return {
      runbook_id: 'magento_media_permissions',
      status: 'ok',
      summary: 'Magento pub/media is writable.',
      observations: ['Permissions check passed.'],
      data: { container: container.name },
      remediation: { attempted: false, actions },
    };
  }

  const fixCmd = [
    'exec',
    container.id,
    'sh',
    '-lc',
    `mkdir -p ${base}/captcha/admin && chown -R www-data:www-data ${base} && chmod -R 775 ${base}`,
  ];
  const fixResult = await runCommand('docker', fixCmd);
  actions.push('Applied mkdir/chown/chmod to /var/www/html/magento/pub/media');

  const recheck = await runCommand('docker', checkCmd);
  const resolved = recheck.code === 0;
  return {
    runbook_id: 'magento_media_permissions',
    status: resolved ? 'ok' : 'warning',
    summary: resolved ? 'Permissions fixed.' : 'Permissions still failing after remediation.',
    observations: [
      resolved ? 'pub/media is now writable.' : 'Permissions check still failing.',
      fixResult.stderr ? `Remediation stderr: ${fixResult.stderr.trim()}` : '',
    ].filter(Boolean),
    data: { container: container.name },
    remediation: { attempted: true, actions },
  };
}

async function runProxySqlReady(environmentId: number): Promise<RunbookResult> {
  const container = await findContainer(environmentId, '_proxysql');
  if (!container) {
    return {
      runbook_id: 'proxysql_ready',
      status: 'failed',
      summary: 'ProxySQL container not found.',
      observations: ['No ProxySQL container matched for this environment.'],
    };
  }
  const health = deriveHealth(container.status);
  const ok = health === 'healthy' || health === 'up';
  return {
    runbook_id: 'proxysql_ready',
    status: ok ? 'ok' : 'warning',
    summary: `ProxySQL status: ${container.status}`,
    observations: [`Container ${container.name} is ${container.status}`],
    data: { container },
  };
}

async function runCloudflared(environmentId: number): Promise<RunbookResult> {
  const containers = await listEnvironmentContainers(environmentId);
  const container = containers.find((entry) => entry.name.includes('cloudflared') || entry.name.includes('_tunnel'));
  if (!container) {
    return {
      runbook_id: 'dns_cloudflared_ingress',
      status: 'failed',
      summary: 'Cloudflared container not found.',
      observations: ['No cloudflared container matched for this environment.'],
    };
  }
  const health = deriveHealth(container.status);
  const ok = health === 'healthy' || health === 'up';
  return {
    runbook_id: 'dns_cloudflared_ingress',
    status: ok ? 'ok' : 'warning',
    summary: `Cloudflared status: ${container.status}`,
    observations: [`Container ${container.name} is ${container.status}`],
    data: { container },
  };
}

async function runRestartSummary(environmentId: number): Promise<RunbookResult> {
  const containers = await listEnvironmentContainers(environmentId);
  const restarts = containers.filter((entry) => entry.status.toLowerCase().includes('restarting'));
  const unhealthy = containers.filter((entry) => entry.status.toLowerCase().includes('unhealthy'));
  const ok = restarts.length === 0 && unhealthy.length === 0;
  const observations: string[] = [];
  if (restarts.length) {
    observations.push(`Restarting: ${restarts.map((entry) => entry.name).join(', ')}`);
  }
  if (unhealthy.length) {
    observations.push(`Unhealthy: ${unhealthy.map((entry) => entry.name).join(', ')}`);
  }
  if (!observations.length) {
    observations.push('No restarting or unhealthy containers detected.');
  }
  return {
    runbook_id: 'container_restart_summary',
    status: ok ? 'ok' : 'warning',
    summary: ok ? 'No restart issues detected.' : 'Container restarts or unhealthy states detected.',
    observations,
    data: { count: containers.length },
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
  let service = null as Awaited<ReturnType<typeof findService>> | null;
  for (const pattern of patterns) {
    service = await findService(environmentId, pattern);
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
  const result = await runCommand('docker', ['service', 'update', '--force', service.id]);
  if (result.code === 0) {
    actions.push(`Forced update for ${service.name}`);
  } else {
    actions.push(`Failed to update ${service.name}`);
  }
  return {
    runbook_id: runbookId,
    status: result.code === 0 ? 'ok' : 'warning',
    summary: result.code === 0 ? `${label} restart triggered.` : `${label} restart failed.`,
    observations: [
      `Service: ${service.name} (${service.replicas || 'replicas unknown'})`,
      result.stderr ? `stderr: ${result.stderr.trim()}` : '',
    ].filter(Boolean),
    data: { service },
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
  const job = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(), { timeout_ms: 60_000 });
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
  const beforeJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(), { timeout_ms: 60_000 });
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
  const passRef = '${REPL_PASS}';
  const ensureReplicaUserSql = [
    `CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    `ALTER USER 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';",
    'FLUSH PRIVILEGES;',
  ].join(' ');
  const changeMasterSql = `CHANGE MASTER TO MASTER_HOST='database', MASTER_PORT=3306, MASTER_USER='replica', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;

  if (!beforeSlave || beforeIo !== 'yes' || beforeSql !== 'yes') {
    const configScript = [
      'set -e',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
      'i=0; until mariadb -uroot -p"$ROOT_PASS" -h database -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "primary not ready" >&2; exit 1; fi; sleep 1; done',
      'i=0; until mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done',
      `mariadb -uroot -p"$ROOT_PASS" -h database -e "${escapeForShellDoubleQuotes(ensureReplicaUserSql)}"`,
      `mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "${escapeForShellDoubleQuotes(changeMasterSql)}"`,
      'mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "SET GLOBAL read_only=1;" || true',
      'echo "CONFIGURED=1"',
    ].join(' && ');
    const configJob = await runDatabaseJob(environmentId, 'db-enable', configScript, { include_replication_secret: true, timeout_ms: 120_000 });
    actions.push(configJob.ok ? 'Configured replication on database-replica' : 'Failed to configure replication on database-replica');
    if (!configJob.ok) {
      observations.push(`Configuration job failed: ${configJob.error || configJob.state}`);
    }
  }

  const afterJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(), { timeout_ms: 60_000 });
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
  const probeJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(), { timeout_ms: 60_000 });
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
  const passRef = '${REPL_PASS}';
  const ensureReplicaUserSql = [
    `CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    `ALTER USER 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';",
    'FLUSH PRIVILEGES;',
  ].join(' ');
  const changeMasterSql = `CHANGE MASTER TO MASTER_HOST='database', MASTER_PORT=3306, MASTER_USER='replica', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;

  const repairScript = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
    'i=0; until mariadb -uroot -p"$ROOT_PASS" -h database -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "primary not ready" >&2; exit 1; fi; sleep 1; done',
    'i=0; until mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 30 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done',
    `mariadb -uroot -p"$ROOT_PASS" -h database -e "${escapeForShellDoubleQuotes(ensureReplicaUserSql)}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "STOP SLAVE; RESET SLAVE ALL;" || true',
    `mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "${escapeForShellDoubleQuotes(changeMasterSql)}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "SET GLOBAL read_only=1;" || true',
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
  const afterJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(), { timeout_ms: 60_000 });
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
  const passRef = '${REPL_PASS}';
  const ensureReplicaUserSql = [
    `CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    `ALTER USER 'replica'@'%' IDENTIFIED BY '${passRef}';`,
    "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';",
    'FLUSH PRIVILEGES;',
  ].join(' ');
  const changeMasterSql = `CHANGE MASTER TO MASTER_HOST='database', MASTER_PORT=3306, MASTER_USER='replica', MASTER_PASSWORD='${passRef}', MASTER_USE_GTID=slave_pos; START SLAVE;`;

  const seedScript = [
    'set -e',
    'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
    'REPL_PASS="$(cat /run/secrets/db_replication_password)"',
    // Wait for primary + replica to accept connections.
    'i=0; until mariadb -uroot -p"$ROOT_PASS" -h database -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 60 ]; then echo "primary not ready" >&2; exit 1; fi; sleep 1; done',
    'i=0; until mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); if [ "$i" -gt 60 ]; then echo "replica not ready" >&2; exit 1; fi; sleep 1; done',
    // Stop any auto-started replication from the init script before importing.
    'mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "STOP SLAVE; RESET SLAVE ALL;" || true',
    // Ensure replication user exists on primary.
    `mariadb -uroot -p"$ROOT_PASS" -h database -e "${escapeForShellDoubleQuotes(ensureReplicaUserSql)}"`,
    // Import snapshot (no binlogging) so replica GTID sequence does not jump ahead of primary.
    'mariadb-dump -uroot -p"$ROOT_PASS" -h database --single-transaction --quick --routines --events --triggers --hex-blob --gtid --master-data=1 --all-databases | mariadb -uroot -p"$ROOT_PASS" -h database-replica --init-command="SET SESSION sql_log_bin=0;"',
    // Configure and start replication.
    `mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "${escapeForShellDoubleQuotes(changeMasterSql)}"`,
    'mariadb -uroot -p"$ROOT_PASS" -h database-replica -e "SET GLOBAL read_only=1;" || true',
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
  const finalProbeJob = await runDatabaseJob(environmentId, 'db-probe', buildDbProbeScript(), { timeout_ms: 60_000 });
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

  const fromContainer = await findContainerForService(environmentId, fromService);
  const toContainer = await findContainerForService(environmentId, toService);

  if (!fromContainer || !toContainer) {
    return {
      runbook_id: direction === 'to_replica' ? 'db_failover' : 'db_failback',
      status: 'failed',
      summary: 'Database containers not found.',
      observations: [
        fromContainer ? `Found ${fromService}: ${fromContainer.name}` : `Missing ${fromService} container.`,
        toContainer ? `Found ${toService}: ${toContainer.name}` : `Missing ${toService} container.`,
      ],
      remediation: { attempted: false, actions: [] },
    };
  }

  const desiredWriterHost = toService;
  const runbookId = direction === 'to_replica' ? 'db_failover' : 'db_failback';

  // Quick no-op check.
  const toReadOnly = await getReadOnly(toContainer.id);
  const toSlave = await getSlaveStatus(toContainer.id);
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
  const roSet = await setReadOnly(fromContainer.id, true);
  actions.push(roSet ? `Set ${fromService} read_only=ON` : `Failed to set ${fromService} read_only=ON`);

  // Ensure the target (toService) is caught up before promotion.
  const caughtUp = await waitForReplicaCaughtUp(toContainer.id, 180_000);
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
  const stopReplica = await stopAndResetSlave(toContainer.id);
  actions.push(stopReplica ? `Stopped replication on ${toService}` : `Failed to stop replication on ${toService}`);
  const rw = await setReadOnly(toContainer.id, false);
  actions.push(rw ? `Set ${toService} read_only=OFF` : `Failed to set ${toService} read_only=OFF`);

  // Configure the old writer as a replica of the new writer.
  const cleaned = await stopAndResetSlave(fromContainer.id);
  actions.push(cleaned ? `Cleared replication state on ${fromService}` : `Failed to clear replication state on ${fromService}`);
  const configured = await configureAsReplica(fromContainer.id, toService, 'replica');
  actions.push(configured ? `Configured ${fromService} as replica of ${toService}` : `Failed to configure ${fromService} replication`);
  const roAgain = await setReadOnly(fromContainer.id, true);
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
  const container = (await findContainer(environmentId, '_php-fpm-admin')) ?? (await findContainer(environmentId, '_php-fpm'));
  const runbookId = mode === 'enable' ? 'magento_maintenance_enable' : 'magento_maintenance_disable';
  if (!container) {
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: 'php-fpm container not found.',
      observations: ['Unable to locate php-fpm container to run bin/magento maintenance command.'],
    };
  }

  const cmd = mode === 'enable'
    ? 'bin/magento maintenance:enable --no-interaction'
    : 'bin/magento maintenance:disable --no-interaction';

  const result = await runCommand('docker', [
    'exec',
    container.id,
    'sh',
    '-lc',
    `cd /var/www/html/magento && ${cmd}`,
  ], 60_000);

  const ok = result.code === 0;
  return {
    runbook_id: runbookId,
    status: ok ? 'ok' : 'failed',
    summary: ok ? `Magento maintenance mode ${mode}d.` : `Magento maintenance mode ${mode} failed.`,
    observations: [
      `Container: ${container.name}`,
      result.stdout?.trim() ? `stdout: ${tailLines(result.stdout.trim(), 20)}` : '',
      result.stderr?.trim() ? `stderr: ${tailLines(result.stderr.trim(), 20)}` : '',
    ].filter(Boolean),
    remediation: { attempted: true, actions: [`Magento maintenance:${mode}`] },
    data: { container: container.name, code: result.code },
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
  const service = await findService(environmentId, serviceName);
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
};
