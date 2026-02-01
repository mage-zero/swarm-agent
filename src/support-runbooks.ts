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

function deriveHealth(status: string) {
  const lower = status.toLowerCase();
  if (lower.includes('unhealthy')) return 'unhealthy';
  if (lower.includes('healthy')) return 'healthy';
  if (lower.includes('up')) return 'up';
  return 'down';
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
