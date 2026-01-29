import crypto from 'crypto';
import fs from 'fs';
import { spawn } from 'child_process';
import { buildSignature } from './node-hmac.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DOCKER_TIMEOUT_MS = Number(process.env.MZ_RUNBOOK_TIMEOUT_MS || 15000);

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
    id: 'php_fpm_health',
    name: 'PHP-FPM health check',
    description: 'Check php-fpm container status and health.',
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
  } | null;
  const runbookId = String(body?.runbook_id || '').trim();
  const environmentId = Number(body?.environment_id || 0);
  if (!runbookId || !environmentId) {
    return { error: 'missing_parameters', status: 400 };
  }
  switch (runbookId) {
    case 'php_fpm_health':
      return runPhpFpmHealth(environmentId);
    case 'magento_var_permissions':
      return runVarPermissions(environmentId);
    case 'proxysql_ready':
      return runProxySqlReady(environmentId);
    case 'dns_cloudflared_ingress':
      return runCloudflared(environmentId);
    case 'container_restart_summary':
      return runRestartSummary(environmentId);
    case 'proxysql_restart':
      return runServiceRestart(environmentId, '_proxysql', 'proxysql_restart', 'ProxySQL');
    case 'cloudflared_restart':
      return runServiceRestart(environmentId, ['cloudflared', '_tunnel'], 'cloudflared_restart', 'Cloudflared');
    default:
      return { error: 'unknown_runbook', status: 404 };
  }
}

export function createRunbookToken(): string {
  return crypto.randomUUID();
}
