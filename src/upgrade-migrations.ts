import fs from 'fs';
import path from 'path';
import { runCommand } from './exec.js';
import { buildNodeHeaders } from './node-hmac.js';
import { bootstrapMonitoringDashboards } from './monitoring-dashboards.js';

export type MigrationContext = {
  environmentId?: number;
  stackId?: number;
  cloudSwarmDir: string;
  mzControlBaseUrl?: string;
  nodeId?: string;
  nodeSecret?: string;
};

export type MigrationFn = (ctx: MigrationContext) => Promise<void>;

type StackSnapshot = {
  stack_type: string;
  dashboards_hostname: string;
};

const CLOUD_SWARM_REPO = process.env.MZ_CLOUD_SWARM_REPO || 'git@github.com:mage-zero/cloud-swarm.git';
const CLOUD_SWARM_KEY_PATH = process.env.MZ_CLOUD_SWARM_KEY_PATH || '/opt/mage-zero/keys/cloud-swarm-deploy';
const DEFAULT_MONITORING_ENV: Record<string, string> = {
  OPENSEARCH_VERSION: '2.12.0',
  APM_SERVER_VERSION: '7.12.1',
  FILEBEAT_VERSION: '7.12.1',
  METRICBEAT_VERSION: '7.12.1',
  MZ_MONITORING_OPENSEARCH_JAVA_OPTS: '-Xms512m -Xmx512m',
  MZ_MONITORING_OPENSEARCH_LIMIT_MEMORY: '1536M',
  MZ_MONITORING_OPENSEARCH_RESERVE_MEMORY: '512M',
};
const MONITORING_DASHBOARDS_REQUIRED = (process.env.MZ_MONITORING_DASHBOARDS_REQUIRED || '0') === '1';

function isMonitoringEligibleStackType(stackType: string): boolean {
  const value = String(stackType || '').trim().toLowerCase();
  return value === 'production' || value === 'performance';
}

function isLoopbackHost(host: string): boolean {
  const value = String(host || '').trim().toLowerCase();
  return value === '127.0.0.1' || value === 'localhost' || value === '::1';
}

async function swarmHasMultipleNodes(): Promise<boolean> {
  const result = await runCommand('docker', ['node', 'ls', '--format', '{{.ID}}'], 12_000);
  if (result.code !== 0) {
    return false;
  }
  const nodes = (result.stdout || '').split('\n').map((line) => line.trim()).filter(Boolean);
  return nodes.length > 1;
}

async function detectWireGuardIpV4(): Promise<string | null> {
  const result = await runCommand('ip', ['-4', 'addr', 'show', 'dev', 'wg0'], 12_000);
  if (result.code !== 0) {
    return null;
  }
  const match = (result.stdout || '').match(/\binet\s+(\d+\.\d+\.\d+\.\d+)\//);
  return match?.[1] || null;
}

async function resolveRegistryPullHost(candidate: string): Promise<string> {
  const trimmed = String(candidate || '').trim();
  if (!trimmed) {
    return '127.0.0.1';
  }
  if (!isLoopbackHost(trimmed)) {
    return trimmed;
  }
  if (!(await swarmHasMultipleNodes())) {
    return trimmed;
  }
  const wgIp = await detectWireGuardIpV4();
  if (wgIp) {
    console.log(`upgrade.migration.registry_pull_host: using WireGuard IP ${wgIp}`);
    return wgIp;
  }
  return trimmed;
}

async function fetchStackSnapshot(ctx: MigrationContext): Promise<StackSnapshot> {
  const baseUrl = ctx.mzControlBaseUrl || '';
  const nodeId = ctx.nodeId || '';
  const nodeSecret = ctx.nodeSecret || '';
  const stackId = Number(ctx.stackId || 0);

  if (!baseUrl || !nodeId || !nodeSecret || !stackId) {
    throw new Error('Missing mz-control connection details for stack snapshot');
  }

  const url = new URL(`/v1/agent/stack/${stackId}`, baseUrl);
  const body = '';
  const headers = buildNodeHeaders('GET', url.pathname, '', body, nodeId, nodeSecret);

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      ...headers,
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Stack snapshot fetch failed: ${response.status} - ${errorBody}`);
  }

  const payload = await response.json() as { stack?: Record<string, unknown> };
  const stack = (payload && typeof payload === 'object' && payload.stack && typeof payload.stack === 'object')
    ? payload.stack
    : {};

  return {
    stack_type: String(stack.stack_type || '').trim(),
    dashboards_hostname: String(stack.dashboards_hostname || '').trim(),
  };
}

async function monitoringStackExists(): Promise<boolean> {
  const result = await runCommand('docker', ['stack', 'ls', '--format', '{{.Name}}'], 15_000);
  if (result.code !== 0) {
    throw new Error(`Unable to list docker stacks: ${result.stderr || result.stdout}`);
  }
  const names = (result.stdout || '').split('\n').map((line) => line.trim()).filter(Boolean);
  return names.includes('mz-monitoring');
}

/**
 * Registry of migration functions keyed by change ID.
 * Each release's changelog.json references change IDs that map to functions here.
 * New migrations are added as the agent gains new capabilities.
 */
const migrations: Record<string, MigrationFn> = {};

function readEnvFile(filePath: string): Record<string, string> {
  if (!fs.existsSync(filePath)) return {};
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const output: Record<string, string> = {};
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const index = trimmed.indexOf('=');
    if (index <= 0) continue;
    const key = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim();
    if (key && value) {
      output[key] = value;
    }
  }
  return output;
}

async function buildMonitoringEnv(cloudSwarmDir: string): Promise<NodeJS.ProcessEnv> {
  const fromFile = readEnvFile(path.join(cloudSwarmDir, 'config', 'versions.env'));
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...fromFile,
  };
  for (const [key, value] of Object.entries(DEFAULT_MONITORING_ENV)) {
    if (!String(env[key] || '').trim()) {
      env[key] = value;
    }
  }
  const registryPullHostCandidate = String(env.REGISTRY_PULL_HOST || env.REGISTRY_HOST || '127.0.0.1').trim() || '127.0.0.1';
  const registryPullHost = await resolveRegistryPullHost(registryPullHostCandidate);
  const registryPort = String(env.REGISTRY_PORT || '5000').trim() || '5000';

  env.REGISTRY_PULL_HOST = registryPullHost;
  env.REGISTRY_HOST = registryPullHost;
  env.REGISTRY_PORT = registryPort;
  const configuredPushHost = String(env.REGISTRY_PUSH_HOST || '127.0.0.1').trim() || '127.0.0.1';
  const configuredCacheHost = String(env.REGISTRY_CACHE_HOST || configuredPushHost).trim() || configuredPushHost;
  env.REGISTRY_PUSH_HOST = configuredPushHost;
  env.REGISTRY_CACHE_HOST = configuredCacheHost;
  const needsHostNetwork =
    !isLoopbackHost(registryPullHost)
    && (isLoopbackHost(configuredPushHost) || isLoopbackHost(configuredCacheHost));
  if (needsHostNetwork && !String(env.BUILDX_NETWORK || '').trim()) {
    // Buildx runs in a container. With loopback registry targets, force host
    // networking so 127.0.0.1 resolves to the host-published registry.
    env.BUILDX_NETWORK = 'host';
  }
  env.REGISTRY_CACHE_PORT = String(env.REGISTRY_CACHE_PORT || registryPort).trim() || registryPort;
  return env;
}

export async function ensureCloudSwarmRepo(cloudSwarmDir: string): Promise<void> {
  const parent = path.dirname(cloudSwarmDir);
  if (!fs.existsSync(parent)) {
    fs.mkdirSync(parent, { recursive: true });
  }

  const gitEnv: NodeJS.ProcessEnv = {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${CLOUD_SWARM_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
  };
  const repoExists = fs.existsSync(path.join(cloudSwarmDir, '.git'));

  if (!repoExists) {
    const clone = await runCommand('git', ['clone', CLOUD_SWARM_REPO, cloudSwarmDir], 180_000, { env: gitEnv });
    if (clone.code !== 0) {
      throw new Error(`cloud-swarm clone failed: ${clone.stderr || clone.stdout}`.trim());
    }
    return;
  }

  const fetch = await runCommand('git', ['-C', cloudSwarmDir, 'fetch', '--prune'], 120_000, { env: gitEnv });
  if (fetch.code !== 0) {
    throw new Error(`cloud-swarm fetch failed: ${fetch.stderr || fetch.stdout}`.trim());
  }

  const checkout = await runCommand(
    'git',
    ['-C', cloudSwarmDir, 'checkout', '-B', 'main', 'origin/main', '--force'],
    120_000,
    { env: gitEnv },
  );
  if (checkout.code !== 0) {
    throw new Error(`cloud-swarm checkout failed: ${checkout.stderr || checkout.stdout}`.trim());
  }
}

export function registerMigration(id: string, fn: MigrationFn): void {
  migrations[id] = fn;
}

export function getMigration(id: string): MigrationFn | undefined {
  return migrations[id];
}

export function hasMigration(id: string): boolean {
  return id in migrations;
}

/**
 * Execute a single migration by ID.
 * Returns true if the migration was found and executed, false if not found (skip).
 */
export async function executeMigration(id: string, ctx: MigrationContext): Promise<boolean> {
  const fn = migrations[id];
  if (!fn) {
    console.warn(`upgrade.migration.not_found: ${id} (skipping)`);
    return false;
  }
  await fn(ctx);
  return true;
}

// --- Built-in migrations ---
// These are registered at import time. Future versions add more entries here.

registerMigration('create-monitoring-network', async () => {
  const result = await runCommand('docker', ['network', 'create', '--driver', 'overlay', '--attachable', 'mz-monitoring']);
  // Exit code 1 = network already exists, which is fine
  if (result.code !== 0 && !result.stderr.includes('already exists')) {
    throw new Error(`Failed to create monitoring network: ${result.stderr}`);
  }
});

registerMigration('connect-php-to-monitoring', async (ctx) => {
  const services = ['php-fpm', 'php-fpm-admin', 'cron'];
  for (const service of services) {
    const serviceName = ctx.environmentId
      ? `mz-env-${ctx.environmentId}_${service}`
      : service;
    const result = await runCommand('docker', ['service', 'update', '--network-add', 'mz-monitoring', serviceName]);
    if (result.code !== 0) {
      console.warn(`upgrade.migration.connect_monitoring: failed to update ${serviceName}: ${result.stderr}`);
    }
  }
});

registerMigration('connect-cloudflared-to-monitoring', async () => {
  const list = await runCommand('docker', ['service', 'ls', '--format', '{{.Name}}']);
  if (list.code !== 0) {
    throw new Error(`Failed to list services: ${list.stderr || list.stdout}`);
  }

  const candidates = list.stdout
    .split('\n')
    .map((entry) => entry.trim())
    .filter((entry) => entry && (entry.includes('cloudflared') || entry.includes('_tunnel')));

  if (!candidates.length) {
    console.warn('upgrade.migration.connect_cloudflared: no cloudflared/tunnel service found');
    return;
  }

  for (const serviceName of candidates) {
    const result = await runCommand('docker', ['service', 'update', '--network-add', 'mz-monitoring', serviceName]);
    if (result.code !== 0) {
      const output = `${result.stderr}\n${result.stdout}`.toLowerCase();
      if (output.includes('already exists')) {
        continue;
      }
      console.warn(`upgrade.migration.connect_cloudflared: failed to update ${serviceName}: ${result.stderr || result.stdout}`);
    }
  }
});

registerMigration('build-monitoring-images', async (ctx) => {
  await ensureCloudSwarmRepo(ctx.cloudSwarmDir);
  const scriptPath = path.join(ctx.cloudSwarmDir, 'scripts', 'build-monitoring.sh');
  if (!fs.existsSync(scriptPath)) {
    throw new Error(`build-monitoring.sh not found at ${scriptPath}`);
  }
  const env = await buildMonitoringEnv(ctx.cloudSwarmDir);
  const result = await runCommand('bash', [scriptPath], 600_000, {
    cwd: ctx.cloudSwarmDir,
    env,
  });
  if (result.code !== 0) {
    throw new Error(`build-monitoring.sh failed (exit ${result.code}): ${result.stderr}`);
  }
});

registerMigration('deploy-monitoring-stack', async (ctx) => {
  await ensureCloudSwarmRepo(ctx.cloudSwarmDir);
  const stacksDir = path.join(ctx.cloudSwarmDir, 'stacks');
  const baseFile = path.join(stacksDir, 'monitoring-base.yml');
  const overrideFile = path.join(stacksDir, 'monitoring.yml');

  if (!fs.existsSync(baseFile) || !fs.existsSync(overrideFile)) {
    throw new Error(`Monitoring stack files not found in ${stacksDir}`);
  }

  const env = await buildMonitoringEnv(ctx.cloudSwarmDir);

  const net = await runCommand('docker', [
    'network', 'create', '--driver', 'overlay', '--attachable', 'mz-monitoring',
  ], 30_000);
  if (net.code !== 0 && !net.stderr.includes('already exists')) {
    throw new Error(`Monitoring network create failed: ${net.stderr || net.stdout}`);
  }

  const result = await runCommand('docker', [
    'stack', 'deploy',
    '--with-registry-auth',
    '-c', baseFile,
    '-c', overrideFile,
    'mz-monitoring',
  ], 120_000, {
    cwd: ctx.cloudSwarmDir,
    env,
  });
  if (result.code !== 0) {
    throw new Error(`Monitoring stack deploy failed (exit ${result.code}): ${result.stderr}`);
  }
});

registerMigration('setup-dashboards-dns', async (ctx) => {
  const baseUrl = ctx.mzControlBaseUrl || '';
  const nodeId = ctx.nodeId || '';
  const nodeSecret = ctx.nodeSecret || '';
  const stackId = ctx.stackId || 0;

  if (!baseUrl || !nodeId || !nodeSecret || !stackId) {
    throw new Error('Missing mz-control connection details for dashboards DNS setup');
  }

  const url = new URL(`/v1/agent/stack/${stackId}/monitoring-dns`, baseUrl);
  const body = '';
  const headers = buildNodeHeaders('POST', url.pathname, '', body, nodeId, nodeSecret);

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...headers,
    },
    body: body || undefined,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Dashboards DNS setup failed: ${response.status} - ${errorBody}`);
  }

  const result = await response.json() as { dashboards_hostname?: string };
  console.log(`upgrade.migration.dashboards_dns: hostname=${result.dashboards_hostname ?? 'unknown'}`);
});

registerMigration('bootstrap-monitoring-dashboards', async () => {
  try {
    const result = await bootstrapMonitoringDashboards();
    console.log(
      `upgrade.migration.bootstrap_monitoring_dashboards: dashboards=${result.dashboard_ids.join(',')} objects=${result.upserted_objects}`
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (MONITORING_DASHBOARDS_REQUIRED) {
      throw error;
    }
    console.warn(`upgrade.migration.bootstrap_monitoring_dashboards: skipped (${message})`);
  }
});

registerMigration('recover-monitoring-dashboards', async (ctx) => {
  const stack = await fetchStackSnapshot(ctx);
  const stackType = String(stack.stack_type || '').trim();
  if (!isMonitoringEligibleStackType(stackType)) {
    console.log(`upgrade.migration.recover_monitoring_dashboards: skipped for stack_type=${stackType || 'unknown'}`);
    return;
  }

  const existingHostname = String(stack.dashboards_hostname || '').trim();
  const hasMonitoringStack = await monitoringStackExists();

  if (!hasMonitoringStack) {
    console.log('upgrade.migration.recover_monitoring_dashboards: monitoring stack missing; deploying');
    await executeMigration('build-monitoring-images', ctx);
    await executeMigration('deploy-monitoring-stack', ctx);
    await executeMigration('connect-cloudflared-to-monitoring', ctx);
  }

  if (!existingHostname) {
    console.log('upgrade.migration.recover_monitoring_dashboards: dashboards hostname missing; configuring dns');
    await executeMigration('setup-dashboards-dns', ctx);
  }

  await executeMigration('bootstrap-monitoring-dashboards', ctx);
  console.log('upgrade.migration.recover_monitoring_dashboards: complete');
});
