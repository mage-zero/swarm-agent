import fs from 'fs';
import path from 'path';
import { runCommand } from './exec.js';
import { buildNodeHeaders } from './node-hmac.js';

export type MigrationContext = {
  environmentId?: number;
  stackId?: number;
  cloudSwarmDir: string;
  mzControlBaseUrl?: string;
  nodeId?: string;
  nodeSecret?: string;
};

export type MigrationFn = (ctx: MigrationContext) => Promise<void>;

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

function buildMonitoringEnv(cloudSwarmDir: string): NodeJS.ProcessEnv {
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
  const env = buildMonitoringEnv(ctx.cloudSwarmDir);
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

  const env = buildMonitoringEnv(ctx.cloudSwarmDir);

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
