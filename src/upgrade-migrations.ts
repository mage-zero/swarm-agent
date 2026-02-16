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

/**
 * Registry of migration functions keyed by change ID.
 * Each release's changelog.json references change IDs that map to functions here.
 * New migrations are added as the agent gains new capabilities.
 */
const migrations: Record<string, MigrationFn> = {};

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

registerMigration('build-monitoring-images', async (ctx) => {
  const scriptPath = path.join(ctx.cloudSwarmDir, 'scripts', 'build-monitoring.sh');
  if (!fs.existsSync(scriptPath)) {
    throw new Error(`build-monitoring.sh not found at ${scriptPath}`);
  }
  const result = await runCommand('bash', [scriptPath], 600_000);
  if (result.code !== 0) {
    throw new Error(`build-monitoring.sh failed (exit ${result.code}): ${result.stderr}`);
  }
});

registerMigration('deploy-monitoring-stack', async (ctx) => {
  const stacksDir = path.join(ctx.cloudSwarmDir, 'stacks');
  const baseFile = path.join(stacksDir, 'monitoring-base.yml');
  const overrideFile = path.join(stacksDir, 'monitoring.yml');

  if (!fs.existsSync(baseFile) || !fs.existsSync(overrideFile)) {
    throw new Error(`Monitoring stack files not found in ${stacksDir}`);
  }

  const result = await runCommand('docker', [
    'stack', 'deploy',
    '--with-registry-auth',
    '-c', baseFile,
    '-c', overrideFile,
    'mz-monitoring',
  ], 120_000);
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
