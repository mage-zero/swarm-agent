import { runCommand } from './exec.js';

export type MigrationContext = {
  environmentId?: number;
  stackId?: number;
  cloudSwarmDir: string;
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
