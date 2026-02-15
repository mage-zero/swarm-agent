import fs from 'fs';
import path from 'path';
import { readConfig, type StatusConfig } from './status.js';
import { buildNodeHeaders } from './node-hmac.js';
import { isDeployPaused, setDeployPaused } from './deploy-pause.js';
import { executeMigration } from './upgrade-migrations.js';

const AGENT_DIR = process.env.MZ_AGENT_DIR || '/opt/mage-zero/agent';
const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const CLOUD_SWARM_DIR = process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm';
const VERSION_PATH = process.env.MZ_SWARM_AGENT_VERSION_PATH || `${AGENT_DIR}/version`;
const UPGRADE_AVAILABLE_PATH = `${AGENT_DIR}/upgrade-available.json`;
const UPGRADE_APPROVED_PATH = `${AGENT_DIR}/upgrade-approved.json`;
const UPGRADE_STATE_PATH = `${AGENT_DIR}/upgrade-state.json`;
const UPGRADE_CHECK_INTERVAL_MS = Number(process.env.MZ_UPGRADE_CHECK_INTERVAL_MS || 60_000);

type UpgradeAvailable = {
  current: string;
  target: string;
  total_downtime_minutes: number;
  changelog: ChangelogVersion[];
  detected_at: string;
};

type ChangelogVersion = {
  version: string;
  date: string;
  summary: string;
  requires: Record<string, string>;
  changes: ChangelogChange[];
};

type ChangelogChange = {
  id: string;
  description: string;
  phase: 'pre_migrate' | 'migrate' | 'post_migrate';
  downtimeMinutes: number;
  scope: 'stack' | 'environment';
};

type UpgradeScheduleEntry = {
  upgrade_id: number;
  environment_id: number;
  from_version: string;
  to_version: string;
  status: string;
  scheduled_at: string | null;
  total_downtime_minutes: number;
};

type UpgradeState = {
  reported_version?: string;
  last_check_at?: string;
  pending_migrations?: boolean;
};

// Environment type ordering for sequential upgrade execution
const ENV_TYPE_ORDER: Record<string, number> = {
  'non-production': 0,
  'development': 0,
  'performance': 1,
  'staging': 1,
  'production': 2,
};

function readNodeFile(filename: string): string {
  try {
    return fs.readFileSync(path.join(NODE_DIR, filename), 'utf8').trim();
  } catch {
    return '';
  }
}

function readAgentVersion(): string {
  const envVersion = process.env.MZ_SWARM_AGENT_VERSION;
  if (envVersion) return envVersion.trim();
  try {
    return fs.readFileSync(VERSION_PATH, 'utf8').trim();
  } catch {
    return 'unknown';
  }
}

function readUpgradeAvailable(): UpgradeAvailable | null {
  try {
    const raw = fs.readFileSync(UPGRADE_AVAILABLE_PATH, 'utf8');
    return JSON.parse(raw) as UpgradeAvailable;
  } catch {
    return null;
  }
}

function readUpgradeState(): UpgradeState {
  try {
    const raw = fs.readFileSync(UPGRADE_STATE_PATH, 'utf8');
    return JSON.parse(raw) as UpgradeState;
  } catch {
    return {};
  }
}

function writeUpgradeState(state: UpgradeState): void {
  fs.writeFileSync(UPGRADE_STATE_PATH, JSON.stringify(state, null, 2), 'utf8');
}

function writeUpgradeApproved(target: string, scheduledAt: string): void {
  const data = { target, scheduled_at: scheduledAt };
  fs.writeFileSync(UPGRADE_APPROVED_PATH, JSON.stringify(data, null, 2), 'utf8');
}

async function fetchJson(
  baseUrl: string,
  urlPath: string,
  method: string,
  body: string | null,
  nodeId: string,
  nodeSecret: string,
): Promise<unknown> {
  const url = new URL(urlPath, baseUrl);
  const query = url.search ? url.search.slice(1) : '';
  const bodyPayload = body ?? '';
  const headers = buildNodeHeaders(method, url.pathname, query, bodyPayload, nodeId, nodeSecret);

  const response = await fetch(url.toString(), {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...headers,
    },
    body: bodyPayload || undefined,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`mz-control upgrade request failed: ${response.status} - ${errorBody}`);
  }

  return response.json();
}

/**
 * Report available upgrade to mz-control.
 */
async function reportUpgradeAvailable(
  config: StatusConfig,
  upgrade: UpgradeAvailable,
): Promise<{ auto_upgrade: boolean }> {
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  const stackId = Number(config.stack_id ?? 0);

  if (!baseUrl || !nodeId || !nodeSecret || !stackId) {
    throw new Error('Missing config for mz-control communication');
  }

  const payload = {
    stack_id: stackId,
    current_version: upgrade.current,
    target_version: upgrade.target,
    total_downtime_minutes: upgrade.total_downtime_minutes,
    changelog_json: JSON.stringify(upgrade.changelog),
  };

  const result = await fetchJson(
    baseUrl,
    '/v1/agent/upgrade/available',
    'POST',
    JSON.stringify(payload),
    nodeId,
    nodeSecret,
  ) as { auto_upgrade: boolean };

  return result;
}

/**
 * Poll mz-control for scheduled upgrades.
 */
async function pollUpgradeSchedule(config: StatusConfig): Promise<UpgradeScheduleEntry[]> {
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  const stackId = Number(config.stack_id ?? 0);

  if (!baseUrl || !nodeId || !nodeSecret || !stackId) {
    return [];
  }

  const result = await fetchJson(
    baseUrl,
    `/v1/agent/upgrade/schedule?stack_id=${stackId}`,
    'GET',
    null,
    nodeId,
    nodeSecret,
  );

  return Array.isArray(result) ? result as UpgradeScheduleEntry[] : [];
}

/**
 * Report upgrade status to mz-control.
 */
async function reportUpgradeStatus(
  config: StatusConfig,
  payload: {
    upgrade_id?: number;
    environment_id?: number;
    status: string;
    current_phase?: string;
    progress_message?: string;
    failure_reason?: string;
  },
): Promise<void> {
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');

  if (!baseUrl || !nodeId || !nodeSecret) {
    return;
  }

  await fetchJson(
    baseUrl,
    '/v1/agent/upgrade/status',
    'POST',
    JSON.stringify(payload),
    nodeId,
    nodeSecret,
  );
}

/**
 * Check cloud-swarm and mz-control versions against requirements.
 */
async function checkRequires(
  requires: Record<string, string>,
  config: StatusConfig,
): Promise<{ satisfied: boolean; missing: string[] }> {
  const missing: string[] = [];

  if (requires['cloud-swarm']) {
    const cloudSwarmVersion = readCloudSwarmVersion();
    if (!satisfiesSemver(cloudSwarmVersion, requires['cloud-swarm'])) {
      missing.push(`cloud-swarm: need ${requires['cloud-swarm']}, have ${cloudSwarmVersion}`);
    }
  }

  if (requires['mz-control']) {
    const mzControlVersion = await fetchMzControlVersion(config);
    if (!satisfiesSemver(mzControlVersion, requires['mz-control'])) {
      missing.push(`mz-control: need ${requires['mz-control']}, have ${mzControlVersion}`);
    }
  }

  return { satisfied: missing.length === 0, missing };
}

function readCloudSwarmVersion(): string {
  try {
    return fs.readFileSync(path.join(CLOUD_SWARM_DIR, 'VERSION'), 'utf8').trim();
  } catch {
    return '0.0.0';
  }
}

async function fetchMzControlVersion(config: StatusConfig): Promise<string> {
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  if (!baseUrl) return '0.0.0';

  try {
    const response = await fetch(new URL('/version', baseUrl).toString(), {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return '0.0.0';
    const data = await response.json() as { version?: string };
    return data.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Minimal semver constraint check. Supports >=X.Y.Z format.
 */
function satisfiesSemver(version: string, constraint: string): boolean {
  if (!version || version === '0.0.0' || version === 'unknown') return false;
  const match = constraint.match(/^>=?\s*(\d+\.\d+\.\d+)$/);
  if (!match) return true; // Unknown constraint format, assume satisfied
  return compareSemver(version, match[1]) >= 0;
}

function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va !== vb) return va - vb;
  }
  return 0;
}

/**
 * Collect all changes from changelog versions, sorted by phase order.
 */
function collectChanges(
  changelog: ChangelogVersion[],
  phase: string,
  scope: string,
): ChangelogChange[] {
  const changes: ChangelogChange[] = [];
  // Changelog versions are already in ascending semver order
  for (const version of changelog) {
    for (const change of version.changes) {
      if (change.phase === phase && change.scope === scope) {
        changes.push(change);
      }
    }
  }
  return changes;
}

/**
 * Sort environments by type for sequential execution.
 * non-production/development first, then performance/staging, then production.
 */
function sortEnvironmentsByType(
  environments: Array<{ environment_id: number; environment_type?: string }>,
): Array<{ environment_id: number; environment_type?: string }> {
  return [...environments].sort((a, b) => {
    const orderA = ENV_TYPE_ORDER[a.environment_type || ''] ?? 0;
    const orderB = ENV_TYPE_ORDER[b.environment_type || ''] ?? 0;
    return orderA - orderB;
  });
}

/**
 * Execute the full upgrade plan after the updater has swapped the binary.
 * Called on startup if there are pending migrations.
 */
export async function executeUpgradePlan(changelog: ChangelogVersion[]): Promise<void> {
  const config = readConfig();
  const stackId = Number(config.stack_id ?? 0);

  console.log('upgrade.execute: starting upgrade plan');

  // Phase 1: pre_migrate (stack-scoped, no downtime)
  const preStackChanges = collectChanges(changelog, 'pre_migrate', 'stack');
  for (const change of preStackChanges) {
    console.log(`upgrade.pre_migrate.stack: ${change.id}`);
    await reportUpgradeStatus(config, {
      status: 'in_progress',
      current_phase: 'pre_migrate',
      progress_message: `Pre-migration: ${change.description}`,
    });
    await executeMigration(change.id, { stackId, cloudSwarmDir: CLOUD_SWARM_DIR });
  }

  // Fetch environments for this stack
  const environments = await fetchStackEnvironments(config);
  const sorted = sortEnvironmentsByType(environments);

  // Phase 1b: pre_migrate (environment-scoped)
  const preEnvChanges = collectChanges(changelog, 'pre_migrate', 'environment');
  for (const env of sorted) {
    for (const change of preEnvChanges) {
      console.log(`upgrade.pre_migrate.env.${env.environment_id}: ${change.id}`);
      await reportUpgradeStatus(config, {
        environment_id: env.environment_id,
        status: 'in_progress',
        current_phase: 'pre_migrate',
        progress_message: `Pre-migration: ${change.description}`,
      });
      await executeMigration(change.id, {
        environmentId: env.environment_id,
        stackId,
        cloudSwarmDir: CLOUD_SWARM_DIR,
      });
    }
  }

  // Phase 2: migrate (causes downtime) — pause deploys first
  const migrateStackChanges = collectChanges(changelog, 'migrate', 'stack');
  const migrateEnvChanges = collectChanges(changelog, 'migrate', 'environment');
  const hasMigrations = migrateStackChanges.length > 0 || migrateEnvChanges.length > 0;

  if (hasMigrations) {
    console.log('upgrade.migrate: pausing deploys');
    setDeployPaused(true);

    // Stack-scoped migrations
    for (const change of migrateStackChanges) {
      console.log(`upgrade.migrate.stack: ${change.id}`);
      await reportUpgradeStatus(config, {
        status: 'in_progress',
        current_phase: 'migrate',
        progress_message: `Migrating: ${change.description}`,
      });
      await executeMigration(change.id, { stackId, cloudSwarmDir: CLOUD_SWARM_DIR });
    }

    // Environment-scoped migrations (sequential by type order)
    for (const env of sorted) {
      for (const change of migrateEnvChanges) {
        console.log(`upgrade.migrate.env.${env.environment_id}: ${change.id}`);
        await reportUpgradeStatus(config, {
          environment_id: env.environment_id,
          status: 'in_progress',
          current_phase: 'migrate',
          progress_message: `Migrating: ${change.description}`,
        });
        await executeMigration(change.id, {
          environmentId: env.environment_id,
          stackId,
          cloudSwarmDir: CLOUD_SWARM_DIR,
        });
      }
    }
  }

  // Phase 3: post_migrate (cleanup)
  const postStackChanges = collectChanges(changelog, 'post_migrate', 'stack');
  for (const change of postStackChanges) {
    console.log(`upgrade.post_migrate.stack: ${change.id}`);
    await reportUpgradeStatus(config, {
      status: 'in_progress',
      current_phase: 'post_migrate',
      progress_message: `Post-migration: ${change.description}`,
    });
    await executeMigration(change.id, { stackId, cloudSwarmDir: CLOUD_SWARM_DIR });
  }

  const postEnvChanges = collectChanges(changelog, 'post_migrate', 'environment');
  for (const env of sorted) {
    for (const change of postEnvChanges) {
      console.log(`upgrade.post_migrate.env.${env.environment_id}: ${change.id}`);
      await reportUpgradeStatus(config, {
        environment_id: env.environment_id,
        status: 'in_progress',
        current_phase: 'post_migrate',
        progress_message: `Post-migration: ${change.description}`,
      });
      await executeMigration(change.id, {
        environmentId: env.environment_id,
        stackId,
        cloudSwarmDir: CLOUD_SWARM_DIR,
      });
    }
  }

  // Resume deploys
  if (hasMigrations) {
    console.log('upgrade.complete: resuming deploys');
    setDeployPaused(false);
  }

  // Report completion for all environments
  for (const env of sorted) {
    await reportUpgradeStatus(config, {
      environment_id: env.environment_id,
      status: 'completed',
      progress_message: 'Upgrade completed successfully',
    });
  }

  // Clear pending state
  const state = readUpgradeState();
  state.pending_migrations = false;
  writeUpgradeState(state);

  console.log('upgrade.execute: upgrade plan completed');
}

/**
 * Fetch environments for the stack from mz-control.
 */
async function fetchStackEnvironments(
  config: StatusConfig,
): Promise<Array<{ environment_id: number; environment_type?: string }>> {
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  const stackId = Number(config.stack_id ?? 0);

  if (!baseUrl || !nodeId || !nodeSecret || !stackId) {
    return [];
  }

  try {
    const result = await fetchJson(
      baseUrl,
      `/v1/agent/stack/${stackId}/environments`,
      'GET',
      null,
      nodeId,
      nodeSecret,
    ) as { environments?: Array<Record<string, unknown>> };

    const envs = result?.environments || [];
    return envs.map((e) => ({
      environment_id: Number(e.environment_id ?? 0),
      environment_type: String(e.environment_type ?? ''),
    })).filter((e) => e.environment_id > 0);
  } catch {
    return [];
  }
}

/**
 * Main upgrade check loop. Runs every 60s on manager only.
 */
async function checkUpgrades(): Promise<void> {
  const config = readConfig();
  const state = readUpgradeState();

  // On startup after updater swaps binary: detect pending migrations
  if (state.pending_migrations) {
    console.log('upgrade.check: pending migrations detected, executing upgrade plan');
    try {
      // Read changelog from the current version's release dir or bundled changelog
      const changelog = readCurrentChangelog();
      if (changelog.length > 0) {
        await executeUpgradePlan(changelog);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('upgrade.execute.failed:', message);
      await reportUpgradeStatus(config, {
        status: 'failed',
        failure_reason: message,
      });
    }
    return;
  }

  // Check for upgrade-available.json (written by updater)
  const upgrade = readUpgradeAvailable();
  if (!upgrade) {
    return;
  }

  const currentVersion = readAgentVersion();
  if (upgrade.current !== currentVersion) {
    // Stale file, updater wrote it for a different version
    return;
  }

  // Report to mz-control if not already reported
  if (state.reported_version !== upgrade.target) {
    try {
      // Check requirements first
      const allRequires: Record<string, string> = {};
      for (const v of upgrade.changelog) {
        Object.assign(allRequires, v.requires);
      }

      const { satisfied, missing } = await checkRequires(allRequires, config);
      if (!satisfied) {
        console.warn('upgrade.check: requirements not satisfied:', missing);
        return;
      }

      const result = await reportUpgradeAvailable(config, upgrade);

      state.reported_version = upgrade.target;
      state.last_check_at = new Date().toISOString();
      writeUpgradeState(state);

      if (result.auto_upgrade) {
        // Zero-downtime: mark pending and let updater swap on next tick
        state.pending_migrations = true;
        writeUpgradeState(state);
        // Write approved file so updater knows to proceed immediately
        writeUpgradeApproved(upgrade.target, new Date().toISOString());
        console.log(`upgrade.auto: approved zero-downtime upgrade to ${upgrade.target}`);
        return;
      }
    } catch (err) {
      console.error('upgrade.report.failed:', err instanceof Error ? err.message : err);
      return;
    }
  }

  // For downtime upgrades: poll for schedule
  if (upgrade.total_downtime_minutes > 0) {
    try {
      const schedule = await pollUpgradeSchedule(config);
      const scheduled = schedule.find(
        (s) => s.to_version === upgrade.target && s.status === 'scheduled' && s.scheduled_at,
      );

      if (scheduled?.scheduled_at) {
        // Write approved file for the updater to pick up
        writeUpgradeApproved(upgrade.target, scheduled.scheduled_at);
        state.pending_migrations = true;
        writeUpgradeState(state);
        console.log(`upgrade.scheduled: upgrade to ${upgrade.target} at ${scheduled.scheduled_at}`);
      }
    } catch (err) {
      console.error('upgrade.poll.failed:', err instanceof Error ? err.message : err);
    }
  }
}

/**
 * Read changelog from bundled changelog.json or release directory.
 */
function readCurrentChangelog(): ChangelogVersion[] {
  // Try bundled changelog first (alongside the running binary)
  const bundledPath = path.join(AGENT_DIR, 'changelog.json');
  try {
    const raw = fs.readFileSync(bundledPath, 'utf8');
    const parsed = JSON.parse(raw) as { versions?: ChangelogVersion[] };
    return parsed.versions || [];
  } catch {
    // ignore
  }

  // Try from upgrade-available.json (updater wrote this)
  const upgrade = readUpgradeAvailable();
  if (upgrade?.changelog) {
    return upgrade.changelog;
  }

  return [];
}

/**
 * Check if we're a swarm manager (upgrade logic only runs on manager).
 */
async function isSwarmManager(): Promise<boolean> {
  if (process.env.MZ_DISABLE_DOCKER === '1') return false;
  try {
    const result = await fetch('http://localhost/info', {
      headers: { Host: 'docker' },
    });
    const info = await result.json() as { Swarm?: { ControlAvailable?: boolean } };
    return Boolean(info?.Swarm?.ControlAvailable);
  } catch {
    return false;
  }
}

let upgradeTimer: ReturnType<typeof setInterval> | null = null;

/**
 * Start the upgrade scheduler. Runs every 60s on manager only.
 */
export function startUpgradeScheduler(): void {
  if (upgradeTimer) return;

  const tick = async () => {
    try {
      if (!(await isSwarmManager())) return;
      await checkUpgrades();
    } catch (err) {
      console.error('upgrade.scheduler.error:', err instanceof Error ? err.message : err);
    }
  };

  // Initial check after short delay
  setTimeout(tick, 5_000);
  upgradeTimer = setInterval(tick, UPGRADE_CHECK_INTERVAL_MS);
}
