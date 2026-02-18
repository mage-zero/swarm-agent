import fs from 'fs';
import path from 'path';
import { readConfig, isSwarmManager, type StatusConfig } from './status.js';
import { buildNodeHeaders } from './node-hmac.js';
import { isDeployPaused, setDeployPaused } from './deploy-pause.js';
import { ensureCloudSwarmRepo, executeMigration } from './upgrade-migrations.js';

const AGENT_DIR = process.env.MZ_AGENT_DIR || '/opt/mage-zero/agent';
const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const CLOUD_SWARM_DIR = process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm';
const RELEASES_DIR = path.join(AGENT_DIR, 'releases');
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
  last_blocked_reason?: string;
  last_blocked_at?: string;
  last_error?: string;
  last_error_at?: string;
};

type UpgradeApproved = {
  target?: string;
  scheduled_at?: string;
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

function writeUpgradeAvailable(upgrade: UpgradeAvailable): void {
  fs.writeFileSync(UPGRADE_AVAILABLE_PATH, JSON.stringify(upgrade, null, 2), 'utf8');
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

function readUpgradeApproved(): UpgradeApproved | null {
  try {
    const raw = fs.readFileSync(UPGRADE_APPROVED_PATH, 'utf8');
    return JSON.parse(raw) as UpgradeApproved;
  } catch {
    return null;
  }
}

function markUpgradeBlocked(state: UpgradeState, reason: string): void {
  state.last_blocked_reason = reason;
  state.last_blocked_at = new Date().toISOString();
}

function clearUpgradeBlocked(state: UpgradeState): void {
  delete state.last_blocked_reason;
  delete state.last_blocked_at;
}

function markUpgradeError(state: UpgradeState, reason: string): void {
  state.last_error = reason;
  state.last_error_at = new Date().toISOString();
}

function clearUpgradeError(state: UpgradeState): void {
  delete state.last_error;
  delete state.last_error_at;
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
    let cloudSwarmVersion = readCloudSwarmVersion();
    if (!satisfiesSemver(cloudSwarmVersion, requires['cloud-swarm'])) {
      // Self-heal on freshly provisioned nodes where cloud-swarm checkout may
      // not exist yet; upgrade migrations can bootstrap it.
      try {
        await ensureCloudSwarmRepo(CLOUD_SWARM_DIR);
        cloudSwarmVersion = readCloudSwarmVersion();
      } catch {
        // Keep original behavior and report unmet requirement below.
      }
    }
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

function isStableSemver(version: string): boolean {
  return /^\d+\.\d+\.\d+$/.test(String(version || '').trim());
}

function readSingleChangelogFromFile(changelogPath: string): ChangelogVersion | null {
  try {
    const raw = fs.readFileSync(changelogPath, 'utf8');
    const parsed = JSON.parse(raw) as Partial<ChangelogVersion> | null;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }

    const version = String(parsed.version || '').trim();
    if (!isStableSemver(version)) {
      return null;
    }

    return {
      version,
      date: String(parsed.date || '').trim(),
      summary: String(parsed.summary || '').trim(),
      requires: (parsed.requires && typeof parsed.requires === 'object') ? parsed.requires : {},
      changes: Array.isArray(parsed.changes) ? parsed.changes : [],
    };
  } catch {
    return null;
  }
}

function readReleaseDirectoryChangelog(releasesDir: string = RELEASES_DIR): ChangelogVersion[] {
  if (!fs.existsSync(releasesDir)) {
    return [];
  }

  const collected: ChangelogVersion[] = [];
  const entries = fs.readdirSync(releasesDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const version = String(entry.name || '').trim();
    if (!isStableSemver(version)) {
      continue;
    }
    const changelogPath = path.join(releasesDir, version, 'changelog.json');
    if (!fs.existsSync(changelogPath)) {
      continue;
    }
    const entryForRelease = readSingleChangelogFromFile(changelogPath);
    if (entryForRelease?.version === version) {
      collected.push(entryForRelease);
    }
  }

  const latestByVersion = new Map<string, ChangelogVersion>();
  for (const item of collected) {
    latestByVersion.set(item.version, item);
  }

  return Array.from(latestByVersion.values()).sort((a, b) => compareSemver(a.version, b.version));
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
  const mzControlBaseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  const baseCtx = { stackId, cloudSwarmDir: CLOUD_SWARM_DIR, mzControlBaseUrl, nodeId, nodeSecret };

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
    await executeMigration(change.id, baseCtx);
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
        ...baseCtx,
        environmentId: env.environment_id,
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
      await executeMigration(change.id, baseCtx);
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
          ...baseCtx,
          environmentId: env.environment_id,
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
    await executeMigration(change.id, baseCtx);
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
        ...baseCtx,
        environmentId: env.environment_id,
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
  clearUpgradeBlocked(state);
  clearUpgradeError(state);
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

async function fetchStackEnvironmentCount(config: StatusConfig): Promise<number | null> {
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  const stackId = Number(config.stack_id ?? 0);

  if (!baseUrl || !nodeId || !nodeSecret || !stackId) {
    return null;
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
    return Array.isArray(result?.environments) ? result.environments.length : 0;
  } catch {
    return null;
  }
}

function computeUpgradeDowntimeMinutes(
  versions: ChangelogVersion[],
  environmentCount: number | null,
): number {
  return versions.reduce((sum, version) => {
    const scoped = version.changes
      .filter((change) => change.phase === 'migrate')
      .reduce((inner, change) => {
        if (change.scope === 'stack') {
          return inner + change.downtimeMinutes;
        }
        if (environmentCount === null) {
          // Unknown env count: fail-safe by keeping stated downtime.
          return inner + change.downtimeMinutes;
        }
        return environmentCount > 0 ? inner + change.downtimeMinutes : inner;
      }, 0);
    return sum + scoped;
  }, 0);
}

/**
 * Main upgrade check loop. Runs every 60s on manager only.
 */
async function checkUpgrades(): Promise<void> {
  const config = readConfig();
  const state = readUpgradeState();
  state.last_check_at = new Date().toISOString();

  // On startup after updater swaps binary: detect pending migrations
  if (state.pending_migrations) {
    console.log('upgrade.check: pending migrations detected, executing upgrade plan');
    try {
      // Read changelog from the current version's release dir or bundled changelog
      const changelog = readCurrentChangelog();
      if (changelog.length > 0) {
        await executeUpgradePlan(changelog);
      } else {
        markUpgradeBlocked(state, 'pending_migrations_without_changelog');
        writeUpgradeState(state);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('upgrade.execute.failed:', message);
      markUpgradeError(state, message);
      markUpgradeBlocked(state, 'upgrade_execution_failed');
      writeUpgradeState(state);
      await reportUpgradeStatus(config, {
        status: 'failed',
        failure_reason: message,
      });
    }
    return;
  }

  // Startup version detection: if our running version is newer than what was
  // last reported, read the bundled changelog and trigger the upgrade flow.
  // This handles: first deployment, manual binary swap, old-updater upgrades.
  const currentVersion = readAgentVersion();
  if (currentVersion !== 'unknown' && currentVersion !== state.reported_version) {
    const changelog = readCurrentChangelog();
    const previousVersion = state.reported_version || '0.0.0';
    const pendingVersions = changelog.filter(
      (v) => compareSemver(v.version, previousVersion) > 0 && compareSemver(v.version, currentVersion) <= 0,
    );

    if (pendingVersions.length > 0) {
      const environmentCount = await fetchStackEnvironmentCount(config);
      const totalDowntime = computeUpgradeDowntimeMinutes(pendingVersions, environmentCount);

      const envCountLabel = environmentCount === null ? 'unknown' : String(environmentCount);
      console.log(
        `upgrade.startup: version jump detected (${previousVersion} → ${currentVersion}), `
        + `${totalDowntime}min downtime (environments=${envCountLabel})`,
      );

      // Check requirements
      const allRequires: Record<string, string> = {};
      for (const v of pendingVersions) {
        Object.assign(allRequires, v.requires);
      }
      const { satisfied, missing } = await checkRequires(allRequires, config);
      if (!satisfied) {
        console.warn('upgrade.startup: requirements not satisfied:', missing);
        markUpgradeBlocked(state, `requirements_unsatisfied: ${missing.join('; ')}`);
        writeUpgradeState(state);
        return;
      }

      // Report as available to mz-control
      const upgradeData: UpgradeAvailable = {
        current: previousVersion,
        target: currentVersion,
        total_downtime_minutes: totalDowntime,
        changelog: pendingVersions,
        detected_at: new Date().toISOString(),
      };

      try {
        const result = await reportUpgradeAvailable(config, upgradeData);
        state.reported_version = currentVersion;
        clearUpgradeBlocked(state);
        clearUpgradeError(state);

        if (result.auto_upgrade || totalDowntime === 0) {
          // Zero downtime or auto-approved — execute immediately
          state.pending_migrations = true;
          writeUpgradeState(state);
          console.log(`upgrade.startup: auto-executing migrations for ${currentVersion}`);
          await executeUpgradePlan(pendingVersions);
        } else {
          // Keep a local upgrade-available file so normal schedule polling can
          // continue even when this upgrade was detected on startup. Use the
          // running version as "current" so stale-file checks do not skip it.
          writeUpgradeAvailable({
            ...upgradeData,
            current: currentVersion,
          });
          writeUpgradeState(state);
          console.log(`upgrade.startup: reported ${currentVersion} as available, waiting for approval`);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error('upgrade.startup.report.failed:', message);
        markUpgradeError(state, message);
        markUpgradeBlocked(state, 'startup_report_failed');
        writeUpgradeState(state);
      }
      return;
    }

    // Version changed but no pending changelog entries — just update state
    state.reported_version = currentVersion;
    clearUpgradeBlocked(state);
    clearUpgradeError(state);
    writeUpgradeState(state);
  }

  // Check for upgrade-available.json (written by updater for future versions)
  const upgrade = readUpgradeAvailable();
  if (!upgrade) {
    const approved = readUpgradeApproved();
    if (!approved?.target) {
      clearUpgradeBlocked(state);
    }
    writeUpgradeState(state);
    return;
  }

  if (upgrade.current !== currentVersion) {
    // Stale file, updater wrote it for a different version
    markUpgradeBlocked(
      state,
      `stale_upgrade_file: current=${currentVersion || 'unknown'} expected=${upgrade.current || 'unknown'}`,
    );
    writeUpgradeState(state);
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
        markUpgradeBlocked(state, `requirements_unsatisfied: ${missing.join('; ')}`);
        writeUpgradeState(state);
        return;
      }

      const result = await reportUpgradeAvailable(config, upgrade);

      state.reported_version = upgrade.target;
      clearUpgradeBlocked(state);
      clearUpgradeError(state);
      writeUpgradeState(state);

      if (result.auto_upgrade) {
        // Zero-downtime: mark pending and let updater swap on next tick
        state.pending_migrations = true;
        clearUpgradeBlocked(state);
        clearUpgradeError(state);
        writeUpgradeState(state);
        // Write approved file so updater knows to proceed immediately
        writeUpgradeApproved(upgrade.target, new Date().toISOString());
        console.log(`upgrade.auto: approved zero-downtime upgrade to ${upgrade.target}`);
        return;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('upgrade.report.failed:', message);
      markUpgradeError(state, message);
      markUpgradeBlocked(state, 'report_available_failed');
      writeUpgradeState(state);
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
        const scheduledAtTs = Date.parse(scheduled.scheduled_at);
        if (!Number.isNaN(scheduledAtTs) && scheduledAtTs > Date.now()) {
          console.log(`upgrade.scheduled: waiting until ${scheduled.scheduled_at} for ${upgrade.target}`);
          markUpgradeBlocked(state, `waiting_for_scheduled_window:${scheduled.scheduled_at}`);
          writeUpgradeState(state);
          return;
        }

        // Write approved file for the updater to pick up
        writeUpgradeApproved(upgrade.target, scheduled.scheduled_at);
        state.pending_migrations = true;
        clearUpgradeBlocked(state);
        clearUpgradeError(state);
        writeUpgradeState(state);
        console.log(`upgrade.scheduled: upgrade to ${upgrade.target} at ${scheduled.scheduled_at}`);
      } else {
        markUpgradeBlocked(state, `waiting_for_approval:${upgrade.target}`);
        writeUpgradeState(state);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('upgrade.poll.failed:', message);
      markUpgradeError(state, message);
      markUpgradeBlocked(state, 'schedule_poll_failed');
      writeUpgradeState(state);
    }
    return;
  }

  clearUpgradeBlocked(state);
  clearUpgradeError(state);
  writeUpgradeState(state);
}

/**
 * Read changelog from bundled changelog.json or release directory.
 */
function readCurrentChangelog(): ChangelogVersion[] {
  // Prefer upgrade-available.json: it contains only the currently approved
  // upgrade path and avoids replaying historical migrations.
  const upgrade = readUpgradeAvailable();
  if (upgrade?.changelog) {
    return upgrade.changelog;
  }

  // Prefer release-path changelogs staged by updater (one file per version).
  const releasePathChangelog = readReleaseDirectoryChangelog(RELEASES_DIR);
  if (releasePathChangelog.length > 0) {
    return releasePathChangelog;
  }

  // Fallback: bundled changelog alongside the running binary.
  const bundledPath = path.join(AGENT_DIR, 'changelog.json');
  try {
    const bundled = readSingleChangelogFromFile(bundledPath);
    return bundled ? [bundled] : [];
  } catch {
    // ignore
  }

  return [];
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

export const __testing = {
  compareSemver,
  readSingleChangelogFromFile,
  readReleaseDirectoryChangelog,
};
