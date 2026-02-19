import fs from 'fs';
import path from 'path';
import { runCommand } from './exec.js';
import { buildNodeHeaders } from './node-hmac.js';
import { bootstrapMonitoringDashboards } from './monitoring-dashboards.js';
import { isEnabledFlag, resolveMageProfilerEnv } from './lib/apm-profiler.js';
import { buildCapacityPayload } from './status.js';

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
  OTEL_COLLECTOR_VERSION: '0.146.0',
  DATA_PREPPER_VERSION: '2.12.0',
  FILEBEAT_VERSION: '7.12.1',
  METRICBEAT_VERSION: '7.12.1',
  MZ_MONITORING_OPENSEARCH_JAVA_OPTS: '-Xms512m -Xmx512m',
  MZ_MONITORING_OPENSEARCH_LIMIT_MEMORY: '1536M',
  MZ_MONITORING_OPENSEARCH_RESERVE_MEMORY: '512M',
};
const MONITORING_DASHBOARDS_REQUIRED = (process.env.MZ_MONITORING_DASHBOARDS_REQUIRED || '0') === '1';
const APP_HA_MIN_READY_NODES = Math.max(1, Number(process.env.MZ_APP_HA_MIN_READY_NODES || 2));
const APP_HA_MAX_REPLICAS = Math.max(1, Number(process.env.MZ_APP_HA_MAX_REPLICAS || 2));
const APP_HA_CPU_EPSILON = 0.01;

type AppHaReplicaPolicyInput = {
  ready_node_count: number;
  free_cpu_cores: number;
  free_memory_bytes: number;
  nginx_reserve_cpu_cores: number;
  nginx_reserve_memory_bytes: number;
  php_fpm_reserve_cpu_cores: number;
  php_fpm_reserve_memory_bytes: number;
  min_ready_nodes: number;
  max_replicas: number;
};

type AppHaReplicaPolicyDecision = {
  replicas: number;
  reason: 'single_node' | 'insufficient_headroom' | 'ha_enabled';
  required_cpu_cores: number;
  required_memory_bytes: number;
  shortfall_cpu_cores: number;
  shortfall_memory_bytes: number;
};

type ServiceReplicaConfig = {
  replicas: number;
  max_replicas_per_node: number;
  reserve_cpu_cores: number;
  reserve_memory_bytes: number;
  restart_condition: string;
  update_order: string;
};

type ServiceReplicaApplyResult = {
  status: 'updated' | 'skipped' | 'failed';
  detail: string;
};

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

function toCpuCores(nanoCpus: unknown): number {
  const numeric = Number(nanoCpus || 0);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return 0;
  }
  return numeric / 1_000_000_000;
}

function resolveAppHaReplicaPolicy(input: AppHaReplicaPolicyInput): AppHaReplicaPolicyDecision {
  const readyNodeCount = Math.max(0, Math.floor(Number(input.ready_node_count) || 0));
  const minReadyNodes = Math.max(1, Math.floor(Number(input.min_ready_nodes) || 1));
  const maxReplicas = Math.max(1, Math.floor(Number(input.max_replicas) || 1));
  if (readyNodeCount < minReadyNodes || maxReplicas <= 1) {
    return {
      replicas: 1,
      reason: 'single_node',
      required_cpu_cores: 0,
      required_memory_bytes: 0,
      shortfall_cpu_cores: 0,
      shortfall_memory_bytes: 0,
    };
  }

  const targetReplicas = Math.max(1, Math.min(maxReplicas, readyNodeCount));
  if (targetReplicas <= 1) {
    return {
      replicas: 1,
      reason: 'single_node',
      required_cpu_cores: 0,
      required_memory_bytes: 0,
      shortfall_cpu_cores: 0,
      shortfall_memory_bytes: 0,
    };
  }

  const extraReplicas = targetReplicas - 1;
  const nginxReserveCpu = Math.max(0, Number(input.nginx_reserve_cpu_cores) || 0);
  const phpFpmReserveCpu = Math.max(0, Number(input.php_fpm_reserve_cpu_cores) || 0);
  const nginxReserveMem = Math.max(0, Math.round(Number(input.nginx_reserve_memory_bytes) || 0));
  const phpFpmReserveMem = Math.max(0, Math.round(Number(input.php_fpm_reserve_memory_bytes) || 0));
  const requiredCpu = extraReplicas * (nginxReserveCpu + phpFpmReserveCpu);
  const requiredMem = extraReplicas * (nginxReserveMem + phpFpmReserveMem);
  const freeCpu = Math.max(0, Number(input.free_cpu_cores) || 0);
  const freeMem = Math.max(0, Math.round(Number(input.free_memory_bytes) || 0));
  const shortfallCpu = requiredCpu > (freeCpu + APP_HA_CPU_EPSILON)
    ? Number((requiredCpu - freeCpu).toFixed(2))
    : 0;
  const shortfallMem = requiredMem > freeMem ? requiredMem - freeMem : 0;

  if (shortfallCpu > 0 || shortfallMem > 0) {
    return {
      replicas: 1,
      reason: 'insufficient_headroom',
      required_cpu_cores: Number(requiredCpu.toFixed(2)),
      required_memory_bytes: requiredMem,
      shortfall_cpu_cores: shortfallCpu,
      shortfall_memory_bytes: shortfallMem,
    };
  }

  return {
    replicas: targetReplicas,
    reason: 'ha_enabled',
    required_cpu_cores: Number(requiredCpu.toFixed(2)),
    required_memory_bytes: requiredMem,
    shortfall_cpu_cores: 0,
    shortfall_memory_bytes: 0,
  };
}

function isNoSuchServiceOutput(text: string): boolean {
  const lower = text.toLowerCase();
  return lower.includes('no such service') || lower.includes('service not found');
}

function isNoopServiceUpdateOutput(text: string): boolean {
  const lower = text.toLowerCase();
  return lower.includes('nothing to update') || lower.includes('no changes detected');
}

function envServiceName(environmentId: number, service: string): string {
  return `mz-env-${environmentId}_${service}`;
}

async function inspectServiceReplicaConfig(serviceName: string): Promise<ServiceReplicaConfig | null> {
  const inspect = await runCommand(
    'docker',
    ['service', 'inspect', serviceName, '--format', '{{json .Spec}}'],
    30_000,
  );
  if (inspect.code !== 0) {
    const output = `${inspect.stdout || ''}\n${inspect.stderr || ''}`;
    if (isNoSuchServiceOutput(output)) {
      return null;
    }
    throw new Error(`Failed to inspect ${serviceName}: ${inspect.stderr || inspect.stdout || `exit ${inspect.code}`}`);
  }

  const raw = String(inspect.stdout || '').trim();
  if (!raw) {
    throw new Error(`Empty service spec for ${serviceName}`);
  }

  let spec: Record<string, unknown>;
  try {
    spec = JSON.parse(raw) as Record<string, unknown>;
  } catch (error) {
    throw new Error(
      `Invalid JSON service spec for ${serviceName}: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const mode = spec.Mode as Record<string, unknown> | undefined;
  const replicated = mode?.Replicated as Record<string, unknown> | undefined;
  const replicasRaw = replicated?.Replicas;
  const replicasParsed = Number(replicasRaw ?? 0);
  const replicas = Number.isFinite(replicasParsed) ? Math.max(0, Math.round(replicasParsed)) : 0;

  const taskTemplate = spec.TaskTemplate as Record<string, unknown> | undefined;
  const placement = taskTemplate?.Placement as Record<string, unknown> | undefined;
  const maxReplicasRaw = placement?.MaxReplicas;
  const maxReplicasParsed = Number(maxReplicasRaw ?? 0);
  const maxReplicasPerNode = Number.isFinite(maxReplicasParsed)
    ? Math.max(0, Math.round(maxReplicasParsed))
    : 0;

  const resources = taskTemplate?.Resources as Record<string, unknown> | undefined;
  const reservations = resources?.Reservations as Record<string, unknown> | undefined;
  const reserveCpu = toCpuCores(reservations?.NanoCPUs);
  const reserveMemoryRaw = Number(reservations?.MemoryBytes || 0);
  const reserveMemory = Number.isFinite(reserveMemoryRaw) ? Math.max(0, Math.round(reserveMemoryRaw)) : 0;
  const restartPolicy = taskTemplate?.RestartPolicy as Record<string, unknown> | undefined;
  const restartCondition = String(restartPolicy?.Condition || '').trim().toLowerCase();
  const updateConfig = spec.UpdateConfig as Record<string, unknown> | undefined;
  const updateOrder = String(updateConfig?.Order || '').trim().toLowerCase();

  return {
    replicas,
    max_replicas_per_node: maxReplicasPerNode,
    reserve_cpu_cores: reserveCpu,
    reserve_memory_bytes: reserveMemory,
    restart_condition: restartCondition,
    update_order: updateOrder,
  };
}

async function applyServiceReplicaPolicy(
  serviceName: string,
  targetReplicas: number,
  maxReplicasPerNode: number,
): Promise<ServiceReplicaApplyResult> {
  let current: ServiceReplicaConfig | null;
  try {
    current = await inspectServiceReplicaConfig(serviceName);
  } catch (error) {
    return {
      status: 'failed',
      detail: error instanceof Error ? error.message : String(error),
    };
  }

  if (!current) {
    return { status: 'skipped', detail: 'service not found' };
  }

  const desiredReplicas = Math.max(0, Math.round(targetReplicas));
  const desiredMaxPerNode = Math.max(0, Math.round(maxReplicasPerNode));
  if (current.replicas === desiredReplicas && current.max_replicas_per_node === desiredMaxPerNode) {
    return { status: 'skipped', detail: 'already aligned' };
  }

  let update = await runCommand(
    'docker',
    [
      'service',
      'update',
      '--replicas',
      String(desiredReplicas),
      '--replicas-max-per-node',
      String(desiredMaxPerNode),
      serviceName,
    ],
    120_000,
  );
  if (update.code !== 0) {
    const combined = `${update.stdout || ''}\n${update.stderr || ''}`;
    const lower = combined.toLowerCase();
    if (lower.includes('unknown flag') && lower.includes('replicas-max-per-node')) {
      update = await runCommand(
        'docker',
        ['service', 'update', '--replicas', String(desiredReplicas), serviceName],
        120_000,
      );
    }
  }

  if (update.code !== 0) {
    const combined = `${update.stdout || ''}\n${update.stderr || ''}`;
    if (isNoSuchServiceOutput(combined)) {
      return { status: 'skipped', detail: 'service not found during update' };
    }
    if (isNoopServiceUpdateOutput(combined)) {
      return { status: 'skipped', detail: 'nothing to update' };
    }
    return {
      status: 'failed',
      detail: combined.trim() || `docker service update failed (exit ${update.code})`,
    };
  }

  return { status: 'updated', detail: `replicas=${desiredReplicas} max_per_node=${desiredMaxPerNode}` };
}

async function applyServiceRuntimePolicy(
  serviceName: string,
  policy: {
    restart_condition?: 'none' | 'on-failure' | 'any';
    update_order?: 'start-first' | 'stop-first';
    force?: boolean;
  },
): Promise<ServiceReplicaApplyResult> {
  let current: ServiceReplicaConfig | null;
  try {
    current = await inspectServiceReplicaConfig(serviceName);
  } catch (error) {
    return {
      status: 'failed',
      detail: error instanceof Error ? error.message : String(error),
    };
  }

  if (!current) {
    return { status: 'skipped', detail: 'service not found' };
  }

  const args: string[] = ['service', 'update'];
  const details: string[] = [];
  if (policy.restart_condition && current.restart_condition !== policy.restart_condition) {
    args.push('--restart-condition', policy.restart_condition);
    details.push(`restart=${policy.restart_condition}`);
  }
  if (policy.update_order && current.update_order !== policy.update_order) {
    args.push('--update-order', policy.update_order, '--rollback-order', policy.update_order);
    details.push(`order=${policy.update_order}`);
  }
  if (policy.force) {
    args.push('--force');
    details.push('force=true');
  }
  if (!details.length) {
    return { status: 'skipped', detail: 'already aligned' };
  }
  args.push(serviceName);

  const update = await runCommand('docker', args, 120_000);
  if (update.code !== 0) {
    const combined = `${update.stdout || ''}\n${update.stderr || ''}`;
    if (isNoSuchServiceOutput(combined)) {
      return { status: 'skipped', detail: 'service not found during update' };
    }
    if (isNoopServiceUpdateOutput(combined)) {
      return { status: 'skipped', detail: 'nothing to update' };
    }
    return {
      status: 'failed',
      detail: combined.trim() || `docker service update failed (exit ${update.code})`,
    };
  }

  return { status: 'updated', detail: details.join(' ') };
}

type ServiceUpdateStatus = {
  state: string;
  message: string;
};

async function inspectServiceUpdateStatus(serviceName: string): Promise<ServiceUpdateStatus | null> {
  const inspect = await runCommand(
    'docker',
    ['service', 'inspect', serviceName, '--format', '{{json .UpdateStatus}}'],
    30_000,
  );
  if (inspect.code !== 0) {
    const output = `${inspect.stdout || ''}\n${inspect.stderr || ''}`;
    if (isNoSuchServiceOutput(output)) {
      return null;
    }
    throw new Error(`Failed to inspect update status for ${serviceName}: ${inspect.stderr || inspect.stdout || `exit ${inspect.code}`}`);
  }

  const raw = String(inspect.stdout || '').trim();
  if (!raw || raw === '<no value>' || raw === 'null') {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return {
      state: String(parsed.State || '').trim(),
      message: String(parsed.Message || '').trim(),
    };
  } catch {
    return null;
  }
}

function isPlacementPausedStatus(status: ServiceUpdateStatus | null): boolean {
  if (!status) return false;
  const state = String(status.state || '').toLowerCase();
  const message = String(status.message || '').toLowerCase();
  if (!state.includes('pause')) {
    return false;
  }
  return message.includes('max replicas per node') || message.includes('no suitable node');
}

async function recoverPlacementPausedFrontendService(
  serviceName: string,
  desiredOrder: 'start-first' | 'stop-first',
): Promise<ServiceReplicaApplyResult> {
  let status: ServiceUpdateStatus | null;
  try {
    status = await inspectServiceUpdateStatus(serviceName);
  } catch (error) {
    return {
      status: 'failed',
      detail: error instanceof Error ? error.message : String(error),
    };
  }

  if (!isPlacementPausedStatus(status)) {
    return { status: 'skipped', detail: 'no placement-paused update' };
  }

  let resume = await runCommand(
    'docker',
    ['service', 'update', '--update-failure-action', 'continue', serviceName],
    120_000,
  );
  if (resume.code !== 0) {
    const output = `${resume.stdout || ''}\n${resume.stderr || ''}`;
    if (isNoSuchServiceOutput(output)) {
      return { status: 'skipped', detail: 'service not found during resume' };
    }
    if (!isNoopServiceUpdateOutput(output)) {
      return {
        status: 'failed',
        detail: output.trim() || `docker service update resume failed (exit ${resume.code})`,
      };
    }
  }

  let recover = await runCommand(
    'docker',
    [
      'service',
      'update',
      '--update-order',
      desiredOrder,
      '--rollback-order',
      desiredOrder,
      '--force',
      serviceName,
    ],
    120_000,
  );
  if (recover.code !== 0) {
    const output = `${recover.stdout || ''}\n${recover.stderr || ''}`;
    if (isNoSuchServiceOutput(output)) {
      return { status: 'skipped', detail: 'service not found during recovery update' };
    }
    if (!isNoopServiceUpdateOutput(output)) {
      return {
        status: 'failed',
        detail: output.trim() || `docker service update recovery failed (exit ${recover.code})`,
      };
    }
    // Some older daemons return "nothing to update" after resuming.
    recover = await runCommand(
      'docker',
      ['service', 'update', '--force', serviceName],
      120_000,
    );
    if (recover.code !== 0) {
      const retryOutput = `${recover.stdout || ''}\n${recover.stderr || ''}`;
      if (isNoSuchServiceOutput(retryOutput)) {
        return { status: 'skipped', detail: 'service not found during force retry' };
      }
      if (!isNoopServiceUpdateOutput(retryOutput)) {
        return {
          status: 'failed',
          detail: retryOutput.trim() || `docker service update force retry failed (exit ${recover.code})`,
        };
      }
    }
  }

  return { status: 'updated', detail: `resumed paused update and forced rollout (order=${desiredOrder})` };
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

  const fetch = await runCommand(
    'git',
    ['-C', cloudSwarmDir, 'fetch', '--prune', CLOUD_SWARM_REPO, '+refs/heads/main:refs/remotes/origin/main'],
    120_000,
    { env: gitEnv },
  );
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

registerMigration('refresh-monitoring-host-metadata', async (ctx) => {
  const stack = await fetchStackSnapshot(ctx);
  const stackType = String(stack.stack_type || '').trim();
  if (!isMonitoringEligibleStackType(stackType)) {
    console.log(`upgrade.migration.refresh_monitoring_host_metadata: skipped for stack_type=${stackType || 'unknown'}`);
    return;
  }

  console.log('upgrade.migration.refresh_monitoring_host_metadata: rebuilding and redeploying monitoring stack');
  await executeMigration('build-monitoring-images', ctx);
  await executeMigration('deploy-monitoring-stack', ctx);
  await executeMigration('connect-cloudflared-to-monitoring', ctx);
  await executeMigration('bootstrap-monitoring-dashboards', ctx);
  console.log('upgrade.migration.refresh_monitoring_host_metadata: complete');
});

registerMigration('refresh-monitoring-host-metadata-v2', async (ctx) => {
  await executeMigration('refresh-monitoring-host-metadata', ctx);
});

registerMigration('rebalance-frontend-ha-replicas', async (ctx) => {
  const environmentId = Number(ctx.environmentId || 0);
  if (!Number.isFinite(environmentId) || environmentId <= 0) {
    console.warn('upgrade.migration.rebalance_frontend_ha_replicas: missing environmentId; skipping');
    return;
  }

  let readyNodeCount = 0;
  let freeCpuCores = 0;
  let freeMemoryBytes = 0;
  try {
    const capacity = await buildCapacityPayload();
    const readyNodes = (capacity.nodes || []).filter(
      (node) => node.status === 'ready' && node.availability === 'active',
    );
    readyNodeCount = readyNodes.length;
    freeCpuCores = Number(capacity.totals.free_cpu_cores || 0);
    freeMemoryBytes = Number(capacity.totals.free_memory_bytes || 0);
  } catch (error) {
    console.warn(
      `upgrade.migration.rebalance_frontend_ha_replicas: failed to read capacity (${error instanceof Error ? error.message : String(error)})`
    );
    return;
  }

  if (readyNodeCount <= 0) {
    console.warn(`upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} no ready nodes; skipping`);
    return;
  }

  const nginxService = envServiceName(environmentId, 'nginx');
  const phpFpmService = envServiceName(environmentId, 'php-fpm');
  const varnishService = envServiceName(environmentId, 'varnish');

  let nginxSpec: ServiceReplicaConfig | null = null;
  let phpFpmSpec: ServiceReplicaConfig | null = null;
  try {
    nginxSpec = await inspectServiceReplicaConfig(nginxService);
    phpFpmSpec = await inspectServiceReplicaConfig(phpFpmService);
  } catch (error) {
    console.warn(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} service inspect failed (${error instanceof Error ? error.message : String(error)})`
    );
    return;
  }

  if (!nginxSpec || !phpFpmSpec) {
    console.warn(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} missing nginx/php-fpm service; skipping`
    );
    return;
  }

  const decision = resolveAppHaReplicaPolicy({
    ready_node_count: readyNodeCount,
    free_cpu_cores: freeCpuCores,
    free_memory_bytes: freeMemoryBytes,
    nginx_reserve_cpu_cores: nginxSpec.reserve_cpu_cores,
    nginx_reserve_memory_bytes: nginxSpec.reserve_memory_bytes,
    php_fpm_reserve_cpu_cores: phpFpmSpec.reserve_cpu_cores,
    php_fpm_reserve_memory_bytes: phpFpmSpec.reserve_memory_bytes,
    min_ready_nodes: APP_HA_MIN_READY_NODES,
    max_replicas: APP_HA_MAX_REPLICAS,
  });

  if (decision.reason === 'ha_enabled') {
    console.log(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} target=${decision.replicas} `
      + `(ready_nodes=${readyNodeCount}, extra_reserve_cpu=${decision.required_cpu_cores}, `
      + `extra_reserve_memory_bytes=${decision.required_memory_bytes})`
    );
  } else if (decision.reason === 'insufficient_headroom') {
    console.log(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} keeping single replica `
      + `(cpu_shortfall=${decision.shortfall_cpu_cores}, memory_shortfall_bytes=${decision.shortfall_memory_bytes})`
    );
  } else {
    console.log(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} single-node policy `
      + `(ready_nodes=${readyNodeCount}, min_ready_nodes=${APP_HA_MIN_READY_NODES})`
    );
  }

  const targetReplicas = decision.replicas;
  const maxReplicasPerNode = targetReplicas > 1 ? 1 : 0;
  const updateOrder: 'start-first' | 'stop-first' = targetReplicas > 1 ? 'stop-first' : 'start-first';
  const services = [varnishService, nginxService, phpFpmService];
  for (const serviceName of services) {
    const replicaResult = await applyServiceReplicaPolicy(serviceName, targetReplicas, maxReplicasPerNode);
    if (replicaResult.status === 'failed') {
      console.warn(`upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} ${serviceName} failed (${replicaResult.detail})`);
      continue;
    }
    console.log(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} ${serviceName} `
      + `${replicaResult.status} (${replicaResult.detail})`
    );

    const runtimeResult = await applyServiceRuntimePolicy(serviceName, {
      restart_condition: 'any',
      update_order: updateOrder,
      // Refresh Varnish workers so backend DNS/IP bindings are rebuilt after
      // frontend topology changes (nginx/vip movement).
      force: serviceName === varnishService,
    });
    if (runtimeResult.status === 'failed') {
      console.warn(`upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} ${serviceName} runtime failed (${runtimeResult.detail})`);
      continue;
    }
    console.log(
      `upgrade.migration.rebalance_frontend_ha_replicas: env=${environmentId} ${serviceName} `
      + `runtime ${runtimeResult.status} (${runtimeResult.detail})`
    );
  }
});

registerMigration('normalize-env-runtime-policies', async (ctx) => {
  const environmentId = Number(ctx.environmentId || 0);
  if (!Number.isFinite(environmentId) || environmentId <= 0) {
    console.warn('upgrade.migration.normalize_env_runtime_policies: missing environmentId; skipping');
    return;
  }

  const frontendServices = [
    envServiceName(environmentId, 'varnish'),
    envServiceName(environmentId, 'nginx'),
    envServiceName(environmentId, 'php-fpm'),
  ];
  for (const serviceName of frontendServices) {
    const current = await inspectServiceReplicaConfig(serviceName);
    if (!current) {
      console.log(`upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} skipped (missing)`);
      continue;
    }
    const desiredMaxPerNode = current.replicas > 1 ? 1 : 0;
    const desiredOrder: 'start-first' | 'stop-first' = current.replicas > 1 ? 'stop-first' : 'start-first';

    const replicaResult = await applyServiceReplicaPolicy(serviceName, current.replicas, desiredMaxPerNode);
    if (replicaResult.status === 'failed') {
      console.warn(
        `upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} `
        + `replica failed (${replicaResult.detail})`
      );
      continue;
    }
    console.log(
      `upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} `
      + `replica ${replicaResult.status} (${replicaResult.detail})`
    );

    const runtimeResult = await applyServiceRuntimePolicy(serviceName, {
      restart_condition: 'any',
      update_order: desiredOrder,
      force: serviceName.endsWith('_varnish'),
    });
    if (runtimeResult.status === 'failed') {
      console.warn(
        `upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} `
        + `runtime failed (${runtimeResult.detail})`
      );
      continue;
    }
    console.log(
      `upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} `
      + `runtime ${runtimeResult.status} (${runtimeResult.detail})`
    );
  }

  const serviceSuffixes = [
    'php-fpm-admin',
    'cron',
    'database',
    'database-replica',
    'proxysql',
    'opensearch',
    'redis-cache',
    'redis-session',
    'rabbitmq',
    'mailhog',
  ];
  for (const suffix of serviceSuffixes) {
    const serviceName = envServiceName(environmentId, suffix);
    const result = await applyServiceRuntimePolicy(serviceName, { restart_condition: 'any' });
    if (result.status === 'failed') {
      console.warn(
        `upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} `
        + `failed (${result.detail})`
      );
      continue;
    }
    console.log(
      `upgrade.migration.normalize_env_runtime_policies: env=${environmentId} ${serviceName} `
      + `${result.status} (${result.detail})`
    );
  }
});

registerMigration('frontend-runtime-policy-reconcile', async (ctx) => {
  const environmentId = Number(ctx.environmentId || 0);
  if (!Number.isFinite(environmentId) || environmentId <= 0) {
    console.warn('upgrade.migration.frontend_runtime_policy_reconcile: missing environmentId; skipping');
    return;
  }
  console.log(`upgrade.migration.frontend_runtime_policy_reconcile: env=${environmentId} running rebalance + runtime normalization`);
  await executeMigration('rebalance-frontend-ha-replicas', ctx);
  await executeMigration('normalize-env-runtime-policies', ctx);
  console.log(`upgrade.migration.frontend_runtime_policy_reconcile: env=${environmentId} complete`);
});

registerMigration('frontend-placement-deadlock-recovery', async (ctx) => {
  const environmentId = Number(ctx.environmentId || 0);
  if (!Number.isFinite(environmentId) || environmentId <= 0) {
    console.warn('upgrade.migration.frontend_placement_deadlock_recovery: missing environmentId; skipping');
    return;
  }

  const services = [
    envServiceName(environmentId, 'varnish'),
    envServiceName(environmentId, 'nginx'),
    envServiceName(environmentId, 'php-fpm'),
  ];
  for (const serviceName of services) {
    const spec = await inspectServiceReplicaConfig(serviceName);
    if (!spec) {
      console.log(`upgrade.migration.frontend_placement_deadlock_recovery: env=${environmentId} ${serviceName} skipped (missing)`);
      continue;
    }
    const desiredOrder: 'start-first' | 'stop-first' = spec.replicas > 1 ? 'stop-first' : 'start-first';
    const result = await recoverPlacementPausedFrontendService(serviceName, desiredOrder);
    if (result.status === 'failed') {
      console.warn(
        `upgrade.migration.frontend_placement_deadlock_recovery: env=${environmentId} ${serviceName} `
        + `failed (${result.detail})`
      );
      continue;
    }
    console.log(
      `upgrade.migration.frontend_placement_deadlock_recovery: env=${environmentId} ${serviceName} `
      + `${result.status} (${result.detail})`
    );
  }
});

registerMigration('sync-magento-apm-profiler-bootstrap', async (ctx) => {
  if (!ctx.environmentId) {
    console.warn('upgrade.migration.sync_magento_apm_profiler_bootstrap: missing environmentId; skipping');
    return;
  }

  const explicitProfilerValue = process.env.MAGE_PROFILER;
  const serviceSuffixes = ['php-fpm', 'php-fpm-admin', 'cron'];

  for (const suffix of serviceSuffixes) {
    const serviceName = `mz-env-${ctx.environmentId}_${suffix}`;
    const inspect = await runCommand(
      'docker',
      ['service', 'inspect', serviceName, '--format', '{{range .Spec.TaskTemplate.ContainerSpec.Env}}{{println .}}{{end}}'],
      30_000,
    );
    if (inspect.code !== 0) {
      const inspectOutput = `${inspect.stdout}\n${inspect.stderr}`.toLowerCase();
      if (inspectOutput.includes('no such service')) {
        console.warn(`upgrade.migration.sync_magento_apm_profiler_bootstrap: ${serviceName} not found; skipping`);
        continue;
      }
      throw new Error(
        `Failed to inspect ${serviceName}: ${inspect.stderr || inspect.stdout || `exit ${inspect.code}`}`
      );
    }

    const envLines = (inspect.stdout || '').split('\n');
    const readEnvValue = (key: string): string => {
      const line = envLines.find((item) => item.startsWith(`${key}=`));
      return line ? line.slice(key.length + 1) : '';
    };
    const apmEnabledValue = readEnvValue('MZ_APM_ENABLED');
    const profilerValue = resolveMageProfilerEnv(
      explicitProfilerValue,
      isEnabledFlag(apmEnabledValue, true) ? '1' : '0',
      {
        serverUrl: readEnvValue('MZ_APM_SERVER_URL'),
        serviceName: readEnvValue('MZ_APM_SERVICE_NAME'),
        environment: readEnvValue('MZ_APM_ENVIRONMENT'),
        transactionSampleRate: readEnvValue('MZ_APM_SAMPLE_RATE'),
        stackTraceLimit: readEnvValue('MZ_APM_STACK_TRACE_LIMIT'),
        timeout: readEnvValue('MZ_APM_TIMEOUT'),
      },
    );

    const args = profilerValue !== ''
      ? ['service', 'update', '--env-add', `MAGE_PROFILER=${profilerValue}`, serviceName]
      : ['service', 'update', '--env-rm', 'MAGE_PROFILER', serviceName];
    const result = await runCommand('docker', args, 120_000);
    if (result.code === 0) {
      continue;
    }
    const output = `${result.stdout}\n${result.stderr}`.toLowerCase();
    if (output.includes('no such service')) {
      console.warn(`upgrade.migration.sync_magento_apm_profiler_bootstrap: ${serviceName} not found; skipping`);
      continue;
    }
    if (output.includes('nothing to update')) {
      continue;
    }
    throw new Error(
      `Failed to sync MAGE_PROFILER on ${serviceName}: ${result.stderr || result.stdout || `exit ${result.code}`}`
    );
  }
});
