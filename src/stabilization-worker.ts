import crypto from 'crypto';
import { runCommand } from './exec.js';
import {
  executeRunbookById,
} from './support-runbooks.js';
import {
  type StabilizationCheck,
  STABILIZATION_LEASE_TTL_MS,
  STABILIZATION_POST_DEPLOY_GRACE_MS,
  consumeStabilizationRunRequest,
  enqueueStabilizationRun,
  isStabilizationLeaseActive,
  listQueuedStabilizationEnvironmentIds,
  listStabilizationLeaseEnvironmentIds,
  listStabilizationStateEnvironmentIds,
  markStabilizationLeaseEnded,
  markStabilizationLeaseHeartbeat,
  markStabilizationLeaseStarted,
  peekStabilizationRunRequest,
  readStabilizationLease,
  readStabilizationState,
  upsertStabilizationState,
} from './stabilization-state.js';

const STABILIZATION_ENABLED = (process.env.MZ_STABILIZATION_ENABLED || '1') !== '0';
const stabilizationTickParsed = Number(process.env.MZ_STABILIZATION_TICK_MS || 30_000);
const STABILIZATION_TICK_MS = Math.max(
  5_000,
  Number.isFinite(stabilizationTickParsed) && stabilizationTickParsed > 0 ? Math.floor(stabilizationTickParsed) : 30_000,
);
const stabilizationRunIntervalParsed = Number(process.env.MZ_STABILIZATION_RUN_INTERVAL_MS || 5 * 60_000);
const STABILIZATION_RUN_INTERVAL_MS = Math.max(
  30_000,
  Number.isFinite(stabilizationRunIntervalParsed) && stabilizationRunIntervalParsed > 0
    ? Math.floor(stabilizationRunIntervalParsed)
    : 5 * 60_000,
);

let stabilizationTickTimer: NodeJS.Timeout | null = null;
let stabilizationTickRunning = false;

const STABILIZATION_CHECK_LABELS: Record<string, string> = {
  db_replication_status: 'Database replication',
  db_replica_healthcheck_status: 'Replica healthcheck/auth',
  db_replica_healthcheck_repair: 'Replica healthcheck/auth repair',
  db_replica_repair: 'Database replica repair',
  proxysql_ready: 'ProxySQL readiness',
  http_smoke_check: 'HTTP smoke check',
  varnish_ready: 'Varnish readiness',
};

function formatStabilizationCheckLabel(runbookId: string): string {
  const normalized = String(runbookId || '').trim();
  if (!normalized) {
    return 'Check';
  }
  return STABILIZATION_CHECK_LABELS[normalized] || normalized.replace(/_/g, ' ');
}

function log(message: string) {
  console.log(`[stabilization] ${message}`);
}

function nowIso() {
  return new Date().toISOString();
}

function parseServiceEnvironmentIds(raw: string): number[] {
  const ids = new Set<number>();
  for (const line of raw.split('\n')) {
    const name = line.trim();
    if (!name) continue;
    const match = name.match(/^mz-env-(\d+)_/);
    if (!match) continue;
    const parsed = Number.parseInt(String(match[1] || ''), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      ids.add(parsed);
    }
  }
  return Array.from(ids).sort((a, b) => a - b);
}

async function listServiceEnvironmentIds(): Promise<number[]> {
  const result = await runCommand('docker', ['service', 'ls', '--format', '{{.Name}}'], 12_000);
  if (result.code !== 0) {
    return [];
  }
  return parseServiceEnvironmentIds(result.stdout || '');
}

async function resolveEnvironmentIds(): Promise<number[]> {
  const ids = new Set<number>();
  for (const id of await listServiceEnvironmentIds()) ids.add(id);
  for (const id of listQueuedStabilizationEnvironmentIds()) ids.add(id);
  for (const id of listStabilizationLeaseEnvironmentIds()) ids.add(id);
  for (const id of listStabilizationStateEnvironmentIds()) ids.add(id);
  return Array.from(ids).sort((a, b) => a - b);
}

async function executeCheck(environmentId: number, runbookId: string): Promise<StabilizationCheck> {
  try {
    const result = await executeRunbookById(runbookId, environmentId, {});
    if (!result) {
      return {
        runbook_id: runbookId,
        status: 'failed',
        summary: `${runbookId} not supported by swarm-agent`,
        finished_at: nowIso(),
      };
    }
    const status = String(result.status || 'failed');
    const summary = String(result.summary || '').trim() || `${runbookId} returned ${status}`;
    return {
      runbook_id: runbookId,
      status,
      summary,
      finished_at: nowIso(),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      runbook_id: runbookId,
      status: 'failed',
      summary: message || 'runbook execution failed',
      finished_at: nowIso(),
    };
  }
}

function shouldRunBySchedule(nextRunAt: string | undefined, nowMs: number): boolean {
  if (!nextRunAt) return true;
  const parsed = Date.parse(nextRunAt);
  if (!Number.isFinite(parsed)) return true;
  return parsed <= nowMs;
}

function parseDesiredReplicaCountFromMode(raw: string): number | null {
  const payload = String(raw || '').trim();
  if (!payload) return null;
  try {
    const parsed = JSON.parse(payload) as {
      Replicated?: { Replicas?: unknown };
      Global?: unknown;
    };
    if (parsed && typeof parsed === 'object') {
      if (parsed.Global && !parsed.Replicated) {
        return 1;
      }
      const replicasRaw = parsed.Replicated?.Replicas;
      if (typeof replicasRaw === 'number' && Number.isFinite(replicasRaw)) {
        return Math.max(0, Math.trunc(replicasRaw));
      }
      if (typeof replicasRaw === 'string') {
        const normalized = replicasRaw.trim();
        if (!normalized) return null;
        const parsedReplicas = Number.parseInt(normalized, 10);
        if (Number.isFinite(parsedReplicas)) {
          return Math.max(0, parsedReplicas);
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

async function isDatabaseReplicaExpected(environmentId: number): Promise<boolean> {
  return isServiceExpected(environmentId, 'database-replica', 'replica stabilization checks');
}

async function isProxySqlExpected(environmentId: number): Promise<boolean> {
  return isServiceExpected(environmentId, 'proxysql', 'ProxySQL stabilization checks');
}

async function isServiceExpected(
  environmentId: number,
  serviceSuffix: string,
  checkDescription: string,
): Promise<boolean> {
  const serviceName = `mz-env-${environmentId}_${serviceSuffix}`;
  const inspect = await runCommand(
    'docker',
    ['service', 'inspect', serviceName, '--format', '{{json .Spec.Mode}}'],
    12_000,
  );
  if (inspect.code !== 0) {
    const errorText = `${inspect.stderr || ''} ${inspect.stdout || ''}`.toLowerCase();
    if (errorText.includes('no such service') || errorText.includes('not found')) {
      log(`env=${environmentId} ${serviceName} is absent; skipping ${checkDescription}`);
      return false;
    }
    log(`env=${environmentId} failed to inspect ${serviceName}; keeping ${checkDescription} enabled`);
    return true;
  }
  const desiredReplicas = parseDesiredReplicaCountFromMode(inspect.stdout || '');
  if (desiredReplicas === null) {
    log(`env=${environmentId} unable to parse replica mode for ${serviceName}; keeping ${checkDescription} enabled`);
    return true;
  }
  if (desiredReplicas < 1) {
    log(`env=${environmentId} ${serviceName} desired replicas=${desiredReplicas}; skipping ${checkDescription}`);
    return false;
  }
  return true;
}

async function runStabilizationCycle(environmentId: number, reason: string): Promise<void> {
  const runId = crypto.randomUUID();
  const checks: StabilizationCheck[] = [];
  const dbReplicaExpected = await isDatabaseReplicaExpected(environmentId);
  const proxysqlExpected = await isProxySqlExpected(environmentId);

  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    run_id: runId,
    current_step: dbReplicaExpected ? 'db_replication_status' : (proxysqlExpected ? 'proxysql_ready' : 'http_smoke_check'),
    current_step_started_at: nowIso(),
    checks: [],
    last_error: '',
  });

  if (dbReplicaExpected) {
    const dbStatus = await executeCheck(environmentId, 'db_replication_status');
    checks.push(dbStatus);

    if (dbStatus.status !== 'ok') {
      upsertStabilizationState(environmentId, {
        status: 'stabilizing',
        mode: 'active',
        run_id: runId,
        current_step: 'db_replica_healthcheck_status',
        current_step_started_at: nowIso(),
        checks,
      });
      const dbHealthcheckStatus = await executeCheck(environmentId, 'db_replica_healthcheck_status');
      checks.push(dbHealthcheckStatus);

      if (dbHealthcheckStatus.status !== 'ok') {
        upsertStabilizationState(environmentId, {
          status: 'stabilizing',
          mode: 'active',
          run_id: runId,
          current_step: 'db_replica_healthcheck_repair',
          current_step_started_at: nowIso(),
          checks,
        });
        checks.push(await executeCheck(environmentId, 'db_replica_healthcheck_repair'));
      }

      upsertStabilizationState(environmentId, {
        status: 'stabilizing',
        mode: 'active',
        run_id: runId,
        current_step: 'db_replica_repair',
        current_step_started_at: nowIso(),
        checks,
      });
      checks.push(await executeCheck(environmentId, 'db_replica_repair'));
    }
  } else {
    checks.push({
      runbook_id: 'db_replication_status',
      status: 'ok',
      summary: 'Database replica is intentionally disabled (service absent or scaled to 0); replication checks skipped.',
      finished_at: nowIso(),
    });
  }

  if (proxysqlExpected) {
    upsertStabilizationState(environmentId, {
      status: 'stabilizing',
      mode: 'active',
      run_id: runId,
      current_step: 'proxysql_ready',
      current_step_started_at: nowIso(),
      checks,
    });
    checks.push(await executeCheck(environmentId, 'proxysql_ready'));
  } else {
    checks.push({
      runbook_id: 'proxysql_ready',
      status: 'ok',
      summary: 'ProxySQL is intentionally disabled (service absent or scaled to 0); readiness checks skipped.',
      finished_at: nowIso(),
    });
  }

  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    run_id: runId,
    current_step: 'http_smoke_check',
    current_step_started_at: nowIso(),
    checks,
  });
  checks.push(await executeCheck(environmentId, 'http_smoke_check'));

  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    run_id: runId,
    current_step: 'varnish_ready',
    current_step_started_at: nowIso(),
    checks,
  });
  checks.push(await executeCheck(environmentId, 'varnish_ready'));

  const hasErrors = checks.some((check) => check.status === 'failed' || check.status === 'warning');
  const nowAt = nowIso();
  const nextRunAt = new Date(Date.now() + STABILIZATION_RUN_INTERVAL_MS).toISOString();
  const lastError = hasErrors
    ? checks
      .filter((check) => check.status === 'failed' || check.status === 'warning')
      .map((check) => `${formatStabilizationCheckLabel(check.runbook_id)}: ${check.summary}`)
      .join('; ')
    : '';

  upsertStabilizationState(environmentId, {
    status: hasErrors ? 'degraded' : 'stable',
    mode: 'active',
    run_id: runId,
    current_step: hasErrors
      ? 'Waiting for next retry cycle'
      : 'Monitoring between scheduled checks',
    current_step_started_at: nowAt,
    checks,
    last_error: lastError,
    last_success_at: hasErrors ? readStabilizationState(environmentId)?.last_success_at : nowAt,
    last_failure_at: hasErrors ? nowAt : readStabilizationState(environmentId)?.last_failure_at,
    next_run_at: nextRunAt,
    lease_active: false,
  });

  log(`env=${environmentId} cycle=${runId} reason=${reason} status=${hasErrors ? 'degraded' : 'stable'}`);
}

async function processEnvironment(environmentId: number): Promise<void> {
  const nowMs = Date.now();
  const state = readStabilizationState(environmentId);
  const lease = readStabilizationLease(environmentId);
  const leaseActive = isStabilizationLeaseActive(lease, nowMs);

  if (leaseActive) {
    upsertStabilizationState(environmentId, {
      status: 'maintenance',
      mode: 'observe_only',
      lease_active: true,
      lease_expires_at: lease?.expires_at || '',
      current_step: 'Deploy window active (observe only)',
      current_step_started_at: lease?.started_at || lease?.last_heartbeat_at || nowIso(),
    });
    return;
  }

  const queued = peekStabilizationRunRequest(environmentId);
  const queuedDue = queued ? Date.parse(String(queued.run_after_at || '')) <= nowMs : false;
  const scheduledDue = shouldRunBySchedule(state?.next_run_at, nowMs);
  const shouldRun = queuedDue || scheduledDue;
  if (!shouldRun) {
    if (state?.lease_active) {
      upsertStabilizationState(environmentId, {
        mode: 'active',
        lease_active: false,
      });
    }
    return;
  }

  if (queuedDue) {
    consumeStabilizationRunRequest(environmentId);
  }
  const reason = queuedDue ? String(queued?.reason || 'queued') : 'scheduled';
  await runStabilizationCycle(environmentId, reason);
}

async function stabilizationTick(): Promise<void> {
  if (stabilizationTickRunning) return;
  stabilizationTickRunning = true;
  try {
    const environmentIds = await resolveEnvironmentIds();
    for (const environmentId of environmentIds) {
      try {
        await processEnvironment(environmentId);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        upsertStabilizationState(environmentId, {
          status: 'degraded',
          mode: 'active',
          current_step: '',
          last_error: message,
          last_failure_at: nowIso(),
          next_run_at: new Date(Date.now() + STABILIZATION_RUN_INTERVAL_MS).toISOString(),
          lease_active: false,
        });
        log(`env=${environmentId} tick failed: ${message}`);
      }
    }
  } finally {
    stabilizationTickRunning = false;
  }
}

export function requestImmediateStabilizationRun(environmentId: number, reason: string, deploymentId = ''): void {
  enqueueStabilizationRun(environmentId, {
    reason,
    delay_ms: 0,
    deployment_id: deploymentId || undefined,
    requested_by: 'deploy-worker',
  });
  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    current_step: 'Queued stabilization run',
    current_step_started_at: nowIso(),
    next_run_at: nowIso(),
    lease_active: false,
  });
}

export function notifyDeployStartForStabilization(environmentId: number, deploymentId: string): void {
  const lease = markStabilizationLeaseStarted(environmentId, deploymentId, STABILIZATION_LEASE_TTL_MS);
  upsertStabilizationState(environmentId, {
    status: 'maintenance',
    mode: 'observe_only',
    lease_active: true,
    lease_expires_at: lease.expires_at,
    current_step: 'Deploy window active (observe only)',
    current_step_started_at: lease.started_at,
  });
}

export function notifyDeployHeartbeatForStabilization(environmentId: number, deploymentId: string): void {
  const lease = markStabilizationLeaseHeartbeat(environmentId, deploymentId, STABILIZATION_LEASE_TTL_MS);
  upsertStabilizationState(environmentId, {
    status: 'maintenance',
    mode: 'observe_only',
    lease_active: true,
    lease_expires_at: lease.expires_at,
    current_step: 'Deploy window active (observe only)',
    current_step_started_at: lease.started_at,
  });
}

export function notifyDeployEndForStabilization(
  environmentId: number,
  deploymentId: string,
  outcome: 'succeeded' | 'failed',
): void {
  markStabilizationLeaseEnded(environmentId, deploymentId, outcome);
  const queued = enqueueStabilizationRun(environmentId, {
    reason: outcome === 'succeeded' ? 'post_deploy' : 'post_deploy_failure',
    delay_ms: STABILIZATION_POST_DEPLOY_GRACE_MS,
    deployment_id: deploymentId,
    requested_by: 'deploy-worker',
  });
  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    lease_active: false,
    lease_expires_at: '',
    current_step: 'Waiting for post-deploy stabilization window',
    current_step_started_at: nowIso(),
    next_run_at: queued.run_after_at,
  });
}

export function startStabilizationWorker(): void {
  if (!STABILIZATION_ENABLED) return;
  if (stabilizationTickTimer) return;
  void stabilizationTick();
  stabilizationTickTimer = setInterval(() => {
    void stabilizationTick();
  }, STABILIZATION_TICK_MS);
  stabilizationTickTimer.unref?.();
}

export const __testing = {
  parseServiceEnvironmentIds,
  parseDesiredReplicaCountFromMode,
  isDatabaseReplicaExpected,
  isProxySqlExpected,
  isServiceExpected,
  runStabilizationCycle,
};
