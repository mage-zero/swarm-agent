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

async function runStabilizationCycle(environmentId: number, reason: string): Promise<void> {
  const runId = crypto.randomUUID();
  const checks: StabilizationCheck[] = [];

  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    run_id: runId,
    current_step: 'db_replication_status',
    current_step_started_at: nowIso(),
    checks: [],
    last_error: '',
  });

  const dbStatus = await executeCheck(environmentId, 'db_replication_status');
  checks.push(dbStatus);

  if (dbStatus.status !== 'ok') {
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

  upsertStabilizationState(environmentId, {
    status: 'stabilizing',
    mode: 'active',
    run_id: runId,
    current_step: 'proxysql_ready',
    current_step_started_at: nowIso(),
    checks,
  });
  checks.push(await executeCheck(environmentId, 'proxysql_ready'));

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
      .map((check) => `${check.runbook_id}: ${check.summary}`)
      .join('; ')
    : '';

  upsertStabilizationState(environmentId, {
    status: hasErrors ? 'degraded' : 'stable',
    mode: 'active',
    run_id: runId,
    current_step: '',
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
