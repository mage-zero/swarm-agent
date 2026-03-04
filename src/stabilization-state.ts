import fs from 'fs';
import path from 'path';

const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const STABILIZATION_META_DIR = process.env.MZ_STABILIZATION_META_DIR || path.join(DEPLOY_QUEUE_DIR, 'meta', 'stabilization');
const STABILIZATION_LEASE_DIR = path.join(STABILIZATION_META_DIR, 'leases');
const STABILIZATION_STATE_DIR = path.join(STABILIZATION_META_DIR, 'state');
const STABILIZATION_QUEUE_DIR = path.join(STABILIZATION_META_DIR, 'queued');
const STABILIZATION_FILE = /^env-(\d+)\.json$/i;

const leaseTtlParsed = Number(process.env.MZ_STABILIZATION_LEASE_TTL_MS || 15 * 60 * 1000);
export const STABILIZATION_LEASE_TTL_MS = Math.max(
  60_000,
  Number.isFinite(leaseTtlParsed) && leaseTtlParsed > 0 ? Math.floor(leaseTtlParsed) : 15 * 60 * 1000,
);

const graceParsed = Number(process.env.MZ_STABILIZATION_POST_DEPLOY_GRACE_MS || 60_000);
export const STABILIZATION_POST_DEPLOY_GRACE_MS = Math.max(
  0,
  Number.isFinite(graceParsed) && graceParsed >= 0 ? Math.floor(graceParsed) : 60_000,
);

export type StabilizationStatus = 'unknown' | 'maintenance' | 'stabilizing' | 'stable' | 'degraded';
export type StabilizationMode = 'observe_only' | 'active';

export type StabilizationLease = {
  environment_id: number;
  deployment_id: string;
  active: boolean;
  started_at: string;
  last_heartbeat_at: string;
  expires_at: string;
  ended_at?: string;
  outcome?: 'succeeded' | 'failed' | 'cancelled';
};

export type StabilizationQueueRequest = {
  environment_id: number;
  requested_at: string;
  run_after_at: string;
  reason: string;
  deployment_id?: string;
  requested_by?: string;
};

export type StabilizationCheck = {
  runbook_id: string;
  status: string;
  summary: string;
  finished_at: string;
};

export type StabilizationState = {
  environment_id: number;
  status: StabilizationStatus;
  mode: StabilizationMode;
  updated_at: string;
  run_id?: string;
  current_step?: string;
  current_step_started_at?: string;
  checks?: StabilizationCheck[];
  last_error?: string;
  last_success_at?: string;
  last_failure_at?: string;
  next_run_at?: string;
  lease_active?: boolean;
  lease_expires_at?: string;
};

type JsonObject = Record<string, unknown>;

function nowIso() {
  return new Date().toISOString();
}

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function ensureStabilizationDirs() {
  ensureDir(STABILIZATION_META_DIR);
  ensureDir(STABILIZATION_LEASE_DIR);
  ensureDir(STABILIZATION_STATE_DIR);
  ensureDir(STABILIZATION_QUEUE_DIR);
}

function readJsonFile<T extends JsonObject>(filePath: string): T | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) {
      return null;
    }
    const parsed = JSON.parse(raw) as T;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function writeJsonAtomic(filePath: string, payload: unknown) {
  ensureStabilizationDirs();
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function listEnvironmentIdsFromDir(dirPath: string): number[] {
  if (!fs.existsSync(dirPath)) {
    return [];
  }
  const ids = new Set<number>();
  const entries = fs.readdirSync(dirPath);
  for (const entry of entries) {
    const match = entry.match(STABILIZATION_FILE);
    if (!match) continue;
    const parsed = Number.parseInt(String(match[1] || ''), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      ids.add(parsed);
    }
  }
  return Array.from(ids).sort((a, b) => a - b);
}

function leasePath(environmentId: number) {
  return path.join(STABILIZATION_LEASE_DIR, `env-${environmentId}.json`);
}

function statePath(environmentId: number) {
  return path.join(STABILIZATION_STATE_DIR, `env-${environmentId}.json`);
}

function queuePath(environmentId: number) {
  return path.join(STABILIZATION_QUEUE_DIR, `env-${environmentId}.json`);
}

export function listStabilizationLeaseEnvironmentIds() {
  return listEnvironmentIdsFromDir(STABILIZATION_LEASE_DIR);
}

export function listStabilizationStateEnvironmentIds() {
  return listEnvironmentIdsFromDir(STABILIZATION_STATE_DIR);
}

export function listQueuedStabilizationEnvironmentIds() {
  return listEnvironmentIdsFromDir(STABILIZATION_QUEUE_DIR);
}

export function readStabilizationLease(environmentId: number): StabilizationLease | null {
  return readJsonFile<StabilizationLease>(leasePath(environmentId));
}

export function isStabilizationLeaseActive(lease: StabilizationLease | null, nowMs = Date.now()): boolean {
  if (!lease || !lease.active) return false;
  const expiresAt = Date.parse(String(lease.expires_at || ''));
  if (!Number.isFinite(expiresAt)) return false;
  return expiresAt > nowMs;
}

export function markStabilizationLeaseStarted(
  environmentId: number,
  deploymentId: string,
  ttlMs = STABILIZATION_LEASE_TTL_MS,
): StabilizationLease {
  const now = Date.now();
  const nowAt = nowIso();
  const existing = readStabilizationLease(environmentId);
  const startedAt = existing && existing.deployment_id === deploymentId
    ? String(existing.started_at || nowAt)
    : nowAt;

  const lease: StabilizationLease = {
    environment_id: environmentId,
    deployment_id: deploymentId,
    active: true,
    started_at: startedAt,
    last_heartbeat_at: nowAt,
    expires_at: new Date(now + Math.max(60_000, ttlMs)).toISOString(),
  };
  writeJsonAtomic(leasePath(environmentId), lease);
  return lease;
}

export function markStabilizationLeaseHeartbeat(
  environmentId: number,
  deploymentId: string,
  ttlMs = STABILIZATION_LEASE_TTL_MS,
): StabilizationLease {
  return markStabilizationLeaseStarted(environmentId, deploymentId, ttlMs);
}

export function markStabilizationLeaseEnded(
  environmentId: number,
  deploymentId: string,
  outcome: StabilizationLease['outcome'] = 'succeeded',
): StabilizationLease {
  const nowAt = nowIso();
  const existing = readStabilizationLease(environmentId);
  const startedAt = existing && existing.deployment_id === deploymentId
    ? String(existing.started_at || nowAt)
    : nowAt;
  const lease: StabilizationLease = {
    environment_id: environmentId,
    deployment_id: deploymentId,
    active: false,
    started_at: startedAt,
    last_heartbeat_at: nowAt,
    expires_at: nowAt,
    ended_at: nowAt,
    outcome,
  };
  writeJsonAtomic(leasePath(environmentId), lease);
  return lease;
}

export function readStabilizationState(environmentId: number): StabilizationState | null {
  return readJsonFile<StabilizationState>(statePath(environmentId));
}

export function writeStabilizationState(state: StabilizationState): StabilizationState {
  const normalized: StabilizationState = {
    ...state,
    environment_id: state.environment_id,
    updated_at: state.updated_at || nowIso(),
  };
  writeJsonAtomic(statePath(state.environment_id), normalized);
  return normalized;
}

export function upsertStabilizationState(
  environmentId: number,
  patch: Partial<StabilizationState>,
): StabilizationState {
  const previous = readStabilizationState(environmentId);
  const next: StabilizationState = {
    status: 'unknown',
    mode: 'active',
    ...(previous || {}),
    ...patch,
    environment_id: environmentId,
    updated_at: nowIso(),
  };
  writeJsonAtomic(statePath(environmentId), next);
  return next;
}

export function enqueueStabilizationRun(
  environmentId: number,
  params: {
    reason: string;
    delay_ms?: number;
    deployment_id?: string;
    requested_by?: string;
  },
): StabilizationQueueRequest {
  const delayMs = Math.max(0, Number(params.delay_ms ?? 0) || 0);
  const request: StabilizationQueueRequest = {
    environment_id: environmentId,
    requested_at: nowIso(),
    run_after_at: new Date(Date.now() + delayMs).toISOString(),
    reason: String(params.reason || 'manual').trim() || 'manual',
    ...(params.deployment_id ? { deployment_id: params.deployment_id } : {}),
    ...(params.requested_by ? { requested_by: params.requested_by } : {}),
  };
  writeJsonAtomic(queuePath(environmentId), request);
  return request;
}

export function peekStabilizationRunRequest(environmentId: number): StabilizationQueueRequest | null {
  return readJsonFile<StabilizationQueueRequest>(queuePath(environmentId));
}

export function consumeStabilizationRunRequest(environmentId: number): StabilizationQueueRequest | null {
  const request = peekStabilizationRunRequest(environmentId);
  if (!request) {
    return null;
  }
  try {
    fs.rmSync(queuePath(environmentId), { force: true });
  } catch {
    // ignore
  }
  return request;
}
