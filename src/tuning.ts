import fs from 'fs';
import path from 'path';
import type {
  CapacityNode,
  PlannerConfigChange,
  PlannerInspectionPayload,
  PlannerResourceSpec,
  PlannerResources,
  PlannerTuningAdjustment,
  PlannerTuningPayload,
  PlannerTuningPlacement,
  PlannerTuningProfile,
  PlannerTuningService,
} from './planner-types.js';
import { buildConfigChanges } from './config-advisor.js';

type StoredTuningProfiles = {
  base: PlannerTuningProfile;
  recommended?: PlannerTuningProfile;
  approved: PlannerTuningProfile[];
  last_recommended_at?: string;
};

type ServiceTuningPolicy = {
  limit_up_threshold: number;
  reserve_up_threshold: number;
  limit_scale_up: number;
  reserve_scale_up: number;
  max_limit_multiplier: number;
  max_reserve_multiplier: number;
};

export type AiTuningProfile = {
  strategy?: string;
  summary?: string;
  confidence?: number;
  adjustments?: Record<string, PlannerTuningAdjustment>;
  placements?: PlannerTuningPlacement[];
};

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
export const TUNING_PROFILE_PATH = process.env.MZ_TUNING_PROFILE_PATH
  || `${NODE_DIR}/tuning-profiles.json`;
export const TUNING_INTERVAL_MS = Number(process.env.MZ_TUNING_INTERVAL_MS || 6 * 60 * 60 * 1000);
const TUNING_RETENTION_DAYS = Number(process.env.MZ_TUNING_RETENTION_DAYS || 365);
const TUNING_STABLE_VARIANCE = Number(process.env.MZ_TUNING_STABLE_VARIANCE || 0.1);
const TUNING_STABLE_STREAK_TARGET = Number(process.env.MZ_TUNING_STABLE_STREAK || 3);
const TUNING_INCREMENTAL_FACTOR = Number(process.env.MZ_TUNING_INCREMENTAL_FACTOR || 0.5);

const DEFAULT_TUNING_POLICY: ServiceTuningPolicy = {
  limit_up_threshold: 0.85,
  reserve_up_threshold: 0.75,
  limit_scale_up: 1.2,
  reserve_scale_up: 1.15,
  max_limit_multiplier: 1.5,
  max_reserve_multiplier: 1.5,
};

const SERVICE_TUNING_POLICIES: Record<string, ServiceTuningPolicy> = {
  'php-fpm': {
    limit_up_threshold: 0.75,
    reserve_up_threshold: 0.65,
    limit_scale_up: 1.35,
    reserve_scale_up: 1.2,
    max_limit_multiplier: 2,
    max_reserve_multiplier: 1.75,
  },
  'php-fpm-admin': {
    limit_up_threshold: 0.9,
    reserve_up_threshold: 0.8,
    limit_scale_up: 1.15,
    reserve_scale_up: 1.1,
    max_limit_multiplier: 1.5,
    max_reserve_multiplier: 1.5,
  },
  cron: {
    limit_up_threshold: 0.85,
    reserve_up_threshold: 0.7,
    limit_scale_up: 1.2,
    reserve_scale_up: 1.15,
    max_limit_multiplier: 1.5,
    max_reserve_multiplier: 1.5,
  },
};

function getTuningPolicy(service: string): ServiceTuningPolicy {
  return SERVICE_TUNING_POLICIES[service] || DEFAULT_TUNING_POLICY;
}

export function clonePlannerResources(resources: PlannerResources): PlannerResources {
  const cloned: PlannerResources = { services: {} };
  for (const [name, spec] of Object.entries(resources.services)) {
    cloned.services[name] = {
      limits: {
        cpu_cores: spec.limits.cpu_cores,
        memory_bytes: spec.limits.memory_bytes,
      },
      reservations: {
        cpu_cores: spec.reservations.cpu_cores,
        memory_bytes: spec.reservations.memory_bytes,
      },
    };
  }
  return cloned;
}

export function cloneTuningProfile(
  profile: PlannerTuningProfile,
  status: PlannerTuningProfile['status'],
  id: string,
  now: string,
): PlannerTuningProfile {
  const adjustments: Record<string, PlannerTuningAdjustment> = {};
  for (const [service, adjustment] of Object.entries(profile.adjustments || {})) {
    adjustments[service] = {
      limits: adjustment.limits ? { ...adjustment.limits } : undefined,
      reservations: adjustment.reservations ? { ...adjustment.reservations } : undefined,
      source: adjustment.source,
      notes: adjustment.notes ? [...adjustment.notes] : undefined,
    };
  }
  const placements = (profile.placements || []).map((placement) => ({ ...placement }));
  const configChanges: PlannerConfigChange[] | undefined = profile.config_changes
    ? profile.config_changes.map((change) => ({
      service: change.service,
      changes: { ...change.changes },
      notes: change.notes ? [...change.notes] : undefined,
      evidence: change.evidence ? { ...change.evidence } : undefined,
    }))
    : undefined;
  return {
    id,
    status,
    strategy: profile.strategy,
    resources: clonePlannerResources(profile.resources),
    adjustments,
    placements,
    created_at: profile.created_at || now,
    updated_at: now,
    confidence: profile.confidence,
    deterministic_confidence: profile.deterministic_confidence,
    ai_confidence: profile.ai_confidence,
    sample_count: profile.sample_count,
    stability_streak: profile.stability_streak,
    summary: profile.summary,
    config_changes: configChanges,
  };
}

function clampFactor(value: number): number {
  if (!Number.isFinite(value)) {
    return 0.5;
  }
  return Math.min(0.9, Math.max(0.1, value));
}

function roundCores(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.round(value * 100) / 100;
}

function blendSpec(base: PlannerResourceSpec, target: PlannerResourceSpec, factor: number): PlannerResourceSpec {
  return {
    limits: {
      cpu_cores: roundCores(base.limits.cpu_cores + (target.limits.cpu_cores - base.limits.cpu_cores) * factor),
      memory_bytes: base.limits.memory_bytes + (target.limits.memory_bytes - base.limits.memory_bytes) * factor,
    },
    reservations: {
      cpu_cores: roundCores(base.reservations.cpu_cores + (target.reservations.cpu_cores - base.reservations.cpu_cores) * factor),
      memory_bytes: base.reservations.memory_bytes + (target.reservations.memory_bytes - base.reservations.memory_bytes) * factor,
    },
  };
}

function blendResources(
  base: PlannerResources,
  target: PlannerResources,
  factor: number,
): PlannerResources {
  const blended: PlannerResources = { services: {} };
  const keys = new Set([...Object.keys(base.services), ...Object.keys(target.services)]);
  for (const key of keys) {
    const baseSpec = base.services[key];
    const targetSpec = target.services[key];
    if (!baseSpec && targetSpec) {
      blended.services[key] = clonePlannerResources({ services: { [key]: targetSpec } }).services[key];
      continue;
    }
    if (baseSpec && !targetSpec) {
      blended.services[key] = clonePlannerResources({ services: { [key]: baseSpec } }).services[key];
      continue;
    }
    if (!baseSpec || !targetSpec) {
      continue;
    }
    blended.services[key] = blendSpec(baseSpec, targetSpec, factor);
  }
  return blended;
}

export function buildIncrementalProfile(
  baseResources: PlannerResources,
  recommended: PlannerTuningProfile,
  now: string,
): PlannerTuningProfile {
  const factor = clampFactor(TUNING_INCREMENTAL_FACTOR);
  const incrementalResources = blendResources(baseResources, recommended.resources, factor);
  const adjustments = calculateAdjustments(baseResources, incrementalResources, 'incremental');
  const summaryParts: string[] = [];
  if (recommended.summary) {
    summaryParts.push(recommended.summary);
  }
  summaryParts.push(`Incremental (${Math.round(factor * 100)}% of recommended)`);
  return {
    id: 'incremental',
    status: 'incremental',
    strategy: `${recommended.strategy}+incremental`,
    resources: incrementalResources,
    adjustments,
    placements: recommended.placements,
    summary: summaryParts.join(' ').trim(),
    created_at: recommended.created_at || now,
    updated_at: now,
    sample_count: recommended.sample_count,
    stability_streak: recommended.stability_streak,
    deterministic_confidence: recommended.deterministic_confidence,
    ai_confidence: recommended.ai_confidence,
    confidence: recommended.confidence,
    config_changes: recommended.config_changes,
  };
}

export function loadTuningProfiles(): StoredTuningProfiles | null {
  try {
    const raw = fs.readFileSync(TUNING_PROFILE_PATH, 'utf8').trim();
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as StoredTuningProfiles;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function saveTuningProfiles(profiles: StoredTuningProfiles) {
  try {
    const dir = path.dirname(TUNING_PROFILE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const tmpPath = `${TUNING_PROFILE_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(profiles, null, 2));
    fs.renameSync(tmpPath, TUNING_PROFILE_PATH);
  } catch {
    // ignore persistence failures
  }
}

export function createBaseProfile(resources: PlannerResources, now: string): PlannerTuningProfile {
  return {
    id: 'base',
    status: 'base',
    strategy: 'base-defaults',
    resources: clonePlannerResources(resources),
    adjustments: {},
    placements: [],
    created_at: now,
    updated_at: now,
  };
}

function calculateAdjustments(
  baseResources: PlannerResources,
  targetResources: PlannerResources,
  source: string,
): Record<string, PlannerTuningAdjustment> {
  const adjustments: Record<string, PlannerTuningAdjustment> = {};
  for (const [service, baseSpec] of Object.entries(baseResources.services)) {
    const targetSpec = targetResources.services[service];
    if (!targetSpec) {
      continue;
    }
    const limitChanged = targetSpec.limits.memory_bytes !== baseSpec.limits.memory_bytes
      || targetSpec.limits.cpu_cores !== baseSpec.limits.cpu_cores;
    const reserveChanged = targetSpec.reservations.memory_bytes !== baseSpec.reservations.memory_bytes
      || targetSpec.reservations.cpu_cores !== baseSpec.reservations.cpu_cores;
    if (!limitChanged && !reserveChanged) {
      continue;
    }
    adjustments[service] = {
      limits: limitChanged
        ? {
          memory_bytes: targetSpec.limits.memory_bytes !== baseSpec.limits.memory_bytes
            ? targetSpec.limits.memory_bytes
            : undefined,
          cpu_cores: targetSpec.limits.cpu_cores !== baseSpec.limits.cpu_cores
            ? targetSpec.limits.cpu_cores
            : undefined,
        }
        : undefined,
      reservations: reserveChanged
        ? {
          memory_bytes: targetSpec.reservations.memory_bytes !== baseSpec.reservations.memory_bytes
            ? targetSpec.reservations.memory_bytes
            : undefined,
          cpu_cores: targetSpec.reservations.cpu_cores !== baseSpec.reservations.cpu_cores
            ? targetSpec.reservations.cpu_cores
            : undefined,
        }
        : undefined,
      source,
    };
  }
  return adjustments;
}

function blendRecommendedResources(
  previous: PlannerResources,
  candidate: PlannerResources,
  weight: number,
): PlannerResources {
  const blended = clonePlannerResources(previous);
  for (const [service, prevSpec] of Object.entries(previous.services)) {
    const candidateSpec = candidate.services[service];
    if (!candidateSpec) {
      continue;
    }
    const nextLimit = Math.round(
      (prevSpec.limits.memory_bytes * weight + candidateSpec.limits.memory_bytes) / (weight + 1),
    );
    const nextReserve = Math.round(
      (prevSpec.reservations.memory_bytes * weight + candidateSpec.reservations.memory_bytes) / (weight + 1),
    );
    const nextCpuLimit = roundCores(
      (prevSpec.limits.cpu_cores * weight + candidateSpec.limits.cpu_cores) / (weight + 1),
    );
    const nextCpuReserve = roundCores(
      (prevSpec.reservations.cpu_cores * weight + candidateSpec.reservations.cpu_cores) / (weight + 1),
    );
    blended.services[service].limits.memory_bytes = nextLimit;
    blended.services[service].reservations.memory_bytes = nextReserve;
    blended.services[service].limits.cpu_cores = nextCpuLimit;
    blended.services[service].reservations.cpu_cores = nextCpuReserve;
  }
  return blended;
}

export function pruneApprovedProfiles(profiles: PlannerTuningProfile[], now: number) {
  const maxAgeMs = TUNING_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  return profiles.filter((profile) => {
    const updatedAt = Date.parse(profile.updated_at || profile.created_at || '');
    if (!updatedAt) {
      return true;
    }
    return now - updatedAt <= maxAgeMs;
  });
}

function isProfileFresh(profile: PlannerTuningProfile | undefined, now: number): boolean {
  if (!profile) {
    return false;
  }
  const maxAgeMs = TUNING_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const updatedAt = Date.parse(profile.updated_at || profile.created_at || '');
  if (!updatedAt) {
    return true;
  }
  return now - updatedAt <= maxAgeMs;
}

function clampConfidence(value?: number): number | null {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }
  if (value < 0) {
    return 0;
  }
  if (value > 1) {
    return 1;
  }
  return value;
}

function calculateProfileDistance(previous: PlannerResources, next: PlannerResources): number {
  const services = new Set([
    ...Object.keys(previous.services),
    ...Object.keys(next.services),
  ]);
  let total = 0;
  let count = 0;
  for (const service of services) {
    const prev = previous.services[service];
    const curr = next.services[service];
    if (!prev || !curr) {
      continue;
    }
    const limitCpuDelta = prev.limits.cpu_cores > 0
      ? Math.abs(curr.limits.cpu_cores - prev.limits.cpu_cores) / prev.limits.cpu_cores
      : 0;
    const reserveCpuDelta = prev.reservations.cpu_cores > 0
      ? Math.abs(curr.reservations.cpu_cores - prev.reservations.cpu_cores) / prev.reservations.cpu_cores
      : 0;
    const limitDelta = prev.limits.memory_bytes > 0
      ? Math.abs(curr.limits.memory_bytes - prev.limits.memory_bytes) / prev.limits.memory_bytes
      : 0;
    const reserveDelta = prev.reservations.memory_bytes > 0
      ? Math.abs(curr.reservations.memory_bytes - prev.reservations.memory_bytes) / prev.reservations.memory_bytes
      : 0;
    total += Math.max(limitCpuDelta, reserveCpuDelta, limitDelta, reserveDelta);
    count += 1;
  }
  return count > 0 ? total / count : 1;
}

function buildDeterministicConfidence(distance: number, stabilityStreak: number): number {
  if (distance > TUNING_STABLE_VARIANCE) {
    return 0;
  }
  const stabilityScore = Math.max(0, 1 - distance / TUNING_STABLE_VARIANCE);
  const streakScore = Math.min(1, stabilityStreak / Math.max(1, TUNING_STABLE_STREAK_TARGET));
  return stabilityScore * streakScore;
}

function buildRecommendedProfile(
  candidate: PlannerTuningProfile,
  baseResources: PlannerResources,
  previous: PlannerTuningProfile | undefined,
  now: string,
): PlannerTuningProfile {
  const nextSampleCount = (previous?.sample_count || 0) + 1;
  const weight = Math.max(1, previous?.sample_count || 1);
  const recommendedResources = previous
    ? blendRecommendedResources(previous.resources, candidate.resources, weight)
    : clonePlannerResources(candidate.resources);
  const adjustments = calculateAdjustments(baseResources, recommendedResources, 'recommended');
  const distance = previous ? calculateProfileDistance(previous.resources, candidate.resources) : 1;
  const stable = distance <= TUNING_STABLE_VARIANCE;
  const stabilityStreak = stable ? (previous?.stability_streak || 0) + 1 : 0;
  const deterministicConfidence = buildDeterministicConfidence(distance, stabilityStreak);
  const aiConfidence = clampConfidence(candidate.ai_confidence);
  const confidence = aiConfidence === null
    ? deterministicConfidence
    : (deterministicConfidence + aiConfidence) / 2;
  return {
    id: 'recommended',
    status: 'recommended',
    strategy: candidate.strategy,
    resources: recommendedResources,
    adjustments,
    placements: candidate.placements,
    summary: candidate.summary,
    created_at: previous?.created_at || now,
    updated_at: now,
    sample_count: nextSampleCount,
    stability_streak: stabilityStreak,
    deterministic_confidence: deterministicConfidence,
    ai_confidence: aiConfidence ?? undefined,
    confidence,
    config_changes: candidate.config_changes,
  };
}

function selectActiveProfile(
  base: PlannerTuningProfile,
  approved: PlannerTuningProfile[],
): PlannerTuningProfile {
  if (!approved.length) {
    return base;
  }
  const sorted = [...approved].sort((a, b) => {
    const aTime = Date.parse(a.updated_at || a.created_at || '') || 0;
    const bTime = Date.parse(b.updated_at || b.created_at || '') || 0;
    return bTime - aTime;
  });
  return sorted[0] || base;
}

type RecommendationState = {
  stored: StoredTuningProfiles | null;
  recommended: PlannerTuningProfile | undefined;
  shouldUpdate: boolean;
  lastRecommendedAt?: string;
};

function resolveRecommendationState(stored: StoredTuningProfiles | null, nowMs: number): RecommendationState {
  let recommendedProfile = stored?.recommended;
  if (recommendedProfile && !isProfileFresh(recommendedProfile, nowMs)) {
    recommendedProfile = undefined;
  }
  const lastRecommendedAt = stored?.last_recommended_at
    ? Date.parse(stored.last_recommended_at)
    : 0;
  const shouldUpdateRecommended = !recommendedProfile
    || !lastRecommendedAt
    || nowMs - lastRecommendedAt >= TUNING_INTERVAL_MS;

  return {
    stored,
    recommended: recommendedProfile,
    shouldUpdate: shouldUpdateRecommended,
    lastRecommendedAt: stored?.last_recommended_at,
  };
}

export function isRecommendationDue(nowMs = Date.now()): boolean {
  const stored = loadTuningProfiles();
  const state = resolveRecommendationState(stored, nowMs);
  return state.shouldUpdate;
}

export function buildTuningPayloadFromStorage(
  baseResources: PlannerResources,
  inspection: PlannerInspectionPayload,
): { payload: PlannerTuningPayload; active: PlannerTuningProfile } {
  const now = new Date().toISOString();
  const nowMs = Date.now();
  const stored = loadTuningProfiles();
  const baseProfile = stored?.base || createBaseProfile(baseResources, now);
  baseProfile.resources = clonePlannerResources(baseResources);
  baseProfile.updated_at = now;

  let recommendedProfile = stored?.recommended;
  if (recommendedProfile && !isProfileFresh(recommendedProfile, nowMs)) {
    recommendedProfile = undefined;
  }
  const incrementalProfile = recommendedProfile
    ? buildIncrementalProfile(baseResources, recommendedProfile, now)
    : undefined;

  const approvedProfiles = pruneApprovedProfiles(stored?.approved || [], nowMs);
  const activeProfile = selectActiveProfile(baseProfile, approvedProfiles);

  const payload: PlannerTuningPayload = {
    generated_at: inspection.generated_at,
    services: [],
    base_profile: baseProfile,
    recommended_profile: recommendedProfile,
    incremental_profile: incrementalProfile,
    approved_profiles: approvedProfiles,
    active_profile_id: activeProfile.id,
  };

  saveTuningProfiles({
    base: baseProfile,
    recommended: recommendedProfile,
    approved: approvedProfiles,
    last_recommended_at: stored?.last_recommended_at,
  });

  return { payload, active: activeProfile };
}

export function buildPlacementHints(
  inspection: PlannerInspectionPayload,
  resources: PlannerResources,
  nodes: CapacityNode[],
): PlannerTuningPlacement[] {
  const placements: PlannerTuningPlacement[] = [];
  const availableNodes = nodes
    .filter((node) => node.status === 'ready' && node.availability === 'active')
    .map((node) => ({
      id: node.id || '',
      hostname: node.hostname || '',
      free_memory_bytes: node.free?.memory_bytes ?? 0,
    }))
    .filter((node) => node.id !== '');

  if (availableNodes.length === 0) {
    return placements;
  }

  const candidates = inspection.services.filter(
    (entry) => !entry.constraints || entry.constraints.length === 0,
  );

  candidates.sort((a, b) => {
    const resourceA = resources.services[a.service];
    const resourceB = resources.services[b.service];
    const footprintA = (resourceA?.reservations.memory_bytes || 0) * Math.max(1, a.replicas || 0);
    const footprintB = (resourceB?.reservations.memory_bytes || 0) * Math.max(1, b.replicas || 0);
    return footprintB - footprintA;
  });

  for (const entry of candidates) {
    const resource = resources.services[entry.service];
    if (!resource) {
      continue;
    }
    const footprint = resource.reservations.memory_bytes * Math.max(1, entry.replicas || 0);
    availableNodes.sort((a, b) => b.free_memory_bytes - a.free_memory_bytes);
    const target = availableNodes[0];
    if (!target) {
      continue;
    }
    placements.push({
      name: entry.name,
      service: entry.service,
      environment_id: entry.environment_id,
      node_id: target.id,
      reason: 'highest available memory headroom',
    });
    target.free_memory_bytes = Math.max(0, target.free_memory_bytes - footprint);
  }

  return placements;
}

export function applyAiAdjustments(
  profile: AiTuningProfile,
  tuningProfile: PlannerTuningProfile,
  resources: PlannerResources,
  baseResources: PlannerResources,
  inspection: PlannerInspectionPayload,
  capacity: { totals: { memory_bytes?: number; cpu_cores?: number }; nodes?: CapacityNode[] },
) {
  const adjustments = profile.adjustments || {};
  const hasAdjustments = adjustments && Object.keys(adjustments).length > 0;

  const totalMem = capacity.totals.memory_bytes || 0;
  const totalCpu = capacity.totals.cpu_cores || 0;
  const maxLimitTotal = totalMem > 0 ? totalMem * 0.9 : 0;
  const maxReserveTotal = totalMem > 0 ? totalMem * 0.8 : 0;
  const maxCpuLimitTotal = totalCpu > 0 ? totalCpu * 0.9 : 0;
  const maxCpuReserveTotal = totalCpu > 0 ? totalCpu * 0.8 : 0;

  let currentLimitTotal = 0;
  let currentReserveTotal = 0;
  let currentCpuLimitTotal = 0;
  let currentCpuReserveTotal = 0;
  const replicasByService = new Map<string, number>();
  const constraintsByService = new Map<string, string[]>();
  for (const entry of inspection.services) {
    replicasByService.set(entry.service, Math.max(1, entry.replicas || 0));
    if (entry.constraints) {
      constraintsByService.set(entry.service, entry.constraints);
    }
    const resource = resources.services[entry.service];
    if (!resource) {
      continue;
    }
    const replicas = Math.max(1, entry.replicas || 0);
    currentLimitTotal += resource.limits.memory_bytes * replicas;
    currentReserveTotal += resource.reservations.memory_bytes * replicas;
    currentCpuLimitTotal += resource.limits.cpu_cores * replicas;
    currentCpuReserveTotal += resource.reservations.cpu_cores * replicas;
  }

  if (hasAdjustments) {
    for (const [service, change] of Object.entries(adjustments)) {
      const resource = resources.services[service];
      const baseResource = baseResources.services[service];
      if (!resource || !baseResource) {
        continue;
      }
      const policy = getTuningPolicy(service);
      const replicas = replicasByService.get(service) || 1;
      const oldMemLimit = resource.limits.memory_bytes;
      const oldMemReserve = resource.reservations.memory_bytes;
      const oldCpuLimit = resource.limits.cpu_cores;
      const oldCpuReserve = resource.reservations.cpu_cores;

      let newLimit = oldMemLimit;
      let newReserve = oldMemReserve;
      let newCpuLimit = oldCpuLimit;
      let newCpuReserve = oldCpuReserve;
      if (change.limits?.memory_bytes && change.limits.memory_bytes > resource.limits.memory_bytes) {
        const cappedLimit = Math.min(
          change.limits.memory_bytes,
          Math.round(baseResource.limits.memory_bytes * policy.max_limit_multiplier),
        );
        newLimit = cappedLimit;
      }
      if (change.reservations?.memory_bytes && change.reservations.memory_bytes > resource.reservations.memory_bytes) {
        const cappedReserve = Math.min(
          change.reservations.memory_bytes,
          Math.round(baseResource.reservations.memory_bytes * policy.max_reserve_multiplier),
        );
        newReserve = cappedReserve;
      }
      if (typeof change.limits?.cpu_cores === 'number' && change.limits.cpu_cores > oldCpuLimit) {
        const maxCpu = baseResource.limits.cpu_cores > 0
          ? baseResource.limits.cpu_cores * policy.max_limit_multiplier
          : oldCpuLimit * policy.max_limit_multiplier;
        newCpuLimit = Math.min(roundCores(change.limits.cpu_cores), roundCores(maxCpu));
      }
      if (typeof change.reservations?.cpu_cores === 'number' && change.reservations.cpu_cores > oldCpuReserve) {
        const maxCpu = baseResource.reservations.cpu_cores > 0
          ? baseResource.reservations.cpu_cores * policy.max_reserve_multiplier
          : oldCpuReserve * policy.max_reserve_multiplier;
        newCpuReserve = Math.min(roundCores(change.reservations.cpu_cores), roundCores(maxCpu));
      }
      if (newReserve > newLimit) {
        newLimit = newReserve;
      }
      if (newCpuReserve > newCpuLimit) {
        newCpuLimit = newCpuReserve;
      }

      const limitDelta = (newLimit - resource.limits.memory_bytes) * replicas;
      if (limitDelta > 0 && maxLimitTotal > 0 && currentLimitTotal + limitDelta > maxLimitTotal) {
        continue;
      }
      const reserveDelta = (newReserve - resource.reservations.memory_bytes) * replicas;
      if (reserveDelta > 0 && maxReserveTotal > 0 && currentReserveTotal + reserveDelta > maxReserveTotal) {
        continue;
      }

      const cpuLimitDelta = (newCpuLimit - oldCpuLimit) * replicas;
      if (cpuLimitDelta > 0 && maxCpuLimitTotal > 0 && currentCpuLimitTotal + cpuLimitDelta > maxCpuLimitTotal) {
        newCpuLimit = oldCpuLimit;
        newCpuReserve = oldCpuReserve;
      }
      if (newCpuReserve > newCpuLimit) {
        newCpuReserve = oldCpuReserve;
      }
      const cpuReserveDelta = (newCpuReserve - oldCpuReserve) * replicas;
      if (cpuReserveDelta > 0 && maxCpuReserveTotal > 0 && currentCpuReserveTotal + cpuReserveDelta > maxCpuReserveTotal) {
        newCpuReserve = oldCpuReserve;
      }

      if (
        newLimit !== oldMemLimit
        || newReserve !== oldMemReserve
        || newCpuLimit !== oldCpuLimit
        || newCpuReserve !== oldCpuReserve
      ) {
        currentLimitTotal += (newLimit - oldMemLimit) * replicas;
        currentReserveTotal += (newReserve - oldMemReserve) * replicas;
        currentCpuLimitTotal += (newCpuLimit - oldCpuLimit) * replicas;
        currentCpuReserveTotal += (newCpuReserve - oldCpuReserve) * replicas;

        resource.limits.memory_bytes = newLimit;
        resource.reservations.memory_bytes = newReserve;
        resource.limits.cpu_cores = newCpuLimit;
        resource.reservations.cpu_cores = newCpuReserve;

        const existing = tuningProfile.adjustments[service];
        const mergedNotes = [
          ...(existing?.notes || []),
          ...(change.notes || []),
        ];
        const nextLimits: NonNullable<PlannerTuningAdjustment['limits']> = {};
        const nextReservations: NonNullable<PlannerTuningAdjustment['reservations']> = {};
        if (resource.limits.memory_bytes !== baseResource.limits.memory_bytes) {
          nextLimits.memory_bytes = resource.limits.memory_bytes;
        }
        if (resource.limits.cpu_cores !== baseResource.limits.cpu_cores) {
          nextLimits.cpu_cores = resource.limits.cpu_cores;
        }
        if (resource.reservations.memory_bytes !== baseResource.reservations.memory_bytes) {
          nextReservations.memory_bytes = resource.reservations.memory_bytes;
        }
        if (resource.reservations.cpu_cores !== baseResource.reservations.cpu_cores) {
          nextReservations.cpu_cores = resource.reservations.cpu_cores;
        }
        tuningProfile.adjustments[service] = {
          limits: Object.keys(nextLimits).length > 0 ? nextLimits : undefined,
          reservations: Object.keys(nextReservations).length > 0 ? nextReservations : undefined,
          source: existing?.source ? `${existing.source}+ai` : 'ai',
          notes: mergedNotes.length > 0 ? mergedNotes : undefined,
        };
      }
    }
  }

  const placements = profile.placements || [];
  if (placements.length > 0) {
    const allowed = placements.filter((entry) => {
      const constraints = constraintsByService.get(entry.service);
      return !constraints || constraints.length === 0;
    });
    if (allowed.length > 0) {
      tuningProfile.placements = allowed;
    }
  }

  const aiConfidence = clampConfidence(profile.confidence);
  if (aiConfidence !== null) {
    tuningProfile.ai_confidence = aiConfidence;
  }

  if (profile.summary) {
    tuningProfile.summary = profile.summary;
  }
  if (profile.strategy) {
    tuningProfile.strategy = `${tuningProfile.strategy}+${profile.strategy}`;
  } else {
    tuningProfile.strategy = `${tuningProfile.strategy}+ai`;
  }
}

export function buildCandidateProfile(
  inspection: PlannerInspectionPayload,
  baseResources: PlannerResources,
  capacity: { totals: { memory_bytes?: number; cpu_cores?: number }; nodes?: CapacityNode[] },
): { profile: PlannerTuningProfile; signals: PlannerTuningService[] } {
  const services: PlannerTuningService[] = [];
  const adjustments: Record<string, PlannerTuningAdjustment> = {};
  const tunedResources = clonePlannerResources(baseResources);

  const totalMem = capacity.totals.memory_bytes || 0;
  const totalCpu = capacity.totals.cpu_cores || 0;
  const maxMemLimitTotal = totalMem > 0 ? totalMem * 0.9 : 0;
  const maxMemReserveTotal = totalMem > 0 ? totalMem * 0.8 : 0;
  const maxCpuLimitTotal = totalCpu > 0 ? totalCpu * 0.9 : 0;
  const maxCpuReserveTotal = totalCpu > 0 ? totalCpu * 0.8 : 0;

  let currentMemLimitTotal = 0;
  let currentMemReserveTotal = 0;
  let currentCpuLimitTotal = 0;
  let currentCpuReserveTotal = 0;
  for (const entry of inspection.services) {
    const resource = tunedResources.services[entry.service];
    if (!resource) {
      continue;
    }
    const replicas = Math.max(1, entry.replicas || 0);
    currentMemLimitTotal += resource.limits.memory_bytes * replicas;
    currentMemReserveTotal += resource.reservations.memory_bytes * replicas;
    currentCpuLimitTotal += resource.limits.cpu_cores * replicas;
    currentCpuReserveTotal += resource.reservations.cpu_cores * replicas;
  }

  for (const entry of inspection.services) {
    const resource = tunedResources.services[entry.service];
    if (!resource) {
      continue;
    }
    const signals: PlannerTuningService['signals'] = {};
    const serviceNotes: string[] = [];
    if (entry.docker?.cpu_percent !== undefined) {
      signals.cpu_percent = entry.docker.cpu_percent;
    }
    if (entry.docker?.memory_bytes !== undefined) {
      if (entry.docker.memory_limit_bytes > 0) {
        signals.memory_limit_ratio = entry.docker.memory_bytes / entry.docker.memory_limit_bytes;
      }
      if (resource.reservations.memory_bytes > 0) {
        const replicas = Math.max(1, entry.replicas || 0);
        signals.memory_reservation_ratio = entry.docker.memory_bytes / (resource.reservations.memory_bytes * replicas);
      }
    }
    const policy = getTuningPolicy(entry.service);
    const replicas = Math.max(1, entry.replicas || 0);
    const oldMemLimit = resource.limits.memory_bytes;
    const oldMemReserve = resource.reservations.memory_bytes;
    const oldCpuLimit = resource.limits.cpu_cores;
    const oldCpuReserve = resource.reservations.cpu_cores;

    let newMemLimit = oldMemLimit;
    let newMemReserve = oldMemReserve;
    let newCpuLimit = oldCpuLimit;
    let newCpuReserve = oldCpuReserve;
    const baseResource = baseResources.services[entry.service] || resource;

    if (signals.memory_limit_ratio !== undefined && signals.memory_limit_ratio >= policy.limit_up_threshold) {
      newMemLimit = Math.min(
        Math.round(oldMemLimit * policy.limit_scale_up),
        Math.round(baseResource.limits.memory_bytes * policy.max_limit_multiplier),
      );
    }

    if (signals.memory_reservation_ratio !== undefined && signals.memory_reservation_ratio >= policy.reserve_up_threshold) {
      newMemReserve = Math.min(
        Math.round(oldMemReserve * policy.reserve_scale_up),
        Math.round(baseResource.reservations.memory_bytes * policy.max_reserve_multiplier),
      );
    }

    const cpuPercent = entry.docker?.cpu_percent;
    const cpuLimitRatio = (cpuPercent !== undefined && oldCpuLimit > 0)
      ? cpuPercent / (oldCpuLimit * replicas * 100)
      : undefined;
    const cpuReserveRatio = (cpuPercent !== undefined && oldCpuReserve > 0)
      ? cpuPercent / (oldCpuReserve * replicas * 100)
      : undefined;

    if (cpuLimitRatio !== undefined && cpuLimitRatio >= policy.limit_up_threshold) {
      const maxCpuLimit = baseResource.limits.cpu_cores > 0
        ? baseResource.limits.cpu_cores * policy.max_limit_multiplier
        : oldCpuLimit * policy.max_limit_multiplier;
      newCpuLimit = Math.min(
        roundCores(oldCpuLimit * policy.limit_scale_up),
        roundCores(maxCpuLimit),
      );
    }

    if (cpuReserveRatio !== undefined && cpuReserveRatio >= policy.reserve_up_threshold) {
      const maxCpuReserve = baseResource.reservations.cpu_cores > 0
        ? baseResource.reservations.cpu_cores * policy.max_reserve_multiplier
        : oldCpuReserve * policy.max_reserve_multiplier;
      newCpuReserve = Math.min(
        roundCores(oldCpuReserve * policy.reserve_scale_up),
        roundCores(maxCpuReserve),
      );
    }

    if (newMemReserve > newMemLimit) {
      newMemLimit = newMemReserve;
    }
    if (newCpuReserve > newCpuLimit) {
      newCpuLimit = newCpuReserve;
    }

    const memLimitDelta = (newMemLimit - oldMemLimit) * replicas;
    if (memLimitDelta > 0 && maxMemLimitTotal > 0 && currentMemLimitTotal + memLimitDelta > maxMemLimitTotal) {
      newMemLimit = oldMemLimit;
      serviceNotes.push('limit increase skipped (capacity headroom)');
    }

    if (newMemReserve > newMemLimit) {
      newMemReserve = oldMemReserve;
    }

    const memReserveDelta = (newMemReserve - oldMemReserve) * replicas;
    if (memReserveDelta > 0 && maxMemReserveTotal > 0 && currentMemReserveTotal + memReserveDelta > maxMemReserveTotal) {
      newMemReserve = oldMemReserve;
      serviceNotes.push('reservation increase skipped (capacity headroom)');
    }

    const cpuLimitDelta = (newCpuLimit - oldCpuLimit) * replicas;
    if (cpuLimitDelta > 0 && maxCpuLimitTotal > 0 && currentCpuLimitTotal + cpuLimitDelta > maxCpuLimitTotal) {
      newCpuLimit = oldCpuLimit;
      serviceNotes.push('cpu limit increase skipped (capacity headroom)');
    }

    if (newCpuReserve > newCpuLimit) {
      newCpuReserve = oldCpuReserve;
    }

    const cpuReserveDelta = (newCpuReserve - oldCpuReserve) * replicas;
    if (cpuReserveDelta > 0 && maxCpuReserveTotal > 0 && currentCpuReserveTotal + cpuReserveDelta > maxCpuReserveTotal) {
      newCpuReserve = oldCpuReserve;
      serviceNotes.push('cpu reservation increase skipped (capacity headroom)');
    }

    const changed = newMemLimit !== oldMemLimit
      || newMemReserve !== oldMemReserve
      || newCpuLimit !== oldCpuLimit
      || newCpuReserve !== oldCpuReserve;

    if (changed) {
      const adjustment: PlannerTuningAdjustment = { source: 'auto' };
      if (newMemLimit !== oldMemLimit || newCpuLimit !== oldCpuLimit) {
        adjustment.limits = {
          memory_bytes: newMemLimit !== oldMemLimit ? newMemLimit : undefined,
          cpu_cores: newCpuLimit !== oldCpuLimit ? newCpuLimit : undefined,
        };
      }
      if (newMemReserve !== oldMemReserve || newCpuReserve !== oldCpuReserve) {
        adjustment.reservations = {
          memory_bytes: newMemReserve !== oldMemReserve ? newMemReserve : undefined,
          cpu_cores: newCpuReserve !== oldCpuReserve ? newCpuReserve : undefined,
        };
      }
      if (serviceNotes.length > 0) {
        adjustment.notes = serviceNotes;
      }
      adjustments[entry.service] = adjustment;

      if (newMemLimit !== oldMemLimit) {
        currentMemLimitTotal += (newMemLimit - oldMemLimit) * replicas;
        resource.limits.memory_bytes = newMemLimit;
      }
      if (newMemReserve !== oldMemReserve) {
        currentMemReserveTotal += (newMemReserve - oldMemReserve) * replicas;
        resource.reservations.memory_bytes = newMemReserve;
      }
      if (newCpuLimit !== oldCpuLimit) {
        currentCpuLimitTotal += (newCpuLimit - oldCpuLimit) * replicas;
        resource.limits.cpu_cores = newCpuLimit;
      }
      if (newCpuReserve !== oldCpuReserve) {
        currentCpuReserveTotal += (newCpuReserve - oldCpuReserve) * replicas;
        resource.reservations.cpu_cores = newCpuReserve;
      }
    }

    services.push({
      name: entry.name,
      service: entry.service,
      environment_id: entry.environment_id,
      signals,
      notes: serviceNotes.length > 0 ? serviceNotes : undefined,
    });
  }

  const placements = buildPlacementHints(inspection, tunedResources, capacity.nodes || []);
  const configChanges = buildConfigChanges(inspection, tunedResources);

  const profile: PlannerTuningProfile = {
    id: `candidate-${inspection.generated_at}`,
    status: 'recommended',
    strategy: 'inspection-capacity-v1',
    resources: tunedResources,
    adjustments,
    placements,
    created_at: inspection.generated_at,
    updated_at: inspection.generated_at,
    config_changes: configChanges,
  };

  return { profile, signals: services };
}

export async function buildTuningProfiles(
  candidate: PlannerTuningProfile,
  signals: PlannerTuningService[],
  baseResources: PlannerResources,
  inspection: PlannerInspectionPayload,
): Promise<{ payload: PlannerTuningPayload; active: PlannerTuningProfile }> {
  const now = new Date().toISOString();
  const nowMs = Date.now();
  const stored = loadTuningProfiles();
  const baseProfile = stored?.base || createBaseProfile(baseResources, now);
  baseProfile.resources = clonePlannerResources(baseResources);
  baseProfile.updated_at = now;

  const state = resolveRecommendationState(stored, nowMs);
  let recommendedProfile = state.recommended;
  if (state.shouldUpdate) {
    recommendedProfile = buildRecommendedProfile(candidate, baseResources, recommendedProfile, now);
  }
  const incrementalProfile = recommendedProfile
    ? buildIncrementalProfile(baseResources, recommendedProfile, now)
    : undefined;

  const approvedProfiles = pruneApprovedProfiles(stored?.approved || [], nowMs);
  const activeProfile = selectActiveProfile(baseProfile, approvedProfiles);

  const payload: PlannerTuningPayload = {
    generated_at: inspection.generated_at,
    services: signals,
    base_profile: baseProfile,
    recommended_profile: recommendedProfile,
    incremental_profile: incrementalProfile,
    approved_profiles: approvedProfiles,
    active_profile_id: activeProfile.id,
  };

  saveTuningProfiles({
    base: baseProfile,
    recommended: recommendedProfile,
    approved: approvedProfiles,
    last_recommended_at: state.shouldUpdate ? now : state.lastRecommendedAt,
  });

  return { payload, active: activeProfile };
}
