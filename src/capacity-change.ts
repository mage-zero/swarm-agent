import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type {
  CapacityNode,
  PlannerCapacityChangePayload,
  PlannerCapacityChangeProfile,
  PlannerCapacityChangeSku,
  PlannerCapacityChangeNodeRemoval,
  PlannerCapacitySummary,
  PlannerInspectionPayload,
  PlannerResources,
} from './planner-types.js';
import { buildNodeHeaders } from './node-hmac.js';

export type VpsCatalogEntry = {
  plan: string;
  vcpu: number;
  ramGb: number;
  diskGb: number;
  diskType: string;
  indicativeCostMonthly?: number;
};

type CatalogCache = {
  fetched_at: string;
  catalog: Record<string, VpsCatalogEntry>;
};

type StoredCapacityChange = {
  base: PlannerCapacityChangeProfile;
  recommended?: PlannerCapacityChangeProfile;
  approved: PlannerCapacityChangeProfile[];
  last_recommended_at?: string;
};

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const CAPACITY_CHANGE_PATH = process.env.MZ_CAPACITY_CHANGE_PATH
  || `${NODE_DIR}/capacity-change.json`;
const CATALOG_CACHE_PATH = process.env.MZ_VPS_CATALOG_CACHE_PATH
  || `${NODE_DIR}/vps-catalog.json`;
const CATALOG_TTL_MS = Number(process.env.MZ_VPS_CATALOG_TTL_MS || 6 * 60 * 60 * 1000);
const CAPACITY_CHANGE_RETENTION_DAYS = Number(process.env.MZ_CAPACITY_CHANGE_RETENTION_DAYS || 365);
const DOWNSCALE_FREE_RATIO = Number(process.env.MZ_CAPACITY_DOWNSCALE_FREE_RATIO || 0.4);
const MIN_NODE_COUNT = Number(process.env.MZ_CAPACITY_MIN_NODES || 2);
const GIB = 1024 * 1024 * 1024;

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 GB';
  }
  const gb = bytes / GIB;
  return `${gb.toFixed(2)} GB`;
}

export function loadCapacityChangeProfiles(): StoredCapacityChange | null {
  try {
    const raw = fs.readFileSync(CAPACITY_CHANGE_PATH, 'utf8').trim();
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as StoredCapacityChange;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function saveCapacityChangeProfiles(profiles: StoredCapacityChange) {
  try {
    const dir = path.dirname(CAPACITY_CHANGE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const tmpPath = `${CAPACITY_CHANGE_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(profiles, null, 2));
    fs.renameSync(tmpPath, CAPACITY_CHANGE_PATH);
  } catch {
    // ignore persistence failures
  }
}

function pruneCapacityProfiles(profiles: PlannerCapacityChangeProfile[], nowMs: number) {
  const maxAgeMs = CAPACITY_CHANGE_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  return profiles.filter((profile) => {
    const updatedAt = Date.parse(profile.updated_at || profile.created_at || '');
    if (!updatedAt) {
      return true;
    }
    return nowMs - updatedAt <= maxAgeMs;
  });
}

function loadCatalogCache(): CatalogCache | null {
  try {
    const raw = fs.readFileSync(CATALOG_CACHE_PATH, 'utf8').trim();
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as CatalogCache;
    if (!parsed || typeof parsed !== 'object' || !parsed.catalog) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function saveCatalogCache(catalog: Record<string, VpsCatalogEntry>) {
  try {
    const dir = path.dirname(CATALOG_CACHE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const payload: CatalogCache = {
      fetched_at: new Date().toISOString(),
      catalog,
    };
    const tmpPath = `${CATALOG_CACHE_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2));
    fs.renameSync(tmpPath, CATALOG_CACHE_PATH);
  } catch {
    // ignore cache write failures
  }
}

function isCatalogFresh(cache: CatalogCache | null): boolean {
  if (!cache?.fetched_at) {
    return false;
  }
  const fetchedAt = Date.parse(cache.fetched_at);
  if (!fetchedAt) {
    return false;
  }
  return Date.now() - fetchedAt <= CATALOG_TTL_MS;
}

export async function fetchVpsCatalog(
  baseUrl: string,
  nodeId: string,
  nodeSecret: string,
): Promise<Record<string, VpsCatalogEntry> | null> {
  const cached = loadCatalogCache();
  if (isCatalogFresh(cached)) {
    return cached?.catalog || null;
  }

  if (!baseUrl || !nodeId || !nodeSecret) {
    return cached?.catalog || null;
  }

  const url = new URL('/v1/stack/catalog', baseUrl);
  const headers = buildNodeHeaders('GET', url.pathname, url.search.slice(1), '', nodeId, nodeSecret);
  headers['Accept'] = 'application/json';

  const timeoutMs = Number(process.env.MZ_VPS_CATALOG_TIMEOUT_MS || 6000);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers,
      signal: controller.signal,
    });
    if (!response.ok) {
      return cached?.catalog || null;
    }
    const data = await response.json().catch(() => null);
    const catalog = (data as { catalog?: Record<string, VpsCatalogEntry> })?.catalog || null;
    if (!catalog || typeof catalog !== 'object') {
      return cached?.catalog || null;
    }
    saveCatalogCache(catalog);
    return catalog;
  } catch {
    return cached?.catalog || null;
  } finally {
    clearTimeout(timeoutId);
  }
}

function buildCapacitySummary(
  cpuCores: number,
  memoryBytes: number,
  nodeCount: number,
): PlannerCapacitySummary {
  return {
    cpu_cores: Number(cpuCores || 0),
    memory_bytes: Number(memoryBytes || 0),
    node_count: Number(nodeCount || 0),
  };
}

function createBaseProfile(
  capacityCpu: number,
  capacityMem: number,
  nodeCount: number,
  now: string,
): PlannerCapacityChangeProfile {
  return {
    id: 'base',
    status: 'base',
    strategy: 'current-capacity',
    change: 'none',
    created_at: now,
    updated_at: now,
    capacity: buildCapacitySummary(capacityCpu, capacityMem, nodeCount),
  };
}

function calculateDesiredTotals(resources: PlannerResources, inspection: PlannerInspectionPayload) {
  const replicasByService = new Map<string, number>();
  for (const service of inspection.services || []) {
    if (!service?.service) {
      continue;
    }
    const current = replicasByService.get(service.service) || 0;
    replicasByService.set(service.service, current + (service.replicas || 0));
  }

  let reservedCpu = 0;
  let reservedMem = 0;
  const missing: string[] = [];

  for (const [service, spec] of Object.entries(resources.services || {})) {
    const replicas = replicasByService.get(service) || 0;
    if (replicas <= 0) {
      missing.push(service);
      continue;
    }
    reservedCpu += spec.reservations.cpu_cores * replicas;
    reservedMem += spec.reservations.memory_bytes * replicas;
  }

  return {
    reservedCpu,
    reservedMem,
    missing,
  };
}

function pickSkuForNeed(
  catalog: Record<string, VpsCatalogEntry>,
  remainingCpu: number,
  remainingMemGb: number,
) {
  let best: { id: string; entry: VpsCatalogEntry; score: number } | null = null;
  const cpuNeed = Math.max(remainingCpu, 0.1);
  const memNeed = Math.max(remainingMemGb, 0.1);
  for (const [sku, entry] of Object.entries(catalog)) {
    if (!entry || !Number.isFinite(entry.vcpu) || !Number.isFinite(entry.ramGb)) {
      continue;
    }
    const cpuCoverage = Math.min(entry.vcpu / cpuNeed, 1);
    const memCoverage = Math.min(entry.ramGb / memNeed, 1);
    const coverage = cpuCoverage + memCoverage;
    const cost = entry.indicativeCostMonthly && entry.indicativeCostMonthly > 0
      ? entry.indicativeCostMonthly
      : 1;
    const score = coverage / cost;
    if (!best || score > best.score) {
      best = { id: sku, entry, score };
    }
  }
  return best;
}

function buildSkuPlan(
  catalog: Record<string, VpsCatalogEntry>,
  requiredCpu: number,
  requiredMemBytes: number,
): PlannerCapacityChangeSku[] {
  if (!catalog || Object.keys(catalog).length === 0) {
    return [];
  }
  let remainingCpu = Math.max(0, requiredCpu);
  let remainingMemGb = Math.max(0, requiredMemBytes / GIB);
  const picks = new Map<string, PlannerCapacityChangeSku>();
  let guard = 0;
  while ((remainingCpu > 0 || remainingMemGb > 0) && guard < 20) {
    guard += 1;
    const best = pickSkuForNeed(catalog, remainingCpu, remainingMemGb);
    if (!best) {
      break;
    }
    const existing = picks.get(best.id);
    if (existing) {
      existing.count += 1;
    } else {
      picks.set(best.id, {
        sku: best.id,
        plan: best.entry.plan,
        count: 1,
        vcpu: best.entry.vcpu,
        ram_gb: best.entry.ramGb,
        disk_gb: best.entry.diskGb,
        disk_type: best.entry.diskType,
      });
    }
    remainingCpu -= best.entry.vcpu;
    remainingMemGb -= best.entry.ramGb;
  }
  return Array.from(picks.values()).sort((a, b) => a.plan.localeCompare(b.plan));
}

function isProtectedNode(node: CapacityNode) {
  const labels = node.labels || {};
  if (labels.database === 'true' || labels.database_replica === 'true' || labels.search === 'true') {
    return true;
  }
  if (labels['mz.role'] === 'manager') {
    return true;
  }
  if (node.role === 'manager') {
    return true;
  }
  return false;
}

function sortNodesForRemoval(nodes: CapacityNode[]) {
  return [...nodes].sort((a, b) => {
    const aReserved = (a.reservations?.cpu_cores || 0) + (a.reservations?.memory_bytes || 0) / GIB;
    const bReserved = (b.reservations?.cpu_cores || 0) + (b.reservations?.memory_bytes || 0) / GIB;
    if (aReserved !== bReserved) {
      return aReserved - bReserved;
    }
    const aTasks = a.tasks?.running || 0;
    const bTasks = b.tasks?.running || 0;
    if (aTasks !== bTasks) {
      return aTasks - bTasks;
    }
    return (a.resources?.memory_bytes || 0) - (b.resources?.memory_bytes || 0);
  });
}

function chooseNodesToRemove(
  nodes: CapacityNode[],
  desiredCpu: number,
  desiredMem: number,
  totalCpu: number,
  totalMem: number,
): { removals: PlannerCapacityChangeNodeRemoval[]; blockedReason?: string } {
  const removable = nodes.filter(
    (node) => node.status === 'ready' && node.availability === 'active' && !isProtectedNode(node),
  );
  if (removable.length === 0) {
    return { removals: [], blockedReason: 'No removable nodes available (protected services pinned).' };
  }
  let remainingCpu = totalCpu;
  let remainingMem = totalMem;
  let remainingNodes = nodes.filter(
    (node) => node.status === 'ready' && node.availability === 'active',
  ).length;
  if (remainingNodes <= MIN_NODE_COUNT) {
    return { removals: [], blockedReason: `Stack is already at the minimum of ${MIN_NODE_COUNT} node(s).` };
  }

  const removals: PlannerCapacityChangeNodeRemoval[] = [];
  for (const node of sortNodesForRemoval(removable)) {
    if (remainingNodes - 1 < MIN_NODE_COUNT) {
      break;
    }
    const nodeCpu = node.resources?.cpu_cores || 0;
    const nodeMem = node.resources?.memory_bytes || 0;
    if (remainingCpu - nodeCpu < desiredCpu || remainingMem - nodeMem < desiredMem) {
      continue;
    }
    removals.push({
      node_id: node.id || '',
      hostname: node.hostname,
      reason: 'Capacity remains above reserved demand after removal',
    });
    remainingCpu -= nodeCpu;
    remainingMem -= nodeMem;
    remainingNodes -= 1;
  }
  const filtered = removals.filter((node) => node.node_id);
  if (filtered.length === 0) {
    return {
      removals: [],
      blockedReason: 'Reserved demand requires the current node count; downscale not possible.',
    };
  }
  return { removals: filtered };
}

function isIncreaseReady(
  profile: PlannerCapacityChangeProfile,
  totalCpu: number,
  totalMem: number,
): boolean {
  const requiredCpu = profile.required?.cpu_cores || 0;
  const requiredMem = profile.required?.memory_bytes || 0;
  const baseCpu = profile.capacity?.cpu_cores || 0;
  const baseMem = profile.capacity?.memory_bytes || 0;
  if (requiredCpu <= 0 && requiredMem <= 0) {
    return false;
  }
  return totalCpu >= baseCpu + requiredCpu && totalMem >= baseMem + requiredMem;
}

function refreshIncreaseProfile(
  profile: PlannerCapacityChangeProfile,
  totalCpu: number,
  totalMem: number,
  now: string,
): PlannerCapacityChangeProfile {
  return {
    ...profile,
    updated_at: now,
    ready: isIncreaseReady(profile, totalCpu, totalMem),
  };
}

function refreshDecreaseProfile(
  profile: PlannerCapacityChangeProfile,
  nodes: CapacityNode[],
  now: string,
): PlannerCapacityChangeProfile {
  const nodeIds = new Set(nodes.map((node) => node.id).filter(Boolean) as string[]);
  const pending = (profile.remove_nodes || []).filter((node) => nodeIds.has(node.node_id));
  const ready = pending.length > 0;
  const notes = ready ? profile.notes : ['Removal targets no longer present in the stack.'];
  return {
    ...profile,
    updated_at: now,
    ready,
    remove_nodes: pending.length > 0 ? pending : profile.remove_nodes,
    notes,
  };
}

function normalizeRecommendedProfile(
  stored: PlannerCapacityChangeProfile | undefined,
  proposal: PlannerCapacityChangeProfile | undefined,
  totalCpu: number,
  totalMem: number,
  nodes: CapacityNode[],
  now: string,
): PlannerCapacityChangeProfile | undefined {
  if (!stored) {
    return proposal;
  }
  if (!proposal) {
    if (stored.change === 'increase') {
      return refreshIncreaseProfile(stored, totalCpu, totalMem, now);
    }
    if (stored.change === 'decrease') {
      return refreshDecreaseProfile(stored, nodes, now);
    }
    return stored;
  }

  if (stored.change !== proposal.change) {
    return proposal;
  }

  if (proposal.change === 'increase') {
    const storedCpu = stored.required?.cpu_cores || 0;
    const storedMem = stored.required?.memory_bytes || 0;
    const proposedCpu = proposal.required?.cpu_cores || 0;
    const proposedMem = proposal.required?.memory_bytes || 0;
    if (proposedCpu > storedCpu || proposedMem > storedMem) {
      return proposal;
    }
    return refreshIncreaseProfile(stored, totalCpu, totalMem, now);
  }

  if (proposal.change === 'decrease') {
    return refreshDecreaseProfile(stored, nodes, now);
  }

  return stored;
}

export function approveCapacityChangeProfile(profileId: string) {
  const stored = loadCapacityChangeProfiles();
  const recommended = stored?.recommended;
  if (!recommended) {
    return { status: 404, body: { error: 'No recommended profile available' } } as const;
  }
  if (recommended.id !== profileId) {
    return {
      status: 409,
      body: {
        error: 'recommended_profile_mismatch',
        recommended_id: recommended.id,
        recommended_updated_at: recommended.updated_at,
      },
    } as const;
  }
  if (!recommended.ready) {
    return {
      status: 409,
      body: {
        error: 'profile_not_ready',
        recommended_id: recommended.id,
        recommended_updated_at: recommended.updated_at,
      },
    } as const;
  }

  const now = new Date().toISOString();
  const approvedId = `approved-${crypto.randomUUID()}`;
  const approvedProfile: PlannerCapacityChangeProfile = {
    ...recommended,
    id: approvedId,
    status: 'approved',
    created_at: now,
    updated_at: now,
  };

  const approvedProfiles = pruneCapacityProfiles(
    [...(stored?.approved || []), approvedProfile],
    Date.now(),
  );
  approvedProfiles.sort((a, b) => Date.parse(a.updated_at) - Date.parse(b.updated_at));

  saveCapacityChangeProfiles({
    base: stored?.base || approvedProfile,
    recommended,
    approved: approvedProfiles,
    last_recommended_at: stored?.last_recommended_at,
  });

  return {
    status: 200,
    body: {
      approved_profile: approvedProfile,
      active_profile_id: approvedProfile.id,
    },
  } as const;
}

export function buildCapacityChangePayload(params: {
  capacity: {
    generated_at: string;
    nodes: CapacityNode[];
    totals: {
      cpu_cores: number;
      memory_bytes: number;
      reserved_cpu_cores: number;
      reserved_memory_bytes: number;
      free_cpu_cores: number;
      free_memory_bytes: number;
    };
  };
  inspection: PlannerInspectionPayload;
  resources: PlannerResources;
  catalog: Record<string, VpsCatalogEntry> | null;
}): PlannerCapacityChangePayload {
  const { capacity, inspection, resources, catalog } = params;
  const now = new Date().toISOString();
  const totalCpu = capacity.totals.cpu_cores || 0;
  const totalMem = capacity.totals.memory_bytes || 0;
  const readyNodes = capacity.nodes.filter(
    (node) => node.status === 'ready' && node.availability === 'active',
  );

  const baseProfile = createBaseProfile(totalCpu, totalMem, readyNodes.length, now);

  const stored = loadCapacityChangeProfiles();
  const approvedProfiles = pruneCapacityProfiles([...(stored?.approved || [])], Date.now());
  approvedProfiles.sort((a, b) => Date.parse(a.updated_at) - Date.parse(b.updated_at));

  let recommendedProfile: PlannerCapacityChangeProfile | undefined;
  const missingInspection = (inspection.sample_count ?? 0) === 0 || inspection.services.length === 0;
  if (!missingInspection) {
    const desired = calculateDesiredTotals(resources, inspection);
    const requiredCpu = Math.max(0, desired.reservedCpu - totalCpu);
    const requiredMem = Math.max(0, desired.reservedMem - totalMem);
    const freeCpuRatio = totalCpu > 0 ? (capacity.totals.free_cpu_cores || 0) / totalCpu : 0;
    const freeMemRatio = totalMem > 0 ? (capacity.totals.free_memory_bytes || 0) / totalMem : 0;

    if (requiredCpu > 0 || requiredMem > 0) {
      const skus = catalog ? buildSkuPlan(catalog, requiredCpu, requiredMem) : [];
      const notes: string[] = [];
      if (desired.missing.length) {
        notes.push(`No inspection data for: ${desired.missing.join(', ')}`);
      }
      if (!catalog || skus.length === 0) {
        notes.push('VPS catalog unavailable; unable to suggest SKU mix');
      }
      notes.push('Provision the stack with the additional VPS nodes before approving this profile.');

      recommendedProfile = {
        id: `recommended-${crypto.randomUUID()}`,
        status: 'recommended',
        strategy: 'capacity-increase',
        change: 'increase',
        created_at: now,
        updated_at: now,
        capacity: buildCapacitySummary(totalCpu, totalMem, readyNodes.length),
        required: {
          cpu_cores: Number(requiredCpu.toFixed(2)),
          memory_bytes: Math.ceil(requiredMem),
        },
        skus: skus.length > 0 ? skus : undefined,
        notes: notes.length > 0 ? notes : undefined,
        summary: `Additional capacity required: ${requiredCpu.toFixed(2)} cores, ${formatBytes(requiredMem)}.`,
        ready: false,
      };
    } else if (freeCpuRatio >= DOWNSCALE_FREE_RATIO && freeMemRatio >= DOWNSCALE_FREE_RATIO) {
      const removalPlan = chooseNodesToRemove(
        capacity.nodes,
        desired.reservedCpu,
        desired.reservedMem,
        totalCpu,
        totalMem,
      );
      if (removalPlan.removals.length > 0) {
        const targetCpu = totalCpu - removalPlan.removals.reduce((acc, node) => {
          const found = capacity.nodes.find((candidate) => candidate.id === node.node_id);
          return acc + (found?.resources?.cpu_cores || 0);
        }, 0);
        const targetMem = totalMem - removalPlan.removals.reduce((acc, node) => {
          const found = capacity.nodes.find((candidate) => candidate.id === node.node_id);
          return acc + (found?.resources?.memory_bytes || 0);
        }, 0);

        recommendedProfile = {
          id: `recommended-${crypto.randomUUID()}`,
          status: 'recommended',
          strategy: 'capacity-decrease',
          change: 'decrease',
          created_at: now,
          updated_at: now,
          capacity: buildCapacitySummary(totalCpu, totalMem, readyNodes.length),
          target_capacity: buildCapacitySummary(
            targetCpu,
            targetMem,
            Math.max(0, readyNodes.length - removalPlan.removals.length),
          ),
          remove_nodes: removalPlan.removals,
          summary: `Capacity appears underutilized; ${removalPlan.removals.length} node(s) could be removed.`,
          ready: true,
        };
      } else if (removalPlan.blockedReason) {
        recommendedProfile = {
          id: `recommended-${crypto.randomUUID()}`,
          status: 'recommended',
          strategy: 'capacity-decrease',
          change: 'decrease',
          created_at: now,
          updated_at: now,
          capacity: buildCapacitySummary(totalCpu, totalMem, readyNodes.length),
          notes: [removalPlan.blockedReason],
          summary: 'Downscale not possible with current pinned services or minimum node constraints.',
          ready: false,
        };
      }
    }
  }

  if (missingInspection) {
    recommendedProfile = undefined;
  }

  const storedRecommended = normalizeRecommendedProfile(
    stored?.recommended,
    recommendedProfile,
    totalCpu,
    totalMem,
    capacity.nodes,
    now,
  );

  const activeProfileId = approvedProfiles.length > 0
    ? approvedProfiles[approvedProfiles.length - 1].id
    : baseProfile.id;

  saveCapacityChangeProfiles({
    base: baseProfile,
    recommended: storedRecommended,
    approved: approvedProfiles,
    last_recommended_at: storedRecommended ? now : stored?.last_recommended_at,
  });

  return {
    generated_at: capacity.generated_at,
    base_profile: baseProfile,
    recommended_profile: storedRecommended,
    approved_profiles: approvedProfiles,
    active_profile_id: activeProfileId,
  };
}
