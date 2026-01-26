import type {
  PlannerConfigChange,
  PlannerInspectionPayload,
  PlannerResources,
} from './planner-types.js';

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.min(Math.max(value, min), max);
}

function roundToMiB(bytes: number): number {
  return Math.max(MIB, Math.round(bytes / MIB) * MIB);
}

function buildPhpConfigChanges(
  service: string,
  memoryLimit: number,
  evidence?: Record<string, number | string>,
): PlannerConfigChange | null {
  if (!Number.isFinite(memoryLimit) || memoryLimit <= 0) {
    return null;
  }

  const perChild = 256 * MIB;
  const usable = memoryLimit * 0.8;
  const maxChildren = clamp(Math.floor(usable / perChild), 2, 32);
  const phpMemoryLimit = clamp(Math.floor((memoryLimit / Math.max(1, maxChildren)) * 0.8), 256 * MIB, 1024 * MIB);

  const opcacheMemory = clamp(Math.floor(memoryLimit * 0.25), 128 * MIB, 1024 * MIB);
  const interned = clamp(Math.floor(opcacheMemory * 0.0625), 8 * MIB, 64 * MIB);
  const maxFiles = opcacheMemory >= 512 * MIB ? 100000 : 60000;

  const startServers = clamp(Math.floor(maxChildren / 2), 2, maxChildren);
  const minSpare = clamp(Math.floor(maxChildren / 4), 1, maxChildren);
  const maxSpare = clamp(Math.floor(maxChildren / 2), 2, maxChildren);

  return {
    service,
    changes: {
      'php.memory_limit': roundToMiB(phpMemoryLimit),
      'opcache.memory_consumption': roundToMiB(opcacheMemory),
      'opcache.interned_strings_buffer': roundToMiB(interned),
      'opcache.max_accelerated_files': maxFiles,
      'fpm.pm.max_children': maxChildren,
      'fpm.pm.start_servers': startServers,
      'fpm.pm.min_spare_servers': minSpare,
      'fpm.pm.max_spare_servers': maxSpare,
    },
    notes: ['Derived from PHP container memory limit and conservative per-worker sizing.'],
    evidence,
  };
}

function buildDatabaseConfigChanges(
  service: string,
  memoryLimit: number,
  evidence?: Record<string, number | string>,
): PlannerConfigChange | null {
  if (!Number.isFinite(memoryLimit) || memoryLimit <= 0) {
    return null;
  }

  const bufferPool = clamp(Math.floor(memoryLimit * 0.6), 256 * MIB, memoryLimit * 0.75);
  const logFile = clamp(Math.floor(bufferPool / 8), 64 * MIB, 512 * MIB);

  const memGiB = memoryLimit / GIB;
  const maxConnections = clamp(Math.round(100 + memGiB * 50), 100, 600);

  const tmpTable = clamp(Math.floor(memoryLimit * 0.05), 32 * MIB, 256 * MIB);
  const threadCache = clamp(Math.round(maxConnections / 10), 16, 128);

  let queryCache = 0;
  if (memoryLimit >= 2 * GIB) {
    queryCache = 64 * MIB;
  } else if (memoryLimit >= 1 * GIB) {
    queryCache = 32 * MIB;
  }

  return {
    service,
    changes: {
      'innodb_buffer_pool_size': roundToMiB(bufferPool),
      'innodb_log_file_size': roundToMiB(logFile),
      'max_connections': maxConnections,
      'tmp_table_size': roundToMiB(tmpTable),
      'max_heap_table_size': roundToMiB(tmpTable),
      'thread_cache_size': threadCache,
      'query_cache_size': queryCache,
    },
    notes: ['Derived from database container memory limit and baseline heuristics.'],
    evidence,
  };
}

export function buildConfigChanges(
  inspection: PlannerInspectionPayload,
  resources: PlannerResources,
): PlannerConfigChange[] {
  const changes: PlannerConfigChange[] = [];
  const inspectionMap = new Map<string, Record<string, number | string>>();

  for (const entry of inspection.services) {
    const evidence: Record<string, number | string> = {};
    if (entry.docker?.cpu_percent !== undefined) {
      evidence.cpu_percent = entry.docker.cpu_percent;
    }
    if (entry.docker?.memory_limit_bytes) {
      evidence.memory_limit_bytes = entry.docker.memory_limit_bytes;
    }
    if (entry.docker?.memory_bytes !== undefined && entry.docker?.memory_limit_bytes) {
      evidence.memory_limit_ratio = entry.docker.memory_limit_bytes > 0
        ? entry.docker.memory_bytes / entry.docker.memory_limit_bytes
        : 0;
    }
    inspectionMap.set(entry.service, evidence);
  }

  const phpServices = ['php-fpm', 'php-fpm-admin'];
  for (const service of phpServices) {
    const resource = resources.services[service];
    if (!resource) {
      continue;
    }
    const change = buildPhpConfigChanges(service, resource.limits.memory_bytes, inspectionMap.get(service));
    if (change) {
      changes.push(change);
    }
  }

  const dbServices = ['database', 'database-replica'];
  for (const service of dbServices) {
    const resource = resources.services[service];
    if (!resource) {
      continue;
    }
    const change = buildDatabaseConfigChanges(service, resource.limits.memory_bytes, inspectionMap.get(service));
    if (change) {
      changes.push(change);
    }
  }

  return changes;
}
