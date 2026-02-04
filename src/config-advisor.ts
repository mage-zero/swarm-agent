import type {
  InspectionMetricValue,
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

function pickAppMetrics(
  inspection: PlannerInspectionPayload,
  preferredService: string,
  fallbackServices: string[],
): Record<string, InspectionMetricValue> | null {
  const direct = inspection.services.find(
    (entry) => entry.service === preferredService && entry.app && Object.keys(entry.app).length > 0,
  );
  if (direct?.app) {
    return direct.app;
  }
  const fallback = inspection.services.find(
    (entry) => fallbackServices.includes(entry.service) && entry.app && Object.keys(entry.app).length > 0,
  );
  return fallback?.app || null;
}

function buildBaselineFromPhpApp(
  service: string,
  app: Record<string, InspectionMetricValue>,
): PlannerConfigChange | null {
  const changes: Record<string, number | string> = {};
  const memoryLimit = app['php.memory_limit'] ?? app.php_memory_limit_bytes;
  if (typeof memoryLimit === 'number' && Number.isFinite(memoryLimit)) {
    changes['php.memory_limit'] = memoryLimit;
  }

  const opcacheMem = app['opcache.memory_consumption'];
  if (typeof opcacheMem === 'number' && Number.isFinite(opcacheMem) && opcacheMem > 0) {
    changes['opcache.memory_consumption'] = opcacheMem;
  }
  const interned = app['opcache.interned_strings_buffer'];
  if (typeof interned === 'number' && Number.isFinite(interned) && interned > 0) {
    changes['opcache.interned_strings_buffer'] = interned;
  }
  const maxFiles = app['opcache.max_accelerated_files'];
  if (typeof maxFiles === 'number' && Number.isFinite(maxFiles) && maxFiles > 0) {
    changes['opcache.max_accelerated_files'] = Math.round(maxFiles);
  }

  const fpmKeys: Array<keyof typeof changes> = [
    'fpm.pm.max_children',
    'fpm.pm.start_servers',
    'fpm.pm.min_spare_servers',
    'fpm.pm.max_spare_servers',
    'fpm.pm.max_requests',
  ];
  for (const key of fpmKeys) {
    const value = app[key];
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
      changes[key] = Math.round(value);
    }
  }

  if (Object.keys(changes).length === 0) {
    return null;
  }

  return {
    service,
    changes,
    notes: ['Captured from running containers.'],
  };
}

function buildBaselineFromDatabaseApp(
  service: string,
  app: Record<string, InspectionMetricValue>,
): PlannerConfigChange | null {
  const keys = [
    'innodb_buffer_pool_size',
    'innodb_log_file_size',
    'max_connections',
    'tmp_table_size',
    'max_heap_table_size',
    'thread_cache_size',
    'query_cache_size',
  ];
  const changes: Record<string, number | string> = {};
  for (const key of keys) {
    const value = app[key];
    if (typeof value === 'number' && Number.isFinite(value)) {
      changes[key] = value;
    }
  }

  if (Object.keys(changes).length === 0) {
    return null;
  }

  return {
    service,
    changes,
    notes: ['Captured from running containers.'],
  };
}

function mergeBaselineChange(
  existing: PlannerConfigChange | undefined,
  incoming: PlannerConfigChange,
  preferIncoming = false,
): PlannerConfigChange {
  if (!existing) {
    return {
      service: incoming.service,
      changes: { ...incoming.changes },
      notes: incoming.notes ? [...incoming.notes] : undefined,
      evidence: incoming.evidence ? { ...incoming.evidence } : undefined,
    };
  }
  const mergedChanges = { ...existing.changes };
  for (const [key, value] of Object.entries(incoming.changes || {})) {
    if (preferIncoming || mergedChanges[key] === undefined) {
      mergedChanges[key] = value;
    }
  }
  const notes = new Set<string>(existing.notes || []);
  for (const note of incoming.notes || []) {
    notes.add(note);
  }
  return {
    service: existing.service,
    changes: mergedChanges,
    notes: notes.size > 0 ? Array.from(notes) : undefined,
    evidence: existing.evidence || incoming.evidence,
  };
}

export function buildConfigBaseline(
  inspection: PlannerInspectionPayload,
  fallback: PlannerConfigChange[] = [],
): PlannerConfigChange[] {
  const baselineMap = new Map<string, PlannerConfigChange>();
  for (const change of fallback) {
    if (!change?.service || !change?.changes) {
      continue;
    }
    baselineMap.set(change.service, mergeBaselineChange(baselineMap.get(change.service), change, true));
  }

  const phpServices = ['php-fpm', 'php-fpm-admin'];
  for (const service of phpServices) {
    const app = pickAppMetrics(inspection, service, phpServices);
    if (!app) {
      continue;
    }
    const change = buildBaselineFromPhpApp(service, app);
    if (change) {
      baselineMap.set(service, mergeBaselineChange(baselineMap.get(service), change, true));
    }
  }

  const dbServices = ['database', 'database-replica'];
  for (const service of dbServices) {
    const app = pickAppMetrics(inspection, service, dbServices);
    if (!app) {
      continue;
    }
    const change = buildBaselineFromDatabaseApp(service, app);
    if (change) {
      baselineMap.set(service, mergeBaselineChange(baselineMap.get(service), change, true));
    }
  }

  return Array.from(baselineMap.values());
}
