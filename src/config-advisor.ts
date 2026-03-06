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

  const notes: string[] = [];

  // Memory pressure from docker stats
  const memoryPressure = typeof evidence?.memory_limit_ratio === 'number'
    && Number.isFinite(evidence.memory_limit_ratio as number)
    ? evidence.memory_limit_ratio as number
    : 0;

  // Scale usable fraction down from 80% when container memory usage > 80%
  let usableRatio = 0.8;
  if (memoryPressure > 0.80) {
    usableRatio = Math.max(0.55, 0.80 - (memoryPressure - 0.80) * 1.5);
    notes.push(`Memory pressure ${Math.round(memoryPressure * 100)}%; reduced usable ratio to ${Math.round(usableRatio * 100)}%.`);
  }

  const perChild = 256 * MIB;
  const usable = memoryLimit * usableRatio;
  const maxChildren = clamp(Math.floor(usable / perChild), 2, 32);
  const phpMemoryLimit = clamp(Math.floor((memoryLimit / Math.max(1, maxChildren)) * 0.8), 256 * MIB, 1024 * MIB);

  const opcacheMemory = clamp(Math.floor(memoryLimit * 0.25), 128 * MIB, 1024 * MIB);
  const interned = clamp(Math.floor(opcacheMemory * 0.0625), 8 * MIB, 64 * MIB);
  const maxFiles = opcacheMemory >= 512 * MIB ? 100000 : 60000;

  const startServers = clamp(Math.floor(maxChildren / 2), 2, maxChildren);
  const minSpare = clamp(Math.floor(maxChildren / 4), 1, maxChildren);
  const maxSpare = clamp(Math.floor(maxChildren / 2), 2, maxChildren);

  notes.push('Derived from PHP container memory limit and conservative per-worker sizing.');

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
    notes,
    evidence,
  };
}

const KIB = 1024;

function metricNum(app: Record<string, InspectionMetricValue> | undefined, key: string): number | null {
  if (!app) {
    return null;
  }
  const v = app[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function roundUp100(n: number): number {
  return Math.ceil(n / 100) * 100;
}

function buildDatabaseConfigChanges(
  service: string,
  memoryLimit: number,
  evidence?: Record<string, number | string>,
  appMetrics?: Record<string, InspectionMetricValue>,
): PlannerConfigChange | null {
  if (!Number.isFinite(memoryLimit) || memoryLimit <= 0) {
    return null;
  }

  const notes: string[] = [];
  const ev: Record<string, number | string> = { ...evidence };

  // --- Memory pressure from docker stats ---
  const memoryPressure = typeof evidence?.memory_limit_ratio === 'number'
    && Number.isFinite(evidence.memory_limit_ratio as number)
    ? evidence.memory_limit_ratio as number
    : 0;

  // --- Memory-based derivations (pressure-aware) ---
  // Scale buffer pool down from 60% when container memory usage > 85%
  let bufferPoolRatio = 0.60;
  if (memoryPressure > 0.85) {
    bufferPoolRatio = Math.max(0.40, 0.60 - (memoryPressure - 0.85) * 2);
    notes.push(`Memory pressure ${Math.round(memoryPressure * 100)}%; reduced buffer pool to ${Math.round(bufferPoolRatio * 100)}% of limit.`);
  }
  const bufferPool = clamp(Math.floor(memoryLimit * bufferPoolRatio), 256 * MIB, memoryLimit * 0.75);
  const logFile = clamp(Math.floor(bufferPool / 8), 64 * MIB, 512 * MIB);

  const memGiB = memoryLimit / GIB;
  let maxConnections = clamp(Math.round(100 + memGiB * 50), 100, 600);
  if (memoryPressure > 0.85) {
    const reduced = clamp(Math.round(maxConnections * (1 - (memoryPressure - 0.85))), 100, maxConnections);
    if (reduced < maxConnections) {
      maxConnections = reduced;
      notes.push(`Reduced max_connections to ${maxConnections} due to memory pressure.`);
    }
  }

  // Scale tmp_table_size down from 5% to 3% under pressure
  const tmpTableRatio = memoryPressure > 0.85
    ? Math.max(0.03, 0.05 - (memoryPressure - 0.85) * 0.2)
    : 0.05;
  const tmpTable = clamp(Math.floor(memoryLimit * tmpTableRatio), 32 * MIB, 256 * MIB);
  const threadCache = clamp(Math.round(maxConnections / 10), 16, 128);

  const queryCache = 0;

  notes.push('Derived from database container memory limit and baseline heuristics.');
  notes.push('Query cache remains disabled (query_cache_size=0) for InnoDB-first workloads.');

  // --- Workload-aware derivations (mysqltuner-style) ---

  // InnoDB buffer pool hit rate
  const bpReads = metricNum(appMetrics, 'Innodb_buffer_pool_reads');
  const bpReadRequests = metricNum(appMetrics, 'Innodb_buffer_pool_read_requests');
  if (bpReads !== null && bpReadRequests !== null && bpReadRequests > 0) {
    const hitRate = 1 - bpReads / bpReadRequests;
    ev.buffer_pool_hit_rate = Math.round(hitRate * 10000) / 100;
    if (hitRate >= 0.99) {
      notes.push(`InnoDB buffer pool hit rate ${ev.buffer_pool_hit_rate}% (healthy).`);
    } else {
      notes.push(`InnoDB buffer pool hit rate ${ev.buffer_pool_hit_rate}% (low); buffer pool sized at 60% of memory limit.`);
    }
  }

  // table_definition_cache
  const openTables = metricNum(appMetrics, 'Open_tables');
  const curTableDefCache = metricNum(appMetrics, 'table_definition_cache');
  let tableDefCache: number;
  if (openTables !== null && curTableDefCache !== null && openTables > curTableDefCache * 0.9) {
    tableDefCache = clamp(roundUp100(Math.ceil(openTables * 1.2)), 400, 4000);
    notes.push(`table_definition_cache ${curTableDefCache} < ${openTables} open tables; raised to ${tableDefCache}.`);
  } else if (openTables !== null) {
    tableDefCache = clamp(Math.max(curTableDefCache ?? 0, roundUp100(Math.ceil(openTables * 1.2)), 1000), 400, 4000);
  } else {
    tableDefCache = clamp(Math.max(curTableDefCache ?? 0, 1000), 400, 4000);
  }

  // table_open_cache
  const openedTables = metricNum(appMetrics, 'Opened_tables');
  const uptime = metricNum(appMetrics, 'Uptime');
  const cacheHits = metricNum(appMetrics, 'Table_open_cache_hits');
  const cacheMisses = metricNum(appMetrics, 'Table_open_cache_misses');
  let tableOpenCache: number;
  if (openedTables !== null && uptime !== null && uptime > 0 && openedTables / uptime > 5 / 3600 && openTables !== null) {
    tableOpenCache = clamp(roundUp100(Math.ceil(openTables * 1.5)), 400, 8000);
    notes.push(`High table open rate (${Math.round(openedTables / uptime * 3600)}/hr); raised table_open_cache to ${tableOpenCache}.`);
  } else {
    tableOpenCache = clamp(Math.max(openTables ?? 0, 2000), 400, 8000);
  }
  if (cacheHits !== null && cacheMisses !== null && (cacheHits + cacheMisses) > 0) {
    ev.table_cache_hit_rate = Math.round(cacheHits / (cacheHits + cacheMisses) * 10000) / 100;
  }

  // join_buffer_size
  const selectFullJoin = metricNum(appMetrics, 'Select_full_join');
  const questions = metricNum(appMetrics, 'Questions');
  let joinBuffer: number;
  if (selectFullJoin !== null && selectFullJoin > 0) {
    ev.joins_without_index = selectFullJoin;
    if (questions !== null && questions > 0 && selectFullJoin / questions > 0.01) {
      joinBuffer = 2 * MIB;
      notes.push(`${selectFullJoin} joins without indexes (${Math.round(selectFullJoin / questions * 10000) / 100}% of queries); raised join_buffer_size to 2M.`);
    } else {
      joinBuffer = 1 * MIB;
      notes.push(`${selectFullJoin} joins without indexes; raised join_buffer_size to 1M.`);
    }
  } else {
    joinBuffer = 256 * KIB;
  }
  joinBuffer = clamp(joinBuffer, 256 * KIB, 4 * MIB);

  // sort_buffer_size
  const sortMergePasses = metricNum(appMetrics, 'Sort_merge_passes');
  const sortRows = metricNum(appMetrics, 'Sort_rows');
  let sortBuffer: number;
  if (sortMergePasses !== null && sortRows !== null && sortRows > 0 && sortMergePasses / sortRows > 0.01) {
    sortBuffer = 2 * MIB;
    ev.sort_merge_pass_rate = Math.round(sortMergePasses / sortRows * 10000) / 100;
    notes.push(`Sort merge pass rate ${ev.sort_merge_pass_rate}%; raised sort_buffer_size to 2M.`);
  } else {
    sortBuffer = 512 * KIB;
  }
  sortBuffer = clamp(sortBuffer, 256 * KIB, 4 * MIB);

  // innodb_log_buffer_size
  const logWaits = metricNum(appMetrics, 'Innodb_log_waits');
  let logBuffer: number;
  if (logWaits !== null && logWaits > 0) {
    logBuffer = 32 * MIB;
    notes.push(`${logWaits} InnoDB log waits; raised innodb_log_buffer_size to 32M.`);
  } else {
    logBuffer = 16 * MIB;
  }
  logBuffer = clamp(logBuffer, 8 * MIB, 64 * MIB);

  // innodb_buffer_pool_instances
  let poolInstances: number;
  if (bufferPool >= GIB) {
    poolInstances = clamp(Math.min(8, Math.floor(bufferPool / (128 * MIB))), 1, 8);
  } else {
    poolInstances = 1;
  }

  // tmp tables on disk ratio (evidence only)
  const tmpDisk = metricNum(appMetrics, 'Created_tmp_disk_tables');
  const tmpTotal = metricNum(appMetrics, 'Created_tmp_tables');
  if (tmpDisk !== null && tmpTotal !== null && tmpTotal > 0) {
    ev.tmp_tables_disk_pct = Math.round(tmpDisk / tmpTotal * 10000) / 100;
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
      'table_definition_cache': tableDefCache,
      'table_open_cache': tableOpenCache,
      'join_buffer_size': joinBuffer,
      'sort_buffer_size': sortBuffer,
      'innodb_log_buffer_size': logBuffer,
      'innodb_buffer_pool_instances': poolInstances,
    },
    notes,
    evidence: ev,
  };
}

export function buildConfigChanges(
  inspection: PlannerInspectionPayload,
  resources: PlannerResources,
  hostCapacity?: { memory_bytes: number; cpu_cores: number },
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
    // Prefer OpenSearch p95 memory over docker stats average when available
    const osMemP95 = entry.app?.os_memory_p95_pct;
    if (typeof osMemP95 === 'number' && Number.isFinite(osMemP95)) {
      evidence.memory_limit_ratio = osMemP95;
      evidence.memory_source = 'opensearch_p95';
    } else {
      evidence.memory_source = 'docker_stats_avg';
    }
    const osCpuP95 = entry.app?.os_cpu_p95_pct;
    if (typeof osCpuP95 === 'number' && Number.isFinite(osCpuP95)) {
      evidence.cpu_p95_pct = osCpuP95;
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
    const appMetrics = inspection.services.find((e) => e.service === service)?.app;
    const change = buildDatabaseConfigChanges(
      service,
      resource.limits.memory_bytes,
      inspectionMap.get(service),
      appMetrics as Record<string, InspectionMetricValue> | undefined,
    );
    if (change) {
      changes.push(change);
    }
  }

  // Host-level cap: if total buffer pool across all DB services exceeds 65% of host memory,
  // scale each buffer pool proportionally to fit
  if (hostCapacity && hostCapacity.memory_bytes > 0) {
    const hostBudget = hostCapacity.memory_bytes * 0.65;
    const replicaMap = new Map<string, number>();
    for (const entry of inspection.services) {
      replicaMap.set(entry.service, Math.max(1, entry.replicas || 0));
    }

    let totalBufferPool = 0;
    const dbChanges: PlannerConfigChange[] = [];
    for (const change of changes) {
      if (dbServices.includes(change.service) && typeof change.changes['innodb_buffer_pool_size'] === 'number') {
        const replicas = replicaMap.get(change.service) || 1;
        totalBufferPool += (change.changes['innodb_buffer_pool_size'] as number) * replicas;
        dbChanges.push(change);
      }
    }

    if (totalBufferPool > hostBudget && dbChanges.length > 0) {
      const scaleFactor = hostBudget / totalBufferPool;
      for (const change of dbChanges) {
        const original = change.changes['innodb_buffer_pool_size'] as number;
        const scaled = roundToMiB(Math.floor(original * scaleFactor));
        if (scaled < original) {
          change.changes['innodb_buffer_pool_size'] = scaled;
          change.changes['innodb_log_file_size'] = roundToMiB(clamp(Math.floor(scaled / 8), 64 * MIB, 512 * MIB));
          if (!change.notes) {
            change.notes = [];
          }
          change.notes.push(`Buffer pool scaled to ${Math.round(scaleFactor * 100)}% (host memory cap).`);
        }
      }
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
    'table_definition_cache',
    'table_open_cache',
    'join_buffer_size',
    'sort_buffer_size',
    'innodb_log_buffer_size',
    'innodb_buffer_pool_instances',
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
