import { describe, expect, it } from 'vitest';
import { buildConfigBaseline, buildConfigChanges } from '../src/config-advisor.js';
import type { PlannerConfigChange, PlannerInspectionPayload, PlannerResources } from '../src/planner-types.js';

const KIB = 1024;
const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

describe('config advisor', () => {
  it('builds php and database config changes from resource limits', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-17T00:00:00.000Z',
      services: [
        { name: 'php', service: 'php-fpm', container_ids: [], replicas: 1, docker: { cpu_percent: 50, memory_bytes: 300 * MIB, memory_limit_bytes: GIB, memory_percent: 30, pids: 20 } },
        { name: 'db', service: 'database', container_ids: [], replicas: 1, docker: { cpu_percent: 30, memory_bytes: 600 * MIB, memory_limit_bytes: 2 * GIB, memory_percent: 29, pids: 40 } },
      ],
    };
    const resources: PlannerResources = {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 2, memory_bytes: GIB },
          reservations: { cpu_cores: 1, memory_bytes: 512 * MIB },
        },
        'php-fpm-admin': {
          limits: { cpu_cores: 1, memory_bytes: 512 * MIB },
          reservations: { cpu_cores: 0.5, memory_bytes: 256 * MIB },
        },
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const php = changes.find((entry) => entry.service === 'php-fpm');
    const phpAdmin = changes.find((entry) => entry.service === 'php-fpm-admin');
    const db = changes.find((entry) => entry.service === 'database');

    expect(php).toBeTruthy();
    expect(phpAdmin).toBeTruthy();
    expect(db).toBeTruthy();

    expect(Number(php?.changes['fpm.pm.max_children'])).toBeGreaterThanOrEqual(2);
    expect(Number(php?.changes['fpm.pm.max_children'])).toBeLessThanOrEqual(32);
    expect(Number(php?.changes['opcache.memory_consumption'])).toBeGreaterThanOrEqual(128 * MIB);
    expect(Number(php?.changes['opcache.interned_strings_buffer'])).toBeGreaterThanOrEqual(8 * MIB);
    expect(Number(phpAdmin?.changes['fpm.pm.max_children'])).toBeGreaterThanOrEqual(2);

    expect(Number(db?.changes['max_connections'])).toBe(200);
    expect(Number(db?.changes['thread_cache_size'])).toBe(20);
    expect(Number(db?.changes['query_cache_size'])).toBe(0);

    // New workload-aware variables should have sensible defaults without app metrics
    expect(Number(db?.changes['table_definition_cache'])).toBe(1000);
    expect(Number(db?.changes['table_open_cache'])).toBe(2000);
    expect(Number(db?.changes['join_buffer_size'])).toBe(256 * KIB);
    expect(Number(db?.changes['sort_buffer_size'])).toBe(512 * KIB);
    expect(Number(db?.changes['innodb_log_buffer_size'])).toBe(16 * MIB);
    // 2G buffer pool -> min(8, floor(1.2G / 128M)) = 8 but pool is ~1.2G so floor(1.2G/128M) = 9 -> capped at 8
    expect(Number(db?.changes['innodb_buffer_pool_instances'])).toBeGreaterThanOrEqual(1);
    expect(Number(db?.changes['innodb_buffer_pool_instances'])).toBeLessThanOrEqual(8);
  });

  it('merges baseline with inspection values taking precedence', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-17T00:00:00.000Z',
      services: [
        {
          name: 'php',
          service: 'php-fpm',
          container_ids: [],
          replicas: 1,
          app: {
            'php.memory_limit': 300 * MIB,
            'opcache.memory_consumption': 192 * MIB,
            'fpm.pm.max_children': 9,
          },
        },
        {
          name: 'db',
          service: 'database',
          container_ids: [],
          replicas: 1,
          app: {
            max_connections: 250,
          },
        },
      ],
    };
    const fallback: PlannerConfigChange[] = [
      {
        service: 'php-fpm',
        changes: {
          'php.memory_limit': 256 * MIB,
          'fpm.pm.max_requests': 500,
        },
        notes: ['fallback-note'],
      },
      {
        service: 'database',
        changes: {
          max_connections: 200,
          innodb_buffer_pool_size: 512 * MIB,
        },
      },
      {
        service: 'cron',
        changes: { custom: '1' },
      },
    ];

    const baseline = buildConfigBaseline(inspection, fallback);
    const php = baseline.find((entry) => entry.service === 'php-fpm');
    const db = baseline.find((entry) => entry.service === 'database');
    const cron = baseline.find((entry) => entry.service === 'cron');

    expect(php).toBeTruthy();
    expect(php?.changes['php.memory_limit']).toBe(300 * MIB);
    expect(php?.changes['fpm.pm.max_children']).toBe(9);
    expect(php?.changes['fpm.pm.max_requests']).toBe(500);
    expect(php?.notes).toContain('fallback-note');
    expect(php?.notes).toContain('Captured from running containers.');

    expect(db).toBeTruthy();
    expect(db?.changes.max_connections).toBe(250);
    expect(db?.changes.innodb_buffer_pool_size).toBe(512 * MIB);

    expect(cron).toEqual({ service: 'cron', changes: { custom: '1' }, notes: undefined, evidence: undefined });
  });

  it('uses php app metrics as fallback for php-fpm-admin baseline', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-17T00:00:00.000Z',
      services: [
        {
          name: 'php',
          service: 'php-fpm',
          container_ids: [],
          replicas: 1,
          app: {
            'php.memory_limit': 384 * MIB,
            'fpm.pm.max_children': 12,
          },
        },
      ],
    };

    const baseline = buildConfigBaseline(inspection);
    const admin = baseline.find((entry) => entry.service === 'php-fpm-admin');
    expect(admin).toBeTruthy();
    expect(admin?.changes['php.memory_limit']).toBe(384 * MIB);
    expect(admin?.changes['fpm.pm.max_children']).toBe(12);
  });

  it('applies php clamp boundaries for very small and very large memory limits', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-19T00:00:00.000Z',
      services: [],
    };
    const resources: PlannerResources = {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 1, memory_bytes: 300 * MIB },
          reservations: { cpu_cores: 0.5, memory_bytes: 128 * MIB },
        },
        'php-fpm-admin': {
          limits: { cpu_cores: 2, memory_bytes: 80 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: 2 * GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const php = changes.find((entry) => entry.service === 'php-fpm');
    const phpAdmin = changes.find((entry) => entry.service === 'php-fpm-admin');

    expect(php).toBeTruthy();
    expect(phpAdmin).toBeTruthy();

    expect(php?.changes['fpm.pm.max_children']).toBe(2);
    expect(php?.changes['php.memory_limit']).toBe(256 * MIB);
    expect(php?.changes['opcache.memory_consumption']).toBe(128 * MIB);
    expect(php?.changes['opcache.max_accelerated_files']).toBe(60000);
    expect(php?.changes['fpm.pm.start_servers']).toBe(2);
    expect(php?.changes['fpm.pm.min_spare_servers']).toBe(1);
    expect(php?.changes['fpm.pm.max_spare_servers']).toBe(2);

    expect(phpAdmin?.changes['fpm.pm.max_children']).toBe(32);
    expect(phpAdmin?.changes['php.memory_limit']).toBe(1024 * MIB);
    expect(phpAdmin?.changes['opcache.memory_consumption']).toBe(1024 * MIB);
    expect(phpAdmin?.changes['opcache.interned_strings_buffer']).toBe(64 * MIB);
    expect(phpAdmin?.changes['opcache.max_accelerated_files']).toBe(100000);
  });

  it('keeps database query cache disabled and applies max_connections clamp', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-19T00:00:00.000Z',
      services: [],
    };
    const resources: PlannerResources = {
      services: {
        database: {
          limits: { cpu_cores: 2, memory_bytes: GIB },
          reservations: { cpu_cores: 1, memory_bytes: 512 * MIB },
        },
        'database-replica': {
          limits: { cpu_cores: 2, memory_bytes: 20 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: 2 * GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const primary = changes.find((entry) => entry.service === 'database');
    const replica = changes.find((entry) => entry.service === 'database-replica');

    expect(primary).toBeTruthy();
    expect(replica).toBeTruthy();

    expect(primary?.changes['query_cache_size']).toBe(0);
    expect(primary?.changes['max_connections']).toBe(150);
    expect(replica?.changes['query_cache_size']).toBe(0);
    expect(replica?.changes['max_connections']).toBe(600);
  });

  it('derives workload-aware DB config from app metrics', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-26T00:00:00.000Z',
      services: [
        {
          name: 'db',
          service: 'database',
          container_ids: [],
          replicas: 1,
          docker: { cpu_percent: 30, memory_bytes: 600 * MIB, memory_limit_bytes: 2 * GIB, memory_percent: 29, pids: 40 },
          app: {
            // Status counters
            Innodb_buffer_pool_reads: 20000,
            Innodb_buffer_pool_read_requests: 3000000,
            Innodb_log_waits: 5,
            Innodb_log_writes: 18000,
            Select_full_join: 4769,
            Questions: 133000,
            Uptime: 20000,
            Open_tables: 955,
            Opened_tables: 60000,
            Table_open_cache_hits: 44000,
            Table_open_cache_misses: 20000,
            Created_tmp_disk_tables: 5000,
            Created_tmp_tables: 37000,
            Sort_merge_passes: 10,
            Sort_rows: 5000,
            // Current variable values
            table_definition_cache: 400,
            table_open_cache: 512,
            join_buffer_size: 256 * KIB,
            sort_buffer_size: 512 * KIB,
            innodb_log_buffer_size: 8 * MIB,
            innodb_buffer_pool_instances: 1,
          },
        },
      ],
    };
    const resources: PlannerResources = {
      services: {
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const db = changes.find((entry) => entry.service === 'database');
    expect(db).toBeTruthy();

    // table_definition_cache: 400 < 955 * 0.9 -> raised to ceil(955 * 1.2) rounded up to 100 = 1200
    expect(Number(db?.changes['table_definition_cache'])).toBe(1200);

    // table_open_cache: Opened_tables/Uptime = 60000/20000 = 3/s >> 5/3600
    // -> ceil(955 * 1.5) rounded to 100 = 1500
    expect(Number(db?.changes['table_open_cache'])).toBe(1500);

    // join_buffer_size: Select_full_join=4769 > 0, 4769/133000=0.036 > 0.01 -> 2M
    expect(Number(db?.changes['join_buffer_size'])).toBe(2 * MIB);

    // innodb_log_buffer_size: Innodb_log_waits=5 > 0 -> 32M
    expect(Number(db?.changes['innodb_log_buffer_size'])).toBe(32 * MIB);

    // innodb_buffer_pool_instances: buffer pool ~1.2G >= 1G -> min(8, floor(1.2G/128M))
    expect(Number(db?.changes['innodb_buffer_pool_instances'])).toBeGreaterThanOrEqual(1);
    expect(Number(db?.changes['innodb_buffer_pool_instances'])).toBeLessThanOrEqual(8);

    // Evidence should include diagnostic ratios
    expect(db?.evidence).toBeTruthy();
    expect(Number(db?.evidence?.buffer_pool_hit_rate)).toBeGreaterThan(99);
    expect(Number(db?.evidence?.joins_without_index)).toBe(4769);
    expect(Number(db?.evidence?.table_cache_hit_rate)).toBeGreaterThan(0);
    expect(Number(db?.evidence?.tmp_tables_disk_pct)).toBeGreaterThan(0);

    // Notes should contain diagnostic messages
    expect(db?.notes?.some((n) => n.includes('table_definition_cache'))).toBe(true);
    expect(db?.notes?.some((n) => n.includes('joins without indexes'))).toBe(true);
    expect(db?.notes?.some((n) => n.includes('InnoDB log waits'))).toBe(true);
  });

  it('captures new DB variables in baseline from app metrics', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-26T00:00:00.000Z',
      services: [
        {
          name: 'db',
          service: 'database',
          container_ids: [],
          replicas: 1,
          app: {
            innodb_buffer_pool_size: 512 * MIB,
            max_connections: 150,
            table_definition_cache: 400,
            table_open_cache: 2000,
            join_buffer_size: 256 * KIB,
            sort_buffer_size: 512 * KIB,
            innodb_log_buffer_size: 16 * MIB,
            innodb_buffer_pool_instances: 1,
          },
        },
      ],
    };

    const baseline = buildConfigBaseline(inspection);
    const db = baseline.find((entry) => entry.service === 'database');
    expect(db).toBeTruthy();
    expect(db?.changes['table_definition_cache']).toBe(400);
    expect(db?.changes['table_open_cache']).toBe(2000);
    expect(db?.changes['join_buffer_size']).toBe(256 * KIB);
    expect(db?.changes['sort_buffer_size']).toBe(512 * KIB);
    expect(db?.changes['innodb_log_buffer_size']).toBe(16 * MIB);
    expect(db?.changes['innodb_buffer_pool_instances']).toBe(1);
  });

  it('reduces database buffer pool and max_connections under high memory pressure', () => {
    // 92% memory usage → buffer pool should drop below the normal 60%
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [
        {
          name: 'db',
          service: 'database',
          container_ids: [],
          replicas: 1,
          docker: { cpu_percent: 40, memory_bytes: Math.round(2 * GIB * 0.92), memory_limit_bytes: 2 * GIB, memory_percent: 92, pids: 50 },
        },
      ],
    };
    const resources: PlannerResources = {
      services: {
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const db = changes.find((entry) => entry.service === 'database');
    expect(db).toBeTruthy();

    // Normal buffer pool at 60% of 2G = ~1.2G. Under 92% pressure:
    // ratio = max(0.40, 0.60 - (0.92 - 0.85) * 2) = max(0.40, 0.46) = 0.46
    // Buffer pool = floor(2G * 0.46) ≈ 986M
    const normalBufferPool = Math.floor(2 * GIB * 0.6);
    expect(Number(db?.changes['innodb_buffer_pool_size'])).toBeLessThan(normalBufferPool);

    // max_connections should be reduced
    const normalMaxConn = Math.round(100 + (2 * GIB / GIB) * 50); // 200
    expect(Number(db?.changes['max_connections'])).toBeLessThan(normalMaxConn);

    // Notes should mention memory pressure
    expect(db?.notes?.some((n) => n.includes('Memory pressure'))).toBe(true);
    expect(db?.notes?.some((n) => n.includes('max_connections'))).toBe(true);
  });

  it('reduces PHP max_children under high memory pressure', () => {
    // 4G limit, 90% usage → usable ratio drops from 80% to 65%
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [
        {
          name: 'php',
          service: 'php-fpm',
          container_ids: [],
          replicas: 1,
          docker: { cpu_percent: 60, memory_bytes: Math.round(4 * GIB * 0.90), memory_limit_bytes: 4 * GIB, memory_percent: 90, pids: 30 },
        },
      ],
    };
    const resources: PlannerResources = {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 4, memory_bytes: 4 * GIB },
          reservations: { cpu_cores: 2, memory_bytes: 2 * GIB },
        },
      },
    };

    const pressureChanges = buildConfigChanges(inspection, resources);
    const phpPressure = pressureChanges.find((entry) => entry.service === 'php-fpm');

    // Compare with no-pressure baseline (no docker stats)
    const noPressureInspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [],
    };
    const noPressureChanges = buildConfigChanges(noPressureInspection, resources);
    const phpNormal = noPressureChanges.find((entry) => entry.service === 'php-fpm');

    expect(phpPressure).toBeTruthy();
    expect(phpNormal).toBeTruthy();

    // Under pressure: fewer max_children
    expect(Number(phpPressure?.changes['fpm.pm.max_children'])).toBeLessThan(
      Number(phpNormal?.changes['fpm.pm.max_children']),
    );

    // Notes should mention memory pressure
    expect(phpPressure?.notes?.some((n) => n.includes('Memory pressure'))).toBe(true);
  });

  it('scales database buffer pools down when they exceed host memory budget', () => {
    // Two databases each wanting ~1.2G buffer pool, but host only has 3G total
    // Budget = 3G * 0.65 = 1.95G, but total would be ~2.4G → scale down
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [
        { name: 'db', service: 'database', container_ids: [], replicas: 1 },
        { name: 'db-replica', service: 'database-replica', container_ids: [], replicas: 1 },
      ],
    };
    const resources: PlannerResources = {
      services: {
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
        'database-replica': {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    // Without host cap
    const uncapped = buildConfigChanges(inspection, resources);
    const dbUncapped = uncapped.find((entry) => entry.service === 'database');

    // With tight host cap (3G total)
    const capped = buildConfigChanges(inspection, resources, { memory_bytes: 3 * GIB, cpu_cores: 4 });
    const dbCapped = capped.find((entry) => entry.service === 'database');
    const replicaCapped = capped.find((entry) => entry.service === 'database-replica');

    expect(dbUncapped).toBeTruthy();
    expect(dbCapped).toBeTruthy();
    expect(replicaCapped).toBeTruthy();

    // Capped buffer pool should be smaller than uncapped
    expect(Number(dbCapped?.changes['innodb_buffer_pool_size'])).toBeLessThan(
      Number(dbUncapped?.changes['innodb_buffer_pool_size']),
    );

    // Total buffer pool should not exceed 65% of 3G
    const totalBp = Number(dbCapped?.changes['innodb_buffer_pool_size'])
      + Number(replicaCapped?.changes['innodb_buffer_pool_size']);
    expect(totalBp).toBeLessThanOrEqual(3 * GIB * 0.65);

    // Notes should mention host memory cap
    expect(dbCapped?.notes?.some((n) => n.includes('host memory cap'))).toBe(true);
  });

  it('does not alter configs when memory pressure is below thresholds', () => {
    // 30% memory usage → no pressure adjustments
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [
        {
          name: 'php',
          service: 'php-fpm',
          container_ids: [],
          replicas: 1,
          docker: { cpu_percent: 50, memory_bytes: 300 * MIB, memory_limit_bytes: GIB, memory_percent: 30, pids: 20 },
        },
        {
          name: 'db',
          service: 'database',
          container_ids: [],
          replicas: 1,
          docker: { cpu_percent: 30, memory_bytes: 600 * MIB, memory_limit_bytes: 2 * GIB, memory_percent: 29, pids: 40 },
        },
      ],
    };
    const resources: PlannerResources = {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 2, memory_bytes: GIB },
          reservations: { cpu_cores: 1, memory_bytes: 512 * MIB },
        },
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    // With docker stats but low pressure
    const withStats = buildConfigChanges(inspection, resources);
    // Without docker stats
    const noStatsInspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [],
    };
    const withoutStats = buildConfigChanges(noStatsInspection, resources);

    const phpWith = withStats.find((entry) => entry.service === 'php-fpm');
    const phpWithout = withoutStats.find((entry) => entry.service === 'php-fpm');
    const dbWith = withStats.find((entry) => entry.service === 'database');
    const dbWithout = withoutStats.find((entry) => entry.service === 'database');

    // Same config values at low pressure
    expect(phpWith?.changes['fpm.pm.max_children']).toBe(phpWithout?.changes['fpm.pm.max_children']);
    expect(dbWith?.changes['innodb_buffer_pool_size']).toBe(dbWithout?.changes['innodb_buffer_pool_size']);
    expect(dbWith?.changes['max_connections']).toBe(dbWithout?.changes['max_connections']);

    // No pressure notes
    expect(dbWith?.notes?.some((n) => n.includes('Memory pressure'))).toBeFalsy();
    expect(phpWith?.notes?.some((n) => n.includes('Memory pressure'))).toBeFalsy();
  });

  it('prefers OpenSearch p95 memory over docker stats average for pressure detection', () => {
    // Docker stats shows 50% usage (low pressure), but OpenSearch p95 shows 92% (high pressure)
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [
        {
          name: 'db', service: 'database', container_ids: [], replicas: 1,
          docker: { cpu_percent: 30, memory_bytes: GIB, memory_limit_bytes: 2 * GIB, memory_percent: 50, pids: 40 },
          app: { os_memory_p95_pct: 0.92, os_cpu_p95_pct: 0.45 },
        },
        {
          name: 'php', service: 'php-fpm', container_ids: [], replicas: 1,
          docker: { cpu_percent: 20, memory_bytes: 400 * MIB, memory_limit_bytes: GIB, memory_percent: 39, pids: 10 },
          app: { os_memory_p95_pct: 0.88, os_cpu_p95_pct: 0.30 },
        },
      ],
    };
    const resources: PlannerResources = {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 2, memory_bytes: GIB },
          reservations: { cpu_cores: 1, memory_bytes: 512 * MIB },
        },
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const db = changes.find((entry) => entry.service === 'database')!;
    const php = changes.find((entry) => entry.service === 'php-fpm')!;

    // DB: p95 at 92% triggers pressure, buffer pool should be < 60% of 2G
    const bufferPool = db.changes['innodb_buffer_pool_size'] as number;
    expect(bufferPool).toBeLessThan(2 * GIB * 0.60);
    expect(db.notes?.some((n) => n.includes('Memory pressure 92%'))).toBeTruthy();
    expect(db.evidence?.memory_source).toBe('opensearch_p95');
    expect(db.evidence?.cpu_p95_pct).toBe(0.45);

    // PHP: p95 at 88% triggers pressure (> 80% threshold), usable ratio reduced
    expect(php.notes?.some((n) => n.includes('Memory pressure 88%'))).toBeTruthy();
    expect(php.evidence?.memory_source).toBe('opensearch_p95');
  });

  it('falls back to docker stats average when OpenSearch p95 is absent', () => {
    // No os_memory_p95_pct in app — should use docker stats memory_limit_ratio
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-03-02T00:00:00.000Z',
      services: [
        {
          name: 'db', service: 'database', container_ids: [], replicas: 1,
          docker: { cpu_percent: 30, memory_bytes: 1.8 * GIB, memory_limit_bytes: 2 * GIB, memory_percent: 90, pids: 40 },
          app: { some_other_metric: 42 },
        },
      ],
    };
    const resources: PlannerResources = {
      services: {
        database: {
          limits: { cpu_cores: 2, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 1, memory_bytes: GIB },
        },
      },
    };

    const changes = buildConfigChanges(inspection, resources);
    const db = changes.find((entry) => entry.service === 'database')!;

    // Docker stats ratio is 1.8/2.0 = 0.9 which is > 0.85, should trigger pressure
    expect(db.evidence?.memory_source).toBe('docker_stats_avg');
    expect(db.notes?.some((n) => n.includes('Memory pressure 90%'))).toBeTruthy();
    const bufferPool = db.changes['innodb_buffer_pool_size'] as number;
    expect(bufferPool).toBeLessThan(2 * GIB * 0.60);
  });
});
