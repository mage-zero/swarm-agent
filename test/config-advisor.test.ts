import { describe, expect, it } from 'vitest';
import { buildConfigBaseline, buildConfigChanges } from '../src/config-advisor.js';
import type { PlannerInspectionPayload, PlannerResources } from '../src/planner-types.js';

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
    expect(Number(db?.changes['query_cache_size'])).toBe(64 * MIB);
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
    const fallback = [
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

  it('applies database query-cache thresholds and max_connections clamp', () => {
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

    expect(primary?.changes['query_cache_size']).toBe(32 * MIB);
    expect(primary?.changes['max_connections']).toBe(150);
    expect(replica?.changes['query_cache_size']).toBe(64 * MIB);
    expect(replica?.changes['max_connections']).toBe(600);
  });
});
