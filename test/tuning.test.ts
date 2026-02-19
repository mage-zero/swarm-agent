import { describe, expect, it } from 'vitest';
import {
  applyAiAdjustments,
  buildIncrementalProfile,
  buildPlacementHints,
  clonePlannerResources,
  cloneTuningProfile,
  createBaseProfile,
  pruneApprovedProfiles,
} from '../src/tuning.js';
import type {
  CapacityNode,
  PlannerInspectionPayload,
  PlannerResources,
  PlannerTuningProfile,
} from '../src/planner-types.js';

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

function sampleResources(): PlannerResources {
  return {
    services: {
      'php-fpm': {
        limits: { cpu_cores: 1, memory_bytes: GIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
      },
      cron: {
        limits: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
        reservations: { cpu_cores: 0.25, memory_bytes: 256 * MIB },
      },
      worker: {
        limits: { cpu_cores: 1, memory_bytes: 800 * MIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 800 * MIB },
      },
      web: {
        limits: { cpu_cores: 1, memory_bytes: 300 * MIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 300 * MIB },
      },
    },
  };
}

describe('tuning helpers', () => {
  it('deep-clones planner resources', () => {
    const original = sampleResources();
    const cloned = clonePlannerResources(original);

    expect(cloned).toEqual(original);
    cloned.services['php-fpm'].limits.memory_bytes = 2 * GIB;
    expect(original.services['php-fpm'].limits.memory_bytes).toBe(GIB);
  });

  it('deep-clones tuning profiles with updated identity fields', () => {
    const now = '2026-02-17T10:00:00.000Z';
    const original: PlannerTuningProfile = {
      id: 'recommended',
      status: 'recommended',
      strategy: 'deterministic',
      resources: sampleResources(),
      adjustments: {
        'php-fpm': {
          limits: { memory_bytes: 2 * GIB },
          reservations: { memory_bytes: 700 * MIB },
          source: 'deterministic',
          notes: ['note-a'],
        },
      },
      placements: [{ name: 'php', service: 'php-fpm', node_id: 'node-a', reason: 'headroom' }],
      created_at: '2026-02-16T00:00:00.000Z',
      updated_at: '2026-02-16T12:00:00.000Z',
      config_changes: [{ service: 'php-fpm', changes: { 'fpm.pm.max_children': 10 }, notes: ['cfg'] }],
    };

    const cloned = cloneTuningProfile(original, 'approved', 'approved-1', now);
    expect(cloned.id).toBe('approved-1');
    expect(cloned.status).toBe('approved');
    expect(cloned.updated_at).toBe(now);
    expect(cloned.created_at).toBe(original.created_at);

    cloned.adjustments['php-fpm'].notes?.push('note-b');
    cloned.placements[0].node_id = 'node-b';
    if (cloned.config_changes) {
      cloned.config_changes[0].changes['fpm.pm.max_children'] = 20;
    }

    expect(original.adjustments['php-fpm'].notes).toEqual(['note-a']);
    expect(original.placements[0].node_id).toBe('node-a');
    expect(original.config_changes?.[0].changes['fpm.pm.max_children']).toBe(10);
  });

  it('builds incremental profile as a weighted blend of base and recommended resources', () => {
    const base: PlannerResources = {
      services: {
        app: {
          limits: { cpu_cores: 1, memory_bytes: 100 * MIB },
          reservations: { cpu_cores: 0.5, memory_bytes: 50 * MIB },
        },
      },
    };
    const recommended: PlannerTuningProfile = {
      id: 'recommended',
      status: 'recommended',
      strategy: 'deterministic',
      resources: {
        services: {
          app: {
            limits: { cpu_cores: 3, memory_bytes: 300 * MIB },
            reservations: { cpu_cores: 1.5, memory_bytes: 150 * MIB },
          },
        },
      },
      adjustments: {},
      placements: [],
      summary: 'Recommended profile',
      created_at: '2026-02-16T00:00:00.000Z',
      updated_at: '2026-02-16T00:00:00.000Z',
    };

    const incremental = buildIncrementalProfile(base, recommended, '2026-02-17T00:00:00.000Z');
    expect(incremental.status).toBe('incremental');
    expect(incremental.strategy).toBe('deterministic+incremental');
    expect(incremental.summary).toContain('Recommended profile');
    expect(incremental.summary).toContain('Incremental');

    expect(incremental.resources.services.app.limits.cpu_cores).toBe(2);
    expect(incremental.resources.services.app.limits.memory_bytes).toBe(200 * MIB);
    expect(incremental.resources.services.app.reservations.cpu_cores).toBe(1);
    expect(incremental.resources.services.app.reservations.memory_bytes).toBe(100 * MIB);
    expect(incremental.adjustments.app?.source).toBe('incremental');
  });

  it('preserves base-only and recommended-only services in incremental profile blending', () => {
    const base: PlannerResources = {
      services: {
        shared: {
          limits: { cpu_cores: 1, memory_bytes: 100 * MIB },
          reservations: { cpu_cores: 0.5, memory_bytes: 50 * MIB },
        },
        baseOnly: {
          limits: { cpu_cores: 0.6, memory_bytes: 200 * MIB },
          reservations: { cpu_cores: 0.3, memory_bytes: 100 * MIB },
        },
      },
    };
    const recommended: PlannerTuningProfile = {
      id: 'recommended',
      status: 'recommended',
      strategy: 'deterministic',
      resources: {
        services: {
          shared: {
            limits: { cpu_cores: 3, memory_bytes: 300 * MIB },
            reservations: { cpu_cores: 1.5, memory_bytes: 150 * MIB },
          },
          recOnly: {
            limits: { cpu_cores: 0.8, memory_bytes: 256 * MIB },
            reservations: { cpu_cores: 0.4, memory_bytes: 128 * MIB },
          },
        },
      },
      adjustments: {},
      placements: [],
      created_at: '2026-02-19T00:00:00.000Z',
      updated_at: '2026-02-19T00:00:00.000Z',
    };

    const incremental = buildIncrementalProfile(base, recommended, '2026-02-19T01:00:00.000Z');
    expect(incremental.resources.services.shared.limits.cpu_cores).toBe(2);
    expect(incremental.resources.services.shared.limits.memory_bytes).toBe(200 * MIB);

    expect(incremental.resources.services.baseOnly).toEqual(base.services.baseOnly);
    expect(incremental.resources.services.recOnly).toEqual(recommended.resources.services.recOnly);
    expect(incremental.adjustments.shared?.source).toBe('incremental');
    expect(incremental.adjustments.baseOnly).toBeUndefined();
    expect(incremental.adjustments.recOnly).toBeUndefined();
  });

  it('prunes stale approved profiles while keeping undated entries', () => {
    const nowMs = Date.parse('2026-02-17T00:00:00.000Z');
    const kept = pruneApprovedProfiles(
      [
        {
          id: 'fresh',
          status: 'approved',
          strategy: 'x',
          resources: sampleResources(),
          adjustments: {},
          placements: [],
          created_at: '2026-02-10T00:00:00.000Z',
          updated_at: '2026-02-10T00:00:00.000Z',
        },
        {
          id: 'stale',
          status: 'approved',
          strategy: 'x',
          resources: sampleResources(),
          adjustments: {},
          placements: [],
          created_at: '2023-01-01T00:00:00.000Z',
          updated_at: '2023-01-01T00:00:00.000Z',
        },
        {
          id: 'undated',
          status: 'approved',
          strategy: 'x',
          resources: sampleResources(),
          adjustments: {},
          placements: [],
          created_at: '',
          updated_at: '',
        },
      ],
      nowMs,
    );

    expect(kept.map((profile) => profile.id).sort()).toEqual(['fresh', 'undated']);
  });

  it('keeps profiles with invalid timestamps when pruning', () => {
    const nowMs = Date.parse('2026-02-19T00:00:00.000Z');
    const kept = pruneApprovedProfiles(
      [
        {
          id: 'invalid-date',
          status: 'approved',
          strategy: 'x',
          resources: sampleResources(),
          adjustments: {},
          placements: [],
          created_at: 'still-not-a-date',
          updated_at: 'not-a-date',
        },
        {
          id: 'stale-valid',
          status: 'approved',
          strategy: 'x',
          resources: sampleResources(),
          adjustments: {},
          placements: [],
          created_at: '2020-01-01T00:00:00.000Z',
          updated_at: '2020-01-01T00:00:00.000Z',
        },
      ],
      nowMs,
    );

    expect(kept.map((profile) => profile.id).sort()).toEqual(['invalid-date']);
  });

  it('builds placement hints based on reservation footprint and available node memory', () => {
    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-17T00:00:00.000Z',
      services: [
        { name: 'worker', service: 'worker', environment_id: 5, container_ids: [], replicas: 1 },
        { name: 'web', service: 'web', environment_id: 5, container_ids: [], replicas: 1 },
        { name: 'constrained', service: 'php-fpm', environment_id: 5, container_ids: [], replicas: 1, constraints: ['node.role == manager'] },
      ],
    };
    const resources = sampleResources();
    const nodes: CapacityNode[] = [
      { id: 'node-1', hostname: 'node-1', status: 'ready', availability: 'active', free: { cpu_cores: 4, memory_bytes: 1000 * MIB } },
      { id: 'node-2', hostname: 'node-2', status: 'ready', availability: 'active', free: { cpu_cores: 4, memory_bytes: 600 * MIB } },
    ];

    const placements = buildPlacementHints(inspection, resources, nodes);
    expect(placements).toHaveLength(2);
    expect(placements.find((entry) => entry.service === 'php-fpm')).toBeUndefined();
    expect(placements.find((entry) => entry.service === 'worker')?.node_id).toBe('node-1');
    expect(placements.find((entry) => entry.service === 'web')?.node_id).toBe('node-2');
  });

  it('applies ai adjustments with policy caps and filters constrained placements', () => {
    const baseResources: PlannerResources = {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 1, memory_bytes: GIB },
          reservations: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
        },
        cron: {
          limits: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
          reservations: { cpu_cores: 0.25, memory_bytes: 256 * MIB },
        },
      },
    };
    const tunedResources = clonePlannerResources(baseResources);
    const tuningProfile = createBaseProfile(tunedResources, '2026-02-17T00:00:00.000Z');
    tuningProfile.status = 'recommended';
    tuningProfile.strategy = 'deterministic';

    const inspection: PlannerInspectionPayload = {
      generated_at: '2026-02-17T00:00:00.000Z',
      services: [
        { name: 'php', service: 'php-fpm', container_ids: [], replicas: 1 },
        { name: 'cron', service: 'cron', container_ids: [], replicas: 1, constraints: ['node.role == manager'] },
      ],
    };

    applyAiAdjustments(
      {
        strategy: 'llm',
        summary: 'AI profile summary',
        confidence: 1.5,
        adjustments: {
          'php-fpm': {
            limits: { memory_bytes: 3 * GIB, cpu_cores: 3 },
            reservations: { memory_bytes: 2 * GIB, cpu_cores: 2 },
            notes: ['from-ai'],
          },
        },
        placements: [
          { name: 'php', service: 'php-fpm', node_id: 'node-1', reason: 'headroom' },
          { name: 'cron', service: 'cron', node_id: 'node-2', reason: 'headroom' },
        ],
      },
      tuningProfile,
      tunedResources,
      baseResources,
      inspection,
      { totals: { memory_bytes: 10 * GIB, cpu_cores: 10 } },
    );

    expect(tunedResources.services['php-fpm'].limits.memory_bytes).toBe(2 * GIB);
    expect(tunedResources.services['php-fpm'].reservations.memory_bytes).toBe(896 * MIB);
    expect(tunedResources.services['php-fpm'].limits.cpu_cores).toBe(2);
    expect(tunedResources.services['php-fpm'].reservations.cpu_cores).toBe(0.88);

    expect(tuningProfile.adjustments['php-fpm']?.source).toBe('ai');
    expect(tuningProfile.adjustments['php-fpm']?.notes).toContain('from-ai');
    expect(tuningProfile.placements).toEqual([
      { name: 'php', service: 'php-fpm', node_id: 'node-1', reason: 'headroom' },
    ]);
    expect(tuningProfile.ai_confidence).toBe(1);
    expect(tuningProfile.summary).toBe('AI profile summary');
    expect(tuningProfile.strategy).toBe('deterministic+llm');
  });
});
