import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { createApp } from '../src/app.js';
import { __testing } from '../src/status.js';

const originalEnv = { ...process.env };

describe('status endpoint', () => {
  beforeEach(() => {
    process.env.MZ_DISABLE_DOCKER = '1';
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns html by default', async () => {
    const res = await createApp().request('/');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('MageZero Provisioning Status');
  });

  it('returns json when format=json', async () => {
    const res = await createApp().request('/?format=json', {
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('generated_at');
  });

  it('rejects join-token without secret', async () => {
    process.env.MZ_JOIN_SECRET = 'test-secret';
    const res = await createApp().request('/join-token');
    expect(res.status).toBe(403);
  });
});

describe('service status helpers', () => {
  it('uses latest task per slot so stale failures do not degrade status', () => {
    const tasks = [
      {
        ID: 'old-slot-1',
        ServiceID: 'svc-1',
        DesiredState: 'running',
        Slot: 1,
        Version: { Index: 10 },
        Status: { State: 'failed' },
      },
      {
        ID: 'new-slot-1',
        ServiceID: 'svc-1',
        DesiredState: 'running',
        Slot: 1,
        Version: { Index: 11 },
        Status: { State: 'running' },
      },
      {
        ID: 'slot-2',
        ServiceID: 'svc-1',
        DesiredState: 'running',
        Slot: 2,
        Version: { Index: 12 },
        Status: { State: 'running' },
      },
    ];

    const selected = __testing.selectLatestServiceTasks(tasks, 'svc-1');
    expect(selected).toHaveLength(2);
    expect(selected.map((task) => task.ID).sort()).toEqual(['new-slot-1', 'slot-2']);
  });

  it('prefers newest status timestamp when task version index is tied', () => {
    const tasks = [
      {
        ID: 'z-failed-older-id',
        ServiceID: 'svc-2',
        DesiredState: 'running',
        NodeID: 'node-a',
        Version: { Index: 141224 },
        Status: { State: 'failed', Timestamp: '2026-02-05T23:38:32.287Z' },
      },
      {
        ID: 'a-running-newer-id',
        ServiceID: 'svc-2',
        DesiredState: 'running',
        NodeID: 'node-a',
        Version: { Index: 141224 },
        Status: { State: 'running', Timestamp: '2026-02-16T09:24:45.262Z' },
      },
    ];

    const selected = __testing.selectLatestServiceTasks(tasks, 'svc-2');
    expect(selected).toHaveLength(1);
    expect(selected[0]?.ID).toBe('a-running-newer-id');
  });

  it('prefers desired running task over newer desired shutdown task in start-first updates', () => {
    const tasks = [
      {
        ID: 'old-task-shutdown-newer',
        ServiceID: 'svc-3',
        DesiredState: 'shutdown',
        Slot: 1,
        Version: { Index: 200 },
        Status: { State: 'shutdown', Timestamp: '2026-02-17T01:08:29.291Z' },
      },
      {
        ID: 'new-task-running-current',
        ServiceID: 'svc-3',
        DesiredState: 'running',
        Slot: 1,
        Version: { Index: 199 },
        Status: { State: 'running', Timestamp: '2026-02-17T01:08:25.706Z' },
      },
    ];

    const selected = __testing.selectLatestServiceTasks(tasks, 'svc-3');
    expect(selected).toHaveLength(1);
    expect(selected[0]?.ID).toBe('new-task-running-current');
  });

  it('counts eligible nodes for global services using placement constraints', () => {
    const service = {
      Spec: {
        TaskTemplate: {
          Placement: {
            Constraints: ['node.role == manager'],
          },
        },
      },
    };
    const readyNodes = [
      { Spec: { Role: 'manager', Availability: 'active' }, Status: { State: 'ready' } },
      { Spec: { Role: 'worker', Availability: 'active' }, Status: { State: 'ready' } },
    ];

    expect(__testing.countEligibleReadyNodesForService(service, readyNodes)).toBe(1);
  });

  it('parses placement constraints with quoted values and rejects invalid forms', () => {
    expect(__testing.parsePlacementConstraint(`node.labels.role == "database"`)).toEqual({
      key: 'node.labels.role',
      operator: '==',
      value: 'database',
    });
    expect(__testing.parsePlacementConstraint(`node.role != 'manager'`)).toEqual({
      key: 'node.role',
      operator: '!=',
      value: 'manager',
    });
    expect(__testing.parsePlacementConstraint('not-a-constraint')).toBeNull();
  });

  it('evaluates node placement constraints including missing labels', () => {
    const node = {
      ID: 'node-1',
      Spec: { Role: 'worker', Labels: { tier: 'app' } },
      Description: {
        Hostname: 'worker-1',
        Platform: { OS: 'linux', Architecture: 'x86_64' },
        Engine: { Labels: { storage: 'ssd' } },
      },
    };

    expect(__testing.nodeMatchesPlacementConstraints(node, [
      'node.role == worker',
      'node.labels.tier == app',
      'engine.labels.storage == ssd',
      'node.role != manager',
    ])).toBe(true);
    expect(__testing.nodeMatchesPlacementConstraints(node, ['node.labels.region == eu-west-1'])).toBe(false);
  });

  it('builds stable grouping keys and recency from partial task payloads', () => {
    expect(__testing.taskGroupingKey({ Slot: 3 })).toBe('slot:3');
    expect(__testing.taskGroupingKey({ Slot: 0, NodeID: 'node-a' })).toBe('node:node-a');
    expect(__testing.taskGroupingKey({ ID: 'task-a' })).toBe('task:task-a');

    expect(__testing.parseTaskRecency({ ID: 'x', Version: { Index: 'invalid' } })).toEqual({
      versionIndex: 0,
      statusTimestamp: 0,
      updatedAt: 0,
      createdAt: 0,
      taskId: 'x',
    });
  });

  it('uses updated_at and created_at to break recency ties when version is absent', () => {
    const tasks = [
      {
        ID: 'old',
        ServiceID: 'svc-4',
        DesiredState: 'running',
        NodeID: 'node-a',
        UpdatedAt: '2026-02-10T00:00:00.000Z',
        CreatedAt: '2026-02-09T00:00:00.000Z',
      },
      {
        ID: 'new',
        ServiceID: 'svc-4',
        DesiredState: 'running',
        NodeID: 'node-a',
        UpdatedAt: '2026-02-11T00:00:00.000Z',
        CreatedAt: '2026-02-09T00:00:00.000Z',
      },
    ];

    const selected = __testing.selectLatestServiceTasks(tasks, 'svc-4');
    expect(selected).toHaveLength(1);
    expect(selected[0]?.ID).toBe('new');
  });
});
