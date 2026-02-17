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
});
