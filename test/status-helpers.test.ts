import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const originalEnv = { ...process.env };
const tempDirs: string[] = [];

function makeTempDir(prefix: string) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function writeJson(filePath: string, payload: unknown) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
}

async function importStatusModule(extraEnv: Record<string, string> = {}) {
  process.env = {
    ...originalEnv,
    MZ_DISABLE_DOCKER: '1',
    ...extraEnv,
  };
  vi.resetModules();
  return import('../src/status.js');
}

afterEach(() => {
  process.env = { ...originalEnv };
  vi.restoreAllMocks();
  vi.resetModules();
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('status helper coverage', () => {
  it('builds node-specific status payloads and prefers env agent version', async () => {
    const tempDir = makeTempDir('mz-status-helper-');
    const configPath = path.join(tempDir, 'status.json');
    writeJson(configPath, {
      stack_domain: 'stack.example.test',
      stack_name: 'mz-example',
      nodes: [
        { node_id: 42, hostname: 'node-42.example.test', role: 'worker' },
      ],
    });

    const status = await importStatusModule({
      STATUS_CONFIG_PATH: configPath,
      MZ_SWARM_AGENT_VERSION: '0.4.97-test',
    });

    const result = await status.buildStatusPayload('node-42.example.test', true);
    expect(result.type).toBe('json');

    const payload = (result as { type: 'json'; payload: any }).payload;
    expect(payload.agent_version).toBe('0.4.97-test');
    expect(payload.node).toMatchObject({
      requested: { node_id: 42, hostname: 'node-42.example.test' },
      swarm: null,
    });
  });

  it('reads the agent version from the configured version file when env is absent', async () => {
    const tempDir = makeTempDir('mz-status-version-');
    const versionPath = path.join(tempDir, 'version.txt');
    fs.writeFileSync(versionPath, '0.4.97-file\n', 'utf8');

    const status = await importStatusModule({
      MZ_SWARM_AGENT_VERSION_PATH: versionPath,
    });

    expect(status.__testing.readAgentVersion()).toBe('0.4.97-file');
  });

  it('returns empty capacity and services payloads when docker is unavailable', async () => {
    const status = await importStatusModule({
      MZ_DISABLE_DOCKER: '0',
    });

    const result = await status.buildStatusPayload(
      'stack.example.test',
      true,
      true,
      false,
      true,
    );
    expect(result.type).toBe('json');

    const payload = (result as { type: 'json'; payload: any }).payload;
    expect(payload.swarm).toMatchObject({ total: 0, managers: 0, workers: 0 });
    expect(payload.capacity).toMatchObject({
      control_available: false,
      nodes: [],
      services: [],
    });
    expect(payload.services).toMatchObject({ services: [] });
  });

  it('maps nodes by label, hostname fallback, and role-based assignment', async () => {
    const status = await importStatusModule();
    const assignments = status.__testing.mapSwarmNodes(
      [
        { node_id: 1, hostname: 'label-id.example.test', role: 'manager' },
        { node_id: 2, hostname: 'label-host.example.test', role: 'worker' },
        { node_id: 3, hostname: 'fallback-manager.example.test', role: 'manager' },
        { node_id: 4, hostname: 'fallback-worker.example.test', role: 'worker' },
      ],
      [
        {
          id: 'manager-label-id',
          hostname: 'manager-a',
          role: 'manager',
          labels: { 'mz.node_id': '1' },
        },
        {
          id: 'worker-label-host',
          hostname: 'worker-a',
          role: 'worker',
          labels: { 'mz.node_hostname': 'label-host.example.test' },
        },
        {
          id: 'manager-fallback',
          hostname: 'manager-z',
          role: 'manager',
          labels: {},
        },
        {
          id: 'worker-fallback',
          hostname: 'worker-z',
          role: 'worker',
          labels: {},
        },
      ],
    );

    expect(assignments.get(1)?.id).toBe('manager-label-id');
    expect(assignments.get(2)?.id).toBe('worker-label-host');
    expect(assignments.get(3)?.id).toBe('manager-fallback');
    expect(assignments.get(4)?.id).toBe('worker-fallback');
  });

  it('covers task recency, grouping, and desired-state branches', async () => {
    const status = await importStatusModule();

    expect(status.__testing.parseTaskRecency({
      Status: { Timestamp: 'not-a-date' },
    })).toMatchObject({
      statusTimestamp: 0,
      taskId: '',
    });

    expect(status.__testing.compareTaskRecency(
      { ID: 'candidate', UpdatedAt: '2026-02-20T00:00:00.000Z' },
      { ID: 'current', UpdatedAt: '2026-02-19T00:00:00.000Z' },
    )).toBeGreaterThan(0);

    expect(status.__testing.desiredStateRank({ DesiredState: 'running' })).toBe(2);
    expect(status.__testing.desiredStateRank({ DesiredState: 'ready' })).toBe(1);
    expect(status.__testing.desiredStateRank({ DesiredState: 'shutdown' })).toBe(0);
    expect(status.__testing.taskGroupingKey({})).toBe('');

    const selected = status.__testing.selectLatestServiceTasks([
      {
        ID: 'current-running',
        ServiceID: 'svc-1',
        DesiredState: 'running',
        NodeID: 'node-a',
        UpdatedAt: '2026-02-20T00:00:00.000Z',
      },
      {
        ID: 'newer-shutdown',
        ServiceID: 'svc-1',
        DesiredState: 'shutdown',
        NodeID: 'node-a',
        UpdatedAt: '2026-02-21T00:00:00.000Z',
      },
      {
        ID: 'other-service',
        ServiceID: 'svc-2',
        DesiredState: 'running',
        NodeID: 'node-b',
      },
      {
        ServiceID: 'svc-1',
        DesiredState: 'running',
      },
    ], 'svc-1');

    expect(selected).toHaveLength(1);
    expect(selected[0]?.ID).toBe('current-running');
  });

  it('covers placement parsing, node value lookup, and constraint fallbacks', async () => {
    const status = await importStatusModule();
    const node = {
      ID: 'node-1',
      Spec: { Role: 'worker', Labels: { tier: 'app' } },
      Description: {
        Hostname: 'worker-1',
        Platform: { OS: 'linux', Architecture: 'arm64' },
        Engine: { Labels: { storage: 'ssd' } },
      },
    };

    expect(status.__testing.parsePlacementConstraint('')).toBeNull();
    expect(status.__testing.parsePlacementConstraint('node.role == ""')).toBeNull();

    expect(status.__testing.getNodeConstraintValue(node, 'node.id')).toBe('node-1');
    expect(status.__testing.getNodeConstraintValue(node, 'node.role')).toBe('worker');
    expect(status.__testing.getNodeConstraintValue(node, 'node.hostname')).toBe('worker-1');
    expect(status.__testing.getNodeConstraintValue(node, 'node.platform.os')).toBe('linux');
    expect(status.__testing.getNodeConstraintValue(node, 'node.platform.arch')).toBe('arm64');
    expect(status.__testing.getNodeConstraintValue(node, 'engine.labels.storage')).toBe('ssd');
    expect(status.__testing.getNodeConstraintValue(node, 'unknown.key')).toBeNull();

    expect(status.__testing.nodeMatchesPlacementConstraints(node, [
      'not-a-constraint',
      'node.role == worker',
    ])).toBe(true);
    expect(status.__testing.nodeMatchesPlacementConstraints(node, [
      'node.role != worker',
    ])).toBe(false);

    expect(status.__testing.countEligibleReadyNodesForService(
      { Spec: { TaskTemplate: {} } },
      [{ ID: 'a' }, { ID: 'b' }],
    )).toBe(2);
  });
});
