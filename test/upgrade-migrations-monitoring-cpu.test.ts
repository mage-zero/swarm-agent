import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/exec.js', () => ({
  runCommand: vi.fn(),
}));

vi.mock('../src/status.js', () => ({
  buildCapacityPayload: vi.fn(),
}));

vi.mock('../src/monitoring-dashboards.js', () => ({
  bootstrapMonitoringDashboardsWithRetry: vi.fn(),
}));

import { runCommand } from '../src/exec.js';
import { bootstrapMonitoringDashboardsWithRetry } from '../src/monitoring-dashboards.js';
import { executeMigration } from '../src/upgrade-migrations.js';

const runCommandMock = vi.mocked(runCommand);
const bootstrapMonitoringDashboardsWithRetryMock = vi.mocked(bootstrapMonitoringDashboardsWithRetry);

function createCloudSwarmFixture(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-monitoring-cpu-'));
  const cloudSwarmDir = path.join(root, 'cloud-swarm');
  fs.mkdirSync(path.join(cloudSwarmDir, '.git'), { recursive: true });
  fs.mkdirSync(path.join(cloudSwarmDir, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(cloudSwarmDir, 'stacks'), { recursive: true });
  fs.writeFileSync(path.join(cloudSwarmDir, 'scripts', 'build-monitoring.sh'), '#!/usr/bin/env bash\nexit 0\n');
  fs.writeFileSync(path.join(cloudSwarmDir, 'stacks', 'monitoring-base.yml'), 'services: {}\n');
  fs.writeFileSync(path.join(cloudSwarmDir, 'stacks', 'monitoring.yml'), 'services: {}\n');
  return root;
}

describe('refresh-monitoring-cpu-schema-v1 migration', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    runCommandMock.mockReset();
    bootstrapMonitoringDashboardsWithRetryMock.mockReset();
    vi.unstubAllGlobals();
    delete process.env.REGISTRY_PULL_HOST;
    for (const dir of tempDirs.splice(0, tempDirs.length)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rebuilds and redeploys monitoring for eligible stacks', async () => {
    process.env.REGISTRY_PULL_HOST = '127.0.0.1';
    const root = createCloudSwarmFixture();
    tempDirs.push(root);
    const cloudSwarmDir = path.join(root, 'cloud-swarm');
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stack: {
          stack_type: 'production',
          dashboards_hostname: 'dashboards.example.test',
        },
      }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);
    bootstrapMonitoringDashboardsWithRetryMock.mockResolvedValue({
      dashboard_id: 'mz-dashboard-ops',
      dashboard_ids: ['mz-dashboard-ops', 'mz-dashboard-magento-containers', 'mz-dashboard-varnish', 'mz-dashboard-cron'],
      upserted_objects: 25,
      container_id: 'abc123',
    });

    runCommandMock.mockImplementation(async (command, args) => {
      const entries = args.map((entry) => String(entry));
      if (command === 'git') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'node' && entries[1] === 'ls') {
        return { code: 0, stdout: 'node-1\n', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'network' && entries[1] === 'create') {
        return { code: 1, stdout: '', stderr: 'already exists' };
      }
      if (command === 'docker' && entries[0] === 'service' && entries[1] === 'ls') {
        return { code: 0, stdout: 'mz-edge-cloudflared\n', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'service' && entries[1] === 'update') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'stack' && entries[1] === 'deploy') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'bash') {
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('refresh-monitoring-cpu-schema-v1', {
      environmentId: 15,
      stackId: 44,
      mzControlBaseUrl: 'https://control.example',
      nodeId: 'node-1',
      nodeSecret: 'secret',
      cloudSwarmDir,
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(bootstrapMonitoringDashboardsWithRetryMock).toHaveBeenCalledTimes(1);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'bash'
        && Array.isArray(args)
        && String(args[0]) === path.join(cloudSwarmDir, 'scripts', 'build-monitoring.sh')
      )),
    ).toBe(true);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'docker'
        && Array.isArray(args)
        && args.slice(0, 2).map(String).join(' ') === 'stack deploy'
      )),
    ).toBe(true);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'docker'
        && Array.isArray(args)
        && String(args[0]) === 'service'
        && String(args[1]) === 'update'
        && String(args[2]) === '--network-add'
        && String(args[3]) === 'mz-monitoring'
        && String(args[4]) === 'mz-edge-cloudflared'
      )),
    ).toBe(true);
  });

  it('refreshes cron monitoring dashboard assets for eligible stacks', async () => {
    process.env.REGISTRY_PULL_HOST = '127.0.0.1';
    const root = createCloudSwarmFixture();
    tempDirs.push(root);
    const cloudSwarmDir = path.join(root, 'cloud-swarm');
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stack: {
          stack_type: 'production',
          dashboards_hostname: 'dashboards.example.test',
        },
      }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);
    bootstrapMonitoringDashboardsWithRetryMock.mockResolvedValue({
      dashboard_id: 'mz-dashboard-ops',
      dashboard_ids: ['mz-dashboard-ops', 'mz-dashboard-magento-containers', 'mz-dashboard-varnish', 'mz-dashboard-cron'],
      upserted_objects: 30,
      container_id: 'cron123',
    });

    runCommandMock.mockImplementation(async (command, args) => {
      const entries = args.map((entry) => String(entry));
      if (command === 'git') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'network' && entries[1] === 'create') {
        return { code: 1, stdout: '', stderr: 'already exists' };
      }
      if (command === 'docker' && entries[0] === 'service' && entries[1] === 'ls') {
        return { code: 0, stdout: 'mz-edge-cloudflared\n', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'service' && entries[1] === 'update') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'stack' && entries[1] === 'deploy') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'bash') {
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('refresh-monitoring-cron-dashboard-v1', {
      stackId: 44,
      mzControlBaseUrl: 'https://control.example',
      nodeId: 'node-1',
      nodeSecret: 'secret',
      cloudSwarmDir,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(bootstrapMonitoringDashboardsWithRetryMock).toHaveBeenCalledTimes(1);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'bash'
        && Array.isArray(args)
        && String(args[0]) === path.join(cloudSwarmDir, 'scripts', 'build-monitoring.sh')
      )),
    ).toBe(true);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'docker'
        && Array.isArray(args)
        && args.slice(0, 2).map(String).join(' ') === 'stack deploy'
      )),
    ).toBe(true);
  });

  it('refreshes cron queue observability assets via v2 migration', async () => {
    process.env.REGISTRY_PULL_HOST = '127.0.0.1';
    const root = createCloudSwarmFixture();
    tempDirs.push(root);
    const cloudSwarmDir = path.join(root, 'cloud-swarm');
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stack: {
          stack_type: 'production',
          dashboards_hostname: 'dashboards.example.test',
        },
      }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);
    bootstrapMonitoringDashboardsWithRetryMock.mockResolvedValue({
      dashboard_id: 'mz-dashboard-ops',
      dashboard_ids: ['mz-dashboard-ops', 'mz-dashboard-magento-containers', 'mz-dashboard-varnish', 'mz-dashboard-cron'],
      upserted_objects: 36,
      container_id: 'cronv2',
    });

    runCommandMock.mockImplementation(async (command, args) => {
      const entries = args.map((entry) => String(entry));
      if (command === 'git') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'network' && entries[1] === 'create') {
        return { code: 1, stdout: '', stderr: 'already exists' };
      }
      if (command === 'docker' && entries[0] === 'service' && entries[1] === 'ls') {
        return { code: 0, stdout: 'mz-edge-cloudflared\n', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'service' && entries[1] === 'update') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'docker' && entries[0] === 'stack' && entries[1] === 'deploy') {
        return { code: 0, stdout: '', stderr: '' };
      }
      if (command === 'bash') {
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('refresh-monitoring-cron-dashboard-v2', {
      stackId: 44,
      mzControlBaseUrl: 'https://control.example',
      nodeId: 'node-1',
      nodeSecret: 'secret',
      cloudSwarmDir,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(bootstrapMonitoringDashboardsWithRetryMock).toHaveBeenCalledTimes(1);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'bash'
        && Array.isArray(args)
        && String(args[0]) === path.join(cloudSwarmDir, 'scripts', 'build-monitoring.sh')
      )),
    ).toBe(true);
    expect(
      runCommandMock.mock.calls.some(([command, args]) => (
        command === 'docker'
        && Array.isArray(args)
        && args.slice(0, 2).map(String).join(' ') === 'stack deploy'
      )),
    ).toBe(true);
  });

  it('skips non-monitoring stack types', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        stack: {
          stack_type: 'development',
          dashboards_hostname: '',
        },
      }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);

    await executeMigration('refresh-monitoring-cpu-schema-v1', {
      environmentId: 15,
      stackId: 44,
      mzControlBaseUrl: 'https://control.example',
      nodeId: 'node-1',
      nodeSecret: 'secret',
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(bootstrapMonitoringDashboardsWithRetryMock).not.toHaveBeenCalled();
  });
});
