import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/exec.js', () => ({
  runCommand: vi.fn(),
}));

vi.mock('../src/status.js', () => ({
  buildCapacityPayload: vi.fn(),
}));

import { runCommand } from '../src/exec.js';
import { buildCapacityPayload } from '../src/status.js';
import { executeMigration } from '../src/upgrade-migrations.js';

const runCommandMock = vi.mocked(runCommand);
const buildCapacityPayloadMock = vi.mocked(buildCapacityPayload);

function serviceSpec(params: {
  replicas: number;
  maxReplicasPerNode?: number;
  reserveNanoCpus?: number;
  reserveMemoryBytes?: number;
}) {
  return JSON.stringify({
    Mode: {
      Replicated: {
        Replicas: params.replicas,
      },
    },
    TaskTemplate: {
      Placement: {
        MaxReplicas: params.maxReplicasPerNode ?? 0,
      },
      Resources: {
        Reservations: {
          NanoCPUs: params.reserveNanoCpus ?? 0,
          MemoryBytes: params.reserveMemoryBytes ?? 0,
        },
      },
    },
  });
}

function expectReplicaUpdate(
  updateArgs: string[][],
  serviceName: string,
  replicas: number,
  maxReplicasPerNode = 1,
) {
  const expected = [
    'service',
    'update',
    '--replicas',
    String(replicas),
    '--replicas-max-per-node',
    String(maxReplicasPerNode),
    serviceName,
  ];
  expect(updateArgs).toContainEqual(expected);
}

describe('rebalance-frontend-ha-replicas migration', () => {
  afterEach(() => {
    runCommandMock.mockReset();
    buildCapacityPayloadMock.mockReset();
  });

  it('scales frontend services to 2 replicas when multi-node headroom is sufficient', async () => {
    buildCapacityPayloadMock.mockResolvedValue({
      generated_at: '2026-02-19T00:00:00.000Z',
      control_available: true,
      nodes: [
        { status: 'ready', availability: 'active' },
        { status: 'ready', availability: 'active' },
      ],
      services: [],
      totals: {
        cpu_cores: 8,
        memory_bytes: 16 * 1024 * 1024 * 1024,
        reserved_cpu_cores: 3,
        reserved_memory_bytes: 5 * 1024 * 1024 * 1024,
        free_cpu_cores: 5,
        free_memory_bytes: 11 * 1024 * 1024 * 1024,
      },
    } as any);

    const updates: string[][] = [];
    runCommandMock.mockImplementation(async (_cmd, args) => {
      if (args[0] === 'service' && args[1] === 'inspect') {
        const serviceName = String(args[2] || '');
        if (serviceName.endsWith('_nginx')) {
          return {
            code: 0,
            stdout: serviceSpec({
              replicas: 1,
              maxReplicasPerNode: 0,
              reserveNanoCpus: 200_000_000,
              reserveMemoryBytes: 256 * 1024 * 1024,
            }),
            stderr: '',
          };
        }
        if (serviceName.endsWith('_php-fpm')) {
          return {
            code: 0,
            stdout: serviceSpec({
              replicas: 1,
              maxReplicasPerNode: 0,
              reserveNanoCpus: 1_000_000_000,
              reserveMemoryBytes: 1024 * 1024 * 1024,
            }),
            stderr: '',
          };
        }
        if (serviceName.endsWith('_varnish')) {
          return {
            code: 0,
            stdout: serviceSpec({
              replicas: 1,
              maxReplicasPerNode: 0,
            }),
            stderr: '',
          };
        }
      }
      if (args[0] === 'service' && args[1] === 'update') {
        updates.push(args.map((item) => String(item)));
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('rebalance-frontend-ha-replicas', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expectReplicaUpdate(updates, 'mz-env-15_varnish', 2);
    expectReplicaUpdate(updates, 'mz-env-15_nginx', 2);
    expectReplicaUpdate(updates, 'mz-env-15_php-fpm', 2);
  });

  it('reduces frontend services back to 1 replica when headroom is insufficient', async () => {
    buildCapacityPayloadMock.mockResolvedValue({
      generated_at: '2026-02-19T00:00:00.000Z',
      control_available: true,
      nodes: [
        { status: 'ready', availability: 'active' },
        { status: 'ready', availability: 'active' },
      ],
      services: [],
      totals: {
        cpu_cores: 8,
        memory_bytes: 16 * 1024 * 1024 * 1024,
        reserved_cpu_cores: 7.95,
        reserved_memory_bytes: 15.9 * 1024 * 1024 * 1024,
        free_cpu_cores: 0.05,
        free_memory_bytes: 100 * 1024 * 1024,
      },
    } as any);

    const updates: string[][] = [];
    runCommandMock.mockImplementation(async (_cmd, args) => {
      if (args[0] === 'service' && args[1] === 'inspect') {
        const serviceName = String(args[2] || '');
        if (serviceName.endsWith('_nginx')) {
          return {
            code: 0,
            stdout: serviceSpec({
              replicas: 2,
              maxReplicasPerNode: 1,
              reserveNanoCpus: 200_000_000,
              reserveMemoryBytes: 256 * 1024 * 1024,
            }),
            stderr: '',
          };
        }
        if (serviceName.endsWith('_php-fpm')) {
          return {
            code: 0,
            stdout: serviceSpec({
              replicas: 2,
              maxReplicasPerNode: 1,
              reserveNanoCpus: 1_000_000_000,
              reserveMemoryBytes: 1024 * 1024 * 1024,
            }),
            stderr: '',
          };
        }
        if (serviceName.endsWith('_varnish')) {
          return {
            code: 0,
            stdout: serviceSpec({
              replicas: 2,
              maxReplicasPerNode: 1,
            }),
            stderr: '',
          };
        }
      }
      if (args[0] === 'service' && args[1] === 'update') {
        updates.push(args.map((item) => String(item)));
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('rebalance-frontend-ha-replicas', {
      environmentId: 22,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expectReplicaUpdate(updates, 'mz-env-22_varnish', 1, 0);
    expectReplicaUpdate(updates, 'mz-env-22_nginx', 1, 0);
    expectReplicaUpdate(updates, 'mz-env-22_php-fpm', 1, 0);
  });
});
