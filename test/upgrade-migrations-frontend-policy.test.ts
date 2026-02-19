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
  restartCondition?: string;
  updateOrder?: string;
  reserveNanoCpus?: number;
  reserveMemoryBytes?: number;
}) {
  return JSON.stringify({
    Mode: {
      Replicated: {
        Replicas: params.replicas,
      },
    },
    UpdateConfig: {
      Order: params.updateOrder ?? 'start-first',
    },
    TaskTemplate: {
      Placement: {
        MaxReplicas: params.maxReplicasPerNode ?? 0,
      },
      RestartPolicy: {
        Condition: params.restartCondition ?? 'on-failure',
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

describe('frontend runtime policy upgrade migrations', () => {
  afterEach(() => {
    runCommandMock.mockReset();
    buildCapacityPayloadMock.mockReset();
  });

  it('frontend-runtime-policy-reconcile executes rebalance + normalization paths', async () => {
    buildCapacityPayloadMock.mockResolvedValue({
      nodes: [
        { status: 'ready', availability: 'active', labels: {} },
        { status: 'ready', availability: 'active', labels: {} },
      ],
      totals: {
        free_cpu_cores: 8,
        free_memory_bytes: 32 * 1024 * 1024 * 1024,
      },
    } as any);

    const specs: Record<string, string> = {
      'mz-env-15_varnish': serviceSpec({
        replicas: 1,
        maxReplicasPerNode: 0,
        restartCondition: 'on-failure',
        updateOrder: 'start-first',
      }),
      'mz-env-15_nginx': serviceSpec({
        replicas: 1,
        maxReplicasPerNode: 0,
        restartCondition: 'on-failure',
        updateOrder: 'start-first',
        reserveNanoCpus: 200_000_000,
        reserveMemoryBytes: 256 * 1024 * 1024,
      }),
      'mz-env-15_php-fpm': serviceSpec({
        replicas: 1,
        maxReplicasPerNode: 0,
        restartCondition: 'on-failure',
        updateOrder: 'start-first',
        reserveNanoCpus: 1_000_000_000,
        reserveMemoryBytes: 1024 * 1024 * 1024,
      }),
    };

    const updates: string[][] = [];
    runCommandMock.mockImplementation(async (_cmd, args) => {
      if (args[0] === 'service' && args[1] === 'inspect') {
        const serviceName = String(args[2] || '');
        const format = String(args[4] || '');
        if (format === '{{json .Spec}}') {
          if (specs[serviceName]) {
            return { code: 0, stdout: specs[serviceName], stderr: '' };
          }
          return { code: 1, stdout: '', stderr: `No such service: ${serviceName}` };
        }
      }
      if (args[0] === 'service' && args[1] === 'update') {
        updates.push(args.map((entry) => String(entry)));
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('frontend-runtime-policy-reconcile', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(buildCapacityPayloadMock).toHaveBeenCalledTimes(1);
    expect(updates).toContainEqual([
      'service',
      'update',
      '--replicas',
      '2',
      '--replicas-max-per-node',
      '1',
      'mz-env-15_nginx',
    ]);
    expect(updates).toContainEqual([
      'service',
      'update',
      '--restart-condition',
      'any',
      '--update-order',
      'stop-first',
      '--rollback-order',
      'stop-first',
      'mz-env-15_nginx',
    ]);
  });

  it('frontend-placement-deadlock-recovery resumes placement-paused frontend updates', async () => {
    const specs: Record<string, string> = {
      'mz-env-15_varnish': serviceSpec({
        replicas: 2,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'stop-first',
      }),
      'mz-env-15_nginx': serviceSpec({
        replicas: 2,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'start-first',
      }),
      'mz-env-15_php-fpm': serviceSpec({
        replicas: 2,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'start-first',
      }),
    };
    const updateStatuses: Record<string, string> = {
      'mz-env-15_nginx': JSON.stringify({
        State: 'paused',
        Message: 'no suitable node (max replicas per node limit exceed)',
      }),
    };

    const updates: string[][] = [];
    runCommandMock.mockImplementation(async (_cmd, args) => {
      if (args[0] === 'service' && args[1] === 'inspect') {
        const serviceName = String(args[2] || '');
        const format = String(args[4] || '');
        if (format === '{{json .Spec}}') {
          if (specs[serviceName]) {
            return { code: 0, stdout: specs[serviceName], stderr: '' };
          }
          return { code: 1, stdout: '', stderr: `No such service: ${serviceName}` };
        }
        if (format === '{{json .UpdateStatus}}') {
          return { code: 0, stdout: updateStatuses[serviceName] || 'null', stderr: '' };
        }
      }
      if (args[0] === 'service' && args[1] === 'update') {
        updates.push(args.map((entry) => String(entry)));
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('frontend-placement-deadlock-recovery', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(updates).toContainEqual([
      'service',
      'update',
      '--update-failure-action',
      'continue',
      'mz-env-15_nginx',
    ]);
    expect(updates).toContainEqual([
      'service',
      'update',
      '--update-order',
      'stop-first',
      '--rollback-order',
      'stop-first',
      '--force',
      'mz-env-15_nginx',
    ]);
  });
});
