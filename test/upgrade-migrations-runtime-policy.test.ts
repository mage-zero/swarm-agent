import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/exec.js', () => ({
  runCommand: vi.fn(),
}));

vi.mock('../src/status.js', () => ({
  buildCapacityPayload: vi.fn(),
}));

import { runCommand } from '../src/exec.js';
import { executeMigration } from '../src/upgrade-migrations.js';

const runCommandMock = vi.mocked(runCommand);

function serviceSpec(params: {
  replicas: number;
  maxReplicasPerNode?: number;
  restartCondition?: string;
  updateOrder?: string;
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
          NanoCPUs: 0,
          MemoryBytes: 0,
        },
      },
    },
  });
}

describe('normalize-env-runtime-policies migration', () => {
  afterEach(() => {
    runCommandMock.mockReset();
  });

  it('normalizes restart condition and update order for HA frontend services', async () => {
    const specs: Record<string, string> = {
      'mz-env-15_varnish': serviceSpec({
        replicas: 2,
        maxReplicasPerNode: 1,
        restartCondition: 'on-failure',
        updateOrder: 'start-first',
      }),
      'mz-env-15_nginx': serviceSpec({
        replicas: 2,
        maxReplicasPerNode: 1,
        restartCondition: 'on-failure',
        updateOrder: 'start-first',
      }),
      'mz-env-15_php-fpm': serviceSpec({
        replicas: 2,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'start-first',
      }),
      'mz-env-15_php-fpm-admin': serviceSpec({ replicas: 1, restartCondition: 'any' }),
      'mz-env-15_cron': serviceSpec({ replicas: 1, restartCondition: 'on-failure' }),
      'mz-env-15_database': serviceSpec({ replicas: 1, restartCondition: 'on-failure' }),
      'mz-env-15_database-replica': serviceSpec({ replicas: 1, restartCondition: 'on-failure' }),
      'mz-env-15_proxysql': serviceSpec({ replicas: 1, restartCondition: 'on-failure' }),
      'mz-env-15_opensearch': serviceSpec({ replicas: 1, restartCondition: 'on-failure' }),
      'mz-env-15_redis-cache': serviceSpec({ replicas: 1, restartCondition: 'any' }),
      'mz-env-15_redis-session': serviceSpec({ replicas: 1, restartCondition: 'any' }),
      'mz-env-15_rabbitmq': serviceSpec({ replicas: 1, restartCondition: 'on-failure' }),
      'mz-env-15_mailhog': serviceSpec({ replicas: 0, restartCondition: 'on-failure' }),
    };

    const updates: string[][] = [];
    runCommandMock.mockImplementation(async (_cmd, args) => {
      if (args[0] === 'service' && args[1] === 'inspect') {
        const serviceName = String(args[2] || '');
        if (specs[serviceName]) {
          return { code: 0, stdout: specs[serviceName], stderr: '' };
        }
        return { code: 1, stdout: '', stderr: `No such service: ${serviceName}` };
      }
      if (args[0] === 'service' && args[1] === 'update') {
        updates.push(args.map((entry) => String(entry)));
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('normalize-env-runtime-policies', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(updates).toContainEqual([
      'service',
      'update',
      '--restart-condition',
      'any',
      '--update-order',
      'stop-first',
      '--rollback-order',
      'stop-first',
      '--force',
      'mz-env-15_varnish',
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
    expect(updates).toContainEqual([
      'service',
      'update',
      '--update-order',
      'stop-first',
      '--rollback-order',
      'stop-first',
      'mz-env-15_php-fpm',
    ]);
    expect(updates).toContainEqual([
      'service',
      'update',
      '--restart-condition',
      'any',
      'mz-env-15_proxysql',
    ]);
  });

  it('drops frontend max-per-node to 0 for single-replica policy', async () => {
    const specs: Record<string, string> = {
      'mz-env-31_varnish': serviceSpec({
        replicas: 1,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'stop-first',
      }),
      'mz-env-31_nginx': serviceSpec({
        replicas: 1,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'stop-first',
      }),
      'mz-env-31_php-fpm': serviceSpec({
        replicas: 1,
        maxReplicasPerNode: 1,
        restartCondition: 'any',
        updateOrder: 'stop-first',
      }),
    };

    const updates: string[][] = [];
    runCommandMock.mockImplementation(async (_cmd, args) => {
      if (args[0] === 'service' && args[1] === 'inspect') {
        const serviceName = String(args[2] || '');
        if (specs[serviceName]) {
          return { code: 0, stdout: specs[serviceName], stderr: '' };
        }
        return { code: 1, stdout: '', stderr: `No such service: ${serviceName}` };
      }
      if (args[0] === 'service' && args[1] === 'update') {
        updates.push(args.map((entry) => String(entry)));
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('normalize-env-runtime-policies', {
      environmentId: 31,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(updates).toContainEqual([
      'service',
      'update',
      '--replicas',
      '1',
      '--replicas-max-per-node',
      '0',
      'mz-env-31_varnish',
    ]);
    expect(updates).toContainEqual([
      'service',
      'update',
      '--replicas',
      '1',
      '--replicas-max-per-node',
      '0',
      'mz-env-31_nginx',
    ]);
    expect(updates).toContainEqual([
      'service',
      'update',
      '--replicas',
      '1',
      '--replicas-max-per-node',
      '0',
      'mz-env-31_php-fpm',
    ]);
  });
});
