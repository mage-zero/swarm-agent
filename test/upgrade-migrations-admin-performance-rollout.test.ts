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

function inspectSpecJson(env: string[] = []) {
  return JSON.stringify({
    Spec: {
      TaskTemplate: {
        ContainerSpec: {
          Image: '10.100.0.10:5000/mz-service:test',
          Env: env,
        },
        Networks: [],
      },
    },
  });
}

function replicaSpecJson(replicas: number, maxReplicasPerNode = 0) {
  return JSON.stringify({
    Mode: {
      Replicated: {
        Replicas: replicas,
      },
    },
    UpdateConfig: {
      Order: 'start-first',
    },
    TaskTemplate: {
      Placement: {
        MaxReplicas: maxReplicasPerNode,
      },
      Resources: {
        Reservations: {
          NanoCPUs: 0,
          MemoryBytes: 0,
        },
      },
      RestartPolicy: {
        Condition: 'on-failure',
      },
    },
  });
}

describe('admin performance rollout upgrade migrations', () => {
  afterEach(() => {
    runCommandMock.mockReset();
  });

  it('routes frontend/admin/cron DB path directly to writer', async () => {
    const updates: string[][] = [];

    runCommandMock.mockImplementation(async (_cmd, args) => {
      const a = args.map((entry) => String(entry));
      if (a[0] === 'service' && a[1] === 'inspect' && a[4] === '{{json .}}') {
        return { code: 0, stdout: inspectSpecJson(['MZ_DB_HOST=proxysql', 'MZ_DB_PORT=6033']), stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'update') {
        updates.push(a);
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('route-admin-cron-db-path-v1', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(updates).toHaveLength(3);
    for (const serviceSuffix of ['php-fpm', 'php-fpm-admin', 'cron']) {
      expect(updates).toContainEqual(expect.arrayContaining([
        'service',
        'update',
        '--env-add',
        'MZ_DB_HOST=mz-env-15_database',
        '--env-add',
        'MZ_DB_PORT=3306',
        '--force',
        `mz-env-15_${serviceSuffix}`,
      ]));
    }
  });

  it('scales proxysql service to standby replicas=0', async () => {
    let updateArgs: string[] | null = null;

    runCommandMock.mockImplementation(async (_cmd, args) => {
      const a = args.map((entry) => String(entry));
      if (a[0] === 'service' && a[1] === 'inspect' && a[2] === 'mz-env-15_proxysql' && a[4] === '{{json .Spec}}') {
        return { code: 0, stdout: replicaSpecJson(1, 1), stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'update') {
        updateArgs = a;
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('scale-proxysql-standby-v1', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(updateArgs).toEqual([
      'service',
      'update',
      '--replicas',
      '0',
      '--replicas-max-per-node',
      '0',
      'mz-env-15_proxysql',
    ]);
  });

  it('enforces DB baseline tuning and waits for running DB tasks', async () => {
    const updates: string[][] = [];

    runCommandMock.mockImplementation(async (_cmd, args) => {
      const a = args.map((entry) => String(entry));

      if (a[0] === 'service' && a[1] === 'inspect' && a[4] === '{{json .}}') {
        return { code: 0, stdout: inspectSpecJson(), stderr: '' };
      }

      if (a[0] === 'service' && a[1] === 'inspect' && a[4] === '{{json .Spec.TaskTemplate.Resources.Limits}}') {
        if (a[2] === 'mz-env-9_database') {
          return { code: 0, stdout: JSON.stringify({ MemoryBytes: 2 * 1024 * 1024 * 1024 }), stderr: '' };
        }
        if (a[2] === 'mz-env-9_database-replica') {
          return { code: 0, stdout: JSON.stringify({ MemoryBytes: 1 * 1024 * 1024 * 1024 }), stderr: '' };
        }
      }

      if (a[0] === 'service' && a[1] === 'update') {
        updates.push(a);
        return { code: 0, stdout: '', stderr: '' };
      }

      if (a[0] === 'service' && a[1] === 'inspect' && a[4] === '{{json .Spec}}') {
        if (a[2] === 'mz-env-9_database') {
          return { code: 0, stdout: replicaSpecJson(1), stderr: '' };
        }
        if (a[2] === 'mz-env-9_database-replica') {
          return { code: 0, stdout: replicaSpecJson(0), stderr: '' };
        }
      }

      if (a[0] === 'service' && a[1] === 'ps' && a[2] === 'mz-env-9_database' && a.includes('{{json .}}')) {
        return {
          code: 0,
          stdout: `${JSON.stringify({
            ID: 'db-task-1',
            Name: 'mz-env-9_database.1',
            Node: 'worker-1',
            DesiredState: 'Running',
            CurrentState: 'Running 5 seconds ago',
            Error: '',
          })}\n`,
          stderr: '',
        };
      }

      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('enforce-db-baseline-tuning-v1', {
      environmentId: 9,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(updates).toContainEqual(expect.arrayContaining([
      'service',
      'update',
      '--env-add',
      'MZ_DB_INNODB_BUFFER_POOL_SIZE=1216M',
      '--env-add',
      'MZ_DB_QUERY_CACHE_SIZE=0',
      '--env-add',
      'MZ_DB_QUERY_CACHE_TYPE=OFF',
      '--force',
      'mz-env-9_database',
    ]));

    expect(updates).toContainEqual(expect.arrayContaining([
      'service',
      'update',
      '--env-add',
      'MZ_DB_INNODB_BUFFER_POOL_SIZE=640M',
      '--env-add',
      'MZ_DB_QUERY_CACHE_SIZE=0',
      '--env-add',
      'MZ_DB_QUERY_CACHE_TYPE=OFF',
      '--force',
      'mz-env-9_database-replica',
    ]));
  });
});
