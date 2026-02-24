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

describe('proxysql query rule upgrade migration', () => {
  afterEach(() => {
    runCommandMock.mockReset();
  });

  it('reconciles ProxySQL query rules via a node-pinned Swarm job', async () => {
    let createArgs: string[] | null = null;

    runCommandMock.mockImplementation(async (_cmd, args) => {
      const a = args.map((value) => String(value));

      if (a[0] === 'service' && a[1] === 'inspect' && a[2] === 'mz-env-15_proxysql' && a[4] === '{{json .}}') {
        return {
          code: 0,
          stdout: JSON.stringify({
            Spec: {
              TaskTemplate: {
                ContainerSpec: {
                  Image: '10.100.0.10:5000/mz-proxysql:env-15-test',
                  Env: [],
                },
                Networks: [
                  {
                    Target: 'net-backend-id',
                    Aliases: ['proxysql'],
                  },
                ],
              },
            },
          }),
          stderr: '',
        };
      }

      if (a[0] === 'network' && a[1] === 'inspect' && a[2] === 'net-backend-id' && a[4] === '{{.Name}}') {
        return { code: 0, stdout: 'mz-env-15_default\n', stderr: '' };
      }

      if (
        a[0] === 'service'
        && a[1] === 'ps'
        && a[2] === 'mz-env-15_proxysql'
        && a.includes('{{json .}}')
      ) {
        return {
          code: 0,
          stdout: `${JSON.stringify({
            ID: 'task1',
            Name: 'mz-env-15_proxysql.1',
            Node: 'worker-node-1',
            DesiredState: 'Running',
            CurrentState: 'Running 10 seconds ago',
            Error: '',
          })}\n`,
          stderr: '',
        };
      }

      if (a[0] === 'service' && a[1] === 'create') {
        createArgs = a;
        return { code: 0, stdout: 'created-job-id\n', stderr: '' };
      }

      if (
        a[0] === 'service'
        && a[1] === 'ps'
        && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')
        && a.includes('{{.CurrentState}}|{{.Error}}')
      ) {
        return { code: 0, stdout: 'Complete 1 second ago|\n', stderr: '' };
      }

      if (a[0] === 'service' && a[1] === 'logs' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: '', stderr: '' };
      }

      if (a[0] === 'service' && a[1] === 'rm' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: '', stderr: '' };
      }

      return { code: 0, stdout: '', stderr: '' };
    });

    await executeMigration('reconcile-proxysql-query-rules', {
      environmentId: 15,
      cloudSwarmDir: '/tmp/cloud-swarm',
    });

    expect(createArgs).not.toBeNull();
    const create = createArgs || [];
    expect(create).toContain('--constraint');
    expect(create).toContain('node.hostname==worker-node-1');
    expect(create).toContain('mz-env-15_default');

    const encodedWrapper = create[create.length - 1];
    expect(encodedWrapper).toContain('base64 -d | sh');
    const encodedMatch = encodedWrapper.match(/printf '%s' '([^']+)' \| base64 -d \| sh/);
    expect(encodedMatch?.[1]).toBeTruthy();
    const decodedScript = Buffer.from(String(encodedMatch?.[1] || ''), 'base64').toString('utf8');

    expect(decodedScript).toContain('search_tmp_');
    expect(decodedScript).toContain('LOAD MYSQL QUERY RULES TO RUNTIME');
    expect(decodedScript).toContain('SAVE MYSQL QUERY RULES TO DISK');
    expect(decodedScript).toContain('"radmin:radmin" "admin:admin"');
    expect(decodedScript).toContain('PROXYSQL_HOST="mz-env-15_proxysql"');
  });

  it('skips without failing the upgrade when proxysql admin is not ready', async () => {
    runCommandMock.mockImplementation(async (_cmd, args) => {
      const a = args.map((value) => String(value));

      if (a[0] === 'service' && a[1] === 'inspect' && a[2] === 'mz-env-5_proxysql' && a[4] === '{{json .}}') {
        return {
          code: 0,
          stdout: JSON.stringify({
            Spec: {
              TaskTemplate: {
                ContainerSpec: { Image: '10.100.0.10:5000/mz-proxysql:env-5-test', Env: [] },
                Networks: [{ Target: 'net-backend-id', Aliases: ['proxysql'] }],
              },
            },
          }),
          stderr: '',
        };
      }
      if (a[0] === 'network' && a[1] === 'inspect' && a[2] === 'net-backend-id') {
        return { code: 0, stdout: 'mz-backend\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'ps' && a[2] === 'mz-env-5_proxysql' && a.includes('{{json .}}')) {
        return {
          code: 0,
          stdout: `${JSON.stringify({
            ID: 'task1',
            Name: 'mz-env-5_proxysql.1',
            Node: 'worker-node-1',
            DesiredState: 'Running',
            CurrentState: 'Running 5 seconds ago',
            Error: '',
          })}\n`,
          stderr: '',
        };
      }
      if (a[0] === 'service' && a[1] === 'create') {
        return { code: 0, stdout: 'created-job-id\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'ps' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: 'Failed 1 second ago|\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'logs' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: 'proxysql admin not ready\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'rm' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await expect(executeMigration('reconcile-proxysql-query-rules', {
      environmentId: 5,
      cloudSwarmDir: '/tmp/cloud-swarm',
    })).resolves.toBe(true);
  });

  it('keeps non-readiness proxysql job failures fatal', async () => {
    runCommandMock.mockImplementation(async (_cmd, args) => {
      const a = args.map((value) => String(value));

      if (a[0] === 'service' && a[1] === 'inspect' && a[2] === 'mz-env-5_proxysql' && a[4] === '{{json .}}') {
        return {
          code: 0,
          stdout: JSON.stringify({
            Spec: {
              TaskTemplate: {
                ContainerSpec: { Image: '10.100.0.10:5000/mz-proxysql:env-5-test', Env: [] },
                Networks: [{ Target: 'net-backend-id', Aliases: ['proxysql'] }],
              },
            },
          }),
          stderr: '',
        };
      }
      if (a[0] === 'network' && a[1] === 'inspect' && a[2] === 'net-backend-id') {
        return { code: 0, stdout: 'mz-backend\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'ps' && a[2] === 'mz-env-5_proxysql' && a.includes('{{json .}}')) {
        return {
          code: 0,
          stdout: `${JSON.stringify({
            ID: 'task1',
            Name: 'mz-env-5_proxysql.1',
            Node: 'worker-node-1',
            DesiredState: 'Running',
            CurrentState: 'Running 5 seconds ago',
            Error: '',
          })}\n`,
          stderr: '',
        };
      }
      if (a[0] === 'service' && a[1] === 'create') {
        return { code: 0, stdout: 'created-job-id\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'ps' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: 'Failed 1 second ago|\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'logs' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: 'SQL syntax error near ...\n', stderr: '' };
      }
      if (a[0] === 'service' && a[1] === 'rm' && a[2].startsWith('mz-rb-upgrade-proxysql-rules-')) {
        return { code: 0, stdout: '', stderr: '' };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await expect(executeMigration('reconcile-proxysql-query-rules', {
      environmentId: 5,
      cloudSwarmDir: '/tmp/cloud-swarm',
    })).rejects.toThrow(/SQL syntax error/i);
  });
});
