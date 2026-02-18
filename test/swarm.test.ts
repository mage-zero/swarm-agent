import { describe, expect, it } from 'vitest';
import { buildJobName, envServiceName, pickNetworkName, pickSecretName, summarizeServiceTasks } from '../src/swarm.js';

describe('swarm helpers', () => {
  it('builds stack-qualified service names', () => {
    expect(envServiceName(5, 'database')).toBe('mz-env-5_database');
  });

  it('summarizes service tasks (healthy)', () => {
    const summary = summarizeServiceTasks([
      {
        id: 'id1',
        name: 'mz-env-5_php-fpm.1',
        node: 'worker-1',
        desired_state: 'Running',
        current_state: 'Running 2 minutes ago',
        error: '',
      },
    ]);
    expect(summary.ok).toBe(true);
    expect(summary.running).toBe(1);
    expect(summary.desired_running).toBe(1);
    expect(summary.issues).toEqual([]);
  });

  it('summarizes service tasks (unhealthy)', () => {
    const summary = summarizeServiceTasks([
      {
        id: 'id1',
        name: 'mz-env-5_varnish.1',
        node: 'worker-2',
        desired_state: 'Running',
        current_state: 'Failed 10 seconds ago',
        error: 'task: non-zero exit (1)',
      },
      {
        id: 'id2',
        name: 'mz-env-5_varnish.2',
        node: 'worker-1',
        desired_state: 'Shutdown',
        current_state: 'Shutdown 1 minute ago',
        error: '',
      },
    ]);
    expect(summary.ok).toBe(false);
    expect(summary.desired_running).toBe(1);
    expect(summary.running).toBe(0);
    expect(summary.issues.length).toBeGreaterThan(0);
  });

  it('selects secret and network names from service spec', () => {
    const spec = {
      service_name: 'mz-env-5_php-fpm',
      image: 'registry:5000/mz-php-fpm:8.3',
      networks: [
        { name: 'mz-public', aliases: ['nginx'] },
        { name: 'mz-backend', aliases: ['php-fpm', 'php'] },
      ],
      secrets: [
        { file_name: 'db_root_password', secret_name: 'mz_env_5_db_root_password_v1' },
      ],
      mounts: [],
      env: {},
    };

    expect(pickSecretName(spec, 'db_root_password')).toBe('mz_env_5_db_root_password_v1');
    expect(pickSecretName(spec, 'missing')).toBeNull();
    expect(pickNetworkName(spec, 'php-fpm')).toBe('mz-backend');
    expect(pickNetworkName(spec, 'missing-alias')).toBe('mz-public');
  });

  it('builds bounded, lowercase swarm job names', () => {
    const name = buildJobName('Promote_DB@Replica', 5);
    expect(name.startsWith('mz-rb-promote-db-replica-5-')).toBe(true);
    expect(name).toMatch(/^[a-z0-9-]+$/);
    expect(name.length).toBeLessThanOrEqual(63);
  });
});
