import { describe, expect, it } from 'vitest';
import { envServiceName, summarizeServiceTasks } from '../src/swarm.js';

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
});

