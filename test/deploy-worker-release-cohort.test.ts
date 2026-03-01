import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { filterReleaseCohortServicesForGate, shouldSkipReleaseCohortTaskReadiness } = __testing;

describe('release cohort filtering', () => {
  it('excludes cron services from the pre-upgrade gate', () => {
    expect(filterReleaseCohortServicesForGate([
      'mz-env-15_nginx',
      'mz-env-15_php-fpm',
      'mz-env-15_php-fpm-admin',
      'mz-env-15_cron',
    ])).toEqual([
      'mz-env-15_nginx',
      'mz-env-15_php-fpm',
      'mz-env-15_php-fpm-admin',
    ]);
  });

  it('leaves non-cron services unchanged', () => {
    expect(filterReleaseCohortServicesForGate([
      'mz-env-15_nginx',
      'mz-env-15_php-fpm',
    ])).toEqual([
      'mz-env-15_nginx',
      'mz-env-15_php-fpm',
    ]);
  });

  it('skips task readiness when a cohort service is intentionally scaled to zero on the expected tag', () => {
    expect(shouldSkipReleaseCohortTaskReadiness(0, 'env-15-92d00cc44064', 'env-15-92d00cc44064')).toBe(true);
  });

  it('does not skip task readiness when a zero-replica service has the wrong tag', () => {
    expect(shouldSkipReleaseCohortTaskReadiness(0, 'env-15-oldtag', 'env-15-92d00cc44064')).toBe(false);
  });

  it('does not skip task readiness for active services', () => {
    expect(shouldSkipReleaseCohortTaskReadiness(1, 'env-15-92d00cc44064', 'env-15-92d00cc44064')).toBe(false);
  });
});
