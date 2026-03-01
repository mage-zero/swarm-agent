import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { filterReleaseCohortServicesForGate } = __testing;

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
});
