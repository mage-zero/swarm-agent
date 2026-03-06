import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const {
  resolveDbBufferPoolBaselineBytes,
  resolveDirectDatabaseRoute,
} = __testing;

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

describe('deploy-worker DB routing helpers', () => {
  it('routes frontend/admin/cron DB traffic to the direct database service endpoint', () => {
    const route = resolveDirectDatabaseRoute((service: string) => `mz-env-15_${service}`);
    expect(route).toEqual({
      host: 'mz-env-15_database',
      port: '3306',
    });
  });

  it('computes DB buffer pool baseline with 60% target, clamped and rounded to 64MiB', () => {
    expect(resolveDbBufferPoolBaselineBytes(0)).toBe(512 * MIB);
    expect(resolveDbBufferPoolBaselineBytes(2 * GIB)).toBe(1216 * MIB);
    expect(resolveDbBufferPoolBaselineBytes(64 * GIB)).toBe(8 * GIB);
  });
});
