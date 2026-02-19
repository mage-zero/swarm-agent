import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const {
  resolveAggressivePruneCutoffSeconds,
  getHistoryLastSuccessfulDeployAt,
  getQueueSourceDirs,
} = __testing;

describe('aggressive prune cutoff policy', () => {
  it('uses previous successful deploy timestamp minus 24h by default', () => {
    const previousSuccessAt = '2026-02-19T14:30:00.000Z';
    const nowMs = Date.parse('2026-02-20T14:30:00.000Z');
    const cutoff = resolveAggressivePruneCutoffSeconds(previousSuccessAt, nowMs);
    expect(cutoff).toBe(Math.floor(Date.parse('2026-02-18T14:30:00.000Z') / 1000));
  });

  it('supports configurable lookback hours', () => {
    const previousSuccessAt = '2026-02-19T14:30:00.000Z';
    const nowMs = Date.parse('2026-02-20T14:30:00.000Z');
    const cutoff = resolveAggressivePruneCutoffSeconds(previousSuccessAt, nowMs, 36);
    expect(cutoff).toBe(Math.floor(Date.parse('2026-02-18T02:30:00.000Z') / 1000));
  });

  it('returns null when previous success is missing or invalid', () => {
    expect(resolveAggressivePruneCutoffSeconds(null, Date.now())).toBeNull();
    expect(resolveAggressivePruneCutoffSeconds('', Date.now())).toBeNull();
    expect(resolveAggressivePruneCutoffSeconds('not-a-date', Date.now())).toBeNull();
  });

  it('returns null when cutoff would be in the future', () => {
    const previousSuccessAt = '2026-02-22T15:00:00.000Z';
    const nowMs = Date.parse('2026-02-20T14:30:00.000Z');
    expect(resolveAggressivePruneCutoffSeconds(previousSuccessAt, nowMs)).toBeNull();
  });
});

describe('history success timestamp lookup', () => {
  it('returns last_success_at when present and valid', () => {
    const history = {
      'env:15:zynqa/datapowertools': {
        artifacts: ['builds/zynqa/datapowertools/build-a.tar.zst'],
        imageTags: ['env-15-abcd1234'],
        last_success_at: '2026-02-19T14:30:00.000Z',
      },
    };
    expect(getHistoryLastSuccessfulDeployAt(history, 'env:15:zynqa/datapowertools')).toBe('2026-02-19T14:30:00.000Z');
  });

  it('returns null for missing or invalid entries', () => {
    const history = {
      'env:15:zynqa/datapowertools': {
        artifacts: [],
        imageTags: [],
        last_success_at: 'invalid',
      },
    };
    expect(getHistoryLastSuccessfulDeployAt(history, 'env:15:zynqa/datapowertools')).toBeNull();
    expect(getHistoryLastSuccessfulDeployAt(history, 'env:99:missing')).toBeNull();
  });
});

describe('deploy queue source directory policy', () => {
  it('prefers stateful queued dir and keeps legacy root as fallback', () => {
    const dirs = getQueueSourceDirs('/opt/mage-zero/deployments/queued', '/opt/mage-zero/deployments');
    expect(dirs).toEqual(['/opt/mage-zero/deployments/queued', '/opt/mage-zero/deployments']);
  });

  it('deduplicates when queued and queue root resolve to the same directory', () => {
    const dirs = getQueueSourceDirs('/opt/mage-zero/deployments', '/opt/mage-zero/deployments');
    expect(dirs).toEqual(['/opt/mage-zero/deployments']);
  });
});
