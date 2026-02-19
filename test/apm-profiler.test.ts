import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAGE_PROFILER_CONFIG,
  isEnabledFlag,
  resolveMageProfilerEnv,
} from '../src/lib/apm-profiler.js';

describe('apm-profiler env helpers', () => {
  it('defaults APM enabled flag to true when unset', () => {
    expect(isEnabledFlag(undefined, true)).toBe(true);
  });

  it('parses disabled APM values', () => {
    expect(isEnabledFlag('0', true)).toBe(false);
    expect(isEnabledFlag('false', true)).toBe(false);
    expect(isEnabledFlag('off', true)).toBe(false);
  });

  it('returns explicit MAGE_PROFILER value when provided', () => {
    const explicit = '{"drivers":[{"type":"Custom\\\\Profiler\\\\Driver"}]}';
    expect(resolveMageProfilerEnv(explicit, '0')).toBe(explicit);
  });

  it('returns default profiler payload when apm is enabled and profiler is unset', () => {
    expect(resolveMageProfilerEnv(undefined, '1')).toBe(DEFAULT_MAGE_PROFILER_CONFIG);
    expect(resolveMageProfilerEnv(undefined, undefined)).toBe(DEFAULT_MAGE_PROFILER_CONFIG);
  });

  it('returns empty profiler payload when apm is disabled and profiler is unset', () => {
    expect(resolveMageProfilerEnv(undefined, 'false')).toBe('');
  });
});
