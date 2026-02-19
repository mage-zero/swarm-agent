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

  it('includes a full driver config in the default profiler payload', () => {
    const parsed = JSON.parse(resolveMageProfilerEnv(undefined, '1'));
    expect(parsed).toEqual({
      drivers: [
        {
          type: 'MageZero\\OpensearchObservability\\Profiler\\Driver',
          enabled: true,
          serverUrl: 'http://mz-monitoring_otel-collector:4318/v1/traces',
          serviceName: 'magento',
          environment: 'production',
          transactionSampleRate: 1,
          stackTraceLimit: 1000,
          timeout: 10,
        },
      ],
    });
  });

  it('builds profiler payload from provided APM defaults', () => {
    const parsed = JSON.parse(resolveMageProfilerEnv(undefined, '1', {
      serverUrl: 'http://collector:4318/v1/traces',
      serviceName: 'mz-env-5',
      environment: 'performance',
      transactionSampleRate: '0.75',
      stackTraceLimit: '500',
      timeout: '15',
    }));

    expect(parsed).toEqual({
      drivers: [
        {
          type: 'MageZero\\OpensearchObservability\\Profiler\\Driver',
          enabled: true,
          serverUrl: 'http://collector:4318/v1/traces',
          serviceName: 'mz-env-5',
          environment: 'performance',
          transactionSampleRate: 0.75,
          stackTraceLimit: 500,
          timeout: 15,
        },
      ],
    });
  });

  it('clamps sample rate and falls back invalid numeric defaults', () => {
    const parsed = JSON.parse(resolveMageProfilerEnv(undefined, '1', {
      transactionSampleRate: '2.75',
      stackTraceLimit: '-1',
      timeout: 'nope',
    }));
    const driver = parsed?.drivers?.[0] || {};

    expect(driver.transactionSampleRate).toBe(1);
    expect(driver.stackTraceLimit).toBe(1000);
    expect(driver.timeout).toBe(10);
  });

  it('uses built-in defaults when provided text defaults are blank', () => {
    const parsed = JSON.parse(resolveMageProfilerEnv(undefined, '1', {
      serverUrl: '   ',
      serviceName: '',
      environment: '   ',
      transactionSampleRate: '-0.5',
    }));
    const driver = parsed?.drivers?.[0] || {};

    expect(driver.serverUrl).toBe('http://mz-monitoring_otel-collector:4318/v1/traces');
    expect(driver.serviceName).toBe('magento');
    expect(driver.environment).toBe('production');
    expect(driver.transactionSampleRate).toBe(0);
  });

  it('returns empty profiler payload when apm is disabled and profiler is unset', () => {
    expect(resolveMageProfilerEnv(undefined, 'false')).toBe('');
  });
});
