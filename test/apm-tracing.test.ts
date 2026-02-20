import { describe, expect, it } from 'vitest';
import {
  DEFAULT_DD_TRACE_AGENT_URL,
  DEFAULT_DD_TRACE_SAMPLE_RATE,
  DEFAULT_DD_SERVICE,
  DEFAULT_DD_ENV,
  isEnabledFlag,
  resolveDatadogTraceEnv,
} from '../src/lib/apm-tracing.js';

describe('apm-tracing env helpers', () => {
  it('defaults APM enabled flag to true when unset', () => {
    expect(isEnabledFlag(undefined, true)).toBe(true);
  });

  it('parses disabled APM values', () => {
    expect(isEnabledFlag('0', true)).toBe(false);
    expect(isEnabledFlag('false', true)).toBe(false);
    expect(isEnabledFlag('off', true)).toBe(false);
  });

  it('builds default Datadog env payload from APM enabled flag', () => {
    expect(resolveDatadogTraceEnv('1')).toEqual({
      DD_TRACE_ENABLED: '1',
      DD_TRACE_AGENT_URL: DEFAULT_DD_TRACE_AGENT_URL,
      DD_SERVICE: DEFAULT_DD_SERVICE,
      DD_ENV: DEFAULT_DD_ENV,
      DD_TRACE_SAMPLE_RATE: DEFAULT_DD_TRACE_SAMPLE_RATE,
      DD_TRACE_AGENT_TIMEOUT: '',
      DD_TRACE_AGENT_CONNECT_TIMEOUT: '',
    });
  });

  it('accepts explicit Datadog defaults', () => {
    expect(resolveDatadogTraceEnv('0', {
      traceEnabled: '1',
      traceAgentUrl: 'http://collector:8126',
      service: 'mz-env-5',
      environment: 'performance',
      sampleRate: '0.75',
      traceAgentTimeout: '500',
      traceAgentConnectTimeout: '250',
    })).toEqual({
      DD_TRACE_ENABLED: '1',
      DD_TRACE_AGENT_URL: 'http://collector:8126',
      DD_SERVICE: 'mz-env-5',
      DD_ENV: 'performance',
      DD_TRACE_SAMPLE_RATE: '0.75',
      DD_TRACE_AGENT_TIMEOUT: '500',
      DD_TRACE_AGENT_CONNECT_TIMEOUT: '250',
    });
  });

  it('clamps sample rate and clears invalid timeout values', () => {
    expect(resolveDatadogTraceEnv('1', {
      sampleRate: '2.75',
      traceAgentTimeout: '-1',
      traceAgentConnectTimeout: 'not-a-number',
    })).toEqual({
      DD_TRACE_ENABLED: '1',
      DD_TRACE_AGENT_URL: DEFAULT_DD_TRACE_AGENT_URL,
      DD_SERVICE: DEFAULT_DD_SERVICE,
      DD_ENV: DEFAULT_DD_ENV,
      DD_TRACE_SAMPLE_RATE: '1',
      DD_TRACE_AGENT_TIMEOUT: '',
      DD_TRACE_AGENT_CONNECT_TIMEOUT: '',
    });
  });

  it('uses APM flag as fallback for DD_TRACE_ENABLED when explicit flag is blank', () => {
    expect(resolveDatadogTraceEnv('false', { traceEnabled: '   ' }).DD_TRACE_ENABLED).toBe('0');
    expect(resolveDatadogTraceEnv(undefined, { traceEnabled: '' }).DD_TRACE_ENABLED).toBe('1');
  });

  it('normalizes negative sample rate to zero', () => {
    expect(resolveDatadogTraceEnv('1', { sampleRate: '-0.5' }).DD_TRACE_SAMPLE_RATE).toBe('0');
  });
});
