const DEFAULT_PROFILER_DRIVER_TYPE = 'MageZero\\OpensearchObservability\\Profiler\\Driver';
const DEFAULT_APM_SERVER_URL = 'http://mz-monitoring_otel-collector:4318/v1/traces';
const DEFAULT_APM_SERVICE_NAME = 'magento';
const DEFAULT_APM_ENVIRONMENT = 'production';
const DEFAULT_APM_SAMPLE_RATE = 1.0;
const DEFAULT_APM_STACK_TRACE_LIMIT = 1000;
const DEFAULT_APM_TIMEOUT = 10;

export interface MageProfilerDefaults {
  serverUrl?: string;
  serviceName?: string;
  environment?: string;
  transactionSampleRate?: string;
  stackTraceLimit?: string;
  timeout?: string;
}

export const DEFAULT_MAGE_PROFILER_CONFIG = JSON.stringify({
  drivers: [
    {
      type: DEFAULT_PROFILER_DRIVER_TYPE,
      enabled: true,
      serverUrl: DEFAULT_APM_SERVER_URL,
      serviceName: DEFAULT_APM_SERVICE_NAME,
      environment: DEFAULT_APM_ENVIRONMENT,
      transactionSampleRate: DEFAULT_APM_SAMPLE_RATE,
      stackTraceLimit: DEFAULT_APM_STACK_TRACE_LIMIT,
      timeout: DEFAULT_APM_TIMEOUT,
    },
  ],
});

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

export function isEnabledFlag(rawValue: string | undefined, defaultValue: boolean): boolean {
  const normalized = String(rawValue || '').trim().toLowerCase();
  if (!normalized) {
    return defaultValue;
  }
  if (TRUE_VALUES.has(normalized)) {
    return true;
  }
  if (FALSE_VALUES.has(normalized)) {
    return false;
  }
  return defaultValue;
}

export function resolveMageProfilerEnv(
  explicitProfilerValue: string | undefined,
  apmEnabledValue: string | undefined,
  defaults: MageProfilerDefaults = {},
): string {
  if (explicitProfilerValue !== undefined) {
    return explicitProfilerValue;
  }
  if (!isEnabledFlag(apmEnabledValue, true)) {
    return '';
  }

  const sampleRateRaw = Number.parseFloat(defaults.transactionSampleRate || String(DEFAULT_APM_SAMPLE_RATE));
  const sampleRate = Number.isFinite(sampleRateRaw)
    ? Math.min(1, Math.max(0, sampleRateRaw))
    : DEFAULT_APM_SAMPLE_RATE;

  const stackTraceRaw = Number.parseInt(defaults.stackTraceLimit || String(DEFAULT_APM_STACK_TRACE_LIMIT), 10);
  const stackTraceLimit = Number.isFinite(stackTraceRaw) && stackTraceRaw > 0
    ? stackTraceRaw
    : DEFAULT_APM_STACK_TRACE_LIMIT;

  const timeoutRaw = Number.parseInt(defaults.timeout || String(DEFAULT_APM_TIMEOUT), 10);
  const timeout = Number.isFinite(timeoutRaw) && timeoutRaw > 0
    ? timeoutRaw
    : DEFAULT_APM_TIMEOUT;

  const serviceName = (defaults.serviceName || '').trim() || DEFAULT_APM_SERVICE_NAME;
  const environment = (defaults.environment || '').trim() || DEFAULT_APM_ENVIRONMENT;
  const serverUrl = (defaults.serverUrl || '').trim() || DEFAULT_APM_SERVER_URL;

  return JSON.stringify({
    drivers: [
      {
        type: DEFAULT_PROFILER_DRIVER_TYPE,
        enabled: true,
        serverUrl,
        serviceName,
        environment,
        transactionSampleRate: sampleRate,
        stackTraceLimit,
        timeout,
      },
    ],
  });
}
