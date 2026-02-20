export const DEFAULT_DD_TRACE_AGENT_URL = 'http://mz-monitoring_otel-collector:8126';
export const DEFAULT_DD_SERVICE = 'magento';
export const DEFAULT_DD_ENV = 'production';
export const DEFAULT_DD_TRACE_SAMPLE_RATE = '1.0';

export interface DatadogTraceDefaults {
  traceEnabled?: string;
  traceAgentUrl?: string;
  service?: string;
  environment?: string;
  sampleRate?: string;
  traceAgentTimeout?: string;
  traceAgentConnectTimeout?: string;
}

export interface DatadogTraceEnv {
  DD_TRACE_ENABLED: string;
  DD_TRACE_AGENT_URL: string;
  DD_SERVICE: string;
  DD_ENV: string;
  DD_TRACE_SAMPLE_RATE: string;
  DD_TRACE_AGENT_TIMEOUT: string;
  DD_TRACE_AGENT_CONNECT_TIMEOUT: string;
}

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

export function resolveDatadogTraceEnv(
  apmEnabledValue: string | undefined,
  defaults: DatadogTraceDefaults = {},
): DatadogTraceEnv {
  const explicitTraceEnabled = normalizeString(defaults.traceEnabled);
  const resolvedTraceEnabled = explicitTraceEnabled !== ''
    ? (isEnabledFlag(explicitTraceEnabled, true) ? '1' : '0')
    : (isEnabledFlag(apmEnabledValue, true) ? '1' : '0');

  return {
    DD_TRACE_ENABLED: resolvedTraceEnabled,
    DD_TRACE_AGENT_URL: normalizeString(defaults.traceAgentUrl) || DEFAULT_DD_TRACE_AGENT_URL,
    DD_SERVICE: normalizeString(defaults.service) || DEFAULT_DD_SERVICE,
    DD_ENV: normalizeString(defaults.environment) || DEFAULT_DD_ENV,
    DD_TRACE_SAMPLE_RATE: normalizeSampleRate(defaults.sampleRate),
    DD_TRACE_AGENT_TIMEOUT: normalizePositiveIntString(defaults.traceAgentTimeout),
    DD_TRACE_AGENT_CONNECT_TIMEOUT: normalizePositiveIntString(defaults.traceAgentConnectTimeout),
  };
}

function normalizeString(value: string | undefined): string {
  return String(value || '').trim();
}

function normalizeSampleRate(value: string | undefined): string {
  const raw = normalizeString(value);
  if (raw === '') {
    return DEFAULT_DD_TRACE_SAMPLE_RATE;
  }

  const parsed = Number.parseFloat(raw);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_DD_TRACE_SAMPLE_RATE;
  }

  return String(Math.max(0, Math.min(1, parsed)));
}

function normalizePositiveIntString(value: string | undefined): string {
  const raw = normalizeString(value);
  if (raw === '') {
    return '';
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return '';
  }

  return String(parsed);
}
