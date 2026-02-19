export const DEFAULT_MAGE_PROFILER_CONFIG =
  '{"drivers":[{"type":"MageZero\\\\OpensearchObservability\\\\Profiler\\\\Driver"}]}';

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
): string {
  if (explicitProfilerValue !== undefined) {
    return explicitProfilerValue;
  }
  return isEnabledFlag(apmEnabledValue, true) ? DEFAULT_MAGE_PROFILER_CONFIG : '';
}
