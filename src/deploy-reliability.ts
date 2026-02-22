/**
 * deploy-reliability.ts
 *
 * Pure functions for deploy error classification, retry policy, disk checks,
 * auto-heal configuration, and error enrichment.
 *
 * All functions are side-effect-free and fully testable without mocking.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ErrorKind = 'transient' | 'permanent';

export type ErrorCategory =
  | 'disk_pressure'
  | 'container_startup'
  | 'network_timeout'
  | 'magento_cli_lock'
  | 'magento_cli_schema'
  | 'build_oom'
  | 'build_manifest'
  | 'config_error'
  | 'unknown';

export type ErrorClassification = {
  kind: ErrorKind;
  category: ErrorCategory;
  retryable: boolean;
};

export type RetryPolicy = {
  shouldRetry: boolean;
  delayMs: number;
  reason: string;
};

export type RetryRecord = {
  deployId: string;
  artifact: string;
  attempt: number;
  error: string;
  timestamp: number;
};

export type DiskCheckResult = {
  canProceed: boolean;
  reason: string;
};


// ---------------------------------------------------------------------------
// Phase 1: Error Classification
// ---------------------------------------------------------------------------

type ErrorRule = {
  pattern: RegExp;
  category: ErrorCategory;
  kind: ErrorKind;
  retryable: boolean;
};

const ERROR_RULES: ErrorRule[] = [
  // disk_pressure — transient, retryable
  { pattern: /no space left on device/i, category: 'disk_pressure', kind: 'transient', retryable: true },
  { pattern: /\bENOSPC\b/i, category: 'disk_pressure', kind: 'transient', retryable: true },
  { pattern: /disk quota exceeded/i, category: 'disk_pressure', kind: 'transient', retryable: true },

  // build_oom — transient, retryable
  { pattern: /OOMKilled/i, category: 'build_oom', kind: 'transient', retryable: true },
  { pattern: /signal:\s*killed/i, category: 'build_oom', kind: 'transient', retryable: true },

  // build_manifest — permanent, not retryable
  { pattern: /manifest unknown/i, category: 'build_manifest', kind: 'permanent', retryable: false },
  { pattern: /failed to resolve source image.*not found/i, category: 'build_manifest', kind: 'permanent', retryable: false },

  // magento_cli_lock — transient, retryable
  { pattern: /Another process is running/i, category: 'magento_cli_lock', kind: 'transient', retryable: true },

  // magento_cli_schema — permanent, not retryable
  { pattern: /SQLSTATE\[42S21\]/i, category: 'magento_cli_schema', kind: 'permanent', retryable: false },
  { pattern: /SQLSTATE\[42S01\]/i, category: 'magento_cli_schema', kind: 'permanent', retryable: false },
  { pattern: /SQLSTATE\[23000\]/i, category: 'magento_cli_schema', kind: 'permanent', retryable: false },

  // config_error — permanent, not retryable
  { pattern: /invalid configuration/i, category: 'config_error', kind: 'permanent', retryable: false },
  { pattern: /configuration file does not exist/i, category: 'config_error', kind: 'permanent', retryable: false },

  // network_timeout — transient, retryable
  { pattern: /\bETIMEDOUT\b/i, category: 'network_timeout', kind: 'transient', retryable: true },
  { pattern: /\bECONNRESET\b/i, category: 'network_timeout', kind: 'transient', retryable: true },
  { pattern: /\bECONNREFUSED\b/i, category: 'network_timeout', kind: 'transient', retryable: true },

  // container_startup — transient, retryable
  { pattern: /expected \d+ got [45]\d{2}/i, category: 'container_startup', kind: 'transient', retryable: true },
  { pattern: /timed out waiting for container/i, category: 'container_startup', kind: 'transient', retryable: true },
];

export function classifyDeployError(error: string, _stage: string): ErrorClassification {
  for (const rule of ERROR_RULES) {
    if (rule.pattern.test(error)) {
      return { kind: rule.kind, category: rule.category, retryable: rule.retryable };
    }
  }
  return { kind: 'transient', category: 'unknown', retryable: true };
}

// ---------------------------------------------------------------------------
// Phase 2: Disk Check
// ---------------------------------------------------------------------------

export function shouldPruneBeforeBuild(diskUsagePercent: number, thresholdPercent: number): boolean {
  return diskUsagePercent >= thresholdPercent;
}

export function buildDiskCheckResult(
  diskUsagePercent: number,
  thresholdPercent: number,
  pruneSucceeded: boolean,
): DiskCheckResult {
  if (diskUsagePercent < thresholdPercent) {
    return { canProceed: true, reason: '' };
  }
  if (pruneSucceeded) {
    return { canProceed: true, reason: `disk at ${diskUsagePercent}% but prune freed space` };
  }
  return {
    canProceed: false,
    reason: `disk usage ${diskUsagePercent}% exceeds threshold ${thresholdPercent}% and prune did not free enough space`,
  };
}

// ---------------------------------------------------------------------------
// Phase 3: Retry Policy + Deduplication
// ---------------------------------------------------------------------------

const RETRY_BASE_DELAY_MS = 30000;

export function resolveRetryPolicy(
  classification: ErrorClassification,
  attempt: number,
  maxRetries: number,
): RetryPolicy {
  if (!classification.retryable) {
    return { shouldRetry: false, delayMs: 0, reason: `${classification.category} is not retryable (permanent error)` };
  }
  if (attempt >= maxRetries) {
    return { shouldRetry: false, delayMs: 0, reason: `max retries exhausted (${attempt}/${maxRetries})` };
  }
  const delayMs = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
  return {
    shouldRetry: true,
    delayMs,
    reason: `transient ${classification.category} error, attempt ${attempt}/${maxRetries}, retrying in ${delayMs}ms`,
  };
}

export function buildRetryRecord(
  deployId: string,
  artifact: string,
  attempt: number,
  error: string,
): RetryRecord {
  return { deployId, artifact, attempt, error, timestamp: Date.now() };
}

const DEDUP_MIN_FAILURES = 3;

export function shouldDeduplicateDeploy(
  artifact: string,
  recentFailures: RetryRecord[],
  windowMs: number,
): boolean {
  const cutoff = Date.now() - windowMs;
  const matching = recentFailures.filter(
    (r) => r.artifact === artifact && r.timestamp >= cutoff,
  );
  return matching.length >= DEDUP_MIN_FAILURES;
}

// ---------------------------------------------------------------------------
// Phase 6: Error Enrichment
// ---------------------------------------------------------------------------

const DOCKER_ID_PATTERN = /^[a-z0-9]{10,}$/;

export function isDockerServiceId(token: string): boolean {
  return DOCKER_ID_PATTERN.test(token);
}

export function enrichCommandError(stderr: string, command: string): string {
  const trimmed = stderr.trim();
  if (isDockerServiceId(trimmed)) {
    return `${stderr.trim()} (opaque docker service ID — run \`docker service inspect ${trimmed}\` and \`docker service ps ${trimmed}\` for details; command was: ${command})`;
  }
  return stderr;
}
