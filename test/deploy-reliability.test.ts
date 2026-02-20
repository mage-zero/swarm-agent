import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  classifyDeployError,
  shouldPruneBeforeBuild,
  buildDiskCheckResult,
  resolveRetryPolicy,
  buildRetryRecord,
  shouldDeduplicateDeploy,
  resolveAutoHealConfig,
  resolveAutoHealTargets,
  isDockerServiceId,
  enrichCommandError,
} from '../src/deploy-reliability.js';

// ---------------------------------------------------------------------------
// Phase 0: Smoke test — validates module imports work
// ---------------------------------------------------------------------------

describe('deploy-reliability module', () => {
  it('exports all expected functions', () => {
    expect(typeof classifyDeployError).toBe('function');
    expect(typeof shouldPruneBeforeBuild).toBe('function');
    expect(typeof buildDiskCheckResult).toBe('function');
    expect(typeof resolveRetryPolicy).toBe('function');
    expect(typeof buildRetryRecord).toBe('function');
    expect(typeof shouldDeduplicateDeploy).toBe('function');
    expect(typeof resolveAutoHealConfig).toBe('function');
    expect(typeof resolveAutoHealTargets).toBe('function');
    expect(typeof isDockerServiceId).toBe('function');
    expect(typeof enrichCommandError).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// Phase 1: Error Classification
// ---------------------------------------------------------------------------

describe('classifyDeployError', () => {
  // -- disk_pressure (transient, retryable) --
  it('classifies "no space left on device" as disk_pressure', () => {
    const result = classifyDeployError('write /var/lib/docker/tmp/...: no space left on device', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'disk_pressure', retryable: true });
  });

  it('classifies ENOSPC errors as disk_pressure', () => {
    const result = classifyDeployError('ENOSPC: no space left on device, write', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'disk_pressure', retryable: true });
  });

  it('classifies "Disk quota exceeded" as disk_pressure', () => {
    const result = classifyDeployError('Error: Disk quota exceeded', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'disk_pressure', retryable: true });
  });

  // -- build_oom (transient, retryable) --
  it('classifies OOM killed as build_oom', () => {
    const result = classifyDeployError('error: process was killed (OOMKilled)', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'build_oom', retryable: true });
  });

  it('classifies "signal: killed" as build_oom', () => {
    const result = classifyDeployError('runc run failed: signal: killed', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'build_oom', retryable: true });
  });

  // -- build_manifest (permanent, not retryable) --
  it('classifies "manifest unknown" as build_manifest', () => {
    const result = classifyDeployError('manifest unknown: manifest unknown to registry', 'build');
    expect(result).toEqual({ kind: 'permanent', category: 'build_manifest', retryable: false });
  });

  it('classifies "not found" manifest as build_manifest', () => {
    const result = classifyDeployError('failed to resolve source image mz-magento:abc123: not found', 'build');
    expect(result).toEqual({ kind: 'permanent', category: 'build_manifest', retryable: false });
  });

  // -- container_startup (transient, retryable) --
  it('classifies smoke check failures as container_startup', () => {
    const result = classifyDeployError(
      'nginx.mz-healthz expected 200 got 502; varnish.mz-healthz expected 200 got 503',
      'smoke_check',
    );
    expect(result).toEqual({ kind: 'transient', category: 'container_startup', retryable: true });
  });

  it('classifies container start timeout as container_startup', () => {
    const result = classifyDeployError('timed out waiting for container to become ready', 'deploy');
    expect(result).toEqual({ kind: 'transient', category: 'container_startup', retryable: true });
  });

  // -- network_timeout (transient, retryable) --
  it('classifies fetch timeout as network_timeout', () => {
    const result = classifyDeployError('fetch failed: connect ETIMEDOUT 1.2.3.4:443', 'artifact_download');
    expect(result).toEqual({ kind: 'transient', category: 'network_timeout', retryable: true });
  });

  it('classifies ECONNRESET as network_timeout', () => {
    const result = classifyDeployError('request to https://r2.example.com failed: ECONNRESET', 'artifact_download');
    expect(result).toEqual({ kind: 'transient', category: 'network_timeout', retryable: true });
  });

  it('classifies ECONNREFUSED as network_timeout', () => {
    const result = classifyDeployError('connect ECONNREFUSED 127.0.0.1:5000', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'network_timeout', retryable: true });
  });

  // -- magento_cli_lock (transient, retryable) --
  it('classifies "Another process is running" as magento_cli_lock', () => {
    const result = classifyDeployError(
      'Another process is running. Please try again later.',
      'magento_cli',
    );
    expect(result).toEqual({ kind: 'transient', category: 'magento_cli_lock', retryable: true });
  });

  // -- magento_cli_schema (permanent, not retryable) --
  it('classifies "Column already exists" as magento_cli_schema', () => {
    const result = classifyDeployError(
      'SQLSTATE[42S21]: Column already exists: 1060 Duplicate column name \'is_active\'',
      'magento_cli',
    );
    expect(result).toEqual({ kind: 'permanent', category: 'magento_cli_schema', retryable: false });
  });

  it('classifies "Table already exists" as magento_cli_schema', () => {
    const result = classifyDeployError(
      'SQLSTATE[42S01]: Base table or view already exists: 1050 Table \'catalog_product_entity\' already exists',
      'magento_cli',
    );
    expect(result).toEqual({ kind: 'permanent', category: 'magento_cli_schema', retryable: false });
  });

  it('classifies "Unique constraint violation" as magento_cli_schema', () => {
    const result = classifyDeployError(
      'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry',
      'magento_cli',
    );
    expect(result).toEqual({ kind: 'permanent', category: 'magento_cli_schema', retryable: false });
  });

  // -- config_error (permanent, not retryable) --
  it('classifies invalid configuration as config_error', () => {
    const result = classifyDeployError(
      'Invalid configuration value: MAGE_MODE must be "production" or "developer"',
      'magento_cli',
    );
    expect(result).toEqual({ kind: 'permanent', category: 'config_error', retryable: false });
  });

  it('classifies missing env.php as config_error', () => {
    const result = classifyDeployError(
      'Configuration file does not exist: /var/www/html/magento/app/etc/env.php',
      'magento_cli',
    );
    expect(result).toEqual({ kind: 'permanent', category: 'config_error', retryable: false });
  });

  // -- unknown (transient, retryable — conservative default) --
  it('classifies unrecognised errors as unknown/transient', () => {
    const result = classifyDeployError('something totally unexpected happened', 'deploy');
    expect(result).toEqual({ kind: 'transient', category: 'unknown', retryable: true });
  });

  // -- edge cases --
  it('handles empty error string', () => {
    const result = classifyDeployError('', 'deploy');
    expect(result).toEqual({ kind: 'transient', category: 'unknown', retryable: true });
  });

  it('is case-insensitive', () => {
    const result = classifyDeployError('NO SPACE LEFT ON DEVICE', 'build');
    expect(result).toEqual({ kind: 'transient', category: 'disk_pressure', retryable: true });
  });

  // -- real multi-line production errors --
  it('classifies disk pressure in multi-line buildx output', () => {
    const error = [
      'ERROR: failed to solve: error from receiver: write /var/lib/docker/tmp/buildkit-mount123/usr/share/nginx/html/pub/static/frontend/Magento/luma/en_US/css/styles-l.css:',
      'no space left on device',
    ].join('\n');
    const result = classifyDeployError(error, 'build');
    expect(result.category).toBe('disk_pressure');
    expect(result.retryable).toBe(true);
  });

  it('classifies cohort rollback timeout as container_startup', () => {
    const result = classifyDeployError(
      'timed out waiting for container mz-env-5_php-fpm.1 to become ready after 180s',
      'release_cohort',
    );
    expect(result.category).toBe('container_startup');
    expect(result.retryable).toBe(true);
  });

  it('classifies deadlock error as magento_cli_schema', () => {
    const result = classifyDeployError(
      'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry \'catalog_product_entity-entity_id\' for key \'PRIMARY\'',
      'magento_cli',
    );
    expect(result.category).toBe('magento_cli_schema');
    expect(result.retryable).toBe(false);
  });

  it('classifies registry connection refused during push as network', () => {
    const result = classifyDeployError(
      'error pushing image: push to 127.0.0.1:5000 failed: connect ECONNREFUSED 127.0.0.1:5000',
      'build',
    );
    expect(result.category).toBe('network_timeout');
    expect(result.retryable).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Phase 2: Disk Check
// ---------------------------------------------------------------------------

describe('shouldPruneBeforeBuild', () => {
  it('returns true when usage exceeds threshold', () => {
    expect(shouldPruneBeforeBuild(85, 80)).toBe(true);
  });

  it('returns true when usage equals threshold', () => {
    expect(shouldPruneBeforeBuild(80, 80)).toBe(true);
  });

  it('returns false when usage is below threshold', () => {
    expect(shouldPruneBeforeBuild(75, 80)).toBe(false);
  });

  it('returns true when disk is 100% full', () => {
    expect(shouldPruneBeforeBuild(100, 80)).toBe(true);
  });

  it('returns false when disk is empty', () => {
    expect(shouldPruneBeforeBuild(0, 80)).toBe(false);
  });
});

describe('buildDiskCheckResult', () => {
  it('allows proceed when usage is below threshold', () => {
    const result = buildDiskCheckResult(70, 80, false);
    expect(result.canProceed).toBe(true);
  });

  it('allows proceed when usage was above threshold but prune succeeded', () => {
    const result = buildDiskCheckResult(85, 80, true);
    expect(result.canProceed).toBe(true);
  });

  it('blocks proceed when usage is above threshold and prune failed', () => {
    const result = buildDiskCheckResult(90, 80, false);
    expect(result.canProceed).toBe(false);
    expect(result.reason).toMatch(/disk/i);
  });

  it('includes usage info in reason when blocking', () => {
    const result = buildDiskCheckResult(92, 80, false);
    expect(result.canProceed).toBe(false);
    expect(result.reason).toContain('92');
  });
});

// ---------------------------------------------------------------------------
// Phase 3: Retry Policy + Deduplication
// ---------------------------------------------------------------------------

describe('resolveRetryPolicy', () => {
  const transient = { kind: 'transient' as const, category: 'disk_pressure' as const, retryable: true };
  const permanent = { kind: 'permanent' as const, category: 'magento_cli_schema' as const, retryable: false };

  it('retries transient error on first attempt', () => {
    const result = resolveRetryPolicy(transient, 1, 2);
    expect(result.shouldRetry).toBe(true);
    expect(result.delayMs).toBeGreaterThan(0);
  });

  it('does not retry when attempts exhausted', () => {
    const result = resolveRetryPolicy(transient, 2, 2);
    expect(result.shouldRetry).toBe(false);
    expect(result.reason).toMatch(/exhausted|max/i);
  });

  it('does not retry permanent errors', () => {
    const result = resolveRetryPolicy(permanent, 1, 2);
    expect(result.shouldRetry).toBe(false);
    expect(result.reason).toMatch(/permanent|not retryable/i);
  });

  it('uses exponential backoff delay', () => {
    const r1 = resolveRetryPolicy(transient, 1, 3);
    const r2 = resolveRetryPolicy(transient, 2, 3);
    expect(r2.delayMs).toBeGreaterThan(r1.delayMs);
  });

  it('applies base delay of 30s on first retry', () => {
    const result = resolveRetryPolicy(transient, 1, 2);
    expect(result.delayMs).toBe(30000);
  });

  it('doubles delay on second retry', () => {
    const result = resolveRetryPolicy(transient, 2, 3);
    expect(result.delayMs).toBe(60000);
  });

  it('includes reason when retrying', () => {
    const result = resolveRetryPolicy(transient, 1, 2);
    expect(result.reason).toBeTruthy();
  });

  it('does not retry when maxRetries is 0', () => {
    const result = resolveRetryPolicy(transient, 1, 0);
    expect(result.shouldRetry).toBe(false);
  });

  it('does not retry permanent error even on first attempt with high max', () => {
    const result = resolveRetryPolicy(permanent, 1, 10);
    expect(result.shouldRetry).toBe(false);
  });
});

describe('buildRetryRecord', () => {
  it('creates a record with all fields', () => {
    const record = buildRetryRecord('deploy-123', 'artifact-abc', 1, 'some error');
    expect(record.deployId).toBe('deploy-123');
    expect(record.artifact).toBe('artifact-abc');
    expect(record.attempt).toBe(1);
    expect(record.error).toBe('some error');
    expect(record.timestamp).toBeGreaterThan(0);
  });

  it('uses current time for timestamp', () => {
    const before = Date.now();
    const record = buildRetryRecord('id', 'art', 1, 'err');
    const after = Date.now();
    expect(record.timestamp).toBeGreaterThanOrEqual(before);
    expect(record.timestamp).toBeLessThanOrEqual(after);
  });
});

describe('shouldDeduplicateDeploy', () => {
  const now = Date.now();
  const windowMs = 30 * 60 * 1000; // 30 min

  it('deduplicates when same artifact has 3+ failures in window', () => {
    const failures = [
      { deployId: 'a', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 10000 },
      { deployId: 'b', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 5000 },
      { deployId: 'c', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 1000 },
    ];
    expect(shouldDeduplicateDeploy('art-1', failures, windowMs)).toBe(true);
  });

  it('allows retry when same artifact has < 3 failures in window', () => {
    const failures = [
      { deployId: 'a', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 10000 },
    ];
    expect(shouldDeduplicateDeploy('art-1', failures, windowMs)).toBe(false);
  });

  it('ignores failures outside the window', () => {
    const failures = [
      { deployId: 'a', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - windowMs - 10000 },
      { deployId: 'b', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - windowMs - 5000 },
      { deployId: 'c', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - windowMs - 1000 },
    ];
    expect(shouldDeduplicateDeploy('art-1', failures, windowMs)).toBe(false);
  });

  it('ignores failures for different artifacts', () => {
    const failures = [
      { deployId: 'a', artifact: 'art-2', attempt: 1, error: 'err', timestamp: now - 10000 },
      { deployId: 'b', artifact: 'art-2', attempt: 1, error: 'err', timestamp: now - 5000 },
      { deployId: 'c', artifact: 'art-2', attempt: 1, error: 'err', timestamp: now - 1000 },
    ];
    expect(shouldDeduplicateDeploy('art-1', failures, windowMs)).toBe(false);
  });

  it('returns false for empty failure list', () => {
    expect(shouldDeduplicateDeploy('art-1', [], windowMs)).toBe(false);
  });

  it('does not deduplicate with exactly 2 failures (below threshold)', () => {
    const failures = [
      { deployId: 'a', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 10000 },
      { deployId: 'b', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 5000 },
    ];
    expect(shouldDeduplicateDeploy('art-1', failures, windowMs)).toBe(false);
  });

  it('deduplicates with mixed artifacts when target has 3+ failures', () => {
    const failures = [
      { deployId: 'a', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 10000 },
      { deployId: 'b', artifact: 'art-2', attempt: 1, error: 'err', timestamp: now - 8000 },
      { deployId: 'c', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 5000 },
      { deployId: 'd', artifact: 'art-2', attempt: 1, error: 'err', timestamp: now - 3000 },
      { deployId: 'e', artifact: 'art-1', attempt: 1, error: 'err', timestamp: now - 1000 },
    ];
    expect(shouldDeduplicateDeploy('art-1', failures, windowMs)).toBe(true);
    expect(shouldDeduplicateDeploy('art-2', failures, windowMs)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Phase 4: Stack templates — failure_action must be "pause"
// ---------------------------------------------------------------------------

describe('stack templates failure_action', () => {
  const stackDir = path.resolve(__dirname, '../../cloud-swarm/stacks');
  const stackDirExists = fs.existsSync(stackDir);
  const stackFiles = [
    'base.yml',
    'magento-app.yml',
    'magento-services.yml',
    'magento.yml',
    'monitoring-base.yml',
  ];

  for (const file of stackFiles) {
    it.skipIf(!stackDirExists)(`${file} uses failure_action: pause (not rollback)`, () => {
      const content = fs.readFileSync(path.join(stackDir, file), 'utf8');
      const rollbackMatches = content.match(/failure_action:\s*rollback/g);
      const pauseMatches = content.match(/failure_action:\s*pause/g);
      expect(rollbackMatches).toBeNull();
      expect(pauseMatches).not.toBeNull();
    });
  }
});

// ---------------------------------------------------------------------------
// Phase 5: Auto-Heal Configuration
// ---------------------------------------------------------------------------

describe('resolveAutoHealConfig', () => {
  it('returns defaults when no env vars set', () => {
    const config = resolveAutoHealConfig({});
    expect(config.enabled).toBe(true);
    expect(config.rounds).toBe(3);
    expect(config.delayMs).toBe(10000);
    expect(config.autoRollback).toBe(false);
  });

  it('respects MZ_DEPLOY_SMOKE_AUTO_HEAL_ENABLED=0', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_ENABLED: '0' });
    expect(config.enabled).toBe(false);
  });

  it('respects explicit rounds override', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_ROUNDS: '5' });
    expect(config.rounds).toBe(5);
  });

  it('respects explicit delay override', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_DELAY_MS: '15000' });
    expect(config.delayMs).toBe(15000);
  });

  it('respects auto rollback enabled', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_ROLLBACK_ENABLED: '1' });
    expect(config.autoRollback).toBe(true);
  });

  it('clamps rounds to 0 minimum', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_ROUNDS: '-1' });
    expect(config.rounds).toBe(0);
  });

  it('falls back to default delay for NaN input', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_DELAY_MS: 'not-a-number' });
    expect(config.delayMs).toBe(10000);
  });

  it('falls back to default delay for negative input', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_DELAY_MS: '-5000' });
    expect(config.delayMs).toBe(10000);
  });

  it('falls back to default delay for zero', () => {
    const config = resolveAutoHealConfig({ MZ_DEPLOY_SMOKE_AUTO_HEAL_DELAY_MS: '0' });
    expect(config.delayMs).toBe(10000);
  });
});

describe('resolveAutoHealTargets', () => {
  it('returns nginx when nginx health check fails', () => {
    const targets = resolveAutoHealTargets(['nginx.mz-healthz']);
    expect(targets).toContain('nginx');
  });

  it('returns varnish when varnish health check fails', () => {
    const targets = resolveAutoHealTargets(['varnish.mz-healthz']);
    expect(targets).toContain('varnish');
  });

  it('returns php-fpm when php health check fails', () => {
    const targets = resolveAutoHealTargets(['nginx.health_check.php']);
    expect(targets).toContain('php-fpm');
  });

  it('returns proxysql when any database-related check fails', () => {
    const targets = resolveAutoHealTargets(['nginx.health_check.php']);
    expect(targets).toContain('proxysql');
  });

  it('returns all frontline services when no checks specified', () => {
    const targets = resolveAutoHealTargets([]);
    expect(targets).toContain('nginx');
    expect(targets).toContain('varnish');
  });

  it('deduplicates targets', () => {
    const targets = resolveAutoHealTargets(['nginx.mz-healthz', 'nginx.health_check.php']);
    const nginxCount = targets.filter((t) => t === 'nginx').length;
    expect(nginxCount).toBe(1);
  });

  it('includes varnish root check', () => {
    const targets = resolveAutoHealTargets(['varnish.root']);
    expect(targets).toContain('varnish');
  });
});

// ---------------------------------------------------------------------------
// Phase 6: Error Enrichment
// ---------------------------------------------------------------------------

describe('isDockerServiceId', () => {
  it('recognises a 25-char lowercase alphanumeric docker ID', () => {
    expect(isDockerServiceId('ypdhdokpsmqr6ttbz9ymb1npx')).toBe(true);
  });

  it('recognises shorter docker IDs (10+ chars)', () => {
    expect(isDockerServiceId('abc123def456')).toBe(true);
  });

  it('rejects normal English words', () => {
    expect(isDockerServiceId('error')).toBe(false);
  });

  it('rejects strings with spaces', () => {
    expect(isDockerServiceId('not a docker id')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isDockerServiceId('')).toBe(false);
  });

  it('rejects strings with special characters', () => {
    expect(isDockerServiceId('abc-123-def')).toBe(false);
  });

  it('rejects strings shorter than 10 chars', () => {
    expect(isDockerServiceId('abc123')).toBe(false);
  });
});

describe('enrichCommandError', () => {
  it('annotates bare docker service ID with context', () => {
    const result = enrichCommandError('ypdhdokpsmqr6ttbz9ymb1npx', 'docker stack deploy');
    expect(result).toContain('docker service ID');
    expect(result).toContain('ypdhdokpsmqr6ttbz9ymb1npx');
    expect(result).toContain('docker service inspect');
  });

  it('leaves descriptive errors unchanged', () => {
    const original = 'error: No such image: mz-magento:abc123';
    const result = enrichCommandError(original, 'docker stack deploy');
    expect(result).toBe(original);
  });

  it('annotates when stderr is just a service ID with whitespace', () => {
    const result = enrichCommandError('  abc123def456ghi  \n', 'docker service update');
    expect(result).toContain('docker service ID');
  });

  it('preserves original error in enriched output', () => {
    const result = enrichCommandError('ypdhdokpsmqr6ttbz9ymb1npx', 'docker stack deploy');
    expect(result).toContain('ypdhdokpsmqr6ttbz9ymb1npx');
  });
});
