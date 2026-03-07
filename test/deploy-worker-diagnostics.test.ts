import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const {
  shouldSkipPostDeployTaskReadiness,
  detectFatalMonitoringRuntimeIssue,
  buildSmokeFailureDiagnostics,
} = __testing;

describe('post-deploy verification task readiness', () => {
  it('skips zero-replica services when the expected image tag is already applied', () => {
    expect(
      shouldSkipPostDeployTaskReadiness(
        0,
        'registry.internal:5000/mz-magento:env-15-0b6c71a02134@sha256:deadbeef',
        'env-15-0b6c71a02134',
      ),
    ).toBe(true);
  });

  it('does not skip zero-replica services when the image tag is wrong', () => {
    expect(
      shouldSkipPostDeployTaskReadiness(
        0,
        'registry.internal:5000/mz-magento:env-15-oldtag@sha256:deadbeef',
        'env-15-0b6c71a02134',
      ),
    ).toBe(false);
  });

  it('does not skip active services', () => {
    expect(
      shouldSkipPostDeployTaskReadiness(
        1,
        'registry.internal:5000/mz-magento:env-15-0b6c71a02134@sha256:deadbeef',
        'env-15-0b6c71a02134',
      ),
    ).toBe(false);
  });
});

describe('monitoring runtime fatal detection', () => {
  it('fails fast when a monitoring service has zero desired tasks', () => {
    const summary = detectFatalMonitoringRuntimeIssue([
      {
        serviceName: 'mz-monitoring_opensearch',
        desiredRunning: 0,
        running: 0,
        issues: ['no tasks desired Running'],
      },
      {
        serviceName: 'mz-monitoring_filebeat',
        desiredRunning: 1,
        running: 1,
        issues: [],
      },
    ]);

    expect(summary).toContain('mz-monitoring_opensearch 0/0');
    expect(summary).toContain('no tasks desired Running');
  });

  it('does not fail fast when monitoring services are simply still starting', () => {
    expect(
      detectFatalMonitoringRuntimeIssue([
        {
          serviceName: 'mz-monitoring_opensearch',
          desiredRunning: 1,
          running: 0,
          issues: ['Preparing 5 seconds ago'],
        },
      ]),
    ).toBeNull();
  });
});

describe('smoke failure diagnostics', () => {
  it('highlights isolated PHP probe failures when the frontend is otherwise healthy', () => {
    const diagnostics = buildSmokeFailureDiagnostics(
      [
        { name: 'nginx.mz-healthz', url: 'http://nginx/mz-healthz', expected: '200', status: 200, ok: true },
        { name: 'varnish.mz-healthz', url: 'http://varnish/mz-healthz', expected: '200', status: 200, ok: true },
        { name: 'nginx.health_check.php', url: 'http://nginx/health_check.php', expected: '200', status: 0, ok: false, detail: 'operation timed out' },
        { name: 'varnish.root', url: 'http://varnish/', expected: '2xx/3xx', status: 302, ok: true },
      ],
      {
        'mz-env-15_php-fpm': ['php warning'],
      },
      {},
    );

    expect(diagnostics.hints).toContain(
      'only the deep PHP readiness probe failed while nginx and varnish were already serving traffic; inspect php-fpm application logs',
    );
  });

  it('surfaces image pull failures and setup mismatch hints', () => {
    const diagnostics = buildSmokeFailureDiagnostics(
      [
        { name: 'nginx.mz-healthz', url: 'http://nginx/mz-healthz', expected: '200', status: 0, ok: false, detail: 'operation timed out' },
      ],
      {
        'mz-env-15_varnish': ['worker-1|Rejected 2 seconds ago|No such image: registry.internal:5000/mz-varnish:env-15-0b6c71a02134'],
      },
      {
        setup_upgrade_post_check: { needed: true },
        setup_upgrade_skipped_persistent_mismatch: { needed: true },
      },
    );

    expect(diagnostics.hints).toContain(
      'one or more service tasks were rejected because the image was unavailable in the registry',
    );
    expect(diagnostics.hints).toContain(
      'setup:db:status still reports pending schema/data changes after setup:upgrade',
    );
    expect(diagnostics.hints).toContain(
      'persistent schema/data mismatch was detected before smoke checks',
    );
  });
});
