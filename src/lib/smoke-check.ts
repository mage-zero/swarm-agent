import { runCommandCaptureWithStatus, delay } from './deploy-exec.js';
import { findLocalContainer } from './docker-service.js';

// ── Types ──────────────────────────────────────────────────────────────

export type HttpProbeResult = {
  url: string;
  status: number;
  ok: boolean;
  detail?: string;
};

export type PostDeploySmokeCheckResult = {
  name: string;
  url: string;
  expected: string;
  status: number;
  ok: boolean;
  detail?: string;
};

// ── Probe functions ────────────────────────────────────────────────────

export async function probeHttpViaBackendNetwork(
  url: string,
  hostHeader: string | undefined,
  timeoutSeconds: number,
): Promise<HttpProbeResult> {
  const args = [
    'run',
    '--rm',
    '--network',
    'mz-backend',
    'curlimages/curl:8.5.0',
    '-sS',
    '-o',
    '/dev/null',
    '-w',
    '%{http_code}',
    '-m',
    String(timeoutSeconds),
  ];
  if (hostHeader) {
    args.push('-H', `Host: ${hostHeader}`);
  }
  args.push(url);

  const result = await runCommandCaptureWithStatus('docker', args);
  const raw = (result.stdout || '').trim();
  const status = Number(raw);
  const stderr = (result.stderr || '').trim();

  if (!Number.isFinite(status)) {
    return {
      url,
      status: 0,
      ok: false,
      detail: stderr || `unexpected curl output: ${raw || '(empty)'}`,
    };
  }

  return {
    url,
    status,
    ok: status >= 200 && status < 400,
    detail: stderr || undefined,
  };
}

export async function probeHttpViaExistingContainer(
  containerId: string,
  url: string,
  hostHeader: string | undefined,
  timeoutSeconds: number,
): Promise<HttpProbeResult> {
  const hostArg = hostHeader ? `-H 'Host: ${hostHeader}' ` : '';
  const cmd = `curl -sS -o /dev/null -w '%{http_code}' -m ${timeoutSeconds} ${hostArg}'${url}'`;
  const result = await runCommandCaptureWithStatus('docker', ['exec', containerId, 'sh', '-c', cmd]);
  const raw = (result.stdout || '').trim();
  const status = Number(raw);
  const stderr = (result.stderr || '').trim();

  if (!Number.isFinite(status)) {
    return {
      url,
      status: 0,
      ok: false,
      detail: stderr || `unexpected curl output: ${raw || '(empty)'}`,
    };
  }

  return {
    url,
    status,
    ok: status >= 200 && status < 400,
    detail: stderr || undefined,
  };
}

// ── Smoke check orchestration ──────────────────────────────────────────

export async function runPostDeploySmokeChecks(
  stackName: string,
  envHostname: string,
  log: (message: string) => void,
) : Promise<{ ok: true; results: PostDeploySmokeCheckResult[] } | { ok: false; results: PostDeploySmokeCheckResult[]; summary: string }> {
  const hostHeader = envHostname.trim() || undefined;
  const checks: Array<{ name: string; url: string; timeoutSeconds: number; expectStatus?: number }> = [
    { name: 'nginx.mz-healthz', url: `http://${stackName}_nginx/mz-healthz`, timeoutSeconds: 10, expectStatus: 200 },
    { name: 'varnish.mz-healthz', url: `http://${stackName}_varnish/mz-healthz`, timeoutSeconds: 10, expectStatus: 200 },
    { name: 'nginx.health_check.php', url: `http://${stackName}_nginx/health_check.php`, timeoutSeconds: 30, expectStatus: 200 },
    // Root path can redirect (302) to https://<hostname>/, so accept any 2xx/3xx.
    { name: 'varnish.root', url: `http://${stackName}_varnish/`, timeoutSeconds: 30 },
  ];

  log('running post-deploy smoke checks');

  // Prefer running probes from an existing container (docker exec) to avoid
  // Docker overlay DNS resolution failures that affect newly-spawned containers.
  let probeContainerId = await findLocalContainer(stackName, 'php-fpm');
  if (probeContainerId) {
    log(`smoke probes will exec into php-fpm container ${probeContainerId.slice(0, 12)}`);
  } else {
    log('no local php-fpm container found; falling back to docker run for probes');
  }

  const deadline = Date.now() + 3 * 60 * 1000;
  let lastSummary = '';
  let lastResults: PostDeploySmokeCheckResult[] = [];

  while (Date.now() < deadline) {
    const results: PostDeploySmokeCheckResult[] = [];
    for (const check of checks) {
      const result = probeContainerId
        ? await probeHttpViaExistingContainer(probeContainerId, check.url, hostHeader, check.timeoutSeconds)
        : await probeHttpViaBackendNetwork(check.url, hostHeader, check.timeoutSeconds);
      const ok = check.expectStatus ? result.status === check.expectStatus : result.ok;
      results.push({
        name: check.name,
        url: check.url,
        expected: check.expectStatus ? String(check.expectStatus) : '2xx/3xx',
        status: result.status,
        ok,
        detail: result.detail,
      });
    }
    lastResults = results;

    const failed = results
      .filter((result) => !result.ok);

    if (!failed.length) {
      log('post-deploy smoke checks passed');
      return { ok: true, results };
    }

    lastSummary = failed
      .map((result) => {
        const detail = result.detail ? ` (${result.detail})` : '';
        return `${result.name} expected ${result.expected} got ${result.status}${detail}`;
      })
      .join('; ');

    log(`post-deploy smoke checks not ready: ${lastSummary}`);
    await delay(5000);
  }

  return { ok: false, results: lastResults, summary: lastSummary || 'unknown error' };
}
