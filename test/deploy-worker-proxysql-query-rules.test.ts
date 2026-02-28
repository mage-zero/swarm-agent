import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { buildProxySqlRuleReconcileScript } = __testing;

describe('deploy-worker proxysql rule reconcile script', () => {
  it('tries radmin first and falls back to admin credentials', () => {
    const wrapped = buildProxySqlRuleReconcileScript('mz-env-15_proxysql');
    const encodedMatch = wrapped.match(/printf '%s' '([^']+)' \| base64 -d \| sh/);
    expect(encodedMatch?.[1]).toBeTruthy();

    const decoded = Buffer.from(String(encodedMatch?.[1] || ''), 'base64').toString('utf8');
    expect(decoded).toContain('PROXYSQL_HOST="mz-env-15_proxysql"');
    expect(decoded).toContain('"radmin:radmin" "admin:admin"');
    expect(decoded).toContain('ADMIN_USER=""');
    expect(decoded).toContain('ADMIN_PASS=""');
    expect(decoded).toContain('LOAD MYSQL QUERY RULES TO RUNTIME');
    expect(decoded).toContain('SAVE MYSQL QUERY RULES TO DISK');
  });
});
