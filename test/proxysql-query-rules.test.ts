import { describe, expect, it } from 'vitest';
import { buildProxySqlQueryRulesSql } from '../src/lib/proxysql.js';

describe('ProxySQL query rules SQL builder', () => {
  it('manages the expected rule ids and persists to runtime+disk', () => {
    const sql = buildProxySqlQueryRulesSql();
    expect(sql).toContain('DELETE FROM mysql_query_rules WHERE rule_id IN (1, 2, 3, 4, 5);');
    expect(sql).toContain('LOAD MYSQL QUERY RULES TO RUNTIME;');
    expect(sql).toContain('SAVE MYSQL QUERY RULES TO DISK;');
  });

  it('routes search_tmp_ traffic to writer before catch-all SELECT reader rule', () => {
    const sql = buildProxySqlQueryRulesSql();
    expect(sql).toContain("VALUES (4, 1, 'search_tmp_', 10, 1, 0, NULL, 'CASELESS');");
    expect(sql).toContain("VALUES (5, 1, '^SELECT', 20, 1, 0, NULL, 'CASELESS');");
    expect(sql.indexOf("'search_tmp_'")).toBeGreaterThan(-1);
    expect(sql.indexOf("'^SELECT'")).toBeGreaterThan(-1);
    expect(sql.indexOf("'search_tmp_'")).toBeLessThan(sql.indexOf("'^SELECT'"));
  });

  it('keeps transaction-start and transaction-end routes pinned to writer', () => {
    const sql = buildProxySqlQueryRulesSql();
    expect(sql).toContain("VALUES (1, 1, '^(BEGIN|START TRANSACTION|SET\\s+AUTOCOMMIT\\s*=\\s*0)', 10, 1, 0, 1, 'CASELESS');");
    expect(sql).toContain("VALUES (2, 1, '^(COMMIT|ROLLBACK)', 10, 1, 0, 0, 'CASELESS');");
  });
});
