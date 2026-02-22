export type ProxySqlQueryRuleSpec = {
  rule_id: number;
  active: number;
  match_pattern: string;
  destination_hostgroup: number;
  apply: number;
  flagIN?: number | null;
  flagOUT?: number | null;
  re_modifiers?: string | null;
};

export const PROXYSQL_MANAGED_QUERY_RULES: ProxySqlQueryRuleSpec[] = [
  {
    rule_id: 1,
    active: 1,
    match_pattern: '^(BEGIN|START TRANSACTION|SET\\s+AUTOCOMMIT\\s*=\\s*0)',
    destination_hostgroup: 10,
    apply: 1,
    flagIN: 0,
    flagOUT: 1,
    re_modifiers: 'CASELESS',
  },
  {
    rule_id: 2,
    active: 1,
    match_pattern: '^(COMMIT|ROLLBACK)',
    destination_hostgroup: 10,
    apply: 1,
    flagIN: 0,
    flagOUT: 0,
    re_modifiers: 'CASELESS',
  },
  {
    rule_id: 3,
    active: 1,
    match_pattern: '^SELECT.*FOR UPDATE',
    destination_hostgroup: 10,
    apply: 1,
    flagIN: 0,
    re_modifiers: 'CASELESS',
  },
  {
    rule_id: 4,
    active: 1,
    match_pattern: 'search_tmp_',
    destination_hostgroup: 10,
    apply: 1,
    flagIN: 0,
    re_modifiers: 'CASELESS',
  },
  {
    rule_id: 5,
    active: 1,
    match_pattern: '^SELECT',
    destination_hostgroup: 20,
    apply: 1,
    flagIN: 0,
    re_modifiers: 'CASELESS',
  },
];

function escapeSqlValue(value: string): string {
  return value.replace(/'/g, "''");
}

export function buildProxySqlQueryRulesSql(rules: ProxySqlQueryRuleSpec[] = PROXYSQL_MANAGED_QUERY_RULES): string {
  const managedRuleIds = rules
    .map((rule) => Math.floor(Number(rule.rule_id)))
    .filter((ruleId) => Number.isFinite(ruleId) && ruleId > 0);
  if (!managedRuleIds.length) {
    throw new Error('ProxySQL managed rules are empty');
  }

  const statements: string[] = [
    `DELETE FROM mysql_query_rules WHERE rule_id IN (${managedRuleIds.join(', ')})`,
  ];

  for (const rule of rules) {
    const ruleId = Math.floor(Number(rule.rule_id));
    if (!Number.isFinite(ruleId) || ruleId <= 0) {
      throw new Error(`Invalid ProxySQL rule id: ${rule.rule_id}`);
    }

    const pattern = String(rule.match_pattern || '').trim();
    if (!pattern) {
      throw new Error(`ProxySQL rule ${ruleId} has empty match_pattern`);
    }

    const destinationHostgroup = Math.max(0, Math.floor(Number(rule.destination_hostgroup) || 0));
    const active = Number(rule.active) === 0 ? 0 : 1;
    const apply = Number(rule.apply) === 0 ? 0 : 1;
    const flagIn = Number.isFinite(Number(rule.flagIN)) ? String(Math.floor(Number(rule.flagIN))) : '0';
    const flagOut = Number.isFinite(Number(rule.flagOUT)) ? String(Math.floor(Number(rule.flagOUT))) : 'NULL';
    const reModifiersRaw = String(rule.re_modifiers || '').trim();
    const reModifiers = reModifiersRaw ? `'${escapeSqlValue(reModifiersRaw)}'` : 'NULL';

    statements.push(
      'INSERT INTO mysql_query_rules '
      + '(rule_id, active, match_pattern, destination_hostgroup, apply, flagIN, flagOUT, re_modifiers) '
      + `VALUES (${ruleId}, ${active}, '${escapeSqlValue(pattern)}', ${destinationHostgroup}, ${apply}, ${flagIn}, ${flagOut}, ${reModifiers})`
    );
  }

  statements.push('LOAD MYSQL QUERY RULES TO RUNTIME');
  statements.push('SAVE MYSQL QUERY RULES TO DISK');
  return `${statements.map((statement) => `${statement};`).join('\n')}\n`;
}
