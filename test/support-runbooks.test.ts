import { describe, expect, it } from 'vitest';
import { __testing, listRunbooks } from '../src/support-runbooks.js';

describe('support-runbooks helpers', () => {
  it('parses slave status output', () => {
    const raw = `
      Master_Host: database
      Slave_IO_Running: Yes
      Slave_SQL_Running: No
      Seconds_Behind_Master: NULL
    `;
    const parsed = __testing.parseSlaveStatus(raw);
    expect(parsed).not.toBeNull();
    expect(parsed?.Master_Host).toBe('database');
    expect(parsed?.Slave_IO_Running).toBe('Yes');
    expect(parsed?.Slave_SQL_Running).toBe('No');
    expect(parsed?.Seconds_Behind_Master).toBe('NULL');
  });

  it('parses db replication probe logs', () => {
    const logs = [
      'PRIMARY_READ_ONLY=0',
      'REPLICA_READ_ONLY=1',
      'PRIMARY_GTID_BINLOG_POS=0-1-10253',
      'PRIMARY_GTID_CURRENT_POS=0-1-10253',
      'REPLICA_GTID_SLAVE_POS=',
      'REPLICA_GTID_CURRENT_POS=0-2-3',
      'PRIMARY_MAGENTO_TABLES=123',
      'REPLICA_MAGENTO_TABLES=0',
      'PRIMARY_SLAVE_STATUS_BEGIN',
      'PRIMARY_SLAVE_STATUS_END',
      'REPLICA_SLAVE_STATUS_BEGIN',
      '                   Master_Host: database',
      '              Slave_IO_Running: Yes',
      '             Slave_SQL_Running: No',
      '         Seconds_Behind_Master: NULL',
      '                Last_SQL_Errno: 1950',
      '                Last_SQL_Error: out-of-order sequence number',
      'REPLICA_SLAVE_STATUS_END',
    ].join('\n');

    const parsed = __testing.parseDbReplicationProbe(logs);
    expect(parsed).not.toBeNull();
    expect(parsed?.primary.read_only).toBe(false);
    expect(parsed?.primary.gtid_binlog_pos).toBe('0-1-10253');
    expect(parsed?.primary.gtid_current_pos).toBe('0-1-10253');
    expect(parsed?.primary.magento_table_count).toBe(123);
    expect(parsed?.primary.slave_status).toBeNull();

    expect(parsed?.replica.read_only).toBe(true);
    expect(parsed?.replica.gtid_slave_pos).toBeNull();
    expect(parsed?.replica.gtid_current_pos).toBe('0-2-3');
    expect(parsed?.replica.magento_table_count).toBe(0);
    expect(parsed?.replica.slave_status?.Master_Host).toBe('database');
    expect(parsed?.replica.slave_status?.Slave_IO_Running).toBe('Yes');
    expect(parsed?.replica.slave_status?.Last_SQL_Errno).toBe('1950');
  });

  it('parses proxysql hostgroup rows', () => {
    const raw = [
      '10 mz-env-5_database ONLINE',
      '20 mz-env-5_database-replica OFFLINE_SOFT',
    ].join('\n');
    const rows = __testing.parseProxySqlHostgroups(raw);
    expect(rows).toEqual([
      { hostgroup: 10, hostname: 'mz-env-5_database', status: 'ONLINE' },
      { hostgroup: 20, hostname: 'mz-env-5_database-replica', status: 'OFFLINE_SOFT' },
    ]);
  });

  it('returns null for empty or malformed slave status blocks', () => {
    expect(__testing.parseSlaveStatus('')).toBeNull();
    expect(__testing.parseSlaveStatus('no-colon-here')).toBeNull();
  });

  it('handles partial probe logs and coerces invalid values to null', () => {
    const probe = __testing.parseDbReplicationProbe([
      'PRIMARY_READ_ONLY=2',
      'REPLICA_READ_ONLY=not-a-bool',
      'PRIMARY_MAGENTO_TABLES=NaN',
      'REPLICA_MAGENTO_TABLES=abc',
      'PRIMARY_SLAVE_STATUS_BEGIN',
      'PRIMARY_SLAVE_STATUS_END',
      'REPLICA_SLAVE_STATUS_BEGIN',
      'Master_Host: database',
      'REPLICA_SLAVE_STATUS_END',
    ].join('\n'));
    expect(probe).not.toBeNull();
    expect(probe?.primary.read_only).toBeNull();
    expect(probe?.replica.read_only).toBeNull();
    expect(probe?.primary.magento_table_count).toBeNull();
    expect(probe?.replica.magento_table_count).toBeNull();
    expect(probe?.replica.slave_status?.Master_Host).toBe('database');
  });

  it('builds db probe script with expected env-scoped hosts and markers', () => {
    const script = __testing.buildDbProbeScript(5);
    expect(script).toContain('primary="mz-env-5_database"');
    expect(script).toContain('replica="mz-env-5_database-replica"');
    expect(script).toContain('PRIMARY_SLAVE_STATUS_BEGIN');
    expect(script).toContain('REPLICA_SLAVE_STATUS_END');
    expect(script).toContain('SHOW SLAVE STATUS');
  });

  it('filters malformed proxysql rows and keeps valid ones', () => {
    const rows = __testing.parseProxySqlHostgroups([
      '0 invalid ONLINE',
      'abc mz-env-5_database ONLINE',
      '10 mz-env-5_database ONLINE',
      '20',
      '30 mz-env-5_database-replica OFFLINE_SOFT',
    ].join('\n'));

    expect(rows).toEqual([
      { hostgroup: 10, hostname: 'mz-env-5_database', status: 'ONLINE' },
      { hostgroup: 30, hostname: 'mz-env-5_database-replica', status: 'OFFLINE_SOFT' },
    ]);
  });

  it('registers deploy_retry_latest runbook as remediation', async () => {
    const runbooks = await listRunbooks();
    const retry = runbooks.find((entry) => entry.id === 'deploy_retry_latest');
    expect(retry).toBeTruthy();
    expect(retry?.safe).toBe(false);
    expect(retry?.supports_remediation).toBe(true);
  });

  it('selects latest deployment state by timestamp', () => {
    const latest = __testing.pickLatestDeploymentState([
      { state: 'failed', deploymentId: 'a', atMs: 1000, atIso: '2024-01-01T00:00:01Z', record: {}, sourcePath: '/tmp/a.json' },
      { state: 'processing', deploymentId: 'b', atMs: 2000, atIso: '2024-01-01T00:00:02Z', record: {}, sourcePath: '/tmp/b.json' },
      { state: 'queued', deploymentId: 'c', atMs: 1500, atIso: '2024-01-01T00:00:01.500Z', record: {}, sourcePath: '/tmp/c.json' },
    ]);
    expect(latest?.state).toBe('processing');
    expect(latest?.deploymentId).toBe('b');
  });

  it('breaks timestamp ties by state priority', () => {
    const latest = __testing.pickLatestDeploymentState([
      { state: 'failed', deploymentId: 'a', atMs: 2000, atIso: '2024-01-01T00:00:02Z', record: {}, sourcePath: '/tmp/a.json' },
      { state: 'queued', deploymentId: 'b', atMs: 2000, atIso: '2024-01-01T00:00:02Z', record: {}, sourcePath: '/tmp/b.json' },
      { state: 'processing', deploymentId: 'c', atMs: 2000, atIso: '2024-01-01T00:00:02Z', record: {}, sourcePath: '/tmp/c.json' },
    ]);
    expect(latest?.state).toBe('processing');
    expect(latest?.deploymentId).toBe('c');
  });

  it('breaks full ties by deployment id descending', () => {
    const latest = __testing.pickLatestDeploymentState([
      { state: 'queued', deploymentId: 'a', atMs: 2000, atIso: '2024-01-01T00:00:02Z', record: {}, sourcePath: '/tmp/a.json' },
      { state: 'queued', deploymentId: 'b', atMs: 2000, atIso: '2024-01-01T00:00:02Z', record: {}, sourcePath: '/tmp/b.json' },
    ]);
    expect(latest?.deploymentId).toBe('b');
  });
});
