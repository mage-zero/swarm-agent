import { describe, expect, it } from 'vitest';
import { __testing } from '../src/support-runbooks.js';

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
});
