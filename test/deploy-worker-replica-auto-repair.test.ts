import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { buildReplicaConfigureScript, buildReplicaSetupFailureMessage } = __testing;

describe('deploy-worker replica auto-repair', () => {
  it('builds a replica config script that resets and reconfigures replication', () => {
    const script = buildReplicaConfigureScript({
      masterHost: 'mz-env-15_database',
      replicaHost: 'mz-env-15_database-replica',
      replicaUser: 'replica',
    });

    expect(script).toContain(`until mariadb -h 'mz-env-15_database' -uroot -p"$ROOT_PASS" -e "SELECT 1"`);
    expect(script).toContain(`until mariadb -h 'mz-env-15_database-replica' -uroot -p"$ROOT_PASS" -e "SELECT 1"`);
    expect(script).toContain(`CREATE USER IF NOT EXISTS 'replica'@'%' IDENTIFIED BY '\${REPL_PASS}';`);
    expect(script).toContain(`ALTER USER 'replica'@'%' IDENTIFIED BY '\${REPL_PASS}';`);
    expect(script).toContain(`GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'replica'@'%';`);
    expect(script).toContain('STOP SLAVE; RESET SLAVE ALL;');
    expect(script).toContain(`CHANGE MASTER TO MASTER_HOST='mz-env-15_database'`);
    expect(script).toContain('SET GLOBAL read_only=1;');
  });

  it('combines initial failure and auto-repair failure details', () => {
    expect(buildReplicaSetupFailureMessage('replica not ready', 'service update paused')).toBe(
      'replica setup failed after auto-repair (initial: replica not ready; auto-repair: service update paused)',
    );
  });
});
