import { afterEach, describe, expect, it, vi } from 'vitest';
import { enforceCommandPolicy } from '../src/command-policy.js';

describe('command policy', () => {
  const originalMode = process.env.MZ_COMMAND_POLICY_MODE;

  afterEach(() => {
    if (originalMode === undefined) {
      delete process.env.MZ_COMMAND_POLICY_MODE;
    } else {
      process.env.MZ_COMMAND_POLICY_MODE = originalMode;
    }
  });

  it('allows docker commands with allowlisted subcommands', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('docker', ['service', 'ls'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('docker', ['exec', 'cid', 'sh', '-c', 'echo ok'], { source: 'test' })).not.toThrow();
  });

  it('allows the specific docker ps invocation used by deploy readiness checks', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() =>
      enforceCommandPolicy(
        'docker',
        ['ps', '--filter', 'name=mz-env-15_php-fpm', '--format', '{{.ID}}'],
        { source: 'test' },
      ),
    ).not.toThrow();
  });

  it('blocks docker ps when args are broader than expected', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('docker', ['ps'], { source: 'test' })).toThrow(/requires/i);
    expect(() => enforceCommandPolicy('docker', ['ps', '--format', '{{.ID}}'], { source: 'test' })).toThrow(/requires/i);
    expect(() =>
      enforceCommandPolicy('docker', ['ps', '--filter', 'label=foo', '--format', '{{.ID}}'], { source: 'test' }),
    ).toThrow(/name=/i);
    expect(() =>
      enforceCommandPolicy('docker', ['ps', '--filter', 'name=foo', '--format', '{{.ID}}', '--no-trunc'], { source: 'test' }),
    ).toThrow(/not allowlisted/i);
  });

  it('blocks unknown commands', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('python', ['-c', 'print(1)'], { source: 'test' })).toThrow(/not allowlisted/i);
  });

  it('does not enforce command checks when mode is off', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'off';
    expect(() => enforceCommandPolicy('python', ['-c', 'print(1)'], { source: 'test' })).not.toThrow();
  });

  it('warns instead of throwing when mode is audit', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'audit';
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(() => enforceCommandPolicy('python', ['-c', 'print(1)'], { source: 'test' })).not.toThrow();
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(String(warnSpy.mock.calls[0]?.[0] || '')).toMatch(/command policy violation/i);
  });

  it('blocks bash -lc', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('bash', ['-lc', 'echo hi'], { source: 'test' })).toThrow(/bash -lc/i);
  });

  it('blocks curl payload flags that can mutate state', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('curl', ['-d', 'k=v', 'https://example.test'], { source: 'test' })).toThrow(/not allowlisted/i);
    expect(() => enforceCommandPolicy('curl', ['--data', 'k=v', 'https://example.test'], { source: 'test' })).toThrow(/not allowlisted/i);
  });

  it('allows deploy bash scripts with expected args', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-services.sh'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-monitoring.sh'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-magento.sh', '/tmp/build.tar.zst'], { source: 'test' })).not.toThrow();
  });

  it('blocks disallowed bash scripts or bad arg counts', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/unknown.sh'], { source: 'test' })).toThrow(/not allowlisted/i);
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-services.sh', 'extra'], { source: 'test' })).toThrow(/does not accept extra args/i);
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-monitoring.sh', 'extra'], { source: 'test' })).toThrow(/does not accept extra args/i);
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-magento.sh'], { source: 'test' })).toThrow(/requires artifact path arg/i);
  });

  it('allows docker network and stack commands used by monitoring stack', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('docker', ['network', 'inspect', 'mz-monitoring'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('docker', ['network', 'create', '--driver', 'overlay', '--attachable', '--opt', 'encrypted=true', 'mz-monitoring'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('docker', ['stack', 'ls'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('docker', ['stack', 'deploy', '-c', 'monitoring.yml', 'mz-monitoring'], { source: 'test' })).not.toThrow();
  });
});
