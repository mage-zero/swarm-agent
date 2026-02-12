import { afterEach, describe, expect, it } from 'vitest';
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

  it('blocks unknown commands', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('python', ['-c', 'print(1)'], { source: 'test' })).toThrow(/not allowlisted/i);
  });

  it('blocks bash -lc', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('bash', ['-lc', 'echo hi'], { source: 'test' })).toThrow(/bash -lc/i);
  });

  it('allows deploy bash scripts with expected args', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-services.sh'], { source: 'test' })).not.toThrow();
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-magento.sh', '/tmp/build.tar.zst'], { source: 'test' })).not.toThrow();
  });

  it('blocks disallowed bash scripts or bad arg counts', () => {
    process.env.MZ_COMMAND_POLICY_MODE = 'enforce';
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/unknown.sh'], { source: 'test' })).toThrow(/not allowlisted/i);
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-services.sh', 'extra'], { source: 'test' })).toThrow(/does not accept extra args/i);
    expect(() => enforceCommandPolicy('bash', ['/opt/mage-zero/cloud-swarm/scripts/build-magento.sh'], { source: 'test' })).toThrow(/requires artifact path arg/i);
  });
});
