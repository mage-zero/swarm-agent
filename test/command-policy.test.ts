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
});

