import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

describe('deploy-worker cron supervisor detection', () => {
  it('treats legacy grouped inline loops without queue telemetry as outdated', () => {
    const spec = {
      command: null,
      args: [
        'sh',
        '-c',
        'php bin/magento cron:run --group=default && php bin/magento cron:run --group=index',
      ],
    };
    expect(__testing.serviceUsesCronSupervisor(spec)).toBe(false);
  });

  it('accepts inline supervisor commands with queue telemetry markers', () => {
    const spec = {
      command: null,
      args: [
        'sh',
        '-c',
        '... cron:run --group=default ... [cron-supervisor] queue status=ok ... queue_top_failed ... queue_top_overdue ...',
      ],
    };
    expect(__testing.serviceUsesCronSupervisor(spec)).toBe(true);
  });

  it('accepts script-based supervisor commands', () => {
    const spec = {
      command: ['/usr/local/bin/mz-cron-supervisor.sh'],
      args: [],
    };
    expect(__testing.serviceUsesCronSupervisor(spec)).toBe(true);
  });
});

