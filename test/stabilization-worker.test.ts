import { beforeEach, describe, expect, it, vi } from 'vitest';

const { upsertStabilizationStateMock, readStabilizationStateMock } = vi.hoisted(() => ({
  upsertStabilizationStateMock: vi.fn(),
  readStabilizationStateMock: vi.fn(() => undefined),
}));

vi.mock('../src/exec.js', () => ({
  runCommand: vi.fn(),
}));

vi.mock('../src/support-runbooks.js', () => ({
  executeRunbookById: vi.fn(),
}));

vi.mock('../src/stabilization-state.js', () => ({
  STABILIZATION_LEASE_TTL_MS: 10 * 60_000,
  STABILIZATION_POST_DEPLOY_GRACE_MS: 30_000,
  consumeStabilizationRunRequest: vi.fn(),
  enqueueStabilizationRun: vi.fn(() => ({
    run_after_at: new Date(0).toISOString(),
  })),
  isStabilizationLeaseActive: vi.fn(() => false),
  listQueuedStabilizationEnvironmentIds: vi.fn(() => []),
  listStabilizationLeaseEnvironmentIds: vi.fn(() => []),
  listStabilizationStateEnvironmentIds: vi.fn(() => []),
  markStabilizationLeaseEnded: vi.fn(),
  markStabilizationLeaseHeartbeat: vi.fn(() => ({
    started_at: new Date(0).toISOString(),
    expires_at: new Date(0).toISOString(),
  })),
  markStabilizationLeaseStarted: vi.fn(() => ({
    started_at: new Date(0).toISOString(),
    expires_at: new Date(0).toISOString(),
  })),
  peekStabilizationRunRequest: vi.fn(() => null),
  readStabilizationLease: vi.fn(() => null),
  readStabilizationState: readStabilizationStateMock,
  upsertStabilizationState: upsertStabilizationStateMock,
}));

import { runCommand } from '../src/exec.js';
import { executeRunbookById } from '../src/support-runbooks.js';
import { __testing } from '../src/stabilization-worker.js';

const runCommandMock = vi.mocked(runCommand);
const executeRunbookByIdMock = vi.mocked(executeRunbookById);

describe('stabilization-worker replica checks', () => {
  beforeEach(() => {
    runCommandMock.mockReset();
    executeRunbookByIdMock.mockReset();
    upsertStabilizationStateMock.mockReset();
    readStabilizationStateMock.mockReset();
    readStabilizationStateMock.mockReturnValue(undefined);

    executeRunbookByIdMock.mockImplementation(async (runbookId) => ({
      runbook_id: runbookId,
      status: 'ok',
      summary: `${runbookId} ok`,
      observations: [],
    }));
  });

  it('skips replica runbooks when replica service is scaled to zero', async () => {
    runCommandMock.mockImplementation(async (_cmd, args) => {
      const service = String(args?.[2] || '');
      if (service.endsWith('_database-replica') || service.endsWith('_proxysql')) {
        return {
          code: 0,
          stdout: '{"Replicated":{"Replicas":0}}',
          stderr: '',
        };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await __testing.runStabilizationCycle(15, 'test');

    const runbookIds = executeRunbookByIdMock.mock.calls.map(([runbookId]) => String(runbookId));
    expect(runbookIds).toEqual(['http_smoke_check', 'varnish_ready']);

    const finalState = upsertStabilizationStateMock.mock.calls.at(-1)?.[1] as {
      status?: string;
      checks?: Array<{ runbook_id?: string; summary?: string }>;
    } | undefined;
    expect(finalState?.status).toBe('stable');
    expect(
      finalState?.checks?.some((check) => (
        check.runbook_id === 'db_replication_status'
        && String(check.summary || '').includes('intentionally disabled')
      )),
    ).toBe(true);
  });

  it('skips replica runbooks when replica service is absent', async () => {
    runCommandMock.mockImplementation(async (_cmd, args) => {
      const service = String(args?.[2] || '');
      if (service.endsWith('_database-replica') || service.endsWith('_proxysql')) {
        return {
          code: 1,
          stdout: '',
          stderr: 'Error response from daemon: no such service',
        };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await __testing.runStabilizationCycle(15, 'test');

    const runbookIds = executeRunbookByIdMock.mock.calls.map(([runbookId]) => String(runbookId));
    expect(runbookIds).toEqual(['http_smoke_check', 'varnish_ready']);
  });

  it('keeps proxysql readiness checks when proxysql is enabled', async () => {
    runCommandMock.mockImplementation(async (_cmd, args) => {
      const service = String(args?.[2] || '');
      if (service.endsWith('_database-replica')) {
        return {
          code: 0,
          stdout: '{"Replicated":{"Replicas":0}}',
          stderr: '',
        };
      }
      if (service.endsWith('_proxysql')) {
        return {
          code: 0,
          stdout: '{"Replicated":{"Replicas":1}}',
          stderr: '',
        };
      }
      return { code: 0, stdout: '', stderr: '' };
    });

    await __testing.runStabilizationCycle(15, 'test');

    const runbookIds = executeRunbookByIdMock.mock.calls.map(([runbookId]) => String(runbookId));
    expect(runbookIds).toEqual(['proxysql_ready', 'http_smoke_check', 'varnish_ready']);
  });
});
