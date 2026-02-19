import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

const ORIGINAL_ENV = { ...process.env };
const tempDirs: string[] = [];

function writeJson(filePath: string, payload: unknown) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
}

function makeTuningProfile(id: string) {
  return {
    id,
    status: id === 'base' ? 'base' : 'recommended',
    strategy: 'deterministic',
    resources: {
      services: {
        'php-fpm': {
          limits: { cpu_cores: 1, memory_bytes: 2 * GIB },
          reservations: { cpu_cores: 0.5, memory_bytes: 768 * MIB },
        },
      },
    },
    adjustments: {},
    placements: [],
    created_at: '2026-02-19T00:00:00.000Z',
    updated_at: '2026-02-19T00:00:00.000Z',
    summary: 'sample',
  };
}

async function importStatusModule(paths: { tuningPath: string; capacityPath: string }) {
  process.env.MZ_TUNING_PROFILE_PATH = paths.tuningPath;
  process.env.MZ_CAPACITY_CHANGE_PATH = paths.capacityPath;
  vi.resetModules();
  return import('../src/status.js');
}

describe('approveTuningProfile', () => {
  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    vi.restoreAllMocks();
    for (const dir of tempDirs.splice(0, tempDirs.length)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns 404 when no recommended tuning profile exists', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-status-approve-'));
    tempDirs.push(tempDir);
    const tuningPath = path.join(tempDir, 'tuning-profiles.json');
    const capacityPath = path.join(tempDir, 'capacity-change.json');
    writeJson(tuningPath, {
      base: makeTuningProfile('base'),
      approved: [],
    });

    const status = await importStatusModule({ tuningPath, capacityPath });
    const result = status.approveTuningProfile('recommended-123', 'tuning');

    expect(result.status).toBe(404);
    expect((result.body as { error?: string }).error).toMatch(/No recommended profile available/i);
  });

  it('returns mismatch when requested tuning profile id differs from recommendation', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-status-approve-'));
    tempDirs.push(tempDir);
    const tuningPath = path.join(tempDir, 'tuning-profiles.json');
    const capacityPath = path.join(tempDir, 'capacity-change.json');
    writeJson(tuningPath, {
      base: makeTuningProfile('base'),
      recommended: makeTuningProfile('recommended-abc'),
      approved: [],
    });

    const status = await importStatusModule({ tuningPath, capacityPath });
    const result = status.approveTuningProfile('recommended-other', 'tuning');

    expect(result.status).toBe(409);
    const body = result.body as { error?: string; recommended_id?: string; incremental_id?: string };
    expect(body.error).toBe('recommended_profile_mismatch');
    expect(body.recommended_id).toBe('recommended-abc');
    expect(body.incremental_id).toBe('incremental');
  });

  it('uses capacity_change approval path when profile_type is capacity_change', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-status-approve-'));
    tempDirs.push(tempDir);
    const tuningPath = path.join(tempDir, 'tuning-profiles.json');
    const capacityPath = path.join(tempDir, 'capacity-change.json');

    writeJson(tuningPath, {
      base: makeTuningProfile('base'),
      approved: [],
    });
    writeJson(capacityPath, {
      base: {
        id: 'base',
        status: 'base',
        strategy: 'current-capacity',
        change: 'none',
        created_at: '2026-02-19T00:00:00.000Z',
        updated_at: '2026-02-19T00:00:00.000Z',
        capacity: { cpu_cores: 4, memory_bytes: 8 * GIB, node_count: 2 },
      },
      recommended: {
        id: 'cap-recommended-1',
        status: 'recommended',
        strategy: 'capacity-increase',
        change: 'increase',
        created_at: '2026-02-19T00:00:00.000Z',
        updated_at: '2026-02-19T00:00:00.000Z',
        capacity: { cpu_cores: 4, memory_bytes: 8 * GIB, node_count: 2 },
        required: { cpu_cores: 2, memory_bytes: 4 * GIB },
        ready: true,
      },
      approved: [],
    });

    const status = await importStatusModule({ tuningPath, capacityPath });
    const result = status.approveTuningProfile('cap-recommended-1', 'capacity_change');

    expect(result.status).toBe(200);
    const body = result.body as { active_profile_id?: string; approved_profile?: { status?: string; change?: string } };
    expect(body.active_profile_id).toMatch(/^approved-/);
    expect(body.approved_profile?.status).toBe('approved');
    expect(body.approved_profile?.change).toBe('increase');
  });
});
