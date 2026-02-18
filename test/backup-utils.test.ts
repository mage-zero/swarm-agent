import { afterEach, describe, expect, it } from 'vitest';
import { getDbBackupZstdLevel } from '../src/backup-utils.js';

const originalEnv = { ...process.env };

describe('backup utils', () => {
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('uses default level when unset, empty, or invalid', () => {
    delete process.env.MZ_DB_BACKUP_ZSTD_LEVEL;
    expect(getDbBackupZstdLevel()).toBe(6);

    process.env.MZ_DB_BACKUP_ZSTD_LEVEL = '   ';
    expect(getDbBackupZstdLevel()).toBe(6);

    process.env.MZ_DB_BACKUP_ZSTD_LEVEL = 'not-a-number';
    expect(getDbBackupZstdLevel()).toBe(6);
  });

  it('clamps values to zstd-supported bounds', () => {
    process.env.MZ_DB_BACKUP_ZSTD_LEVEL = '-9';
    expect(getDbBackupZstdLevel()).toBe(1);

    process.env.MZ_DB_BACKUP_ZSTD_LEVEL = '42';
    expect(getDbBackupZstdLevel()).toBe(19);
  });

  it('accepts integer values and truncates numeric strings', () => {
    process.env.MZ_DB_BACKUP_ZSTD_LEVEL = '12';
    expect(getDbBackupZstdLevel()).toBe(12);

    process.env.MZ_DB_BACKUP_ZSTD_LEVEL = '7.9';
    expect(getDbBackupZstdLevel()).toBe(7);
  });
});
