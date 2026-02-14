export function getDbBackupZstdLevel(): number {
  const raw = String(process.env.MZ_DB_BACKUP_ZSTD_LEVEL || '').trim();
  if (!raw) return 6;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return 6;
  const level = Math.trunc(parsed);
  if (level < 1) return 1;
  if (level > 19) return 19;
  return level;
}

