function escapeSqlValue(value: string): string {
  return value.replace(/'/g, "''");
}

export function parseDetectedEngine(stdout: string): string | null {
  const engine = stdout.trim();
  return (engine === 'elasticsearch7' || engine === 'opensearch') ? engine : null;
}

export function defaultSearchEngine(applicationVersion: string): 'opensearch' | 'elasticsearch7' {
  // Magento <2.4.6 does not have an opensearch adapter; use elasticsearch7
  // (which is API-compatible with our OpenSearch containers).
  const match = applicationVersion.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) return 'opensearch';
  const [, major, minor, patch] = match.map(Number);
  if (major < 2 || (major === 2 && minor < 4) || (major === 2 && minor === 4 && patch < 6)) {
    return 'elasticsearch7';
  }
  return 'opensearch';
}

export function resolveSearchEngine(override: string, detected: string | null, applicationVersion = ''): string {
  return override || detected || defaultSearchEngine(applicationVersion);
}

export function buildSearchEngineEnvOverride(override: string): Record<string, string> {
  return override ? { MZ_SEARCH_ENGINE: override } : {};
}

export function buildSearchSystemConfigSql(host: string, port: string, timeout: string): string {
  const safeHost = escapeSqlValue(String(host || ''));
  const safePort = escapeSqlValue(String(port || ''));
  const safeTimeout = escapeSqlValue(String(timeout || ''));
  const upsert = (p: string, v: string) =>
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, '${p}', '${v}') ON DUPLICATE KEY UPDATE value=VALUES(value)`;
  return [
    upsert('catalog/search/opensearch_server_hostname', safeHost),
    upsert('catalog/search/opensearch_server_port', safePort),
    upsert('catalog/search/opensearch_server_timeout', safeTimeout),
    upsert('catalog/search/elasticsearch7_server_hostname', safeHost),
    upsert('catalog/search/elasticsearch7_server_port', safePort),
    upsert('catalog/search/elasticsearch7_server_timeout', safeTimeout),
    upsert('catalog/search/elasticsearch7_enable_auth', '0'),
    upsert('catalog/search/opensearch_enable_auth', '0'),
  ].join('; ');
}
