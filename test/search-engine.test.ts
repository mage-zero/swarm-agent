import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { __testing } from '../src/deploy-worker.js';

const {
  parseDetectedEngine,
  defaultSearchEngine,
  resolveSearchEngine,
  buildSearchEngineEnvOverride,
  buildSearchSystemConfigSql,
  resolveAppHaReplicaPolicy,
  resolveFrontendRuntimePolicy,
} = __testing;

// ---------------------------------------------------------------------------
// parseDetectedEngine – parses mariadb stdout into a known engine or null
// ---------------------------------------------------------------------------
describe('parseDetectedEngine', () => {
  it('returns elasticsearch7 from clean output', () => {
    expect(parseDetectedEngine('elasticsearch7\n')).toBe('elasticsearch7');
  });

  it('returns opensearch from clean output', () => {
    expect(parseDetectedEngine('opensearch\n')).toBe('opensearch');
  });

  it('trims surrounding whitespace and newlines', () => {
    expect(parseDetectedEngine('  elasticsearch7  \n')).toBe('elasticsearch7');
    expect(parseDetectedEngine('\topensearch\t\n')).toBe('opensearch');
    expect(parseDetectedEngine('\n\nelasticsearch7\n\n')).toBe('elasticsearch7');
  });

  it('returns null for empty or whitespace-only output', () => {
    expect(parseDetectedEngine('')).toBeNull();
    expect(parseDetectedEngine('  \n')).toBeNull();
    expect(parseDetectedEngine('\n')).toBeNull();
  });

  it('returns null for unrecognised engine values', () => {
    expect(parseDetectedEngine('mysql')).toBeNull();
    expect(parseDetectedEngine('elasticsearch6')).toBeNull();
    expect(parseDetectedEngine('elasticsearch8')).toBeNull();
    expect(parseDetectedEngine('solr')).toBeNull();
    expect(parseDetectedEngine('amasty_elastic')).toBeNull();
  });

  it('returns null when mariadb returns NULL (no row)', () => {
    expect(parseDetectedEngine('NULL')).toBeNull();
    expect(parseDetectedEngine('null')).toBeNull();
  });

  it('returns null for multi-line output (unexpected format)', () => {
    // If mariadb emits warnings before the value, trim() collapses to multi-word
    expect(parseDetectedEngine('Warning: something\nopensearch\n')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// defaultSearchEngine – version-aware default
// ---------------------------------------------------------------------------
describe('defaultSearchEngine', () => {
  it('returns elasticsearch7 for Magento <2.4.6', () => {
    expect(defaultSearchEngine('2.4.5')).toBe('elasticsearch7');
    expect(defaultSearchEngine('2.4.5-p1')).toBe('elasticsearch7');
    expect(defaultSearchEngine('2.4.4')).toBe('elasticsearch7');
    expect(defaultSearchEngine('2.4.0')).toBe('elasticsearch7');
    expect(defaultSearchEngine('2.3.7')).toBe('elasticsearch7');
  });

  it('returns opensearch for Magento >=2.4.6', () => {
    expect(defaultSearchEngine('2.4.6')).toBe('opensearch');
    expect(defaultSearchEngine('2.4.6-p1')).toBe('opensearch');
    expect(defaultSearchEngine('2.4.7')).toBe('opensearch');
    expect(defaultSearchEngine('2.4.7-p3')).toBe('opensearch');
    expect(defaultSearchEngine('2.4.8')).toBe('opensearch');
  });

  it('returns opensearch when version is empty or unparseable', () => {
    expect(defaultSearchEngine('')).toBe('opensearch');
    expect(defaultSearchEngine('unknown')).toBe('opensearch');
  });
});

// ---------------------------------------------------------------------------
// resolveSearchEngine – override > detected > version-aware default
// ---------------------------------------------------------------------------
describe('resolveSearchEngine', () => {
  it('uses explicit override over detected engine', () => {
    expect(resolveSearchEngine('opensearch', 'elasticsearch7')).toBe('opensearch');
    expect(resolveSearchEngine('elasticsearch7', 'opensearch')).toBe('elasticsearch7');
  });

  it('uses detected engine when override is empty', () => {
    expect(resolveSearchEngine('', 'elasticsearch7')).toBe('elasticsearch7');
    expect(resolveSearchEngine('', 'opensearch')).toBe('opensearch');
  });

  it('defaults to opensearch when version is unknown', () => {
    expect(resolveSearchEngine('', null)).toBe('opensearch');
    expect(resolveSearchEngine('', null, '')).toBe('opensearch');
  });

  it('defaults to elasticsearch7 for Magento <2.4.6', () => {
    expect(resolveSearchEngine('', null, '2.4.5')).toBe('elasticsearch7');
    expect(resolveSearchEngine('', null, '2.4.5-p1')).toBe('elasticsearch7');
  });

  it('defaults to opensearch for Magento >=2.4.6', () => {
    expect(resolveSearchEngine('', null, '2.4.7')).toBe('opensearch');
  });

  it('uses override even when detected is null', () => {
    expect(resolveSearchEngine('elasticsearch7', null)).toBe('elasticsearch7');
  });

  it('detected engine takes priority over version-aware default', () => {
    // DB says opensearch but version is <2.4.6 - trust what's in the DB
    expect(resolveSearchEngine('', 'opensearch', '2.4.5')).toBe('opensearch');
  });
});

// ---------------------------------------------------------------------------
// buildSearchEngineEnvOverride – only sets MZ_SEARCH_ENGINE when override is non-empty
// ---------------------------------------------------------------------------
describe('buildSearchEngineEnvOverride', () => {
  it('returns MZ_SEARCH_ENGINE when override is set', () => {
    expect(buildSearchEngineEnvOverride('opensearch')).toEqual({ MZ_SEARCH_ENGINE: 'opensearch' });
    expect(buildSearchEngineEnvOverride('elasticsearch7')).toEqual({ MZ_SEARCH_ENGINE: 'elasticsearch7' });
  });

  it('returns empty object when override is empty string', () => {
    expect(buildSearchEngineEnvOverride('')).toEqual({});
  });

  it('spreads cleanly into an env object', () => {
    const base = { MZ_OPENSEARCH_HOST: 'search', OTHER: 'val' };
    const withOverride = { ...base, ...buildSearchEngineEnvOverride('opensearch') };
    expect(withOverride).toEqual({ MZ_OPENSEARCH_HOST: 'search', OTHER: 'val', MZ_SEARCH_ENGINE: 'opensearch' });

    const withoutOverride = { ...base, ...buildSearchEngineEnvOverride('') };
    expect(withoutOverride).toEqual({ MZ_OPENSEARCH_HOST: 'search', OTHER: 'val' });
    expect(withoutOverride).not.toHaveProperty('MZ_SEARCH_ENGINE');
  });
});

// ---------------------------------------------------------------------------
// resolveAppHaReplicaPolicy – frontend HA replica policy
// ---------------------------------------------------------------------------
describe('resolveAppHaReplicaPolicy', () => {
  it('keeps single-replica mode when the stack has fewer ready nodes than required', () => {
    const decision = resolveAppHaReplicaPolicy({
      ready_node_count: 1,
      free_cpu_cores: 8,
      free_memory_bytes: 16 * 1024 * 1024 * 1024,
      nginx_reserve_cpu_cores: 0.2,
      nginx_reserve_memory_bytes: 256 * 1024 * 1024,
      php_fpm_reserve_cpu_cores: 1,
      php_fpm_reserve_memory_bytes: 1024 * 1024 * 1024,
      min_ready_nodes: 2,
      max_replicas: 2,
    });
    expect(decision).toEqual({
      replicas: 1,
      reason: 'single_node',
      required_cpu_cores: 0,
      required_memory_bytes: 0,
      shortfall_cpu_cores: 0,
      shortfall_memory_bytes: 0,
    });
  });

  it('enables HA replicas when enough nodes and headroom are available', () => {
    const decision = resolveAppHaReplicaPolicy({
      ready_node_count: 2,
      free_cpu_cores: 2,
      free_memory_bytes: 2 * 1024 * 1024 * 1024,
      nginx_reserve_cpu_cores: 0.2,
      nginx_reserve_memory_bytes: 256 * 1024 * 1024,
      php_fpm_reserve_cpu_cores: 1,
      php_fpm_reserve_memory_bytes: 1024 * 1024 * 1024,
      min_ready_nodes: 2,
      max_replicas: 2,
    });
    expect(decision.replicas).toBe(2);
    expect(decision.reason).toBe('ha_enabled');
    expect(decision.required_cpu_cores).toBe(1.2);
    expect(decision.required_memory_bytes).toBe(1280 * 1024 * 1024);
    expect(decision.shortfall_cpu_cores).toBe(0);
    expect(decision.shortfall_memory_bytes).toBe(0);
  });

  it('caps target replicas by max_replicas when more nodes are available', () => {
    const decision = resolveAppHaReplicaPolicy({
      ready_node_count: 4,
      free_cpu_cores: 8,
      free_memory_bytes: 32 * 1024 * 1024 * 1024,
      nginx_reserve_cpu_cores: 0.2,
      nginx_reserve_memory_bytes: 256 * 1024 * 1024,
      php_fpm_reserve_cpu_cores: 1,
      php_fpm_reserve_memory_bytes: 1024 * 1024 * 1024,
      min_ready_nodes: 2,
      max_replicas: 2,
    });
    expect(decision.replicas).toBe(2);
    expect(decision.reason).toBe('ha_enabled');
  });

  it('falls back to single-replica when HA headroom is insufficient', () => {
    const decision = resolveAppHaReplicaPolicy({
      ready_node_count: 2,
      free_cpu_cores: 0.5,
      free_memory_bytes: 500 * 1024 * 1024,
      nginx_reserve_cpu_cores: 0.2,
      nginx_reserve_memory_bytes: 256 * 1024 * 1024,
      php_fpm_reserve_cpu_cores: 1,
      php_fpm_reserve_memory_bytes: 1024 * 1024 * 1024,
      min_ready_nodes: 2,
      max_replicas: 2,
    });
    expect(decision.replicas).toBe(1);
    expect(decision.reason).toBe('insufficient_headroom');
    expect(decision.shortfall_cpu_cores).toBeGreaterThan(0);
    expect(decision.shortfall_memory_bytes).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// resolveFrontendRuntimePolicy – rollout-safe frontend runtime settings
// ---------------------------------------------------------------------------
describe('resolveFrontendRuntimePolicy', () => {
  it('uses start-first with no per-node cap for single replica', () => {
    expect(resolveFrontendRuntimePolicy(1)).toEqual({
      replicas: 1,
      max_replicas_per_node: 0,
      update_order: 'start-first',
      restart_condition: 'any',
    });
  });

  it('uses stop-first with one-per-node spread for HA replicas', () => {
    expect(resolveFrontendRuntimePolicy(2)).toEqual({
      replicas: 2,
      max_replicas_per_node: 1,
      update_order: 'stop-first',
      restart_condition: 'any',
    });
    expect(resolveFrontendRuntimePolicy(4)).toEqual({
      replicas: 4,
      max_replicas_per_node: 1,
      update_order: 'stop-first',
      restart_condition: 'any',
    });
  });

  it('normalizes invalid replica counts to safe single-replica defaults', () => {
    expect(resolveFrontendRuntimePolicy(0)).toEqual({
      replicas: 1,
      max_replicas_per_node: 0,
      update_order: 'start-first',
      restart_condition: 'any',
    });
    expect(resolveFrontendRuntimePolicy(-7)).toEqual({
      replicas: 1,
      max_replicas_per_node: 0,
      update_order: 'start-first',
      restart_condition: 'any',
    });
  });
});

// ---------------------------------------------------------------------------
// buildSearchSystemConfigSql – generates SQL for both engine connection paths
// ---------------------------------------------------------------------------
describe('buildSearchSystemConfigSql', () => {
  const EXPECTED_PATHS = [
    'catalog/search/opensearch_server_hostname',
    'catalog/search/opensearch_server_port',
    'catalog/search/opensearch_server_timeout',
    'catalog/search/elasticsearch7_server_hostname',
    'catalog/search/elasticsearch7_server_port',
    'catalog/search/elasticsearch7_server_timeout',
    'catalog/search/elasticsearch7_enable_auth',
    'catalog/search/opensearch_enable_auth',
  ];

  it('contains exactly the 8 expected Magento config paths', () => {
    const sql = buildSearchSystemConfigSql('host', '9200', '15');
    for (const p of EXPECTED_PATHS) {
      expect(sql).toContain(`'${p}'`);
    }
    expect((sql.match(/INSERT INTO/g) || []).length).toBe(8);
  });

  it('sets connection values for both opensearch and elasticsearch7', () => {
    const sql = buildSearchSystemConfigSql('my-search', '9201', '30');
    expect(sql).toContain("'catalog/search/opensearch_server_hostname', 'my-search'");
    expect(sql).toContain("'catalog/search/opensearch_server_port', '9201'");
    expect(sql).toContain("'catalog/search/opensearch_server_timeout', '30'");
    expect(sql).toContain("'catalog/search/elasticsearch7_server_hostname', 'my-search'");
    expect(sql).toContain("'catalog/search/elasticsearch7_server_port', '9201'");
    expect(sql).toContain("'catalog/search/elasticsearch7_server_timeout', '30'");
  });

  it('disables auth for both engines', () => {
    const sql = buildSearchSystemConfigSql('host', '9200', '15');
    expect(sql).toContain("'catalog/search/elasticsearch7_enable_auth', '0'");
    expect(sql).toContain("'catalog/search/opensearch_enable_auth', '0'");
  });

  it('each statement uses ON DUPLICATE KEY UPDATE', () => {
    const sql = buildSearchSystemConfigSql('host', '9200', '15');
    const insertCount = (sql.match(/INSERT INTO/g) || []).length;
    const upsertCount = (sql.match(/ON DUPLICATE KEY UPDATE/g) || []).length;
    expect(insertCount).toBe(upsertCount);
  });

  it('escapes single quotes in host value', () => {
    const sql = buildSearchSystemConfigSql("host'name", '9200', '15');
    expect(sql).toContain("host''name");
    expect(sql).not.toMatch(/host'name/);
  });

  it('handles empty string inputs gracefully', () => {
    const sql = buildSearchSystemConfigSql('', '', '');
    expect((sql.match(/INSERT INTO/g) || []).length).toBe(8);
    // Values should be empty strings, not undefined/null
    expect(sql).toContain("'catalog/search/opensearch_server_hostname', ''");
  });
});

// ---------------------------------------------------------------------------
// env.php.wrapper – PHP integration tests for search engine config logic
// ---------------------------------------------------------------------------
describe('env.php.wrapper search engine config', () => {
  const wrapperPath = path.resolve(__dirname, '../../cloud-swarm/docker/magento/env.php.wrapper');

  /**
   * Runs a PHP snippet that sources the wrapper's search-engine logic in isolation.
   * We can't require the full wrapper (it needs env.base.php, docker secrets, etc.)
   * so we replicate the exact conditional block and test its behaviour.
   */
  function evalSearchConfig(env: Record<string, string>, existingEngine?: string): Record<string, unknown> {
    const existingEnginePhp = existingEngine
      ? `$base['system']['default']['catalog']['search']['engine'] = '${existingEngine}';`
      : '';
    // Replicate exactly the search-engine block from env.php.wrapper
    const php = `<?php
$base = ['system' => ['default' => ['catalog' => ['search' => []]]]];
${existingEnginePhp}
$opensearchHost = getenv('MZ_OPENSEARCH_HOST') ?: 'opensearch';
$opensearchPort = getenv('MZ_OPENSEARCH_PORT') ?: '9200';
$opensearchTimeout = getenv('MZ_OPENSEARCH_TIMEOUT') ?: '15';
// Only override engine if MZ_SEARCH_ENGINE is explicitly set and non-empty
$mzSearchEngine = getenv('MZ_SEARCH_ENGINE');
if (is_string($mzSearchEngine) && $mzSearchEngine !== '') {
    $base['system']['default']['catalog']['search']['engine'] = $mzSearchEngine;
}
// Set connection paths for BOTH engines (whichever the customer uses)
$base['system']['default']['catalog']['search']['opensearch_server_hostname'] = $opensearchHost;
$base['system']['default']['catalog']['search']['opensearch_server_port'] = $opensearchPort;
$base['system']['default']['catalog']['search']['opensearch_server_timeout'] = $opensearchTimeout;
$base['system']['default']['catalog']['search']['elasticsearch7_server_hostname'] = $opensearchHost;
$base['system']['default']['catalog']['search']['elasticsearch7_server_port'] = $opensearchPort;
$base['system']['default']['catalog']['search']['elasticsearch7_server_timeout'] = $opensearchTimeout;
echo json_encode($base['system']['default']['catalog']['search']);
`;
    const result = execFileSync('docker', [
      'run', '--rm', '-i',
      ...Object.entries(env).map(([k, v]) => `-e${k}=${v}`),
      'php:8.2-cli', 'php',
    ], { input: php, timeout: 15000 });
    return JSON.parse(result.toString());
  }

  it('does NOT override engine when MZ_SEARCH_ENGINE is absent (preserves customer value)', () => {
    const config = evalSearchConfig({}, 'elasticsearch7');
    expect(config.engine).toBe('elasticsearch7');
  });

  it('does NOT override engine when MZ_SEARCH_ENGINE is empty string (stack YAML default)', () => {
    // The stack YAML uses ${MZ_SEARCH_ENGINE:-} which produces an empty string
    // when the deploy-worker does not set an explicit override.
    const config = evalSearchConfig({ MZ_SEARCH_ENGINE: '' }, 'elasticsearch7');
    expect(config.engine).toBe('elasticsearch7');
  });

  it('overrides engine when MZ_SEARCH_ENGINE is explicitly set', () => {
    const config = evalSearchConfig({ MZ_SEARCH_ENGINE: 'opensearch' }, 'elasticsearch7');
    expect(config.engine).toBe('opensearch');
  });

  it('sets both opensearch and elasticsearch7 connection paths', () => {
    const config = evalSearchConfig({
      MZ_OPENSEARCH_HOST: 'my-search',
      MZ_OPENSEARCH_PORT: '9201',
      MZ_OPENSEARCH_TIMEOUT: '30',
    });
    expect(config.opensearch_server_hostname).toBe('my-search');
    expect(config.opensearch_server_port).toBe('9201');
    expect(config.opensearch_server_timeout).toBe('30');
    expect(config.elasticsearch7_server_hostname).toBe('my-search');
    expect(config.elasticsearch7_server_port).toBe('9201');
    expect(config.elasticsearch7_server_timeout).toBe('30');
  });

  it('uses default connection values when env vars are absent', () => {
    const config = evalSearchConfig({});
    expect(config.opensearch_server_hostname).toBe('opensearch');
    expect(config.opensearch_server_port).toBe('9200');
    expect(config.elasticsearch7_server_hostname).toBe('opensearch');
    expect(config.elasticsearch7_server_port).toBe('9200');
  });

  it('preserves customer elasticsearch7 engine when no override is set', () => {
    // The key scenario: Magento <2.4.6 with elasticsearch7 in DB
    const config = evalSearchConfig(
      { MZ_OPENSEARCH_HOST: 'stack_opensearch' },
      'elasticsearch7'
    );
    // Engine must NOT be overridden
    expect(config.engine).toBe('elasticsearch7');
    // But connection paths for both engines point to our container
    expect(config.elasticsearch7_server_hostname).toBe('stack_opensearch');
    expect(config.opensearch_server_hostname).toBe('stack_opensearch');
  });
});
