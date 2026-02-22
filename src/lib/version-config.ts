import fs from 'fs';
import path from 'path';

export type AppSelection = { flavor?: string; version?: string };
export type ApplicationSelections = {
  php?: string;
  varnish?: string;
  database?: AppSelection;
  search?: AppSelection;
  cache?: AppSelection;
  queue?: AppSelection;
};

export type PlannerResourceSpec = {
  limits: {
    cpu_cores: number;
    memory_bytes: number;
  };
  reservations: {
    cpu_cores: number;
    memory_bytes: number;
  };
};

export type PlannerResources = Record<string, PlannerResourceSpec>;

export type PlannerConfigChange = {
  service: string;
  changes: Record<string, number | string>;
};

export type PlannerTuningProfileLike = {
  id?: string;
  config_changes?: PlannerConfigChange[];
};

export type PlannerTuningPayloadLike = {
  active_profile_id?: string;
  base_profile?: PlannerTuningProfileLike;
  recommended_profile?: PlannerTuningProfileLike;
  incremental_profile?: PlannerTuningProfileLike;
  approved_profiles?: PlannerTuningProfileLike[];
};

export const MIB = 1024 * 1024;
export const GIB = 1024 * 1024 * 1024;

export const RESOURCE_ENV_MAP = [
  { service: 'varnish', prefix: 'MZ_VARNISH' },
  { service: 'nginx', prefix: 'MZ_NGINX' },
  { service: 'php-fpm', prefix: 'MZ_PHP_FPM' },
  { service: 'php-fpm-admin', prefix: 'MZ_PHP_FPM_ADMIN' },
  { service: 'cron', prefix: 'MZ_CRON' },
  { service: 'database', prefix: 'MZ_DATABASE' },
  { service: 'database-replica', prefix: 'MZ_DATABASE_REPLICA' },
  { service: 'proxysql', prefix: 'MZ_PROXYSQL' },
  { service: 'opensearch', prefix: 'MZ_OPENSEARCH' },
  { service: 'redis-cache', prefix: 'MZ_REDIS_CACHE' },
  { service: 'redis-session', prefix: 'MZ_REDIS_SESSION' },
  { service: 'rabbitmq', prefix: 'MZ_RABBITMQ' },
  { service: 'mailhog', prefix: 'MZ_MAILHOG' },
] as const;

export const RESOURCE_ENV_KEYS = RESOURCE_ENV_MAP.flatMap((entry) => [
  `${entry.prefix}_LIMIT_CPUS`,
  `${entry.prefix}_LIMIT_MEMORY`,
  `${entry.prefix}_RESERVE_CPUS`,
  `${entry.prefix}_RESERVE_MEMORY`,
]);

export function assertRequiredEnv(env: NodeJS.ProcessEnv, keys: string[]) {
  const missing = keys.filter((key) => !env[key]);
  if (missing.length) {
    throw new Error(`Missing required environment values: ${missing.join(', ')}`);
  }
}

export function formatCpuCores(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid CPU cores value: ${value}`);
  }
  return String(value);
}

export function formatMemoryBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    throw new Error(`Invalid memory bytes value: ${bytes}`);
  }
  if (bytes % GIB === 0) {
    return `${bytes / GIB}G`;
  }
  if (bytes % MIB === 0) {
    return `${bytes / MIB}M`;
  }
  return String(Math.round(bytes));
}

export function formatMemoryMiB(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    throw new Error(`Invalid memory bytes value: ${bytes}`);
  }
  return String(Math.max(1, Math.round(bytes / MIB)));
}

export function buildPlannerResourceEnv(resources: PlannerResources) {
  const env: Record<string, string> = {};
  for (const entry of RESOURCE_ENV_MAP) {
    const resource = resources[entry.service];
    if (!resource) {
      throw new Error(`Planner missing resource sizing for ${entry.service}`);
    }
    env[`${entry.prefix}_LIMIT_CPUS`] = formatCpuCores(resource.limits.cpu_cores);
    env[`${entry.prefix}_LIMIT_MEMORY`] = formatMemoryBytes(resource.limits.memory_bytes);
    env[`${entry.prefix}_RESERVE_CPUS`] = formatCpuCores(resource.reservations.cpu_cores);
    env[`${entry.prefix}_RESERVE_MEMORY`] = formatMemoryBytes(resource.reservations.memory_bytes);
  }
  return env;
}

export function resolveActiveProfile(tuning: PlannerTuningPayloadLike | null | undefined): PlannerTuningProfileLike | null {
  if (!tuning) {
    return null;
  }
  const activeId = tuning.active_profile_id;
  const approved = Array.isArray(tuning.approved_profiles) ? tuning.approved_profiles : [];
  if (activeId) {
    const fromApproved = approved.find((profile) => profile?.id === activeId);
    if (fromApproved) {
      return fromApproved;
    }
    if (tuning.recommended_profile?.id === activeId) {
      return tuning.recommended_profile;
    }
    if (tuning.incremental_profile?.id === activeId) {
      return tuning.incremental_profile;
    }
    if (tuning.base_profile?.id === activeId) {
      return tuning.base_profile;
    }
  }
  return tuning.base_profile || approved[0] || tuning.recommended_profile || null;
}

export function buildConfigEnv(configChanges: PlannerConfigChange[]): Record<string, string> {
  const env: Record<string, string> = {};
  const seen = new Set<string>();

  const setEnv = (key: string, value: string) => {
    if (!seen.has(key)) {
      env[key] = value;
      seen.add(key);
    }
  };

  for (const change of configChanges) {
    const service = String(change?.service || '');
    const changes = change?.changes || {};
    for (const [key, rawValue] of Object.entries(changes)) {
      if (rawValue === null || rawValue === undefined) {
        continue;
      }
      if (service === 'php-fpm' || service === 'php-fpm-admin') {
        switch (key) {
          case 'php.memory_limit':
            if (Number(rawValue) > 0) {
              setEnv('MZ_PHP_MEMORY_LIMIT', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'opcache.memory_consumption':
            if (Number(rawValue) > 0) {
              setEnv('MZ_OPCACHE_MEMORY_CONSUMPTION', formatMemoryMiB(Number(rawValue)));
            }
            break;
          case 'opcache.interned_strings_buffer':
            if (Number(rawValue) > 0) {
              setEnv('MZ_OPCACHE_INTERNED_STRINGS_BUFFER', formatMemoryMiB(Number(rawValue)));
            }
            break;
          case 'opcache.max_accelerated_files':
            setEnv('MZ_OPCACHE_MAX_ACCELERATED_FILES', String(rawValue));
            break;
          case 'fpm.pm.max_children':
            setEnv('MZ_FPM_PM_MAX_CHILDREN', String(rawValue));
            break;
          case 'fpm.pm.start_servers':
            setEnv('MZ_FPM_PM_START_SERVERS', String(rawValue));
            break;
          case 'fpm.pm.min_spare_servers':
            setEnv('MZ_FPM_PM_MIN_SPARE_SERVERS', String(rawValue));
            break;
          case 'fpm.pm.max_spare_servers':
            setEnv('MZ_FPM_PM_MAX_SPARE_SERVERS', String(rawValue));
            break;
          case 'fpm.pm.max_requests':
            setEnv('MZ_FPM_PM_MAX_REQUESTS', String(rawValue));
            break;
          case 'fpm.request_terminate_timeout':
            setEnv('MZ_FPM_REQUEST_TERMINATE_TIMEOUT', String(rawValue));
            break;
          default:
            break;
        }
      } else if (service === 'database' || service === 'database-replica') {
        switch (key) {
          case 'innodb_buffer_pool_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_INNODB_BUFFER_POOL_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'innodb_log_file_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_INNODB_LOG_FILE_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'max_connections':
            setEnv('MZ_DB_MAX_CONNECTIONS', String(rawValue));
            break;
          case 'tmp_table_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_TMP_TABLE_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'max_heap_table_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_MAX_HEAP_TABLE_SIZE', formatMemoryBytes(Number(rawValue)));
            }
            break;
          case 'thread_cache_size':
            setEnv('MZ_DB_THREAD_CACHE_SIZE', String(rawValue));
            break;
          case 'query_cache_size':
            if (Number(rawValue) > 0) {
              setEnv('MZ_DB_QUERY_CACHE_SIZE', formatMemoryBytes(Number(rawValue)));
            } else {
              setEnv('MZ_DB_QUERY_CACHE_SIZE', '0');
            }
            break;
          default:
            break;
        }
      }
    }
  }

  return env;
}

export function normalizeSelectionFlavor(flavor: string | undefined, fallback: string): string {
  return (flavor || fallback).toLowerCase();
}

export function resolveVersionEnv(selections: ApplicationSelections | undefined) {
  const phpVersion = selections?.php || '';
  const varnishVersion = selections?.varnish || '';
  const databaseFlavor = normalizeSelectionFlavor(selections?.database?.flavor, 'mariadb');
  const databaseVersion = selections?.database?.version || '';
  const searchFlavor = normalizeSelectionFlavor(selections?.search?.flavor, 'opensearch');
  const searchVersion = selections?.search?.version || '';
  const cacheFlavor = normalizeSelectionFlavor(selections?.cache?.flavor, 'redis');
  const cacheVersion = selections?.cache?.version || '';
  const queueFlavor = normalizeSelectionFlavor(selections?.queue?.flavor, 'rabbitmq');
  const queueVersion = selections?.queue?.version || '';

  const mappedDb = databaseFlavor === 'mysql' ? 'mariadb' : databaseFlavor;
  const mappedSearch = searchFlavor === 'elasticsearch' ? 'opensearch' : searchFlavor;
  const mappedCache = cacheFlavor === 'valkey' ? 'redis' : cacheFlavor;
  const mappedQueue = queueFlavor === 'activemq-artemis' ? 'rabbitmq' : queueFlavor;

  return {
    phpVersion,
    varnishVersion,
    mariadbVersion: mappedDb === 'mariadb' ? databaseVersion : '',
    opensearchVersion: mappedSearch === 'opensearch' ? searchVersion : '',
    redisVersion: mappedCache === 'redis' ? cacheVersion : '',
    rabbitmqVersion: mappedQueue === 'rabbitmq' ? queueVersion : '',
  };
}

export function readVersionDefaults(cloudSwarmDir: string): Record<string, string> {
  const file = path.join(cloudSwarmDir, 'config/versions.env');
  if (!fs.existsSync(file)) {
    return {};
  }
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const output: Record<string, string> = {};
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const idx = trimmed.indexOf('=');
    if (idx === -1) {
      continue;
    }
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (key && value) {
      output[key] = value;
    }
  }
  return output;
}

export function resolveImageTag(artifactKey: string, ref: string, deploymentId: string) {
  const base = path.basename(artifactKey);
  const match = base.match(/-([0-9a-f]{7,40})\.tar\.zst$/);
  if (match) {
    return match[1].slice(0, 12);
  }
  if (ref.startsWith('refs/heads/')) {
    return ref.split('/').pop() || ref;
  }
  if (ref) {
    return ref.slice(0, 12);
  }
  return deploymentId.slice(0, 8);
}
