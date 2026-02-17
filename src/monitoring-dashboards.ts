import fs from 'fs';
import { runCommand } from './exec.js';
import { buildSignature } from './node-hmac.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DASHBOARDS_CONTAINER_FILTER = 'name=mz-monitoring_opensearch-dashboards';
const DASHBOARDS_BASE_URL = 'http://127.0.0.1:5601';
const DASHBOARDS_READY_TIMEOUT_MS = Number(process.env.MZ_DASHBOARDS_READY_TIMEOUT_MS || 180_000);
const DASHBOARDS_READY_POLL_MS = Number(process.env.MZ_DASHBOARDS_READY_POLL_MS || 3_000);

const DATA_VIEW_LOGS_ID = 'mz-data-logs';
const DATA_VIEW_METRICS_ID = 'mz-data-metrics';
const DATA_VIEW_LOGS_COMPAT_ID = 'mz-logs-pattern';
const DATA_VIEW_METRICS_COMPAT_ID = 'mz-metrics-pattern';
const SEARCH_LOGS_ID = 'mz-search-logs';
const SEARCH_METRICS_ID = 'mz-search-host-metrics';
const SEARCH_DOCKER_METRICS_ID = 'mz-search-docker-metrics';
const VIS_VPS_CPU_BY_HOST_ID = 'mz-vis-vps-cpu-by-host';
const VIS_VPS_MEM_BY_HOST_ID = 'mz-vis-vps-mem-by-host';
const VIS_VPS_CPU_TREND_ID = 'mz-vis-vps-cpu-trend';
const VIS_VPS_MEM_TREND_ID = 'mz-vis-vps-mem-trend';
const VIS_CONTAINER_CPU_BY_SERVICE_ID = 'mz-vis-container-cpu-by-service';
const VIS_CONTAINER_MEM_BY_SERVICE_ID = 'mz-vis-container-mem-by-service';
const VIS_CONTAINER_CPU_TREND_ID = 'mz-vis-container-cpu-trend';
const VIS_CONTAINER_MEM_TREND_ID = 'mz-vis-container-mem-trend';
const DASHBOARD_OPS_ID = 'mz-dashboard-ops';
const DASHBOARD_MAGENTO_CONTAINERS_ID = 'mz-dashboard-magento-containers';
const DEPRECATED_SAVED_OBJECTS: Array<{ type: SavedObject['type']; id: string }> = [
  { type: 'visualization', id: 'mz-vis-host-tophosts' },
  { type: 'visualization', id: 'mz-vis-container-active-by-service' },
  { type: 'visualization', id: 'mz-vis-host-snapshot' },
  { type: 'visualization', id: 'mz-vis-host-timeseries' },
  { type: 'visualization', id: 'mz-vis-stack-cpu-by-stack' },
  { type: 'visualization', id: 'mz-vis-stack-mem-by-stack' },
  { type: 'visualization', id: 'mz-vis-stack-cpu-trend' },
  { type: 'visualization', id: 'mz-vis-stack-mem-trend' },
];

type SavedObject = {
  type: 'index-pattern' | 'search' | 'visualization' | 'dashboard';
  id: string;
  attributes: Record<string, unknown>;
  references?: Array<{ name: string; type: string; id: string }>;
};

type DashboardsApiResponse = {
  status: number;
  body: string;
  parsed: Record<string, unknown> | null;
};

type BootstrapResult = {
  dashboard_id: string;
  dashboard_ids: string[];
  upserted_objects: number;
  container_id: string;
};

function readNodeFile(filename: string): string {
  try {
    return fs.readFileSync(`${NODE_DIR}/${filename}`, 'utf8').trim();
  } catch {
    return '';
  }
}

function timingSafeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function validateNodeRequest(request: Request): Promise<boolean> {
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!nodeId || !nodeSecret) {
    return false;
  }

  const headerNodeId = (request.headers.get('X-MZ-Node-Id') || '').trim();
  const timestamp = (request.headers.get('X-MZ-Timestamp') || '').trim();
  const nonce = (request.headers.get('X-MZ-Nonce') || '').trim();
  const signature = (request.headers.get('X-MZ-Signature') || '').trim();
  if (!headerNodeId || !timestamp || !nonce || !signature) {
    return false;
  }
  if (headerNodeId !== nodeId) {
    return false;
  }

  const timestampInt = Number.parseInt(timestamp, 10);
  if (!timestampInt || Math.abs(Date.now() / 1000 - timestampInt) > 300) {
    return false;
  }

  const url = new URL(request.url);
  const query = url.search ? url.search.slice(1) : '';
  const body = await request.clone().text();
  const expected = buildSignature(request.method, url.pathname, query, timestamp, nonce, body, nodeSecret);
  return timingSafeEquals(expected, signature);
}

async function findDashboardsContainerId(): Promise<string> {
  const result = await runCommand(
    'docker',
    ['ps', '--filter', DASHBOARDS_CONTAINER_FILTER, '--format', '{{.ID}}'],
    15_000,
  );
  if (result.code !== 0) {
    throw new Error(`docker ps failed: ${result.stderr || result.stdout}`.trim());
  }
  const containerId = (result.stdout || '')
    .split('\n')
    .map((line) => line.trim())
    .find(Boolean);
  if (!containerId) {
    throw new Error('OpenSearch Dashboards container not found');
  }
  return containerId;
}

function parseDashboardsApiOutput(stdout: string): DashboardsApiResponse {
  const normalized = stdout.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const statusRaw = (lines.pop() || '').trim();
  const status = Number.parseInt(statusRaw, 10);
  const body = lines.join('\n').trim();

  let parsed: Record<string, unknown> | null = null;
  if (body.startsWith('{') && body.endsWith('}')) {
    try {
      parsed = JSON.parse(body) as Record<string, unknown>;
    } catch {
      parsed = null;
    }
  }

  return {
    status: Number.isFinite(status) ? status : 0,
    body,
    parsed,
  };
}

async function dashboardsRequest(
  containerId: string,
  method: 'GET' | 'POST' | 'DELETE',
  path: string,
  body?: Record<string, unknown>,
): Promise<DashboardsApiResponse> {
  const args = [
    'exec',
    containerId,
    'curl',
    '-sS',
    '--max-time',
    '20',
    '-X',
    method,
    `${DASHBOARDS_BASE_URL}${path}`,
    '-H',
    'osd-xsrf: true',
    '-H',
    'content-type: application/json',
    '-w',
    '\n%{http_code}',
  ];
  if (body) {
    args.push('-d', JSON.stringify(body));
  }

  const result = await runCommand('docker', args, 30_000);
  if (result.code !== 0) {
    throw new Error(`Dashboards API call failed: ${result.stderr || result.stdout}`.trim());
  }
  return parseDashboardsApiOutput(result.stdout || '');
}

function isDashboardsReady(response: DashboardsApiResponse): boolean {
  if (response.status < 200 || response.status >= 300) {
    return false;
  }
  const payload = response.parsed;
  if (payload && typeof payload === 'object') {
    const statusObj = payload.status;
    if (statusObj && typeof statusObj === 'object') {
      const overall = (statusObj as Record<string, unknown>).overall;
      if (overall && typeof overall === 'object') {
        const state = String((overall as Record<string, unknown>).state || '').trim().toLowerCase();
        if (state === 'green' || state === 'yellow') {
          return true;
        }
      }
    }
  }
  const lower = response.body.toLowerCase();
  return lower.includes('"state":"green"') || lower.includes('"state":"yellow"');
}

async function waitForDashboardsReady(containerId: string): Promise<void> {
  const deadline = Date.now() + Math.max(10_000, DASHBOARDS_READY_TIMEOUT_MS);
  let lastMessage = '';

  while (Date.now() < deadline) {
    try {
      const response = await dashboardsRequest(containerId, 'GET', '/api/status');
      if (isDashboardsReady(response)) {
        return;
      }
      lastMessage = `status=${response.status} body=${response.body.slice(0, 200)}`;
    } catch (error) {
      lastMessage = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, Math.max(500, DASHBOARDS_READY_POLL_MS)));
  }

  throw new Error(`OpenSearch Dashboards did not become ready: ${lastMessage || 'timeout'}`);
}

async function upsertSavedObject(containerId: string, object: SavedObject): Promise<void> {
  const path = `/api/saved_objects/${encodeURIComponent(object.type)}/${encodeURIComponent(object.id)}?overwrite=true`;
  const response = await dashboardsRequest(containerId, 'POST', path, {
    attributes: object.attributes,
    references: object.references || [],
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(
      `Failed to upsert ${object.type}/${object.id}: ${response.status} ${response.body}`.trim(),
    );
  }
}

async function deleteSavedObjectIfExists(
  containerId: string,
  objectType: SavedObject['type'],
  objectId: string,
): Promise<void> {
  const path = `/api/saved_objects/${encodeURIComponent(objectType)}/${encodeURIComponent(objectId)}`;
  const response = await dashboardsRequest(containerId, 'DELETE', path);
  if (response.status === 404) {
    return;
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(
      `Failed to delete ${objectType}/${objectId}: ${response.status} ${response.body}`.trim(),
    );
  }
}

function buildSavedObjects(): SavedObject[] {
  const logsSearchSource = JSON.stringify({
    index: DATA_VIEW_LOGS_ID,
    query: { language: 'kuery', query: '' },
    filter: [],
  });

  const hostMetricsSearchSource = JSON.stringify({
    index: DATA_VIEW_METRICS_ID,
    query: {
      language: 'kuery',
      query: 'event.module.keyword : "system" and host.name.keyword : "vmi*"',
    },
    filter: [],
  });

  const dockerMetricsSearchSource = JSON.stringify({
    index: DATA_VIEW_METRICS_ID,
    query: { language: 'kuery', query: 'event.module.keyword : "docker"' },
    filter: [],
  });

  const vpsCpuByHostSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'VPS CPU by Host (avg in time range)',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'system.cpu' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'system.cpu.total.norm.pct' } },
                  ],
                },
              },
              aggs: {
                hosts: {
                  terms: {
                    field: 'host.name.keyword',
                    size: 10,
                    order: { cpu_avg: 'desc' },
                  },
                  aggs: {
                    cpu_avg: { avg: { field: 'system.cpu.total.norm.pct' } },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.hosts.buckets' },
    },
    transform: [
      { calculate: 'datum.key', as: 'host_label' },
      { calculate: 'datum.cpu_avg && datum.cpu_avg.value ? datum.cpu_avg.value * 100 : 0', as: 'cpu_pct' },
    ],
    mark: { type: 'bar' },
    encoding: {
      y: { field: 'host_label', type: 'nominal', sort: '-x', title: 'Host' },
      x: { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', scale: { domain: [0, 100] } },
      tooltip: [
        { field: 'host_label', type: 'nominal', title: 'Host' },
        { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', format: '.2f' },
      ],
    },
  };

  const vpsMemByHostSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'VPS Memory by Host (avg in time range)',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'system.memory' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'system.memory.actual.used.pct' } },
                  ],
                },
              },
              aggs: {
                hosts: {
                  terms: {
                    field: 'host.name.keyword',
                    size: 10,
                    order: { mem_avg: 'desc' },
                  },
                  aggs: {
                    mem_avg: { avg: { field: 'system.memory.actual.used.pct' } },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.hosts.buckets' },
    },
    transform: [
      { calculate: 'datum.key', as: 'host_label' },
      { calculate: 'datum.mem_avg && datum.mem_avg.value ? datum.mem_avg.value * 100 : 0', as: 'mem_pct' },
    ],
    mark: { type: 'bar' },
    encoding: {
      y: { field: 'host_label', type: 'nominal', sort: '-x', title: 'Host' },
      x: { field: 'mem_pct', type: 'quantitative', title: 'Memory %', scale: { domain: [0, 100] } },
      tooltip: [
        { field: 'host_label', type: 'nominal', title: 'Host' },
        { field: 'mem_pct', type: 'quantitative', title: 'Memory %', format: '.2f' },
      ],
    },
  };

  const vpsCpuTrendSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'VPS CPU Trend by Host',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'system.cpu' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'system.cpu.total.norm.pct' } },
                  ],
                },
              },
              aggs: {
                hosts: {
                  terms: {
                    field: 'host.name.keyword',
                    size: 8,
                    order: { cpu_avg: 'desc' },
                  },
                  aggs: {
                    cpu_avg: { avg: { field: 'system.cpu.total.norm.pct' } },
                    timeline: {
                      date_histogram: {
                        field: '@timestamp',
                        fixed_interval: '1m',
                        min_doc_count: 0,
                      },
                      aggs: {
                        cpu_avg: { avg: { field: 'system.cpu.total.norm.pct' } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.hosts.buckets' },
    },
    transform: [
      { flatten: ['timeline.buckets'], as: ['point'] },
      { calculate: 'datum.key', as: 'host_label' },
      { calculate: 'toDate(datum.point.key_as_string)', as: 'timestamp' },
      { calculate: 'datum.point.cpu_avg && datum.point.cpu_avg.value ? datum.point.cpu_avg.value * 100 : null', as: 'cpu_pct' },
      { filter: 'isValid(datum.cpu_pct)' },
    ],
    mark: { type: 'line', point: false },
    encoding: {
      x: { field: 'timestamp', type: 'temporal', title: 'Time' },
      y: { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', scale: { domain: [0, 100] } },
      color: { field: 'host_label', type: 'nominal', title: 'Host' },
      tooltip: [
        { field: 'timestamp', type: 'temporal', title: 'Time' },
        { field: 'host_label', type: 'nominal', title: 'Host' },
        { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', format: '.2f' },
      ],
    },
  };

  const vpsMemTrendSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'VPS Memory Trend by Host',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'system.memory' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'system.memory.actual.used.pct' } },
                  ],
                },
              },
              aggs: {
                hosts: {
                  terms: {
                    field: 'host.name.keyword',
                    size: 8,
                    order: { mem_avg: 'desc' },
                  },
                  aggs: {
                    mem_avg: { avg: { field: 'system.memory.actual.used.pct' } },
                    timeline: {
                      date_histogram: {
                        field: '@timestamp',
                        fixed_interval: '1m',
                        min_doc_count: 0,
                      },
                      aggs: {
                        mem_avg: { avg: { field: 'system.memory.actual.used.pct' } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.hosts.buckets' },
    },
    transform: [
      { flatten: ['timeline.buckets'], as: ['point'] },
      { calculate: 'datum.key', as: 'host_label' },
      { calculate: 'toDate(datum.point.key_as_string)', as: 'timestamp' },
      { calculate: 'datum.point.mem_avg && datum.point.mem_avg.value ? datum.point.mem_avg.value * 100 : null', as: 'mem_pct' },
      { filter: 'isValid(datum.mem_pct)' },
    ],
    mark: { type: 'line', point: false },
    encoding: {
      x: { field: 'timestamp', type: 'temporal', title: 'Time' },
      y: { field: 'mem_pct', type: 'quantitative', title: 'Memory %', scale: { domain: [0, 100] } },
      color: { field: 'host_label', type: 'nominal', title: 'Host' },
      tooltip: [
        { field: 'timestamp', type: 'temporal', title: 'Time' },
        { field: 'host_label', type: 'nominal', title: 'Host' },
        { field: 'mem_pct', type: 'quantitative', title: 'Memory %', format: '.2f' },
      ],
    },
  };

  const containerCpuByServiceSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'Container CPU by Service (avg in time range)',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'docker.cpu' } },
                    { prefix: { 'container.name.keyword': 'mz-env-' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'docker.container.labels.com_docker_swarm_service_name.keyword' } },
                    { exists: { field: 'docker.cpu.total.norm.pct' } },
                  ],
                },
              },
              aggs: {
                services: {
                  terms: {
                    field: 'docker.container.labels.com_docker_swarm_service_name.keyword',
                    size: 20,
                    order: { cpu_avg: 'desc' },
                  },
                  aggs: {
                    cpu_avg: { avg: { field: 'docker.cpu.total.norm.pct' } },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.services.buckets' },
    },
    transform: [
      { calculate: 'replace(datum.key, /^mz-env-[0-9]+_/, "")', as: 'service_label' },
      { calculate: 'datum.cpu_avg && datum.cpu_avg.value ? datum.cpu_avg.value * 100 : 0', as: 'cpu_pct' },
    ],
    mark: { type: 'bar' },
    encoding: {
      y: { field: 'service_label', type: 'nominal', sort: '-x', title: 'Service' },
      x: { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', scale: { domain: [0, 100] } },
      tooltip: [
        { field: 'service_label', type: 'nominal', title: 'Service' },
        { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', format: '.2f' },
      ],
    },
  };

  const containerMemByServiceSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'Container Memory by Service (avg in time range)',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'docker.memory' } },
                    { prefix: { 'container.name.keyword': 'mz-env-' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'docker.container.labels.com_docker_swarm_service_name.keyword' } },
                    { exists: { field: 'docker.memory.usage.pct' } },
                  ],
                },
              },
              aggs: {
                services: {
                  terms: {
                    field: 'docker.container.labels.com_docker_swarm_service_name.keyword',
                    size: 20,
                    order: { mem_avg: 'desc' },
                  },
                  aggs: {
                    mem_avg: { avg: { field: 'docker.memory.usage.pct' } },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.services.buckets' },
    },
    transform: [
      { calculate: 'replace(datum.key, /^mz-env-[0-9]+_/, "")', as: 'service_label' },
      { calculate: 'datum.mem_avg && datum.mem_avg.value ? datum.mem_avg.value * 100 : 0', as: 'mem_pct' },
    ],
    mark: { type: 'bar' },
    encoding: {
      y: { field: 'service_label', type: 'nominal', sort: '-x', title: 'Service' },
      x: { field: 'mem_pct', type: 'quantitative', title: 'Memory %', scale: { domain: [0, 100] } },
      tooltip: [
        { field: 'service_label', type: 'nominal', title: 'Service' },
        { field: 'mem_pct', type: 'quantitative', title: 'Memory %', format: '.2f' },
      ],
    },
  };

  const containerCpuTrendSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'Container CPU Trend by Service',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'docker.cpu' } },
                    { prefix: { 'container.name.keyword': 'mz-env-' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'docker.container.labels.com_docker_swarm_service_name.keyword' } },
                    { exists: { field: 'docker.cpu.total.norm.pct' } },
                  ],
                },
              },
              aggs: {
                services: {
                  terms: {
                    field: 'docker.container.labels.com_docker_swarm_service_name.keyword',
                    size: 8,
                    order: { cpu_avg: 'desc' },
                  },
                  aggs: {
                    cpu_avg: { avg: { field: 'docker.cpu.total.norm.pct' } },
                    timeline: {
                      date_histogram: {
                        field: '@timestamp',
                        fixed_interval: '1m',
                        min_doc_count: 0,
                      },
                      aggs: {
                        cpu_avg: { avg: { field: 'docker.cpu.total.norm.pct' } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.services.buckets' },
    },
    transform: [
      { flatten: ['timeline.buckets'], as: ['point'] },
      { calculate: 'replace(datum.key, /^mz-env-[0-9]+_/, "")', as: 'service_label' },
      { calculate: 'toDate(datum.point.key_as_string)', as: 'timestamp' },
      { calculate: 'datum.point.cpu_avg && datum.point.cpu_avg.value ? datum.point.cpu_avg.value * 100 : null', as: 'cpu_pct' },
      { filter: 'isValid(datum.cpu_pct)' },
    ],
    mark: { type: 'line', point: false },
    encoding: {
      x: { field: 'timestamp', type: 'temporal', title: 'Time' },
      y: { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', scale: { domain: [0, 100] } },
      color: { field: 'service_label', type: 'nominal', title: 'Service' },
      tooltip: [
        { field: 'timestamp', type: 'temporal', title: 'Time' },
        { field: 'service_label', type: 'nominal', title: 'Service' },
        { field: 'cpu_pct', type: 'quantitative', title: 'CPU %', format: '.2f' },
      ],
    },
  };

  const containerMemTrendSpec = {
    $schema: 'https://vega.github.io/schema/vega-lite/v5.json',
    title: 'Container Memory Trend by Service',
    data: {
      url: {
        '%context%': true,
        '%timefield%': '@timestamp',
        index: 'mz-metrics-*',
        body: {
          size: 0,
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: [
                    { term: { 'event.dataset.keyword': 'docker.memory' } },
                    { prefix: { 'container.name.keyword': 'mz-env-' } },
                    { prefix: { 'host.name.keyword': 'vmi' } },
                    { exists: { field: 'docker.container.labels.com_docker_swarm_service_name.keyword' } },
                    { exists: { field: 'docker.memory.usage.pct' } },
                  ],
                },
              },
              aggs: {
                services: {
                  terms: {
                    field: 'docker.container.labels.com_docker_swarm_service_name.keyword',
                    size: 8,
                    order: { mem_avg: 'desc' },
                  },
                  aggs: {
                    mem_avg: { avg: { field: 'docker.memory.usage.pct' } },
                    timeline: {
                      date_histogram: {
                        field: '@timestamp',
                        fixed_interval: '1m',
                        min_doc_count: 0,
                      },
                      aggs: {
                        mem_avg: { avg: { field: 'docker.memory.usage.pct' } },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      format: { property: 'aggregations.filtered.services.buckets' },
    },
    transform: [
      { flatten: ['timeline.buckets'], as: ['point'] },
      { calculate: 'replace(datum.key, /^mz-env-[0-9]+_/, "")', as: 'service_label' },
      { calculate: 'toDate(datum.point.key_as_string)', as: 'timestamp' },
      { calculate: 'datum.point.mem_avg && datum.point.mem_avg.value ? datum.point.mem_avg.value * 100 : null', as: 'mem_pct' },
      { filter: 'isValid(datum.mem_pct)' },
    ],
    mark: { type: 'line', point: false },
    encoding: {
      x: { field: 'timestamp', type: 'temporal', title: 'Time' },
      y: { field: 'mem_pct', type: 'quantitative', title: 'Memory %', scale: { domain: [0, 100] } },
      color: { field: 'service_label', type: 'nominal', title: 'Service' },
      tooltip: [
        { field: 'timestamp', type: 'temporal', title: 'Time' },
        { field: 'service_label', type: 'nominal', title: 'Service' },
        { field: 'mem_pct', type: 'quantitative', title: 'Memory %', format: '.2f' },
      ],
    },
  };

  const operationsDashboardPanels = JSON.stringify([
    {
      panelIndex: '1',
      gridData: { x: 0, y: 0, w: 24, h: 14, i: '1' },
      type: 'visualization',
      id: VIS_VPS_CPU_BY_HOST_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
    {
      panelIndex: '2',
      gridData: { x: 24, y: 0, w: 24, h: 14, i: '2' },
      type: 'visualization',
      id: VIS_VPS_MEM_BY_HOST_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
    {
      panelIndex: '3',
      gridData: { x: 0, y: 14, w: 24, h: 15, i: '3' },
      type: 'visualization',
      id: VIS_VPS_CPU_TREND_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
    {
      panelIndex: '4',
      gridData: { x: 24, y: 14, w: 24, h: 15, i: '4' },
      type: 'visualization',
      id: VIS_VPS_MEM_TREND_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
  ]);

  const magentoContainersDashboardPanels = JSON.stringify([
    {
      panelIndex: '1',
      gridData: { x: 0, y: 0, w: 24, h: 14, i: '1' },
      type: 'visualization',
      id: VIS_CONTAINER_CPU_BY_SERVICE_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
    {
      panelIndex: '2',
      gridData: { x: 24, y: 0, w: 24, h: 14, i: '2' },
      type: 'visualization',
      id: VIS_CONTAINER_MEM_BY_SERVICE_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
    {
      panelIndex: '3',
      gridData: { x: 0, y: 14, w: 24, h: 15, i: '3' },
      type: 'visualization',
      id: VIS_CONTAINER_CPU_TREND_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
    {
      panelIndex: '4',
      gridData: { x: 24, y: 14, w: 24, h: 15, i: '4' },
      type: 'visualization',
      id: VIS_CONTAINER_MEM_TREND_ID,
      embeddableConfig: {},
      version: '8.0.0',
    },
  ]);

  return [
    {
      type: 'index-pattern',
      id: DATA_VIEW_LOGS_ID,
      attributes: {
        title: 'mz-logs-*',
        timeFieldName: '@timestamp',
      },
    },
    {
      type: 'index-pattern',
      id: DATA_VIEW_LOGS_COMPAT_ID,
      attributes: {
        title: 'mz-logs-*',
        timeFieldName: '@timestamp',
      },
    },
    {
      type: 'index-pattern',
      id: DATA_VIEW_METRICS_ID,
      attributes: {
        title: 'mz-metrics-*',
        timeFieldName: '@timestamp',
      },
    },
    {
      type: 'index-pattern',
      id: DATA_VIEW_METRICS_COMPAT_ID,
      attributes: {
        title: 'mz-metrics-*',
        timeFieldName: '@timestamp',
      },
    },
    {
      type: 'search',
      id: SEARCH_LOGS_ID,
      attributes: {
        title: 'MageZero Logs',
        columns: ['host.name', 'service.name', 'log.level', 'message'],
        sort: [['@timestamp', 'desc']],
        kibanaSavedObjectMeta: {
          searchSourceJSON: logsSearchSource,
        },
      },
    },
    {
      type: 'search',
      id: SEARCH_METRICS_ID,
      attributes: {
        title: 'Host Metrics (Raw)',
        columns: [
          'host.name',
          'system.cpu.total.norm.pct',
          'system.memory.actual.used.pct',
          'system.load.1',
          'system.network.in.bytes',
          'system.network.out.bytes',
        ],
        sort: [['@timestamp', 'desc']],
        kibanaSavedObjectMeta: {
          searchSourceJSON: hostMetricsSearchSource,
        },
      },
    },
    {
      type: 'search',
      id: SEARCH_DOCKER_METRICS_ID,
      attributes: {
        title: 'Container Metrics (Raw)',
        columns: [
          'host.name',
          'docker.container.labels.com_docker_swarm_service_name',
          'container.name',
          'docker.cpu.total.norm.pct',
          'docker.memory.usage.pct',
        ],
        sort: [['@timestamp', 'desc']],
        kibanaSavedObjectMeta: {
          searchSourceJSON: dockerMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_VPS_CPU_BY_HOST_ID,
      attributes: {
        title: 'Host CPU by VPS (%)',
        visState: JSON.stringify({
          title: 'Host CPU by VPS (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(vpsCpuByHostSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: hostMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_VPS_MEM_BY_HOST_ID,
      attributes: {
        title: 'Host Memory by VPS (%)',
        visState: JSON.stringify({
          title: 'Host Memory by VPS (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(vpsMemByHostSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: hostMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_VPS_CPU_TREND_ID,
      attributes: {
        title: 'Host CPU Trend by VPS (%)',
        visState: JSON.stringify({
          title: 'Host CPU Trend by VPS (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(vpsCpuTrendSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: hostMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_VPS_MEM_TREND_ID,
      attributes: {
        title: 'Host Memory Trend by VPS (%)',
        visState: JSON.stringify({
          title: 'Host Memory Trend by VPS (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(vpsMemTrendSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: hostMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_CONTAINER_CPU_BY_SERVICE_ID,
      attributes: {
        title: 'Container CPU by Service (%)',
        visState: JSON.stringify({
          title: 'Container CPU by Service (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(containerCpuByServiceSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: dockerMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_CONTAINER_MEM_BY_SERVICE_ID,
      attributes: {
        title: 'Container Memory by Service (%)',
        visState: JSON.stringify({
          title: 'Container Memory by Service (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(containerMemByServiceSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: dockerMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_CONTAINER_CPU_TREND_ID,
      attributes: {
        title: 'Container CPU Trend by Service (%)',
        visState: JSON.stringify({
          title: 'Container CPU Trend by Service (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(containerCpuTrendSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: dockerMetricsSearchSource,
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_CONTAINER_MEM_TREND_ID,
      attributes: {
        title: 'Container Memory Trend by Service (%)',
        visState: JSON.stringify({
          title: 'Container Memory Trend by Service (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(containerMemTrendSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: dockerMetricsSearchSource,
        },
      },
    },
    {
      type: 'dashboard',
      id: DASHBOARD_OPS_ID,
      attributes: {
        title: 'Server Group Monitoring',
        hits: 0,
        description: 'Infrastructure monitoring dashboard for server group KPIs.',
        panelsJSON: operationsDashboardPanels,
        optionsJSON: JSON.stringify({
          useMargins: true,
          syncColors: false,
          syncCursor: true,
          syncTooltips: false,
          hidePanelTitles: false,
        }),
        version: 1,
        timeRestore: false,
        kibanaSavedObjectMeta: {
          searchSourceJSON: JSON.stringify({
            query: { language: 'kuery', query: '' },
            filter: [],
          }),
        },
      },
    },
    {
      type: 'dashboard',
      id: DASHBOARD_MAGENTO_CONTAINERS_ID,
      attributes: {
        title: 'Magento Containers Monitoring',
        hits: 0,
        description: 'Container health and performance KPIs for Magento environment services.',
        panelsJSON: magentoContainersDashboardPanels,
        optionsJSON: JSON.stringify({
          useMargins: true,
          syncColors: false,
          syncCursor: true,
          syncTooltips: false,
          hidePanelTitles: false,
        }),
        version: 1,
        timeRestore: false,
        kibanaSavedObjectMeta: {
          searchSourceJSON: JSON.stringify({
            query: { language: 'kuery', query: '' },
            filter: [],
          }),
        },
      },
    },
  ];
}

export async function bootstrapMonitoringDashboards(): Promise<BootstrapResult> {
  const containerId = await findDashboardsContainerId();
  await waitForDashboardsReady(containerId);

  for (const deprecatedObject of DEPRECATED_SAVED_OBJECTS) {
    await deleteSavedObjectIfExists(containerId, deprecatedObject.type, deprecatedObject.id);
  }

  const objects = buildSavedObjects();
  for (const object of objects) {
    await upsertSavedObject(containerId, object);
  }

  return {
    dashboard_id: DASHBOARD_OPS_ID,
    dashboard_ids: [DASHBOARD_OPS_ID, DASHBOARD_MAGENTO_CONTAINERS_ID],
    upserted_objects: objects.length,
    container_id: containerId,
  };
}

export async function handleMonitoringDashboardsBootstrap(
  request: Request,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const authorized = await validateNodeRequest(request);
  if (!authorized) {
    return { status: 401, body: { error: 'unauthorized' } };
  }

  try {
    const result = await bootstrapMonitoringDashboards();
    return {
      status: 200,
      body: {
        ok: true,
        ...result,
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      status: 500,
      body: {
        error: 'monitoring_dashboards_bootstrap_failed',
        message,
      },
    };
  }
}
