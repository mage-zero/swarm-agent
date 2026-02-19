import fs from 'fs';
import { runCommand } from './exec.js';
import { buildSignature } from './node-hmac.js';

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DASHBOARDS_CONTAINER_FILTER = 'name=mz-monitoring_opensearch-dashboards';
const DASHBOARDS_BASE_URL = 'http://127.0.0.1:5601';
const OPENSEARCH_BASE_URL = 'http://opensearch:9200';
const DASHBOARDS_READY_TIMEOUT_MS = Number(process.env.MZ_DASHBOARDS_READY_TIMEOUT_MS || 180_000);
const DASHBOARDS_READY_POLL_MS = Number(process.env.MZ_DASHBOARDS_READY_POLL_MS || 3_000);

const DATA_VIEW_LOGS_ID = 'mz-data-logs';
const DATA_VIEW_METRICS_ID = 'mz-data-metrics';
const DATA_VIEW_LOGS_COMPAT_ID = 'mz-logs-pattern';
const DATA_VIEW_METRICS_COMPAT_ID = 'mz-metrics-pattern';
const SEARCH_LOGS_ID = 'mz-search-logs';
const SEARCH_METRICS_ID = 'mz-search-host-metrics';
const SEARCH_DOCKER_METRICS_ID = 'mz-search-docker-metrics';
const VIS_VPS_RESOURCE_COCKPIT_ID = 'mz-vis-vps-resource-cockpit';
const VIS_VPS_ROOT_TREND_ID = 'mz-vis-vps-root-trend';
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

async function opensearchRequest(
  containerId: string,
  method: 'GET' | 'PUT',
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
    `${OPENSEARCH_BASE_URL}${path}`,
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
    throw new Error(`OpenSearch API call failed: ${result.stderr || result.stdout}`.trim());
  }
  return parseDashboardsApiOutput(result.stdout || '');
}

function isReadOnlyAllowDeleteBlockError(message: string): boolean {
  const lower = String(message || '').toLowerCase();
  return (
    lower.includes('read-only-allow-delete')
    || (lower.includes('cluster_block_exception') && lower.includes('flood-stage watermark'))
  );
}

async function clearReadOnlyAllowDeleteBlocks(containerId: string): Promise<void> {
  const response = await opensearchRequest(containerId, 'PUT', '/_all/_settings', {
    'index.blocks.read_only_allow_delete': null,
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Failed to clear OpenSearch read_only_allow_delete block: ${response.status} ${response.body}`);
  }
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
      query: 'event.module.keyword : "system" and host.name.keyword : vmi*',
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
      { calculate: 'datum.point.key_as_string ? toDate(datum.point.key_as_string) : toDate(datum.point.key)', as: 'timestamp' },
      { calculate: 'isValid(datum.point.cpu_avg) && isValid(datum.point.cpu_avg.value) ? datum.point.cpu_avg.value * 100 : null', as: 'cpu_pct' },
      { filter: 'isValid(datum.timestamp) && isValid(datum.cpu_pct)' },
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
      { calculate: 'datum.point.key_as_string ? toDate(datum.point.key_as_string) : toDate(datum.point.key)', as: 'timestamp' },
      { calculate: 'isValid(datum.point.mem_avg) && isValid(datum.point.mem_avg.value) ? datum.point.mem_avg.value * 100 : null', as: 'mem_pct' },
      { filter: 'isValid(datum.timestamp) && isValid(datum.mem_pct)' },
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

  const vpsResourceCockpitSpec = JSON.parse(
    Buffer.from('eyIkc2NoZW1hIjoiaHR0cHM6Ly92ZWdhLmdpdGh1Yi5pby9zY2hlbWEvdmVnYS1saXRlL3Y1Lmpzb24iLCJhdXRvc2l6ZSI6Im5vbmUiLCJ0aXRsZSI6IlZQUyBSZXNvdXJjZSBDb2NrcGl0IChMaXZlIERpYWwgR2F1Z2VzKSIsImNvbmZpZyI6eyJ2aWV3Ijp7InN0cm9rZSI6bnVsbH0sImF4aXMiOnsidGl0bGUiOm51bGx9fSwiZGF0YSI6eyJ1cmwiOnsiJWNvbnRleHQlIjp0cnVlLCIldGltZWZpZWxkJSI6IkB0aW1lc3RhbXAiLCJpbmRleCI6Im16LW1ldHJpY3MtKiIsImJvZHkiOnsic2l6ZSI6MCwiYWdncyI6eyJob3N0cyI6eyJ0ZXJtcyI6eyJmaWVsZCI6Imhvc3QubmFtZS5rZXl3b3JkIiwiaW5jbHVkZSI6InZtaS4qIiwic2l6ZSI6MTYsIm9yZGVyIjp7Il9rZXkiOiJhc2MifX0sImFnZ3MiOnsiY3B1X2xhdGVzdCI6eyJmaWx0ZXIiOnsiYm9vbCI6eyJtdXN0IjpbeyJ0ZXJtIjp7Im1ldHJpY3NldC5uYW1lLmtleXdvcmQiOiJjcHUifX0seyJleGlzdHMiOnsiZmllbGQiOiJzeXN0ZW0uY3B1LnRvdGFsLm5vcm0ucGN0In19XX19LCJhZ2dzIjp7ImxhdGVzdCI6eyJ0b3BfaGl0cyI6eyJzaXplIjoxLCJzb3J0IjpbeyJAdGltZXN0YW1wIjp7Im9yZGVyIjoiZGVzYyJ9fV0sIl9zb3VyY2UiOnsiaW5jbHVkZXMiOlsic3lzdGVtLmNwdS50b3RhbC5ub3JtLnBjdCJdfX19fX0sIm1lbW9yeV9sYXRlc3QiOnsiZmlsdGVyIjp7ImJvb2wiOnsibXVzdCI6W3sidGVybSI6eyJtZXRyaWNzZXQubmFtZS5rZXl3b3JkIjoibWVtb3J5In19LHsiZXhpc3RzIjp7ImZpZWxkIjoic3lzdGVtLm1lbW9yeS5hY3R1YWwudXNlZC5wY3QifX1dfX0sImFnZ3MiOnsibGF0ZXN0Ijp7InRvcF9oaXRzIjp7InNpemUiOjEsInNvcnQiOlt7IkB0aW1lc3RhbXAiOnsib3JkZXIiOiJkZXNjIn19XSwiX3NvdXJjZSI6eyJpbmNsdWRlcyI6WyJzeXN0ZW0ubWVtb3J5LmFjdHVhbC51c2VkLnBjdCJdfX19fX0sImRpc2tfbGF0ZXN0Ijp7ImZpbHRlciI6eyJib29sIjp7Im11c3QiOlt7InRlcm0iOnsibWV0cmljc2V0Lm5hbWUua2V5d29yZCI6ImZpbGVzeXN0ZW0ifX0seyJleGlzdHMiOnsiZmllbGQiOiJzeXN0ZW0uZmlsZXN5c3RlbS50b3RhbCJ9fSx7ImV4aXN0cyI6eyJmaWVsZCI6InN5c3RlbS5maWxlc3lzdGVtLmF2YWlsYWJsZSJ9fV0sInNob3VsZCI6W3sidGVybSI6eyJzeXN0ZW0uZmlsZXN5c3RlbS5tb3VudF9wb2ludC5rZXl3b3JkIjoiL2hvc3RmcyJ9fSx7InRlcm0iOnsic3lzdGVtLmZpbGVzeXN0ZW0ubW91bnRfcG9pbnQua2V5d29yZCI6Ii8ifX1dLCJtaW5pbXVtX3Nob3VsZF9tYXRjaCI6MX19LCJhZ2dzIjp7ImxhdGVzdCI6eyJ0b3BfaGl0cyI6eyJzaXplIjoxLCJzb3J0IjpbeyJAdGltZXN0YW1wIjp7Im9yZGVyIjoiZGVzYyJ9fV0sIl9zb3VyY2UiOnsiaW5jbHVkZXMiOlsic3lzdGVtLmZpbGVzeXN0ZW0udG90YWwiLCJzeXN0ZW0uZmlsZXN5c3RlbS5hdmFpbGFibGUiLCJzeXN0ZW0uZmlsZXN5c3RlbS51c2VkLnBjdCJdfX19fX19fX19fSwiZm9ybWF0Ijp7InByb3BlcnR5IjoiYWdncmVnYXRpb25zLmhvc3RzLmJ1Y2tldHMifX0sInRyYW5zZm9ybSI6W3siY2FsY3VsYXRlIjoiZGF0dW0ua2V5IiwiYXMiOiJob3N0X2xhYmVsIn0seyJjYWxjdWxhdGUiOiJkYXR1bS5jcHVfbGF0ZXN0ICYmIGRhdHVtLmNwdV9sYXRlc3QubGF0ZXN0ICYmIGRhdHVtLmNwdV9sYXRlc3QubGF0ZXN0LmhpdHMgJiYgZGF0dW0uY3B1X2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzICYmIGRhdHVtLmNwdV9sYXRlc3QubGF0ZXN0LmhpdHMuaGl0cy5sZW5ndGggPiAwID8gZGF0dW0uY3B1X2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzWzBdLl9zb3VyY2Uuc3lzdGVtLmNwdS50b3RhbC5ub3JtLnBjdCAqIDEwMCA6IDAiLCJhcyI6ImNwdV9wY3QifSx7ImNhbGN1bGF0ZSI6ImRhdHVtLm1lbW9yeV9sYXRlc3QgJiYgZGF0dW0ubWVtb3J5X2xhdGVzdC5sYXRlc3QgJiYgZGF0dW0ubWVtb3J5X2xhdGVzdC5sYXRlc3QuaGl0cyAmJiBkYXR1bS5tZW1vcnlfbGF0ZXN0LmxhdGVzdC5oaXRzLmhpdHMgJiYgZGF0dW0ubWVtb3J5X2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzLmxlbmd0aCA+IDAgPyBkYXR1bS5tZW1vcnlfbGF0ZXN0LmxhdGVzdC5oaXRzLmhpdHNbMF0uX3NvdXJjZS5zeXN0ZW0ubWVtb3J5LmFjdHVhbC51c2VkLnBjdCAqIDEwMCA6IDAiLCJhcyI6Im1lbW9yeV9wY3QifSx7ImNhbGN1bGF0ZSI6ImRhdHVtLmRpc2tfbGF0ZXN0ICYmIGRhdHVtLmRpc2tfbGF0ZXN0LmxhdGVzdCAmJiBkYXR1bS5kaXNrX2xhdGVzdC5sYXRlc3QuaGl0cyAmJiBkYXR1bS5kaXNrX2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzICYmIGRhdHVtLmRpc2tfbGF0ZXN0LmxhdGVzdC5oaXRzLmhpdHMubGVuZ3RoID4gMCAmJiBkYXR1bS5kaXNrX2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzWzBdLl9zb3VyY2Uuc3lzdGVtLmZpbGVzeXN0ZW0udG90YWwgPiAwID8gKChkYXR1bS5kaXNrX2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzWzBdLl9zb3VyY2Uuc3lzdGVtLmZpbGVzeXN0ZW0udG90YWwgLSBkYXR1bS5kaXNrX2xhdGVzdC5sYXRlc3QuaGl0cy5oaXRzWzBdLl9zb3VyY2Uuc3lzdGVtLmZpbGVzeXN0ZW0uYXZhaWxhYmxlKSAvIGRhdHVtLmRpc2tfbGF0ZXN0LmxhdGVzdC5oaXRzLmhpdHNbMF0uX3NvdXJjZS5zeXN0ZW0uZmlsZXN5c3RlbS50b3RhbCkgKiAxMDAgOiAoZGF0dW0uZGlza19sYXRlc3QgJiYgZGF0dW0uZGlza19sYXRlc3QubGF0ZXN0ICYmIGRhdHVtLmRpc2tfbGF0ZXN0LmxhdGVzdC5oaXRzICYmIGRhdHVtLmRpc2tfbGF0ZXN0LmxhdGVzdC5oaXRzLmhpdHMgJiYgZGF0dW0uZGlza19sYXRlc3QubGF0ZXN0LmhpdHMuaGl0cy5sZW5ndGggPiAwICYmIGlzVmFsaWQoZGF0dW0uZGlza19sYXRlc3QubGF0ZXN0LmhpdHMuaGl0c1swXS5fc291cmNlLnN5c3RlbS5maWxlc3lzdGVtLnVzZWQucGN0KSA/IGRhdHVtLmRpc2tfbGF0ZXN0LmxhdGVzdC5oaXRzLmhpdHNbMF0uX3NvdXJjZS5zeXN0ZW0uZmlsZXN5c3RlbS51c2VkLnBjdCAqIDEwMCA6IDApIiwiYXMiOiJkaXNrX3BjdCJ9LHsiZm9sZCI6WyJjcHVfcGN0IiwibWVtb3J5X3BjdCIsImRpc2tfcGN0Il0sImFzIjpbIm1ldHJpY19rZXkiLCJ2YWx1ZV9yYXciXX0seyJjYWxjdWxhdGUiOiJkYXR1bS5tZXRyaWNfa2V5ID09PSAnY3B1X3BjdCcgPyAnQ1BVJyA6IGRhdHVtLm1ldHJpY19rZXkgPT09ICdtZW1vcnlfcGN0JyA/ICdNZW1vcnknIDogJ1Jvb3QgRGlzayciLCJhcyI6Im1ldHJpY19sYWJlbCJ9LHsiY2FsY3VsYXRlIjoiZGF0dW0ubWV0cmljX2tleSA9PT0gJ2NwdV9wY3QnID8gMCA6IGRhdHVtLm1ldHJpY19rZXkgPT09ICdtZW1vcnlfcGN0JyA/IDEgOiAyIiwiYXMiOiJtZXRyaWNfaWR4In0seyJ3aW5kb3ciOlt7Im9wIjoiZGVuc2VfcmFuayIsImFzIjoiaG9zdF9pZHgifV0sInNvcnQiOlt7ImZpZWxkIjoiaG9zdF9sYWJlbCIsIm9yZGVyIjoiYXNjZW5kaW5nIn1dfSx7ImpvaW5hZ2dyZWdhdGUiOlt7Im9wIjoibWF4IiwiZmllbGQiOiJob3N0X2lkeCIsImFzIjoiaG9zdF9jb3VudCJ9XX0seyJjYWxjdWxhdGUiOiI4IiwiYXMiOiJob3N0c19wZXJfcm93In0seyJjYWxjdWxhdGUiOiIyMDAiLCJhcyI6ImNvbF9zcGFjaW5nIn0seyJjYWxjdWxhdGUiOiI0MjAiLCJhcyI6InJvd19zcGFjaW5nIn0seyJjYWxjdWxhdGUiOiIxMjAiLCJhcyI6Im1ldHJpY19zcGFjaW5nIn0seyJjYWxjdWxhdGUiOiIoZGF0dW0uaG9zdF9pZHggLSAxKSAlIGRhdHVtLmhvc3RzX3Blcl9yb3ciLCJhcyI6Imhvc3RfY29sIn0seyJjYWxjdWxhdGUiOiJmbG9vcigoZGF0dW0uaG9zdF9pZHggLSAxKSAvIGRhdHVtLmhvc3RzX3Blcl9yb3cpIiwiYXMiOiJob3N0X3JvdyJ9LHsiY2FsY3VsYXRlIjoiKG1pbihkYXR1bS5ob3N0X2NvdW50LCBkYXR1bS5ob3N0c19wZXJfcm93KSAtIDEpICogZGF0dW0uY29sX3NwYWNpbmciLCJhcyI6InJvd19zcGFuIn0seyJjYWxjdWxhdGUiOiI5MCIsImFzIjoieF9zdGFydCJ9LHsiY2FsY3VsYXRlIjoiZGF0dW0ueF9zdGFydCArIGRhdHVtLmhvc3RfY29sICogZGF0dW0uY29sX3NwYWNpbmciLCJhcyI6ImN4In0seyJjYWxjdWxhdGUiOiI4OCArIGRhdHVtLmhvc3Rfcm93ICogZGF0dW0ucm93X3NwYWNpbmcgKyBkYXR1bS5tZXRyaWNfaWR4ICogZGF0dW0ubWV0cmljX3NwYWNpbmciLCJhcyI6ImN5In0seyJjYWxjdWxhdGUiOiJkYXR1bS5jeCAtIDgyIiwiYXMiOiJwYW5lbF94MCJ9LHsiY2FsY3VsYXRlIjoiZGF0dW0uY3ggKyA4MiIsImFzIjoicGFuZWxfeDEifSx7ImNhbGN1bGF0ZSI6ImRhdHVtLmN5IC0gODgiLCJhcyI6InBhbmVsX3kwIn0seyJjYWxjdWxhdGUiOiJkYXR1bS5jeSArIDMwMCIsImFzIjoicGFuZWxfeTEifSx7ImNhbGN1bGF0ZSI6Im1heCgwLCBtaW4oMTAwLCBkYXR1bS52YWx1ZV9yYXcpKSIsImFzIjoidmFsdWUifSx7ImNhbGN1bGF0ZSI6IjMuMTQxNTkyNjUzNTg5NzkzIiwiYXMiOiJzdGFydCJ9LHsiY2FsY3VsYXRlIjoiMCIsImFzIjoiZW5kIn0seyJjYWxjdWxhdGUiOiJkYXR1bS5zdGFydCArIChkYXR1bS52YWx1ZSAvIDEwMCkgKiAoZGF0dW0uZW5kIC0gZGF0dW0uc3RhcnQpIiwiYXMiOiJ2YWx1ZV9lbmQifSx7ImNhbGN1bGF0ZSI6ImRhdHVtLnZhbHVlID49IDkwID8gJyNkYzI2MjYnIDogZGF0dW0udmFsdWUgPj0gNzUgPyAnI2Y1OWUwYicgOiAnIzE2YTM0YSciLCJhcyI6InZhbHVlX2NvbG9yIn0seyJjYWxjdWxhdGUiOiJmb3JtYXQoZGF0dW0udmFsdWUsICcuMWYnKSArICclJyIsImFzIjoidmFsdWVfbGFiZWwifSx7ImNhbGN1bGF0ZSI6ImRhdHVtLm1ldHJpY19pZHggPT09IDAgPyBkYXR1bS5ob3N0X2xhYmVsIDogJyciLCJhcyI6Imhvc3RfbGFiZWxfb25jZSJ9XSwid2lkdGgiOjE2ODAsImhlaWdodCI6OTIwLCJsYXllciI6W3sidHJhbnNmb3JtIjpbeyJmaWx0ZXIiOiJkYXR1bS5tZXRyaWNfaWR4ID09PSAwIn1dLCJtYXJrIjp7InR5cGUiOiJyZWN0IiwiY29ybmVyUmFkaXVzIjoxMiwic3Ryb2tlIjoiI2QxZDVkYiIsInN0cm9rZVdpZHRoIjoxLCJmaWxsIjoiI2Y4ZmFmYyIsIm9wYWNpdHkiOjF9LCJlbmNvZGluZyI6eyJ4Ijp7ImZpZWxkIjoicGFuZWxfeDAiLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwiYXhpcyI6bnVsbCwic2NhbGUiOm51bGx9LCJ4MiI6eyJmaWVsZCI6InBhbmVsX3gxIn0sInkiOnsiZmllbGQiOiJwYW5lbF95MCIsInR5cGUiOiJxdWFudGl0YXRpdmUiLCJheGlzIjpudWxsLCJzY2FsZSI6bnVsbH0sInkyIjp7ImZpZWxkIjoicGFuZWxfeTEifX19LHsibWFyayI6eyJ0eXBlIjoiYXJjIiwiaW5uZXJSYWRpdXMiOjMwLCJvdXRlclJhZGl1cyI6NDMsImNvcm5lclJhZGl1cyI6NCwiY29sb3IiOiIjZDFkNWRiIn0sImVuY29kaW5nIjp7IngiOnsiZmllbGQiOiJjeCIsInR5cGUiOiJxdWFudGl0YXRpdmUiLCJheGlzIjpudWxsLCJzY2FsZSI6bnVsbH0sInkiOnsiZmllbGQiOiJjeSIsInR5cGUiOiJxdWFudGl0YXRpdmUiLCJheGlzIjpudWxsLCJzY2FsZSI6bnVsbH0sInRoZXRhIjp7ImZpZWxkIjoiZW5kIiwidHlwZSI6InF1YW50aXRhdGl2ZSIsInNjYWxlIjpudWxsfSwidGhldGEyIjp7ImZpZWxkIjoic3RhcnQiLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwic2NhbGUiOm51bGx9fX0seyJtYXJrIjp7InR5cGUiOiJhcmMiLCJpbm5lclJhZGl1cyI6MzAsIm91dGVyUmFkaXVzIjo0MywiY29ybmVyUmFkaXVzIjo0fSwiZW5jb2RpbmciOnsieCI6eyJmaWVsZCI6ImN4IiwidHlwZSI6InF1YW50aXRhdGl2ZSIsImF4aXMiOm51bGwsInNjYWxlIjpudWxsfSwieSI6eyJmaWVsZCI6ImN5IiwidHlwZSI6InF1YW50aXRhdGl2ZSIsImF4aXMiOm51bGwsInNjYWxlIjpudWxsfSwidGhldGEiOnsiZmllbGQiOiJ2YWx1ZV9lbmQiLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwic2NhbGUiOm51bGx9LCJ0aGV0YTIiOnsiZmllbGQiOiJzdGFydCIsInR5cGUiOiJxdWFudGl0YXRpdmUiLCJzY2FsZSI6bnVsbH0sImNvbG9yIjp7ImZpZWxkIjoidmFsdWVfY29sb3IiLCJ0eXBlIjoibm9taW5hbCIsInNjYWxlIjpudWxsLCJsZWdlbmQiOm51bGx9LCJ0b29sdGlwIjpbeyJmaWVsZCI6Imhvc3RfbGFiZWwiLCJ0eXBlIjoibm9taW5hbCIsInRpdGxlIjoiVlBTIn0seyJmaWVsZCI6Im1ldHJpY19sYWJlbCIsInR5cGUiOiJub21pbmFsIiwidGl0bGUiOiJNZXRyaWMifSx7ImZpZWxkIjoidmFsdWUiLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwidGl0bGUiOiJVc2VkICUiLCJmb3JtYXQiOiIuMWYifV19fSx7Im1hcmsiOnsidHlwZSI6InRleHQiLCJmb250U2l6ZSI6MTUsImZvbnRXZWlnaHQiOiJib2xkIiwiY29sb3IiOiIjMTExODI3In0sImVuY29kaW5nIjp7IngiOnsiZmllbGQiOiJjeCIsInR5cGUiOiJxdWFudGl0YXRpdmUiLCJheGlzIjpudWxsLCJzY2FsZSI6bnVsbH0sInkiOnsiZmllbGQiOiJjeSIsInR5cGUiOiJxdWFudGl0YXRpdmUiLCJheGlzIjpudWxsLCJzY2FsZSI6bnVsbH0sInRleHQiOnsiZmllbGQiOiJ2YWx1ZV9sYWJlbCJ9fX0seyJtYXJrIjp7InR5cGUiOiJ0ZXh0IiwiZm9udFNpemUiOjExLCJjb2xvciI6IiM0YjU1NjMiLCJkeSI6NTV9LCJlbmNvZGluZyI6eyJ4Ijp7ImZpZWxkIjoiY3giLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwiYXhpcyI6bnVsbCwic2NhbGUiOm51bGx9LCJ5Ijp7ImZpZWxkIjoiY3kiLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwiYXhpcyI6bnVsbCwic2NhbGUiOm51bGx9LCJ0ZXh0Ijp7ImZpZWxkIjoibWV0cmljX2xhYmVsIn19fSx7InRyYW5zZm9ybSI6W3siZmlsdGVyIjoiZGF0dW0ubWV0cmljX2lkeCA9PT0gMCJ9XSwibWFyayI6eyJ0eXBlIjoidGV4dCIsImZvbnRTaXplIjoxMywiZm9udFdlaWdodCI6ImJvbGQiLCJjb2xvciI6IiMxMTE4MjciLCJhbGlnbiI6ImNlbnRlciIsImR5IjotNjZ9LCJlbmNvZGluZyI6eyJ4Ijp7ImZpZWxkIjoiY3giLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwiYXhpcyI6bnVsbCwic2NhbGUiOm51bGx9LCJ5Ijp7ImZpZWxkIjoiY3kiLCJ0eXBlIjoicXVhbnRpdGF0aXZlIiwiYXhpcyI6bnVsbCwic2NhbGUiOm51bGx9LCJ0ZXh0Ijp7ImZpZWxkIjoiaG9zdF9sYWJlbF9vbmNlIn19fV19Cg==', 'base64').toString('utf8'),
  ) as Record<string, unknown>;
  const cockpitSpecMutable = vpsResourceCockpitSpec as {
    title?: unknown;
    height?: unknown;
    transform?: Array<Record<string, unknown>>;
    layer?: Array<Record<string, unknown>>;
  };
  cockpitSpecMutable.title = 'VPS Resource Snapshot (%)';
  if (typeof cockpitSpecMutable.height === 'number') {
    cockpitSpecMutable.height = 380;
  }
  const cockpitTransforms = cockpitSpecMutable.transform;
  if (Array.isArray(cockpitTransforms)) {
    for (const transform of cockpitTransforms) {
      if (transform.as === 'row_spacing') {
        transform.calculate = '360';
      } else if (transform.as === 'metric_spacing') {
        transform.calculate = '104';
      } else if (transform.as === 'panel_y0') {
        transform.calculate = 'datum.cy - 78';
      } else if (transform.as === 'panel_y1') {
        transform.calculate = 'datum.cy + 256';
      } else if (transform.as === 'value_label') {
        transform.calculate = "format(round(datum.value), '.0f') + '%'";
      }
    }
  }
  const cockpitLayers = cockpitSpecMutable.layer;
  if (Array.isArray(cockpitLayers)) {
    for (const layer of cockpitLayers) {
      const encoding = (layer.encoding && typeof layer.encoding === 'object')
        ? (layer.encoding as Record<string, unknown>)
        : null;
      const text = (encoding?.text && typeof encoding.text === 'object')
        ? (encoding.text as Record<string, unknown>)
        : null;
      const textField = typeof text?.field === 'string' ? text.field : '';
      if (!textField) {
        continue;
      }
      const mark = (layer.mark && typeof layer.mark === 'object')
        ? (layer.mark as Record<string, unknown>)
        : {};
      if (textField === 'metric_label') {
        mark.align = 'right';
        mark.baseline = 'middle';
        mark.dx = -14;
        delete mark.dy;
        layer.mark = mark;
      } else if (textField === 'value_label') {
        mark.align = 'left';
        mark.baseline = 'middle';
        mark.dx = -8;
        delete mark.dy;
        layer.mark = mark;
      }
    }
  }

  const vpsRootTrendSpec = JSON.parse(
    Buffer.from('ewogICIkc2NoZW1hIjogImh0dHBzOi8vdmVnYS5naXRodWIuaW8vc2NoZW1hL3ZlZ2EtbGl0ZS92NS5qc29uIiwKICAidGl0bGUiOiAiVlBTIFJvb3QgVXNhZ2UgVHJlbmQgYnkgSG9zdCIsCiAgImRhdGEiOiB7CiAgICAidXJsIjogewogICAgICAiJWNvbnRleHQlIjogdHJ1ZSwKICAgICAgIiV0aW1lZmllbGQlIjogIkB0aW1lc3RhbXAiLAogICAgICAiaW5kZXgiOiAibXotbWV0cmljcy0qIiwKICAgICAgImJvZHkiOiB7CiAgICAgICAgInNpemUiOiAwLAogICAgICAgICJhZ2dzIjogewogICAgICAgICAgImZpbHRlcmVkIjogewogICAgICAgICAgICAiZmlsdGVyIjogewogICAgICAgICAgICAgICJib29sIjogewogICAgICAgICAgICAgICAgIm11c3QiOiBbCiAgICAgICAgICAgICAgICAgIHsgInRlcm0iOiB7ICJldmVudC5tb2R1bGUua2V5d29yZCI6ICJzeXN0ZW0iIH0gfSwKICAgICAgICAgICAgICAgICAgeyAicHJlZml4IjogeyAiaG9zdC5uYW1lLmtleXdvcmQiOiAidm1pIiB9IH0sCiAgICAgICAgICAgICAgICAgIHsgInRlcm0iOiB7ICJtZXRyaWNzZXQubmFtZS5rZXl3b3JkIjogImZpbGVzeXN0ZW0iIH0gfSwKICAgICAgICAgICAgICAgICAgeyAiZXhpc3RzIjogeyAiZmllbGQiOiAic3lzdGVtLmZpbGVzeXN0ZW0udG90YWwiIH0gfSwKICAgICAgICAgICAgICAgICAgeyAiZXhpc3RzIjogeyAiZmllbGQiOiAic3lzdGVtLmZpbGVzeXN0ZW0uYXZhaWxhYmxlIiB9IH0KICAgICAgICAgICAgICAgIF0sCiAgICAgICAgICAgICAgICAic2hvdWxkIjogWwogICAgICAgICAgICAgICAgICB7ICJ0ZXJtIjogeyAic3lzdGVtLmZpbGVzeXN0ZW0ubW91bnRfcG9pbnQua2V5d29yZCI6ICIvaG9zdGZzIiB9IH0sCiAgICAgICAgICAgICAgICAgIHsgInRlcm0iOiB7ICJzeXN0ZW0uZmlsZXN5c3RlbS5tb3VudF9wb2ludC5rZXl3b3JkIjogIi8iIH0gfQogICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgICAgICJtaW5pbXVtX3Nob3VsZF9tYXRjaCI6IDEKICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJhZ2dzIjogewogICAgICAgICAgICAgICJob3N0cyI6IHsKICAgICAgICAgICAgICAgICJ0ZXJtcyI6IHsKICAgICAgICAgICAgICAgICAgImZpZWxkIjogImhvc3QubmFtZS5rZXl3b3JkIiwKICAgICAgICAgICAgICAgICAgInNpemUiOiA4LAogICAgICAgICAgICAgICAgICAib3JkZXIiOiB7ICJfa2V5IjogImFzYyIgfQogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJhZ2dzIjogewogICAgICAgICAgICAgICAgICAidGltZWxpbmUiOiB7CiAgICAgICAgICAgICAgICAgICAgImRhdGVfaGlzdG9ncmFtIjogewogICAgICAgICAgICAgICAgICAgICAgImZpZWxkIjogIkB0aW1lc3RhbXAiLAogICAgICAgICAgICAgICAgICAgICAgImZpeGVkX2ludGVydmFsIjogIjFtIiwKICAgICAgICAgICAgICAgICAgICAgICJtaW5fZG9jX2NvdW50IjogMAogICAgICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAgICAgImFnZ3MiOiB7CiAgICAgICAgICAgICAgICAgICAgICAidG90YWxfYXZnIjogeyAiYXZnIjogeyAiZmllbGQiOiAic3lzdGVtLmZpbGVzeXN0ZW0udG90YWwiIH0gfSwKICAgICAgICAgICAgICAgICAgICAgICJhdmFpbGFibGVfYXZnIjogeyAiYXZnIjogeyAiZmllbGQiOiAic3lzdGVtLmZpbGVzeXN0ZW0uYXZhaWxhYmxlIiB9IH0sCiAgICAgICAgICAgICAgICAgICAgICAicm9vdF91c2VkX3BjdCI6IHsKICAgICAgICAgICAgICAgICAgICAgICAgImJ1Y2tldF9zY3JpcHQiOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgImJ1Y2tldHNfcGF0aCI6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICJ0b3RhbCI6ICJ0b3RhbF9hdmciLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgImF2YWlsYWJsZSI6ICJhdmFpbGFibGVfYXZnIgogICAgICAgICAgICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgInNjcmlwdCI6ICJwYXJhbXMudG90YWwgPiAwID8gKHBhcmFtcy50b3RhbCAtIHBhcmFtcy5hdmFpbGFibGUpIC8gcGFyYW1zLnRvdGFsIDogbnVsbCIKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgfQogICAgfSwKICAgICJmb3JtYXQiOiB7ICJwcm9wZXJ0eSI6ICJhZ2dyZWdhdGlvbnMuZmlsdGVyZWQuaG9zdHMuYnVja2V0cyIgfQogIH0sCiAgInRyYW5zZm9ybSI6IFsKICAgIHsgImZsYXR0ZW4iOiBbInRpbWVsaW5lLmJ1Y2tldHMiXSwgImFzIjogWyJwb2ludCJdIH0sCiAgICB7ICJjYWxjdWxhdGUiOiAiZGF0dW0ua2V5IiwgImFzIjogImhvc3RfbGFiZWwiIH0sCiAgICB7ICJjYWxjdWxhdGUiOiAiZGF0dW0ucG9pbnQua2V5X2FzX3N0cmluZyA/IHRvRGF0ZShkYXR1bS5wb2ludC5rZXlfYXNfc3RyaW5nKSA6IHRvRGF0ZShkYXR1bS5wb2ludC5rZXkpIiwgImFzIjogInRpbWVzdGFtcCIgfSwKICAgIHsgImNhbGN1bGF0ZSI6ICJpc1ZhbGlkKGRhdHVtLnBvaW50LnJvb3RfdXNlZF9wY3QpICYmIGlzVmFsaWQoZGF0dW0ucG9pbnQucm9vdF91c2VkX3BjdC52YWx1ZSkgPyBkYXR1bS5wb2ludC5yb290X3VzZWRfcGN0LnZhbHVlICogMTAwIDogbnVsbCIsICJhcyI6ICJyb290X3BjdCIgfSwKICAgIHsgImZpbHRlciI6ICJpc1ZhbGlkKGRhdHVtLnRpbWVzdGFtcCkgJiYgaXNWYWxpZChkYXR1bS5yb290X3BjdCkiIH0KICBdLAogICJtYXJrIjogeyAidHlwZSI6ICJsaW5lIiwgInBvaW50IjogZmFsc2UgfSwKICAiZW5jb2RpbmciOiB7CiAgICAieCI6IHsgImZpZWxkIjogInRpbWVzdGFtcCIsICJ0eXBlIjogInRlbXBvcmFsIiwgInRpdGxlIjogIlRpbWUiIH0sCiAgICAieSI6IHsKICAgICAgImZpZWxkIjogInJvb3RfcGN0IiwKICAgICAgInR5cGUiOiAicXVhbnRpdGF0aXZlIiwKICAgICAgInRpdGxlIjogIlJvb3QgRGlzayAlIiwKICAgICAgInNjYWxlIjogeyAiZG9tYWluIjogWzAsIDEwMF0gfQogICAgfSwKICAgICJjb2xvciI6IHsKICAgICAgImZpZWxkIjogImhvc3RfbGFiZWwiLAogICAgICAidHlwZSI6ICJub21pbmFsIiwKICAgICAgInNjYWxlIjogewogICAgICAgICJkb21haW4iOiBbInZtaTI5OTY2OTgiLCAidm1pMjk5NjY5OSJdLAogICAgICAgICJyYW5nZSI6IFsiIzU0QjM5OSIsICIjNjA5MkMwIl0KICAgICAgfSwKICAgICAgImxlZ2VuZCI6IHsgInRpdGxlIjogIkhvc3QiIH0KICAgIH0sCiAgICAidG9vbHRpcCI6IFsKICAgICAgeyAiZmllbGQiOiAidGltZXN0YW1wIiwgInR5cGUiOiAidGVtcG9yYWwiLCAidGl0bGUiOiAiVGltZSIgfSwKICAgICAgeyAiZmllbGQiOiAiaG9zdF9sYWJlbCIsICJ0eXBlIjogIm5vbWluYWwiLCAidGl0bGUiOiAiSG9zdCIgfSwKICAgICAgeyAiZmllbGQiOiAicm9vdF9wY3QiLCAidHlwZSI6ICJxdWFudGl0YXRpdmUiLCAidGl0bGUiOiAiUm9vdCBEaXNrICUiLCAiZm9ybWF0IjogIi4yZiIgfQogICAgXQogIH0KfQoK', 'base64').toString('utf8'),
  ) as Record<string, unknown>;
  const rootTrendEncoding = (vpsRootTrendSpec.encoding && typeof vpsRootTrendSpec.encoding === 'object')
    ? (vpsRootTrendSpec.encoding as Record<string, unknown>)
    : null;
  const rootTrendColor = (rootTrendEncoding?.color && typeof rootTrendEncoding.color === 'object')
    ? (rootTrendEncoding.color as Record<string, unknown>)
    : null;
  const rootTrendColorScale = (rootTrendColor?.scale && typeof rootTrendColor.scale === 'object')
    ? (rootTrendColor.scale as Record<string, unknown>)
    : null;
  if (rootTrendColorScale) {
    delete rootTrendColorScale.domain;
    delete rootTrendColorScale.range;
  }

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
      gridData: { x: 0, y: 0, w: 48, h: 15, i: '1' },
      type: 'visualization',
      id: VIS_VPS_RESOURCE_COCKPIT_ID,
      embeddableConfig: {},
      version: '2.12.0',
    },
    {
      panelIndex: '2',
      gridData: { x: 0, y: 15, w: 16, h: 14, i: '2' },
      type: 'visualization',
      id: VIS_VPS_CPU_TREND_ID,
      embeddableConfig: {},
      version: '2.12.0',
    },
    {
      panelIndex: '3',
      gridData: { x: 16, y: 15, w: 16, h: 14, i: '3' },
      type: 'visualization',
      id: VIS_VPS_MEM_TREND_ID,
      embeddableConfig: {},
      version: '2.12.0',
    },
    {
      panelIndex: '4',
      gridData: { x: 32, y: 15, w: 16, h: 14, i: '4' },
      type: 'visualization',
      id: VIS_VPS_ROOT_TREND_ID,
      embeddableConfig: {},
      version: '2.12.0',
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
      id: VIS_VPS_RESOURCE_COCKPIT_ID,
      attributes: {
        title: 'VPS Resource Snapshot (%)',
        visState: JSON.stringify({
          title: 'VPS Resource Snapshot (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(vpsResourceCockpitSpec) },
        }),
        uiStateJSON: '{}',
        description: 'CPU, memory, and root disk live dial gauges per VPS.',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: JSON.stringify({
            index: DATA_VIEW_METRICS_ID,
            query: { language: 'kuery', query: '' },
            filter: [],
          }),
        },
      },
    },
    {
      type: 'visualization',
      id: VIS_VPS_ROOT_TREND_ID,
      attributes: {
        title: 'VPS Root Usage Trend by Host (%)',
        visState: JSON.stringify({
          title: 'VPS Root Usage Trend by Host (%)',
          type: 'vega',
          aggs: [],
          params: { spec: JSON.stringify(vpsRootTrendSpec) },
        }),
        uiStateJSON: '{}',
        description: '',
        version: 1,
        kibanaSavedObjectMeta: {
          searchSourceJSON: JSON.stringify({
            index: DATA_VIEW_METRICS_ID,
            query: { language: 'kuery', query: 'event.module.keyword : "system"' },
            filter: [],
          }),
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
        title: '1) Server Group',
        hits: 0,
        description: 'Infrastructure monitoring dashboard for server group KPIs.',
        panelsJSON: operationsDashboardPanels,
        optionsJSON: JSON.stringify({
          useMargins: true,
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
        title: '2) Containers',
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

  const runBootstrap = async () => {
    for (const deprecatedObject of DEPRECATED_SAVED_OBJECTS) {
      await deleteSavedObjectIfExists(containerId, deprecatedObject.type, deprecatedObject.id);
    }

    const objects = buildSavedObjects();
    for (const object of objects) {
      await upsertSavedObject(containerId, object);
    }
    return objects.length;
  };

  let upsertedObjects = 0;
  try {
    upsertedObjects = await runBootstrap();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!isReadOnlyAllowDeleteBlockError(message)) {
      throw error;
    }
    await clearReadOnlyAllowDeleteBlocks(containerId);
    upsertedObjects = await runBootstrap();
  }

  return {
    dashboard_id: DASHBOARD_OPS_ID,
    dashboard_ids: [DASHBOARD_OPS_ID, DASHBOARD_MAGENTO_CONTAINERS_ID],
    upserted_objects: upsertedObjects,
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
