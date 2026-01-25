import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import type {
  CapacityNode,
  InspectionMetricValue,
  PlannerInspectionPayload,
  PlannerInspectionService,
  PlannerResources,
  PlannerTuningPayload,
  PlannerTuningProfile,
} from './planner-types.js';
import {
  applyAiAdjustments,
  buildCandidateProfile,
  buildTuningProfiles,
  cloneTuningProfile,
  createBaseProfile,
  isRecommendationDue,
  loadTuningProfiles,
  pruneApprovedProfiles,
  saveTuningProfiles,
  TUNING_INTERVAL_MS,
  type AiTuningProfile,
} from './tuning.js';

export type StatusConfig = {
  stack_id?: number;
  stack_domain?: string;
  stack_name?: string;
  magento_base_url?: string;
  mz_control_base_url?: string;
  node_hostname?: string;
  nodes?: Array<{ node_id: number; hostname?: string; role?: string }>;
};

type SwarmNode = {
  id?: string;
  hostname?: string;
  status?: string;
  availability?: string;
  role?: string;
  labels?: Record<string, string>;
  address?: string;
};

type SwarmSummary = {
  total: number;
  managers: number;
  workers: number;
  nodes: SwarmNode[];
};

type CapacityService = {
  id?: string;
  name?: string;
  mode?: string;
  constraints?: string[];
  reservations?: {
    cpu_cores: number;
    memory_bytes: number;
  };
};

type CapacityTotals = {
  cpu_cores: number;
  memory_bytes: number;
  reserved_cpu_cores: number;
  reserved_memory_bytes: number;
  free_cpu_cores: number;
  free_memory_bytes: number;
};

type PlannerRecommendation = {
  type: string;
  message: string;
  node_id?: string;
  labels?: Record<string, string>;
};

type PlannerPayload = {
  generated_at: string;
  control_available: boolean;
  summary: {
    node_count: number;
    ready_count: number;
    manager_count: number;
    worker_count: number;
  };
  capacity: {
    totals: {
      cpu_cores: number;
      memory_bytes: number;
    };
    nodes: Array<{
      id?: string;
      hostname?: string;
      role?: string;
      cpu_cores: number;
      memory_bytes: number;
    }>;
  };
  placements: {
    primary_manager_node_id: string | null;
    database_node_id: string | null;
    search_node_id: string | null;
    database_replica_node_id: string | null;
  };
  headroom: {
    free_cpu_cores: number;
    free_memory_bytes: number;
    free_cpu_ratio: number;
    free_memory_ratio: number;
  };
  resources: PlannerResources;
  inspection: PlannerInspectionPayload;
  tuning: PlannerTuningPayload;
  warnings: string[];
  recommendations: PlannerRecommendation[];
};

type TuningApprovalRequest = {
  profile_id?: string;
};

type InspectionHistoryEntry = {
  captured_at: string;
  inspection: PlannerInspectionPayload;
};

type ServiceHealthCounts = {
  healthy: number;
  unhealthy: number;
  starting: number;
  none: number;
};

type ServiceStateCounts = {
  running: number;
  pending: number;
  failed: number;
  rejected: number;
  shutdown: number;
};

type ServiceStatus = {
  id?: string;
  name?: string;
  service?: string;
  environment_id?: number;
  mode?: string;
  desired_replicas: number;
  running_replicas: number;
  health: ServiceHealthCounts;
  state_counts: ServiceStateCounts;
  nodes: Array<{ id?: string; hostname?: string; count: number }>;
  restart_count: number;
  last_error?: string;
  last_error_at?: string;
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
};

type ServiceStatusPayload = {
  generated_at: string;
  control_available: boolean;
  services: ServiceStatus[];
};

type LocalSwarmInfo = {
  localNodeState?: string;
  controlAvailable?: boolean;
  nodeId?: string;
};

const CONFIG_PATH = process.env.STATUS_CONFIG_PATH || '/opt/status/data.json';
const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
const VERSION_PATH = process.env.MZ_SWARM_AGENT_VERSION_PATH
  || '/opt/mage-zero/agent/version';
const AI_TUNING_DISABLED = process.env.MZ_AI_TUNING_DISABLED === '1';
const INSPECTION_HISTORY_PATH = process.env.MZ_INSPECTION_HISTORY_PATH
  || `${NODE_DIR}/inspection-history.json`;
const INSPECTION_INTERVAL_MS = Number(process.env.MZ_INSPECTION_INTERVAL_MS || 60 * 60 * 1000);
const INSPECTION_RETENTION_MS = Number(process.env.MZ_INSPECTION_RETENTION_MS || 24 * 60 * 60 * 1000);
const MIB = 1024 * 1024;
const GIB = 1024 * 1024 * 1024;

let cachedAgentVersion: string | null = null;

let cachedDockerApiVersion: string | null = null;
let cachedDockerApiVersionAt = 0;

export function readConfig(): StatusConfig {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) as StatusConfig;
  } catch {
    return { stack_domain: '', nodes: [] };
  }
}

function readAgentVersion(): string {
  if (cachedAgentVersion) {
    return cachedAgentVersion;
  }
  const envVersion = process.env.MZ_SWARM_AGENT_VERSION;
  if (envVersion) {
    cachedAgentVersion = envVersion.trim();
    return cachedAgentVersion;
  }
  try {
    const fileVersion = fs.readFileSync(VERSION_PATH, 'utf8').trim();
    if (fileVersion) {
      cachedAgentVersion = fileVersion;
      return cachedAgentVersion;
    }
  } catch {
    // ignore missing file
  }
  cachedAgentVersion = 'unknown';
  return cachedAgentVersion;
}

type DockerRequestOptions = {
  method?: string;
  body?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  parseJson?: boolean;
};

function dockerRequestWithOptions(path: string, options: DockerRequestOptions = {}): Promise<any> {
  return new Promise((resolve, reject) => {
    const method = options.method || 'GET';
    const parseJson = options.parseJson !== false;
    const body = options.body || '';
    const headers: Record<string, string> = {
      Host: 'docker',
      Connection: 'close',
      ...options.headers,
    };
    if (body) {
      headers['Content-Length'] = Buffer.byteLength(body).toString();
    }
    const req = http.request(
      {
        socketPath: DOCKER_SOCKET,
        path,
        method,
        headers,
        timeout: options.timeoutMs || 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          if (!parseJson) {
            resolve(buffer);
            return;
          }
          const bodyText = buffer.toString('utf8');
          try {
            resolve(JSON.parse(bodyText));
          } catch (err) {
            reject(err);
          }
        });
      },
    );

    req.on('timeout', () => {
      req.destroy(new Error('Docker socket timeout'));
    });
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function dockerRequest(path: string): Promise<any> {
  return dockerRequestWithOptions(path);
}

async function getDockerApiVersion(): Promise<string> {
  if (cachedDockerApiVersion && Date.now() - cachedDockerApiVersionAt < 5 * 60 * 1000) {
    return cachedDockerApiVersion;
  }

  const fallback = process.env.DOCKER_API_VERSION || 'v1.41';
  const normalizedFallback = fallback.startsWith('v') ? fallback : `v${fallback}`;

  try {
    const versionInfo = await dockerRequest('/version');
    if (versionInfo && versionInfo.ApiVersion) {
      cachedDockerApiVersion = `v${String(versionInfo.ApiVersion).replace(/^v/, '')}`;
      cachedDockerApiVersionAt = Date.now();
      return cachedDockerApiVersion;
    }
  } catch {
    // ignore and try fallback
  }

  try {
    const versionInfo = await dockerRequest(`/${normalizedFallback}/version`);
    if (versionInfo && versionInfo.ApiVersion) {
      cachedDockerApiVersion = `v${String(versionInfo.ApiVersion).replace(/^v/, '')}`;
      cachedDockerApiVersionAt = Date.now();
      return cachedDockerApiVersion;
    }
  } catch {
    // ignore and use fallback
  }

  return normalizedFallback;
}

function toCpuCores(nanoCpus?: number): number {
  if (!nanoCpus || Number.isNaN(nanoCpus)) {
    return 0;
  }
  return nanoCpus / 1_000_000_000;
}

function demuxDockerStream(buffer: Buffer) {
  if (!buffer || buffer.length < 8) {
    return { stdout: buffer.toString('utf8'), stderr: '' };
  }
  let stdout = '';
  let stderr = '';
  let offset = 0;
  while (offset + 8 <= buffer.length) {
    const streamType = buffer[offset];
    const chunkSize = buffer.readUInt32BE(offset + 4);
    const start = offset + 8;
    const end = start + chunkSize;
    if (end > buffer.length) {
      break;
    }
    const chunk = buffer.slice(start, end).toString('utf8');
    if (streamType === 1) {
      stdout += chunk;
    } else if (streamType === 2) {
      stderr += chunk;
    }
    offset = end;
  }
  if (offset === 0) {
    return { stdout: buffer.toString('utf8'), stderr: '' };
  }
  return { stdout, stderr };
}

function calculateCpuPercent(stats: any): number {
  const cpuTotal = stats?.cpu_stats?.cpu_usage?.total_usage ?? 0;
  const cpuTotalPrev = stats?.precpu_stats?.cpu_usage?.total_usage ?? 0;
  const systemTotal = stats?.cpu_stats?.system_cpu_usage ?? 0;
  const systemPrev = stats?.precpu_stats?.system_cpu_usage ?? 0;
  const cpuDelta = cpuTotal - cpuTotalPrev;
  const systemDelta = systemTotal - systemPrev;
  const onlineCpus = stats?.cpu_stats?.online_cpus
    || stats?.cpu_stats?.cpu_usage?.percpu_usage?.length
    || 0;
  if (cpuDelta > 0 && systemDelta > 0 && onlineCpus > 0) {
    return (cpuDelta / systemDelta) * onlineCpus * 100;
  }
  return 0;
}

async function execContainerCommand(containerId: string, cmd: string[], timeoutMs = 5000) {
  const apiVersion = await getDockerApiVersion();
  const createBody = JSON.stringify({
    AttachStdout: true,
    AttachStderr: true,
    Tty: false,
    Cmd: cmd,
  });
  const execCreate = await dockerRequestWithOptions(`/${apiVersion}/containers/${containerId}/exec`, {
    method: 'POST',
    body: createBody,
    headers: { 'Content-Type': 'application/json' },
  });
  const execId = execCreate?.Id;
  if (!execId) {
    throw new Error('docker exec create failed');
  }
  const startBody = JSON.stringify({ Detach: false, Tty: false });
  const outputBuffer = await dockerRequestWithOptions(`/${apiVersion}/exec/${execId}/start`, {
    method: 'POST',
    body: startBody,
    headers: { 'Content-Type': 'application/json' },
    parseJson: false,
    timeoutMs,
  });
  const execInspect = await dockerRequestWithOptions(`/${apiVersion}/exec/${execId}/json`);
  const output = demuxDockerStream(Buffer.isBuffer(outputBuffer) ? outputBuffer : Buffer.from(String(outputBuffer)));
  return {
    stdout: output.stdout.trim(),
    stderr: output.stderr.trim(),
    exitCode: typeof execInspect?.ExitCode === 'number' ? execInspect.ExitCode : null,
  };
}

function normalizeLocalSwarmInfo(info: any): LocalSwarmInfo {
  const swarm = info?.Swarm || {};
  return {
    localNodeState: swarm.LocalNodeState ? String(swarm.LocalNodeState) : '',
    controlAvailable: Boolean(swarm.ControlAvailable),
    nodeId: swarm.NodeID ? String(swarm.NodeID) : '',
  };
}

async function getLocalSwarmInfo(): Promise<LocalSwarmInfo> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return {};
  }

  try {
    const info = await dockerRequest('/info');
    return normalizeLocalSwarmInfo(info);
  } catch {
    // ignore and retry with versioned path
  }

  try {
    const apiVersion = await getDockerApiVersion();
    const info = await dockerRequest(`/${apiVersion}/info`);
    return normalizeLocalSwarmInfo(info);
  } catch {
    return {};
  }
}

export async function isSwarmManager(): Promise<boolean> {
  const local = await getLocalSwarmInfo();
  return local.controlAvailable === true;
}

function summarizeNodes(nodes: any[]): SwarmSummary {
  const managers = nodes.filter((node) => node.ManagerStatus && node.ManagerStatus.Leader !== undefined);
  const workers = nodes.filter((node) => !node.ManagerStatus);
  return {
    total: nodes.length,
    managers: managers.length,
    workers: workers.length,
    nodes: nodes.map((node) => ({
      id: node.ID,
      hostname: node.Description?.Hostname,
      status: node.Status?.State,
      availability: node.Spec?.Availability,
      role: node.Spec?.Role,
      labels: node.Spec?.Labels || {},
      address: node.Status?.Addr,
    })),
  };
}

function mapSwarmNodes(configNodes: StatusConfig['nodes'], swarmNodes: SwarmNode[]) {
  const assignments = new Map<number, SwarmNode>();
  const availableManagers = swarmNodes
    .filter((node) => node.role === 'manager')
    .sort((a, b) => String(a.hostname || '').localeCompare(String(b.hostname || '')));
  const availableWorkers = swarmNodes
    .filter((node) => node.role !== 'manager')
    .sort((a, b) => String(a.hostname || '').localeCompare(String(b.hostname || '')));

  const removeNode = (list: SwarmNode[], node: SwarmNode) => {
    const idx = list.indexOf(node);
    if (idx >= 0) {
      list.splice(idx, 1);
    }
  };

  for (const configNode of configNodes || []) {
    let match = swarmNodes.find((node) => node.labels?.['mz.node_id'] === String(configNode.node_id));
    if (!match && configNode.hostname) {
      match = swarmNodes.find((node) => node.labels?.['mz.node_hostname'] === configNode.hostname);
    }
    if (match) {
      assignments.set(configNode.node_id, match);
      removeNode(availableManagers, match);
      removeNode(availableWorkers, match);
      continue;
    }

    const role = String(configNode.role || '').toLowerCase();
    if (role === 'manager' && availableManagers.length) {
      assignments.set(configNode.node_id, availableManagers.shift()!);
    } else if (role === 'worker' && availableWorkers.length) {
      assignments.set(configNode.node_id, availableWorkers.shift()!);
    }
  }

  return assignments;
}

function escapeHtml(value: string) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function readNodeFile(filename: string) {
  try {
    return fs.readFileSync(`${NODE_DIR}/${filename}`, 'utf8').trim();
  } catch {
    return '';
  }
}

function readCloudInitStatus() {
  try {
    const raw = fs.readFileSync(`${NODE_DIR}/cloud-init.status`, 'utf8').trim();
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const cleaned = { ...parsed } as Record<string, unknown>;
    const display = String(cleaned.display_status || cleaned.status || '').toLowerCase();
    if (display === 'running') {
      cleaned.display_status = 'done';
      cleaned.status = 'done';
      cleaned.note = cleaned.note
        ? `${cleaned.note}; mapped running to done for Contabo image`
        : 'Cloud-init running mapped to done for Contabo image';
    }
    delete cleaned.raw;
    delete cleaned.status_raw;
    delete cleaned.extended_status;
    return cleaned;
  } catch {
    return null;
  }
}

function buildSignature(method: string, path: string, query: string, timestamp: string, nonce: string, body: string, secret: string) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [
    method.toUpperCase(),
    path,
    query,
    timestamp,
    nonce,
    bodyHash,
  ].join('\n');

  return crypto.createHmac('sha256', secret).update(stringToSign).digest('base64');
}

function buildNodeHeaders(method: string, path: string, query: string, body: string, nodeId: string, secret: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const signature = buildSignature(method, path, query, timestamp, nonce, body, secret);

  return {
    'X-MZ-Node-Id': nodeId,
    'X-MZ-Timestamp': timestamp,
    'X-MZ-Nonce': nonce,
    'X-MZ-Signature': signature,
  };
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
  const pathName = url.pathname;
  const query = url.search ? url.search.slice(1) : '';
  const body = await request.clone().text();
  const expected = buildSignature(request.method, pathName, query, timestamp, nonce, body, nodeSecret);
  return timingSafeEquals(expected, signature);
}

async function getSwarmSummary(controlAvailable?: boolean): Promise<SwarmSummary> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return { total: 0, managers: 0, workers: 0, nodes: [] };
  }
  if (controlAvailable === false) {
    return { total: 0, managers: 0, workers: 0, nodes: [] };
  }
  let nodes: any[] = [];
  try {
    const apiVersion = await getDockerApiVersion();
    const response = await dockerRequest(`/${apiVersion}/nodes`);
    if (Array.isArray(response)) {
      nodes = response;
    }
  } catch {
    nodes = [];
  }
  return summarizeNodes(nodes);
}

async function getSwarmNodes(controlAvailable?: boolean): Promise<any[]> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return [];
  }
  if (controlAvailable === false) {
    return [];
  }
  try {
    const apiVersion = await getDockerApiVersion();
    const response = await dockerRequest(`/${apiVersion}/nodes`);
    return Array.isArray(response) ? response : [];
  } catch {
    return [];
  }
}

async function getSwarmTasks(controlAvailable?: boolean): Promise<any[]> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return [];
  }
  if (controlAvailable === false) {
    return [];
  }
  try {
    const apiVersion = await getDockerApiVersion();
    const response = await dockerRequest(`/${apiVersion}/tasks`);
    return Array.isArray(response) ? response : [];
  } catch {
    return [];
  }
}

async function getSwarmServices(controlAvailable?: boolean): Promise<any[]> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
    return [];
  }
  if (controlAvailable === false) {
    return [];
  }
  try {
    const apiVersion = await getDockerApiVersion();
    const response = await dockerRequest(`/${apiVersion}/services`);
    return Array.isArray(response) ? response : [];
  } catch {
    return [];
  }
}

export async function buildStatusPayload(
  reqHost: string,
  wantsJson: boolean,
  includeCapacity = false,
  includePlanner = false,
  includeServices = false,
) {
  const config = readConfig();
  const localSwarm = await getLocalSwarmInfo();
  const swarm = await getSwarmSummary(localSwarm.controlAvailable);
  const nodeAssignments = mapSwarmNodes(config.nodes || [], swarm.nodes || []);
  const summary = {
    host: reqHost,
    stack_domain: config.stack_domain || '',
    stack_name: config.stack_name || '',
    generated_at: new Date().toISOString(),
    agent_version: readAgentVersion(),
    swarm,
  };

  const capacity = includeCapacity ? await buildCapacityPayload() : null;
  const planner = includePlanner ? await buildPlannerPayload() : null;
  const services = includeServices ? await buildServiceStatusPayload() : null;

  let nodeStatus: any = null;
  if (reqHost && reqHost !== config.stack_domain) {
    const target = (config.nodes || []).find((node) => node.hostname === reqHost);
    if (target) {
      const match = nodeAssignments.get(target.node_id) || null;
      nodeStatus = {
        requested: target,
        swarm: match,
      };
    }
  }

  const payload = nodeStatus ? { ...summary, node: nodeStatus } : summary;
  if (capacity) {
    (payload as Record<string, unknown>).capacity = capacity;
  }
  if (planner) {
    (payload as Record<string, unknown>).planner = planner;
  }
  if (services) {
    (payload as Record<string, unknown>).services = services;
  }

  if (wantsJson) {
    return { type: 'json' as const, payload };
  }

  const html = [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <title>MageZero Stack Status</title>',
    '  <style>',
    '    body { font-family: Arial, sans-serif; padding: 24px; background: #f7f9fb; color: #1f2a37; }',
    '    h1 { margin-bottom: 8px; }',
    '    .hint { color: #6b7280; margin-bottom: 16px; }',
    '    pre { background: #fff; padding: 16px; border-radius: 8px; border: 1px solid #e5e7eb; overflow: auto; }',
    '  </style>',
    '</head>',
    '<body>',
    '  <h1>MageZero Provisioning Status</h1>',
    `  <div class="hint">Host: ${escapeHtml(reqHost || 'unknown')} | Agent: ${escapeHtml(readAgentVersion())}</div>`,
    `  <pre>${escapeHtml(JSON.stringify(payload, null, 2))}</pre>`,
    '</body>',
    '</html>',
  ].join('\n');

  return { type: 'html' as const, payload: html };
}

export async function buildCapacityPayload() {
  const localSwarm = await getLocalSwarmInfo();
  const swarmNodes = await getSwarmNodes(localSwarm.controlAvailable);
  const tasks = await getSwarmTasks(localSwarm.controlAvailable);
  const services = await getSwarmServices(localSwarm.controlAvailable);

  const serviceSummaries: CapacityService[] = services.map((service) => {
    const constraints = service?.Spec?.TaskTemplate?.Placement?.Constraints || [];
    const reservations = service?.Spec?.TaskTemplate?.Resources?.Reservations || {};
    return {
      id: service?.ID,
      name: service?.Spec?.Name,
      mode: service?.Spec?.Mode?.Replicated ? 'replicated' : 'global',
      constraints,
      reservations: {
        cpu_cores: toCpuCores(reservations?.NanoCPUs),
        memory_bytes: reservations?.MemoryBytes || 0,
      },
    };
  });

  const serviceNameById = new Map(
    services.map((service) => [service?.ID, service?.Spec?.Name].filter((entry) => Boolean(entry[0])) as [string, string])
  );

  const nodes: CapacityNode[] = swarmNodes.map((node) => {
    const resources = node?.Description?.Resources || {};
    const nodeId = node?.ID;
    const nodeTasks = tasks.filter(
      (task) =>
        task?.NodeID === nodeId &&
        task?.DesiredState === 'running' &&
        task?.Status?.State !== 'shutdown',
    );

    let reservedCpu = 0;
    let reservedMem = 0;
    const servicesUsed = new Set<string>();
    for (const task of nodeTasks) {
      const reservations = task?.Spec?.Resources?.Reservations || {};
      reservedCpu += toCpuCores(reservations?.NanoCPUs);
      reservedMem += reservations?.MemoryBytes || 0;
      const serviceId = task?.ServiceID;
      if (serviceId) {
        servicesUsed.add(serviceNameById.get(serviceId) || serviceId);
      }
    }

    const totalCpu = toCpuCores(resources?.NanoCPUs);
    const totalMem = resources?.MemoryBytes || 0;
    const freeCpu = Math.max(0, totalCpu - reservedCpu);
    const freeMem = Math.max(0, totalMem - reservedMem);

    return {
      id: nodeId,
      hostname: node?.Description?.Hostname,
      role: node?.Spec?.Role,
      status: node?.Status?.State,
      availability: node?.Spec?.Availability,
      labels: node?.Spec?.Labels || {},
      address: node?.Status?.Addr,
      resources: {
        cpu_cores: totalCpu,
        memory_bytes: totalMem,
      },
      reservations: {
        cpu_cores: reservedCpu,
        memory_bytes: reservedMem,
      },
      free: {
        cpu_cores: freeCpu,
        memory_bytes: freeMem,
      },
      tasks: {
        running: nodeTasks.length,
        services: Array.from(servicesUsed).sort(),
      },
    };
  });

  const totals: CapacityTotals = nodes.reduce(
    (acc, node) => {
      acc.cpu_cores += node?.resources?.cpu_cores || 0;
      acc.memory_bytes += node?.resources?.memory_bytes || 0;
      acc.reserved_cpu_cores += node?.reservations?.cpu_cores || 0;
      acc.reserved_memory_bytes += node?.reservations?.memory_bytes || 0;
      acc.free_cpu_cores += node?.free?.cpu_cores || 0;
      acc.free_memory_bytes += node?.free?.memory_bytes || 0;
      return acc;
    },
    {
      cpu_cores: 0,
      memory_bytes: 0,
      reserved_cpu_cores: 0,
      reserved_memory_bytes: 0,
      free_cpu_cores: 0,
      free_memory_bytes: 0,
    },
  );

  return {
    generated_at: new Date().toISOString(),
    control_available: Boolean(localSwarm.controlAvailable),
    nodes,
    services: serviceSummaries,
    totals,
  };
}

function parseEnvironmentServiceName(name: string) {
  const match = name.match(/^mz-env-(\d+)_(.+)$/i);
  if (!match) {
    return { service: name };
  }
  return {
    environmentId: Number.parseInt(match[1], 10),
    service: match[2],
  };
}

export async function buildServiceStatusPayload(environmentId?: number): Promise<ServiceStatusPayload> {
  const localSwarm = await getLocalSwarmInfo();
  const swarmNodes = await getSwarmNodes(localSwarm.controlAvailable);
  const tasks = await getSwarmTasks(localSwarm.controlAvailable);
  const services = await getSwarmServices(localSwarm.controlAvailable);

  const readyNodes = swarmNodes.filter(
    (node) => node?.Status?.State === 'ready' && node?.Spec?.Availability === 'active',
  );
  const nodeLookup = new Map(
    swarmNodes
      .map((node) => [node?.ID, node] as const)
      .filter((entry) => Boolean(entry[0])),
  );

  const servicesStatus: ServiceStatus[] = [];
  for (const service of services) {
    const name = String(service?.Spec?.Name || '');
    if (!name) {
      continue;
    }
    const parsed = parseEnvironmentServiceName(name);
    if (environmentId && parsed.environmentId !== environmentId) {
      continue;
    }

    const mode = service?.Spec?.Mode?.Replicated ? 'replicated' : 'global';
    const desiredReplicas = mode === 'replicated'
      ? Number(service?.Spec?.Mode?.Replicated?.Replicas || 0)
      : readyNodes.length;

    const stateCounts: ServiceStateCounts = {
      running: 0,
      pending: 0,
      failed: 0,
      rejected: 0,
      shutdown: 0,
    };
    const healthCounts: ServiceHealthCounts = {
      healthy: 0,
      unhealthy: 0,
      starting: 0,
      none: 0,
    };
    let runningReplicas = 0;
    let restartCount = 0;
    let lastError = '';
    let lastErrorAt = '';
    let lastErrorTime = 0;

    const nodeCounts = new Map<string, { hostname: string; count: number }>();
    const serviceTasks = tasks.filter(
      (task) => task?.ServiceID === service?.ID && task?.DesiredState === 'running',
    );
    for (const task of serviceTasks) {
      const state = String(task?.Status?.State || '').toLowerCase();
      if (state && state in stateCounts) {
        stateCounts[state as keyof ServiceStateCounts] += 1;
      }

      const nodeId = task?.NodeID;
      if (nodeId) {
        const node = nodeLookup.get(nodeId);
        const hostname = node?.Description?.Hostname || nodeId;
        const existing = nodeCounts.get(nodeId);
        if (existing) {
          existing.count += 1;
        } else {
          nodeCounts.set(nodeId, { hostname, count: 1 });
        }
      }

      if (task?.DesiredState === 'running' && task?.Status?.State === 'running') {
        runningReplicas += 1;
      }

      const health = String(task?.Status?.ContainerStatus?.Health?.Status || '').toLowerCase();
      if (health === 'healthy') {
        healthCounts.healthy += 1;
      } else if (health === 'unhealthy') {
        healthCounts.unhealthy += 1;
      } else if (health === 'starting') {
        healthCounts.starting += 1;
      } else {
        healthCounts.none += 1;
      }

      const restarts = Number(task?.Status?.ContainerStatus?.RestartCount || 0);
      restartCount += Number.isFinite(restarts) ? restarts : 0;

      const errorMessage = String(task?.Status?.Err || task?.Status?.Message || '').trim();
      if (errorMessage) {
        const timestamp = String(task?.Status?.Timestamp || '');
        const timeValue = timestamp ? Date.parse(timestamp) : 0;
        if (timeValue >= lastErrorTime) {
          lastErrorTime = timeValue;
          lastError = errorMessage;
          lastErrorAt = timestamp;
        }
      }
    }

    const hasIssues = healthCounts.unhealthy > 0 || stateCounts.failed > 0 || stateCounts.rejected > 0;
    let status: ServiceStatus['status'] = 'unknown';
    if (desiredReplicas > 0) {
      if (runningReplicas >= desiredReplicas && !hasIssues) {
        status = 'healthy';
      } else if (runningReplicas > 0) {
        status = 'degraded';
      } else {
        status = 'down';
      }
    }

    servicesStatus.push({
      id: service?.ID,
      name,
      service: parsed.service,
      environment_id: parsed.environmentId,
      mode,
      desired_replicas: desiredReplicas,
      running_replicas: runningReplicas,
      health: healthCounts,
      state_counts: stateCounts,
      nodes: Array.from(nodeCounts.entries()).map(([id, entry]) => ({
        id,
        hostname: entry.hostname,
        count: entry.count,
      })),
      restart_count: restartCount,
      last_error: lastError || undefined,
      last_error_at: lastErrorAt || undefined,
      status,
    });
  }

  servicesStatus.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

  return {
    generated_at: new Date().toISOString(),
    control_available: Boolean(localSwarm.controlAvailable),
    services: servicesStatus,
  };
}

function pickNodeByLabel(nodes: CapacityNode[], label: string, value: string) {
  return nodes.find((node) => node.labels?.[label] === value) || null;
}

function pickReadyNode(nodes: CapacityNode[]) {
  return nodes.find((node) => node.status === 'ready' && node.availability === 'active') || null;
}

function pickManager(nodes: CapacityNode[]) {
  const managers = nodes.filter(
    (node) => node.role === 'manager' && node.status === 'ready' && node.availability === 'active',
  );
  return managers[0] || pickReadyNode(nodes);
}

function pickHighestFreeMemory(nodes: CapacityNode[]) {
  return nodes
    .filter((node) => node.status === 'ready' && node.availability === 'active')
    .sort((a, b) => (b.free?.memory_bytes || 0) - (a.free?.memory_bytes || 0))[0] || null;
}

function pickHighestCapacity(nodes: CapacityNode[]) {
  return nodes
    .filter((node) => node.status === 'ready' && node.availability === 'active')
    .sort((a, b) => {
      const memDiff = (b.resources?.memory_bytes || 0) - (a.resources?.memory_bytes || 0);
      if (memDiff !== 0) {
        return memDiff;
      }
      return (b.resources?.cpu_cores || 0) - (a.resources?.cpu_cores || 0);
    })[0] || null;
}

function buildPlannerResourceDefaults(): PlannerResources {
  return {
    services: {
      varnish: {
        limits: { cpu_cores: 1, memory_bytes: 512 * MIB },
        reservations: { cpu_cores: 0.25, memory_bytes: 256 * MIB },
      },
      nginx: {
        limits: { cpu_cores: 0.5, memory_bytes: 256 * MIB },
        reservations: { cpu_cores: 0.1, memory_bytes: 128 * MIB },
      },
      'php-fpm': {
        limits: { cpu_cores: 2, memory_bytes: 4 * GIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 1.5 * GIB },
      },
      'php-fpm-admin': {
        limits: { cpu_cores: 2, memory_bytes: 3 * GIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 0.75 * GIB },
      },
      cron: {
        limits: { cpu_cores: 0.5, memory_bytes: 1 * GIB },
        reservations: { cpu_cores: 0.1, memory_bytes: 512 * MIB },
      },
      database: {
        limits: { cpu_cores: 2, memory_bytes: 1 * GIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
      },
      'database-replica': {
        limits: { cpu_cores: 2, memory_bytes: 1 * GIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
      },
      proxysql: {
        limits: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
        reservations: { cpu_cores: 0.1, memory_bytes: 256 * MIB },
      },
      opensearch: {
        limits: { cpu_cores: 2, memory_bytes: 1 * GIB },
        reservations: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
      },
      'redis-cache': {
        limits: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
        reservations: { cpu_cores: 0.1, memory_bytes: 256 * MIB },
      },
      'redis-session': {
        limits: { cpu_cores: 0.5, memory_bytes: 512 * MIB },
        reservations: { cpu_cores: 0.1, memory_bytes: 256 * MIB },
      },
      rabbitmq: {
        limits: { cpu_cores: 1, memory_bytes: 512 * MIB },
        reservations: { cpu_cores: 0.25, memory_bytes: 256 * MIB },
      },
    },
  };
}

type InspectionCommand = {
  id: string;
  command: string[];
  timeoutMs?: number;
  parser: (output: string) => Record<string, InspectionMetricValue>;
};

const PHP_OPCACHE_COMMAND: string[] = [
  'sh',
  '-lc',
  'php -r \'$limit=ini_get("memory_limit"); $limitBytes=null; if ($limit===false) { $limitBytes=null; } elseif ($limit==="-1") { $limitBytes=-1; } else { $unit=strtolower(substr($limit,-1)); $value=(float)$limit; if (in_array($unit, ["k","m","g","t"], true)) { $value=(float)substr($limit,0,-1); $mult=1; if ($unit==="k") { $mult=1024; } elseif ($unit==="m") { $mult=1024*1024; } elseif ($unit==="g") { $mult=1024*1024*1024; } elseif ($unit==="t") { $mult=1024*1024*1024*1024; } $limitBytes=(int)($value*$mult); } else { $limitBytes=(int)$value; } } $out=["php_memory_limit_bytes"=>$limitBytes]; if (function_exists("opcache_get_status")) { $s=opcache_get_status(false); if ($s) { $mem=$s["memory_usage"]??[]; $stat=$s["opcache_statistics"]??[]; $out["opcache_used_bytes"]=$mem["used_memory"]??null; $out["opcache_free_bytes"]=$mem["free_memory"]??null; $out["opcache_wasted_bytes"]=$mem["wasted_memory"]??null; $out["opcache_hit_rate"]=$stat["opcache_hit_rate"]??null; $out["opcache_cached_scripts"]=$stat["num_cached_scripts"]??null; $out["opcache_cached_keys"]=$stat["num_cached_keys"]??null; $out["opcache_max_keys"]=$stat["max_cached_keys"]??null; $out["opcache_enabled"]=true; } else { $out["opcache_enabled"]=false; } } else { $out["opcache_enabled"]=false; } echo json_encode($out);\'',
];

const INSPECTION_COMMANDS: Record<string, InspectionCommand> = {
  'php-fpm': {
    id: 'opcache',
    command: PHP_OPCACHE_COMMAND,
    parser: parseJsonMetrics,
  },
  'php-fpm-admin': {
    id: 'opcache',
    command: PHP_OPCACHE_COMMAND,
    parser: parseJsonMetrics,
  },
  cron: {
    id: 'opcache',
    command: PHP_OPCACHE_COMMAND,
    parser: parseJsonMetrics,
  },
  varnish: {
    id: 'varnishstat',
    command: [
      'sh',
      '-lc',
      'command -v varnishstat >/dev/null 2>&1 && varnishstat -1 -f MAIN.cache_hit,MAIN.cache_miss,MAIN.cache_hitpass,MAIN.client_req,MAIN.backend_conn,MAIN.backend_fail,MAIN.backend_unhealthy || true',
    ],
    parser: parseVarnishMetrics,
  },
  'redis-cache': {
    id: 'redis-info',
    command: ['sh', '-lc', 'command -v redis-cli >/dev/null 2>&1 && redis-cli info || true'],
    parser: parseRedisMetrics,
  },
  'redis-session': {
    id: 'redis-info',
    command: ['sh', '-lc', 'command -v redis-cli >/dev/null 2>&1 && redis-cli info || true'],
    parser: parseRedisMetrics,
  },
  database: {
    id: 'mysql-status',
    command: [
      'sh',
      '-lc',
      'MYSQL_PWD="$(cat /run/secrets/db_root_password 2>/dev/null || true)"; if [ -z "$MYSQL_PWD" ]; then exit 0; fi; export MYSQL_PWD; mysql -uroot -N -B -e "SHOW GLOBAL STATUS WHERE Variable_name IN (\'Threads_connected\',\'Threads_running\',\'Slow_queries\',\'Questions\',\'Uptime\',\'Connections\'); SHOW GLOBAL VARIABLES WHERE Variable_name IN (\'innodb_buffer_pool_size\',\'max_connections\');"',
    ],
    parser: parseMysqlMetrics,
  },
  'database-replica': {
    id: 'mysql-status',
    command: [
      'sh',
      '-lc',
      'MYSQL_PWD="$(cat /run/secrets/db_root_password 2>/dev/null || true)"; if [ -z "$MYSQL_PWD" ]; then exit 0; fi; export MYSQL_PWD; mysql -uroot -N -B -e "SHOW GLOBAL STATUS WHERE Variable_name IN (\'Threads_connected\',\'Threads_running\',\'Slow_queries\',\'Questions\',\'Uptime\',\'Connections\'); SHOW GLOBAL VARIABLES WHERE Variable_name IN (\'innodb_buffer_pool_size\',\'max_connections\');"',
    ],
    parser: parseMysqlMetrics,
  },
  opensearch: {
    id: 'opensearch-health',
    command: [
      'sh',
      '-lc',
      'if command -v curl >/dev/null 2>&1; then curl -s http://localhost:9200/_cluster/health?pretty=false; elif command -v wget >/dev/null 2>&1; then wget -qO- http://localhost:9200/_cluster/health?pretty=false; else exit 0; fi',
    ],
    parser: parseOpensearchMetrics,
  },
};

function parseJsonMetrics(output: string): Record<string, InspectionMetricValue> {
  try {
    const parsed = JSON.parse(output);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function parseNumber(value: string): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseKeyValueLines(output: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    if (trimmed.includes('\t')) {
      const [key, value] = trimmed.split('\t');
      if (key && value !== undefined) {
        metrics[key.trim()] = value.trim();
      }
      continue;
    }
    if (trimmed.includes(':')) {
      const idx = trimmed.indexOf(':');
      const key = trimmed.slice(0, idx).trim();
      const value = trimmed.slice(idx + 1).trim();
      if (key) {
        metrics[key] = value;
      }
    }
  }
  return metrics;
}

function parseVarnishMetrics(output: string): Record<string, InspectionMetricValue> {
  const metrics: Record<string, InspectionMetricValue> = {};
  const pairs: Record<string, string> = {};
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      pairs[parts[0]] = parts[1];
    }
  }
  const hit = parseNumber(pairs['MAIN.cache_hit'] || '') || 0;
  const miss = parseNumber(pairs['MAIN.cache_miss'] || '') || 0;
  const hitPass = parseNumber(pairs['MAIN.cache_hitpass'] || '') || 0;
  const clientReq = parseNumber(pairs['MAIN.client_req'] || '') || 0;
  const backendConn = parseNumber(pairs['MAIN.backend_conn'] || '') || 0;
  const backendFail = parseNumber(pairs['MAIN.backend_fail'] || '') || 0;
  const backendUnhealthy = parseNumber(pairs['MAIN.backend_unhealthy'] || '') || 0;
  metrics.cache_hit = hit;
  metrics.cache_miss = miss;
  metrics.cache_hitpass = hitPass;
  metrics.client_req = clientReq;
  metrics.backend_conn = backendConn;
  metrics.backend_fail = backendFail;
  metrics.backend_unhealthy = backendUnhealthy;
  const total = hit + miss;
  metrics.cache_hit_rate = total > 0 ? hit / total : null;
  return metrics;
}

function parseRedisMetrics(output: string): Record<string, InspectionMetricValue> {
  const raw = parseKeyValueLines(output);
  const metrics: Record<string, InspectionMetricValue> = {};
  const usedMemory = parseNumber(raw.used_memory || '');
  const usedMemoryPeak = parseNumber(raw.used_memory_peak || '');
  const connectedClients = parseNumber(raw.connected_clients || '');
  const keyspaceHits = parseNumber(raw.keyspace_hits || '');
  const keyspaceMisses = parseNumber(raw.keyspace_misses || '');
  const evictedKeys = parseNumber(raw.evicted_keys || '');
  metrics.used_memory_bytes = usedMemory;
  metrics.used_memory_peak_bytes = usedMemoryPeak;
  metrics.connected_clients = connectedClients;
  metrics.keyspace_hits = keyspaceHits;
  metrics.keyspace_misses = keyspaceMisses;
  metrics.evicted_keys = evictedKeys;
  if (keyspaceHits !== null && keyspaceMisses !== null) {
    const total = keyspaceHits + keyspaceMisses;
    metrics.keyspace_hit_rate = total > 0 ? keyspaceHits / total : null;
  }
  return metrics;
}

function parseMysqlMetrics(output: string): Record<string, InspectionMetricValue> {
  const raw = parseKeyValueLines(output);
  const metrics: Record<string, InspectionMetricValue> = {};
  const keys = [
    'Threads_connected',
    'Threads_running',
    'Slow_queries',
    'Questions',
    'Uptime',
    'Connections',
    'innodb_buffer_pool_size',
    'max_connections',
  ];
  for (const key of keys) {
    const value = parseNumber(raw[key] || '');
    metrics[key] = value;
  }
  return metrics;
}

function parseOpensearchMetrics(output: string): Record<string, InspectionMetricValue> {
  const parsed = parseJsonMetrics(output);
  if (!parsed || typeof parsed !== 'object') {
    return {};
  }
  return {
    status: (parsed as Record<string, InspectionMetricValue>).status ?? null,
    number_of_nodes: (parsed as Record<string, InspectionMetricValue>).number_of_nodes ?? null,
    active_shards_percent: (parsed as Record<string, InspectionMetricValue>).active_shards_percent_as_number ?? null,
  };
}

async function getContainerStats(containerId: string) {
  const apiVersion = await getDockerApiVersion();
  return dockerRequest(`/${apiVersion}/containers/${containerId}/stats?stream=false`);
}

async function buildDockerAggregateStats(containerIds: string[], warnings: string[]) {
  if (containerIds.length === 0) {
    return null;
  }
  let cpuPercent = 0;
  let memoryBytes = 0;
  let memoryLimitBytes = 0;
  let pids = 0;
  let samples = 0;
  for (const containerId of containerIds) {
    try {
      const stats = await getContainerStats(containerId);
      if (!stats) {
        continue;
      }
      samples += 1;
      cpuPercent += calculateCpuPercent(stats);
      memoryBytes += Number(stats?.memory_stats?.usage || 0);
      memoryLimitBytes += Number(stats?.memory_stats?.limit || 0);
      pids += Number(stats?.pids_stats?.current || 0);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`docker stats failed: ${message}`);
    }
  }
  if (samples === 0) {
    return null;
  }
  const memoryPercent = memoryLimitBytes > 0 ? (memoryBytes / memoryLimitBytes) * 100 : 0;
  return {
    cpu_percent: cpuPercent,
    memory_bytes: memoryBytes,
    memory_limit_bytes: memoryLimitBytes,
    memory_percent: memoryPercent,
    pids,
  };
}

async function collectAppMetrics(service: string, containerId: string, warnings: string[]) {
  const command = INSPECTION_COMMANDS[service];
  if (!command) {
    return null;
  }
  try {
    const result = await execContainerCommand(containerId, command.command, command.timeoutMs || 5000);
    if (result.exitCode && result.exitCode !== 0) {
      warnings.push(`${command.id} exited with code ${result.exitCode}`);
    }
    if (result.stderr) {
      warnings.push(`${command.id} stderr: ${result.stderr}`);
    }
    if (!result.stdout) {
      return null;
    }
    return command.parser(result.stdout);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    warnings.push(`${command.id} failed: ${message}`);
    return null;
  }
}

async function buildInspectionPayload(): Promise<PlannerInspectionPayload> {
  const localSwarm = await getLocalSwarmInfo();
  if (process.env.MZ_DISABLE_DOCKER === '1' || localSwarm.controlAvailable === false) {
    return { generated_at: new Date().toISOString(), services: [] };
  }

  const tasks = await getSwarmTasks(localSwarm.controlAvailable);
  const services = await getSwarmServices(localSwarm.controlAvailable);
  const serviceNameById = new Map(
    services
      .map((service) => [service?.ID, service?.Spec?.Name] as const)
      .filter((entry) => Boolean(entry[0] && entry[1])),
  );
  const serviceConstraintsByName = new Map(
    services
      .map((service) => [service?.Spec?.Name, service?.Spec?.TaskTemplate?.Placement?.Constraints || []] as const)
      .filter((entry) => Boolean(entry[0])),
  );

  const grouped = new Map<
    string,
    { name: string; service: string; environmentId?: number; containerIds: string[] }
  >();

  for (const task of tasks) {
    if (task?.DesiredState !== 'running' || task?.Status?.State !== 'running') {
      continue;
    }
    const containerId = task?.Status?.ContainerStatus?.ContainerID;
    if (!containerId) {
      continue;
    }
    const serviceName = serviceNameById.get(task?.ServiceID) || '';
    if (!serviceName) {
      continue;
    }
    const parsed = parseEnvironmentServiceName(serviceName);
    const entry = grouped.get(serviceName);
    if (entry) {
      entry.containerIds.push(containerId);
    } else {
      grouped.set(serviceName, {
        name: serviceName,
        service: parsed.service,
        environmentId: parsed.environmentId,
        containerIds: [containerId],
      });
    }
  }

  const inspections: PlannerInspectionService[] = [];
  for (const entry of grouped.values()) {
    const warnings: string[] = [];
    const docker = await buildDockerAggregateStats(entry.containerIds, warnings);
    const sampledContainerId = entry.containerIds[0];
    const app = sampledContainerId
      ? await collectAppMetrics(entry.service, sampledContainerId, warnings)
      : null;
    inspections.push({
      name: entry.name,
      service: entry.service,
      environment_id: entry.environmentId,
      container_ids: entry.containerIds,
      replicas: entry.containerIds.length,
      constraints: serviceConstraintsByName.get(entry.name) || undefined,
      sampled_container_id: sampledContainerId,
      docker: docker || undefined,
      app: app || undefined,
      warnings: warnings.length > 0 ? warnings : undefined,
    });
  }

  inspections.sort((a, b) => a.name.localeCompare(b.name));

  return {
    generated_at: new Date().toISOString(),
    services: inspections,
  };
}

function readInspectionHistory(): InspectionHistoryEntry[] {
  try {
    const raw = fs.readFileSync(INSPECTION_HISTORY_PATH, 'utf8').trim();
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw) as InspectionHistoryEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeInspectionHistory(entries: InspectionHistoryEntry[]) {
  try {
    const dir = path.dirname(INSPECTION_HISTORY_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const tmpPath = `${INSPECTION_HISTORY_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(entries, null, 2));
    fs.renameSync(tmpPath, INSPECTION_HISTORY_PATH);
  } catch {
    // ignore persistence failures
  }
}

function pruneInspectionHistory(entries: InspectionHistoryEntry[], nowMs: number) {
  return entries.filter((entry) => {
    const capturedAt = Date.parse(entry.captured_at);
    if (!capturedAt) {
      return false;
    }
    return nowMs - capturedAt <= INSPECTION_RETENTION_MS;
  });
}

function aggregateInspectionHistory(
  entries: InspectionHistoryEntry[],
  fallback: PlannerInspectionPayload,
): PlannerInspectionPayload {
  if (entries.length === 0) {
    return fallback;
  }

  const sorted = [...entries].sort((a, b) => Date.parse(a.captured_at) - Date.parse(b.captured_at));
  const latestEntry = sorted[sorted.length - 1];
  const latestInspection = latestEntry?.inspection || fallback;
  const aggregates = new Map<string, {
    latest: PlannerInspectionService;
    docker: Record<string, { sum: number; count: number }>;
    app: Record<string, { sum: number; count: number }>;
  }>();

  for (const entry of sorted) {
    const inspection = entry.inspection;
    for (const service of inspection.services) {
      const key = `${service.service}:${service.environment_id ?? '0'}`;
      let aggregate = aggregates.get(key);
      if (!aggregate) {
        aggregate = {
          latest: service,
          docker: {},
          app: {},
        };
        aggregates.set(key, aggregate);
      }
      aggregate.latest = service;

      const docker = service.docker;
      if (docker) {
        const dockerKeys: Array<keyof NonNullable<PlannerInspectionService['docker']>> = [
          'cpu_percent',
          'memory_bytes',
          'memory_limit_bytes',
          'memory_percent',
          'pids',
        ];
        for (const keyName of dockerKeys) {
          const value = docker[keyName];
          if (typeof value === 'number' && !Number.isNaN(value)) {
            const existing = aggregate.docker[keyName] || { sum: 0, count: 0 };
            existing.sum += value;
            existing.count += 1;
            aggregate.docker[keyName] = existing;
          }
        }
      }

      const app = service.app || {};
      for (const [metric, value] of Object.entries(app)) {
        if (typeof value !== 'number' || Number.isNaN(value)) {
          continue;
        }
        const existing = aggregate.app[metric] || { sum: 0, count: 0 };
        existing.sum += value;
        existing.count += 1;
        aggregate.app[metric] = existing;
      }
    }
  }

  const services: PlannerInspectionService[] = [];
  for (const aggregate of aggregates.values()) {
    const latest = aggregate.latest;
    const docker: PlannerInspectionService['docker'] | undefined = latest.docker
      ? { ...latest.docker }
      : undefined;
    if (docker) {
      for (const [metric, value] of Object.entries(aggregate.docker)) {
        if (value.count > 0) {
          (docker as Record<string, number>)[metric] = value.sum / value.count;
        }
      }
    }

    const app: Record<string, InspectionMetricValue> | undefined = latest.app
      ? { ...latest.app }
      : undefined;
    if (app) {
      for (const [metric, value] of Object.entries(aggregate.app)) {
        if (value.count > 0) {
          app[metric] = value.sum / value.count;
        }
      }
    }

    services.push({
      name: latest.name,
      service: latest.service,
      environment_id: latest.environment_id,
      container_ids: latest.container_ids,
      replicas: latest.replicas,
      constraints: latest.constraints,
      sampled_container_id: latest.sampled_container_id,
      docker,
      app,
      warnings: latest.warnings,
    });
  }

  services.sort((a, b) => a.name.localeCompare(b.name));

  return {
    generated_at: latestInspection.generated_at,
    services,
  };
}

async function buildInspectionForTuning(): Promise<PlannerInspectionPayload> {
  const latest = await buildInspectionPayload();
  const nowMs = Date.now();
  const history = pruneInspectionHistory(readInspectionHistory(), nowMs);
  const windowEntries = history.filter((entry) => {
    const capturedAt = Date.parse(entry.captured_at);
    if (!capturedAt) {
      return false;
    }
    return nowMs - capturedAt <= TUNING_INTERVAL_MS;
  });
  const samples = [
    ...windowEntries,
    { captured_at: latest.generated_at, inspection: latest },
  ];
  const aggregated = samples.length > 1
    ? aggregateInspectionHistory(samples, latest)
    : latest;
  aggregated.window_minutes = Math.round(TUNING_INTERVAL_MS / 60000);
  aggregated.sample_count = samples.length;
  return aggregated;
}

async function recordInspectionSnapshot() {
  const snapshot = await buildInspectionPayload();
  const nowMs = Date.now();
  const history = pruneInspectionHistory(readInspectionHistory(), nowMs);
  history.push({ captured_at: snapshot.generated_at, inspection: snapshot });
  writeInspectionHistory(history);
}


async function fetchAiTuningProfile(
  inspection: PlannerInspectionPayload,
  capacity: Awaited<ReturnType<typeof buildCapacityPayload>>,
  resources: PlannerResources,
): Promise<AiTuningProfile | null> {
  if (AI_TUNING_DISABLED) {
    return null;
  }
  const config = readConfig();
  const baseUrl = config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '';
  const stackId = Number(config.stack_id || 0);
  if (!baseUrl || !stackId) {
    return null;
  }

  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!nodeId || !nodeSecret) {
    return null;
  }

  const payload = JSON.stringify({
    stack_id: stackId,
    inspection,
    capacity: {
      totals: capacity.totals,
      nodes: capacity.nodes?.map((node) => ({
        id: node.id,
        hostname: node.hostname,
        role: node.role,
        resources: node.resources,
        free: node.free,
      })),
    },
    resources,
  });
  const url = new URL('/v1/stack/tuning', baseUrl);
  const headers = buildNodeHeaders('POST', url.pathname, url.search.slice(1), payload, nodeId, nodeSecret);
  headers['Content-Type'] = 'application/json';
  headers['Accept'] = 'application/json';

  const timeoutMs = Number(process.env.MZ_AI_TUNING_TIMEOUT_MS || 12000);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url.toString(), {
      method: 'POST',
      headers,
      body: payload,
      signal: controller.signal,
    });
    if (!response.ok) {
      return null;
    }
    const data = await response.json().catch(() => null);
    if (!data || typeof data !== 'object') {
      return null;
    }
    if ((data as Record<string, unknown>).disabled) {
      return null;
    }
    return (data as { profile?: AiTuningProfile }).profile || null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function buildPlannerPayload(): Promise<PlannerPayload> {
  const capacity = await buildCapacityPayload();
  const nodes = capacity.nodes || [];
  const warnings: string[] = [];
  const recommendations: PlannerRecommendation[] = [];
  const readyNodes = nodes.filter(
    (node) => node.status === 'ready' && node.availability === 'active',
  );
  const managerNodes = nodes.filter(
    (node) => node.role === 'manager' && node.status === 'ready' && node.availability === 'active',
  );

  const primaryManager = pickManager(nodes);
  if (!primaryManager) {
    warnings.push('no ready node available for manager placement');
  }

  const existingDb = pickNodeByLabel(nodes, 'database', 'true');
  const existingSearch = pickNodeByLabel(nodes, 'search', 'true');
  const existingReplica = pickNodeByLabel(nodes, 'database_replica', 'true');

  let dbNode = existingDb;
  let searchNode = existingSearch;
  const replicaLabelMissing = !existingReplica;
  let replicaNode = existingReplica;

  if (!dbNode) {
    const candidates = nodes.length > 1
      ? readyNodes.filter((node) => node.id !== primaryManager?.id)
      : readyNodes;
    dbNode = pickHighestCapacity(candidates) || pickHighestCapacity(readyNodes) || primaryManager;
    if (dbNode) {
      recommendations.push({
        type: 'label',
        node_id: dbNode.id,
        labels: { database: 'true' },
        message: `Recommend setting database=true on ${dbNode.hostname || dbNode.id}`,
      });
    }
  }

  if (!searchNode) {
    const candidates = readyNodes.filter((node) => node.id !== dbNode?.id);
    searchNode = pickHighestCapacity(candidates) || pickHighestCapacity(readyNodes) || dbNode || primaryManager;
    if (searchNode) {
      recommendations.push({
        type: 'label',
        node_id: searchNode.id,
        labels: { search: 'true' },
        message: `Recommend setting search=true on ${searchNode.hostname || searchNode.id}`,
      });
    }
  }

  if (!pickNodeByLabel(nodes, 'mz.role', 'manager') && primaryManager) {
    recommendations.push({
      type: 'label',
      node_id: primaryManager.id,
      labels: { 'mz.role': 'manager' },
      message: `Recommend setting mz.role=manager on ${primaryManager.hostname || primaryManager.id}`,
    });
  }

  if (readyNodes.length <= 1) {
    replicaNode = null;
  } else {
    const replicaCandidates = readyNodes.filter((node) => node.id !== dbNode?.id);
    const preferredReplica = pickHighestCapacity(replicaCandidates) || pickHighestCapacity(readyNodes);
    if (!replicaNode && preferredReplica) {
      recommendations.push({
        type: 'label',
        node_id: preferredReplica.id,
        labels: { database_replica: 'true' },
        message: `Recommend setting database_replica=true on ${preferredReplica.hostname || preferredReplica.id}`,
      });
      replicaNode = preferredReplica;
    } else if (replicaNode && dbNode && replicaNode.id === dbNode.id && preferredReplica && preferredReplica.id !== dbNode.id) {
      recommendations.push({
        type: 'label',
        node_id: preferredReplica.id,
        labels: { database_replica: 'true' },
        message: `Recommend moving database_replica=true to ${preferredReplica.hostname || preferredReplica.id}`,
      });
      replicaNode = preferredReplica;
    }
  }

  const totalCpu = capacity.totals.cpu_cores || 0;
  const totalMem = capacity.totals.memory_bytes || 0;
  const freeCpu = capacity.totals.free_cpu_cores || 0;
  const freeMem = capacity.totals.free_memory_bytes || 0;

  if (readyNodes.length === 0) {
    warnings.push('no ready nodes available');
  }
  if (readyNodes.length > 1 && dbNode && searchNode && dbNode.id === searchNode.id) {
    warnings.push('database and search are co-located; consider splitting across nodes');
  }
  if (readyNodes.length > 1 && dbNode && existingReplica && dbNode.id === existingReplica.id) {
    warnings.push('database replica label is co-located with primary; consider moving it');
  }
  if (readyNodes.length > 1 && dbNode && replicaNode && dbNode.id === replicaNode.id) {
    warnings.push('database primary and replica are co-located; consider separating replicas');
  }
  if (readyNodes.length > 1 && replicaLabelMissing) {
    warnings.push('database replica label missing; add database_replica=true to enable');
  }

  const capacityNodes = nodes.map((node) => ({
    id: node.id,
    hostname: node.hostname,
    role: node.role,
    cpu_cores: node.resources?.cpu_cores || 0,
    memory_bytes: node.resources?.memory_bytes || 0,
  }));

  const baseResources = buildPlannerResourceDefaults();
  const inspection = await buildInspectionForTuning();
  const candidate = buildCandidateProfile(inspection, baseResources, capacity);
  const shouldUpdateRecommendation = isRecommendationDue();
  if (shouldUpdateRecommendation) {
    const aiProfile = await fetchAiTuningProfile(inspection, capacity, candidate.profile.resources);
    if (aiProfile) {
      applyAiAdjustments(
        aiProfile,
        candidate.profile,
        candidate.profile.resources,
        baseResources,
        inspection,
        capacity,
      );
    }
  }
  const tuningResult = await buildTuningProfiles(
    candidate.profile,
    candidate.signals,
    baseResources,
    inspection,
  );
  const resources = tuningResult.active.resources;

  return {
    generated_at: capacity.generated_at,
    control_available: Boolean(capacity.control_available),
    summary: {
      node_count: nodes.length,
      ready_count: readyNodes.length,
      manager_count: managerNodes.length,
      worker_count: nodes.length - managerNodes.length,
    },
    capacity: {
      totals: {
        cpu_cores: totalCpu,
        memory_bytes: totalMem,
      },
      nodes: capacityNodes,
    },
    placements: {
      primary_manager_node_id: primaryManager?.id || null,
      database_node_id: dbNode?.id || null,
      search_node_id: searchNode?.id || null,
      database_replica_node_id: replicaNode?.id || null,
    },
    headroom: {
      free_cpu_cores: freeCpu,
      free_memory_bytes: freeMem,
      free_cpu_ratio: totalCpu > 0 ? freeCpu / totalCpu : 0,
      free_memory_ratio: totalMem > 0 ? freeMem / totalMem : 0,
    },
    resources,
    inspection,
    tuning: tuningResult.payload,
    warnings,
    recommendations,
  };
}

export async function handleTuningApprovalRequest(request: Request) {
  const authorized = await validateNodeRequest(request);
  if (!authorized) {
    return { status: 401, body: { error: 'Unauthorized' } } as const;
  }

  const body = await request.json<TuningApprovalRequest>().catch(() => ({}));
  const expectedId = typeof body?.profile_id === 'string' ? body.profile_id.trim() : '';
  if (!expectedId) {
    return { status: 400, body: { error: 'Missing profile_id' } } as const;
  }

  const stored = loadTuningProfiles();
  const recommended = stored?.recommended;
  if (!recommended) {
    return { status: 404, body: { error: 'No recommended profile available' } } as const;
  }

  if (expectedId !== recommended.id) {
    return {
      status: 409,
      body: {
        error: 'recommended_profile_mismatch',
        recommended_id: recommended.id,
        recommended_updated_at: recommended.updated_at,
      },
    } as const;
  }

  const now = new Date().toISOString();
  const approvedId = `approved-${crypto.randomUUID()}`;
  const approvedProfile = cloneTuningProfile(recommended, 'approved', approvedId, now);
  approvedProfile.created_at = now;
  approvedProfile.updated_at = now;

  const baseProfile = stored?.base || createBaseProfile(buildPlannerResourceDefaults(), now);
  const approvedProfiles = pruneApprovedProfiles(
    [...(stored?.approved || []), approvedProfile],
    Date.now(),
  );

  saveTuningProfiles({
    base: baseProfile,
    recommended,
    approved: approvedProfiles,
    last_recommended_at: stored?.last_recommended_at,
  });

  return {
    status: 200,
    body: {
      approved_profile: approvedProfile,
      active_profile_id: approvedProfile.id,
    },
  } as const;
}

export async function pushStatus() {
  const config = readConfig();
  const mzControlBaseUrl = config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '';
  const magentoBaseUrl = config.magento_base_url || process.env.MAGENTO_BASE_URL || '';
  const baseUrl = mzControlBaseUrl || magentoBaseUrl;
  if (!baseUrl) {
    return;
  }

  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!nodeId || !nodeSecret) {
    return;
  }

  const localSwarm = await getLocalSwarmInfo();
  const swarm = await getSwarmSummary(localSwarm.controlAvailable);
  const stackStatus = localSwarm.controlAvailable
    ? (swarm.total > 0 && swarm.nodes.every((node) => node.status === 'ready') ? 'healthy' : 'unhealthy')
    : null;

  const localHostname = os.hostname();
  const localState = String(localSwarm.localNodeState || '').toLowerCase();
  let nodeStatus = localState === 'active' ? 'active' : 'provisioning';
  if (localSwarm.controlAvailable) {
    const swarmNode = swarm.nodes.find((node) => node.labels?.['mz.node_id'] === String(nodeId))
      || swarm.nodes.find((node) => node.hostname === localHostname);
    if (swarmNode) {
      nodeStatus = swarmNode.status === 'ready' ? 'active' : 'provisioning';
    }
  }

  const cloudInitStatus = readCloudInitStatus();
  const cloudInitPayload = cloudInitStatus ? JSON.stringify(cloudInitStatus) : null;
  const masterSshPublicKey = readNodeFile('stack_master_ssh.pub');
  const payload: Record<string, unknown> = {
    status: nodeStatus,
    cloud_init_status: cloudInitPayload,
  };
  if (stackStatus) {
    payload.stack_status = stackStatus;
  }
  if (masterSshPublicKey) {
    payload.master_ssh_public_key = masterSshPublicKey;
  }
  const body = JSON.stringify({ payload });
  const url = new URL(`/rest/V1/mz-node/${nodeId}`, baseUrl);
  const path = url.pathname;
  const query = url.search ? url.search.slice(1) : '';
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const signature = buildSignature('POST', path, query, timestamp, nonce, body, nodeSecret);

  try {
    await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-MZ-Node-Id': String(nodeId),
        'X-MZ-Timestamp': timestamp,
        'X-MZ-Nonce': nonce,
        'X-MZ-Signature': signature,
      },
      body,
    });
  } catch {
    // ignore status reporting failures
  }
}

export async function getJoinTokens() {
  const provided = (process.env.MZ_JOIN_SECRET || '').trim();
  if (!provided) {
    return null;
  }

  const apiVersion = await getDockerApiVersion();
  const swarmInfo = await dockerRequest(`/${apiVersion}/swarm`);
  const joinTokens = swarmInfo?.JoinTokens || {};
  return {
    worker: joinTokens.Worker || '',
    manager: joinTokens.Manager || '',
  };
}

export async function handleJoinTokenRequest(secretHeader: string | undefined) {
  const expected = process.env.MZ_JOIN_SECRET || '';
  if (!expected || secretHeader !== expected) {
    return { status: 403, body: { error: 'forbidden' } } as const;
  }

  try {
    const tokens = await getJoinTokens();
    if (!tokens) {
      return { status: 502, body: { error: 'swarm_unavailable' } } as const;
    }
    return { status: 200, body: tokens } as const;
  } catch {
    return { status: 502, body: { error: 'swarm_unavailable' } } as const;
  }
}

export function startTuningScheduler() {
  if (process.env.MZ_TUNING_SCHEDULER_ENABLED === '0') {
    return;
  }
  const intervalMs = TUNING_INTERVAL_MS;
  const run = async () => {
    const manager = await isSwarmManager();
    if (!manager) {
      return;
    }
    try {
      await buildPlannerPayload();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('tuning.scheduler.failed', { message });
    }
  };
  void run();
  setInterval(() => {
    void run();
  }, intervalMs);
}

export function startInspectionScheduler() {
  if (process.env.MZ_INSPECTION_SCHEDULER_ENABLED === '0') {
    return;
  }
  const intervalMs = INSPECTION_INTERVAL_MS;
  const run = async () => {
    const manager = await isSwarmManager();
    if (!manager) {
      return;
    }
    try {
      await recordInspectionSnapshot();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('inspection.scheduler.failed', { message });
    }
  };
  void run();
  setInterval(() => {
    void run();
  }, intervalMs);
}

export function startStatusReporter() {
  if (process.env.MZ_STATUS_REPORT_ENABLED === '0') {
    return;
  }
  const intervalMs = Number(process.env.MZ_STATUS_REPORT_INTERVAL_MS || 60000);
  void pushStatus();
  setInterval(() => {
    void pushStatus();
  }, intervalMs);
}
