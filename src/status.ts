import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';

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

type CapacityNode = {
  id?: string;
  hostname?: string;
  role?: string;
  status?: string;
  availability?: string;
  labels?: Record<string, string>;
  address?: string;
  resources?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  reservations?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  free?: {
    cpu_cores: number;
    memory_bytes: number;
  };
  tasks?: {
    running: number;
    services: string[];
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
  warnings: string[];
  recommendations: PlannerRecommendation[];
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

function dockerRequest(path: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath: DOCKER_SOCKET,
        path,
        method: 'GET',
        headers: {
          Host: 'docker',
          Connection: 'close',
        },
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          try {
            resolve(JSON.parse(body));
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
    req.end();
  });
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
    warnings,
    recommendations,
  };
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
