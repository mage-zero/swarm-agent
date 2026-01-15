import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import os from 'os';

export type StatusConfig = {
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

const CONFIG_PATH = process.env.STATUS_CONFIG_PATH || '/opt/status/data.json';
const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';

let cachedDockerApiVersion: string | null = null;
let cachedDockerApiVersionAt = 0;

export function readConfig(): StatusConfig {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) as StatusConfig;
  } catch {
    return { stack_domain: '', nodes: [] };
  }
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

async function getSwarmSummary(): Promise<SwarmSummary> {
  if (process.env.MZ_DISABLE_DOCKER === '1') {
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

export async function buildStatusPayload(reqHost: string, wantsJson: boolean) {
  const config = readConfig();
  const swarm = await getSwarmSummary();
  const nodeAssignments = mapSwarmNodes(config.nodes || [], swarm.nodes || []);
  const summary = {
    host: reqHost,
    stack_domain: config.stack_domain || '',
    stack_name: config.stack_name || '',
    generated_at: new Date().toISOString(),
    swarm,
  };

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
    `  <div class="hint">Host: ${escapeHtml(reqHost || 'unknown')}</div>`,
    `  <pre>${escapeHtml(JSON.stringify(payload, null, 2))}</pre>`,
    '</body>',
    '</html>',
  ].join('\n');

  return { type: 'html' as const, payload: html };
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

  const swarm = await getSwarmSummary();
  const stackStatus = swarm.total > 0 && swarm.nodes.every((node) => node.status === 'ready')
    ? 'healthy'
    : 'unhealthy';

  const localHostname = os.hostname();
  const swarmNode = swarm.nodes.find((node) => node.labels?.['mz.node_id'] === String(nodeId))
    || swarm.nodes.find((node) => node.hostname === localHostname);
  const nodeStatus = swarmNode && swarmNode.status === 'ready' ? 'active' : 'provisioning';

  const cloudInitStatus = readCloudInitStatus();
  const cloudInitPayload = cloudInitStatus ? JSON.stringify(cloudInitStatus) : null;
  const masterSshPublicKey = readNodeFile('stack_master_ssh.pub');
  const payload: Record<string, unknown> = {
    status: nodeStatus,
    stack_status: stackStatus,
    cloud_init_status: cloudInitPayload,
  };
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
