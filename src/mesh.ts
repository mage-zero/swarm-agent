import fs from 'fs';
import { execSync } from 'child_process';
import { buildNodeHeaders } from './node-hmac.js';
import { getJoinTokens, isSwarmManager, readConfig, readNodeFile } from './status.js';

const WIREGUARD_CONF = '/etc/wireguard/wg0.conf';
const WIREGUARD_PRIVATE_KEY = '/etc/wireguard/mz-private.key';
const WIREGUARD_PORT = 51820;

function readPrivateKey(): string {
  try {
    if (fs.existsSync(WIREGUARD_PRIVATE_KEY)) {
      return fs.readFileSync(WIREGUARD_PRIVATE_KEY, 'utf8').trim();
    }
  } catch {
    // ignore
  }

  try {
    const existing = fs.readFileSync(WIREGUARD_CONF, 'utf8');
    const match = existing.match(/^\s*PrivateKey\s*=\s*(.+)$/m);
    if (match && match[1]) {
      return match[1].trim();
    }
  } catch {
    // ignore
  }

  return '';
}

function readMeshIp(): string {
  try {
    const existing = fs.readFileSync(WIREGUARD_CONF, 'utf8');
    const match = existing.match(/^\s*Address\s*=\s*([^\s/]+)(?:\/\d+)?\s*$/m);
    if (match && match[1]) {
      return match[1].trim();
    }
  } catch {
    // ignore
  }
  return '';
}

function readPublicKey(): string {
  const privateKey = readPrivateKey();
  if (!privateKey) {
    return '';
  }
  try {
    const proc = execSync('wg pubkey', { input: privateKey, stdio: ['pipe', 'pipe', 'ignore'] });
    return proc.toString('utf8').trim();
  } catch {
    return '';
  }
}

function buildWireguardConfig(meshIp: string, privateKey: string, peers: Array<Record<string, unknown>>): string {
  const lines = [
    '[Interface]',
    `Address = ${meshIp}/16`,
    `ListenPort = ${WIREGUARD_PORT}`,
    `PrivateKey = ${privateKey}`,
  ];

  for (const peer of peers) {
    const peerKey = typeof peer.wireguard_public_key === 'string' ? peer.wireguard_public_key.trim() : '';
    const peerIp = typeof peer.wireguard_ip === 'string' ? peer.wireguard_ip.trim() : '';
    const peerEndpoint = typeof peer.ip_address === 'string' ? peer.ip_address.trim() : '';
    if (!peerKey || !peerIp || !peerEndpoint) {
      continue;
    }
    lines.push('', '[Peer]');
    lines.push(`PublicKey = ${peerKey}`);
    lines.push(`Endpoint = ${peerEndpoint}:${WIREGUARD_PORT}`);
    lines.push(`AllowedIPs = ${peerIp}/32`);
    lines.push('PersistentKeepalive = 25');
  }

  return `${lines.join('\n')}\n`;
}

function applyWireguardConfig(config: string): void {
  let existing = '';
  try {
    existing = fs.readFileSync(WIREGUARD_CONF, 'utf8');
  } catch {
    existing = '';
  }

  if (existing === config) {
    return;
  }

  fs.writeFileSync(WIREGUARD_CONF, config, { encoding: 'utf8', mode: 0o600 });

  try {
    const hasWg = fs.existsSync('/sys/class/net/wg0');
    if (hasWg) {
      execSync('wg syncconf wg0 <(wg-quick strip /etc/wireguard/wg0.conf)', {
        stdio: 'ignore',
        shell: '/bin/bash',
      });
      return;
    }
  } catch {
    // fall through to restart
  }

  try {
    execSync('systemctl enable wg-quick@wg0', { stdio: 'ignore' });
    execSync('systemctl restart wg-quick@wg0', { stdio: 'ignore' });
  } catch {
    // ignore restart errors
  }
}

async function fetchMeshPayload(): Promise<{ stack_id: number; nodes: Array<Record<string, unknown>> } | null> {
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

  const url = new URL(`/v1/stack/mesh?stack_id=${stackId}`, baseUrl);
  const headers = buildNodeHeaders('GET', url.pathname, url.search.slice(1), '', nodeId, nodeSecret);
  headers['Accept'] = 'application/json';

  const response = await fetch(url.toString(), { headers });
  if (!response.ok) {
    return null;
  }
  const payload = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (!payload || typeof payload !== 'object') {
    return null;
  }
  const nodes = Array.isArray(payload.nodes) ? payload.nodes as Array<Record<string, unknown>> : [];
  return { stack_id: stackId, nodes };
}

async function publishMeshSelf(stackId: number, nodeId: string, nodeSecret: string): Promise<void> {
  const baseUrl = readConfig().mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '';
  if (!baseUrl) {
    return;
  }

  const wireguardIp = readMeshIp();
  const publicKey = readPublicKey();
  if (!wireguardIp || !publicKey) {
    return;
  }

  const payload = JSON.stringify({
    stack_id: stackId,
    wireguard_ip: wireguardIp,
    wireguard_public_key: publicKey,
  });
  const url = new URL('/v1/stack/mesh/self', baseUrl);
  const headers = buildNodeHeaders('POST', url.pathname, url.search.slice(1), payload, nodeId, nodeSecret);
  headers['Content-Type'] = 'application/json';
  headers['Accept'] = 'application/json';

  await fetch(url.toString(), { method: 'POST', headers, body: payload }).catch(() => null);
}

export async function syncMeshPeers(): Promise<void> {
  const payload = await fetchMeshPayload();
  if (!payload) {
    return;
  }

  const nodeIdRaw = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  const nodeId = Number(nodeIdRaw || 0);
  if (!nodeId || !nodeIdRaw || !nodeSecret) {
    return;
  }

  const nodes = payload.nodes;
  const self = nodes.find((node) => Number(node?.node_id || 0) === nodeId);
  if (!self) {
    return;
  }

  const meshIp = typeof self.wireguard_ip === 'string' ? self.wireguard_ip.trim() : '';
  const selfPublicKey = typeof self.wireguard_public_key === 'string' ? self.wireguard_public_key.trim() : '';
  if (!meshIp || !selfPublicKey) {
    await publishMeshSelf(payload.stack_id, nodeIdRaw, nodeSecret);
    return;
  }

  const privateKey = readPrivateKey();
  if (!privateKey) {
    return;
  }

  const peers = nodes.filter((node) => Number(node?.node_id || 0) !== nodeId);
  const config = buildWireguardConfig(meshIp, privateKey, peers);
  applyWireguardConfig(config);
}

export async function handleMeshJoinRequest(request: Request) {
  if (!await isSwarmManager()) {
    return { status: 403, body: { error: 'not_manager' } } as const;
  }

  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  const stackId = Number(body?.stack_id || 0);
  const nodeId = Number(body?.node_id || 0);
  const token = typeof body?.bootstrap_token === 'string' ? body.bootstrap_token.trim() : '';
  const publicKey = typeof body?.wireguard_public_key === 'string' ? body.wireguard_public_key.trim() : '';
  const publicIp = typeof body?.ip_address === 'string' ? body.ip_address.trim() : '';

  if (!stackId || !nodeId || !token || !publicKey) {
    return { status: 400, body: { error: 'missing_payload' } } as const;
  }

  const config = readConfig();
  const baseUrl = config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '';
  if (!baseUrl) {
    return { status: 500, body: { error: 'missing_mz_control' } } as const;
  }

  const managerNodeId = readNodeFile('node-id');
  const managerSecret = readNodeFile('node-secret');
  if (!managerNodeId || !managerSecret) {
    return { status: 500, body: { error: 'missing_node_secret' } } as const;
  }

  const payload = JSON.stringify({
    stack_id: stackId,
    node_id: nodeId,
    bootstrap_token: token,
    wireguard_public_key: publicKey,
    ip_address: publicIp,
  });
  const url = new URL('/v1/stack/mesh/register', baseUrl);
  const headers = buildNodeHeaders('POST', url.pathname, url.search.slice(1), payload, managerNodeId, managerSecret);
  headers['Content-Type'] = 'application/json';
  headers['Accept'] = 'application/json';

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body: payload,
  });
  const responseText = await response.text();
  if (!response.ok) {
    return { status: response.status, body: { error: responseText || 'mesh_register_failed' } } as const;
  }

  let registerPayload: Record<string, unknown> | null = null;
  try {
    registerPayload = JSON.parse(responseText) as Record<string, unknown>;
  } catch {
    registerPayload = null;
  }
  if (!registerPayload) {
    return { status: 502, body: { error: 'invalid_mesh_response' } } as const;
  }

  const joinTokens = await getJoinTokens();
  if (!joinTokens) {
    return { status: 502, body: { error: 'swarm_unavailable' } } as const;
  }

  return {
    status: 200,
    body: {
      mesh_ip: registerPayload.mesh_ip,
      peers: registerPayload.peers,
      join_tokens: joinTokens,
    },
  } as const;
}

export function startMeshSyncScheduler() {
  if (process.env.MZ_MESH_SYNC_ENABLED === '0') {
    return;
  }
  const intervalMs = Number(process.env.MZ_MESH_SYNC_INTERVAL_MS || 300000);
  const run = async () => {
    try {
      await syncMeshPeers();
    } catch {
      // ignore sync errors
    }
  };
  void run();
  setInterval(run, intervalMs).unref();
}
