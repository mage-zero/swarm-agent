import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildNodeHeaders, buildSignature } from '../src/node-hmac.js';

const originalEnv = { ...process.env };

async function writeNodeIdentity(nodeDir: string) {
  await fs.writeFile(path.join(nodeDir, 'node-id'), 'node-123\n', 'utf8');
  await fs.writeFile(path.join(nodeDir, 'node-secret'), 'secret-key\n', 'utf8');
}

async function loadStatusModule(nodeDir: string, extraEnv: Record<string, string> = {}) {
  process.env = {
    ...originalEnv,
    MZ_DISABLE_DOCKER: '1',
    MZ_NODE_DIR: nodeDir,
    ...extraEnv,
  };
  vi.resetModules();
  return import('../src/status.js');
}

function signedRequest(pathName: string, options: {
  method?: string;
  query?: string;
  body?: string;
  nodeId?: string;
  secret?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
} = {}) {
  const method = options.method || 'GET';
  const query = options.query || '';
  const body = options.body || '';
  const nodeId = options.nodeId || 'node-123';
  const secret = options.secret || 'secret-key';
  const timestamp = options.timestamp || String(Math.floor(Date.now() / 1000));
  const nonce = options.nonce || 'nonce-123';
  const signature = options.signature
    || buildSignature(method, pathName, query, timestamp, nonce, body, secret);
  const url = query ? `http://localhost${pathName}?${query}` : `http://localhost${pathName}`;
  return new Request(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-MZ-Node-Id': nodeId,
      'X-MZ-Timestamp': timestamp,
      'X-MZ-Nonce': nonce,
      'X-MZ-Signature': signature,
    },
    body: method === 'GET' ? undefined : body,
  });
}

describe('status auth helpers', () => {
  let nodeDir = '';

  beforeEach(async () => {
    nodeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mz-status-auth-'));
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    vi.resetModules();
    await fs.rm(nodeDir, { recursive: true, force: true });
  });

  it('returns false when node identity files are missing', async () => {
    const { validateNodeRequest } = await loadStatusModule(nodeDir);
    const request = signedRequest('/v1/planner');

    await expect(validateNodeRequest(request)).resolves.toBe(false);
  });

  it('returns false when auth headers are missing', async () => {
    await writeNodeIdentity(nodeDir);
    const { validateNodeRequest } = await loadStatusModule(nodeDir);
    const request = new Request('http://localhost/v1/planner');

    await expect(validateNodeRequest(request)).resolves.toBe(false);
  });

  it('returns false when the node id does not match', async () => {
    await writeNodeIdentity(nodeDir);
    const { validateNodeRequest } = await loadStatusModule(nodeDir);
    const request = signedRequest('/v1/planner', { nodeId: 'node-999' });

    await expect(validateNodeRequest(request)).resolves.toBe(false);
  });

  it('returns false when the timestamp is outside the accepted window', async () => {
    await writeNodeIdentity(nodeDir);
    const { validateNodeRequest } = await loadStatusModule(nodeDir);
    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 600);
    const request = signedRequest('/v1/planner', {
      timestamp: staleTimestamp,
      nonce: 'nonce-old',
    });

    await expect(validateNodeRequest(request)).resolves.toBe(false);
  });

  it('returns false when the signature does not match', async () => {
    await writeNodeIdentity(nodeDir);
    const { validateNodeRequest } = await loadStatusModule(nodeDir);
    const request = signedRequest('/v1/planner', {
      signature: 'invalid-signature',
    });

    await expect(validateNodeRequest(request)).resolves.toBe(false);
  });

  it('accepts a correctly signed request with query and body', async () => {
    await writeNodeIdentity(nodeDir);
    const { validateNodeRequest } = await loadStatusModule(nodeDir);
    const request = signedRequest('/v1/tuning/approve', {
      method: 'POST',
      query: 'debug=1',
      body: JSON.stringify({ profile_id: 'profile-1' }),
      nonce: 'nonce-valid',
    });

    await expect(validateNodeRequest(request)).resolves.toBe(true);
  });

  it('rejects unsigned tuning approval requests', async () => {
    await writeNodeIdentity(nodeDir);
    const { handleTuningApprovalRequest } = await loadStatusModule(nodeDir);
    const request = new Request('http://localhost/v1/tuning/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    await expect(handleTuningApprovalRequest(request)).resolves.toEqual({
      status: 401,
      body: { error: 'Unauthorized' },
    });
  });

  it('rejects authorized tuning approvals without a profile id', async () => {
    await writeNodeIdentity(nodeDir);
    const { handleTuningApprovalRequest } = await loadStatusModule(nodeDir);
    const body = JSON.stringify({});
    const request = new Request('http://localhost/v1/tuning/approve', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...buildNodeHeaders('POST', '/v1/tuning/approve', '', body, 'node-123', 'secret-key'),
      },
      body,
    });

    await expect(handleTuningApprovalRequest(request)).resolves.toEqual({
      status: 400,
      body: { error: 'Missing profile_id' },
    });
  });

  it('rejects unsigned tuning disapproval requests', async () => {
    await writeNodeIdentity(nodeDir);
    const { handleTuningDisapprovalRequest } = await loadStatusModule(nodeDir);
    const request = new Request('http://localhost/v1/tuning/disapprove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    await expect(handleTuningDisapprovalRequest(request)).resolves.toEqual({
      status: 401,
      body: { error: 'Unauthorized' },
    });
  });

  it('rejects authorized tuning disapprovals without a profile id', async () => {
    await writeNodeIdentity(nodeDir);
    const { handleTuningDisapprovalRequest } = await loadStatusModule(nodeDir);
    const body = JSON.stringify({});
    const request = new Request('http://localhost/v1/tuning/disapprove', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...buildNodeHeaders('POST', '/v1/tuning/disapprove', '', body, 'node-123', 'secret-key'),
      },
      body,
    });

    await expect(handleTuningDisapprovalRequest(request)).resolves.toEqual({
      status: 400,
      body: { error: 'Missing profile_id' },
    });
  });

  it('rejects unsigned node removal requests', async () => {
    await writeNodeIdentity(nodeDir);
    const { handleNodeRemovalRequest } = await loadStatusModule(nodeDir);
    const request = new Request('http://localhost/v1/swarm/nodes/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    await expect(handleNodeRemovalRequest(request)).resolves.toEqual({
      status: 401,
      body: { error: 'Unauthorized' },
    });
  });

  it('rejects authorized node removal requests when the node is not a manager', async () => {
    await writeNodeIdentity(nodeDir);
    const { handleNodeRemovalRequest } = await loadStatusModule(nodeDir);
    const body = JSON.stringify({ node_id: 123 });
    const request = new Request('http://localhost/v1/swarm/nodes/remove', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...buildNodeHeaders('POST', '/v1/swarm/nodes/remove', '', body, 'node-123', 'secret-key'),
      },
      body,
    });

    await expect(handleNodeRemovalRequest(request)).resolves.toEqual({
      status: 403,
      body: { error: 'not_manager' },
    });
  });
});
