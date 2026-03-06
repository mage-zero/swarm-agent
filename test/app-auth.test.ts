import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildNodeHeaders } from '../src/node-hmac.js';

const originalEnv = { ...process.env };

async function writeNodeIdentity(nodeDir: string) {
  await fs.writeFile(path.join(nodeDir, 'node-id'), 'node-123\n', 'utf8');
  await fs.writeFile(path.join(nodeDir, 'node-secret'), 'secret-key\n', 'utf8');
}

async function loadApp(nodeDir: string) {
  process.env = {
    ...originalEnv,
    MZ_DISABLE_DOCKER: '1',
    MZ_NODE_DIR: nodeDir,
  };
  vi.resetModules();
  const { createApp } = await import('../src/app.js');
  return createApp();
}

function signedHeaders(pathName: string, query = '') {
  return {
    Accept: 'application/json',
    ...buildNodeHeaders('GET', pathName, query, '', 'node-123', 'secret-key'),
  };
}

describe('agent read endpoint auth', () => {
  let nodeDir = '';

  beforeEach(async () => {
    nodeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mz-agent-auth-'));
    await writeNodeIdentity(nodeDir);
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    vi.resetModules();
    await fs.rm(nodeDir, { recursive: true, force: true });
  });

  it.each([
    '/v1/planner',
    '/v1/services',
    '/v1/support/runbooks',
  ])('rejects %s without node auth', async (pathname) => {
    const app = await loadApp(nodeDir);
    const response = await app.request(pathname);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Unauthorized' });
  });

  it.each([
    '/v1/planner',
    '/v1/services',
    '/v1/support/runbooks',
  ])('accepts signed requests for %s', async (pathname) => {
    const app = await loadApp(nodeDir);
    const response = await app.request(pathname, { headers: signedHeaders(pathname) });

    expect(response.status).toBe(200);
  });

  it('ignores include expansions on unsigned root status requests', async () => {
    const app = await loadApp(nodeDir);
    const response = await app.request('/?format=json&include=capacity,planner,services', {
      headers: { Accept: 'application/json' },
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toHaveProperty('generated_at');
    expect(body).not.toHaveProperty('capacity');
    expect(body).not.toHaveProperty('planner');
    expect(body).not.toHaveProperty('services');
  });

  it('keeps include expansions for signed root status requests', async () => {
    const query = 'format=json&include=capacity,planner,services';
    const app = await loadApp(nodeDir);
    const response = await app.request(`/?${query}`, {
      headers: signedHeaders('/', query),
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toHaveProperty('capacity');
    expect(body).toHaveProperty('planner');
    expect(body).toHaveProperty('services');
  });
});
