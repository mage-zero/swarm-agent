import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { createApp } from '../src/app.js';

const originalEnv = { ...process.env };

describe('status endpoint', () => {
  beforeEach(() => {
    process.env.MZ_DISABLE_DOCKER = '1';
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns html by default', async () => {
    const res = await createApp().request('/');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('MageZero Provisioning Status');
  });

  it('returns json when format=json', async () => {
    const res = await createApp().request('/?format=json', {
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('generated_at');
  });

  it('rejects join-token without secret', async () => {
    process.env.MZ_JOIN_SECRET = 'test-secret';
    const res = await createApp().request('/join-token');
    expect(res.status).toBe(403);
  });
});
