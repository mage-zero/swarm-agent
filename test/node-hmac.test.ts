import crypto from 'crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildNodeHeaders, buildSignature } from '../src/node-hmac.js';

describe('node hmac helpers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('builds deterministic signatures from canonical request data', () => {
    const method = 'post';
    const requestPath = '/v1/deploy/status';
    const query = 'a=1&b=2';
    const timestamp = '1771305600';
    const nonce = 'nonce-1';
    const body = '{"ok":true}';
    const secret = 'top-secret';

    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    const canonical = [
      method.toUpperCase(),
      requestPath,
      query,
      timestamp,
      nonce,
      bodyHash,
    ].join('\n');
    const expected = crypto.createHmac('sha256', secret).update(canonical).digest('base64');

    expect(buildSignature(method, requestPath, query, timestamp, nonce, body, secret)).toBe(expected);
  });

  it('changes signature when request body changes', () => {
    const commonArgs = ['POST', '/v1/x', '', '1771305600', 'nonce', 'secret'] as const;
    const sigA = buildSignature(commonArgs[0], commonArgs[1], commonArgs[2], commonArgs[3], commonArgs[4], '{"a":1}', commonArgs[5]);
    const sigB = buildSignature(commonArgs[0], commonArgs[1], commonArgs[2], commonArgs[3], commonArgs[4], '{"a":2}', commonArgs[5]);
    expect(sigA).not.toBe(sigB);
  });

  it('builds node headers with timestamp, nonce, and matching signature', () => {
    const now = new Date('2026-02-17T10:11:12.000Z');
    vi.useFakeTimers();
    vi.setSystemTime(now);
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('nonce-fixed');

    const headers = buildNodeHeaders(
      'POST',
      '/v1/deploy/status',
      'debug=1',
      '{"id":"abc"}',
      'node-123',
      'secret-key',
    );
    const expectedTimestamp = String(Math.floor(now.getTime() / 1000));
    const expectedSignature = buildSignature(
      'POST',
      '/v1/deploy/status',
      'debug=1',
      expectedTimestamp,
      'nonce-fixed',
      '{"id":"abc"}',
      'secret-key',
    );

    expect(headers['X-MZ-Node-Id']).toBe('node-123');
    expect(headers['X-MZ-Timestamp']).toBe(expectedTimestamp);
    expect(headers['X-MZ-Nonce']).toBe('nonce-fixed');
    expect(headers['X-MZ-Signature']).toBe(expectedSignature);
  });
});
