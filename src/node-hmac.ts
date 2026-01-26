import crypto from 'crypto';

export function buildSignature(
  method: string,
  path: string,
  query: string,
  timestamp: string,
  nonce: string,
  body: string,
  secret: string,
): string {
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

export function buildNodeHeaders(
  method: string,
  path: string,
  query: string,
  body: string,
  nodeId: string,
  secret: string,
) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const signature = buildSignature(method, path, query, timestamp, nonce, body, secret);

  const headers: Record<string, string> = {
    'X-MZ-Node-Id': nodeId,
    'X-MZ-Timestamp': timestamp,
    'X-MZ-Nonce': nonce,
    'X-MZ-Signature': signature,
  };

  return headers;
}
