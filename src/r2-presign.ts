import crypto from 'crypto';

export function presignS3Url(params: {
  method: 'PUT' | 'GET';
  endpoint: string;
  bucket: string;
  key: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  expiresIn: number;
}) {
  const endpointUrl = new URL(params.endpoint);
  const host = endpointUrl.host;
  const now = new Date();
  const amzDate = toAmzDate(now);
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${params.region}/s3/aws4_request`;
  const signedHeaders = 'host';

  const canonicalUri = `/${encodePath(`${params.bucket}/${params.key}`)}`;
  const queryParams: Array<[string, string]> = [
    ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
    ['X-Amz-Credential', `${params.accessKeyId}/${credentialScope}`],
    ['X-Amz-Date', amzDate],
    ['X-Amz-Expires', String(params.expiresIn)],
    ['X-Amz-SignedHeaders', signedHeaders],
    ['X-Amz-Content-Sha256', 'UNSIGNED-PAYLOAD'],
  ];
  const canonicalQuery = buildCanonicalQuery(queryParams);

  const canonicalHeaders = `host:${host}\n`;
  const canonicalRequest = [
    params.method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    hashHex(canonicalRequest),
  ].join('\n');

  const signingKey = getSigningKey(params.secretAccessKey, dateStamp, params.region, 's3');
  const signature = hmac(signingKey, stringToSign).toString('hex');

  const finalQuery = `${canonicalQuery}&X-Amz-Signature=${signature}`;
  return `${endpointUrl.origin}${canonicalUri}?${finalQuery}`;
}

function toAmzDate(date: Date) {
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
}

function encodePath(path: string) {
  return path
    .split('/')
    .map((part) => encodeRfc3986(part))
    .join('/');
}

function encodeRfc3986(value: string) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function buildCanonicalQuery(params: Array<[string, string]>) {
  return params
    .map(([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)])
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])))
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
}

function hashHex(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hmac(key: Buffer, value: string) {
  return crypto.createHmac('sha256', key).update(value).digest();
}

function getSigningKey(secret: string, dateStamp: string, region: string, service: string) {
  const kDate = hmac(Buffer.from(`AWS4${secret}`, 'utf8'), dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}
