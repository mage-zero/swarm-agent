import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import { presignS3Url } from './r2-presign.js';
import { isSwarmManager, readConfig } from './status.js';

type DeployPayload = {
  artifact?: string;
  stack_id?: number;
  environment_id?: number;
  repository?: string;
  ref?: string;
};

type DeploymentRecord = {
  id?: string;
  queued_at?: string;
  payload?: DeployPayload;
};

type R2Credentials = {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  endpoint: string;
  region?: string;
};

type R2CredFile = {
  environment_id?: number;
  backups?: R2Credentials;
  media?: R2Credentials;
  updated_at?: string;
};

type EnvironmentSecrets = {
  crypt_key?: string;
  graphql_id_salt?: string;
};

type AppSelection = { flavor?: string; version?: string };
type ApplicationSelections = {
  php?: string;
  varnish?: string;
  database?: AppSelection;
  search?: AppSelection;
  cache?: AppSelection;
  queue?: AppSelection;
};

type EnvironmentRecord = {
  environment_id?: number;
  stack_id?: number;
  db_backup_bucket?: string;
  db_backup_object?: string;
  application_selections?: ApplicationSelections;
  environment_secrets?: EnvironmentSecrets | null;
};

const NODE_DIR = process.env.MZ_NODE_DIR || '/opt/mz-node';
const DEPLOY_QUEUE_DIR = process.env.MZ_DEPLOY_QUEUE_DIR || '/opt/mage-zero/deployments';
const DEPLOY_WORK_DIR = process.env.MZ_DEPLOY_WORK_DIR || '/opt/mage-zero/deployments/work';
const CLOUD_SWARM_DIR = process.env.MZ_CLOUD_SWARM_DIR || '/opt/mage-zero/cloud-swarm';
const CLOUD_SWARM_REPO = process.env.MZ_CLOUD_SWARM_REPO || 'git@github.com:mage-zero/cloud-swarm.git';
const CLOUD_SWARM_KEY_PATH = process.env.MZ_CLOUD_SWARM_KEY_PATH || '/opt/mage-zero/keys/cloud-swarm-deploy';
const R2_CRED_DIR = process.env.MZ_R2_CRED_DIR || '/opt/mage-zero/r2';
const STACK_MASTER_KEY_PATH = process.env.MZ_STACK_MASTER_KEY_PATH || '/etc/magezero/stack_master_ssh';
const DEFAULT_DB_BACKUP_OBJECT = process.env.MZ_DB_BACKUP_OBJECT || 'provisioning-database.sql.zst.age';
const SECRET_VERSION = process.env.MZ_SECRET_VERSION || '1';
const DEPLOY_INTERVAL_MS = Number(process.env.MZ_DEPLOY_WORKER_INTERVAL_MS || 5000);
const FETCH_TIMEOUT_MS = Number(process.env.MZ_FETCH_TIMEOUT_MS || 30000);

let processing = false;

function readNodeFile(name: string): string {
  try {
    return fs.readFileSync(path.join(NODE_DIR, name), 'utf8').trim();
  } catch {
    return '';
  }
}

function ensureDir(target: string) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function listQueueFiles(): string[] {
  if (!fs.existsSync(DEPLOY_QUEUE_DIR)) {
    return [];
  }
  return fs.readdirSync(DEPLOY_QUEUE_DIR, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => path.join(DEPLOY_QUEUE_DIR, entry.name))
    .sort((a, b) => a.localeCompare(b));
}

function claimNextDeployment(): string | null {
  const files = listQueueFiles();
  if (!files.length) {
    return null;
  }

  ensureDir(DEPLOY_QUEUE_DIR);
  const processingDir = path.join(DEPLOY_QUEUE_DIR, 'processing');
  ensureDir(processingDir);

  const source = files[0];
  const target = path.join(processingDir, path.basename(source));
  try {
    fs.renameSync(source, target);
    return target;
  } catch {
    return null;
  }
}

async function runCommand(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  // TODO: Harden command execution with an allowlist or explicit wrappers before production.
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: 'inherit',
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
      }
    });
  });
}

async function runCommandLogged(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; logDir: string; label: string }
) {
  ensureDir(options.logDir);
  const safeLabel = options.label.replace(/[^a-z0-9._-]/gi, '_');
  const stdoutPath = path.join(options.logDir, `${safeLabel}.stdout.log`);
  const stderrPath = path.join(options.logDir, `${safeLabel}.stderr.log`);
  const header = `\n# ${new Date().toISOString()} ${command} ${args.join(' ')}\n`;
  fs.appendFileSync(stdoutPath, header);
  fs.appendFileSync(stderrPath, header);

  await new Promise<void>((resolve, reject) => {
    const stdoutStream = fs.createWriteStream(stdoutPath, { flags: 'a' });
    const stderrStream = fs.createWriteStream(stderrPath, { flags: 'a' });
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => {
      stdoutStream.write(chunk);
      process.stdout.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrStream.write(chunk);
      process.stderr.write(chunk);
    });
    child.on('error', (error) => {
      stdoutStream.end();
      stderrStream.end();
      reject(error);
    });
    child.on('close', (code) => {
      stdoutStream.end();
      stderrStream.end();
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
      }
    });
  });
}

async function runCommandCapture(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  return await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${args.join(' ')} failed: ${stderr || stdout}`));
      }
    });
  });
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function generateSecretHex(bytes: number) {
  return crypto.randomBytes(bytes).toString('hex');
}

async function ensureDockerSecret(secretName: string, value: string, workDir: string) {
  if (!value) {
    throw new Error(`Missing secret value for ${secretName}`);
  }
  try {
    await runCommandCapture('docker', ['secret', 'inspect', secretName]);
    return;
  } catch {
    // secret missing
  }

  ensureDir(workDir);
  const secretPath = path.join(workDir, `${secretName}.secret`);
  fs.writeFileSync(secretPath, value, { mode: 0o600 });
  try {
    await runCommand('docker', ['secret', 'create', secretName, secretPath]);
  } finally {
    try {
      fs.unlinkSync(secretPath);
    } catch {
      // ignore cleanup failure
    }
  }
}

function readR2CredFile(environmentId: number): R2CredFile | null {
  try {
    const raw = fs.readFileSync(path.join(R2_CRED_DIR, `env-${environmentId}.json`), 'utf8');
    return JSON.parse(raw) as R2CredFile;
  } catch {
    return null;
  }
}

function buildSignature(method: string, pathName: string, query: string, timestamp: string, nonce: string, body: string, secret: string) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [
    method.toUpperCase(),
    pathName,
    query,
    timestamp,
    nonce,
    bodyHash,
  ].join('\n');
  return crypto.createHmac('sha256', secret).update(stringToSign).digest('base64');
}

function buildNodeHeaders(method: string, pathName: string, query: string, body: string, nodeId: string, secret: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const signature = buildSignature(method, pathName, query, timestamp, nonce, body, secret);
  return {
    'X-MZ-Node-Id': nodeId,
    'X-MZ-Timestamp': timestamp,
    'X-MZ-Nonce': nonce,
    'X-MZ-Signature': signature,
  };
}

async function fetchJson(baseUrl: string, pathName: string, method: string, body: string | null, nodeId: string, nodeSecret: string) {
  const url = new URL(pathName, baseUrl);
  const query = url.search ? url.search.slice(1) : '';
  const payload = body ?? '';
  const headers = buildNodeHeaders(method, url.pathname, query, payload, nodeId, nodeSecret);
  const controller = new AbortController();
  const timeoutMs = Number.isFinite(FETCH_TIMEOUT_MS) && FETCH_TIMEOUT_MS > 0 ? FETCH_TIMEOUT_MS : 30000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...headers,
      },
      body: payload || undefined,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`mz-control request failed: ${response.status} - ${errorBody}`);
  }

  return response.json() as Promise<any>;
}

async function fetchEnvironmentRecord(stackId: number, environmentId: number, baseUrl: string, nodeId: string, nodeSecret: string) {
  const payload = await fetchJson(
    baseUrl,
    `/v1/agent/stack/${stackId}/environments`,
    'GET',
    null,
    nodeId,
    nodeSecret,
  );
  const environments = Array.isArray(payload?.environments) ? payload.environments as EnvironmentRecord[] : [];
  return environments.find((env) => Number(env.environment_id ?? 0) === environmentId) || null;
}

function normalizeSelectionFlavor(flavor: string | undefined, fallback: string): string {
  return (flavor || fallback).toLowerCase();
}

function resolveVersionEnv(selections: ApplicationSelections | undefined) {
  const phpVersion = selections?.php || '';
  const varnishVersion = selections?.varnish || '';
  const databaseFlavor = normalizeSelectionFlavor(selections?.database?.flavor, 'mariadb');
  const databaseVersion = selections?.database?.version || '';
  const searchFlavor = normalizeSelectionFlavor(selections?.search?.flavor, 'opensearch');
  const searchVersion = selections?.search?.version || '';
  const cacheFlavor = normalizeSelectionFlavor(selections?.cache?.flavor, 'redis');
  const cacheVersion = selections?.cache?.version || '';
  const queueFlavor = normalizeSelectionFlavor(selections?.queue?.flavor, 'rabbitmq');
  const queueVersion = selections?.queue?.version || '';

  const mappedDb = databaseFlavor === 'mysql' ? 'mariadb' : databaseFlavor;
  const mappedSearch = searchFlavor === 'elasticsearch' ? 'opensearch' : searchFlavor;
  const mappedCache = cacheFlavor === 'valkey' ? 'redis' : cacheFlavor;
  const mappedQueue = queueFlavor === 'activemq-artemis' ? 'rabbitmq' : queueFlavor;

  return {
    phpVersion,
    varnishVersion,
    mariadbVersion: mappedDb === 'mariadb' ? databaseVersion : '',
    opensearchVersion: mappedSearch === 'opensearch' ? searchVersion : '',
    redisVersion: mappedCache === 'redis' ? cacheVersion : '',
    rabbitmqVersion: mappedQueue === 'rabbitmq' ? queueVersion : '',
  };
}

function readVersionDefaults(): Record<string, string> {
  const file = path.join(CLOUD_SWARM_DIR, 'config/versions.env');
  if (!fs.existsSync(file)) {
    return {};
  }
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const output: Record<string, string> = {};
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const idx = trimmed.indexOf('=');
    if (idx === -1) {
      continue;
    }
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (key && value) {
      output[key] = value;
    }
  }
  return output;
}

function resolveImageTag(artifactKey: string, ref: string, deploymentId: string) {
  const base = path.basename(artifactKey);
  const match = base.match(/-([0-9a-f]{7,40})\.tar\.zst$/);
  if (match) {
    return match[1].slice(0, 12);
  }
  if (ref.startsWith('refs/heads/')) {
    return ref.split('/').pop() || ref;
  }
  if (ref) {
    return ref.slice(0, 12);
  }
  return deploymentId.slice(0, 8);
}

async function ensureCloudSwarmRepo() {
  ensureDir(path.dirname(CLOUD_SWARM_DIR));
  const repoExists = fs.existsSync(path.join(CLOUD_SWARM_DIR, '.git'));
  const gitEnv = {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${CLOUD_SWARM_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
  };

  if (!repoExists) {
    await runCommand('git', ['clone', CLOUD_SWARM_REPO, CLOUD_SWARM_DIR], { env: gitEnv });
    return;
  }

  await runCommand('git', ['-C', CLOUD_SWARM_DIR, 'fetch', '--prune'], { env: gitEnv });
  await runCommand('git', ['-C', CLOUD_SWARM_DIR, 'checkout', 'main'], { env: gitEnv });
  await runCommand('git', ['-C', CLOUD_SWARM_DIR, 'pull', '--ff-only'], { env: gitEnv });
}

async function downloadArtifact(creds: R2Credentials, objectKey: string, targetPath: string) {
  const url = presignS3Url({
    method: 'GET',
    endpoint: creds.endpoint,
    bucket: creds.bucket,
    key: objectKey,
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    region: creds.region || 'auto',
    expiresIn: 3600,
  });
  await runCommand('curl', ['-fsSL', url, '-o', targetPath]);
}

async function extractArtifact(archivePath: string, targetDir: string) {
  ensureDir(targetDir);
  await runCommand('tar', ['-I', 'zstd -d', '-xf', archivePath, '-C', targetDir]);
}

async function stripDefiners(inputPath: string, outputPath: string) {
  await new Promise<void>((resolve, reject) => {
    const input = fs.createReadStream(inputPath, 'utf8');
    const output = fs.createWriteStream(outputPath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input, crlfDelay: Infinity });

    rl.on('line', (line) => {
      const cleaned = line
        .replace(/DEFINER=`[^`]+`@`[^`]+`/g, '')
        .replace(/DEFINER=[^ ]+ /g, '');
      output.write(`${cleaned}\n`);
    });
    rl.on('close', () => {
      output.end();
      resolve();
    });
    rl.on('error', reject);
  });
}

async function waitForContainer(stackName: string, serviceName: string, timeoutMs: number) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const { stdout } = await runCommandCapture('docker', [
      'ps',
      '--filter',
      `name=${stackName}_${serviceName}`,
      '--format',
      '{{.ID}}',
    ]);
    const id = stdout.trim().split('\n')[0] || '';
    if (id) {
      return id;
    }
    await delay(2000);
  }
  throw new Error(`Timed out waiting for ${serviceName} container`);
}

async function waitForDatabase(containerId: string, timeoutMs: number) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await runCommandCapture('docker', [
        'exec',
        containerId,
        'sh',
        '-c',
        'mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -e "SELECT 1" >/dev/null 2>&1',
      ]);
      return;
    } catch {
      await delay(3000);
    }
  }
  throw new Error('Database did not become ready in time');
}

async function restoreDatabase(
  containerId: string,
  encryptedPath: string,
  workDir: string,
  dbName: string
) {
  const decryptedPath = path.join(workDir, 'db.sql.zst');
  const sqlPath = path.join(workDir, 'db.sql');
  const sanitizedPath = path.join(workDir, 'db.sanitized.sql');

  await runCommand('age', ['-d', '-i', STACK_MASTER_KEY_PATH, '-o', decryptedPath, encryptedPath]);
  await runCommand('zstd', ['-d', '-f', '-o', sqlPath, decryptedPath]);
  await stripDefiners(sqlPath, sanitizedPath);

  await runCommand('docker', ['cp', sanitizedPath, `${containerId}:/tmp/mz-restore.sql`]);
  const safeDbName = dbName.replace(/`/g, '``');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    [
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -e "CREATE DATABASE IF NOT EXISTS \\\`${safeDbName}\\\`;"`,
      `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" --database="${safeDbName}" < /tmp/mz-restore.sql`,
    ].join(' && '),
  ]);
}

async function syncDatabaseUser(containerId: string, dbName: string, dbUser: string) {
  const safeDbName = dbName.replace(/`/g, '``');
  const safeDbUser = dbUser.replace(/'/g, "''");
  const grantStatement =
    'GRANT ALL PRIVILEGES ON ' +
    safeDbName +
    ".* TO '" +
    safeDbUser +
    "'@'%'; FLUSH PRIVILEGES;";
  const dbPassRef = '${DB_PASS}';
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    [
      'set -e',
      'DB_PASS="$(cat /run/secrets/db_password)"',
      'ROOT_PASS="$(cat /run/secrets/db_root_password)"',
      `mariadb -uroot -p"$ROOT_PASS" -e "CREATE USER IF NOT EXISTS '${safeDbUser}'@'%' IDENTIFIED BY '${dbPassRef}';"`,
      `mariadb -uroot -p"$ROOT_PASS" -e "ALTER USER '${safeDbUser}'@'%' IDENTIFIED BY '${dbPassRef}';"`,
      `mariadb -uroot -p"$ROOT_PASS" -e "${grantStatement}"`,
    ].join(' && '),
  ]);
}

async function setSearchEngine(containerId: string, dbName: string, engine: string) {
  const safeDbName = dbName.replace(/`/g, '``');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/engine', '${engine}') ON DUPLICATE KEY UPDATE value=VALUES(value);"`,
  ]);
}

async function setBaseUrls(containerId: string, dbName: string, baseUrl: string) {
  const safeDbName = dbName.replace(/`/g, '``');
  const normalized = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/unsecure/base_url', '${normalized}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/base_url', '${normalized}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/use_in_frontend', '1') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'web/secure/use_in_adminhtml', '1') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`,
  ]);
}

async function setOpensearchSystemConfig(
  containerId: string,
  dbName: string,
  host: string,
  port: string,
  timeout: string
) {
  const safeDbName = dbName.replace(/`/g, '``');
  const statements = [
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_hostname', '${host}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_port', '${port}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
    `INSERT INTO core_config_data (scope, scope_id, path, value) VALUES ('default', 0, 'catalog/search/opensearch_server_timeout', '${timeout}') ON DUPLICATE KEY UPDATE value=VALUES(value)`,
  ].join('; ');
  await runCommand('docker', [
    'exec',
    containerId,
    'sh',
    '-c',
    `mariadb -uroot -p"$(cat /run/secrets/db_root_password)" -D ${safeDbName} -e "${statements};"`,
  ]);
}

async function runMagentoCommand(containerId: string, command: string) {
  await runCommand('docker', ['exec', containerId, 'sh', '-c', command]);
}

async function reportDeploymentStatus(
  baseUrl: string,
  nodeId: string,
  nodeSecret: string,
  payload: { deployment_id: string; environment_id: number; status: string; message?: string }
) {
  const body = JSON.stringify(payload);
  const url = new URL('/v1/deploy/status', baseUrl);
  const headers = buildNodeHeaders('POST', url.pathname, url.search.slice(1), body, nodeId, nodeSecret);
  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...headers,
    },
    body,
  });
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`mz-control status update failed: ${response.status} - ${errorBody}`);
  }
}

async function processDeployment(recordPath: string) {
  const raw = fs.readFileSync(recordPath, 'utf8');
  const record = JSON.parse(raw) as DeploymentRecord;
  const deploymentId = record.id || path.basename(recordPath, '.json');
  const payload = record.payload || {};
  const artifactKey = String(payload.artifact || '').trim();
  const stackId = Number(payload.stack_id ?? 0);
  const environmentId = Number(payload.environment_id ?? 0);
  const ref = String(payload.ref || '').trim();
  const logPrefix = `[deploy ${deploymentId}]`;
  const log = (message: string) => {
    console.log(`${logPrefix} ${message}`);
  };

  if (!artifactKey || !stackId || !environmentId) {
    throw new Error('Deployment payload missing artifact/stack/environment');
  }
  log(`start stack=${stackId} env=${environmentId} artifact=${artifactKey}`);

  const config = readConfig();
  const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
  const nodeId = readNodeFile('node-id');
  const nodeSecret = readNodeFile('node-secret');
  if (!baseUrl || !nodeId || !nodeSecret) {
    throw new Error('Missing mz-control base URL or node credentials');
  }

  await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
    deployment_id: deploymentId,
    environment_id: environmentId,
    status: 'deploying',
  });
  log('reported deploying status');

  await ensureCloudSwarmRepo();
  log('cloud-swarm repo updated');

  const envRecord = await fetchEnvironmentRecord(stackId, environmentId, baseUrl, nodeId, nodeSecret);
  if (!envRecord) {
    throw new Error(`Environment ${environmentId} not found in stack ${stackId}`);
  }
  log('fetched environment record');
  const selections = envRecord?.application_selections;
  const versions = resolveVersionEnv(selections);
  const searchEngine = process.env.MZ_SEARCH_ENGINE || 'opensearch';
  const opensearchHost = process.env.MZ_OPENSEARCH_HOST || 'opensearch';
  const opensearchPort = process.env.MZ_OPENSEARCH_PORT || '9200';
  const opensearchTimeout = process.env.MZ_OPENSEARCH_TIMEOUT || '15';

  const r2 = readR2CredFile(environmentId);
  if (!r2?.backups) {
    throw new Error('Missing R2 backup credentials');
  }

  const objectKey = String(envRecord?.db_backup_object || DEFAULT_DB_BACKUP_OBJECT).replace(/^\/+/, '');
  const workDir = path.join(DEPLOY_WORK_DIR, deploymentId);
  ensureDir(workDir);

  const artifactPath = path.join(workDir, path.basename(artifactKey));
  log('downloading build artifact');
  await downloadArtifact(r2.backups, artifactKey, artifactPath);
  log('downloaded build artifact');

  const logDir = path.join(workDir, 'logs');
  ensureDir(logDir);

  const imageTag = resolveImageTag(artifactKey, ref, deploymentId);
  const mageVersion = `env-${environmentId}-${imageTag}`;
  const defaultVersions = readVersionDefaults();
  const overrideVersions: Record<string, string> = {};
  if (versions.phpVersion) overrideVersions.PHP_VERSION = versions.phpVersion;
  if (versions.varnishVersion) overrideVersions.VARNISH_VERSION = versions.varnishVersion;
  if (versions.mariadbVersion) overrideVersions.MARIADB_VERSION = versions.mariadbVersion;
  if (versions.opensearchVersion) overrideVersions.OPENSEARCH_VERSION = versions.opensearchVersion;
  if (versions.redisVersion) overrideVersions.REDIS_VERSION = versions.redisVersion;
  if (versions.rabbitmqVersion) overrideVersions.RABBITMQ_VERSION = versions.rabbitmqVersion;

  const envVars: NodeJS.ProcessEnv = {
    ...process.env,
    ...defaultVersions,
    ...overrideVersions,
    REGISTRY_HOST: 'registry',
    REGISTRY_PUSH_HOST: '127.0.0.1',
    REGISTRY_PORT: '5000',
    SECRET_VERSION,
    MAGE_VERSION: mageVersion,
    MYSQL_DATABASE: process.env.MYSQL_DATABASE || 'magento',
    MYSQL_USER: process.env.MYSQL_USER || 'magento',
    MZ_SEARCH_ENGINE: searchEngine,
    MZ_OPENSEARCH_HOST: opensearchHost,
    MZ_OPENSEARCH_PORT: opensearchPort,
    MZ_OPENSEARCH_TIMEOUT: opensearchTimeout,
  };

  const secrets = envRecord?.environment_secrets ?? null;
  const envHostname = String(envRecord?.environment_hostname || envRecord?.hostname || '').trim();
  const envBaseUrl = envHostname ? `https://${envHostname.replace(/^https?:\/\//, '').replace(/\/+$/, '')}` : '';
  const dbSecretName = `mz_db_password_v${SECRET_VERSION}`;
  const dbRootSecretName = `mz_db_root_password_v${SECRET_VERSION}`;
  const rabbitSecretName = `mz_rabbitmq_password_v${SECRET_VERSION}`;
  const mageSecretName = `mz_mage_crypto_key_v${SECRET_VERSION}`;

  log('ensuring docker secrets');
  await ensureDockerSecret(dbSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(dbRootSecretName, generateSecretHex(24), workDir);
  await ensureDockerSecret(rabbitSecretName, generateSecretHex(24), workDir);

  if (!secrets?.crypt_key) {
    throw new Error('Missing Magento crypt key for environment');
  }
  await ensureDockerSecret(mageSecretName, secrets.crypt_key, workDir);
  log('docker secrets ready');

  await runCommandLogged(
    'bash',
    [path.join(CLOUD_SWARM_DIR, 'scripts/build-services.sh')],
    { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-services' }
  );
  log('built base services');
  await runCommandLogged(
    'bash',
    [path.join(CLOUD_SWARM_DIR, 'scripts/build-magento.sh'), artifactPath],
    { cwd: CLOUD_SWARM_DIR, env: envVars, logDir, label: 'build-magento' }
  );
  log('built magento images');

  const stackName = `mz-env-${environmentId}`;
  await runCommandLogged('docker', [
    'stack',
    'deploy',
    '--with-registry-auth',
    '-c',
    path.join(CLOUD_SWARM_DIR, 'stacks/magento.yml'),
    stackName,
  ], { env: envVars, logDir, label: 'stack-deploy' });
  log('stack deployed');

  const dbContainerId = await waitForContainer(stackName, 'database', 5 * 60 * 1000);
  await waitForDatabase(dbContainerId, 5 * 60 * 1000);

  const encryptedBackupPath = path.join(workDir, path.basename(objectKey));
  await downloadArtifact(r2.backups, objectKey, encryptedBackupPath);
  await restoreDatabase(
    dbContainerId,
    encryptedBackupPath,
    workDir,
    envVars.MYSQL_DATABASE || 'magento'
  );
  log('database restored');
  await syncDatabaseUser(
    dbContainerId,
    envVars.MYSQL_DATABASE || 'magento',
    envVars.MYSQL_USER || 'magento'
  );
  log('database user synced');
  if (envBaseUrl) {
    await setBaseUrls(dbContainerId, envVars.MYSQL_DATABASE || 'magento', envBaseUrl);
    log(`base URLs set to ${envBaseUrl}`);
  }

  const adminContainerId = await waitForContainer(stackName, 'php-fpm-admin', 5 * 60 * 1000);
  const webContainerId = await waitForContainer(stackName, 'php-fpm', 5 * 60 * 1000);
  await runCommand('docker', [
    'exec',
    '--user',
    'root',
    adminContainerId,
    'sh',
    '-c',
    'mkdir -p /var/www/html/magento/var/log /var/www/html/magento/var/report /var/www/html/magento/var/session /var/www/html/magento/var/cache /var/www/html/magento/var/page_cache /var/www/html/magento/var/tmp /var/www/html/magento/var/export /var/www/html/magento/var/import /var/www/html/magento/pub/media && chmod -R 0777 /var/www/html/magento/var/log /var/www/html/magento/var/report /var/www/html/magento/var/session /var/www/html/magento/var/cache /var/www/html/magento/var/page_cache /var/www/html/magento/var/tmp /var/www/html/magento/var/export /var/www/html/magento/var/import /var/www/html/magento/pub/media',
  ]);
  await runCommand('docker', [
    'exec',
    '--user',
    'root',
    webContainerId,
    'sh',
    '-c',
    'mkdir -p /var/www/html/magento/var/log /var/www/html/magento/var/report /var/www/html/magento/var/session /var/www/html/magento/var/cache /var/www/html/magento/var/page_cache /var/www/html/magento/var/tmp /var/www/html/magento/var/export /var/www/html/magento/var/import /var/www/html/magento/pub/media && chmod -R 0777 /var/www/html/magento/var/log /var/www/html/magento/var/report /var/www/html/magento/var/session /var/www/html/magento/var/cache /var/www/html/magento/var/page_cache /var/www/html/magento/var/tmp /var/www/html/magento/var/export /var/www/html/magento/var/import /var/www/html/magento/pub/media',
  ]);
  let upgradeWarning = false;
  await setOpensearchSystemConfig(
    dbContainerId,
    envVars.MYSQL_DATABASE || 'magento',
    opensearchHost,
    opensearchPort,
    opensearchTimeout
  );
  await setSearchEngine(dbContainerId, envVars.MYSQL_DATABASE || 'magento', 'mysql');
  try {
    await runCommandCapture('docker', [
      'exec',
      adminContainerId,
      'sh',
      '-c',
      'php bin/magento setup:upgrade --keep-generated',
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes('OpenSearch') || !message.includes('default website')) {
      throw error;
    }
    upgradeWarning = true;
    console.warn(`${logPrefix} setup:upgrade warning: ${message}`);
  } finally {
    await setSearchEngine(dbContainerId, envVars.MYSQL_DATABASE || 'magento', searchEngine);
  }
  if (!upgradeWarning) {
    await runMagentoCommand(adminContainerId, 'php bin/magento cache:flush');
  }
  log('magento upgrade complete');

  await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
    deployment_id: deploymentId,
    environment_id: environmentId,
    status: 'active',
  });
}

async function handleDeploymentFile(recordPath: string) {
  const failedDir = path.join(DEPLOY_QUEUE_DIR, 'failed');
  ensureDir(failedDir);
  try {
    await processDeployment(recordPath);
    fs.unlinkSync(recordPath);
  } catch (error) {
    const failedRecord = {
      error: error instanceof Error ? error.message : String(error),
      failed_at: new Date().toISOString(),
    };
    const failedPath = path.join(failedDir, path.basename(recordPath));
    const payload = fs.existsSync(recordPath) ? fs.readFileSync(recordPath, 'utf8') : '{}';
    let existing: Record<string, unknown> = {};
    try {
      existing = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      existing = {};
    }
    const merged = { ...existing, ...failedRecord } as Record<string, any>;
    fs.writeFileSync(failedPath, JSON.stringify(merged, null, 2));
    try {
      fs.unlinkSync(recordPath);
    } catch {
      // ignore
    }

    const config = readConfig();
    const baseUrl = (config.mz_control_base_url || process.env.MZ_CONTROL_BASE_URL || '').trim();
    const nodeId = readNodeFile('node-id');
    const nodeSecret = readNodeFile('node-secret');
    const environmentId = Number(merged?.payload?.environment_id ?? 0);
    if (baseUrl && nodeId && nodeSecret && environmentId) {
      try {
        await reportDeploymentStatus(baseUrl, nodeId, nodeSecret, {
          deployment_id: merged?.id || path.basename(recordPath, '.json'),
          environment_id: environmentId,
          status: 'failed',
          message: failedRecord.error,
        });
      } catch {
        // ignore secondary failures
      }
    }

    console.error('deploy.worker.failed', failedRecord);
  }
}

async function tick() {
  if (processing) {
    return;
  }
  if (!(await isSwarmManager())) {
    return;
  }
  const next = claimNextDeployment();
  if (!next) {
    return;
  }
  processing = true;
  try {
    await handleDeploymentFile(next);
  } finally {
    processing = false;
  }
}

export function startDeploymentWorker() {
  if (process.env.MZ_DEPLOY_WORKER_ENABLED === '0') {
    return;
  }
  ensureDir(DEPLOY_QUEUE_DIR);
  ensureDir(DEPLOY_WORK_DIR);
  void tick();
  setInterval(() => {
    void tick();
  }, Number.isFinite(DEPLOY_INTERVAL_MS) && DEPLOY_INTERVAL_MS > 1000 ? DEPLOY_INTERVAL_MS : 5000);
}
