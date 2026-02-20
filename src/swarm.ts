import crypto from 'crypto';
import { runCommand } from './exec.js';

export function envStackPrefix(environmentId: number): string {
  return `mz-env-${environmentId}_`;
}

export function envServiceName(environmentId: number, serviceName: string): string {
  return `${envStackPrefix(environmentId)}${serviceName}`;
}

export type SwarmServiceSecret = {
  file_name: string;
  secret_name: string;
};

export type SwarmServiceNetwork = {
  name: string;
  aliases: string[];
};

export type SwarmServiceMount = {
  type: string;
  source: string;
  target: string;
  read_only: boolean;
};

export type SwarmServiceSpecSummary = {
  service_name: string;
  image: string;
  networks: SwarmServiceNetwork[];
  secrets: SwarmServiceSecret[];
  mounts: SwarmServiceMount[];
  env: Record<string, string>;
};

export type SwarmJobOptions = {
  name: string;
  image: string;
  command: string[];
  networks?: string[];
  secrets?: Array<{ source: string; target: string }>;
  mounts?: Array<{ type: string; source: string; target: string; read_only?: boolean }>;
  env?: Record<string, string>;
  constraints?: string[];
  timeout_ms?: number;
};

export type SwarmJobResult = {
  ok: boolean;
  state: string;
  logs: string;
  error?: string;
  details?: string[];
};

export type SwarmServiceListEntry = {
  id: string;
  name: string;
  replicas: string;
};

export type SwarmServiceTask = {
  id: string;
  name: string;
  node: string;
  desired_state: string;
  current_state: string;
  error: string;
};

export type SwarmServiceUpdateStatus = {
  state: string;
  started_at: string;
  completed_at: string;
  message: string;
};

type RunbookServiceEntry = {
  name: string;
  replicas: string;
};

export function stripDigestFromImageRef(image: string): string {
  const raw = String(image || '').trim();
  if (!raw) return raw;

  const at = raw.indexOf('@');
  if (at <= 0) return raw;

  const nameWithTag = raw.slice(0, at);
  const digest = raw.slice(at + 1).trim();
  if (!/^sha256:[a-f0-9]{64}$/i.test(digest)) {
    return raw;
  }

  const slash = nameWithTag.lastIndexOf('/');
  const colon = nameWithTag.lastIndexOf(':');
  const hasExplicitTag = colon > slash;

  // Keep digest-only refs (repo@sha256:...) unchanged to avoid implicitly using :latest.
  if (!hasExplicitTag) {
    return raw;
  }

  return nameWithTag;
}

function parseDockerJsonLines(raw: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        out.push(parsed);
      }
    } catch {
      continue;
    }
  }
  return out;
}

function parseTaskStateWord(currentState: string): string {
  return currentState.trim().split(/\s+/)[0] || '';
}

function isTerminalTaskState(currentState: string): boolean {
  const state = parseTaskStateWord(currentState);
  return state === 'Complete'
    || state === 'Failed'
    || state === 'Rejected'
    || state === 'Shutdown'
    || state === 'Remove'
    || state === 'Orphaned';
}

function replicasSuggestsTerminal(replicas: string): boolean {
  const lower = replicas.trim().toLowerCase();
  if (!lower) return false;
  return lower.includes('completed')
    || lower.includes('failed')
    || lower.includes('rejected')
    || lower.includes('shutdown');
}

async function listRunbookJobServices(): Promise<RunbookServiceEntry[]> {
  const result = await runCommand('docker', ['service', 'ls', '--format', '{{json .}}'], 12_000);
  if (result.code !== 0) return [];
  return parseDockerJsonLines(result.stdout)
    .map((row) => ({
      name: String(row.Name || '').trim(),
      replicas: String(row.Replicas || '').trim(),
    }))
    .filter((row) => row.name.startsWith('mz-rb-'));
}

async function isRunbookServiceTerminal(serviceName: string): Promise<boolean> {
  const tasks = await listServiceTasks(serviceName);
  if (!tasks.length) return true;
  return tasks.every((task) => isTerminalTaskState(task.current_state));
}

export async function listEnvironmentServices(environmentId: number): Promise<SwarmServiceListEntry[]> {
  const prefix = envStackPrefix(environmentId);
  const result = await runCommand('docker', ['service', 'ls', '--format', '{{json .}}'], 12_000);
  if (result.code !== 0) return [];
  return parseDockerJsonLines(result.stdout)
    .map((row) => {
      const id = String(row.ID || '').trim();
      const name = String(row.Name || '').trim();
      const replicas = String(row.Replicas || '').trim();
      return { id, name, replicas };
    })
    .filter((entry) => entry.id !== '' && entry.name.startsWith(prefix));
}

export async function findEnvironmentService(environmentId: number, includes: string): Promise<SwarmServiceListEntry | null> {
  const services = await listEnvironmentServices(environmentId);
  return services.find((entry) => entry.name.includes(includes)) || null;
}

export async function listServiceTasks(serviceName: string): Promise<SwarmServiceTask[]> {
  const result = await runCommand('docker', ['service', 'ps', serviceName, '--no-trunc', '--format', '{{json .}}'], 12_000);
  if (result.code !== 0) return [];
  return parseDockerJsonLines(result.stdout)
    .map((row) => {
      const id = String(row.ID || '').trim();
      const name = String(row.Name || '').trim();
      const node = String(row.Node || '').trim();
      const desiredState = String(row.DesiredState || '').trim();
      const currentState = String(row.CurrentState || '').trim();
      const error = String(row.Error || '').trim();
      return {
        id,
        name,
        node,
        desired_state: desiredState,
        current_state: currentState,
        error,
      };
    })
    .filter((task) => task.id !== '' && task.name !== '');
}

export function summarizeServiceTasks(tasks: SwarmServiceTask[]): { ok: boolean; desired_running: number; running: number; total: number; issues: string[]; nodes: string[] } {
  const desiredRunning = tasks.filter((task) => task.desired_state.toLowerCase() === 'running');
  const running = desiredRunning.filter((task) => task.current_state.startsWith('Running'));

  const issues: string[] = [];
  const nonRunningDesired = desiredRunning.filter((task) => !task.current_state.startsWith('Running'));
  for (const task of nonRunningDesired.slice(0, 5)) {
    const suffix = task.error ? ` (${task.error})` : '';
    issues.push(`${task.name} on ${task.node || '(unknown node)'}: ${task.current_state}${suffix}`.trim());
  }

  if (desiredRunning.length === 0) {
    issues.push('No tasks desired to be Running.');
  }

  const nodes = Array.from(new Set(tasks.map((t) => t.node).filter(Boolean))).sort();
  const ok = desiredRunning.length > 0 && nonRunningDesired.length === 0;
  return {
    ok,
    desired_running: desiredRunning.length,
    running: running.length,
    total: tasks.length,
    issues,
    nodes,
  };
}

export async function getServiceTaskNode(environmentId: number, serviceName: string): Promise<string | null> {
  const service = envServiceName(environmentId, serviceName);
  const tasks = await listServiceTasks(service);
  const running = tasks.find((t) => t.current_state.startsWith('Running') && t.node) || tasks.find((t) => t.node);
  return running?.node || null;
}

const networkNameCache = new Map<string, string>();

async function getNetworkName(networkId: string): Promise<string | null> {
  const cached = networkNameCache.get(networkId);
  if (cached) return cached;
  const result = await runCommand('docker', ['network', 'inspect', networkId, '--format', '{{.Name}}'], 12_000);
  if (result.code !== 0) return null;
  const name = result.stdout.trim();
  if (!name) return null;
  networkNameCache.set(networkId, name);
  return name;
}

export async function inspectServiceSpec(serviceName: string): Promise<SwarmServiceSpecSummary | null> {
  const result = await runCommand('docker', ['service', 'inspect', serviceName, '--format', '{{json .}}'], 12_000);
  if (result.code !== 0) return null;
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = JSON.parse(result.stdout.trim()) as Record<string, unknown>;
  } catch {
    parsed = null;
  }
  if (!parsed || typeof parsed !== 'object') return null;

  const spec = (parsed as any).Spec as Record<string, unknown> | undefined;
  const task = (spec as any)?.TaskTemplate as Record<string, unknown> | undefined;
  const containerSpec = (task as any)?.ContainerSpec as Record<string, unknown> | undefined;
  const image = String((containerSpec as any)?.Image || '').trim();
  if (!image) return null;

  const networksRaw = Array.isArray((task as any)?.Networks) ? (task as any).Networks as Array<Record<string, unknown>> : [];
  const networks: SwarmServiceNetwork[] = [];
  for (const entry of networksRaw) {
    const targetId = String((entry as any)?.Target || '').trim();
    const aliases = Array.isArray((entry as any)?.Aliases) ? (entry as any).Aliases.map((a: unknown) => String(a || '').trim()).filter(Boolean) : [];
    if (!targetId) continue;
    const networkName = await getNetworkName(targetId);
    if (!networkName) continue;
    networks.push({ name: networkName, aliases });
  }

  const secretsRaw = Array.isArray((containerSpec as any)?.Secrets) ? (containerSpec as any).Secrets as Array<Record<string, unknown>> : [];
  const secrets: SwarmServiceSecret[] = [];
  for (const entry of secretsRaw) {
    const file = (entry as any)?.File as Record<string, unknown> | undefined;
    const fileName = String((file as any)?.Name || '').trim();
    const secretName = String((entry as any)?.SecretName || '').trim();
    if (!fileName || !secretName) continue;
    secrets.push({ file_name: fileName, secret_name: secretName });
  }

  const mountsRaw = Array.isArray((containerSpec as any)?.Mounts) ? (containerSpec as any).Mounts as Array<Record<string, unknown>> : [];
  const mounts: SwarmServiceMount[] = [];
  for (const entry of mountsRaw) {
    const type = String((entry as any)?.Type || '').trim();
    const source = String((entry as any)?.Source || '').trim();
    const target = String((entry as any)?.Target || '').trim();
    const readOnly = Boolean((entry as any)?.ReadOnly);
    if (!type || !source || !target) continue;
    mounts.push({ type, source, target, read_only: readOnly });
  }

  const envRaw = Array.isArray((containerSpec as any)?.Env) ? (containerSpec as any).Env as unknown[] : [];
  const env: Record<string, string> = {};
  for (const entry of envRaw) {
    const line = String(entry || '');
    const idx = line.indexOf('=');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1);
    if (!key) continue;
    env[key] = value;
  }

  return {
    service_name: serviceName,
    image,
    networks,
    secrets,
    mounts,
    env,
  };
}

export async function inspectServiceUpdateStatus(serviceName: string): Promise<SwarmServiceUpdateStatus | null> {
  const result = await runCommand('docker', ['service', 'inspect', serviceName, '--format', '{{json .UpdateStatus}}'], 12_000);
  if (result.code !== 0) return null;
  const raw = result.stdout.trim();
  if (!raw || raw === '<no value>' || raw === 'null') {
    return null;
  }
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    parsed = null;
  }
  if (!parsed || typeof parsed !== 'object') {
    return null;
  }
  const state = String((parsed as any).State || '').trim();
  const startedAt = String((parsed as any).StartedAt || '').trim();
  const completedAt = String((parsed as any).CompletedAt || '').trim();
  const message = String((parsed as any).Message || '').trim();
  if (!state && !message) {
    return null;
  }
  return {
    state,
    started_at: startedAt,
    completed_at: completedAt,
    message,
  };
}

export function pickSecretName(spec: SwarmServiceSpecSummary, fileName: string): string | null {
  const match = spec.secrets.find((entry) => entry.file_name === fileName);
  return match?.secret_name || null;
}

export function pickNetworkName(spec: SwarmServiceSpecSummary, requiredAlias?: string): string | null {
  if (requiredAlias) {
    const match = spec.networks.find((net) => net.aliases.includes(requiredAlias));
    if (match?.name) return match.name;
  }
  return spec.networks[0]?.name || null;
}

export function buildJobName(prefix: string, environmentId: number): string {
  const suffix = crypto.randomBytes(3).toString('hex');
  const raw = `mz-rb-${prefix}-${environmentId}-${suffix}`.toLowerCase();
  return raw.replace(/[^a-z0-9-]/g, '-').slice(0, 63);
}

export async function waitForServiceRunning(serviceFullName: string, timeoutMs = 180_000): Promise<{ ok: boolean; state?: string; note?: string }> {
  const startedAt = Date.now();
  let lastState = '';
  while (Date.now() - startedAt < timeoutMs) {
    const tasks = await listServiceTasks(serviceFullName);
    if (tasks.length) {
      const running = tasks.find((t) => t.current_state.startsWith('Running'))?.current_state || '';
      const state = running || tasks[0]?.current_state || '';
      lastState = state || lastState;
      if (state.startsWith('Running')) {
        return { ok: true, state };
      }
      if (state.startsWith('Failed') || state.startsWith('Rejected')) {
        const errorText = tasks[0]?.error || '';
        return { ok: false, state, note: errorText || 'service task failed' };
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { ok: false, state: lastState || undefined, note: `timeout after ${timeoutMs}ms` };
}

export async function waitForServiceNotRunning(serviceFullName: string, timeoutMs = 120_000): Promise<{ ok: boolean; note?: string }> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const tasks = await listServiceTasks(serviceFullName);
    const hasRunning = tasks.some((task) => task.current_state.startsWith('Running'));
    if (!hasRunning) return { ok: true };
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { ok: false, note: `timeout after ${timeoutMs}ms` };
}

export async function runSwarmJob(options: SwarmJobOptions): Promise<SwarmJobResult> {
  const timeoutMs = options.timeout_ms ?? 5 * 60_000;
  const jobImage = stripDigestFromImageRef(options.image) || options.image;
  const args: string[] = [
    'service',
    'create',
    '--quiet',
    '--name',
    options.name,
    '--restart-condition',
    'none',
    '--mode',
    'replicated-job',
    '--replicas',
    '1',
    '--no-resolve-image',
  ];

  for (const network of options.networks || []) {
    args.push('--network', network);
  }

  for (const secret of options.secrets || []) {
    args.push('--secret', `source=${secret.source},target=${secret.target}`);
  }

  for (const mount of options.mounts || []) {
    const readOnly = mount.read_only ? ',readonly' : '';
    args.push('--mount', `type=${mount.type},src=${mount.source},dst=${mount.target}${readOnly}`);
  }

  for (const [key, value] of Object.entries(options.env || {})) {
    args.push('--env', `${key}=${value}`);
  }

  for (const constraint of options.constraints || []) {
    args.push('--constraint', constraint);
  }

  args.push(jobImage, ...options.command);

  const created = await runCommand('docker', args, 30_000);
  if (created.code !== 0) {
    return {
      ok: false,
      state: 'create_failed',
      logs: '',
      error: created.stderr.trim() || created.stdout.trim() || 'failed to create swarm job',
    };
  }

  let finalState = 'unknown';
  let logs = '';
  const details: string[] = [];

  try {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
      const ps = await runCommand('docker', ['service', 'ps', options.name, '--no-trunc', '--format', '{{.CurrentState}}|{{.Error}}'], 12_000);
      const lines = ps.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
      if (lines.length) {
        details.splice(0, details.length, ...lines.slice(0, 5));
        const [stateRaw] = (lines[0] || '').split('|');
        const stateWord = (stateRaw || '').trim().split(' ')[0] || '';
        if (stateWord) {
          finalState = stateWord;
        }
        if (stateWord === 'Complete' || stateWord === 'Failed' || stateWord === 'Rejected') {
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 500));
    }

    const logResult = await runCommand('docker', ['service', 'logs', options.name, '--raw', '--no-task-ids'], 30_000);
    logs = (logResult.stdout || logResult.stderr || '').trim();
  } finally {
    await runCommand('docker', ['service', 'rm', options.name], 12_000);
  }

  const ok = finalState === 'Complete';
  if (!ok && finalState === 'unknown') {
    return {
      ok: false,
      state: 'timeout',
      logs,
      error: `swarm job timed out after ${timeoutMs}ms`,
      details,
    };
  }

  return {
    ok,
    state: finalState,
    logs,
    error: ok ? undefined : `swarm job ended with state: ${finalState}`,
    details,
  };
}

export async function cleanupOrphanedRunbookJobs(): Promise<{ removed: string[]; failed: string[] }> {
  const services = await listRunbookJobServices();

  const removed: string[] = [];
  const failed: string[] = [];

  for (const service of services) {
    // Skip active runbook jobs and only reap terminal leftovers.
    const terminalByReplicas = replicasSuggestsTerminal(service.replicas);
    if (!terminalByReplicas) continue;

    const terminalByTasks = await isRunbookServiceTerminal(service.name);
    if (!terminalByTasks) continue;

    const rm = await runCommand('docker', ['service', 'rm', service.name], 12_000);
    if (rm.code === 0) {
      removed.push(service.name);
    } else {
      failed.push(service.name);
    }
  }

  return { removed, failed };
}

let runbookCleanupTimer: NodeJS.Timeout | null = null;
let runbookCleanupRunning = false;

async function runRunbookCleanup(reason: string): Promise<void> {
  if (runbookCleanupRunning) return;
  runbookCleanupRunning = true;
  try {
    const result = await cleanupOrphanedRunbookJobs();
    if (result.removed.length || result.failed.length) {
      const removed = result.removed.length;
      const failed = result.failed.length;
      console.log(`runbook.cleanup:${reason} removed=${removed} failed=${failed}`);
    }
  } finally {
    runbookCleanupRunning = false;
  }
}

export function startRunbookCleanupScheduler(): void {
  if (runbookCleanupTimer) return;
  const defaultIntervalMs = 5 * 60_000;
  const configured = Number(process.env.MZ_RUNBOOK_CLEANUP_INTERVAL_MS || defaultIntervalMs);
  const intervalMs = Number.isFinite(configured) && configured >= 30_000
    ? configured
    : defaultIntervalMs;

  void runRunbookCleanup('startup');
  runbookCleanupTimer = setInterval(() => {
    void runRunbookCleanup('interval');
  }, intervalMs);
  runbookCleanupTimer.unref?.();
}
