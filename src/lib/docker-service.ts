import { runCommandCapture, runCommandCaptureWithStatus, delay } from './deploy-exec.js';

// ── Types ──────────────────────────────────────────────────────────────

export type ServiceUpdateStatus = {
  state: string;
  started_at: string;
  completed_at: string;
  message: string;
};

export type ServiceInspectSummary = {
  name: string;
  image: string;
  labels: Record<string, string>;
  replicas: number | null;
};

export type ServiceTaskRow = {
  id: string;
  name: string;
  node: string;
  desired_state: string;
  current_state: string;
  error: string;
  image: string;
};

// ── Helpers ────────────────────────────────────────────────────────────

export function parseDockerJsonLines(raw: string): Array<Record<string, unknown>> {
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

function parseReplicasFromServiceInspect(mode: any): number | null {
  const replicas = mode?.Replicated?.Replicas;
  if (typeof replicas === 'number' && Number.isFinite(replicas)) {
    return replicas;
  }
  if (typeof replicas === 'string' && replicas.trim() && Number.isFinite(Number(replicas))) {
    return Number(replicas);
  }
  return null;
}

// ── Container discovery ────────────────────────────────────────────────

export async function waitForContainer(stackName: string, serviceName: string, timeoutMs: number) {
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

export async function findLocalContainer(stackName: string, serviceName: string) {
  const { stdout } = await runCommandCapture('docker', [
    'ps',
    '--filter',
    `name=${stackName}_${serviceName}`,
    '--format',
    '{{.ID}}',
  ]);
  return stdout.trim().split('\n')[0] || '';
}

// ── Service inspection ─────────────────────────────────────────────────

export async function inspectServiceUpdateStatus(serviceName: string): Promise<ServiceUpdateStatus | null> {
  const result = await runCommandCaptureWithStatus('docker', ['service', 'inspect', serviceName, '--format', '{{json .UpdateStatus}}']);
  if (result.code !== 0) {
    return null;
  }
  const raw = (result.stdout || '').trim();
  if (!raw || raw === '<no value>' || raw === 'null') {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as any;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const state = String(parsed.State || '').trim();
    const startedAt = String(parsed.StartedAt || '').trim();
    const completedAt = String(parsed.CompletedAt || '').trim();
    const message = String(parsed.Message || '').trim();
    if (!state && !message) {
      return null;
    }
    return { state, started_at: startedAt, completed_at: completedAt, message };
  } catch {
    return null;
  }
}

export async function inspectServiceImage(serviceName: string): Promise<string | null> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'inspect',
    serviceName,
    '--format',
    '{{.Spec.TaskTemplate.ContainerSpec.Image}}',
  ]);
  if (result.code !== 0) {
    return null;
  }
  return (result.stdout || '').trim() || null;
}

export async function listStackServices(stackName: string): Promise<string[]> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'ls',
    '--filter',
    `label=com.docker.stack.namespace=${stackName}`,
    '--format',
    '{{.Name}}',
  ]);
  if (result.code !== 0) {
    return [];
  }
  return result.stdout.split('\n').map((line) => line.trim()).filter(Boolean);
}

export async function inspectServices(serviceNames: string[]): Promise<ServiceInspectSummary[]> {
  if (!serviceNames.length) return [];
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'inspect',
    ...serviceNames,
    '--format',
    '{{json .}}',
  ]);
  if (result.code !== 0) {
    return [];
  }
  return parseDockerJsonLines(result.stdout)
    .map((row) => {
      const spec = (row as any).Spec || {};
      const name = String(spec?.Name || '').trim();
      const image = String(spec?.TaskTemplate?.ContainerSpec?.Image || '').trim();
      const labelsRaw = spec?.Labels && typeof spec.Labels === 'object' ? spec.Labels : {};
      const labels: Record<string, string> = {};
      for (const [key, value] of Object.entries(labelsRaw as Record<string, unknown>)) {
        labels[String(key)] = String(value ?? '');
      }
      const replicas = parseReplicasFromServiceInspect(spec?.Mode);
      return { name, image, labels, replicas };
    })
    .filter((entry) => entry.name !== '');
}

// ── Service updates ────────────────────────────────────────────────────

export async function resumePausedServiceUpdate(serviceName: string, log: (message: string) => void): Promise<boolean> {
  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const state = (updateStatus?.state || '').toLowerCase();
  if (!state.includes('pause')) {
    return true;
  }
  log(`service update paused: ${serviceName} (${updateStatus?.state || 'paused'})${updateStatus?.message ? ` ${updateStatus.message}` : ''}`);
  const resume = await runCommandCaptureWithStatus('docker', [
    'service',
    'update',
    '--update-failure-action',
    'continue',
    serviceName,
  ]);
  const output = (resume.stderr || resume.stdout || '').trim();
  log(`service update resume: ${serviceName} exit=${resume.code}${output ? ` ${output}` : ''}`);
  return resume.code === 0;
}

export async function tryForceUpdateService(serviceName: string, log: (message: string) => void): Promise<boolean> {
  let result = await runCommandCaptureWithStatus('docker', ['service', 'update', '--force', serviceName]);
  if (result.code !== 0) {
    const output = `${result.stderr || ''}\n${result.stdout || ''}`.toLowerCase();
    if (output.includes('update paused') || output.includes('paused')) {
      await resumePausedServiceUpdate(serviceName, log);
      result = await runCommandCaptureWithStatus('docker', ['service', 'update', '--force', serviceName]);
    }
  }

  if (result.code === 0) {
    log(`forced update: ${serviceName}`);
    return true;
  }
  const output = (result.stderr || result.stdout || '').trim();
  const updateStatus = await inspectServiceUpdateStatus(serviceName);
  const updateText = updateStatus
    ? ` update=${updateStatus.state}${updateStatus.message ? ` (${updateStatus.message})` : ''}`
    : '';
  log(`forced update failed: ${serviceName} (exit ${result.code})${updateText} ${output}`);
  return false;
}

export async function captureServicePs(serviceName: string): Promise<string[]> {
  const result = await runCommandCaptureWithStatus('docker', [
    'service',
    'ps',
    serviceName,
    '--no-trunc',
    '--format',
    '{{.Node}}|{{.CurrentState}}|{{.Error}}',
  ]);
  const out = (result.stdout || result.stderr || '').trim();
  if (result.code !== 0) {
    return [out ? `error: ${out}` : `error: exit ${result.code}`];
  }
  return out.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 10);
}
