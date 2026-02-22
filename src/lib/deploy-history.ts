import fs from 'fs';
import path from 'path';
import { ensureDir } from './deploy-exec.js';

export type DeployHistoryEntry = {
  artifacts?: string[];
  imageTags?: string[];
  failedArtifacts?: string[];
  failedImageTags?: string[];
  updated_at?: string;
  last_success_at?: string;
  last_failure_at?: string;
};

export type DeployHistory = Record<string, DeployHistoryEntry>;

export function readDeploymentHistory(historyFile: string, legacyHistoryFile: string): DeployHistory {
  const candidates = [historyFile, legacyHistoryFile];
  for (const file of candidates) {
    if (!file) continue;
    try {
      if (!fs.existsSync(file)) continue;
      const raw = fs.readFileSync(file, 'utf8');
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        continue;
      }
      const history = parsed as DeployHistory;
      if (file === legacyHistoryFile && historyFile !== legacyHistoryFile) {
        try {
          ensureDir(path.dirname(historyFile));
          fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
          fs.unlinkSync(legacyHistoryFile);
        } catch {
          // ignore migration failures
        }
      }
      return history;
    } catch {
      continue;
    }
  }
  return {};
}

export function writeDeploymentHistory(history: DeployHistory, historyFile: string) {
  ensureDir(path.dirname(historyFile));
  fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
}

export function normalizeHistoryList(values: unknown): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  const output: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = String(value || '').replace(/^\/+/, '').trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    output.push(normalized);
  }
  return output;
}

export function getDeploymentHistoryEntry(
  history: DeployHistory,
  key: string
): Required<Pick<DeployHistoryEntry, 'artifacts' | 'imageTags' | 'failedArtifacts' | 'failedImageTags'>> & { last_success_at?: string } {
  const entry = history[key] || {};
  const lastSuccessAt = String((entry as DeployHistoryEntry).last_success_at || '').trim();
  return {
    artifacts: normalizeHistoryList((entry as DeployHistoryEntry).artifacts),
    imageTags: normalizeHistoryList((entry as DeployHistoryEntry).imageTags),
    failedArtifacts: normalizeHistoryList((entry as DeployHistoryEntry).failedArtifacts),
    failedImageTags: normalizeHistoryList((entry as DeployHistoryEntry).failedImageTags),
    last_success_at: lastSuccessAt || undefined,
  };
}

export function parseIsoTimestampMs(value: string | null | undefined): number | null {
  const normalized = String(value || '').trim();
  if (!normalized) return null;
  const parsed = Date.parse(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

export function getHistoryLastSuccessfulDeployAt(history: DeployHistory, key: string): string | null {
  const raw = String((history[key] as DeployHistoryEntry | undefined)?.last_success_at || '').trim();
  if (!raw) {
    return null;
  }
  return parseIsoTimestampMs(raw) === null ? null : raw;
}

export function resolveAggressivePruneCutoffSeconds(
  previousSuccessAt: string | null,
  nowMs = Date.now(),
  lookbackHours = 24
): number | null {
  const successMs = parseIsoTimestampMs(previousSuccessAt);
  if (successMs === null) {
    return null;
  }
  const hours = Math.max(1, Number(lookbackHours) || 24);
  const cutoffMs = successMs - (hours * 60 * 60 * 1000);
  if (!Number.isFinite(cutoffMs) || cutoffMs <= 0) {
    return null;
  }
  // Clock skew or bad timestamps: never ask docker to prune "future" objects.
  if (cutoffMs >= nowMs) {
    return null;
  }
  return Math.floor(cutoffMs / 1000);
}

export function updateDeploymentHistory(
  history: DeployHistory,
  key: string,
  artifactKey: string,
  imageTag: string,
  retainCount: number
) {
  const existing = getDeploymentHistoryEntry(history, key);
  const normalizedArtifactKey = String(artifactKey || '').replace(/^\/+/, '').trim();
  const normalizedImageTag = String(imageTag || '').trim();
  const artifacts = [normalizedArtifactKey, ...existing.artifacts.filter((item) => item !== normalizedArtifactKey)];
  const imageTags = [normalizedImageTag, ...existing.imageTags.filter((item) => item !== normalizedImageTag)];
  const keepArtifacts = artifacts.slice(0, retainCount);
  const keepImageTags = imageTags.slice(0, retainCount);
  const removedArtifacts = artifacts.slice(retainCount);
  const removedImageTags = imageTags.slice(retainCount);

  // A successful deploy supersedes failed retries: purge failed retention immediately.
  const removedFailedArtifacts = [...existing.failedArtifacts];
  const removedFailedImageTags = [...existing.failedImageTags];
  const nowIso = new Date().toISOString();
  history[key] = {
    artifacts: keepArtifacts,
    imageTags: keepImageTags,
    failedArtifacts: [],
    failedImageTags: [],
    updated_at: nowIso,
    last_success_at: nowIso,
  };
  return {
    keepArtifacts,
    keepImageTags,
    removedArtifacts,
    removedImageTags,
    removedFailedArtifacts,
    removedFailedImageTags,
  };
}

export function updateFailedDeploymentHistory(
  history: DeployHistory,
  key: string,
  artifactKey: string,
  imageTag: string,
  failedArtifactRetainCount: number,
  failedImageRetainCount: number
) {
  const existing = getDeploymentHistoryEntry(history, key);
  const normalizedArtifactKey = String(artifactKey || '').replace(/^\/+/, '').trim();
  const normalizedImageTag = String(imageTag || '').trim();

  const failedArtifacts = normalizedArtifactKey
    ? [normalizedArtifactKey, ...existing.failedArtifacts.filter((item) => item !== normalizedArtifactKey)]
    : [...existing.failedArtifacts];
  const failedImageTags = normalizedImageTag
    ? [normalizedImageTag, ...existing.failedImageTags.filter((item) => item !== normalizedImageTag)]
    : [...existing.failedImageTags];

  const keepFailedArtifacts = failedArtifacts.slice(0, failedArtifactRetainCount);
  const keepFailedImageTags = failedImageTags.slice(0, failedImageRetainCount);
  const removedFailedArtifacts = failedArtifacts.slice(failedArtifactRetainCount);
  const removedFailedImageTags = failedImageTags.slice(failedImageRetainCount);

  const nowIso = new Date().toISOString();
  history[key] = {
    artifacts: existing.artifacts,
    imageTags: existing.imageTags,
    failedArtifacts: keepFailedArtifacts,
    failedImageTags: keepFailedImageTags,
    updated_at: nowIso,
    last_success_at: existing.last_success_at,
    last_failure_at: nowIso,
  };

  return {
    keepArtifacts: existing.artifacts,
    keepImageTags: existing.imageTags,
    keepFailedArtifacts,
    keepFailedImageTags,
    removedFailedArtifacts,
    removedFailedImageTags,
  };
}
