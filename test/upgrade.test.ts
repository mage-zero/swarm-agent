import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { __testing } from '../src/upgrade.js';

function writeChangelog(filePath: string, changelog: unknown) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(changelog, null, 2));
}

describe('upgrade changelog readers', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0, tempDirs.length)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reads and sorts release-path changelogs by semver', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-upgrade-'));
    tempDirs.push(root);

    writeChangelog(path.join(root, '0.4.7', 'changelog.json'), {
      version: '0.4.7',
      date: '2026-02-17',
      summary: 'v047',
      requires: {},
      changes: [{ id: 'a', description: 'a', phase: 'post_migrate', downtimeMinutes: 0, scope: 'stack' }],
    });
    writeChangelog(path.join(root, '0.4.6', 'changelog.json'), {
      version: '0.4.6',
      date: '2026-02-17',
      summary: 'v046',
      requires: {},
      changes: [],
    });
    writeChangelog(path.join(root, 'not-a-version', 'changelog.json'), {
      version: 'not-a-version',
      date: 'x',
      summary: 'x',
      requires: {},
      changes: [],
    });

    const versions = __testing.readReleaseDirectoryChangelog(root);
    expect(versions.map((entry) => entry.version)).toEqual(['0.4.6', '0.4.7']);
  });

  it('keeps only changelog entries matching the release directory version', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-upgrade-'));
    tempDirs.push(root);

    writeChangelog(path.join(root, '1.2.3', 'changelog.json'), {
      version: '1.2.2',
      date: '2026-02-17',
      summary: 'wrong',
      requires: {},
      changes: [],
    });

    const versions = __testing.readReleaseDirectoryChangelog(root);
    expect(versions).toHaveLength(0);
  });

  it('returns null when changelog file is malformed', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-upgrade-'));
    tempDirs.push(root);
    const filePath = path.join(root, 'bad.json');
    fs.writeFileSync(filePath, '{not-json');

    expect(__testing.readSingleChangelogFromFile(filePath)).toBeNull();
  });

  it('reads a single changelog object from file', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mz-upgrade-'));
    tempDirs.push(root);
    const filePath = path.join(root, 'changelog.json');
    writeChangelog(filePath, {
      version: '2.0.0',
      date: '2026-02-18',
      summary: 'single',
      requires: {},
      changes: [],
    });

    const entry = __testing.readSingleChangelogFromFile(filePath);
    expect(entry?.version).toBe('2.0.0');
    expect(entry?.summary).toBe('single');
  });

  it('compares semver in expected order', () => {
    expect(__testing.compareSemver('0.4.7', '0.4.7')).toBe(0);
    expect(__testing.compareSemver('0.4.8', '0.4.7')).toBeGreaterThan(0);
    expect(__testing.compareSemver('0.4.6', '0.4.7')).toBeLessThan(0);
  });
});
