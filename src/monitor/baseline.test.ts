import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ComplianceReport } from '../schema/index.js';
import { BaselineStore, hashRepoUrl, sanitizeBranchForFilename } from './baseline.js';

describe('BaselineStore', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-baseline-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('stores and loads compliance reports per repo and branch', async () => {
    const store = new BaselineStore({ rootDir: tempDir });
    const report = makeReport(88);

    const saved = await store.save('https://github.com/example/repo.git', 'feature/test', report, 'abc123');
    const loaded = await store.load('https://github.com/example/repo.git', 'feature/test');

    expect(saved.repoHash).toBe(hashRepoUrl('https://github.com/example/repo.git'));
    expect(loaded?.commitSha).toBe('abc123');
    expect(loaded?.report.overallScore).toBe(88);
    expect(loaded?.summary.findingCount).toBe(0);
    expect(await fileExists(store.getPath('https://github.com/example/repo.git', 'feature/test'))).toBe(true);
  });

  it('sanitizes branch names for file storage', () => {
    expect(sanitizeBranchForFilename('feature/privacy monitoring')).toBe('feature__privacy__monitoring');
  });
});

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function makeReport(score: number): ComplianceReport {
  return {
    id: 'report',
    timestamp: new Date().toISOString(),
    target: { name: 'repo' },
    overallScore: score,
    overallGrade: 'A',
    riskLevel: 'low',
    appControls: [],
    findings: [],
    remediation: [],
    metadata: {
      scannerVersions: {},
      deterministicHash: 'hash',
      scanDurationMs: 1,
      configHash: '',
    },
    disclaimer: 'test',
  };
}
