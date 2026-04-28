import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { ComplianceReport } from '../schema/index.js';
import type { Baseline, BaselineControlSnapshot } from './types.js';

export interface BaselineStoreOptions {
  rootDir?: string;
}

export class BaselineStore {
  private readonly rootDir: string;

  constructor(options: BaselineStoreOptions = {}) {
    this.rootDir = options.rootDir || getDefaultBaselineRoot();
  }

  async save(repoUrl: string, branch: string, report: ComplianceReport, commitSha?: string): Promise<Baseline> {
    const existing = await this.load(repoUrl, branch);
    const now = new Date().toISOString();
    const baseline: Baseline = {
      schemaVersion: '1.0',
      repoUrl,
      repoHash: hashRepoUrl(repoUrl),
      branch,
      commitSha,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
      report: ComplianceReport.parse(report),
      summary: summarizeReport(report),
    };

    const filePath = this.getPath(repoUrl, branch);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, 'utf-8');
    return baseline;
  }

  async load(repoUrl: string, branch: string): Promise<Baseline | undefined> {
    const filePath = this.getPath(repoUrl, branch);
    try {
      const raw = await fs.readFile(filePath, 'utf-8');
      return parseBaseline(JSON.parse(raw));
    } catch (error: any) {
      if (error?.code === 'ENOENT') {
        return undefined;
      }
      throw error;
    }
  }

  async exists(repoUrl: string, branch: string): Promise<boolean> {
    return (await this.load(repoUrl, branch)) !== undefined;
  }

  getPath(repoUrl: string, branch: string): string {
    return path.join(this.rootDir, hashRepoUrl(repoUrl), `${sanitizeBranchForFilename(branch)}.json`);
  }
}

export function getDefaultBaselineRoot(): string {
  return path.join(os.homedir(), '.attestlens', 'baselines');
}

export function hashRepoUrl(repoUrl: string): string {
  return crypto.createHash('sha256').update(normalizeRepoUrl(repoUrl)).digest('hex').substring(0, 16);
}

export function normalizeRepoUrl(repoUrl: string): string {
  const trimmed = repoUrl.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  try {
    const parsed = new URL(trimmed);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.toString().replace(/\/+$/, '').replace(/\.git$/, '');
  } catch {
    return trimmed;
  }
}

export function sanitizeBranchForFilename(branch: string): string {
  const sanitized = branch.trim().replace(/[^a-zA-Z0-9._-]+/g, '__');
  return sanitized.length > 0 ? sanitized : 'default';
}

export function summarizeReport(report: ComplianceReport): Baseline['summary'] {
  return {
    overallScore: report.overallScore,
    overallGrade: report.overallGrade,
    riskLevel: report.riskLevel,
    findingCount: report.findings.length,
    appControls: report.appControls.map(toControlSnapshot),
  };
}

function toControlSnapshot(control: ComplianceReport['appControls'][number]): BaselineControlSnapshot {
  return {
    principle: control.principle,
    status: control.status,
    score: control.score,
    findingCount: control.findingCount,
    findings: [...control.findings],
  };
}

function parseBaseline(value: unknown): Baseline {
  if (!value || typeof value !== 'object') {
    throw new Error('Invalid baseline file: expected object');
  }

  const candidate = value as Baseline;
  if (candidate.schemaVersion !== '1.0') {
    throw new Error('Invalid baseline file: unsupported schemaVersion');
  }

  return {
    ...candidate,
    report: ComplianceReport.parse(candidate.report),
    summary: summarizeReport(candidate.report),
  };
}
