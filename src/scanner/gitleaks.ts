/**
 * AttestLens — gitleaks Scanner Adapter
 *
 * Opt-in git-history secret scanning via gitleaks SARIF output.
 */

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import type { ScannerAdapter, ScannerContext, ScannerError, ScannerResult } from './types.js';

const execFileAsync = promisify(execFile);

export interface GitleaksAdapterOptions {
  enabled?: boolean;
  path?: string;
  run?: GitleaksRunner;
}

export type GitleaksRunner = (
  binaryPath: string,
  args: string[],
  options: { cwd: string; signal?: AbortSignal },
) => Promise<{ stdout?: string; stderr?: string }>;

interface SarifLog {
  runs?: SarifRun[];
}

interface SarifRun {
  tool?: {
    driver?: {
      rules?: Array<{
        id?: string;
        name?: string;
        shortDescription?: { text?: string };
        fullDescription?: { text?: string };
      }>;
    };
  };
  results?: SarifResult[];
}

interface SarifResult {
  ruleId?: string;
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: {
        startLine?: number;
        snippet?: { text?: string };
      };
    };
  }>;
  partialFingerprints?: Record<string, string>;
}

interface GitleaksCategory {
  category: string;
  severity: Severity;
}

const DEFAULT_GITLEAKS_BINARY = 'gitleaks';

const GITLEAKS_CATEGORY_MAP: Record<string, GitleaksCategory> = {
  'aws-access-token': { category: 'Cloud Credentials', severity: 'critical' },
  'aws-secret-access-key': { category: 'Cloud Credentials', severity: 'critical' },
  'aws-session-token': { category: 'Cloud Credentials', severity: 'critical' },
  'azure-storage-account-key': { category: 'Cloud Credentials', severity: 'critical' },
  'gcp-api-key': { category: 'Cloud Credentials', severity: 'critical' },
  'google-api-key': { category: 'Cloud Credentials', severity: 'critical' },
  'private-key': { category: 'Private Key', severity: 'critical' },
  'rsa-private-key': { category: 'Private Key', severity: 'critical' },
  'github-pat': { category: 'Developer Credentials', severity: 'high' },
  'github-oauth': { category: 'Developer Credentials', severity: 'high' },
  'gitlab-pat': { category: 'Developer Credentials', severity: 'high' },
  'npm-token': { category: 'Package Registry Credentials', severity: 'high' },
  'pypi-upload-token': { category: 'Package Registry Credentials', severity: 'high' },
  'slack-token': { category: 'Collaboration Credentials', severity: 'high' },
  'stripe-access-token': { category: 'Payment Credentials', severity: 'critical' },
  'twilio-api-key': { category: 'Messaging Credentials', severity: 'high' },
  'sendgrid-api-key': { category: 'Messaging Credentials', severity: 'high' },
  'openai-api-key': { category: 'AI Service Credentials', severity: 'high' },
  'database-url': { category: 'Database Credentials', severity: 'critical' },
  'generic-api-key': { category: 'Application Credentials', severity: 'high' },
};

export class GitleaksAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'gitleaks';
  readonly version = '0.2.0';
  private readonly binaryPath: string;
  private readonly runner: GitleaksRunner;

  constructor(options: GitleaksAdapterOptions = {}) {
    this.binaryPath = options.path || DEFAULT_GITLEAKS_BINARY;
    this.runner = options.run || defaultGitleaksRunner;
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.runner(this.binaryPath, ['version'], { cwd: process.cwd() });
      return true;
    } catch {
      return false;
    }
  }

  async getVersion(): Promise<string> {
    try {
      const result = await this.runner(this.binaryPath, ['version'], { cwd: process.cwd() });
      return (result.stdout || '').trim() || this.version;
    } catch {
      return this.version;
    }
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(targetPath);
    const findings: AttestLensFinding[] = [];

    let pathStat;
    try {
      pathStat = await fs.stat(resolvedPath);
    } catch {
      return this.result(findings, [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }], startTime);
    }
    if (!pathStat.isDirectory()) {
      return this.result(findings, [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }], startTime);
    }

    const isGitRepo = await fs.stat(path.join(resolvedPath, '.git'))
      .then(() => true)
      .catch(() => false);
    if (!isGitRepo) {
      return this.result(findings, [{ source: this.name, message: 'Not a git repository — gitleaks skipped', code: 'NOT_GIT_REPOSITORY', recoverable: true }], startTime);
    }

    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-gitleaks-'));
    const reportPath = path.join(tempDir, 'gitleaks.sarif');
    try {
      const args = [
        'detect',
        '--source',
        resolvedPath,
        '--report-format',
        'sarif',
        '--report-path',
        reportPath,
        '--no-banner',
      ];

      try {
        await this.runner(this.binaryPath, args, { cwd: resolvedPath, signal: context?.signal });
      } catch (error) {
        const hasReport = await fileExists(reportPath);
        if (!hasReport) {
          const message = error instanceof Error ? error.message : 'gitleaks failed';
          return this.result(findings, [{ source: this.name, message: `gitleaks failed: ${message}`, code: 'GITLEAKS_FAILED', recoverable: true }], startTime);
        }
      }

      const sarifContent = await fs.readFile(reportPath, 'utf-8').catch(() => '');
      if (!sarifContent) {
        return this.result(findings, [{ source: this.name, message: 'gitleaks did not produce a SARIF report', code: 'GITLEAKS_NO_REPORT', recoverable: true }], startTime);
      }

      const sarif = JSON.parse(sarifContent) as SarifLog;
      findings.push(...this.parseSarif(sarif, resolvedPath));
      return this.result(findings, [], startTime);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  }

  private parseSarif(sarif: SarifLog, targetPath: string): AttestLensFinding[] {
    const findings: AttestLensFinding[] = [];
    for (const run of sarif.runs || []) {
      const ruleMetadata = new Map((run.tool?.driver?.rules || []).map(rule => [rule.id, rule]));
      for (const result of run.results || []) {
        const ruleId = result.ruleId || 'gitleaks-secret';
        const location = result.locations?.[0]?.physicalLocation;
        const uri = location?.artifactLocation?.uri || 'unknown';
        const filePath = path.resolve(targetPath, uri);
        const line = location?.region?.startLine;
        const rule = ruleMetadata.get(ruleId);
        const category = categorizeRule(ruleId);
        const sourceRule = toAttestLensRuleId(ruleId);
        const ruleName = rule?.name || rule?.shortDescription?.text || ruleId;

        findings.push({
          id: this.generateId(sourceRule, uri, line, result.partialFingerprints?.primaryLocationLineHash),
          source: this.name,
          sourceRule,
          severity: category.severity,
          category: category.category,
          title: `Secret detected in git history: ${ruleName}`,
          description: `gitleaks detected "${ruleName}" in git history at ${uri}${line ? `:${line}` : ''}. Secrets committed to git history may remain exposed after deletion from current files.`,
          file: path.relative(process.cwd(), filePath),
          line,
          code: '[redacted secret evidence]',
          fix: 'Rotate the exposed secret, remove it from git history where practical, and verify downstream services no longer accept the old value.',
          regulationMappings: [],
          appMappings: [],
          evidence: {
            timestamp: new Date().toISOString(),
            scannerVersion: this.version,
            rawOutput: {
              ruleId,
              ruleName,
              category: category.category,
              location: uri,
              line,
              fingerprint: result.partialFingerprints?.primaryLocationLineHash,
              message: redactSecretText(result.message?.text || ''),
            },
            scannerCommand: `${this.binaryPath} detect --source <target> --report-format sarif --report-path <tmp>`,
          },
        });
      }
    }
    return findings;
  }

  private result(findings: AttestLensFinding[], errors: ScannerError[], startTime: number): ScannerResult {
    return {
      source: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      findings,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  private generateId(ruleId: string, uri: string, line?: number, fingerprint?: string): string {
    return crypto
      .createHash('sha256')
      .update(`${this.name}:${ruleId}:${uri}:${line || ''}:${fingerprint || ''}`)
      .digest('hex')
      .substring(0, 12);
  }
}

async function defaultGitleaksRunner(
  binaryPath: string,
  args: string[],
  options: { cwd: string; signal?: AbortSignal },
): Promise<{ stdout?: string; stderr?: string }> {
  return execFileAsync(binaryPath, args, {
    cwd: options.cwd,
    signal: options.signal,
    timeout: 60_000,
    maxBuffer: 1024 * 1024,
  });
}

function categorizeRule(ruleId: string): GitleaksCategory {
  const normalized = ruleId.toLowerCase();
  return GITLEAKS_CATEGORY_MAP[normalized] || { category: 'Secrets', severity: 'high' };
}

function toAttestLensRuleId(ruleId: string): string {
  const normalized = ruleId
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  return `VS-GL-${normalized || 'SECRET'}`;
}

function redactSecretText(value: string): string {
  if (!value) return '';
  return value
    .replace(/[A-Za-z0-9_+/=.-]{20,}/g, '[redacted]')
    .replace(/(['"])[^'"]{8,}\1/g, '$1[redacted]$1');
}

async function fileExists(filePath: string): Promise<boolean> {
  return fs.stat(filePath).then(stat => stat.isFile()).catch(() => false);
}

export default GitleaksAdapter;
