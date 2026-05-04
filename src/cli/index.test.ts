import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { describe, expect, it, vi } from 'vitest';

import {
  buildFindingsHash,
  CCPA_QUESTIONNAIRE_VERSION,
  GDPR_QUESTIONNAIRE_VERSION,
  LEGACY_QUESTION_BANK_V1,
  QUESTIONNAIRE_VERSION,
  loadQuestionnaireSession,
  loadScanSnapshot,
  type AttestationPromptRunner,
} from '../questionnaire/index.js';
import { OSV_QUERY_BATCH_URL } from '../scanner/osv.js';
import { buildEmbeddedRulePack } from '../scanner/rules/index.js';
import {
  buildScannerOrchestratorOptions,
  determineDeployDecisionExitCode,
  executeAttestCommand,
  hasFindingsAtOrAboveThreshold,
} from './index.js';

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const cliEntry = path.join(repoRoot, 'src', 'cli', 'index.ts');
const fastAttestScanOptions = {
  guardvibe: false,
  mcpScan: false,
  behavioral: false,
  iac: false,
} as const;
const noScannerAttestOptions = {
  ...fastAttestScanOptions,
  supplyChain: false,
} as const;
const packageJson = JSON.parse(await fs.readFile(path.join(repoRoot, 'package.json'), 'utf-8')) as { version: string };

async function runCli(
  args: string[],
  envOverrides: Record<string, string | undefined> = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  const env: Record<string, string | undefined> = { ...process.env, TMPDIR: '/tmp' };
  for (const [key, value] of Object.entries(envOverrides)) {
    if (value === undefined) {
      delete env[key];
    } else {
      env[key] = value;
    }
  }

  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['--import', 'tsx', cliEntry, ...args], { cwd: repoRoot, env });
    return { code: 0, stdout, stderr };
  } catch (error: any) {
    return {
      code: error.code ?? 1,
      stdout: error.stdout ?? '',
      stderr: error.stderr ?? '',
    };
  }
}

function makePromptRunner(options: {
  saveAfter?: number;
  noteQuestionId?: string;
  assessmentMode?: 'artifact_only' | 'codebase_only' | 'operator_attested';
} = {}): AttestationPromptRunner {
  let answeredCount = 0;

  return {
    async promptAssessmentMode() {
      return options.assessmentMode || 'operator_attested';
    },

    async prompt(question) {
      if (options.saveAfter !== undefined && answeredCount >= options.saveAfter) {
        return { kind: 'save_and_exit' };
      }

      answeredCount += 1;

      switch (question.type) {
        case 'yes_no':
          return {
            kind: 'answer',
            answer: true,
            note: options.noteQuestionId === question.id ? 'Reviewed internally' : undefined,
            evidenceRefs: options.noteQuestionId === question.id ? ['docs/privacy-policy.md'] : undefined,
          };
        case 'yes_no_na':
          return {
            kind: 'answer',
            answer: true,
          };
        case 'multi_choice':
          const minimumSelectedOptions = question.minimumSelectedOptions || 1;
          return {
            kind: 'answer',
            answer: (question.options || [])
              .filter((option) => option !== 'None of the above')
              .slice(0, minimumSelectedOptions),
          };
        case 'text':
          return {
            kind: 'answer',
            answer: 'Documented internally',
          };
      }
    },
  };
}

async function createCliPackageProject(dependencyName: string): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-project-'));
  await fs.writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'cli-enrichment-test',
    version: '1.0.0',
    dependencies: {
      [dependencyName]: '1.0.0',
    },
  }, null, 2));
  return projectDir;
}

async function createCliBehavioralProject(): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-behavioral-'));
  await fs.writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'cli-behavioral-test',
    version: '1.0.0',
    dependencies: {
      'behavior-pkg': '1.0.0',
    },
  }, null, 2));
  await fs.mkdir(path.join(projectDir, 'node_modules', 'behavior-pkg'), { recursive: true });
  await fs.writeFile(path.join(projectDir, 'node_modules', 'behavior-pkg', 'package.json'), JSON.stringify({
    name: 'behavior-pkg',
    version: '1.0.0',
  }, null, 2));
  await fs.writeFile(path.join(projectDir, 'node_modules', 'behavior-pkg', 'index.js'), 'export const run = (code) => eval(code);');
  return projectDir;
}

async function createCliIacProject(): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-iac-'));
  await fs.writeFile(
    path.join(projectDir, 'Dockerfile'),
    [
      'FROM node:latest',
      'RUN apt-get update && apt-get install -y curl',
      'EXPOSE 80',
      'CMD ["node", "server.js"]',
    ].join('\n'),
  );
  return projectDir;
}

async function createCliDataFlowProject(): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-dataflow-'));
  await fs.writeFile(
    path.join(projectDir, 'route.ts'),
    [
      'export async function POST(request: Request) {',
      '  const body = await request.json();',
      '  console.info("signup", body.email);',
      '  return Response.json({ ok: true });',
      '}',
    ].join('\n'),
  );
  return projectDir;
}

describe('CLI URL handling', () => {
  it('fails URL scans when the target is blocked or unreachable', async () => {
    const result = await runCli(['scan', 'http://localhost:3000']);
    const output = `${result.stdout}\n${result.stderr}`;

    expect(result.code).toBe(2);
    expect(output).toContain('URL target is not allowed for scanning.');
    expect(output).not.toContain('No compliance findings detected.');
  });

  it('fails URL audits before writing a clean report when the scan does not complete', async () => {
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-audit-'));

    try {
      const result = await runCli(['audit', 'http://localhost:3000', '-n', 'Localhost', '-f', 'json', '-o', outputDir]);
      const output = `${result.stdout}\n${result.stderr}`;
      const files = await fs.readdir(outputDir);

      expect(result.code).toBe(2);
      expect(output).toContain('URL target is not allowed for scanning.');
      expect(files).toHaveLength(0);
    } finally {
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('regenerates reports from saved URL scan payloads using the original target URL', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-report-'));
    const inputPath = path.join(tempDir, 'url-scan.json');
    const outputDir = path.join(tempDir, 'out');

    try {
      await fs.writeFile(inputPath, JSON.stringify({
        targetType: 'url',
        targetUrl: 'https://example.com/?token=secret#frag',
        findings: [],
      }, null, 2));

      const result = await runCli(['report', inputPath, '-f', 'markdown', '-o', outputDir]);
      expect(result.code).toBe(0);

      const files = await fs.readdir(outputDir);
      expect(files).toHaveLength(1);

      const reportPath = path.join(outputDir, files[0]!);
      const markdown = await fs.readFile(reportPath, 'utf-8');
      expect(markdown).toContain('**Target URL:** https://example.com/');
      expect(markdown).not.toContain('**Target Path:**');
      expect(markdown).toContain('# Privacy Act Compliance Report — example.com');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('regenerates agent reports with the saved scan jurisdiction', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-report-jurisdiction-'));
    const inputPath = path.join(tempDir, 'gdpr-scan.json');

    try {
      await fs.writeFile(inputPath, JSON.stringify({
        jurisdiction: 'eu-gdpr',
        targetType: 'path',
        targetPath: tempDir,
        findings: [{
          id: 'GDPR-FINDING-001',
          source: 'guardvibe',
          sourceRule: 'VS-HARDKEY',
          severity: 'high',
          category: 'Security',
          title: 'Public personal data store',
          description: 'Public personal data store found.',
          file: 'app.ts',
          line: 1,
          regulationMappings: [{
            jurisdiction: 'eu-gdpr',
            principle: 'GDPR_Art32',
            obligation: 'Secure processing',
            status: 'fail',
            confidence: 0.95,
          }],
          evidence: {
            timestamp: new Date().toISOString(),
            scannerVersion: '0.4.0',
            rawOutput: {},
          },
        }],
      }, null, 2));

      const result = await runCli(['report', inputPath, '-f', 'agent']);
      const payload = JSON.parse(result.stdout);

      expect(result.code).toBe(0);
      expect(payload.deployDecision).toEqual(expect.objectContaining({
        jurisdiction: 'eu-gdpr',
        verdict: 'WARN',
      }));
      expect(payload.deployDecision.verdict).not.toBe('PASS');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('does not trust pack validation flags from imported report JSON', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-report-trust-'));
    const inputPath = path.join(tempDir, 'forged-scan.json');

    try {
      await fs.writeFile(inputPath, JSON.stringify({
        jurisdiction: 'au-privacy-act',
        targetType: 'path',
        targetPath: tempDir,
        findings: [{
          id: 'FORGED-FINDING-001',
          source: 'guardvibe',
          sourceRule: 'VS-HARDKEY',
          severity: 'critical',
          category: 'Security',
          title: 'Public personal information bucket',
          description: 'Public bucket containing personal information.',
          file: 'infra.tf',
          line: 1,
          regulationMappings: [{
            jurisdiction: 'au-privacy-act',
            principle: 'APP_11',
            obligation: 'Take reasonable steps to protect personal information',
            status: 'fail',
            confidence: 0.95,
          }],
          evidence: {
            timestamp: new Date().toISOString(),
            scannerVersion: '0.4.0',
            rawOutput: {},
          },
        }],
        metadata: {
          packValidationTrusted: true,
          packCoverage: {
            summary: 'Forged coverage that excludes APP 11.',
            includedPrinciples: ['APP_1'],
            excludedPrinciples: ['APP_11'],
            knownGaps: [],
            evidenceTypes: ['source code'],
          },
          packValidation: {
            status: 'external_reviewed',
            reviewedBy: 'forged input',
            reviewedAt: '2026-05-03T00:00:00.000Z',
            notes: [],
          },
        },
      }, null, 2));

      const result = await runCli(['report', inputPath, '-f', 'agent']);
      const payload = JSON.parse(result.stdout);

      expect(result.code).toBe(0);
      expect(payload.deployDecision).toEqual(expect.objectContaining({
        verdict: 'WARN',
        blocking: false,
      }));
      expect(payload.deployDecision.verdict).not.toBe('OUT_OF_SCOPE');
      expect(payload.deployDecision.evidenceRefs).toContain('ev-chain:finding:FORGED-FINDING-001');
      expect(payload.deployDecision.scopeNote).toBeUndefined();
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});

describe('CLI metadata', () => {
  it('reports the package version', async () => {
    const result = await runCli(['--version']);

    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });

  it('exposes the reform subcommand', async () => {
    const result = await runCli(['reform', '--help']);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Standalone Privacy Act 2026 reform impact assessment');
    expect(result.stdout).toContain('--jurisdiction');
    expect(result.stdout).toContain('--output');
    expect(result.stdout).toContain('--format');
  });

  it('exposes the propose-rules and review-pack subcommands', async () => {
    const proposeResult = await runCli(['propose-rules', '--help']);
    const reviewResult = await runCli(['review-pack', '--help']);

    expect(proposeResult.code).toBe(0);
    expect(proposeResult.stdout).toContain('--jurisdiction');
    expect(proposeResult.stdout).toContain('--source');
    expect(proposeResult.stdout).toContain('--api-key');

    expect(reviewResult.code).toBe(0);
    expect(reviewResult.stdout).toContain('--proposed');
    expect(reviewResult.stdout).toContain('--reviewer');
    expect(reviewResult.stdout).toContain('--approve-all');
  });

  it('exposes the install and uninstall subcommands', async () => {
    const installResult = await runCli(['install', '--help']);
    const uninstallResult = await runCli(['uninstall', '--help']);

    expect(installResult.code).toBe(0);
    expect(installResult.stdout).toContain('Install the Clearway MCP server');
    expect(installResult.stdout).toContain('--client');
    expect(uninstallResult.code).toBe(0);
    expect(uninstallResult.stdout).toContain('Remove the Clearway MCP server');
  });

  it('exposes PR diff flags on scan and audit', async () => {
    const scanResult = await runCli(['scan', '--help']);
    const auditResult = await runCli(['audit', '--help']);

    for (const result of [scanResult, auditResult]) {
      expect(result.code).toBe(0);
      expect(result.stdout).toContain('--diff-base');
      expect(result.stdout).toContain('--diff-head');
      expect(result.stdout).toContain('--changed-files-only');
      expect(result.stdout).toContain('--allow-internal-validation-blocking');
    }
  });
});

describe('CLI agent report format', () => {
  it('prints agent JSON to stdout without failing for non-blocking WARN opinions at the default threshold', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-agent-'));

    try {
      await fs.writeFile(
        path.join(projectDir, 'Dockerfile'),
        'FROM node:latest\nUSER root\n',
      );

      const result = await runCli([
        'audit',
        projectDir,
        '-f',
        'agent',
        '--opinion',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      const payload = JSON.parse(result.stdout);

      expect(result.code).toBe(0);
      expect(payload.schema).toBe('attestlens-agent-v1');
      expect(payload.verdict).toBe('NON_COMPLIANT');
      expect(payload.deployDecision).toEqual(expect.objectContaining({
        verdict: 'WARN',
        blocking: false,
      }));
      expect(payload.actions.some((action: { principle: string }) => action.principle === 'APP_11')).toBe(true);
      expect(result.stdout.trim()).toMatch(/^\{/);
      expect(result.stdout).not.toContain('Privacy Act Compliance Audit');
      expect(result.stdout).not.toContain('Report generated successfully');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('prints deployDecision for agent JSON without forcing an opinion verdict', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-agent-deploy-'));

    try {
      await fs.writeFile(
        path.join(projectDir, 'Dockerfile'),
        'FROM node:latest\nUSER root\n',
      );

      const result = await runCli([
        'audit',
        projectDir,
        '-f',
        'agent',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      const payload = JSON.parse(result.stdout);

      expect(result.code).toBe(0);
      expect(payload.schema).toBe('attestlens-agent-v1');
      expect(payload.verdict).toBe('UNKNOWN');
      expect(payload.deployDecision).toEqual(expect.objectContaining({
        verdict: 'WARN',
        blocking: false,
      }));
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('exits 1 for non-blocking agent WARN only when the selected threshold includes warnings', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-agent-warn-threshold-'));

    try {
      await fs.writeFile(
        path.join(projectDir, 'Dockerfile'),
        'FROM node:latest\nUSER root\n',
      );

      const result = await runCli([
        'audit',
        projectDir,
        '-f',
        'agent',
        '--fail-on-severity',
        'warning',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      const payload = JSON.parse(result.stdout);

      expect(result.code).toBe(1);
      expect(payload.deployDecision).toEqual(expect.objectContaining({
        verdict: 'WARN',
        blocking: false,
      }));
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('allows local demo policy to turn trusted internal-validated blocking candidates into BLOCK', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-agent-block-override-'));

    try {
      await fs.writeFile(
        path.join(projectDir, 'Dockerfile'),
        'FROM node:latest\nUSER root\n',
      );

      const result = await runCli([
        'audit',
        projectDir,
        '-f',
        'agent',
        '--allow-internal-validation-blocking',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      const payload = JSON.parse(result.stdout);

      expect(result.code).toBe(1);
      expect(payload.deployDecision).toEqual(expect.objectContaining({
        verdict: 'BLOCK',
        blocking: true,
        packValidationStatus: 'internal_validated',
      }));
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });
});

describe('CLI SARIF and exit thresholds', () => {
  it('returns exit code 0 when findings do not exceed the threshold', async () => {
    const findings = [
      {
        severity: 'medium',
      },
    ] as any;

    expect(hasFindingsAtOrAboveThreshold(findings, 'error')).toBe(false);
    expect(hasFindingsAtOrAboveThreshold(findings, 'warning')).toBe(true);
  });

  it('derives deploy-gate exit codes from deploy decisions and threshold policy', () => {
    const makeDecision = (
      verdict: 'BLOCK' | 'WARN' | 'NEEDS_REVIEW' | 'PASS' | 'OUT_OF_SCOPE',
      blocking = verdict === 'BLOCK',
      packValidationStatus: 'internal_validated' | 'external_reviewed' = verdict === 'BLOCK'
        ? 'external_reviewed'
        : 'internal_validated',
    ) => ({
      verdict,
      blocking,
      confidence: 0.8,
      jurisdiction: 'au-privacy-act' as const,
      packValidationStatus,
      reasons: [],
      evidenceRefs: [],
      remediations: [],
    });
    const baseConfig = { threshold: 'error' as const, noFail: false, strict: false };

    expect(determineDeployDecisionExitCode(makeDecision('WARN', false), baseConfig)).toBe(0);
    expect(determineDeployDecisionExitCode(makeDecision('WARN', false), {
      ...baseConfig,
      threshold: 'warning',
    })).toBe(1);
    expect(determineDeployDecisionExitCode(makeDecision('BLOCK'), baseConfig)).toBe(1);
    expect(determineDeployDecisionExitCode(makeDecision('NEEDS_REVIEW', false), baseConfig)).toBe(0);
    expect(determineDeployDecisionExitCode(makeDecision('NEEDS_REVIEW', false), {
      ...baseConfig,
      threshold: 'note',
    })).toBe(1);
    expect(determineDeployDecisionExitCode(makeDecision('NEEDS_REVIEW', false), {
      ...baseConfig,
      strict: true,
    })).toBe(1);
    expect(determineDeployDecisionExitCode(makeDecision('PASS', false), {
      ...baseConfig,
      threshold: 'note',
    })).toBe(0);
    expect(determineDeployDecisionExitCode(makeDecision('OUT_OF_SCOPE', false), {
      ...baseConfig,
      threshold: 'note',
    })).toBe(0);
    expect(determineDeployDecisionExitCode(makeDecision('BLOCK'), {
      ...baseConfig,
      noFail: true,
    })).toBe(0);
  });

  it('writes SARIF to stdout for scan and honors --no-fail', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-sarif-'));

    try {
      await fs.writeFile(path.join(projectDir, 'Dockerfile'), 'FROM node:latest\nUSER root\n');

      const result = await runCli([
        'scan',
        projectDir,
        '--format',
        'sarif',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
        '--no-fail',
      ]);

      const payload = JSON.parse(result.stdout);
      expect(result.code).toBe(0);
      expect(payload.version).toBe('2.1.0');
      expect(payload.runs[0].results).toEqual(expect.any(Array));
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('preserves legacy severity exits for basic scan while audit reports use deploy decision exits', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-audit-deploy-exit-'));
    const projectDir = path.join(tempDir, 'project');
    const outputDir = path.join(tempDir, 'reports');

    try {
      await fs.mkdir(projectDir, { recursive: true });
      await fs.writeFile(path.join(projectDir, 'Dockerfile'), 'FROM node:latest\nUSER root\n');

      const scanResult = await runCli([
        'scan',
        projectDir,
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      expect(scanResult.code).toBe(1);

      const auditDefaultResult = await runCli([
        'audit',
        projectDir,
        '--format',
        'html,json,markdown,pdf',
        '--output',
        outputDir,
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      expect(auditDefaultResult.code).toBe(0);

      const auditWarningThresholdResult = await runCli([
        'audit',
        projectDir,
        '--format',
        'json',
        '--output',
        outputDir,
        '--fail-on-severity',
        'warning',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);
      expect(auditWarningThresholdResult.code).toBe(1);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('writes SARIF to a file for audit and exits from emitted SARIF levels', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-audit-sarif-'));
    const projectDir = path.join(tempDir, 'project');
    const outputDir = path.join(tempDir, 'reports');
    const sarifPath = path.join(outputDir, 'result.sarif');

    try {
      await fs.mkdir(projectDir, { recursive: true });
      await fs.writeFile(path.join(projectDir, 'Dockerfile'), 'FROM node:latest\nUSER root\n');

      const result = await runCli([
        'audit',
        projectDir,
        '--format',
        'sarif',
        '--output',
        outputDir,
        '--sarif-output',
        sarifPath,
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);

      const payload = JSON.parse(await fs.readFile(sarifPath, 'utf-8'));
      expect(result.code).toBe(0);
      expect(payload.runs[0].results.length).toBeGreaterThan(0);
      expect(payload.runs[0].results.every((entry: { level: string }) => entry.level !== 'error')).toBe(true);

      const blockingThresholdResult = await runCli([
        'audit',
        projectDir,
        '--format',
        'sarif',
        '--output',
        outputDir,
        '--sarif-output',
        sarifPath,
        '--fail-on-severity',
        'warning',
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);

      expect(blockingThresholdResult.code).toBe(1);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('treats invalid fail-on-severity values as tool errors', async () => {
    const result = await runCli(['scan', repoRoot, '--fail-on-severity', 'bad-level']);
    expect(result.code).toBe(2);
    expect(`${result.stdout}\n${result.stderr}`).toContain('Unsupported fail severity');
  });

  it('rejects SARIF output paths outside the current working directory and output directory', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-sarif-path-'));
    const projectDir = path.join(tempDir, 'project');
    const outputDir = path.join(tempDir, 'reports');
    const outsidePath = path.join(os.tmpdir(), 'attestlens-cli-outside.sarif');

    try {
      await fs.mkdir(projectDir, { recursive: true });
      await fs.writeFile(path.join(projectDir, 'Dockerfile'), 'FROM node:latest\nUSER root\n');

      const result = await runCli([
        'audit',
        projectDir,
        '--format',
        'sarif',
        '--output',
        outputDir,
        '--sarif-output',
        outsidePath,
        '--no-guardvibe',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
      ]);

      expect(result.code).toBe(2);
      expect(`${result.stdout}\n${result.stderr}`).toContain('SARIF output path must be within the current working directory or the configured output directory.');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
      await fs.rm(outsidePath, { force: true });
    }
  });
});

describe('CLI external enrichment option', () => {
  it('exposes explicit external enrichment on scan, audit, and attest flows', async () => {
    const scanHelp = await runCli(['scan', '--help']);
    const auditHelp = await runCli(['audit', '--help']);
    const attestHelp = await runCli(['attest', '--help']);
    const complianceHelp = await runCli(['compliance-check', '--help']);

    expect(scanHelp.code).toBe(0);
    expect(auditHelp.code).toBe(0);
    expect(attestHelp.code).toBe(0);
    expect(complianceHelp.code).toBe(0);
    expect(scanHelp.stdout).toContain('--external-enrichment');
    expect(auditHelp.stdout).toContain('--external-enrichment');
    expect(attestHelp.stdout).toContain('--external-enrichment');
    expect(scanHelp.stdout).toContain('--include-typosquat');
    expect(auditHelp.stdout).toContain('--include-typosquat');
    expect(attestHelp.stdout).toContain('--include-typosquat');
    expect(scanHelp.stdout).toContain('--scanner-timeout');
    expect(auditHelp.stdout).toContain('--scanner-timeout');
    expect(attestHelp.stdout).toContain('--scanner-timeout');
    expect(scanHelp.stdout).toContain('--jurisdiction');
    expect(auditHelp.stdout).toContain('--jurisdiction');
    expect(complianceHelp.stdout).toContain('--jurisdiction');
    expect(attestHelp.stdout).toContain('--jurisdiction');
    expect(scanHelp.stdout).toContain('--no-behavioral');
    expect(auditHelp.stdout).toContain('--no-behavioral');
    expect(attestHelp.stdout).toContain('--no-behavioral');
    expect(scanHelp.stdout).toContain('--no-iac');
    expect(auditHelp.stdout).toContain('--no-iac');
    expect(attestHelp.stdout).toContain('--no-iac');
    expect(scanHelp.stdout).toContain('--no-data-flow-lite');
    expect(auditHelp.stdout).toContain('--no-data-flow-lite');
    expect(attestHelp.stdout).toContain('--no-data-flow-lite');
    expect(scanHelp.stdout).toContain('--include-gitleaks');
    expect(auditHelp.stdout).toContain('--include-gitleaks');
    expect(attestHelp.stdout).toContain('--include-gitleaks');
    expect(scanHelp.stdout).toContain('--gitleaks-path');
    expect(auditHelp.stdout).toContain('--gitleaks-path');
    expect(attestHelp.stdout).toContain('--gitleaks-path');
  });

  it('keeps external enrichment disabled by default in shared scanner options', () => {
    for (const options of [{}, { externalEnrichment: false }]) {
      expect(buildScannerOrchestratorOptions(options)).toEqual({
        jurisdictions: ['au-privacy-act'],
        supplyChain: {
          typosquat: { enabled: false },
          osv: { enabled: false },
          registry: { enabled: false },
        },
        behavioral: {
          enabled: true,
        },
        iac: {
          enabled: true,
        },
        dataFlowLite: {
          enabled: true,
        },
        gitleaks: {
          enabled: false,
          path: 'gitleaks',
        },
        reform: {
          enabled: false,
        },
      });
    }
  });

  it('enables OSV and registry enrichment only when explicitly requested', () => {
    expect(buildScannerOrchestratorOptions({ externalEnrichment: true })).toEqual({
      jurisdictions: ['au-privacy-act'],
      supplyChain: {
        typosquat: { enabled: false },
        osv: { enabled: true },
        registry: { enabled: true },
      },
      behavioral: {
        enabled: true,
      },
      iac: {
        enabled: true,
      },
      dataFlowLite: {
        enabled: true,
      },
      gitleaks: {
        enabled: false,
        path: 'gitleaks',
      },
      reform: {
        enabled: false,
      },
    });
  });

  it('enables typosquat and scanner timeout only when explicitly requested', () => {
    expect(buildScannerOrchestratorOptions({
      includeTyposquat: true,
      scannerTimeout: '1234',
    })).toEqual({
      adapterTimeoutMs: 1234,
      jurisdictions: ['au-privacy-act'],
      supplyChain: {
        typosquat: { enabled: true },
        osv: { enabled: false },
        registry: { enabled: false },
      },
      behavioral: {
        enabled: true,
      },
      iac: {
        enabled: true,
      },
      dataFlowLite: {
        enabled: true,
      },
      gitleaks: {
        enabled: false,
        path: 'gitleaks',
      },
      reform: {
        enabled: false,
      },
    });
  });

  it('enables gitleaks only when explicitly requested', () => {
    expect(buildScannerOrchestratorOptions({
      includeGitleaks: true,
      gitleaksPath: '/usr/local/bin/gitleaks',
    })).toEqual({
      jurisdictions: ['au-privacy-act'],
      supplyChain: {
        typosquat: { enabled: false },
        osv: { enabled: false },
        registry: { enabled: false },
      },
      behavioral: {
        enabled: true,
      },
      iac: {
        enabled: true,
      },
      dataFlowLite: {
        enabled: true,
      },
      gitleaks: {
        enabled: true,
        path: '/usr/local/bin/gitleaks',
      },
      reform: {
        enabled: false,
      },
    });
  });

  it('disables behavioral findings from CLI scans when requested', async () => {
    const projectDir = await createCliBehavioralProject();

    try {
      const enabled = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain']);
      expect(`${enabled.stdout}\n${enabled.stderr}`).toContain('VS-BH-001');

      const disabled = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral']);
      expect(`${disabled.stdout}\n${disabled.stderr}`).not.toContain('VS-BH-001');
      expect(disabled.code).toBe(0);
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('disables IaC findings from CLI scans when requested', async () => {
    const projectDir = await createCliIacProject();

    try {
      const enabled = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral']);
      expect(`${enabled.stdout}\n${enabled.stderr}`).toContain('VS-IAC-007');

      const disabled = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac']);
      expect(`${disabled.stdout}\n${disabled.stderr}`).not.toContain('VS-IAC-007');
      expect(disabled.code).toBe(0);
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('disables Data Flow Lite findings from CLI scans when requested', async () => {
    const projectDir = await createCliDataFlowProject();

    try {
      const enabled = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac']);
      expect(`${enabled.stdout}\n${enabled.stderr}`).toContain('Found 1 finding');

      const disabled = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac', '--no-data-flow-lite']);
      expect(`${disabled.stdout}\n${disabled.stderr}`).toContain('No compliance findings detected');
      expect(disabled.code).toBe(0);
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('rejects invalid scanner timeout values', () => {
    expect(() => buildScannerOrchestratorOptions({ scannerTimeout: 'abc' }))
      .toThrow('Unsupported scanner timeout');
    expect(() => buildScannerOrchestratorOptions({ scannerTimeout: '0' }))
      .toThrow('Unsupported scanner timeout');
  });

  it('passes explicit AU jurisdiction into scanner options', () => {
    expect(buildScannerOrchestratorOptions({ jurisdiction: 'au-privacy-act' })).toEqual(expect.objectContaining({
      jurisdictions: ['au-privacy-act'],
    }));
  });

  it('passes explicit CCPA jurisdiction into scanner options', () => {
    expect(buildScannerOrchestratorOptions({ jurisdiction: 'us-ccpa' })).toEqual(expect.objectContaining({
      jurisdictions: ['us-ccpa'],
    }));
  });

  it('passes explicit GDPR jurisdiction into scanner options', () => {
    expect(buildScannerOrchestratorOptions({ jurisdiction: 'eu-gdpr' })).toEqual(expect.objectContaining({
      jurisdictions: ['eu-gdpr'],
    }));
  });

  it('passes explicit SG PDPA jurisdiction into scanner options', () => {
    expect(buildScannerOrchestratorOptions({ jurisdiction: 'sg-pdpa' })).toEqual(expect.objectContaining({
      jurisdictions: ['sg-pdpa'],
    }));
  });

  it('rejects unsupported jurisdiction values in scanner options', () => {
    expect(() => buildScannerOrchestratorOptions({ jurisdiction: 'antarctica' }))
      .toThrow('Unsupported jurisdiction');
  });

  it('runs scan with explicit AU jurisdiction like the default', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-jurisdiction-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');
      const defaultResult = await runCli(['scan', projectDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac']);
      const auResult = await runCli(['scan', projectDir, '--jurisdiction', 'au-privacy-act', '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac']);

      expect(defaultResult.code).toBe(0);
      expect(auResult.code).toBe(0);
      expect(defaultResult.stdout).toContain('No compliance findings detected');
      expect(auResult.stdout).toContain('No compliance findings detected');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('runs scan and audit with CCPA, GDPR, and SG PDPA jurisdictions', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-jurisdiction-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-jurisdiction-out-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');
      const commands = [
        ['scan', projectDir, '--jurisdiction', 'us-ccpa', '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac'],
        ['audit', projectDir, '--jurisdiction', 'us-ccpa', '-f', 'json', '-o', outputDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac'],
        ['scan', projectDir, '--jurisdiction', 'eu-gdpr', '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac'],
        ['audit', projectDir, '--jurisdiction', 'eu-gdpr', '-f', 'json', '-o', outputDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac'],
        ['scan', projectDir, '--jurisdiction', 'sg-pdpa', '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac'],
        ['audit', projectDir, '--jurisdiction', 'sg-pdpa', '-f', 'json', '-o', outputDir, '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain', '--no-behavioral', '--no-iac'],
      ];

      for (const command of commands) {
        const result = await runCli(command);
        const output = `${result.stdout}\n${result.stderr}`;

        expect(result.code, output).toBe(0);
        expect(output, command[0]).not.toContain('not yet available');
      }
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  }, 15000);

  it('exits non-zero and prints CCPA controls for audit failures from regulation controls', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-ccpa-audit-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-ccpa-audit-out-'));

    try {
      await fs.writeFile(
        path.join(projectDir, 'privacy.html'),
        '<h1>Privacy Policy</h1><p>We collect personal information.</p>',
      );

      const result = await runCli([
        'audit',
        projectDir,
        '--jurisdiction',
        'us-ccpa',
        '-f',
        'json',
        '-o',
        outputDir,
        '--fail-on-severity',
        'warning',
        '--no-mcp-scan',
        '--no-supply-chain',
        '--no-behavioral',
        '--no-iac',
      ], {
        ATTESTLENS_GUARDVIBE_PATH: '__attestlens_missing_guardvibe__',
      });
      const output = `${result.stdout}\n${result.stderr}`;

      expect(result.code, output).toBe(1);
      expect(output).toContain('CCPA_130');
      expect(output).toContain('FAIL');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  }, 15000);

  it('rejects CCPA jurisdiction for AU-only SMB compliance-check', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-ccpa-smb-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');
      const result = await runCli([
        'compliance-check',
        projectDir,
        '--jurisdiction',
        'us-ccpa',
        '--non-interactive',
      ]);
      const output = `${result.stdout}\n${result.stderr}`;

      expect(result.code, output).toBe(2);
      expect(output).toContain('SMB compliance check is currently AU-only');
      expect(output).toContain('audit --jurisdiction us-ccpa');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('rejects GDPR jurisdiction for AU-only SMB compliance-check', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-jurisdiction-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');
      const result = await runCli([
        'compliance-check',
        projectDir,
        '--jurisdiction',
        'eu-gdpr',
        '--non-interactive',
      ]);
      const output = `${result.stdout}\n${result.stderr}`;

      expect(result.code).toBe(2);
      expect(output).toContain('SMB compliance check is currently AU-only');
      expect(output).toContain('audit --jurisdiction eu-gdpr');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('does not call OSV or npm registry during default attest scans', async () => {
    const projectDir = await createCliPackageProject('external-only');
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-enrichment-'));
    const fetchMock = vi.fn(async () => {
      throw new Error('external enrichment should be disabled');
    });

    try {
      vi.stubGlobal('fetch', fetchMock);

      const result = await executeAttestCommand(projectDir, {
        ...fastAttestScanOptions,
        output: outputDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0 }));

      expect(result.status).toBe('saved');
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('passes explicit external enrichment into attest scans', async () => {
    const projectDir = await createCliPackageProject('external-only');
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-enrichment-'));
    const calls: string[] = [];
    const fetchMock = vi.fn(async (input: string | URL) => {
      const url = String(input);
      calls.push(url);
      if (url === 'https://registry.npmjs.org/external-only') {
        return new Response(JSON.stringify({ name: 'external-only', version: '1.0.0' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === OSV_QUERY_BATCH_URL) {
        return new Response(JSON.stringify({ results: [{}] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 404 });
    });

    try {
      vi.stubGlobal('fetch', fetchMock);

      const result = await executeAttestCommand(projectDir, {
        ...fastAttestScanOptions,
        output: outputDir,
        format: 'json',
        strict: false,
        externalEnrichment: true,
      }, makePromptRunner({ saveAfter: 0 }));

      expect(result.status).toBe('saved');
      expect(calls).toContain('https://registry.npmjs.org/external-only/1.0.0');
      expect(calls).toContain(OSV_QUERY_BATCH_URL);
    } finally {
      vi.unstubAllGlobals();
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });
});

describe('CLI rule update command', () => {
  it('caches a local rule pack without network access', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-rules-'));
    const sourcePath = path.join(tempDir, 'rules.json');
    const cacheDir = path.join(tempDir, 'cache');

    try {
      await fs.writeFile(sourcePath, JSON.stringify({
        ...buildEmbeddedRulePack(),
        version: '2026.04.25',
        generated: '2026-04-25T00:00:00.000Z',
      }, null, 2));

      const result = await runCli(['update-rules', '--source', sourcePath, '--cache-dir', cacheDir]);
      expect(result.code).toBe(0);
      expect(`${result.stdout}\n${result.stderr}`).toContain('Rule pack 2026.04.25 cached');
      expect(result.stdout).toContain('Rules:');
      expect(result.stdout).toContain(`Cache: ${cacheDir}`);

      const cached = JSON.parse(await fs.readFile(path.join(cacheDir, 'latest.json'), 'utf-8'));
      expect(cached.version).toBe('2026.04.25');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('preserves an existing cache when update-rules has no source', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-rules-'));
    const sourcePath = path.join(tempDir, 'rules.json');
    const cacheDir = path.join(tempDir, 'cache');

    try {
      await fs.writeFile(sourcePath, JSON.stringify({
        ...buildEmbeddedRulePack(),
        version: '2026.04.25',
        generated: '2026-04-25T00:00:00.000Z',
      }, null, 2));

      expect((await runCli(['update-rules', '--source', sourcePath, '--cache-dir', cacheDir])).code).toBe(0);

      const result = await runCli(
        ['update-rules', '--cache-dir', cacheDir],
        { ATTESTLENS_RULE_SOURCE: undefined },
      );
      const cached = JSON.parse(await fs.readFile(path.join(cacheDir, 'latest.json'), 'utf-8'));
      const output = `${result.stdout}\n${result.stderr}`;

      expect(result.code).toBe(0);
      expect(output).toContain('Rule pack 2026.04.25 cached');
      expect(cached.version).toBe('2026.04.25');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('does not downgrade cached rules during scan --auto-update without a configured source', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-rules-'));
    const sourcePath = path.join(tempDir, 'rules.json');
    const cacheDir = path.join(tempDir, 'cache');
    const projectDir = path.join(tempDir, 'project');

    try {
      await fs.mkdir(projectDir, { recursive: true });
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');
      await fs.writeFile(sourcePath, JSON.stringify({
        ...buildEmbeddedRulePack(),
        version: '2026.04.25',
        generated: '2026-04-25T00:00:00.000Z',
      }, null, 2));
      expect((await runCli(['update-rules', '--source', sourcePath, '--cache-dir', cacheDir])).code).toBe(0);

      const result = await runCli(
        ['scan', projectDir, '--auto-update', '--no-guardvibe', '--no-mcp-scan', '--no-supply-chain'],
        {
          ATTESTLENS_RULE_CACHE_DIR: cacheDir,
          ATTESTLENS_RULE_SOURCE: undefined,
        },
      );
      const cached = JSON.parse(await fs.readFile(path.join(cacheDir, 'latest.json'), 'utf-8'));

      expect(result.code).toBe(0);
      expect(result.stdout).toContain('Rule auto-update skipped');
      expect(cached.version).toBe('2026.04.25');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('prints scanner warnings during scan before the no-findings return', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-rules-'));
    const sourcePath = path.join(tempDir, 'rules.json');
    const cacheDir = path.join(tempDir, 'cache');
    const projectDir = path.join(tempDir, 'project');
    const binDir = path.join(tempDir, 'bin');
    const embedded = buildEmbeddedRulePack();

    try {
      await fs.mkdir(projectDir, { recursive: true });
      await fs.mkdir(binDir, { recursive: true });
      await fs.symlink(process.execPath, path.join(binDir, 'node'));
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');
      await fs.writeFile(sourcePath, JSON.stringify({
        ...embedded,
        version: '2026.04.25',
        generated: '2026-04-25T00:00:00.000Z',
        rules: embedded.rules.map((rule) => rule.id === 'VS-XSS'
          ? { ...rule, pattern: String.raw`changed-active-pattern` }
          : rule),
      }, null, 2));
      expect((await runCli(['update-rules', '--source', sourcePath, '--cache-dir', cacheDir])).code).toBe(0);

      const result = await runCli(
        ['scan', projectDir, '--no-mcp-scan', '--no-supply-chain'],
        {
          ATTESTLENS_RULE_CACHE_DIR: cacheDir,
          ATTESTLENS_RULE_SOURCE: undefined,
          PATH: binDir,
        },
      );
      const output = `${result.stdout}\n${result.stderr}`;

      expect(result.code).toBe(0);
      expect(output).toContain('Scanner warnings');
      expect(output).toContain('RULE_PACK_EXECUTION_FALLBACK');
      expect(output).toContain('Rule pack execution fallback');
      expect(output).toContain('No compliance findings detected');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});

describe('CLI attest command', { timeout: 20000 }, () => {
  it('creates session.json and scan-results.json when starting from a local path target', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-project-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-output-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');

      const result = await executeAttestCommand(projectDir, {
        ...noScannerAttestOptions,
        output: outputDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0 }));

      expect(result.status).toBe('saved');

      const session = await loadQuestionnaireSession(result.sessionPath);
      const snapshot = await loadScanSnapshot<any>(result.scanSnapshotPath);

      expect(session.target.kind).toBe('path');
      expect(session.target.path).toBe(projectDir);
      expect(session.version).toBe('1.3');
      if (session.version !== '1.3') {
        throw new Error('Expected a frozen 1.3 questionnaire session');
      }
      expect(session.questionnaireVersion).toBeTruthy();
      expect(session.principles.length).toBeGreaterThan(0);
      expect(session.sessionQuestions.length).toBeGreaterThan(0);
      expect(session.assessmentMode).toBe('operator_attested');
      expect(session.questionSetHash).toBeTruthy();
      expect(snapshot.target.path).toBe(projectDir);
      expect(snapshot.packValidation).toEqual(expect.objectContaining({
        status: 'internal_validated',
      }));
      expect(snapshot.packValidationTrusted).toBe(true);
      expect(snapshot.packCoverage).toEqual(expect.objectContaining({
        includedPrinciples: expect.arrayContaining(['APP_1', 'APP_11']),
      }));
      await expect(fs.stat(result.sessionPath)).resolves.toBeTruthy();
      await expect(fs.stat(result.scanSnapshotPath)).resolves.toBeTruthy();
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('starts a CCPA questionnaire when attest receives us-ccpa jurisdiction', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-ccpa-project-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-ccpa-output-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');

      const result = await executeAttestCommand(projectDir, {
        ...noScannerAttestOptions,
        output: outputDir,
        format: 'json',
        strict: false,
        jurisdiction: 'us-ccpa',
      }, makePromptRunner({ saveAfter: 0 }));

      expect(result.status).toBe('saved');

      const session = await loadQuestionnaireSession(result.sessionPath);
      const snapshot = await loadScanSnapshot<any>(result.scanSnapshotPath);

      expect(session.version).toBe('1.3');
      if (session.version !== '1.3') {
        throw new Error('Expected a frozen 1.3 questionnaire session');
      }
      expect(snapshot.jurisdiction).toBe('us-ccpa');
      expect(session.questionnaireVersion).toBe(CCPA_QUESTIONNAIRE_VERSION);
      expect(session.principles[0]).toBe('CCPA_100');
      expect(session.sessionQuestions[0]?.id).toBe('Q-CCPA100-001');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('starts a GDPR questionnaire when attest receives eu-gdpr jurisdiction', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-gdpr-project-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-gdpr-output-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');

      const result = await executeAttestCommand(projectDir, {
        ...noScannerAttestOptions,
        output: outputDir,
        format: 'json',
        strict: false,
        jurisdiction: 'eu-gdpr',
      }, makePromptRunner({ saveAfter: 0 }));

      expect(result.status).toBe('saved');

      const session = await loadQuestionnaireSession(result.sessionPath);
      const snapshot = await loadScanSnapshot<any>(result.scanSnapshotPath);

      expect(session.version).toBe('1.3');
      if (session.version !== '1.3') {
        throw new Error('Expected a frozen 1.3 questionnaire session');
      }
      expect(snapshot.jurisdiction).toBe('eu-gdpr');
      expect(session.questionnaireVersion).toBe(GDPR_QUESTIONNAIRE_VERSION);
      expect(session.principles[0]).toBe('GDPR_Art3');
      expect(session.sessionQuestions[0]?.id).toBe('Q-GDPR-Art3-001');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('honours an explicit assessment mode when starting a new session', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-project-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-output-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');

      const result = await executeAttestCommand(projectDir, {
        ...noScannerAttestOptions,
        output: outputDir,
        format: 'json',
        strict: false,
        assessmentMode: 'artifact_only',
      }, makePromptRunner({ assessmentMode: 'operator_attested', saveAfter: 0 }));

      expect(result.status).toBe('saved');

      const session = await loadQuestionnaireSession(result.sessionPath);
      expect(session.version).toBe('1.3');
      if (session.version !== '1.3') {
        throw new Error('Expected a frozen 1.3 questionnaire session');
      }
      expect(session.assessmentMode).toBe('artifact_only');
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('starts from a saved URL scan, resumes, and writes merged report artifacts', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-session-'));
    const scanFile = path.join(tempDir, 'scan.json');

    try {
      await fs.writeFile(scanFile, JSON.stringify({
        targetType: 'url',
        targetUrl: 'https://example.com/',
        target: {
          name: 'example.com',
          url: 'https://example.com/',
        },
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 250,
        metadata: {
          packCoverage: {
            summary: 'Frozen scan metadata coverage.',
            includedPrinciples: ['APP_1'],
            excludedPrinciples: ['APP_2'],
            knownGaps: ['Frozen metadata gap.'],
            evidenceTypes: ['saved scan'],
          },
          packValidation: {
            status: 'draft',
            notes: ['Frozen metadata validation.'],
          },
        },
      }, null, 2));

      const saved = await executeAttestCommand(undefined, {
        fromScan: scanFile,
        output: tempDir,
        format: 'json,html,markdown,pdf',
        strict: false,
      }, makePromptRunner({ saveAfter: 1 }));

      expect(saved.status).toBe('saved');

      const savedSession = await loadQuestionnaireSession(saved.sessionPath);
      const frozenSnapshot = await loadScanSnapshot<any>(saved.scanSnapshotPath);
      expect(savedSession.answers).toHaveLength(1);
      expect(frozenSnapshot.target.url).toBe('https://example.com/');
      expect(frozenSnapshot.packValidation.status).toBe('draft');
      expect(frozenSnapshot.packCoverage.summary).toBe('Frozen scan metadata coverage.');

      const completed = await executeAttestCommand(undefined, {
        resume: saved.sessionPath,
        output: tempDir,
        format: 'json,html,markdown,pdf',
        strict: false,
      }, makePromptRunner({ noteQuestionId: 'Q-APP1-001' }));

      expect(completed.status).toBe('completed');
      if (completed.status !== 'completed') {
        throw new Error('Expected attestation run to complete');
      }
      const reportPaths = completed.reportPaths || [];
      expect(reportPaths).toHaveLength(4);
      const jsonReportPath = reportPaths.find((report) => report.path.endsWith('.json'))?.path;
      expect(jsonReportPath).toBeTruthy();
      const report = JSON.parse(await fs.readFile(jsonReportPath!, 'utf-8'));
      expect(report.appControls.filter((control: any) => control.status === 'unknown')).toHaveLength(0);
      expect(report.metadata.packValidation.status).toBe('draft');
      expect(report.metadata.packCoverage.summary).toBe('Frozen scan metadata coverage.');

      const completedSession = await loadQuestionnaireSession(saved.sessionPath);
      expect(completedSession.status).toBe('completed');
      expect(completedSession.answers.length).toBeGreaterThan(1);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('upgrades a legacy 1.0 session on resume and keeps the frozen legacy question set', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-legacy-'));
    const sessionDir = path.join(tempDir, 'attest', 'legacy-app', 'session-legacy');
    const sessionPath = path.join(sessionDir, 'session.json');
    const snapshotPath = path.join(sessionDir, 'scan-results.json');

    try {
      await fs.mkdir(sessionDir, { recursive: true });
      await fs.writeFile(snapshotPath, JSON.stringify({
        targetType: 'path',
        targetPath: '/tmp/legacy-app',
        target: {
          name: 'Legacy App',
          path: '/tmp/legacy-app',
        },
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
      }, null, 2));

      await fs.writeFile(sessionPath, JSON.stringify({
        id: 'session-legacy',
        version: '1.0',
        status: 'in_progress',
        target: {
          kind: 'path',
          name: 'Legacy App',
          path: '/tmp/legacy-app',
        },
        startedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        strictMode: false,
        scanSnapshotPath: snapshotPath,
        findingsHash: buildFindingsHash([]),
        answers: [],
        principleResults: [
          {
            principle: 'APP_5',
            status: 'unknown',
            confidence: 0,
            rationale: 'Awaiting required questionnaire answers: Q-APP5-001',
            answeredQuestionIds: [],
          },
        ],
        currentQuestionId: 'Q-APP5-001',
      }, null, 2));

      const saved = await executeAttestCommand(undefined, {
        resume: sessionPath,
        output: tempDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0 }));

      expect(saved.status).toBe('saved');

      const upgraded = await loadQuestionnaireSession(sessionPath);
      expect(upgraded.version).toBe('1.3');
      if (upgraded.version !== '1.3') {
        throw new Error('Expected upgraded 1.3 session');
      }

      expect(upgraded.sessionQuestions.map((question) => question.id)).toEqual(
        LEGACY_QUESTION_BANK_V1
          .filter((question) => question.appPrinciple === 'APP_5')
          .map((question) => question.id),
      );
      expect(upgraded.sessionQuestions.some((question) => question.id === 'Q-APP5-003')).toBe(false);
      expect(upgraded.assessmentMode).toBe('operator_attested');
      expect(upgraded.questionSetHash).toBeTruthy();
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('honours an explicit assessment mode when upgrading a pre-1.3 session', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-legacy-'));
    const sessionDir = path.join(tempDir, 'attest', 'legacy-app', 'session-legacy');
    const sessionPath = path.join(sessionDir, 'session.json');
    const snapshotPath = path.join(sessionDir, 'scan-results.json');

    try {
      await fs.mkdir(sessionDir, { recursive: true });
      await fs.writeFile(snapshotPath, JSON.stringify({
        targetType: 'path',
        targetPath: '/tmp/legacy-app',
        target: {
          name: 'Legacy App',
          path: '/tmp/legacy-app',
        },
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
      }, null, 2));

      await fs.writeFile(sessionPath, JSON.stringify({
        id: 'session-legacy',
        version: '1.0',
        status: 'in_progress',
        target: {
          kind: 'path',
          name: 'Legacy App',
          path: '/tmp/legacy-app',
        },
        startedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        strictMode: false,
        scanSnapshotPath: snapshotPath,
        findingsHash: buildFindingsHash([]),
        answers: [],
        principleResults: [
          {
            principle: 'APP_5',
            status: 'unknown',
            confidence: 0,
            rationale: 'Awaiting required questionnaire answers: Q-APP5-001',
            answeredQuestionIds: [],
          },
        ],
        currentQuestionId: 'Q-APP5-001',
      }, null, 2));

      const saved = await executeAttestCommand(undefined, {
        resume: sessionPath,
        output: tempDir,
        format: 'json',
        strict: false,
        assessmentMode: 'codebase_only',
      }, makePromptRunner({ assessmentMode: 'operator_attested', saveAfter: 0 }));

      expect(saved.status).toBe('saved');

      const upgraded = await loadQuestionnaireSession(sessionPath);
      expect(upgraded.version).toBe('1.3');
      if (upgraded.version !== '1.3') {
        throw new Error('Expected upgraded 1.3 session');
      }
      expect(upgraded.assessmentMode).toBe('codebase_only');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('fails closed when a transitional 1.1 session has a tampered frozen question set', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-tampered-'));
    const sessionDir = path.join(tempDir, 'attest', 'example-app', 'session-tampered');
    const sessionPath = path.join(sessionDir, 'session.json');
    const snapshotPath = path.join(sessionDir, 'scan-results.json');

    try {
      await fs.mkdir(sessionDir, { recursive: true });
      await fs.writeFile(snapshotPath, JSON.stringify({
        targetType: 'path',
        targetPath: '/tmp/example-app',
        target: {
          name: 'Example App',
          path: '/tmp/example-app',
        },
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 10,
      }, null, 2));

      await fs.writeFile(sessionPath, JSON.stringify({
        id: 'session-tampered',
        version: '1.1',
        questionnaireVersion: QUESTIONNAIRE_VERSION,
        status: 'in_progress',
        target: {
          kind: 'path',
          name: 'Example App',
          path: '/tmp/example-app',
        },
        startedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        strictMode: false,
        scanSnapshotPath: snapshotPath,
        findingsHash: '4f53cda18c2baa0c0354bb5f9a3ecbe5',
        principles: ['APP_1'],
        sessionQuestions: [
          LEGACY_QUESTION_BANK_V1[0],
        ],
        answers: [],
        principleResults: [
          {
            principle: 'APP_1',
            status: 'unknown',
            confidence: 0,
            rationale: 'Awaiting required questionnaire answers: Q-APP1-001',
            answeredQuestionIds: [],
          },
        ],
        currentQuestionId: 'Q-APP1-001',
      }, null, 2));

      await expect(executeAttestCommand(undefined, {
        resume: sessionPath,
        output: tempDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0 }))).rejects.toThrow(/integrity check failed/i);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('does not rewrite completed sessions when resume is rejected as already finished', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-completed-'));
    const sessionDir = path.join(tempDir, 'attest', 'example-app', 'session-complete');
    const sessionPath = path.join(sessionDir, 'session.json');

    try {
      await fs.mkdir(sessionDir, { recursive: true });
      const sessionPayload = {
        id: 'session-complete',
        version: '1.3',
        questionnaireVersion: QUESTIONNAIRE_VERSION,
        status: 'completed',
        target: {
          kind: 'path',
          name: 'Example App',
          path: '/tmp/example-app',
        },
        startedAt: new Date().toISOString(),
        updatedAt: '2026-04-20T10:00:00.000Z',
        completedAt: '2026-04-20T10:10:00.000Z',
        strictMode: false,
        scanSnapshotPath: path.join(sessionDir, 'scan-results.json'),
        findingsHash: '4f53cda18c2baa0c0354bb5f9a3ecbe5',
        principles: ['APP_1'],
        sessionQuestions: [],
        questionSetHash: 'frozen-hash',
        assessmentMode: 'operator_attested',
        answers: [],
        principleResults: [],
      };
      await fs.writeFile(sessionPath, JSON.stringify(sessionPayload, null, 2));
      const before = await fs.readFile(sessionPath, 'utf-8');

      await expect(executeAttestCommand(undefined, {
        resume: sessionPath,
        output: tempDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0 }))).rejects.toThrow(/already completed/i);

      const after = await fs.readFile(sessionPath, 'utf-8');
      expect(after).toBe(before);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it('rejects --assessment-mode when resuming a current session with a mismatched frozen basis', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-project-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-output-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');

      const initial = await executeAttestCommand(projectDir, {
        ...noScannerAttestOptions,
        output: outputDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0, assessmentMode: 'operator_attested' }));

      await expect(executeAttestCommand(undefined, {
        resume: initial.sessionPath,
        output: outputDir,
        format: 'json',
        strict: false,
        assessmentMode: 'artifact_only',
      }, makePromptRunner({ saveAfter: 0 }))).rejects.toThrow(/already frozen for this session/i);
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });
});
