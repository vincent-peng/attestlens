import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import YAML from 'yaml';

const execFileAsync = promisify(execFile);

export interface ValidationTarget {
  id: string;
  name: string;
  url: string;
  expectedSurface: string;
}

export interface ValidationCorpus {
  targets: ValidationTarget[];
}

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type ValidationCommand = 'scan' | 'audit';
export type ValidationRunner = (
  command: ValidationCommand,
  args: string[],
  cwd: string,
) => Promise<CommandResult>;

export interface ValidationTargetResult {
  target: ValidationTarget;
  targetDir: string;
  status: 'passed' | 'failed';
  findingsCount: number;
  grade?: string;
  risk?: string;
  scanExitCode: number;
  auditExitCode?: number;
  notes: string;
  artifactPaths: string[];
}

export interface ValidationCorpusResult {
  runDate: string;
  commitSha: string;
  outputRoot: string;
  summaryPath: string;
  results: ValidationTargetResult[];
}

export interface RunValidationOptions {
  repoRoot: string;
  manifestPath: string;
  outputRoot: string;
  runDate?: string;
  commitSha?: string;
  runner?: ValidationRunner;
}

export async function loadValidationCorpus(manifestPath: string): Promise<ValidationCorpus> {
  const raw = await fs.readFile(manifestPath, 'utf-8');
  const parsed = YAML.parse(raw) as ValidationCorpus;

  if (!parsed || !Array.isArray(parsed.targets)) {
    throw new Error('Validation corpus manifest must define a targets array.');
  }

  for (const target of parsed.targets) {
    if (!target.id || !target.name || !target.url || !target.expectedSurface) {
      throw new Error(`Validation target is missing required fields: ${JSON.stringify(target)}`);
    }
  }

  return parsed;
}

export function sanitizeValidationTargetId(targetId: string): string {
  return targetId
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    || 'target';
}

export function buildValidationTargetDir(outputRoot: string, runDate: string, targetId: string): string {
  return path.join(outputRoot, runDate, sanitizeValidationTargetId(targetId));
}

export function renderValidationSummary(
  runDate: string,
  commitSha: string,
  results: ValidationTargetResult[],
): string {
  const lines = [
    '# Validation Corpus Summary',
    '',
    `- Run date: ${runDate}`,
    `- Commit: ${commitSha}`,
    `- Targets: ${results.length}`,
    '',
    '| Target | Status | Findings | Grade | Risk | Notes |',
    '|---|---:|---:|---:|---:|---|',
  ];

  for (const result of results) {
    lines.push(
      `| ${result.target.name} | ${result.status.toUpperCase()} | ${result.findingsCount} | ${result.grade || '-'} | ${result.risk || '-'} | ${result.notes} |`,
    );
  }

  return `${lines.join('\n')}\n`;
}

export async function runValidationCorpus(options: RunValidationOptions): Promise<ValidationCorpusResult> {
  const repoRoot = path.resolve(options.repoRoot);
  const manifest = await loadValidationCorpus(path.resolve(options.manifestPath));
  const runDate = options.runDate || new Date().toISOString().slice(0, 10);
  const outputRoot = path.resolve(options.outputRoot);
  const commitSha = options.commitSha || await getCommitSha(repoRoot);
  const runner = options.runner || createCliRunner(repoRoot);

  const runRoot = path.join(outputRoot, runDate);
  await fs.mkdir(runRoot, { recursive: true });

  const results: ValidationTargetResult[] = [];

  for (const target of manifest.targets) {
    results.push(await runValidationTarget(target, {
      repoRoot,
      runDate,
      outputRoot,
      runner,
    }));
  }

  const summary = renderValidationSummary(runDate, commitSha, results);
  const summaryPath = path.join(runRoot, 'SUMMARY.md');
  await fs.writeFile(summaryPath, summary, 'utf-8');

  return {
    runDate,
    commitSha,
    outputRoot: runRoot,
    summaryPath,
    results,
  };
}

async function runValidationTarget(
  target: ValidationTarget,
  options: {
    repoRoot: string;
    runDate: string;
    outputRoot: string;
    runner: ValidationRunner;
  },
): Promise<ValidationTargetResult> {
  const targetDir = buildValidationTargetDir(options.outputRoot, options.runDate, target.id);
  await fs.mkdir(targetDir, { recursive: true });

  const scanResult = await options.runner('scan', [target.url], options.repoRoot);
  await writeCommandLogs(targetDir, 'scan', scanResult);

  if (scanResult.code !== 0) {
    return {
      target,
      targetDir,
      status: 'failed',
      findingsCount: 0,
      scanExitCode: scanResult.code,
      notes: 'scan command failed before audit could run',
      artifactPaths: listLogArtifacts(targetDir),
    };
  }

  const auditArgs = [
    target.url,
    '-n',
    target.name,
    '-f',
    'json,markdown,pdf',
    '-o',
    targetDir,
  ];
  const auditResult = await options.runner('audit', auditArgs, options.repoRoot);
  await writeCommandLogs(targetDir, 'audit', auditResult);

  const artifactPaths = await listArtifacts(targetDir);
  const reportJsonPath = artifactPaths.find((artifactPath) => artifactPath.endsWith('.json'));

  if (!reportJsonPath || ![0, 1, 2].includes(auditResult.code)) {
    return {
      target,
      targetDir,
      status: 'failed',
      findingsCount: 0,
      scanExitCode: scanResult.code,
      auditExitCode: auditResult.code,
      notes: reportJsonPath
        ? 'audit exited unexpectedly'
        : 'audit did not produce a JSON report artifact',
      artifactPaths,
    };
  }

  const report = JSON.parse(await fs.readFile(reportJsonPath, 'utf-8')) as {
    findings?: unknown[];
    overallGrade?: string;
    riskLevel?: string;
  };

  return {
    target,
    targetDir,
    status: 'passed',
    findingsCount: Array.isArray(report.findings) ? report.findings.length : 0,
    grade: report.overallGrade,
    risk: report.riskLevel,
    scanExitCode: scanResult.code,
    auditExitCode: auditResult.code,
    notes: target.expectedSurface,
    artifactPaths,
  };
}

async function writeCommandLogs(
  targetDir: string,
  command: ValidationCommand,
  result: CommandResult,
): Promise<void> {
  await fs.writeFile(path.join(targetDir, `${command}.stdout.log`), result.stdout, 'utf-8');
  await fs.writeFile(path.join(targetDir, `${command}.stderr.log`), result.stderr, 'utf-8');
}

async function listArtifacts(targetDir: string): Promise<string[]> {
  const entries = await fs.readdir(targetDir);
  return entries
    .map((entry) => path.join(targetDir, entry))
    .sort();
}

function listLogArtifacts(targetDir: string): string[] {
  return [
    path.join(targetDir, 'scan.stdout.log'),
    path.join(targetDir, 'scan.stderr.log'),
  ];
}

export function createCliRunner(repoRoot: string): ValidationRunner {
  const tsxBin = path.join(repoRoot, 'node_modules', '.bin', 'tsx');
  const cliEntry = path.join(repoRoot, 'src', 'cli', 'index.ts');

  return async (command, args, cwd) => {
    try {
      const { stdout, stderr } = await execFileAsync(tsxBin, [cliEntry, command, ...args], { cwd });
      return { code: 0, stdout, stderr };
    } catch (error: any) {
      return {
        code: error.code ?? 1,
        stdout: error.stdout ?? '',
        stderr: error.stderr ?? '',
      };
    }
  };
}

export async function getCommitSha(repoRoot: string): Promise<string> {
  const { stdout } = await execFileAsync('git', ['rev-parse', '--short', 'HEAD'], { cwd: repoRoot });
  return stdout.trim();
}

export async function runValidationCorpusCli(argv = process.argv.slice(2)): Promise<ValidationCorpusResult> {
  const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  const manifestPath = argv[0]
    ? path.resolve(argv[0])
    : path.join(repoRoot, 'docs', 'validation', 'corpus.yaml');
  const outputRoot = path.join(repoRoot, 'attestlens-reports', 'validation');

  const result = await runValidationCorpus({
    repoRoot,
    manifestPath,
    outputRoot,
  });

  process.stdout.write(
    `Validation corpus completed for ${result.results.length} targets.\nSummary: ${result.summaryPath}\n`,
  );
  return result;
}
