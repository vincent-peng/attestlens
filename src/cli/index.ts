#!/usr/bin/env node
/**
 * AttestLens — CLI Entry Point
 * 
 * Usage:
 *   attestlens scan <path>     Scan a project directory
 *   attestlens audit <path>    Scan + generate compliance report
 *   attestlens report <path>   Generate report from existing scan data
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { ScannerOrchestrator, type ScannerOrchestratorOptions } from '../scanner/orchestrator.js';
import { mapAllFindings } from '../mapping/engine.js';
import {
  buildComplianceReport,
  generateHTMLReport,
  generateJSONReport,
  generateMarkdownReport,
  generatePDFReport,
} from '../report/generator.js';
import { updateRuleCache } from '../scanner/rules/index.js';
import {
  buildAttestationScanSnapshot,
  buildFrozenSessionQuestions,
  createInteractivePromptRunner,
  deriveQuestionnairePrinciples,
  initializeAttestationSession,
  loadQuestionnaireSession,
  loadScanSnapshot,
  prepareQuestionnaireSessionForResume,
  runAttestationSession,
  saveQuestionnaireSession,
} from '../questionnaire/index.js';
import { RuleFreshness } from '../schema/index.js';
import type {
  AssessmentMode,
  AttestLensFinding,
  QuestionnaireSession,
  RuleFreshness as RuleFreshnessMetadata,
} from '../schema/index.js';
import type { ReportFormat, ReportOptions } from '../report/generator.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import type { AttestationPromptRunner, AttestationScanSnapshot, SessionTarget } from '../questionnaire/index.js';
import { getHostnameFromTargetUrl } from '../utils/target.js';

const program = new Command();

program
  .name('attestlens')
  .description('AI Compliance Scanner & Privacy Act Attestation Tool')
  .version('0.2.0');

// ─── Scan Command ─────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan a project directory or URL for privacy compliance findings')
  .argument('<target>', 'Path to project directory or URL (https://...)')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown,pdf)', 'json,html')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .option('--include-typosquat', 'Enable experimental typosquatting detection (VS-SC-004)')
  .option('--external-enrichment', 'Enable external OSV.dev and npm registry dependency enrichment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--auto-update', 'Refresh the cached rule pack from ATTESTLENS_RULE_SOURCE before scanning')
  .action(async (targetInput: string, options: any) => {
    console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Scanner\n'));

    try {
      const target = await resolveCliTarget(targetInput, options.name);
      await maybeAutoUpdateRules(options);
      const orchestrator = createOrchestrator(target.kind, options);
      const spinner = ora(target.kind === 'url' ? `Scanning URL: ${target.value}` : 'Scanning project...').start();
      const startTime = Date.now();

      const result = await orchestrator.scan(target.value);
      const urlScanFailure = target.kind === 'url' ? getUrlScanFailureMessage(result) : null;
      if (urlScanFailure) {
        spinner.fail('URL scan failed');
        throw new Error(urlScanFailure);
      }
      const duration = Date.now() - startTime;
      spinner.succeed(`${target.kind === 'url' ? 'URL scan' : 'Scan'} complete in ${(duration / 1000).toFixed(1)}s`);
      displayRuleFreshness(result.ruleFreshness);
      displayScannerWarnings(result.errors);

      const findings = result.findings;
      if (findings.length === 0) {
        console.log(chalk.green('\n✅ No compliance findings detected.'));
        console.log(chalk.gray('   Run `attestlens audit` for a full APP control assessment.'));
        return;
      }

      console.log(chalk.yellow(`\n⚠ Found ${findings.length} finding${findings.length > 1 ? 's' : ''}:\n`));
      displayFindings(findings);

      // Map to APP
      const { controls: appControls } = mapAllFindings(findings);
      const affectedPrinciples = appControls
        .filter(c => c.status !== 'unknown' || c.findings.length > 0)
        .map(c => c.principle);
      console.log(chalk.cyan(`\n📋 Affected APP Principles: ${affectedPrinciples.join(', ')}`));
      console.log(chalk.gray(`   Run \`attestlens audit ${target.rawInput}\` for a full compliance report.`));

    } catch (error: any) {
      const label = isUrlTarget(targetInput) ? 'URL scan failed' : 'Scan failed';
      console.error(chalk.red(`\n${label.replace(/^./, s => s.toUpperCase())}`));
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Audit Command ────────────────────────────────────────────────────────────

program
  .command('audit')
  .description('Full compliance audit — scan + generate APP/NDB report')
  .argument('<target>', 'Path to project directory or URL (https://...)')
  .option('-n, --name <name>', 'Project name', '')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown,pdf)', 'html,json')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .option('--include-typosquat', 'Enable experimental typosquatting detection (VS-SC-004)')
  .option('--external-enrichment', 'Enable external OSV.dev and npm registry dependency enrichment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--auto-update', 'Refresh the cached rule pack from ATTESTLENS_RULE_SOURCE before scanning')
  .action(async (targetInput: string, options: any) => {
    console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Audit\n'));

    try {
      const target = await resolveCliTarget(targetInput, options.name);
      const projectName = target.name;
      await maybeAutoUpdateRules(options);
      const orchestrator = createOrchestrator(target.kind, options);
      const spinner = ora(`Running compliance scan for ${target.kind === 'url' ? 'URL' : 'project'}...`).start();
      const startTime = Date.now();

      const scanResult = await orchestrator.scan(target.value);
      const urlScanFailure = target.kind === 'url' ? getUrlScanFailureMessage(scanResult) : null;
      if (urlScanFailure) {
        spinner.fail('Audit failed');
        throw new Error(urlScanFailure);
      }
      const duration = Date.now() - startTime;

      const reportFormats = parseReportFormats(options.format);
      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath: target.kind === 'path' ? target.value : undefined,
        targetUrl: target.kind === 'url' ? target.value : undefined,
        formats: reportFormats,
        outputDir: path.resolve(options.output),
        strictMode: options.strict,
        ruleFreshness: scanResult.ruleFreshness,
      };

      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map(r => [r.source, r.version])
      );

      spinner.succeed(`Audit complete in ${(duration / 1000).toFixed(1)}s`);

      // Display summary
      console.log('');
      console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
      console.log(chalk.bold(`  Grade: ${getGradeDisplay(report.overallGrade, report.overallScore)}`));
      console.log(chalk.bold(`  Risk:  ${getRiskDisplay(report.riskLevel)}`));
      if (report.breachReadiness) {
        console.log(chalk.bold(`  Breach Readiness: ${report.breachReadiness.level.toUpperCase()} (${report.breachReadiness.score}/100, ${Math.round(report.breachReadiness.confidence * 100)}% confidence)`));
      }
      console.log(chalk.bold(`  Rule Pack: ${formatRuleFreshnessForCli(scanResult.ruleFreshness)}`));
      console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
      console.log('');

      // APP Control summary
      for (const control of report.appControls) {
        const statusIcon = control.status === 'pass' ? '✅' : control.status === 'fail' ? '❌' : '⚠️';
        console.log(`  ${statusIcon} ${control.principle} — ${control.shortName}: ${control.status.toUpperCase()} (${control.score}/100)`);
      }

      console.log('');

      // Write output files
      for (const output of await writeReportFiles(report, reportOptions)) {
        console.log(chalk.green(`  📄 ${output.label}: ${output.path}`));
      }

      displayScannerWarnings(scanResult.errors);

      console.log(chalk.gray(`\n  ${report.disclaimer}`));

      // Exit with non-zero if critical findings
      const criticalCount = report.findings.filter(f => f.severity === 'critical').length;
      if (criticalCount > 0) {
        process.exit(2);
      }
      const failCount = report.appControls.filter(c => c.status === 'fail').length;
      if (failCount > 0) {
        process.exit(1);
      }

    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Attest Command ───────────────────────────────────────────────────────────

program
  .command('attest')
  .description('Start, resume, or complete a questionnaire-backed attestation session')
  .argument('[target]', 'Path to project directory or URL (https://...)')
  .option('--from-scan <file>', 'Create a new attestation session from an existing scan JSON')
  .option('--resume <file>', 'Resume an existing attestation session JSON')
  .option('-n, --name <name>', 'Target name', '')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown,pdf)', 'html,json,markdown,pdf')
  .option('--assessment-mode <mode>', 'Frozen assessment basis (artifact_only, codebase_only, operator_attested)')
  .option('--strict', 'Treat unresolved controls as FAIL after questionnaire merge')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .option('--include-typosquat', 'Enable experimental typosquatting detection (VS-SC-004)')
  .option('--external-enrichment', 'Enable external OSV.dev and npm registry dependency enrichment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--auto-update', 'Refresh the cached rule pack from ATTESTLENS_RULE_SOURCE before scanning')
  .action(async (targetInput: string | undefined, options: any) => {
    console.log(chalk.bold.cyan('\n📝 AttestLens — Privacy Act Attestation\n'));

    try {
      await executeAttestCommand(targetInput, options);
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Report Command ───────────────────────────────────────────────────────────

program
  .command('report')
  .description('Generate report from existing scan data (JSON)')
  .argument('<file>', 'Path to scan results JSON file')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats', 'html,json,markdown,pdf')
  .option('-n, --name <name>', 'Project name', '')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .action(async (filePath: string, options: any) => {
    const resolvedPath = path.resolve(filePath);
    
    try {
      const data = await fs.readFile(resolvedPath, 'utf-8');
      const scanData = JSON.parse(data);
      
      const reportFormats = parseReportFormats(options.format);
      const reportTarget = resolveReportTarget(scanData, resolvedPath, options.name);

      const reportOptions: ReportOptions = {
        targetName: reportTarget.targetName,
        targetPath: reportTarget.targetPath,
        targetUrl: reportTarget.targetUrl,
        formats: reportFormats,
        outputDir: path.resolve(options.output),
        strictMode: options.strict,
        ruleFreshness: extractRuleFreshness(scanData),
      };

      const report = buildComplianceReport(scanData.findings || scanData, reportOptions, 0);
      await writeReportFiles(report, reportOptions);

      console.log(chalk.green('✅ Report generated successfully.'));
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Rule Update Command ─────────────────────────────────────────────────────

program
  .command('update-rules')
  .description('Refresh the local AttestLens rule pack cache')
  .option('--source <url-or-path>', 'Rule pack JSON source. Defaults to ATTESTLENS_RULE_SOURCE; no source preserves or seeds the local cache')
  .option('--cache-dir <dir>', 'Rule pack cache directory')
  .action(async (options: any) => {
    const spinner = ora('Updating rule pack...').start();

    try {
      const loaded = await updateRuleCache({
        source: options.source || process.env.ATTESTLENS_RULE_SOURCE,
        cacheDir: options.cacheDir ? path.resolve(options.cacheDir) : undefined,
      });

      spinner.succeed(`Rule pack ${loaded.freshness.version} cached`);
      console.log(chalk.gray(`  Rules: ${loaded.freshness.ruleCount}`));
      console.log(chalk.gray(`  Source: ${loaded.freshness.source}`));
      if (loaded.cachePath) {
        console.log(chalk.gray(`  Cache: ${loaded.cachePath}`));
      }
    } catch (error: any) {
      spinner.fail('Rule update failed');
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Helpers ──────────────────────────────────────────────────────────────────

type CliTarget =
  | { kind: 'path'; rawInput: string; value: string; name: string }
  | { kind: 'url'; rawInput: string; value: string; name: string };

function isUrlTarget(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

async function resolveCliTarget(targetInput: string, explicitName?: string): Promise<CliTarget> {
  if (isUrlTarget(targetInput)) {
    const url = new URL(targetInput);
    return {
      kind: 'url',
      rawInput: targetInput,
      value: url.toString(),
      name: explicitName || url.hostname,
    };
  }

  const resolvedPath = path.resolve(targetInput);
  const stat = await fs.stat(resolvedPath).catch(() => null);
  if (!stat) {
    throw new Error(`${resolvedPath} does not exist`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`${resolvedPath} is not a directory`);
  }

  return {
    kind: 'path',
    rawInput: targetInput,
    value: resolvedPath,
    name: explicitName || path.basename(resolvedPath),
  };
}

async function maybeAutoUpdateRules(options: any): Promise<void> {
  if (!options.autoUpdate) {
    return;
  }

  const source = process.env.ATTESTLENS_RULE_SOURCE;
  if (!source) {
    console.log(chalk.gray('Rule auto-update skipped: ATTESTLENS_RULE_SOURCE is not set. Using cached or embedded rules.'));
    return;
  }

  const spinner = ora('Refreshing rule pack...').start();
  try {
    const loaded = await updateRuleCache({
      source,
    });
    spinner.succeed(`Rule pack ready: ${formatRuleFreshnessForCli(loaded.freshness)}`);
  } catch (error: any) {
    spinner.warn(`Rule update skipped: ${error.message}. Continuing with cached or embedded rules.`);
  }
}

function extractRuleFreshness(scanData: Record<string, any>): RuleFreshnessMetadata | undefined {
  const raw = scanData.ruleFreshness || scanData.metadata?.ruleFreshness;
  if (!raw) {
    return undefined;
  }

  return RuleFreshness.parse(raw);
}

function displayRuleFreshness(ruleFreshness: RuleFreshnessMetadata): void {
  console.log(chalk.gray(`Rules: ${formatRuleFreshnessForCli(ruleFreshness)}`));
}

function displayScannerWarnings(errors: ScannerError[]): void {
  if (errors.length === 0) {
    return;
  }

  console.log(chalk.yellow('\n⚠ Scanner warnings:'));
  for (const error of errors) {
    const code = error.code ? ` [${error.code}]` : '';
    console.log(chalk.yellow(`  ${error.source}${code}: ${error.message}`));
  }
}

function formatRuleFreshnessForCli(ruleFreshness: RuleFreshnessMetadata): string {
  const age = ruleFreshness.ageDays === 1 ? '1 day old' : `${ruleFreshness.ageDays} days old`;
  const state = ruleFreshness.stale ? 'stale' : 'fresh';
  return `${ruleFreshness.version} (${ruleFreshness.source}, ${ruleFreshness.ruleCount} rules, ${age}, ${state})`;
}

export function buildScannerOrchestratorOptions(options: any): ScannerOrchestratorOptions {
  const externalEnrichment = options.externalEnrichment === true;
  const scannerTimeoutMs = parseScannerTimeoutOption(options.scannerTimeout);
  return {
    ...(scannerTimeoutMs !== undefined ? { adapterTimeoutMs: scannerTimeoutMs } : {}),
    supplyChain: {
      typosquat: { enabled: options.includeTyposquat === true },
      osv: { enabled: externalEnrichment },
      registry: { enabled: externalEnrichment },
    },
  };
}

function parseScannerTimeoutOption(rawValue: unknown): number | undefined {
  if (rawValue === undefined || rawValue === null || rawValue === '') {
    return undefined;
  }

  if (typeof rawValue === 'string' && !/^\d+$/.test(rawValue.trim())) {
    throw new Error(`Unsupported scanner timeout: ${rawValue}. Provide a positive integer number of milliseconds.`);
  }
  const value = typeof rawValue === 'number' ? rawValue : Number.parseInt(String(rawValue), 10);
  if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0) {
    throw new Error(`Unsupported scanner timeout: ${rawValue}. Provide a positive integer number of milliseconds.`);
  }
  return value;
}

function createOrchestrator(targetKind: CliTarget['kind'], options: any): ScannerOrchestrator {
  const orchestrator = new ScannerOrchestrator(buildScannerOrchestratorOptions(options));

  if (targetKind === 'url') {
    orchestrator.disable('guardvibe');
    orchestrator.disable('mcp-scan');
    orchestrator.disable('supply-chain');
    return orchestrator;
  }

  if (options.guardvibe === false) orchestrator.disable('guardvibe');
  if (options.mcpScan === false) orchestrator.disable('mcp-scan');
  if (options.supplyChain === false) orchestrator.disable('supply-chain');
  return orchestrator;
}

export interface AttestCommandResult {
  status: 'saved' | 'completed';
  sessionPath: string;
  scanSnapshotPath: string;
  outputDir: string;
  reportPaths?: Array<{ label: string; path: string }>;
}

function countDefined(values: Array<unknown>): number {
  return values.filter((value) => value !== undefined && value !== null && value !== '').length;
}

function toSessionTarget(target: CliTarget): SessionTarget {
  return target.kind === 'url'
    ? { kind: 'url', name: target.name, url: target.value }
    : { kind: 'path', name: target.name, path: target.value };
}

function buildSessionTargetFromReportTarget(reportTarget: {
  targetName: string;
  targetPath?: string;
  targetUrl?: string;
}): SessionTarget {
  if (reportTarget.targetUrl) {
    return {
      kind: 'url',
      name: reportTarget.targetName,
      url: reportTarget.targetUrl,
    };
  }

  return {
    kind: 'path',
    name: reportTarget.targetName,
    path: reportTarget.targetPath || reportTarget.targetName,
  };
}

function normalizeScanSnapshot(
  scanData: Record<string, any> | AttestLensFinding[],
  resolvedPath: string,
  explicitName?: string,
): { snapshot: AttestationScanSnapshot; target: SessionTarget } {
  const normalizedScanData = Array.isArray(scanData)
    ? { findings: scanData }
    : scanData;

  const reportTarget = resolveReportTarget(normalizedScanData, resolvedPath, explicitName);
  const target = buildSessionTargetFromReportTarget(reportTarget);
  const findings = Array.isArray(normalizedScanData.findings) ? normalizedScanData.findings : [];

  return {
    target,
    snapshot: {
      targetType: target.kind,
      target: {
        name: target.name,
        path: target.kind === 'path' ? target.path : undefined,
        url: target.kind === 'url' ? target.url : undefined,
      },
      targetPath: target.kind === 'path' ? target.path : undefined,
      targetUrl: target.kind === 'url' ? target.url : undefined,
      findings,
      results: Array.isArray(normalizedScanData.results) ? normalizedScanData.results : [],
      errors: Array.isArray(normalizedScanData.errors) ? normalizedScanData.errors : [],
      totalDurationMs: typeof normalizedScanData.totalDurationMs === 'number'
        ? normalizedScanData.totalDurationMs
        : typeof normalizedScanData.metadata?.scanDurationMs === 'number'
          ? normalizedScanData.metadata.scanDurationMs
          : 0,
      ruleFreshness: extractRuleFreshness(normalizedScanData),
    },
  };
}

function getReportOptionsForSession(
  sessionTarget: SessionTarget,
  formats: ReportFormat[],
  outputDir: string,
  strictMode: boolean,
  ruleFreshness?: RuleFreshnessMetadata,
): ReportOptions {
  return {
    targetName: sessionTarget.name,
    targetPath: sessionTarget.kind === 'path' ? sessionTarget.path : undefined,
    targetUrl: sessionTarget.kind === 'url' ? sessionTarget.url : undefined,
    formats,
    outputDir,
    strictMode,
    ruleFreshness,
  };
}

function getScannerVersions(snapshot: AttestationScanSnapshot): Record<string, string> {
  return Object.fromEntries(snapshot.results.map((result) => [result.source, result.version]));
}

function summarizeQuestionnaireResults(report: ReturnType<typeof buildComplianceReport>): {
  resolved: number;
  unresolved: string[];
} {
  const results = report.questionnaireResults || [];
  return {
    resolved: results.filter((result) => result.status !== 'unknown').length,
    unresolved: results
      .filter((result) => result.status === 'unknown')
      .map((result) => result.principle),
  };
}

export async function executeAttestCommand(
  targetInput: string | undefined,
  options: any,
  promptRunner?: AttestationPromptRunner,
): Promise<AttestCommandResult> {
  const selectedSources = countDefined([targetInput, options.fromScan, options.resume]);
  if (selectedSources !== 1) {
    throw new Error('Choose exactly one start mode: <target>, --from-scan <file>, or --resume <session.json>.');
  }

  const runner = promptRunner || createInteractivePromptRunner();
  const outputRoot = path.resolve(options.output);
  const reportFormats = parseReportFormats(options.format);
  const requestedAssessmentMode = parseAssessmentModeOption(options.assessmentMode);

  let sessionPath: string;
  let scanSnapshotPath: string;
  let sessionTarget: SessionTarget;
  let snapshot: AttestationScanSnapshot;
  let session;

  if (options.resume) {
    sessionPath = path.resolve(options.resume);
    const loadedSession = await loadQuestionnaireSession(sessionPath);
    if (loadedSession.status === 'completed') {
      throw new Error(`Attestation session is already completed: ${sessionPath}`);
    }

    snapshot = await loadScanSnapshot<AttestationScanSnapshot>(loadedSession.scanSnapshotPath);
    const expectedPrinciples = deriveQuestionnairePrinciples(snapshot.findings);
    const expectedQuestions = buildFrozenSessionQuestions(expectedPrinciples);
    const upgradeAssessmentMode = loadedSession.version === '1.3'
      ? undefined
      : await resolveAssessmentModeSelection(
        requestedAssessmentMode,
        runner,
        loadedSession.target.kind,
        loadedSession.target.name,
      );

    if (
      loadedSession.version === '1.3'
      && requestedAssessmentMode
      && requestedAssessmentMode !== loadedSession.assessmentMode
    ) {
      throw new Error(
        `Assessment basis is already frozen for this session as "${loadedSession.assessmentMode}". Remove --assessment-mode to resume it.`,
      );
    }

    const preparedSession = prepareQuestionnaireSessionForResume({
      session: loadedSession,
      findings: snapshot.findings,
      expectedPrinciples,
      expectedQuestions,
      upgradeAssessmentMode,
    });

    session = preparedSession.session;
    if (preparedSession.didUpgrade) {
      await saveQuestionnaireSession(session, sessionPath);
    }

    scanSnapshotPath = session.scanSnapshotPath;
    sessionTarget = session.target.kind === 'url'
      ? { kind: 'url', name: session.target.name, url: session.target.url! }
      : { kind: 'path', name: session.target.name, path: session.target.path! };
  } else if (options.fromScan) {
    const resolvedScanPath = path.resolve(options.fromScan);
    const rawScanData = JSON.parse(await fs.readFile(resolvedScanPath, 'utf-8'));
    const normalized = normalizeScanSnapshot(rawScanData, resolvedScanPath, options.name);
    snapshot = normalized.snapshot;
    sessionTarget = normalized.target;
    const assessmentMode = await resolveAssessmentModeSelection(
      requestedAssessmentMode,
      runner,
      sessionTarget.kind,
      sessionTarget.name,
    );

    const spinner = ora('Creating attestation session from saved scan...').start();
    const initialized = await initializeAttestationSession({
      snapshot,
      target: sessionTarget,
      outputDir: outputRoot,
      strictMode: Boolean(options.strict),
      assessmentMode,
    });
    spinner.succeed(`Session created at ${initialized.paths.directory}`);

    session = initialized.session;
    sessionPath = initialized.paths.sessionPath;
    scanSnapshotPath = initialized.paths.scanSnapshotPath;
  } else {
    const target = await resolveCliTarget(targetInput!, options.name);
    sessionTarget = toSessionTarget(target);
    await maybeAutoUpdateRules(options);
    const orchestrator = createOrchestrator(target.kind, options);
    const spinner = ora(target.kind === 'url' ? `Scanning URL: ${target.value}` : 'Scanning project...').start();
    const startTime = Date.now();
    const scanResult = await orchestrator.scan(target.value);
    const urlScanFailure = target.kind === 'url' ? getUrlScanFailureMessage(scanResult) : null;
    if (urlScanFailure) {
      spinner.fail('Attestation scan failed');
      throw new Error(urlScanFailure);
    }

    snapshot = buildAttestationScanSnapshot({
      target: sessionTarget,
      findings: scanResult.findings,
      results: scanResult.results,
      errors: scanResult.errors,
      totalDurationMs: Date.now() - startTime,
      ruleFreshness: scanResult.ruleFreshness,
    });
    const assessmentMode = await resolveAssessmentModeSelection(
      requestedAssessmentMode,
      runner,
      sessionTarget.kind,
      sessionTarget.name,
    );

    const initialized = await initializeAttestationSession({
      snapshot,
      target: sessionTarget,
      outputDir: outputRoot,
      strictMode: Boolean(options.strict),
      assessmentMode,
    });
    spinner.succeed(`Session created at ${initialized.paths.directory}`);

    session = initialized.session;
    sessionPath = initialized.paths.sessionPath;
    scanSnapshotPath = initialized.paths.scanSnapshotPath;
  }

  console.log(chalk.gray(`Session file: ${sessionPath}`));
  console.log(chalk.gray(`Frozen scan snapshot: ${scanSnapshotPath}`));
  console.log(chalk.gray(`Assessment basis: ${session.assessmentMode}`));

  const runResult = await runAttestationSession({
    session,
    sessionPath,
    snapshot,
    promptRunner: runner,
  });

  if (runResult.status === 'saved') {
    console.log(chalk.yellow('\nAttestation saved for later completion.'));
    console.log(chalk.yellow(`Resume with: attestlens attest --resume ${sessionPath}`));
    return {
      status: 'saved',
      sessionPath,
      scanSnapshotPath,
      outputDir: path.dirname(sessionPath),
    };
  }

  const reportOptions = getReportOptionsForSession(
    sessionTarget,
    reportFormats,
    path.dirname(sessionPath),
    runResult.session.strictMode,
    snapshot.ruleFreshness,
  );
  const report = buildComplianceReport(
    snapshot.findings,
    reportOptions,
    snapshot.totalDurationMs,
    runResult.session,
  );
  report.metadata.scannerVersions = getScannerVersions(snapshot);

  const reportPaths = await writeReportFiles(report, reportOptions, runResult.session);
  const questionnaireSummary = summarizeQuestionnaireResults(report);

  console.log('');
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.bold(`  Grade: ${getGradeDisplay(report.overallGrade, report.overallScore)}`));
  console.log(chalk.bold(`  Risk:  ${getRiskDisplay(report.riskLevel)}`));
  if (report.breachReadiness) {
    console.log(chalk.bold(`  Breach Readiness: ${report.breachReadiness.level.toUpperCase()} (${report.breachReadiness.score}/100, ${Math.round(report.breachReadiness.confidence * 100)}% confidence)`));
  }
  console.log(chalk.bold(`  Questionnaire Resolved: ${questionnaireSummary.resolved}`));
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));

  if (report.assessment?.incomplete) {
    console.log(chalk.yellow('\nAssessment incomplete:'));
    console.log(chalk.yellow(report.assessment.summary));
    console.log(chalk.yellow(`Unresolved principles: ${report.assessment.unknownPrinciples.join(', ')}`));
  }

  if (questionnaireSummary.unresolved.length > 0) {
    console.log(chalk.yellow(`\nUnresolved questionnaire principles: ${questionnaireSummary.unresolved.join(', ')}`));
  }

  console.log('');
  for (const output of reportPaths) {
    console.log(chalk.green(`  📄 ${output.label}: ${output.path}`));
  }

  return {
    status: 'completed',
    sessionPath,
    scanSnapshotPath,
    outputDir: path.dirname(sessionPath),
    reportPaths,
  };
}

function parseAssessmentModeOption(rawValue: unknown): AssessmentMode | undefined {
  if (typeof rawValue !== 'string' || rawValue.trim().length === 0) {
    return undefined;
  }

  switch (rawValue.trim()) {
    case 'artifact_only':
    case 'codebase_only':
    case 'operator_attested':
      return rawValue.trim() as AssessmentMode;
    default:
      throw new Error(`Unsupported assessment mode: ${rawValue}`);
  }
}

async function resolveAssessmentModeSelection(
  requestedAssessmentMode: AssessmentMode | undefined,
  runner: AttestationPromptRunner,
  targetKind: 'path' | 'url',
  targetName: string,
): Promise<AssessmentMode> {
  if (requestedAssessmentMode) {
    return requestedAssessmentMode;
  }

  return runner.promptAssessmentMode({
    targetKind,
    targetName,
  });
}

function getUrlScanFailureMessage(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
): string | null {
  const urlResult = result.results.find((scannerResult) => scannerResult.source === 'url-scan');
  const urlErrors = collectUrlScanErrors(result, urlResult);

  if (!urlResult && urlErrors.length > 0) {
    return formatUrlScanFailure(urlErrors[0]);
  }

  if (!urlResult) {
    return 'URL scan failed before findings could be collected.';
  }

  const fatalError = urlErrors.find((error) => !error.recoverable);
  if (fatalError) {
    return formatUrlScanFailure(fatalError);
  }

  if (urlErrors.length > 0 && urlResult.findings.length === 0) {
    return formatUrlScanFailure(urlErrors[0]);
  }

  return null;
}

function collectUrlScanErrors(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
  urlResult?: ScannerResult,
): ScannerError[] {
  const resultErrors = urlResult?.errors ?? [];
  const orchestratorErrors = result.errors.filter((error) => error.source === 'url-scan');
  return [...resultErrors, ...orchestratorErrors];
}

function formatUrlScanFailure(error: ScannerError): string {
  switch (error.code) {
    case 'INVALID_URL':
      return 'URL target is not allowed for scanning.';
    case 'FETCH_FAILED':
      return 'URL scan failed before findings could be collected.';
    default:
      return 'URL scan failed before findings could be collected.';
  }
}

function parseReportFormats(rawFormats: string): ReportFormat[] {
  const supported = new Set<ReportFormat>(['json', 'html', 'markdown', 'pdf']);
  const formats = rawFormats
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean);

  if (formats.length === 0) {
    throw new Error('At least one report format is required');
  }

  for (const format of formats) {
    if (!supported.has(format as ReportFormat)) {
      throw new Error(`Unsupported report format: ${format}`);
    }
  }

  return formats as ReportFormat[];
}

function resolveReportTarget(
  scanData: Record<string, any>,
  resolvedPath: string,
  explicitName?: string,
): { targetName: string; targetPath?: string; targetUrl?: string } {
  const embeddedTarget = typeof scanData.target === 'object' && scanData.target ? scanData.target : {};
  const targetUrl = typeof embeddedTarget.url === 'string'
    ? embeddedTarget.url
    : typeof scanData.targetUrl === 'string'
      ? scanData.targetUrl
      : undefined;
  const targetPath = targetUrl
    ? undefined
    : typeof embeddedTarget.path === 'string'
      ? embeddedTarget.path
      : typeof scanData.targetPath === 'string'
        ? scanData.targetPath
        : resolvedPath;
  const targetName = explicitName
    || (typeof embeddedTarget.name === 'string' ? embeddedTarget.name : undefined)
    || getHostnameFromTargetUrl(targetUrl)
    || (targetPath ? path.basename(targetPath) : undefined)
    || path.basename(resolvedPath, '.json');

  return { targetName, targetPath, targetUrl };
}

function buildReportFilename(targetName: string, timestamp: string): string {
  const slug = targetName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'target';
  return `attestlens-report-${slug}-${timestamp.split('T')[0]}`;
}

async function writeReportFiles(
  report: any,
  reportOptions: ReportOptions,
  questionnaireSession?: QuestionnaireSession,
): Promise<Array<{ label: string; path: string }>> {
  const outputDir = path.resolve(reportOptions.outputDir);
  await fs.mkdir(outputDir, { recursive: true });

  const filename = buildReportFilename(reportOptions.targetName, report.timestamp);
  const outputs: Array<{ label: string; path: string }> = [];

  for (const format of reportOptions.formats) {
      const filePath = path.join(outputDir, `${filename}.${format === 'markdown' ? 'md' : format}`);

    switch (format) {
      case 'html':
        await fs.writeFile(filePath, generateHTMLReport(report, reportOptions, questionnaireSession));
        outputs.push({ label: 'HTML report', path: filePath });
        break;
      case 'json':
        await fs.writeFile(filePath, generateJSONReport(report));
        outputs.push({ label: 'JSON report', path: filePath });
        break;
      case 'markdown':
        await fs.writeFile(filePath, generateMarkdownReport(report, questionnaireSession));
        outputs.push({ label: 'Markdown report', path: filePath });
        break;
      case 'pdf':
        await fs.writeFile(filePath, await generatePDFReport(report, reportOptions, questionnaireSession));
        outputs.push({ label: 'PDF report', path: filePath });
        break;
    }
  }

  return outputs;
}

function displayFindings(findings: AttestLensFinding[]) {
  const criticals = findings.filter(f => f.severity === 'critical');
  const highs = findings.filter(f => f.severity === 'high');
  const mediums = findings.filter(f => f.severity === 'medium');
  const lows = findings.filter(f => f.severity === 'low' || f.severity === 'info');

  if (criticals.length) {
    console.log(chalk.red(`  🔴 Critical: ${criticals.length}`));
    for (const f of criticals) {
      console.log(chalk.red(`     ${f.sourceRule}: ${f.title}`));
      if (f.file) console.log(chalk.gray(`       ${f.file}${f.line ? `:${f.line}` : ''}`));
      if (f.url) console.log(chalk.gray(`       ${f.url}`));
    }
  }
  if (highs.length) {
    console.log(chalk.yellow(`  🟠 High: ${highs.length}`));
    for (const f of highs) {
      console.log(chalk.yellow(`     ${f.sourceRule}: ${f.title}`));
      if (f.file) console.log(chalk.gray(`       ${f.file}${f.line ? `:${f.line}` : ''}`));
      if (f.url) console.log(chalk.gray(`       ${f.url}`));
    }
  }
  if (mediums.length) {
    console.log(chalk.hex('#f4a261')(`  🟡 Medium: ${mediums.length}`));
  }
  if (lows.length) {
    console.log(chalk.green(`  🟢 Low/Info: ${lows.length}`));
  }
}

function getGradeDisplay(grade: string, score: number): string {
  const colors: Record<string, (text: string) => string> = {
    'A': chalk.green,
    'B': chalk.cyan,
    'C': chalk.yellow,
    'D': chalk.hex('#f4a261'),
    'F': chalk.red,
  };
  const color = colors[grade] || chalk.white;
  return `${color(grade)} (${score}/100)`;
}

function getRiskDisplay(risk: string): string {
  const colors: Record<string, (text: string) => string> = {
    'low': chalk.green,
    'medium': chalk.yellow,
    'high': chalk.hex('#f4a261'),
    'critical': chalk.red,
  };
  const color = colors[risk] || chalk.white;
  return color(risk.toUpperCase());
}

// ─── Run ──────────────────────────────────────────────────────────────────────

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await program.parseAsync();
}
