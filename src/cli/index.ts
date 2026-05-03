#!/usr/bin/env node
/**
 * AttestLens — CLI Entry Point
 * 
 * Usage:
 *   attestlens scan <path>     Scan a project directory
 *   attestlens audit <path>    Scan + generate compliance report
 *   attestlens report <path>   Generate report from existing scan data
 */

import { Command, CommanderError } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { select } from '@inquirer/prompts';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { formatSarif, mapFindingSeverityToSarifLevel } from '../formatters/sarif.js';
import type { SarifOutput } from '../formatters/sarif.js';
import { ScannerOrchestrator, type ScannerOrchestratorOptions } from '../scanner/orchestrator.js';
import { mapAllFindings } from '../mapping/engine.js';
import {
  buildDeployDecision,
  buildComplianceReport,
  generateAgentReport,
  generateHTMLReport,
  generateJSONReport,
  generateMarkdownReport,
  generatePDFReport,
  SUPPORTED_REPORT_FORMATS,
} from '../report/generator.js';
import {
  buildSMBComplianceResult,
  generateSMBHTMLReport,
  generateSMBMarkdownReport,
  type SMBComplianceResult,
} from '../report/smb-generator.js';
import { updateRuleCache } from '../scanner/rules/index.js';
import {
  SMB_QUESTIONS,
  SMB_QUESTIONNAIRE_VERSION,
  aggregatePrincipleResults,
  buildAttestationScanSnapshot,
  buildFindingsHash,
  buildFrozenSessionQuestions,
  completeQuestionnaireSession,
  createQuestionnaireSession,
  createInteractivePromptRunner,
  deriveQuestionnairePrinciples,
  evaluateResponse,
  getQuestionBankForJurisdiction,
  initializeAttestationSession,
  loadQuestionnaireSession,
  loadScanSnapshot,
  prepareQuestionnaireSessionForResume,
  runAttestationSession,
  saveQuestionnaireSession,
} from '../questionnaire/index.js';
import {
  Jurisdiction,
  JurisdictionCoverage as JurisdictionCoverageSchema,
  PackValidation as PackValidationSchema,
  RuleFreshness,
} from '../schema/index.js';
import type {
  APPPrinciple,
  AssessmentMode,
  AttestLensFinding,
  ComplianceReport,
  DiffContext,
  JurisdictionCoverage,
  Jurisdiction as JurisdictionType,
  PackValidation,
  Question,
  QuestionnaireResponse,
  QuestionnaireSession,
  ReformImpactAssessment,
  RegulationControl,
  RuleFreshness as RuleFreshnessMetadata,
} from '../schema/index.js';
import type { ComplianceReportWithSMB, ReportFormat, ReportOptions } from '../report/generator.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import type { AttestationPromptRunner, AttestationScanSnapshot, SessionTarget } from '../questionnaire/index.js';
import { getHostnameFromTargetUrl } from '../utils/target.js';
import {
  installClients,
  uninstallClients,
  type SupportedClient,
} from './install.js';
import { registerMonitorCommands } from '../monitor/cli.js';
import { proposeRules } from '../authoring/propose.js';
import { reviewPack } from '../authoring/review.js';
import { buildDiffContext } from '../git/diff.js';
import { ATTESTLENS_VERSION } from '../version.js';

const CLI_VERSION = ATTESTLENS_VERSION;
const program = new Command();

program
  .name('attestlens')
  .description('Privacy Compliance Deploy Gate for AI Agents')
  .version(CLI_VERSION);
program.exitOverride();

registerMonitorCommands(program);

// ─── Scan Command ─────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan a project directory or URL for privacy compliance findings')
  .argument('<target>', 'Path to project directory or URL (https://...)')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown,pdf,sarif,agent)', 'json,html')
  .option('--sarif-output <path>', 'Write SARIF output to a file instead of stdout')
  .option('--fail-on-severity <level>', 'Exit 1 when findings at or above this level exist (error, warning, note)', 'error')
  .option('--no-fail', 'Always exit 0')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .option('--no-behavioral', 'Disable behavioral supply-chain analysis')
  .option('--no-iac', 'Disable infrastructure-as-code misconfiguration scanning')
  .option('--include-gitleaks', 'Enable opt-in git history secret scanning via gitleaks')
  .option('--gitleaks-path <path>', 'Path to gitleaks binary', 'gitleaks')
  .option('--include-typosquat', 'Enable experimental typosquatting detection (VS-SC-004)')
  .option('--external-enrichment', 'Enable external OSV.dev and npm registry dependency enrichment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--auto-update', 'Refresh the cached rule pack from ATTESTLENS_RULE_SOURCE before scanning')
  .option('--jurisdiction <jurisdiction>', 'Jurisdiction to check against (default: au-privacy-act)', 'au-privacy-act')
  .option('--diff-base <ref>', 'Git base ref for PR diff mode')
  .option('--diff-head <ref>', 'Git head ref for PR diff mode')
  .option('--changed-files-only', 'Restrict feasible file-based findings to files changed in diff mode')
  .option('--reform', 'Include Privacy Act 2026 reform impact assessment')
  .action(async (targetInput: string, options: any) => {
    const sarifRequested = isSarifRequested(options.format);
    if (!sarifRequested) {
      console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Scanner\n'));
    }

    try {
      const failConfig = parseFailureControlOptions(options);
      const target = await resolveCliTarget(targetInput, options.name);
      const jurisdiction = parseJurisdictionOption(options.jurisdiction);
      assertJurisdictionAvailableForCli(jurisdiction);
      await maybeAutoUpdateRules(options);
      const diffContext = await resolveCliDiffContext(target, options);
      const orchestrator = createOrchestrator(target.kind, options);
      const spinner = ora(target.kind === 'url' ? `Scanning URL: ${target.value}` : 'Scanning project...').start();
      const startTime = Date.now();

      const result = await orchestrator.scan(target.value, undefined, {
        diffContext,
        changedFilesOnly: options.changedFilesOnly === true,
      });
      const urlScanFailure = target.kind === 'url' ? getUrlScanFailureMessage(result) : null;
      if (urlScanFailure) {
        spinner.fail('URL scan failed');
        throw new Error(urlScanFailure);
      }
      const duration = Date.now() - startTime;
      spinner.succeed(`${target.kind === 'url' ? 'URL scan' : 'Scan'} complete in ${(duration / 1000).toFixed(1)}s`);
      if (!sarifRequested) {
        displayRuleFreshness(result.ruleFreshness);
        displayScannerWarnings(result.errors);
      }

      const findings = result.findings;
      if (sarifRequested) {
        const sarifReport = buildComplianceReport(findings, {
          targetName: target.name,
          targetPath: target.kind === 'path' ? target.value : undefined,
          targetUrl: target.kind === 'url' ? target.value : undefined,
          formats: ['json'],
          outputDir: path.resolve(options.output),
          strictMode: options.strict,
          includeDeployDecision: true,
          ruleFreshness: result.ruleFreshness,
          jurisdiction,
          jurisdictionPack: result.jurisdictionManifests?.[jurisdiction],
          packValidationTrusted: result.ruleFreshness.source === 'embedded',
          diffContext: result.diffContext,
        }, duration);
        const sarif = await formatSarif({
          findings,
          jurisdiction,
          version: CLI_VERSION,
          basePath: target.kind === 'path' ? target.value : undefined,
          deployDecision: sarifReport.deployDecision,
        });
        await emitSarifOutput(sarif, options.sarifOutput, path.resolve(options.output));
        process.exit(determineSarifExitCode(sarif, failConfig));
      }

      if (findings.length === 0) {
        console.log(chalk.green('\n✅ No compliance findings detected.'));
        console.log(chalk.gray(`   Run \`attestlens audit --jurisdiction ${jurisdiction}\` for a full ${getJurisdictionAssessmentLabel(jurisdiction)} control assessment.`));
        return;
      }

      console.log(chalk.yellow(`\n⚠ Found ${findings.length} finding${findings.length > 1 ? 's' : ''}:\n`));
      displayFindings(findings);

      // Map to active jurisdiction controls
      const { controls } = mapAllFindings(findings, { jurisdictions: [jurisdiction] });
      const affectedPrinciples = controls
        .filter(c => c.status !== 'unknown' || c.findings.length > 0)
        .map(c => c.principle);
      console.log(chalk.cyan(`\n📋 Affected Controls: ${affectedPrinciples.join(', ')}`));
      console.log(chalk.gray(`   Run \`attestlens audit ${target.rawInput}\` for a full compliance report.`));
      process.exit(determineExitCode(findings, failConfig));

    } catch (error: any) {
      const label = isUrlTarget(targetInput) ? 'URL scan failed' : 'Scan failed';
      console.error(chalk.red(`\n${label.replace(/^./, s => s.toUpperCase())}`));
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(2);
    }
  });

// ─── Audit Command ────────────────────────────────────────────────────────────

program
  .command('audit')
  .description('Full compliance audit — scan + generate APP/NDB report')
  .argument('<target>', 'Path to project directory or URL (https://...)')
  .option('-n, --name <name>', 'Project name', '')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown,pdf,sarif,agent)', 'html,json')
  .option('--sarif-output <path>', 'Write SARIF output to a file instead of stdout')
  .option('--fail-on-severity <level>', 'Exit 1 when findings at or above this level exist (error, warning, note)', 'error')
  .option('--no-fail', 'Always exit 0')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .option('--no-behavioral', 'Disable behavioral supply-chain analysis')
  .option('--no-iac', 'Disable infrastructure-as-code misconfiguration scanning')
  .option('--include-gitleaks', 'Enable opt-in git history secret scanning via gitleaks')
  .option('--gitleaks-path <path>', 'Path to gitleaks binary', 'gitleaks')
  .option('--include-typosquat', 'Enable experimental typosquatting detection (VS-SC-004)')
  .option('--external-enrichment', 'Enable external OSV.dev and npm registry dependency enrichment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--auto-update', 'Refresh the cached rule pack from ATTESTLENS_RULE_SOURCE before scanning')
  .option('--jurisdiction <jurisdiction>', 'Jurisdiction to check against (default: au-privacy-act)', 'au-privacy-act')
  .option('--diff-base <ref>', 'Git base ref for PR diff mode')
  .option('--diff-head <ref>', 'Git head ref for PR diff mode')
  .option('--changed-files-only', 'Restrict feasible file-based findings to files changed in diff mode')
  .option('--opinion', 'Include compliance opinion in report')
  .option('--reform', 'Include Privacy Act 2026 reform impact assessment')

  .action(async (targetInput: string, options: any) => {
    try {
      const failConfig = parseFailureControlOptions(options);
      const reportFormats = parseReportFormats(options.format);
      const agentOutput = isAgentReportFormat(reportFormats);
      const includesSarif = reportFormats.includes('sarif');
      const sarifOnly = reportFormats.length === 1 && reportFormats[0] === 'sarif';
      if (!agentOutput) {
        console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Audit\n'));
      }
      const target = await resolveCliTarget(targetInput, options.name);
      const jurisdiction = parseJurisdictionOption(options.jurisdiction);
      assertJurisdictionAvailableForCli(jurisdiction);
      const projectName = target.name;
      await maybeAutoUpdateRules(options, agentOutput);
      const diffContext = await resolveCliDiffContext(target, options);
      const orchestrator = createOrchestrator(target.kind, options);
      const spinner = agentOutput
        ? undefined
        : ora(`Running compliance scan for ${target.kind === 'url' ? 'URL' : 'project'}...`).start();
      const startTime = Date.now();

      const scanResult = await orchestrator.scan(target.value, undefined, {
        diffContext,
        changedFilesOnly: options.changedFilesOnly === true,
      });
      const urlScanFailure = target.kind === 'url' ? getUrlScanFailureMessage(scanResult) : null;
      if (urlScanFailure) {
        spinner?.fail('Audit failed');
        throw new Error(urlScanFailure);
      }
      const duration = Date.now() - startTime;
      if (sarifOnly) {
        const sarifReport = buildComplianceReport(scanResult.findings, {
          targetName: projectName,
          targetPath: target.kind === 'path' ? target.value : undefined,
          targetUrl: target.kind === 'url' ? target.value : undefined,
          formats: ['json'],
          outputDir: path.resolve(options.output),
          strictMode: options.strict,
          includeDeployDecision: true,
          ruleFreshness: scanResult.ruleFreshness,
          jurisdiction,
          jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
          packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
          diffContext: scanResult.diffContext,
        }, duration);
        const sarif = await formatSarif({
          findings: scanResult.findings,
          jurisdiction,
          version: CLI_VERSION,
          basePath: target.kind === 'path' ? target.value : undefined,
          deployDecision: sarifReport.deployDecision,
        });
        spinner?.succeed(`Audit complete in ${(duration / 1000).toFixed(1)}s`);
        displayRuleFreshness(scanResult.ruleFreshness);
        displayScannerWarnings(scanResult.errors);
        await emitSarifOutput(sarif, options.sarifOutput, path.resolve(options.output));
        process.exit(determineSarifExitCode(sarif, failConfig));
      }

      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath: target.kind === 'path' ? target.value : undefined,
        targetUrl: target.kind === 'url' ? target.value : undefined,
        formats: reportFormats.filter((format) => format !== 'sarif'),
        outputDir: path.resolve(options.output),
        strictMode: options.strict,
        includeOpinion: options.opinion,
        includeDeployDecision: agentOutput,
        includeReform: options.reform,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
        diffContext: scanResult.diffContext,
      };

      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map(r => [r.source, r.version])
      );
      const effectiveControls = getEffectiveControls(report, jurisdiction);

      if (agentOutput) {
        console.log(generateAgentReport(report, effectiveControls));
        process.exit(determineExitCode(scanResult.findings, failConfig));
        return;
      }

      spinner?.succeed(`Audit complete in ${(duration / 1000).toFixed(1)}s`);

      // Display summary
      console.log('');
      console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
      console.log(chalk.bold(`  Grade: ${getGradeDisplay(report.overallGrade, report.overallScore)}`));
      console.log(chalk.bold(`  Risk:  ${getRiskDisplay(report.riskLevel)}`));
      if (report.breachReadiness) {
        console.log(chalk.bold(`  Breach Readiness: ${report.breachReadiness.level.toUpperCase()} (${report.breachReadiness.score}/100, ${Math.round(report.breachReadiness.confidence * 100)}% confidence)`));
      }
      console.log(chalk.bold(`  Rule Pack: ${formatRuleFreshnessForCli(scanResult.ruleFreshness)}`));
      if (report.complianceOpinion) {
        const op = report.complianceOpinion;
        const verdictColor = op.overallVerdict === 'COMPLIANT' ? chalk.green : op.overallVerdict === 'NON_COMPLIANT' ? chalk.red : chalk.yellow;
        console.log(chalk.bold(`  Opinion: ${verdictColor(op.overallVerdict.replace(/_/g, ' '))} (confidence: ${op.overallConfidence})`));
        console.log(chalk.gray(`  Signed: ${op.signedBy} @ ${op.signedAt}`));
      }
      console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
      console.log('');

      // Control summary
      for (const control of effectiveControls) {
        const statusIcon = control.status === 'pass' ? '✅' : control.status === 'fail' ? '❌' : '⚠️';
        console.log(`  ${statusIcon} ${control.principle} — ${control.shortName}: ${control.status.toUpperCase()} (${control.score}/100)`);
      }

      console.log('');

      // Write output files
      let sarifExitCode: number | undefined;
      for (const output of await writeReportFiles(report, reportOptions)) {
        console.log(chalk.green(`  📄 ${output.label}: ${output.path}`));
      }
      if (includesSarif) {
        const sarifDeployDecision = report.deployDecision ?? buildDeployDecision(report, {
          packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
        });
        const sarif = await formatSarif({
          findings: scanResult.findings,
          jurisdiction,
          version: CLI_VERSION,
          basePath: target.kind === 'path' ? target.value : undefined,
          deployDecision: sarifDeployDecision,
        });
        const sarifPath = options.sarifOutput || path.join(path.resolve(options.output), `${buildReportFilename(projectName, report.timestamp)}.sarif`);
        await emitSarifOutput(sarif, sarifPath, path.resolve(options.output));
        sarifExitCode = determineSarifExitCode(sarif, failConfig);
        console.log(chalk.green(`  📄 SARIF report: ${sarifPath}`));
      }

      displayScannerWarnings(scanResult.errors);

      console.log(chalk.gray(`\n  ${report.disclaimer}`));
      process.exit(sarifExitCode ?? determineExitCode(scanResult.findings, failConfig));

    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(2);
    }
  });

program
  .command('install')
  .description('Install the Clearway MCP server into a supported client config')
  .option('--client <name>', 'Specific client to configure (claude-desktop, cline, continue, cursor)')
  .option('--dry-run', 'Show the changes without writing files')
  .action(async (options: { client?: SupportedClient; dryRun?: boolean }) => {
    try {
      const results = await installClients({ client: options.client, dryRun: options.dryRun });
      displayClientMutationResults(results, 'install');
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

program
  .command('uninstall')
  .description('Remove the Clearway MCP server from supported client configs')
  .option('--client <name>', 'Specific client to configure (claude-desktop, cline, continue, cursor)')
  .option('--dry-run', 'Show the changes without writing files')
  .action(async (options: { client?: SupportedClient; dryRun?: boolean }) => {
    try {
      const results = await uninstallClients({ client: options.client, dryRun: options.dryRun });
      displayClientMutationResults(results, 'uninstall');
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

program
  .command('mcp')
  .description('Run the Clearway MCP server over stdio')
  .action(async () => {
    const { main } = await import('../mcp/index.js');
    await main();
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
  .option('-f, --format <formats>', 'Output formats (json,html,markdown,pdf,agent)', 'html,json,markdown,pdf')
  .option('--assessment-mode <mode>', 'Frozen assessment basis (artifact_only, codebase_only, operator_attested)')
  .option('--strict', 'Treat unresolved controls as FAIL after questionnaire merge')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .option('--no-behavioral', 'Disable behavioral supply-chain analysis')
  .option('--no-iac', 'Disable infrastructure-as-code misconfiguration scanning')
  .option('--include-gitleaks', 'Enable opt-in git history secret scanning via gitleaks')
  .option('--gitleaks-path <path>', 'Path to gitleaks binary', 'gitleaks')
  .option('--include-typosquat', 'Enable experimental typosquatting detection (VS-SC-004)')
  .option('--external-enrichment', 'Enable external OSV.dev and npm registry dependency enrichment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--auto-update', 'Refresh the cached rule pack from ATTESTLENS_RULE_SOURCE before scanning')
  .option('--jurisdiction <jurisdiction>', 'Jurisdiction to check against (default: au-privacy-act)', 'au-privacy-act')
  .action(async (targetInput: string | undefined, options: any) => {
    console.log(chalk.bold.cyan('\n📝 AttestLens — Privacy Act Attestation\n'));

    try {
      await executeAttestCommand(targetInput, options);
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(2);
    }
  });

// ─── Compliance Check Command ────────────────────────────────────────────────

program
  .command('compliance-check')
  .description('Plain-English compliance check for Australian businesses')
  .argument('<target>', 'Path to project directory or URL (https://...)')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown)', 'html,markdown')
  .option('--strict', 'Treat unknown controls as failing')
  .option('--non-interactive', 'Skip questionnaire, scan-only assessment')
  .option('--include-gitleaks', 'Enable git history secret scanning')
  .option('--gitleaks-path <path>', 'Path to gitleaks binary', 'gitleaks')
  .option('--reform', 'Include Privacy Act 2026 reform impact assessment')
  .option('--scanner-timeout <ms>', 'Per-scanner timeout in milliseconds')
  .option('--jurisdiction <jurisdiction>', 'Jurisdiction to check against (default: au-privacy-act)', 'au-privacy-act')
  .action(async (targetInput: string, options: any) => {
    console.log(chalk.bold.cyan('\n📋 AttestLens — Compliance Check\n'));

    try {
      const outputFormats = parseSMBOutputFormats(options.format);
      const target = await resolveCliTarget(targetInput);
      const jurisdiction = parseJurisdictionOption(options.jurisdiction);
      assertJurisdictionAvailableForCli(jurisdiction);
      if (jurisdiction !== 'au-privacy-act') {
        throw new Error(`SMB compliance check is currently AU-only; use \`audit --jurisdiction ${jurisdiction}\` for ${getJurisdictionAssessmentLabel(jurisdiction)} assessments.`);
      }
      const outputDir = path.resolve(options.output);
      const orchestrator = createOrchestrator(target.kind, options);
      const spinner = ora(target.kind === 'url' ? `Checking URL: ${target.value}` : 'Checking project...').start();
      const startTime = Date.now();

      const scanResult = await orchestrator.scan(target.value);
      const urlScanFailure = target.kind === 'url' ? getUrlScanFailureMessage(scanResult) : null;
      if (urlScanFailure) {
        spinner.fail('Compliance check failed');
        throw new Error(urlScanFailure);
      }
      const duration = Date.now() - startTime;
      spinner.succeed(`Compliance scan complete in ${(duration / 1000).toFixed(1)}s`);
      displayRuleFreshness(scanResult.ruleFreshness);

      const preliminaryReportOptions: ReportOptions = {
        targetName: target.name,
        targetPath: target.kind === 'path' ? target.value : undefined,
        targetUrl: target.kind === 'url' ? target.value : undefined,
        formats: ['json'],
        outputDir,
        strictMode: false,
        includeReform: options.reform,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };
      const preliminaryReport = buildComplianceReport(
        scanResult.findings,
        preliminaryReportOptions,
        duration,
      );

      const questionnaireSession = options.nonInteractive
        ? undefined
        : await runSMBQuestionnaire({
          preliminaryReport,
          target,
          findings: scanResult.findings,
          strictMode: Boolean(options.strict),
        });

      const reportOptions: ReportOptions = {
        targetName: target.name,
        targetPath: target.kind === 'path' ? target.value : undefined,
        targetUrl: target.kind === 'url' ? target.value : undefined,
        formats: ['smb'],
        outputDir,
        strictMode: options.strict,
        includeReform: options.reform,
        includeSMB: true,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };

      const report = buildComplianceReport(
        scanResult.findings,
        reportOptions,
        duration,
        questionnaireSession,
      ) as ComplianceReportWithSMB;
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map(r => [r.source, r.version]),
      );

      const reportPaths = await writeSMBComplianceFiles(report, reportOptions, outputFormats, questionnaireSession);
      displaySMBTerminalSummary(getSMBComplianceResult(report, questionnaireSession), reportPaths, outputDir);
      displayScannerWarnings(scanResult.errors);
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(2);
    }
  });

// ─── Reform Command ───────────────────────────────────────────────────────────

program
  .command('reform')
  .description('Standalone Privacy Act 2026 reform impact assessment')
  .argument('<target>', 'Path to project directory')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown)', 'json,markdown')
  .option('--jurisdiction <jurisdiction>', 'Jurisdiction to check against (default: au-privacy-act)', 'au-privacy-act')
  .action(async (targetInput: string, options: any) => {
    console.log(chalk.bold.cyan('\n🏛️  AttestLens — Reform Impact Assessment\n'));

    try {
      const outputFormats = parseReformOutputFormats(options.format);
      const target = await resolveCliTarget(targetInput);
      if (target.kind !== 'path') {
        throw new Error('Reform impact assessment currently supports project directories only.');
      }

      const jurisdiction = parseJurisdictionOption(options.jurisdiction);
      assertJurisdictionAvailableForCli(jurisdiction);
      const outputDir = path.resolve(options.output);
      const orchestrator = createOrchestrator(target.kind, { ...options, reform: true });
      const spinner = ora('Assessing reform impact...').start();
      const startTime = Date.now();

      const scanResult = await orchestrator.scan(target.value);
      const duration = Date.now() - startTime;
      spinner.succeed(`Reform scan complete in ${(duration / 1000).toFixed(1)}s`);
      displayRuleFreshness(scanResult.ruleFreshness);

      const reportOptions: ReportOptions = {
        targetName: target.name,
        targetPath: target.value,
        formats: ['json'],
        outputDir,
        strictMode: false,
        includeReform: true,
        ruleFreshness: scanResult.ruleFreshness,
        jurisdiction,
        jurisdictionPack: scanResult.jurisdictionManifests?.[jurisdiction],
        packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
      };

      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map(r => [r.source, r.version]),
      );

      const assessment = report.reformImpactAssessment;
      if (!assessment) {
        throw new Error('Reform impact assessment generation failed.');
      }

      const reportPaths = await writeReformAssessmentFiles(
        assessment,
        report.target.name,
        report.timestamp,
        outputDir,
        outputFormats,
      );

      displayReformTerminalSummary(assessment, reportPaths, outputDir);
      displayScannerWarnings(scanResult.errors);
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(2);
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
  .option('--jurisdiction <jurisdiction>', 'Jurisdiction to check against when regenerating a report')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .action(async (filePath: string, options: any) => {
    const resolvedPath = path.resolve(filePath);
    
    try {
      const data = await fs.readFile(resolvedPath, 'utf-8');
      const scanData = JSON.parse(data);
      
      const reportFormats = parseReportFormats(options.format);
      const reportTarget = resolveReportTarget(scanData, resolvedPath, options.name);
      const jurisdiction = resolveReportJurisdiction(scanData, options.jurisdiction);

      const reportOptions: ReportOptions = {
        targetName: reportTarget.targetName,
        targetPath: reportTarget.targetPath,
        targetUrl: reportTarget.targetUrl,
        formats: reportFormats,
        outputDir: path.resolve(options.output),
        strictMode: options.strict,
        includeDeployDecision: isAgentReportFormat(reportFormats),
        jurisdiction,
        ruleFreshness: extractRuleFreshness(scanData),
        packCoverage: extractPackCoverage(scanData),
        packValidation: extractPackValidation(scanData),
        packValidationTrusted: false,
      };

      const report = buildComplianceReport(scanData.findings || scanData, reportOptions, 0);
      if (isAgentReportFormat(reportFormats)) {
        console.log(generateAgentReport(report));
        return;
      }
      await writeReportFiles(report, reportOptions);

      console.log(chalk.green('✅ Report generated successfully.'));
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

// ─── Rule Update Command ─────────────────────────────────────────────────────

program
  .command('propose-rules')
  .description('Draft a proposed rule pack from legislation text using an LLM')
  .requiredOption('--jurisdiction <jurisdiction>', 'Jurisdiction to draft for')
  .requiredOption('--source <path>', 'Path to legislation text file')
  .option('--source-url <url>', 'Official legislation source URL')
  .requiredOption('--output <path>', 'Path to write proposed pack JSON')
  .option('--model <model>', 'LLM model to use', 'gpt-5.5')
  .option('--api-key <key>', 'API key (defaults to OPENAI_API_KEY)')
  .option('--base-url <url>', 'OpenAI-compatible base URL')
  .option('--existing-pack <path>', 'Existing pack JSON for prompt diffing')
  .action(async (options: any) => {
    const spinner = ora('Drafting proposed rule pack...').start();

    try {
      const manifest = await proposeRules({
        jurisdiction: parseJurisdictionOption(options.jurisdiction),
        sourcePath: options.source,
        sourceUrl: options.sourceUrl,
        outputPath: options.output,
        model: options.model,
        apiKey: options.apiKey,
        baseUrl: options.baseUrl,
        existingPackPath: options.existingPack,
      });

      spinner.succeed(`Proposed pack created for ${manifest.jurisdiction}`);
      console.log(chalk.gray(`  Rules: ${manifest.rules.length}`));
      console.log(chalk.gray(`  Confidence: ${manifest.confidence}`));
      console.log(chalk.gray(`  Output: ${path.resolve(options.output)}`));
    } catch (error: any) {
      spinner.fail('Rule proposal failed');
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

program
  .command('review-pack')
  .description('Review a proposed AI-authored rule pack and emit a validated pack')
  .requiredOption('--proposed <path>', 'Path to proposed pack JSON')
  .requiredOption('--reviewer <name>', 'Reviewer name or identifier')
  .requiredOption('--output <path>', 'Path to write validated pack JSON')
  .option('--approve-all', 'Approve all proposed rules without prompting (requires ATTESTLENS_UNSAFE_TEST_MODE=1)')
  .option('--reject-low-confidence', 'Automatically reject rules with low confidence')
  .action(async (options: any) => {
    // PH11-001: --approve-all requires ATTESTLENS_UNSAFE_TEST_MODE=1 to prevent production bypass
    if (options.approveAll && !process.env.ATTESTLENS_UNSAFE_TEST_MODE) {
      console.error(chalk.red('--approve-all requires ATTESTLENS_UNSAFE_TEST_MODE=1 environment variable'));
      process.exit(2);
    }

    const spinner = options.approveAll ? ora('Compiling validated pack... [UNSAFE TEST MODE]').start() : undefined;

    try {
      const manifest = await reviewPack({
        proposedPath: options.proposed,
        reviewer: options.reviewer,
        outputPath: options.output,
        approveAll: options.approveAll === true,
        rejectLowConfidence: options.rejectLowConfidence === true,
      });

      spinner?.succeed(`Validated pack created for ${manifest.jurisdiction}`);
      console.log(chalk.gray(`  Rules approved: ${manifest.rules.length}`));
      console.log(chalk.gray(`  Reviewer: ${manifest.provenance.reviewedBy}`));
      console.log(chalk.gray(`  Output: ${path.resolve(options.output)}`));
    } catch (error: any) {
      spinner?.fail('Pack review failed');
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

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
      process.exit(2);
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

async function resolveCliDiffContext(target: CliTarget, options: any): Promise<DiffContext | undefined> {
  const hasDiffBase = typeof options.diffBase === 'string' && options.diffBase.trim().length > 0;
  const hasDiffHead = typeof options.diffHead === 'string' && options.diffHead.trim().length > 0;
  const changedFilesOnly = options.changedFilesOnly === true;
  if (!hasDiffBase && !hasDiffHead && !changedFilesOnly) {
    return undefined;
  }
  if (target.kind !== 'path') {
    throw new Error('PR diff mode is only supported for local path scans.');
  }
  if (!hasDiffBase || !hasDiffHead) {
    throw new Error('--diff-base and --diff-head are required for PR diff mode.');
  }

  return buildDiffContext({
    cwd: target.value,
    baseRef: options.diffBase,
    headRef: options.diffHead,
    timeoutMs: parseScannerTimeoutOption(options.scannerTimeout),
  });
}

async function maybeAutoUpdateRules(options: any, quiet = false): Promise<void> {
  if (!options.autoUpdate) {
    return;
  }

  const source = process.env.ATTESTLENS_RULE_SOURCE;
  if (!source) {
    if (!quiet) {
      console.log(chalk.gray('Rule auto-update skipped: ATTESTLENS_RULE_SOURCE is not set. Using cached or embedded rules.'));
    }
    return;
  }

  if (quiet) {
    try {
      await updateRuleCache({ source });
    } catch (error: any) {
      // Machine-readable modes must keep stdout clean; write warning to stderr instead.
      process.stderr.write(`Warning: Rule auto-update failed: ${error.message}. Continuing with cached or embedded rules.\n`);
    }
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

function extractPackCoverage(scanData: Record<string, any>): JurisdictionCoverage | undefined {
  const raw = scanData.packCoverage || scanData.metadata?.packCoverage;
  const parsed = JurisdictionCoverageSchema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

function extractPackValidation(scanData: Record<string, any>): PackValidation | undefined {
  const raw = scanData.packValidation || scanData.metadata?.packValidation;
  const parsed = PackValidationSchema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
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

function parseJurisdictionOption(rawValue: unknown): JurisdictionType {
  const value = rawValue === undefined || rawValue === null || rawValue === ''
    ? 'au-privacy-act'
    : rawValue;
  const result = Jurisdiction.safeParse(value);
  if (!result.success) {
    throw new Error(`Unsupported jurisdiction: ${String(value)}. Valid jurisdictions: ${Jurisdiction.options.join(', ')}`);
  }
  return result.data;
}

function resolveReportJurisdiction(scanData: Record<string, any>, rawValue: unknown): JurisdictionType | undefined {
  if (rawValue !== undefined && rawValue !== null && rawValue !== '') {
    return parseJurisdictionOption(rawValue);
  }

  const direct = Jurisdiction.safeParse(scanData.jurisdiction ?? scanData.metadata?.jurisdiction);
  if (direct.success) {
    return direct.data;
  }

  const controlJurisdictions = new Set<string>();
  for (const control of scanData.regulationControls || []) {
    if (typeof control?.jurisdiction === 'string') {
      controlJurisdictions.add(control.jurisdiction);
    }
  }
  if (controlJurisdictions.size === 1) {
    const parsed = Jurisdiction.safeParse([...controlJurisdictions][0]);
    if (parsed.success) {
      return parsed.data;
    }
  }

  const findingJurisdictions = new Set<string>();
  const findings = Array.isArray(scanData.findings)
    ? scanData.findings
    : Array.isArray(scanData)
      ? scanData
      : [];
  for (const finding of findings) {
    for (const mapping of finding?.regulationMappings || []) {
      if (typeof mapping?.jurisdiction === 'string') {
        findingJurisdictions.add(mapping.jurisdiction);
      }
    }
  }
  if (findingJurisdictions.size === 1) {
    const parsed = Jurisdiction.safeParse([...findingJurisdictions][0]);
    if (parsed.success) {
      return parsed.data;
    }
  }

  return undefined;
}

function assertJurisdictionAvailableForCli(jurisdiction: JurisdictionType): void {
  Jurisdiction.parse(jurisdiction);
}

function getJurisdictionAssessmentLabel(jurisdiction: JurisdictionType): string {
  if (jurisdiction === 'us-ccpa') {
    return 'CCPA';
  }
  if (jurisdiction === 'eu-gdpr') {
    return 'GDPR';
  }
  if (jurisdiction === 'sg-pdpa') {
    return 'SG PDPA';
  }
  return 'AU Privacy Act';
}

type EffectiveControl = ComplianceReport['appControls'][number] | RegulationControl;

export function getEffectiveControls(
  report: ComplianceReport,
  jurisdiction: JurisdictionType,
): EffectiveControl[] {
  if (jurisdiction === 'au-privacy-act') {
    return report.appControls;
  }

  return (report.regulationControls || [])
    .filter((control) => control.jurisdiction === jurisdiction);
}

function inferQuestionnaireJurisdiction(
  principles: string[] | undefined,
  fallback: JurisdictionType = 'au-privacy-act',
): JurisdictionType {
  if (principles?.some((principle) => principle.startsWith('CCPA_'))) {
    return 'us-ccpa';
  }
  if (principles?.some((principle) => principle.startsWith('GDPR_'))) {
    return 'eu-gdpr';
  }
  if (principles?.some((principle) => principle.startsWith('SGPDPA_'))) {
    return 'sg-pdpa';
  }
  return fallback;
}

export function buildScannerOrchestratorOptions(options: any): ScannerOrchestratorOptions {
  const externalEnrichment = options.externalEnrichment === true;
  const scannerTimeoutMs = parseScannerTimeoutOption(options.scannerTimeout);
  const jurisdiction = parseJurisdictionOption(options.jurisdiction);
  return {
    ...(scannerTimeoutMs !== undefined ? { adapterTimeoutMs: scannerTimeoutMs } : {}),
    jurisdictions: [jurisdiction],
    supplyChain: {
      typosquat: { enabled: options.includeTyposquat === true },
      osv: { enabled: externalEnrichment },
      registry: { enabled: externalEnrichment },
    },
    behavioral: {
      enabled: options.behavioral !== false,
    },
    iac: {
      enabled: options.iac !== false,
    },
    gitleaks: {
      enabled: options.includeGitleaks === true,
      path: options.gitleaksPath || 'gitleaks',
    },
    reform: {
      enabled: options.reform === true,
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
  if (options.behavioral === false) orchestrator.disable('behavioral');
  if (options.iac === false) orchestrator.disable('iac');
  if (options.includeGitleaks === true) orchestrator.enable('gitleaks');
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

type SMBOutputFormat = 'json' | 'html' | 'markdown';

function parseSMBOutputFormats(rawFormats: string): SMBOutputFormat[] {
  const formats = rawFormats
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean);

  if (formats.length === 0) {
    throw new Error('At least one report format is required');
  }

  const normalized = new Set<SMBOutputFormat>();
  for (const format of formats) {
    switch (format) {
      case 'json':
      case 'html':
      case 'markdown':
        normalized.add(format);
        break;
      case 'md':
        normalized.add('markdown');
        break;
      case 'smb':
        normalized.add('html');
        normalized.add('markdown');
        break;
      default:
        throw new Error(`Unsupported compliance-check format: ${format}`);
    }
  }

  return Array.from(normalized);
}

function deriveSMBQuestionnairePrinciples(report: ComplianceReport): APPPrinciple[] {
  return report.appControls
    .filter((control) => control.status === 'unknown')
    .map((control) => control.principle);
}

function getSMBQuestionsForReport(report: ComplianceReport): Question[] {
  const principles = new Set<string>(deriveSMBQuestionnairePrinciples(report));
  return SMB_QUESTIONS.filter((question) => principles.has(question.regulationPrinciple));
}

async function promptSMBQuestion(question: Question, index: number, total: number): Promise<QuestionnaireResponse> {
  console.log('');
  console.log(chalk.bold.cyan(`Business question ${index + 1} of ${total}`));
  if (question.helpText) {
    console.log(chalk.gray(question.helpText));
  }

  const answer = await select<boolean>({
    message: question.question,
    choices: [
      { name: 'Yes', value: true },
      { name: 'No', value: false },
    ],
  });
  const response: QuestionnaireResponse = {
    questionId: question.id,
    answer,
    timestamp: new Date().toISOString(),
  };

  return {
    ...response,
    evaluation: evaluateResponse(question, response),
  };
}

async function runSMBQuestionnaire(params: {
  preliminaryReport: ComplianceReport;
  target: CliTarget;
  findings: AttestLensFinding[];
  strictMode: boolean;
}): Promise<QuestionnaireSession | undefined> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Compliance check questions require an interactive terminal. Use --non-interactive for scan-only assessment.');
  }

  const questions = getSMBQuestionsForReport(params.preliminaryReport);
  if (questions.length === 0) {
    return undefined;
  }

  console.log('');
  console.log(chalk.bold.cyan('Business Questions'));
  console.log(chalk.gray('Answer yes or no so the report can include business processes the scan cannot see.'));

  const responses: QuestionnaireResponse[] = [];
  for (const [index, question] of questions.entries()) {
    responses.push(await promptSMBQuestion(question, index, questions.length));
  }

  const assessmentMode: AssessmentMode = 'operator_attested';
  const principles = Array.from(new Set(questions.map((question) => question.regulationPrinciple)));
  const initialPrincipleResults = aggregatePrincipleResults(principles, [], questions, assessmentMode);
  const principleResults = aggregatePrincipleResults(principles, responses, questions, assessmentMode);
  const session = createQuestionnaireSession({
    target: toSessionTarget(params.target),
    strictMode: params.strictMode,
    scanSnapshotPath: '',
    findingsHash: buildFindingsHash(params.findings),
    questionnaireVersion: SMB_QUESTIONNAIRE_VERSION,
    principles,
    sessionQuestions: questions,
    principleResults: initialPrincipleResults,
    assessmentMode,
  });

  return completeQuestionnaireSession(session, responses, principleResults);
}

function getSMBComplianceResult(
  report: ComplianceReportWithSMB,
  questionnaireSession?: QuestionnaireSession,
): SMBComplianceResult {
  if (!report.smbCompliance) {
    report.smbCompliance = buildSMBComplianceResult(report, questionnaireSession);
  }

  return report.smbCompliance;
}

function toPublicSMBComplianceJSON(result: SMBComplianceResult): Record<string, unknown> {
  return {
    ...result,
    actions: result.actions.map(({ principle: _principle, ...action }) => action),
  };
}

async function writeSMBComplianceFiles(
  report: ComplianceReportWithSMB,
  reportOptions: ReportOptions,
  outputFormats: SMBOutputFormat[],
  questionnaireSession?: QuestionnaireSession,
): Promise<Array<{ label: string; path: string }>> {
  const outputDir = path.resolve(reportOptions.outputDir);
  await fs.mkdir(outputDir, { recursive: true });

  const filename = `${buildReportFilename(reportOptions.targetName, report.timestamp)}-compliance-check`;
  const result = getSMBComplianceResult(report, questionnaireSession);
  const outputs: Array<{ label: string; path: string }> = [];

  for (const format of outputFormats) {
    switch (format) {
      case 'html': {
        const filePath = path.join(outputDir, `${filename}.html`);
        await fs.writeFile(filePath, generateSMBHTMLReport(result));
        outputs.push({ label: 'Compliance check HTML', path: filePath });
        break;
      }
      case 'markdown': {
        const filePath = path.join(outputDir, `${filename}.md`);
        await fs.writeFile(filePath, generateSMBMarkdownReport(result));
        outputs.push({ label: 'Compliance check Markdown', path: filePath });
        break;
      }
      case 'json': {
        const filePath = path.join(outputDir, `${filename}.json`);
        await fs.writeFile(filePath, JSON.stringify(toPublicSMBComplianceJSON(result), null, 2));
        outputs.push({ label: 'Compliance check JSON', path: filePath });
        break;
      }
    }
  }

  return outputs;
}

function formatOutputDirForDisplay(outputDir: string): string {
  const relative = path.relative(process.cwd(), outputDir);
  if (!relative) {
    return '.';
  }
  return relative.startsWith('..') ? outputDir : relative;
}

function colorReadiness(result: SMBComplianceResult): string {
  const label = `${result.readinessScore}/100 — ${result.readinessLabel}`;
  switch (result.readinessLabel) {
    case 'Ready':
      return chalk.green(label);
    case 'Nearly Ready':
      return chalk.yellow(label);
    case 'Needs Work':
      return chalk.hex('#f4a261')(label);
    case 'Not Ready':
      return chalk.red(label);
    case 'Unknown':
    default:
      return chalk.gray(label);
  }
}

function colorPriority(priority: SMBComplianceResult['actions'][number]['priority']): string {
  switch (priority) {
    case 'urgent':
      return chalk.red(priority);
    case 'high':
      return chalk.hex('#f4a261')(priority);
    case 'medium':
      return chalk.yellow(priority);
    case 'low':
    default:
      return chalk.cyan(priority);
  }
}

function displaySMBTerminalSummary(
  result: SMBComplianceResult,
  reportPaths: Array<{ label: string; path: string }>,
  outputDir: string,
): void {
  console.log('');
  console.log(`${result.readinessLabel === 'Ready' ? '✅' : '⚠️'} Compliance Readiness: ${colorReadiness(result)}`);
  console.log('');
  console.log(result.summary);

  const topActions = result.actions.slice(0, 3);
  console.log(chalk.bold('\n⚡ Top Actions:'));
  if (topActions.length === 0) {
    console.log(chalk.green('  No priority actions found.'));
  } else {
    topActions.forEach((action, index) => {
      console.log(`  ${index + 1}. ${action.title} (${colorPriority(action.priority)})`);
    });
  }

  console.log(chalk.bold(`\n🔍 ${result.gaps.length} gap${result.gaps.length === 1 ? '' : 's'} need investigation`));
  const reformCount = result.reformWarnings?.length || 0;
  if (reformCount > 0) {
    console.log(chalk.bold(`⚠️  ${reformCount} upcoming law change${reformCount === 1 ? '' : 's'} may affect you`));
  }

  console.log('');
  for (const output of reportPaths) {
    console.log(chalk.green(`  📄 ${output.label}: ${output.path}`));
  }
  console.log(chalk.green(`\nReport saved to ${formatOutputDirForDisplay(outputDir)}/`));
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
  const parsedJurisdiction = Jurisdiction.safeParse(normalizedScanData.jurisdiction);

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
      jurisdiction: parsedJurisdiction.success ? parsedJurisdiction.data : undefined,
      packCoverage: extractPackCoverage(normalizedScanData),
      packValidation: extractPackValidation(normalizedScanData),
      packValidationTrusted: false,
    },
  };
}

function getReportOptionsForSession(
  sessionTarget: SessionTarget,
  formats: ReportFormat[],
  outputDir: string,
  strictMode: boolean,
  ruleFreshness?: RuleFreshnessMetadata,
  jurisdiction: JurisdictionType = 'au-privacy-act',
  packCoverage?: JurisdictionCoverage,
  packValidation?: PackValidation,
  packValidationTrusted?: boolean,
): ReportOptions {
  return {
    targetName: sessionTarget.name,
    targetPath: sessionTarget.kind === 'path' ? sessionTarget.path : undefined,
    targetUrl: sessionTarget.kind === 'url' ? sessionTarget.url : undefined,
    formats,
    outputDir,
    strictMode,
    ruleFreshness,
    jurisdiction,
    packCoverage,
    packValidation,
    packValidationTrusted,
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
  let jurisdiction = parseJurisdictionOption(options.jurisdiction);
  assertJurisdictionAvailableForCli(jurisdiction);

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
    jurisdiction = snapshot.jurisdiction ?? inferQuestionnaireJurisdiction(
      'principles' in loadedSession ? loadedSession.principles : undefined,
      jurisdiction,
    );
    const expectedPrinciples = deriveQuestionnairePrinciples(snapshot.findings, jurisdiction);
    const expectedQuestions = buildFrozenSessionQuestions(expectedPrinciples, getQuestionBankForJurisdiction(jurisdiction));
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
    jurisdiction = snapshot.jurisdiction ?? jurisdiction;
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
      jurisdiction,
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
      jurisdiction,
      packCoverage: scanResult.jurisdictionManifests?.[jurisdiction]?.coverage,
      packValidation: scanResult.jurisdictionManifests?.[jurisdiction]?.validation,
      packValidationTrusted: scanResult.ruleFreshness.source === 'embedded',
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
      jurisdiction,
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
    jurisdiction,
    snapshot.packCoverage,
    snapshot.packValidation,
    snapshot.packValidationTrusted,
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
  const supported = new Set<ReportFormat>(SUPPORTED_REPORT_FORMATS);
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

  if (formats.includes('agent') && formats.length > 1) {
    throw new Error('The agent report format must be requested by itself');
  }

  return formats as ReportFormat[];
}

function isAgentReportFormat(formats: ReportFormat[]): boolean {
  return formats.length === 1 && formats[0] === 'agent';
}

function isSarifRequested(rawFormats: string): boolean {
  const formats = rawFormats
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  return formats.includes('sarif');
}

type FailureSeverityThreshold = 'error' | 'warning' | 'note';

interface FailureControlOptions {
  threshold: FailureSeverityThreshold;
  noFail: boolean;
}

function parseFailureControlOptions(options: { failOnSeverity?: unknown; fail?: boolean }): FailureControlOptions {
  const rawThreshold = String(options.failOnSeverity ?? 'error').trim().toLowerCase();
  if (rawThreshold !== 'error' && rawThreshold !== 'warning' && rawThreshold !== 'note') {
    throw new Error(`Unsupported fail severity: ${String(options.failOnSeverity)}. Valid values: error, warning, note`);
  }

  return {
    threshold: rawThreshold,
    noFail: options.fail === false,
  };
}

function determineExitCode(findings: AttestLensFinding[], options: FailureControlOptions): number {
  if (options.noFail) {
    return 0;
  }

  return hasFindingsAtOrAboveThreshold(findings, options.threshold) ? 1 : 0;
}

function determineSarifExitCode(sarif: SarifOutput, options: FailureControlOptions): number {
  if (options.noFail) {
    return 0;
  }

  const thresholdRank = getSarifLevelRank(options.threshold);
  const failsThreshold = sarif.runs.some((run) => (
    run.results.some((result) => getSarifLevelRank(result.level) <= thresholdRank)
  ));
  return failsThreshold ? 1 : 0;
}

export function hasFindingsAtOrAboveThreshold(
  findings: AttestLensFinding[],
  threshold: FailureSeverityThreshold,
): boolean {
  const thresholdRank = getSarifLevelRank(threshold);
  return findings.some((finding) => getSarifLevelRank(mapFindingSeverityToSarifLevel(finding.severity)) <= thresholdRank);
}

function getSarifLevelRank(level: FailureSeverityThreshold): number {
  switch (level) {
    case 'error':
      return 0;
    case 'warning':
      return 1;
    case 'note':
      return 2;
  }
}

async function emitSarifOutput(payload: unknown, outputPath?: string, allowedOutputDir?: string): Promise<void> {
  const content = `${JSON.stringify(payload, null, 2)}\n`;
  if (!outputPath) {
    process.stdout.write(content);
    return;
  }

  const resolvedOutputPath = resolveSarifOutputPath(outputPath, allowedOutputDir);
  await fs.mkdir(path.dirname(resolvedOutputPath), { recursive: true });
  await fs.writeFile(resolvedOutputPath, content, 'utf-8');
}

function resolveSarifOutputPath(outputPath: string, allowedOutputDir?: string): string {
  const cwd = process.cwd();
  const resolvedOutputPath = path.resolve(cwd, outputPath);
  const allowedRoots = [cwd];
  if (allowedOutputDir) {
    allowedRoots.push(path.resolve(allowedOutputDir));
  }

  if (allowedRoots.some((root) => isPathWithinRoot(resolvedOutputPath, root))) {
    return resolvedOutputPath;
  }

  throw new Error('SARIF output path must be within the current working directory or the configured output directory.');
}

function isPathWithinRoot(candidatePath: string, rootPath: string): boolean {
  const relative = path.relative(rootPath, candidatePath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function displayClientMutationResults(
  results: Array<{
    client: SupportedClient;
    configPath: string;
    changed: boolean;
    backupPath?: string;
    dryRun: boolean;
  }>,
  action: 'install' | 'uninstall',
): void {
  if (results.length === 0) {
    console.log(chalk.yellow('No client configs matched.'));
    return;
  }

  for (const result of results) {
    const verb = action === 'install' ? 'Configured' : 'Removed';
    const suffix = result.changed ? '' : ' (no changes)';
    const prefix = result.dryRun ? '[dry-run] ' : '';
    console.log(`${prefix}${verb} ${result.client}: ${result.configPath}${suffix}`);
    if (result.backupPath) {
      console.log(chalk.gray(`  backup: ${result.backupPath}`));
    }
  }
}

type ReformOutputFormat = 'json' | 'html' | 'markdown';

function parseReformOutputFormats(rawFormats: string): ReformOutputFormat[] {
  const formats = rawFormats
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean);

  if (formats.length === 0) {
    throw new Error('At least one reform output format is required');
  }

  const normalized = new Set<ReformOutputFormat>();
  for (const format of formats) {
    switch (format) {
      case 'json':
      case 'html':
      case 'markdown':
        normalized.add(format);
        break;
      case 'md':
        normalized.add('markdown');
        break;
      default:
        throw new Error(`Unsupported reform format: ${format}`);
    }
  }

  return Array.from(normalized);
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
  report: ComplianceReportWithSMB,
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
      case 'smb': {
        const smbResult = getSMBComplianceResult(report, questionnaireSession);
        const markdownPath = path.join(outputDir, `${filename}-compliance-check.md`);
        const htmlPath = path.join(outputDir, `${filename}-compliance-check.html`);
        await fs.writeFile(markdownPath, generateSMBMarkdownReport(smbResult));
        await fs.writeFile(htmlPath, generateSMBHTMLReport(smbResult));
        outputs.push({ label: 'Compliance check Markdown', path: markdownPath });
        outputs.push({ label: 'Compliance check HTML', path: htmlPath });
        break;
      }
      case 'agent':
      case 'sarif':
        break;
    }
  }

  return outputs;
}

async function writeReformAssessmentFiles(
  assessment: ReformImpactAssessment,
  targetName: string,
  timestamp: string,
  outputDir: string,
  outputFormats: ReformOutputFormat[],
): Promise<Array<{ label: string; path: string }>> {
  const resolvedOutputDir = path.resolve(outputDir);
  await fs.mkdir(resolvedOutputDir, { recursive: true });

  const filename = `${buildReportFilename(targetName, timestamp)}-reform`;
  const outputs: Array<{ label: string; path: string }> = [];

  for (const format of outputFormats) {
    switch (format) {
      case 'json': {
        const filePath = path.join(resolvedOutputDir, `${filename}.json`);
        await fs.writeFile(filePath, JSON.stringify(assessment, null, 2));
        outputs.push({ label: 'Reform assessment JSON', path: filePath });
        break;
      }
      case 'markdown': {
        const filePath = path.join(resolvedOutputDir, `${filename}.md`);
        await fs.writeFile(filePath, generateReformAssessmentMarkdown(assessment, targetName));
        outputs.push({ label: 'Reform assessment Markdown', path: filePath });
        break;
      }
      case 'html': {
        const filePath = path.join(resolvedOutputDir, `${filename}.html`);
        await fs.writeFile(filePath, generateReformAssessmentHTML(assessment, targetName));
        outputs.push({ label: 'Reform assessment HTML', path: filePath });
        break;
      }
    }
  }

  return outputs;
}

function generateReformAssessmentMarkdown(
  assessment: ReformImpactAssessment,
  targetName: string,
): string {
  const lines: string[] = [
    `# Reform Impact Assessment — ${targetName}`,
    '',
    `- **Overall Impact:** ${assessment.overallImpact.toUpperCase()}`,
    `- **Assessment Date:** ${assessment.assessmentDate}`,
    '',
    assessment.disclaimer,
    '',
    '## Provisions',
    '',
  ];

  for (const provision of assessment.provisions) {
    lines.push(`### ${provision.shortName}`);
    lines.push(`- **Provision:** ${provision.provision}`);
    lines.push(`- **Status:** ${provision.status}`);
    lines.push(`- **Effective Date:** ${provision.effectiveDate}`);
    lines.push(`- **Findings:** ${provision.findingCount}`);
    lines.push('');
    lines.push(provision.summary);
    lines.push('');

    if (provision.findings.length === 0) {
      lines.push('No reform-specific findings detected.');
      lines.push('');
      continue;
    }

    for (const finding of provision.findings) {
      lines.push(`- **${finding.id}** ${finding.title} (${finding.severity})`);
      lines.push(`  ${finding.description}`);
      if (finding.file) {
        lines.push(`  File: ${finding.file}${finding.line ? `:${finding.line}` : ''}`);
      }
      if (finding.remediation) {
        lines.push(`  Remediation: ${finding.remediation}`);
      }
    }
    lines.push('');
  }

  lines.push('## Action Items');
  lines.push('');
  if (assessment.actionItems.length === 0) {
    lines.push('No action items.');
  } else {
    for (const actionItem of assessment.actionItems) {
      lines.push(`- **${actionItem.title}** (${actionItem.priority}, deadline ${actionItem.deadline})`);
      lines.push(`  ${actionItem.description}`);
    }
  }

  return `${lines.join('\n')}\n`;
}

function generateReformAssessmentHTML(
  assessment: ReformImpactAssessment,
  targetName: string,
): string {
  const escapeHtml = (value: string): string => value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Reform Impact Assessment — ${escapeHtml(targetName)}</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 40px; color: #1f2933; background: #f8fafc; }
    main { max-width: 960px; margin: 0 auto; background: #fff; border-radius: 16px; padding: 32px; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08); }
    h1, h2, h3 { color: #102a43; }
    .meta { color: #486581; margin-bottom: 24px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #d9e2ec; font-weight: 700; }
    .provision { border-top: 1px solid #e5e7eb; padding-top: 20px; margin-top: 20px; }
    .finding { background: #f8fafc; border-radius: 12px; padding: 16px; margin-top: 12px; }
  </style>
</head>
<body>
  <main>
    <h1>Reform Impact Assessment — ${escapeHtml(targetName)}</h1>
    <p class="meta"><strong>Overall Impact:</strong> <span class="badge">${escapeHtml(assessment.overallImpact.toUpperCase())}</span> · <strong>Assessment Date:</strong> ${escapeHtml(assessment.assessmentDate)}</p>
    <p>${escapeHtml(assessment.disclaimer)}</p>
    <h2>Provisions</h2>
    ${assessment.provisions.map((provision) => `
      <section class="provision">
        <h3>${escapeHtml(provision.shortName)}</h3>
        <p><strong>Provision:</strong> ${escapeHtml(provision.provision)}<br />
        <strong>Status:</strong> ${escapeHtml(provision.status)}<br />
        <strong>Effective Date:</strong> ${escapeHtml(provision.effectiveDate)}<br />
        <strong>Findings:</strong> ${provision.findingCount}</p>
        <p>${escapeHtml(provision.summary)}</p>
        ${provision.findings.length === 0 ? '<p>No reform-specific findings detected.</p>' : provision.findings.map((finding) => `
          <article class="finding">
            <strong>${escapeHtml(finding.id)}</strong> ${escapeHtml(finding.title)} (${escapeHtml(finding.severity)})</br>
            <p>${escapeHtml(finding.description)}</p>
            ${finding.file ? `<p><strong>File:</strong> ${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ''}</p>` : ''}
            ${finding.remediation ? `<p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>` : ''}
          </article>
        `).join('')}
      </section>
    `).join('')}
    <h2>Action Items</h2>
    ${assessment.actionItems.length === 0 ? '<p>No action items.</p>' : `<ul>${assessment.actionItems.map((actionItem) => `
      <li><strong>${escapeHtml(actionItem.title)}</strong> (${escapeHtml(actionItem.priority)}, deadline ${escapeHtml(actionItem.deadline)}) — ${escapeHtml(actionItem.description)}</li>
    `).join('')}</ul>`}
  </main>
</body>
</html>`;
}

function displayReformTerminalSummary(
  assessment: ReformImpactAssessment,
  reportPaths: Array<{ label: string; path: string }>,
  outputDir: string,
): void {
  console.log('');
  console.log(`Overall Impact: ${assessment.overallImpact.toUpperCase()}`);
  console.log(`Assessment Date: ${assessment.assessmentDate}`);
  console.log('');

  for (const provision of assessment.provisions) {
    console.log(chalk.bold(`${provision.shortName} (${provision.status})`));
    console.log(`  Effective: ${provision.effectiveDate}`);
    console.log(`  Findings: ${provision.findingCount}`);
    console.log(`  ${provision.summary}`);
  }

  console.log(chalk.bold('\nAction Items:'));
  if (assessment.actionItems.length === 0) {
    console.log('  No action items.');
  } else {
    assessment.actionItems.forEach((actionItem, index) => {
      console.log(`  ${index + 1}. ${actionItem.title} [${actionItem.priority}] (${actionItem.deadline})`);
      console.log(`     ${actionItem.description}`);
    });
  }

  console.log('');
  for (const output of reportPaths) {
    console.log(chalk.green(`  📄 ${output.label}: ${output.path}`));
  }
  console.log(chalk.green(`\nReform assessment saved to ${formatOutputDirForDisplay(outputDir)}/`));
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
  try {
    await program.parseAsync();
  } catch (error: any) {
    if (error instanceof CommanderError) {
      const exitCode = error.exitCode === 0 ? 0 : 2;
      if (error.code !== 'commander.helpDisplayed' && error.code !== 'commander.version') {
        if (error.message) {
          process.stderr.write(`${error.message}\n`);
        }
      }
      process.exit(exitCode);
    }
    console.error(chalk.red(`Error: ${error.message}`));
    process.exit(2);
  }
}
