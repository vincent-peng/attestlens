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

import { ScannerOrchestrator } from '../scanner/orchestrator.js';
import { mapAllFindings } from '../mapping/engine.js';
import {
  buildComplianceReport,
  generateHTMLReport,
  generateJSONReport,
  generateMarkdownReport,
  generatePDFReport,
} from '../report/generator.js';
import type { AttestLensFinding } from '../schema/index.js';
import type { ReportFormat, ReportOptions } from '../report/generator.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
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
  .action(async (targetInput: string, options: any) => {
    console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Scanner\n'));

    try {
      const target = await resolveCliTarget(targetInput, options.name);
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
  .action(async (targetInput: string, options: any) => {
    console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Audit\n'));

    try {
      const target = await resolveCliTarget(targetInput, options.name);
      const projectName = target.name;
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

      // Show errors if any
      if (scanResult.errors.length > 0) {
        console.log(chalk.yellow('\n⚠ Scanner warnings:'));
        for (const error of scanResult.errors) {
          console.log(chalk.yellow(`  ${error.source}: ${error.message}`));
        }
      }

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
      };

      const report = buildComplianceReport(scanData.findings || scanData, reportOptions, 0);
      await writeReportFiles(report, reportOptions);

      console.log(chalk.green('✅ Report generated successfully.'));
    } catch (error: any) {
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

function createOrchestrator(targetKind: CliTarget['kind'], options: any): ScannerOrchestrator {
  const orchestrator = new ScannerOrchestrator();

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

async function writeReportFiles(report: any, reportOptions: ReportOptions): Promise<Array<{ label: string; path: string }>> {
  const outputDir = path.resolve(reportOptions.outputDir);
  await fs.mkdir(outputDir, { recursive: true });

  const filename = buildReportFilename(reportOptions.targetName, report.timestamp);
  const outputs: Array<{ label: string; path: string }> = [];

  for (const format of reportOptions.formats) {
    const filePath = path.join(outputDir, `${filename}.${format === 'markdown' ? 'md' : format}`);

    switch (format) {
      case 'html':
        await fs.writeFile(filePath, generateHTMLReport(report, reportOptions));
        outputs.push({ label: 'HTML report', path: filePath });
        break;
      case 'json':
        await fs.writeFile(filePath, generateJSONReport(report));
        outputs.push({ label: 'JSON report', path: filePath });
        break;
      case 'markdown':
        await fs.writeFile(filePath, generateMarkdownReport(report));
        outputs.push({ label: 'Markdown report', path: filePath });
        break;
      case 'pdf':
        await fs.writeFile(filePath, await generatePDFReport(report, reportOptions));
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
