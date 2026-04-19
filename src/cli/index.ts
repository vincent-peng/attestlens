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

import { ScannerOrchestrator } from '../scanner/orchestrator.js';
import { mapAllFindings } from '../mapping/engine.js';
import { buildComplianceReport, generateHTMLReport, generateJSONReport, generateMarkdownReport } from '../report/generator.js';
import type { ReportOptions } from '../report/generator.js';

const program = new Command();

program
  .name('attestlens')
  .description('AI Compliance Scanner & Privacy Act Attestation Tool')
  .version('0.1.0');

// ─── Scan Command ─────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan a project directory or URL for privacy compliance findings')
  .argument('<path>', 'Path to project directory or URL (https://...)')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown)', 'json,html')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .option('--url-only', 'Only run URL scanner (skip file-based scanners)')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .action(async (targetPath: string, options: any) => {
    console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Scanner\n'));

    // Detect if input is a URL
    const isUrl = /^https?:\/\//i.test(targetPath);

    if (isUrl) {
      // URL mode: enable URL scanner, optionally disable file-based scanners
      const orchestrator = new ScannerOrchestrator();
      if (!options.urlOnly) {
        // File-based scanners will fail gracefully for URLs
        orchestrator.disable('guardvibe');
        orchestrator.disable('mcp-scan');
        orchestrator.disable('supply-chain');
      } else {
        orchestrator.disable('guardvibe');
        orchestrator.disable('mcp-scan');
        orchestrator.disable('supply-chain');
      }

      const spinner = ora(`Scanning URL: ${targetPath}`).start();
      const startTime = Date.now();

      try {
        const result = await orchestrator.scan(targetPath);
        const duration = Date.now() - startTime;
        spinner.succeed(`URL scan complete in ${(duration / 1000).toFixed(1)}s`);

        const findings = result.findings;
        if (findings.length === 0) {
          console.log(chalk.green('\n✅ No compliance findings detected.'));
          console.log(chalk.gray('   Run `attestlens audit` for a full APP control assessment.'));
          return;
        }

        console.log(chalk.yellow(`\n⚠ Found ${findings.length} finding${findings.length > 1 ? 's' : ''}:\n`));
        displayFindings(findings);

        const { controls: appControls } = mapAllFindings(findings);
        const affectedPrinciples = appControls
          .filter(c => c.status !== 'unknown' || c.findings.length > 0)
          .map(c => c.principle);
        console.log(chalk.cyan(`\n📋 Affected APP Principles: ${affectedPrinciples.join(', ')}`));
        console.log(chalk.gray(`   Run \`attestlens audit ${targetPath}\` for a full compliance report.`));

      } catch (error: any) {
        spinner.fail('URL scan failed');
        console.error(chalk.red(`\nError: ${error.message}`));
        process.exit(1);
      }
      return;
    }

    // Directory mode (existing behavior)
    const resolvedPath = path.resolve(targetPath);
    try {
      const stat = await fs.stat(resolvedPath);
      if (!stat.isDirectory()) {
        console.error(chalk.red(`Error: ${resolvedPath} is not a directory`));
        process.exit(1);
      }
    } catch {
      console.error(chalk.red(`Error: ${resolvedPath} does not exist`));
      process.exit(1);
    }

    // Setup orchestrator
    const orchestrator = new ScannerOrchestrator();
    if (options.noGuardvibe) orchestrator.disable('guardvibe');
    if (options.noMcpScan) orchestrator.disable('mcp-scan');
    if (options.noSupplyChain) orchestrator.disable('supply-chain');

    // Run scan
    const spinner = ora('Scanning project...').start();
    const startTime = Date.now();

    try {
      const result = await orchestrator.scan(resolvedPath);
      const duration = Date.now() - startTime;

      spinner.succeed(`Scan complete in ${(duration / 1000).toFixed(1)}s`);

      // Display findings
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
      console.log(chalk.gray(`   Run \`attestlens audit ${targetPath}\` for a full compliance report.`));

    } catch (error: any) {
      spinner.fail('Scan failed');
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Audit Command ────────────────────────────────────────────────────────────

program
  .command('audit')
  .description('Full compliance audit — scan + generate APP/NDB report')
  .argument('<path>', 'Path to project directory')
  .option('-n, --name <name>', 'Project name', '')
  .option('-o, --output <dir>', 'Output directory', './attestlens-reports')
  .option('-f, --format <formats>', 'Output formats (json,html,markdown)', 'html,json')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .option('--no-guardvibe', 'Disable GuardVibe scanner')
  .option('--no-mcp-scan', 'Disable mcp-scan')
  .option('--no-supply-chain', 'Disable supply chain scanner')
  .action(async (targetPath: string, options: any) => {
    console.log(chalk.bold.cyan('\n🔍 AttestLens — Privacy Act Compliance Audit\n'));

    const resolvedPath = path.resolve(targetPath);
    const projectName = options.name || path.basename(resolvedPath);

    // Setup orchestrator
    const orchestrator = new ScannerOrchestrator();
    if (options.noGuardvibe) orchestrator.disable('guardvibe');
    if (options.noMcpScan) orchestrator.disable('mcp-scan');
    if (options.noSupplyChain) orchestrator.disable('supply-chain');

    // Run scan
    const spinner = ora('Running compliance scan...').start();
    const startTime = Date.now();

    try {
      const scanResult = await orchestrator.scan(resolvedPath);
      const duration = Date.now() - startTime;

      // Build report (mapAllFindings is called inside buildComplianceReport)
      const reportFormats = options.format.split(',') as Array<'json' | 'html' | 'markdown'>;
      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath: resolvedPath,
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
      const outputDir = path.resolve(options.output);
      await fs.mkdir(outputDir, { recursive: true });

      for (const format of reportFormats) {
        const filename = `attestlens-report-${projectName.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}`;
        
        switch (format) {
          case 'html': {
            const html = generateHTMLReport(report, reportOptions);
            const htmlPath = path.join(outputDir, `${filename}.html`);
            await fs.writeFile(htmlPath, html);
            console.log(chalk.green(`  📄 HTML report: ${htmlPath}`));
            break;
          }
          case 'json': {
            const json = generateJSONReport(report);
            const jsonPath = path.join(outputDir, `${filename}.json`);
            await fs.writeFile(jsonPath, json);
            console.log(chalk.green(`  📄 JSON report: ${jsonPath}`));
            break;
          }
          case 'markdown': {
            const md = generateMarkdownReport(report);
            const mdPath = path.join(outputDir, `${filename}.md`);
            await fs.writeFile(mdPath, md);
            console.log(chalk.green(`  📄 Markdown report: ${mdPath}`));
            break;
          }
        }
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
      spinner.fail('Audit failed');
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
  .option('-f, --format <formats>', 'Output formats', 'html,json,markdown')
  .option('-n, --name <name>', 'Project name', '')
  .option('--strict', 'Treat UNKNOWN controls as FAIL')
  .action(async (filePath: string, options: any) => {
    const resolvedPath = path.resolve(filePath);
    
    try {
      const data = await fs.readFile(resolvedPath, 'utf-8');
      const scanData = JSON.parse(data);
      
      const reportFormats = options.format.split(',') as Array<'json' | 'html' | 'markdown'>;
      const projectName = options.name || path.basename(resolvedPath, '.json');

      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath: resolvedPath,
        formats: reportFormats,
        outputDir: path.resolve(options.output),
        strictMode: options.strict,
      };

      const report = buildComplianceReport(scanData.findings || scanData, reportOptions, 0);

      const outputDir = path.resolve(options.output);
      await fs.mkdir(outputDir, { recursive: true });

      for (const format of reportFormats) {
        const filename = `attestlens-report-${projectName.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}`;
        
        switch (format) {
          case 'html': {
            await fs.writeFile(path.join(outputDir, `${filename}.html`), generateHTMLReport(report, reportOptions));
            break;
          }
          case 'json': {
            await fs.writeFile(path.join(outputDir, `${filename}.json`), generateJSONReport(report));
            break;
          }
          case 'markdown': {
            await fs.writeFile(path.join(outputDir, `${filename}.md`), generateMarkdownReport(report));
            break;
          }
        }
      }

      console.log(chalk.green('✅ Report generated successfully.'));
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// ─── Helpers ──────────────────────────────────────────────────────────────────

// ─── Helpers ──────────────────────────────────────────────────────────────────

function displayFindings(findings: any[]) {
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

program.parse();