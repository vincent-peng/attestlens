#!/usr/bin/env node
/**
 * AttestLens — MCP Server
 *
 * Exposes AttestLens as an MCP server so AI editors (Cursor, Windsurf, etc.)
 * can run compliance scans directly.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { mapAllFindings } from '../mapping/engine.js';
import {
  buildComplianceReport,
  generateAgentReport,
  generateHTMLReport,
  generateJSONReport,
  generateMarkdownReport,
  generatePDFReport,
} from '../report/generator.js';
import { buildSMBComplianceResult } from '../report/smb-generator.js';
import type { ComplianceReportWithSMB, ReportFormat, ReportOptions } from '../report/generator.js';
import { ScannerOrchestrator, type ScannerOrchestratorOptions } from '../scanner/orchestrator.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import { APPInfo, RuleFreshness as RuleFreshnessSchema } from '../schema/index.js';
import type { APPPrinciple, AttestLensFinding, ReformImpactAssessment } from '../schema/index.js';
import { sanitizeTargetPathForOutput, sanitizeTargetUrlForOutput } from '../utils/target.js';

const ATTESTLENS_VERSION = '0.2.0';

type ToolResponse = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
type ToolErrorResponse = ToolResponse & { isError: true };

const LOCAL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const URL_READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export const MCP_TOOLS = [
  {
    name: 'attestlens_scan',
    title: 'Project Compliance Scan',
    description: 'Scan a project directory for Australian Privacy Act (APP/NDB) compliance findings.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory to scan' },
        strict: { type: 'boolean', description: 'Treat UNKNOWN controls as FAIL', default: false },
        externalEnrichment: {
          type: 'boolean',
          description: 'Enable external OSV.dev and npm registry dependency enrichment',
          default: false,
        },
        includeTyposquat: {
          type: 'boolean',
          description: 'Enable experimental typosquatting detection (VS-SC-004)',
          default: false,
        },
        behavioral: {
          type: 'boolean',
          description: 'Enable behavioral supply-chain analysis',
          default: true,
        },
        iac: {
          type: 'boolean',
          description: 'Enable infrastructure-as-code misconfiguration scanning',
          default: true,
        },
        includeGitleaks: {
          type: 'boolean',
          description: 'Enable opt-in git history secret scanning via gitleaks',
          default: false,
        },
        gitleaksPath: {
          type: 'string',
          description: 'Path to gitleaks binary',
        },
        scannerTimeoutMs: {
          type: 'number',
          description: 'Per-scanner timeout in milliseconds',
        },
      },
      required: ['path'],
    },
    annotations: URL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_scan_url',
    title: 'Live Site Compliance Scan',
    description: 'Scan a public URL for live-site APP/NDB compliance findings.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Public http(s) URL to scan' },
        strict: { type: 'boolean', description: 'Treat UNKNOWN controls as FAIL', default: false },
        scannerTimeoutMs: {
          type: 'number',
          description: 'Per-scanner timeout in milliseconds',
        },
      },
      required: ['url'],
    },
    annotations: URL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_audit',
    title: 'Full Compliance Audit',
    description: 'Full APP/NDB compliance audit. Scans a project, maps findings to Australian Privacy Act obligations, and generates a compliance report.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory to audit' },
        name: { type: 'string', description: 'Project name for the report' },
        format: { type: 'string', enum: ['json', 'html', 'markdown', 'pdf', 'agent'], description: 'Output format', default: 'json' },
        strict: { type: 'boolean', description: 'Treat UNKNOWN controls as FAIL', default: false },
        externalEnrichment: {
          type: 'boolean',
          description: 'Enable external OSV.dev and npm registry dependency enrichment',
          default: false,
        },
        includeTyposquat: {
          type: 'boolean',
          description: 'Enable experimental typosquatting detection (VS-SC-004)',
          default: false,
        },
        behavioral: {
          type: 'boolean',
          description: 'Enable behavioral supply-chain analysis',
          default: true,
        },
        iac: {
          type: 'boolean',
          description: 'Enable infrastructure-as-code misconfiguration scanning',
          default: true,
        },
        includeGitleaks: {
          type: 'boolean',
          description: 'Enable opt-in git history secret scanning via gitleaks',
          default: false,
        },
        gitleaksPath: {
          type: 'string',
          description: 'Path to gitleaks binary',
        },
        scannerTimeoutMs: {
          type: 'number',
          description: 'Per-scanner timeout in milliseconds',
        },
        opinion: {
          type: 'boolean',
          description: 'Include compliance opinion in the audit result',
          default: false,
        },
      },
      required: ['path'],
    },
    annotations: URL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_map',
    title: 'Map Findings to APP/NDB',
    description: 'Map a list of security findings to APP/NDB obligations.',
    inputSchema: {
      type: 'object',
      properties: {
        findings: {
          type: 'array',
          description: 'List of findings to map',
          items: {
            type: 'object',
            properties: {
              source: { type: 'string' },
              sourceRule: { type: 'string' },
              severity: { type: 'string' },
              category: { type: 'string' },
              title: { type: 'string' },
              description: { type: 'string' },
            },
            required: ['source', 'sourceRule', 'severity', 'title'],
          },
        },
      },
      required: ['findings'],
    },
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_opinion',
    title: 'Compliance Opinion',
    description: 'Generate a compliance opinion for a project. Returns a definitive verdict (COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT) with per-principle assessments, confidence levels, and evidence chains. Deterministic — no LLM calls.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory to audit' },
        strict: { type: 'boolean', description: 'Treat UNKNOWN controls as NON_COMPLIANT', default: false },
      },
      required: ['path'],
    },
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_check',
    title: 'Single Principle Compliance Check',
    description: 'Check a single APP principle compliance. Runs a full compliance scan and returns results for a single APP principle. Returns { principle, verdict, score, findings, remediations }.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory' },
        principle: { type: 'string', description: 'APP principle to check (e.g. APP_11)' },
        strict: { type: 'boolean', description: 'Treat UNKNOWN as NON_COMPLIANT', default: false },
      },
      required: ['path', 'principle'],
    },
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_compliance_check',
    title: 'Compliance Check for Australian Businesses',
    description: 'Run a plain-English compliance check for Australian businesses. Scans a project for Privacy Act (APP/NDB) obligations and returns a readiness score, priority actions, compliance gaps, and reform warnings. Non-interactive: always scan-only without questionnaire.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory to check' },
        strict: { type: 'boolean', description: 'Treat unknown controls as failing', default: false },
        reform: { type: 'boolean', description: 'Include Privacy Act 2026 reform impact warnings', default: false },
      },
      required: ['path'],
    },
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
  {
    name: 'attestlens_reform',
    title: 'Privacy Act Reform Impact Assessment',
    description: 'Run a Privacy Act 2026 reform impact assessment. Scans the project for reform-relevant patterns (statutory tort, children\'s privacy code, automated decision-making, AML/CTF) and returns a structured impact assessment with per-provision status, action items with deadlines, and overall impact rating.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory to assess' },
        strict: { type: 'boolean', description: 'Treat UNKNOWN controls as FAIL', default: false },
      },
      required: ['path'],
    },
    annotations: LOCAL_READ_ONLY_ANNOTATIONS,
  },
] as const;

function makeToolError(message: string): ToolErrorResponse {
  return {
    content: [{ type: 'text', text: message }],
    isError: true,
  };
}

function isToolError(value: unknown): value is ToolErrorResponse {
  return typeof value === 'object' && value !== null && (value as ToolResponse).isError === true;
}

function getAllowedRoots(): string[] {
  if (!process.env.ATTESTLENS_ALLOWED_ROOTS) {
    return [process.cwd()];
  }
  return process.env.ATTESTLENS_ALLOWED_ROOTS
    .split(path.delimiter)
    .map((root) => root.trim())
    .filter(Boolean);
}

export async function validatePath(targetPath: unknown): Promise<string | ToolErrorResponse> {
  if (!targetPath || typeof targetPath !== 'string') {
    return makeToolError('path is required');
  }
  if (/[;|`$\\]/.test(targetPath)) {
    return makeToolError('path contains invalid characters');
  }

  const resolved = path.resolve(targetPath);
  let realTarget: string;
  try {
    realTarget = await fs.realpath(resolved);
  } catch {
    return makeToolError(`path does not exist: ${sanitizeTargetPathForOutput(resolved)}`);
  }

  let stat;
  try {
    stat = await fs.stat(realTarget);
  } catch {
    return makeToolError(`path does not exist: ${sanitizeTargetPathForOutput(resolved)}`);
  }

  if (!stat.isDirectory()) {
    return makeToolError(`path is not a directory: ${sanitizeTargetPathForOutput(resolved)}`);
  }

  const realRoots = await Promise.all(getAllowedRoots().map(async (root) => {
    const resolvedRoot = path.resolve(root);
    try {
      return await fs.realpath(resolvedRoot);
    } catch {
      return resolvedRoot;
    }
  }));

  const isAllowed = realRoots.some((root) => realTarget === root || realTarget.startsWith(root + path.sep));
  if (!isAllowed) {
    return makeToolError('path is outside allowed workspace roots');
  }

  return realTarget;
}

export function validateUrl(targetUrl: unknown): string | ToolErrorResponse {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return makeToolError('url is required');
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return makeToolError(`invalid URL: ${sanitizeTargetUrlForOutput(targetUrl)}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return makeToolError(`unsupported URL protocol: ${parsed.protocol}`);
  }

  return parsed.toString();
}

function createOrchestrator(
  targetKind: 'path' | 'url',
  options: { externalEnrichment?: boolean; includeTyposquat?: boolean; behavioral?: boolean; iac?: boolean; includeGitleaks?: boolean; gitleaksPath?: string; scannerTimeoutMs?: number; reform?: boolean } = {},
): ScannerOrchestrator {
  const externalEnrichment = targetKind === 'path' && options.externalEnrichment === true;
  const orchestratorOptions: ScannerOrchestratorOptions = {
    adapterTimeoutMs: options.scannerTimeoutMs,
    supplyChain: {
      typosquat: { enabled: targetKind === 'path' && options.includeTyposquat === true },
      osv: { enabled: externalEnrichment },
      registry: { enabled: externalEnrichment },
    },
    behavioral: {
      enabled: targetKind === 'path' && options.behavioral !== false,
    },
    iac: {
      enabled: targetKind === 'path' && options.iac !== false,
    },
    gitleaks: {
      enabled: targetKind === 'path' && options.includeGitleaks === true,
      path: options.gitleaksPath || 'gitleaks',
    },
    reform: {
      enabled: targetKind === 'path' && options.reform === true,
    },
  };
  const orchestrator = new ScannerOrchestrator(orchestratorOptions);
  if (targetKind === 'url') {
    orchestrator.disable('guardvibe');
    orchestrator.disable('mcp-scan');
    orchestrator.disable('supply-chain');
  }
  return orchestrator;
}

function parseScannerTimeoutMs(value: unknown): number | undefined | ToolErrorResponse {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    return makeToolError('scannerTimeoutMs must be a positive integer number of milliseconds');
  }
  return value;
}

function validatePrinciple(value: unknown): APPPrinciple | ToolErrorResponse {
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(APPInfo, value)) {
    return makeToolError(`invalid APP principle: ${String(value)}. Valid principles: ${Object.keys(APPInfo).join(', ')}`);
  }
  return value as APPPrinciple;
}

function serializeFindings(findings: AttestLensFinding[]) {
  return findings.map((finding: AttestLensFinding) => ({
    id: finding.id,
    source: finding.source,
    sourceRule: finding.sourceRule,
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    file: finding.file,
    line: finding.line,
    url: finding.url,
    fix: finding.fix,
    fixPrompt: finding.fixPrompt,
    corroboratedBy: finding.corroboratedBy,
    appMappings: finding.appMappings.map((mapping) => ({
      principle: mapping.principle,
      obligation: mapping.obligation,
      status: mapping.status,
      confidence: mapping.confidence,
    })),
  }));
}

function collectUrlScanErrors(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
  urlResult?: ScannerResult,
): ScannerError[] {
  const resultErrors = urlResult?.errors ?? [];
  const orchestratorErrors = result.errors.filter((error) => error.source === 'url-scan');
  return [...resultErrors, ...orchestratorErrors];
}

function getUrlScanFailureError(
  result: Awaited<ReturnType<ScannerOrchestrator['scan']>>,
): ToolErrorResponse | null {
  const urlResult = result.results.find((scannerResult) => scannerResult.source === 'url-scan');
  const urlErrors = collectUrlScanErrors(result, urlResult);

  if (!urlResult && urlErrors.length > 0) {
    return formatUrlScanFailure(urlErrors[0]);
  }

  if (!urlResult) {
    return makeToolError('URL scan failed before any findings could be collected.');
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

function formatUrlScanFailure(error: ScannerError): ToolErrorResponse {
  switch (error.code) {
    case 'INVALID_URL':
      return makeToolError('URL target is not allowed for scanning.');
    case 'FETCH_FAILED':
      return makeToolError('URL scan failed before any findings could be collected.');
    default:
      return makeToolError('URL scan failed before any findings could be collected.');
  }
}

function buildScanSummary(result: Awaited<ReturnType<ScannerOrchestrator['scan']>>, strictMode = false) {
  const { controls, unmapped } = mapAllFindings(result.findings, strictMode);
  return {
    findings: serializeFindings(result.findings),
    controls: controls.map((control) => ({
      principle: control.principle,
      shortName: control.shortName,
      status: control.status,
      score: control.score,
    })),
    summary: {
      total: result.findings.length,
      critical: result.findings.filter((finding) => finding.severity === 'critical').length,
      high: result.findings.filter((finding) => finding.severity === 'high').length,
      medium: result.findings.filter((finding) => finding.severity === 'medium').length,
      low: result.findings.filter((finding) => finding.severity === 'low').length,
      info: result.findings.filter((finding) => finding.severity === 'info').length,
      affectedPrinciples: controls.filter((control) => control.status === 'fail').map((control) => control.principle),
      unmappedCount: unmapped.length,
    },
    errors: result.errors,
    durationMs: result.totalDurationMs,
    ruleFreshness: RuleFreshnessSchema.parse(result.ruleFreshness),
  };
}

function parseReportFormat(rawFormat: unknown): ReportFormat | ToolErrorResponse {
  const format = typeof rawFormat === 'string' ? rawFormat : 'json';
  if (format === 'json' || format === 'html' || format === 'markdown' || format === 'pdf' || format === 'agent') {
    return format;
  }
  return makeToolError(`unsupported report format: ${format}`);
}

async function renderAuditContent(
  report: ReturnType<typeof buildComplianceReport>,
  reportOptions: ReportOptions,
  format: ReportFormat,
): Promise<string> {
  switch (format) {
    case 'html':
      return generateHTMLReport(report, reportOptions);
    case 'markdown':
      return generateMarkdownReport(report);
    case 'agent':
      return generateAgentReport(report);
    case 'pdf': {
      const pdf = await generatePDFReport(report, reportOptions);
      return JSON.stringify(
        {
          format: 'pdf',
          encoding: 'base64',
          filename: `attestlens-report-${report.target.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.pdf`,
          mimeType: 'application/pdf',
          content: pdf.toString('base64'),
        },
        null,
        2,
      );
    }
    case 'json':
    default:
      return generateJSONReport(report);
  }
}

export async function handleToolCall(name: string, args: Record<string, unknown> | undefined): Promise<ToolResponse> {
  switch (name) {
    case 'attestlens_scan': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const strict = args?.strict === true;
      const externalEnrichment = args?.externalEnrichment === true;
      const includeTyposquat = args?.includeTyposquat === true;
      const behavioral = args?.behavioral !== false;
      const iac = args?.iac !== false;
      const includeGitleaks = args?.includeGitleaks === true;
      const gitleaksPath = typeof args?.gitleaksPath === 'string' ? args.gitleaksPath : undefined;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);
      if (isToolError(scannerTimeoutMs)) {
        return scannerTimeoutMs;
      }

      const orchestrator = createOrchestrator('path', { externalEnrichment, includeTyposquat, behavioral, iac, includeGitleaks, gitleaksPath, scannerTimeoutMs });
      const result = await orchestrator.scan(targetPath);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            targetType: 'path',
            targetPath: sanitizeTargetPathForOutput(targetPath),
            ...buildScanSummary(result, strict),
          }, null, 2),
        }],
      };
    }

    case 'attestlens_scan_url': {
      const targetUrl = validateUrl(args?.url);
      if (isToolError(targetUrl)) {
        return targetUrl;
      }
      const strict = args?.strict === true;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);
      if (isToolError(scannerTimeoutMs)) {
        return scannerTimeoutMs;
      }

      const orchestrator = createOrchestrator('url', { scannerTimeoutMs });
      const result = await orchestrator.scan(targetUrl);
      const urlScanFailure = getUrlScanFailureError(result);
      if (urlScanFailure) {
        return urlScanFailure;
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            targetType: 'url',
            targetUrl: sanitizeTargetUrlForOutput(targetUrl),
            ...buildScanSummary(result, strict),
          }, null, 2),
        }],
      };
    }

    case 'attestlens_audit': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const projectName = (args?.name as string) || path.basename(targetPath) || 'project';
      const format = parseReportFormat(args?.format);
      if (isToolError(format)) {
        return format;
      }
      const strict = args?.strict === true;
      const externalEnrichment = args?.externalEnrichment === true;
      const includeTyposquat = args?.includeTyposquat === true;
      const behavioral = args?.behavioral !== false;
      const iac = args?.iac !== false;
      const includeGitleaks = args?.includeGitleaks === true;
      const gitleaksPath = typeof args?.gitleaksPath === 'string' ? args.gitleaksPath : undefined;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);
      if (isToolError(scannerTimeoutMs)) {
        return scannerTimeoutMs;
      }

      const orchestrator = createOrchestrator('path', { externalEnrichment, includeTyposquat, behavioral, iac, includeGitleaks, gitleaksPath, scannerTimeoutMs });
      const startTime = Date.now();
      const scanResult = await orchestrator.scan(targetPath);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath,
        formats: [format],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeOpinion: args?.opinion === true,
        ruleFreshness: scanResult.ruleFreshness,
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      return {
        content: [{
          type: 'text',
          text: await renderAuditContent(report, reportOptions, format),
        }],
      };
    }

    case 'attestlens_map': {
      const rawFindings = args?.findings as Array<Record<string, unknown>> | undefined;
      if (!rawFindings || !Array.isArray(rawFindings)) {
        return makeToolError('findings array is required');
      }

      const findings: AttestLensFinding[] = rawFindings.map((finding, index) => ({
        id: (finding.id as string) || `FIND-${index + 1}`,
        source: (finding.source as AttestLensFinding['source']) || 'manual',
        sourceRule: finding.sourceRule as string,
        severity: (finding.severity as AttestLensFinding['severity']) || 'medium',
        category: (finding.category as string) || 'Security',
        title: finding.title as string,
        description: (finding.description as string) || '',
        file: finding.file as string | undefined,
        line: finding.line as number | undefined,
        appMappings: [],
        evidence: {
          timestamp: new Date().toISOString(),
          scannerVersion: ATTESTLENS_VERSION,
          rawOutput: finding,
        },
      }));

      const { controls } = mapAllFindings(findings);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            appMappings: Object.fromEntries(
              controls.map((control) => [
                control.principle,
                {
                  status: control.status,
                  score: control.score,
                  findingCount: control.findingCount,
                },
              ]),
            ),
          }, null, 2),
        }],
      };
    }

    case 'attestlens_opinion': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const strict = args?.strict === true;

      const orchestrator = createOrchestrator('path', {});
      const startTime = Date.now();
      const scanResult = await orchestrator.scan(targetPath);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: path.basename(targetPath) || 'project',
        targetPath,
        formats: ['json'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeOpinion: true,
        ruleFreshness: scanResult.ruleFreshness,
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      // Return just the opinion, not the full report
      const opinion = report.complianceOpinion;
      if (!opinion) {
        return makeToolError('Opinion generation failed');
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(opinion, null, 2),
        }],
      };
    }

    case 'attestlens_check': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const principle = validatePrinciple(args?.principle);
      if (isToolError(principle)) {
        return principle;
      }
      const strict = args?.strict === true;

      const orchestrator = createOrchestrator('path', {});
      const startTime = Date.now();
      const scanResult = await orchestrator.scan(targetPath);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: path.basename(targetPath) || 'project',
        targetPath,
        formats: ['json'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeOpinion: true,
        ruleFreshness: scanResult.ruleFreshness,
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const control = report.appControls.find((appControl) => appControl.principle === principle);
      if (!control) {
        return makeToolError(`APP principle not found in report: ${principle}`);
      }

      const opinion = report.complianceOpinion?.principles.find((principleOpinion) => (
        principleOpinion.principle === principle
      ));
      if (!opinion) {
        return makeToolError(`Opinion generation failed for ${principle}`);
      }

      const findingIds = new Set(control.findings);
      const findings = report.findings
        .filter((finding) => findingIds.has(finding.id))
        .map((finding) => ({
          id: finding.id,
          severity: finding.severity,
          title: finding.title,
          fix: finding.fix,
        }));

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            principle,
            verdict: opinion.verdict,
            score: opinion.score,
            confidence: opinion.confidence,
            findings,
            remediations: findings
              .map((finding) => finding.fix)
              .filter((fix): fix is string => typeof fix === 'string' && fix.length > 0),
          }, null, 2),
        }],
      };
    }

    case 'attestlens_compliance_check': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const strict = args?.strict === true;
      const reform = args?.reform === true;

      const orchestrator = createOrchestrator('path', {
        externalEnrichment: false,
        includeTyposquat: false,
        behavioral: true,
        iac: true,
        includeGitleaks: false,
        reform,
      });
      const scanResult = await orchestrator.scan(targetPath);
      const duration = scanResult.totalDurationMs;

      const reportOptions: ReportOptions = {
        targetName: path.basename(targetPath) || 'project',
        targetPath: sanitizeTargetPathForOutput(targetPath),
        formats: ['smb'],
        outputDir: './attestlens-reports',
        strictMode: strict,
        includeReform: reform,
        includeSMB: true,
        ruleFreshness: scanResult.ruleFreshness,
      };

      const report = buildComplianceReport(scanResult.findings, reportOptions, duration) as ComplianceReportWithSMB;
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const smbResult = report.smbCompliance ?? buildSMBComplianceResult(report);
      if (!smbResult) {
        return makeToolError('Failed to generate SMB compliance result');
      }

      const gapControls = report.appControls.filter((control) => control.status === 'unknown');
      const reformProvisions = report.reformImpactAssessment?.provisions.filter((provision) => (
        provision.findingCount > 0
      )) ?? [];

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            readinessScore: smbResult.readinessScore,
            readinessLabel: smbResult.readinessLabel,
            verdict: smbResult.verdict,
            summary: smbResult.summary,
            actions: smbResult.actions.map((action) => ({
              priority: action.priority,
              title: action.title,
              description: action.description,
              principle: action.principle,
            })),
            gaps: smbResult.gaps.map((gap, index) => {
              const control = gapControls[index];
              return {
                principle: control?.principle,
                shortName: control?.shortName ?? gap.area,
                description: gap.description,
                status: gap.status,
              };
            }),
            reformWarnings: smbResult.reformWarnings?.map((warning, index) => {
              const provision = reformProvisions[index];
              return {
                provision: warning.provision,
                shortName: provision?.shortName ?? warning.provision,
                impact: warning.impact,
                deadline: warning.deadline,
                actionNeeded: warning.description,
              };
            }),
            metadata: {
              target: report.target,
              scanDurationMs: duration,
              scannerVersions: report.metadata.scannerVersions,
            },
          }, null, 2),
        }],
      };
    }

    case 'attestlens_reform': {
      const targetPath = await validatePath(args?.path);
      if (isToolError(targetPath)) {
        return targetPath;
      }
      const strict = args?.strict === true;

      const orchestrator = createOrchestrator('path', { reform: true });
      const startTime = Date.now();
      const scanResult = await orchestrator.scan(targetPath);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: path.basename(targetPath) || 'project',
        targetPath,
        formats: ['json'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
        includeReform: true,
        ruleFreshness: scanResult.ruleFreshness,
      };
      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);
      report.metadata.scannerVersions = Object.fromEntries(
        scanResult.results.map((scannerResult) => [scannerResult.source, scannerResult.version]),
      );

      const assessment: ReformImpactAssessment | undefined = report.reformImpactAssessment;
      if (!assessment) {
        return makeToolError('Reform impact assessment generation failed');
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify(assessment, null, 2),
        }],
      };
    }

    default:
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
  }
}

export function createServer(): Server {
  const server = new Server(
    { name: 'attestlens', version: ATTESTLENS_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...MCP_TOOLS] }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return handleToolCall(name, args as Record<string, unknown> | undefined);
  });

  return server;
}

export const server = createServer();

export async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AttestLens MCP server running on stdio');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
