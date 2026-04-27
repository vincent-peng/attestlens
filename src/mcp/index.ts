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
  generateHTMLReport,
  generateJSONReport,
  generateMarkdownReport,
  generatePDFReport,
} from '../report/generator.js';
import type { ReportFormat, ReportOptions } from '../report/generator.js';
import { ScannerOrchestrator, type ScannerOrchestratorOptions } from '../scanner/orchestrator.js';
import type { ScannerError, ScannerResult } from '../scanner/types.js';
import { RuleFreshness as RuleFreshnessSchema } from '../schema/index.js';
import type { AttestLensFinding } from '../schema/index.js';
import { sanitizeTargetPathForOutput, sanitizeTargetUrlForOutput } from '../utils/target.js';

const ATTESTLENS_VERSION = '0.2.0';

type ToolResponse = { content: Array<{ type: 'text'; text: string }> };

export const MCP_TOOLS = [
  {
    name: 'attestlens_scan',
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
  },
  {
    name: 'attestlens_scan_url',
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
  },
  {
    name: 'attestlens_audit',
    description: 'Full APP/NDB compliance audit. Scans a project, maps findings to Australian Privacy Act obligations, and generates a compliance report.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the project directory to audit' },
        name: { type: 'string', description: 'Project name for the report' },
        format: { type: 'string', enum: ['json', 'html', 'markdown', 'pdf'], description: 'Output format', default: 'json' },
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
  },
  {
    name: 'attestlens_map',
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
  },
] as const;

function getAllowedRoots(): string[] | undefined {
  if (!process.env.ATTESTLENS_ALLOWED_ROOTS) {
    return undefined;
  }
  return process.env.ATTESTLENS_ALLOWED_ROOTS.split(':').filter(Boolean);
}

export async function validatePath(targetPath: string): Promise<string> {
  if (!targetPath || typeof targetPath !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'path is required');
  }
  if (/[;|`$\\]/.test(targetPath)) {
    throw new McpError(ErrorCode.InvalidParams, 'path contains invalid characters');
  }

  const resolved = path.resolve(targetPath);
  const allowedRoots = getAllowedRoots();
  if (allowedRoots) {
    const isAllowed = allowedRoots.some((root) => {
      const normalizedRoot = path.resolve(root);
      return resolved === normalizedRoot || resolved.startsWith(normalizedRoot + path.sep);
    });
    if (!isAllowed) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `path is outside allowed roots: ${resolved}. Allowed roots: ${allowedRoots.join(', ')}`,
      );
    }
  }

  let stat;
  try {
    stat = await fs.stat(resolved);
  } catch {
    throw new McpError(ErrorCode.InvalidParams, `path does not exist: ${resolved}`);
  }

  if (!stat.isDirectory()) {
    throw new McpError(ErrorCode.InvalidParams, `path is not a directory: ${resolved}`);
  }

  return resolved;
}

export function validateUrl(targetUrl: string): string {
  if (!targetUrl || typeof targetUrl !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'url is required');
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new McpError(ErrorCode.InvalidParams, `invalid URL: ${targetUrl}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new McpError(ErrorCode.InvalidParams, `unsupported URL protocol: ${parsed.protocol}`);
  }

  return parsed.toString();
}

function createOrchestrator(
  targetKind: 'path' | 'url',
  options: { externalEnrichment?: boolean; includeTyposquat?: boolean; behavioral?: boolean; includeGitleaks?: boolean; gitleaksPath?: string; scannerTimeoutMs?: number } = {},
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
    gitleaks: {
      enabled: targetKind === 'path' && options.includeGitleaks === true,
      path: options.gitleaksPath || 'gitleaks',
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

function parseScannerTimeoutMs(value: unknown): number | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    throw new McpError(ErrorCode.InvalidParams, 'scannerTimeoutMs must be a positive integer number of milliseconds');
  }
  return value;
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
): McpError | null {
  const urlResult = result.results.find((scannerResult) => scannerResult.source === 'url-scan');
  const urlErrors = collectUrlScanErrors(result, urlResult);

  if (!urlResult && urlErrors.length > 0) {
    return formatUrlScanFailure(urlErrors[0]);
  }

  if (!urlResult) {
    return new McpError(ErrorCode.InternalError, 'URL scan failed before any findings could be collected.');
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

function formatUrlScanFailure(error: ScannerError): McpError {
  switch (error.code) {
    case 'INVALID_URL':
      return new McpError(ErrorCode.InvalidParams, 'URL target is not allowed for scanning.');
    case 'FETCH_FAILED':
      return new McpError(ErrorCode.InternalError, 'URL scan failed before any findings could be collected.');
    default:
      return new McpError(ErrorCode.InternalError, 'URL scan failed before any findings could be collected.');
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

function parseReportFormat(rawFormat: unknown): ReportFormat {
  const format = typeof rawFormat === 'string' ? rawFormat : 'json';
  if (format === 'json' || format === 'html' || format === 'markdown' || format === 'pdf') {
    return format;
  }
  throw new McpError(ErrorCode.InvalidParams, `unsupported report format: ${format}`);
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
      const targetPath = await validatePath(args?.path as string);
      const strict = args?.strict === true;
      const externalEnrichment = args?.externalEnrichment === true;
      const includeTyposquat = args?.includeTyposquat === true;
      const behavioral = args?.behavioral !== false;
      const includeGitleaks = args?.includeGitleaks === true;
      const gitleaksPath = typeof args?.gitleaksPath === 'string' ? args.gitleaksPath : undefined;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);

      const orchestrator = createOrchestrator('path', { externalEnrichment, includeTyposquat, behavioral, includeGitleaks, gitleaksPath, scannerTimeoutMs });
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
      const targetUrl = validateUrl(args?.url as string);
      const strict = args?.strict === true;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);

      const orchestrator = createOrchestrator('url', { scannerTimeoutMs });
      const result = await orchestrator.scan(targetUrl);
      const urlScanFailure = getUrlScanFailureError(result);
      if (urlScanFailure) {
        throw urlScanFailure;
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
      const targetPath = await validatePath(args?.path as string);
      const projectName = (args?.name as string) || path.basename(targetPath) || 'project';
      const format = parseReportFormat(args?.format);
      const strict = args?.strict === true;
      const externalEnrichment = args?.externalEnrichment === true;
      const includeTyposquat = args?.includeTyposquat === true;
      const behavioral = args?.behavioral !== false;
      const includeGitleaks = args?.includeGitleaks === true;
      const gitleaksPath = typeof args?.gitleaksPath === 'string' ? args.gitleaksPath : undefined;
      const scannerTimeoutMs = parseScannerTimeoutMs(args?.scannerTimeoutMs);

      const orchestrator = createOrchestrator('path', { externalEnrichment, includeTyposquat, behavioral, includeGitleaks, gitleaksPath, scannerTimeoutMs });
      const startTime = Date.now();
      const scanResult = await orchestrator.scan(targetPath);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath,
        formats: [format],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
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
        throw new McpError(ErrorCode.InvalidParams, 'findings array is required');
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
