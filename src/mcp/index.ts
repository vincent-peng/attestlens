#!/usr/bin/env node
/**
 * AttestLens — MCP Server
 * 
 * Exposes AttestLens as an MCP server so AI editors (Cursor, Windsurf, etc.)
 * can run compliance scans directly.
 * 
 * Tools:
 *   attestlens_scan   - Scan a project for privacy findings
 *   attestlens_audit  - Full APP/NDB compliance audit
 *   attestlens_map    - Map findings to APP obligations
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { ScannerOrchestrator } from '../scanner/orchestrator.js';
import { mapAllFindings } from '../mapping/engine.js';
import { buildComplianceReport, generateHTMLReport, generateJSONReport, generateMarkdownReport } from '../report/generator.js';
import type { ReportOptions } from '../report/generator.js';
import type { AttestLensFinding } from '../schema/index.js';
import path from 'node:path';
import fs from 'node:fs/promises';

/**
 * Validate and resolve a path parameter to prevent path traversal.
 * Returns the resolved absolute path if valid, throws McpError otherwise.
 */
async function validatePath(targetPath: string): Promise<string> {
  if (!targetPath || typeof targetPath !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'path is required');
  }
  // Reject paths with suspicious characters
  if (/[;|`$\\]/.test(targetPath)) {
    throw new McpError(ErrorCode.InvalidParams, 'path contains invalid characters');
  }
  const resolved = path.resolve(targetPath);
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

const server = new Server(
  { name: 'attestlens', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

// ─── Tool Definitions ────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'attestlens_scan',
      description: 'Scan a project directory for Australian Privacy Act (APP/NDB) compliance findings.',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Path to the project directory to scan' },
          strict: { type: 'boolean', description: 'Treat UNKNOWN controls as FAIL', default: false },
        },
        required: ['path'],
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
          format: { type: 'string', enum: ['json', 'html', 'markdown'], description: 'Output format', default: 'json' },
          strict: { type: 'boolean', description: 'Treat UNKNOWN controls as FAIL', default: false },
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
  ],
}));

// ─── Tool Handlers ────────────────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'attestlens_scan': {
      const targetPath = await validatePath(args?.path as string);

      const orchestrator = new ScannerOrchestrator();
      const result = await orchestrator.scan(targetPath);

      // Map findings to APP obligations
      const { controls, unmapped } = mapAllFindings(result.findings);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            findings: result.findings.map((f: AttestLensFinding) => ({
              id: f.id,
              source: f.source,
              sourceRule: f.sourceRule,
              severity: f.severity,
              title: f.title,
              description: f.description,
              file: f.file,
              line: f.line,
              appMappings: f.appMappings.map(m => ({
                principle: m.principle,
                obligation: m.obligation,
                status: m.status,
                confidence: m.confidence,
              })),
            })),
            controls: controls.map(c => ({
              principle: c.principle,
              shortName: c.shortName,
              status: c.status,
              score: c.score,
            })),
            summary: {
              total: result.findings.length,
              critical: result.findings.filter(f => f.severity === 'critical').length,
              high: result.findings.filter(f => f.severity === 'high').length,
              medium: result.findings.filter(f => f.severity === 'medium').length,
              low: result.findings.filter(f => f.severity === 'low').length,
              affectedPrinciples: controls.filter(c => c.status === 'fail').map(c => c.principle),
              unmappedCount: unmapped.length,
            },
            errors: result.errors,
            durationMs: result.totalDurationMs,
          }, null, 2),
        }],
      };
    }

    case 'attestlens_audit': {
      const targetPath = await validatePath(args?.path as string);
      // Removed: if (!targetPath) throw — validatePath handles this

      const projectName = (args?.name as string) || targetPath.split('/').pop() || 'project';
      const format = (args?.format as string) || 'json';
      const strict = (args?.strict as boolean) || false;

      const orchestrator = new ScannerOrchestrator();
      const startTime = Date.now();
      const scanResult = await orchestrator.scan(targetPath);
      const duration = Date.now() - startTime;

      const reportOptions: ReportOptions = {
        targetName: projectName,
        targetPath,
        formats: [format as 'json' | 'html' | 'markdown'],
        outputDir: '/tmp/attestlens-mcp',
        strictMode: strict,
      };

      const report = buildComplianceReport(scanResult.findings, reportOptions, duration);

      let reportContent: string;
      switch (format) {
        case 'html':
          reportContent = generateHTMLReport(report, reportOptions);
          break;
        case 'markdown':
          reportContent = generateMarkdownReport(report);
          break;
        default:
          reportContent = generateJSONReport(report);
      }

      return { content: [{ type: 'text' as const, text: reportContent }] };
    }

    case 'attestlens_map': {
      const rawFindings = args?.findings as Array<any>;
      if (!rawFindings || !Array.isArray(rawFindings)) {
        throw new McpError(ErrorCode.InvalidParams, 'findings array is required');
      }

      const findings: AttestLensFinding[] = rawFindings.map((f: any, i: number) => ({
        id: f.id || `FIND-${i + 1}`,
        source: f.source || 'manual',
        sourceRule: f.sourceRule,
        severity: f.severity || 'medium',
        category: f.category || 'Security',
        title: f.title,
        description: f.description || '',
        file: f.file,
        line: f.line,
        appMappings: [],
        evidence: {
          timestamp: new Date().toISOString(),
          scannerVersion: '0.1.0',
          rawOutput: f,
        },
      }));

      const { controls } = mapAllFindings(findings);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            appMappings: Object.fromEntries(
              controls.map(c => [c.principle, { status: c.status, score: c.score, findingCount: c.findingCount }])
            ),
          }, null, 2),
        }],
      };
    }

    default:
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
  }
});

// ─── Start ──────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AttestLens MCP server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});