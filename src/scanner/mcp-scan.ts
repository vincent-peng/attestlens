/**
 * AttestLens — mcp-scan Adapter
 * 
 * Integrates with mcp-scan for MCP server configuration security.
 * Detects secrets, CVEs, permission issues, and exfiltration vectors
 * across 10+ AI tool clients.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs/promises';
import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type { ScannerAdapter, ScannerContext, ScannerResult, ScannerError, McpScanResult } from './types.js';

export class McpScanAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'mcp-scan';
  readonly version = '0.2.0';

  private binaryPath: string;

  constructor(binaryPath?: string) {
    this.binaryPath = binaryPath || 'npx';
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { execSync } = await import('node:child_process');
      execSync('npx mcp-scan --version', { stdio: 'pipe', timeout: 10000 });
      return true;
    } catch {
      return false;
    }
  }

  async getVersion(): Promise<string> {
    try {
      const { execFileSync } = await import('node:child_process');
      return execFileSync('npx', ['mcp-scan', '--version'], { stdio: 'pipe', timeout: 10000 }).toString().trim();
    } catch {
      return 'unknown';
    }
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    // Validate and resolve path
    const resolvedPath = path.resolve(targetPath);
    let stat;
    try {
      stat = await fs.stat(resolvedPath);
    } catch {
      return {
        source: this.name,
        findings: [],
        errors: [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }],
        durationMs: 0,
        version: this.version,
        timestamp: new Date().toISOString(),
      };
    }
    if (!stat.isDirectory()) {
      return {
        source: this.name,
        findings: [],
        errors: [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }],
        durationMs: 0,
        version: this.version,
        timestamp: new Date().toISOString(),
      };
    }
    const safePath = resolvedPath;
    const startTime = Date.now();
    const errors: ScannerError[] = [];
    const findings: AttestLensFinding[] = [];

    try {
      const { execFile } = await import('node:child_process');
      const { promisify } = await import('node:util');
      const execFileAsync = promisify(execFile);
      
      // mcp-scan checks MCP server configurations for security issues
      // Use execFile to prevent command injection
      const { stdout } = await execFileAsync(
        'npx',
        ['mcp-scan', 'scan', '--path', safePath, '--format', 'json'],
        { timeout: 60000, signal: context?.signal }
      );
      const result = stdout.toString();

      const scanResult: McpScanResult = JSON.parse(result);
      
      for (const finding of scanResult.findings) {
        findings.push(this.normalizeFinding(finding, targetPath));
      }
    } catch (error: any) {
      errors.push({
        source: 'mcp-scan',
        message: `mcp-scan failed: ${error.message}. Skipping MCP config scan.`,
        code: 'MCP_SCAN_UNAVAILABLE',
        recoverable: true,
      });
    }

    return {
      source: 'mcp-scan',
      version: this.version,
      timestamp: new Date().toISOString(),
      findings,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  private normalizeFinding(finding: McpScanResult['findings'][0], targetPath: string): AttestLensFinding {
    return {
      id: crypto.createHash('sha256')
        .update(`mcp-scan:${finding.id}:${finding.file || ''}:${finding.line || ''}`)
        .digest('hex').substring(0, 12),
      source: 'mcp-scan',
      sourceRule: finding.id,
      severity: this.mapSeverity(finding.severity),
      category: finding.category,
      title: finding.title,
      description: finding.description,
      file: finding.file,
      line: finding.line,
      fix: finding.remediation,
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: finding,
        scannerCommand: `mcp-scan scan --path "${targetPath}"`,
      },
    };
  }

  private mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'info': 'info',
      'warning': 'medium',
      'error': 'high',
    };
    return map[severity.toLowerCase()] || 'medium';
  }
}

export default McpScanAdapter;
