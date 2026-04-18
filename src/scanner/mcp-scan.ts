/**
 * AttestLens — mcp-scan Adapter
 * 
 * Integrates with mcp-scan for MCP server configuration security.
 * Detects secrets, CVEs, permission issues, and exfiltration vectors
 * across 10+ AI tool clients.
 */

import crypto from 'node:crypto';
import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type { ScannerAdapter, ScannerResult, ScannerError, McpScanResult } from './types.js';

export class McpScanAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'mcp-scan';
  readonly version = '0.1.0';

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
      const { execSync } = await import('node:child_process');
      return execSync('npx mcp-scan --version', { stdio: 'pipe', timeout: 10000 }).toString().trim();
    } catch {
      return 'unknown';
    }
  }

  async scan(targetPath: string): Promise<ScannerResult> {
    const startTime = Date.now();
    const errors: ScannerError[] = [];
    const findings: AttestLensFinding[] = [];

    try {
      const { execSync } = await import('node:child_process');
      
      // mcp-scan checks MCP server configurations for security issues
      const result = execSync(
        `npx mcp-scan scan --path "${targetPath}" --format json`,
        { stdio: 'pipe', timeout: 60000 }
      ).toString();

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