/**
 * AttestLens — GuardVibe Scanner Adapter
 * 
 * Integrates with GuardVibe MCP (335 rules, 36 tools) for security scanning.
 * GuardVibe is the primary scanner — it covers Next.js, Supabase, Clerk,
 * Stripe, Prisma, tRPC, and the full AI-generated stack.
 * 
 * This adapter calls GuardVibe's MCP tools and normalizes findings.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type { ScannerAdapter, ScannerContext, ScannerResult, ScannerError, GuardVibeFinding, GuardVibeAuditResult } from './types.js';
import { getExecutableGuardVibeStaticRuleSet } from './rules/executable.js';
import { scanRepoStackChecks, shouldSkipRepoScanPath } from './rules/repo-stack-checks.js';

export class GuardVibeAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'guardvibe';
  readonly version = '0.2.0';
  
  private binaryPath: string;

  constructor(binaryPath?: string) {
    this.binaryPath = binaryPath || 'npx';
  }

  async isAvailable(): Promise<boolean> {
    // Always available — static fallback runs when MCP/CLI is absent
    return true;
  }

  async getVersion(): Promise<string> {
    try {
      const { execFileSync } = await import('node:child_process');
      return execFileSync(this.binaryPath, ['@guardvibe/cli', '--version'], {
        stdio: 'pipe',
        timeout: 10000,
      }).toString().trim();
    } catch {
      return 'unknown';
    }
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    // Validate and normalize path to prevent traversal
    const resolvedPath = path.resolve(targetPath);
    const { stat } = await import('node:fs/promises');
    let pathStat;
    try {
      pathStat = await stat(resolvedPath);
    } catch {
      pathStat = null;
    }
    if (!pathStat || !pathStat.isDirectory()) {
      return {
        source: this.name,
        findings: [],
        errors: [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }],
        durationMs: 0,
        version: await this.getVersion(),
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
      
      // Run GuardVibe full_audit tool via CLI
      // Use execFile to prevent command injection (args are not shell-interpolated)
      const { stdout } = await execFileAsync(
        this.binaryPath,
        ['@guardvibe/cli', 'full_audit', '--path', safePath, '--format', 'json'],
        { 
          timeout: 120000,
          cwd: safePath,
          signal: context?.signal,
        }
      );
      const result = stdout.toString();

      const auditResult: GuardVibeAuditResult = JSON.parse(result);
      
      for (const finding of auditResult.findings) {
        findings.push(this.normalizeFinding(finding, safePath));
      }
    } catch (error: any) {
      // If GuardVibe is not available, we fall back to static analysis
      errors.push({
        source: 'guardvibe',
        message: `GuardVibe scan failed: ${error.message}. Using static fallback.`,
        code: 'GUARDVIBE_UNAVAILABLE',
        recoverable: true,
      });

      // Static fallback: scan for common patterns
      const staticResult = await this.staticFallback(safePath, context);
      findings.push(...staticResult.findings);
      errors.push(...staticResult.errors);
    }

    return {
      source: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      findings,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Normalize a GuardVibe finding into AttestLens format.
   */
  private normalizeFinding(finding: GuardVibeFinding, targetPath: string): AttestLensFinding {
    const severity = this.mapSeverity(finding.severity);
    const id = this.generateId('guardvibe', finding.rule, finding.file, finding.line);
    
    return {
      id,
      source: 'guardvibe',
      sourceRule: finding.rule,
      severity,
      category: finding.category,
      title: finding.title,
      description: finding.description,
      file: finding.file,
      line: finding.line,
      code: finding.code,
      fix: finding.fix,
      appMappings: [], // Will be filled by mapping engine
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: finding,
        scannerCommand: `guardvibe full_audit --path "${targetPath}"`,
      },
    };
  }

  /**
   * Static fallback: scan target directory for common security patterns.
   * Used when GuardVibe MCP is not available.
   */
  private async staticFallback(
    targetPath: string,
    context?: ScannerContext,
  ): Promise<{ findings: AttestLensFinding[]; errors: ScannerError[] }> {
    const findings: AttestLensFinding[] = [];
    const errors: ScannerError[] = [];
    const fs = await import('node:fs/promises');
    const pathModule = await import('node:path');
    const executableRules = getExecutableGuardVibeStaticRuleSet(context?.rulePack);
    const patterns = executableRules.rules;

    for (const warning of executableRules.warnings) {
      errors.push({
        source: this.name,
        message: `Rule pack execution fallback: ${warning} Using embedded GuardVibe static rules.`,
        code: 'RULE_PACK_EXECUTION_FALLBACK',
        recoverable: true,
      });
    }

    try {
      // Recursively find relevant files
      const files = await this.findRelevantFiles(targetPath);
      
      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf-8');
          const lines = content.split('\n');
          const relativePath = pathModule.relative(targetPath, file);

          for (const pattern of patterns) {
            for (let i = 0; i < lines.length; i++) {
              pattern.regex.lastIndex = 0;
              const match = pattern.regex.exec(lines[i]);
              if (match) {
                findings.push({
                  id: this.generateId('guardvibe', pattern.rule, relativePath, i + 1),
                  source: 'guardvibe',
                  sourceRule: pattern.rule,
                  severity: pattern.severity as any,
                  category: pattern.category,
                  title: pattern.title,
                  description: pattern.description,
                  file: relativePath,
                  line: i + 1,
                  code: lines[i].trim(),
                  fix: pattern.fix,
                  appMappings: [], // Filled by mapping engine
                  evidence: {
                    timestamp: new Date().toISOString(),
                    scannerVersion: this.version,
                    rawOutput: { match: match[0], rule: pattern.rule },
                    scannerCommand: `attestlens static-scan "${targetPath}"`,
                  },
                });
              }
            }
          }
        } catch {
          // Skip files we can't read
        }
      }
    } catch (error: any) {
      // Static fallback failed — return what we have
    }

    try {
      const stackFindings = await scanRepoStackChecks(targetPath, this.version);
      findings.push(...stackFindings);
    } catch {
      // Stack-specific checks are best-effort only.
    }

    return {
      findings: this.pruneGenericDuplicates(findings),
      errors,
    };
  }

  /**
   * Find relevant source files to scan.
   */
  private async findRelevantFiles(targetPath: string): Promise<string[]> {
    const fs = await import('node:fs/promises');
    const pathModule = await import('node:path');
    
    const extensions = ['.ts', '.tsx', '.js', '.jsx', '.env', '.env.local', '.env.production'];
    const excludeDirs = ['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.venv', '__pycache__'];
    const files: string[] = [];

    async function walk(dir: string): Promise<void> {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = pathModule.join(dir, entry.name);
        const relativePath = pathModule.relative(targetPath, fullPath);
        if (entry.isDirectory()) {
          if (!excludeDirs.includes(entry.name) && !shouldSkipRepoScanPath(relativePath)) {
            await walk(fullPath);
          }
        } else if (extensions.some(ext => entry.name.endsWith(ext)) && !shouldSkipRepoScanPath(relativePath)) {
          files.push(fullPath);
        }
      }
    }

    await walk(targetPath);
    return files;
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

  private generateId(source: string, rule: string, file?: string, line?: number): string {
    const payload = `${source}:${rule}:${file || ''}:${line || ''}`;
    return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12);
  }

  private pruneGenericDuplicates(findings: AttestLensFinding[]): AttestLensFinding[] {
    const specificRules = new Set(['VS-PUBLIC-SECRET-ENV', 'VS-PLATFORM-SECRET', 'VS-FB-SERVICE-ACCOUNT']);
    const genericRules = new Set(['VS-HARDKEY', 'VS-ENV']);
    const specificLocations = new Set(
      findings
        .filter((finding) => specificRules.has(finding.sourceRule))
        .map((finding) => `${finding.file || ''}:${finding.line || ''}`),
    );

    return findings.filter((finding) => {
      if (!genericRules.has(finding.sourceRule)) {
        return true;
      }

      return !specificLocations.has(`${finding.file || ''}:${finding.line || ''}`);
    });
  }
}

export default GuardVibeAdapter;
