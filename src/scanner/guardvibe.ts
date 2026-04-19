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
import type { ScannerAdapter, ScannerResult, ScannerError, GuardVibeFinding, GuardVibeAuditResult } from './types.js';
import { scanRepoStackChecks } from './rules/repo-stack-checks.js';

export class GuardVibeAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'guardvibe';
  readonly version = '0.1.0';
  
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
      return execFileSync('npx', ['@guardvibe/cli', '--version'], {
        stdio: 'pipe',
        timeout: 10000,
      }).toString().trim();
    } catch {
      return 'unknown';
    }
  }

  async scan(targetPath: string): Promise<ScannerResult> {
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
      const { execFileSync } = await import('node:child_process');
      
      // Run GuardVibe full_audit tool via CLI
      // Use execFileSync to prevent command injection (args are not shell-interpolated)
      const result = execFileSync(
        'npx',
        ['@guardvibe/cli', 'full_audit', '--path', safePath, '--format', 'json'],
        { 
          stdio: 'pipe' as const, 
          timeout: 120000,
          cwd: safePath,
        }
      ).toString();

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
      const staticFindings = await this.staticFallback(safePath);
      findings.push(...staticFindings);
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
  private async staticFallback(targetPath: string): Promise<AttestLensFinding[]> {
    const findings: AttestLensFinding[] = [];
    const fs = await import('node:fs/promises');
    const pathModule = await import('node:path');

    // Pattern definitions for static scanning
    const patterns: Array<{
      rule: string;
      regex: RegExp;
      severity: 'critical' | 'high' | 'medium' | 'low';
      category: string;
      title: string;
      description: string;
      fix: string;
    }> = [
      {
        rule: 'VG-SEC-001',
        regex: /(?:SUPABASE_URL|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_URL)\s*=\s*['"][^'"]+['"]/gi,
        severity: 'critical',
        category: 'Security',
        title: 'Exposed Supabase credentials',
        description: 'Supabase URL or keys found in source code. Anon keys in client code are expected but should be validated; service role keys must never be exposed.',
        fix: 'Move service role keys to server-only environment variables. Use NEXT_PUBLIC_ prefix only for anon keys.',
      },
      {
        rule: 'VG-SEC-002',
        regex: /(?:supabase_admin|service_role|supabase_service_role_key)\s*=\s*['"][^'"]+['"]/gi,
        severity: 'critical',
        category: 'Security',
        title: 'Service role key in client code',
        description: 'Supabase service role key found in client-accessible code. This bypasses all Row Level Security.',
        fix: 'Remove service role keys from client code. Use server-side API routes for admin operations.',
      },
      {
        rule: 'VS-HARDKEY',
        regex: /(?:api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{16,}['"]?/gi,
        severity: 'critical',
        category: 'Security',
        title: 'Hardcoded secret key',
        description: 'A hardcoded secret key was found in source code. Secrets should never be committed.',
        fix: 'Move secrets to environment variables (.env.local, not committed). Add to .gitignore.',
      },
      {
        rule: 'VS-SQLI',
        regex: /(?:\.from\(|\.raw\(|sql`|\.query\().*(?:\$\{|`|\+\s*(?:req\.|params|query))/gi,
        severity: 'high',
        category: 'Security',
        title: 'Potential SQL injection vector',
        description: 'Dynamic query construction detected that may allow SQL injection through user input.',
        fix: 'Use parameterized queries. Supabase client .from().select() is parameterized; avoid raw SQL with string interpolation.',
      },
      {
        rule: 'VS-RLS',
        regex: /(?:enable_rls|ALTER\s+TABLE.*ENABLE\s+ROW\s+LEVEL\s+SECURITY)/gi,
        severity: 'high',
        category: 'Security',
        title: 'RLS policy check',
        description: 'Row Level Security check — ensuring tables handling personal data have RLS enabled.',
        fix: 'Enable RLS on all tables with personal data: ALTER TABLE tablename ENABLE ROW LEVEL SECURITY;',
      },
      {
        rule: 'VS-XSS',
        regex: /dangerouslySetInnerHTML|v-html|innerHTML\s*=/gi,
        severity: 'medium',
        category: 'Security',
        title: 'Potential XSS vector',
        description: 'Direct HTML injection detected. This can allow cross-site scripting attacks.',
        fix: 'Sanitize HTML before rendering. Use DOMPurify or similar libraries. Avoid dangerouslySetInnerHTML.',
      },
      {
        rule: 'VS-DEBUG',
        regex: /console\.(log|debug|trace|info)\(.*(?:password|token|secret|key|credential)/gi,
        severity: 'medium',
        category: 'Security',
        title: 'Debug logging of sensitive data',
        description: 'Sensitive data may be logged in debug output. This is an APP 11 data handling violation.',
        fix: 'Remove debug logging of sensitive fields. Use redaction in production logging.',
      },
      {
        rule: 'VS-ENV',
        regex: /(?:NEXT_PUBLIC_(?:SECRET|PRIVATE|KEY|TOKEN|PASSWORD)|supabase_service_role_key)\s*=\s*['"]?[^'"\s\n]+['"]?/gi,
        severity: 'critical',
        category: 'Security',
        title: 'Sensitive env var exposed to client',
        description: 'A sensitive environment variable with NEXT_PUBLIC_ prefix was found, making it accessible in client-side code.',
        fix: 'Remove NEXT_PUBLIC_ prefix from secrets. Only expose anon-level keys to the client.',
      },
      {
        rule: 'VS-CORS',
        regex: /Access-Control-Allow-Origin\s*:\s*['"]\*['"]/gi,
        severity: 'high',
        category: 'Security',
        title: 'Overly permissive CORS',
        description: 'Wildcard CORS origin detected. This allows any domain to access your API.',
        fix: 'Restrict CORS to specific allowed origins. Never use * in production.',
      },
    ];

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

    return this.pruneGenericDuplicates(findings);
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
        if (entry.isDirectory()) {
          if (!excludeDirs.includes(entry.name)) {
            await walk(fullPath);
          }
        } else if (extensions.some(ext => entry.name.endsWith(ext))) {
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
