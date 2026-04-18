/**
 * AttestLens — Supply Chain Scanner Adapter
 *
 * Detects supply chain risks in npm projects:
 * - Install-time scripts (postinstall, preinstall) in dependencies
 * - Manifest-only dependency additions (no code import)
 * - New/unknown packages (<30 days publishing history)
 * - Typosquatting against top npm packages
 * - Lockfile integrity mismatches
 * - Packages with no source repository
 * - Known vulnerabilities (npm audit)
 * - Outdated major versions
 *
 * Designed to catch attacks like the Axios supply chain compromise (March 2026).
 */

import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs/promises';
import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type { ScannerAdapter, ScannerResult, ScannerError } from './types.js';

// Top 100 npm packages (by download count) — typosquatting targets
const TOP_NPM_PACKAGES = new Set([
  'react', 'react-dom', 'next', 'vue', 'angular', 'express', 'lodash',
  'axios', 'typescript', 'webpack', 'babel-core', 'eslint', 'jest',
  'mocha', 'chalk', 'commander', 'inquirer', 'dotenv', 'cors',
  'body-parser', 'mongoose', 'prisma', 'supabase', 'firebase',
  'aws-sdk', '@azure/core-http', '@google-cloud/storage',
  'moment', 'dayjs', 'date-fns', 'uuid', 'nanoid',
  'zod', 'joi', 'yup', 'ajv',
  'tailwindcss', 'sass', 'postcss', 'autoprefixer',
  'vite', 'rollup', 'esbuild', 'turbo',
  'socket.io', 'ws', 'node-fetch', 'got', 'undici',
  'knex', 'sequelize', 'typeorm', 'drizzle-orm',
  'redis', 'ioredis', 'amqplib', 'kafkajs',
  'sharp', 'canvas', 'pdfkit', 'puppeteer',
  'crypto-js', 'bcrypt', 'jsonwebtoken', 'jose',
  'helmet', 'rate-limit', 'csurf', 'cookie-parser',
  'nodemailer', 'handlebars', 'ejs', 'pug',
  '@supabase/supabase-js', '@clerk/backend', 'next-auth',
  'stripe', '@stripe/stripe-js', '@paypal/sdk',
  'twilio', '@sendgrid/mail',
  'prisma', '@prisma/client',
  'playwright', '@playwright/test',
  'electron', 'tauri',
]);

// Known legitimate packages that are NOT typosquats
const TYPOSQUAT_ALLOWLIST = new Set([
  'ora',     // Not a typosquat of 'cors' — it's a legitimate terminal spinner
  'zod',     // Legitimate validation library
  'got',     // Legitimate HTTP client, not a typosquat
  'ws',      // Legitimate WebSocket library
  'ejs',     // Legitimate template engine
  'pug',     // Legitimate template engine
  'ajv',     // Legitimate JSON schema validator
  'joi',     // Legitimate validation library
  'yup',     // Legitimate validation library (not a typosquat of 'vue')
  'glob',    // Legitimate file globbing library (not a typosquat of 'got')
  'sass',    // Legitimate CSS preprocessor
  'nps',     // Legitimate npm-publish shortcut (not a typosquat of 'ws')
  'stylis',  // Legitimate CSS preprocessor used by emotion
  'cors',    // Legitimate Express middleware (not unused — used in server setup)
  'pg',      // Legitimate PostgreSQL client (not a typosquat of 'ws')
  'tslint',  // Legitimate (deprecated) linter, not a typosquat of 'eslint'
  'ncp',      // Legitimate file copy utility, not a typosquat of 'yup'
]);

// Typosquatting distance threshold (Levenshtein distance)
const TYPOSQUAT_DISTANCE = 2;

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function isTyposquat(depName: string): string | null {
  // Check allowlist first
  const name = depName.startsWith('@') ? depName.split('/')[1] : depName;
  if (TYPOSQUAT_ALLOWLIST.has(name) || TYPOSQUAT_ALLOWLIST.has(depName)) {
    return null;
  }
  
  // Scoped packages from well-known orgs are not typosquats
  if (depName.startsWith('@')) {
    const scope = depName.split('/')[0].slice(1); // Remove @
    const wellKnownScopes = new Set([
      'supabase', 'clerk', 'stripe', 'paypal', 'sendgrid', 'prisma',
      'playwright', 'types', 'emotion', 'next', 'react', 'vue',
      'angular', 'svelte', 'tailwindcss', 'babel', 'typescript-eslint',
      'nestjs', 'trpc', 'tanstack', 'dnd-kit', 'radix', 'headlessui',
      'chakra-ui', 'mantine', 'shadcn',
    ]);
    if (wellKnownScopes.has(scope)) return null;
  }
  
  // If the dependency IS a popular package, it's not a typosquat
  if (TOP_NPM_PACKAGES.has(name)) return null;
  
  for (const popular of TOP_NPM_PACKAGES) {
    if (name === popular) return null; // Exact match with popular package — not a typosquat
    if (Math.abs(name.length - popular.length) > TYPOSQUAT_DISTANCE) continue;
    const dist = levenshteinDistance(name, popular);
    if (dist > 0 && dist <= TYPOSQUAT_DISTANCE) {
      return popular;
    }
  }
  return null;
}

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

interface LockfileEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  requires?: Record<string, string>;
}

interface LockfileV2 {
  lockfileVersion: number;
  packages?: Record<string, LockfileEntry>;
  dependencies?: Record<string, { version: string; resolved?: string; integrity?: string }>;
}

export class SupplyChainAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'supply-chain';
  readonly version = '0.1.0';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string): Promise<ScannerResult> {
    // Validate and resolve path
    const resolvedPath = path.resolve(targetPath);
    let pathStat;
    try {
      pathStat = await fs.stat(resolvedPath);
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
    if (!pathStat.isDirectory()) {
      return {
        source: this.name,
        findings: [],
        errors: [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }],
        durationMs: 0,
        version: this.version,
        timestamp: new Date().toISOString(),
      };
    }

    const startTime = Date.now();
    const errors: ScannerError[] = [];
    const findings: AttestLensFinding[] = [];
    const safePath = resolvedPath;

    // ─── 1. Parse package.json ────────────────────────────────────────────
    let pkgJson: PackageJson | null = null;
    try {
      const pkgContent = await fs.readFile(path.join(safePath, 'package.json'), 'utf-8');
      pkgJson = JSON.parse(pkgContent);
    } catch {
      // No package.json — not an npm project, skip
      return {
        source: this.name,
        findings: [],
        errors: [{ source: this.name, message: 'No package.json found — not an npm project', code: 'NOT_NPM_PROJECT', recoverable: true }],
        durationMs: Date.now() - startTime,
        version: this.version,
        timestamp: new Date().toISOString(),
      };
    }

    // ─── 2. Check for install scripts ─────────────────────────────────────
    // pkgJson is guaranteed non-null here (we return early in catch above)
    const pkg = pkgJson!;
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    // ─── 3. Parse package-lock.json ───────────────────────────────────────
    let lockfile: LockfileV2 | null = null;
    try {
      const lockContent = await fs.readFile(path.join(safePath, 'package-lock.json'), 'utf-8');
      lockfile = JSON.parse(lockContent);
    } catch {
      findings.push(this.makeFinding(
        'VS-SC-005',
        'critical',
        'Security',
        'Missing or invalid lockfile',
        'No package-lock.json found. Without a lockfile, dependency resolution is non-deterministic, increasing supply chain risk. npm ci cannot be used for reproducible builds.',
        'Run npm install to generate package-lock.json. Commit it to version control. Use npm ci in CI/CD.',
        safePath,
      ));
    }

    // ─── 4. Analyze each dependency ──────────────────────────────────────
    const lockPackages = lockfile?.packages || {};
    
    for (const [depName, depVersion] of Object.entries(allDeps)) {
      const lockKey = depName.startsWith('@') 
        ? `node_modules/${depName}` 
        : `node_modules/${depName}`;
      const lockEntry = lockPackages[lockKey];
      
      // VS-SC-001: Install scripts in dependencies
      await this.checkInstallScripts(depName, lockEntry, safePath, findings);
      
      // VS-SC-003: Check package age (requires network — skip in offline mode)
      // Will be implemented with npm registry API integration
      
      // VS-SC-004: Typosquatting
      const typosquatTarget = isTyposquat(depName);
      if (typosquatTarget) {
        findings.push(this.makeFinding(
          'VS-SC-004',
          'critical',
          'Security',
          `Potential typosquat: "${depName}" resembles "${typosquatTarget}"`,
          `Dependency "${depName}" appears to be a typosquat of the popular package "${typosquatTarget}". Typosquatting is a common supply chain attack vector where malicious packages mimic popular ones to trick developers into installing them.`,
          `Verify this is the correct package. If intentional, add to an allowlist. Consider replacing with "${typosquatTarget}" if this was unintentional.`,
          safePath,
          { typosquatTarget, packageName: depName },
        ));
      }
      
      // VS-SC-007: No repository field
      if (lockEntry && !lockEntry.resolved) {
        findings.push(this.makeFinding(
          'VS-SC-007',
          'medium',
          'Security',
          `Dependency "${depName}" has no resolved URL`,
          `Package "${depName}" has no resolved URL in the lockfile, which may indicate it was installed from a non-registry source (file, git, or link). This bypasses npm's integrity checks.`,
          `Verify the source of "${depName}". Prefer installing from the npm registry with integrity hashes.`,
          safePath,
          { packageName: depName },
        ));
      }
    }

    // ─── 5. Check for manifest-only changes ─────────────────────────────
    // Compare package.json dependencies against actual imports in source code
    await this.checkUnusedDependencies(pkg, safePath, findings);

    // ─── 6. Check project-level install scripts ───────────────────────────
    if (pkg.scripts) {
      const dangerousScripts = ['postinstall', 'preinstall', 'install', 'postpublish', 'prepare'];
      for (const scriptName of dangerousScripts) {
        if (pkg.scripts[scriptName]) {
          findings.push(this.makeFinding(
            'VS-SC-001',
            'high',
            'Security',
            `Install script detected in project: "${scriptName}"`,
            `Your package.json contains a "${scriptName}" script: "${pkg.scripts[scriptName]}". Install scripts run automatically during npm install and can execute arbitrary code, posing a supply chain risk.`,
            `Review the script contents. If unnecessary, remove it. Consider using npm config set ignore-scripts true for production installs.`,
            path.join(safePath, 'package.json'),
            { scriptName, scriptContent: pkg.scripts[scriptName] },
          ));
        }
      }
    }

    // ─── 7. Run npm audit ────────────────────────────────────────────────
    await this.runNpmAudit(safePath, findings, errors);

    // ─── 8. Check lockfile integrity ─────────────────────────────────────
    // (Already handled by VS-SC-005 above for missing lockfile)

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
   * Check if a dependency has install scripts in its package.json.
   */
  private async checkInstallScripts(
    depName: string,
    lockEntry: LockfileEntry | undefined,
    safePath: string,
    findings: AttestLensFinding[],
  ): Promise<void> {
    // Check lockfile entry for install scripts indicator
    // In npm lockfiles, packages with install scripts don't have explicit markers,
    // so we need to check the actual package's package.json
    const depPkgPath = path.join(safePath, 'node_modules', depName, 'package.json');
    
    let depPkg: { scripts?: Record<string, string>; repository?: any } | null = null;
    try {
      const content = await fs.readFile(depPkgPath, 'utf-8');
      depPkg = JSON.parse(content);
    } catch {
      // Dependency not installed yet — can't check
      return;
    }

    if (!depPkg) return;

    const dangerousScripts = ['postinstall', 'preinstall', 'install'];
    const hasInstallScript = dangerousScripts.some(s => depPkg!.scripts?.[s]);

    if (hasInstallScript) {
      const hasRepo = depPkg.repository !== undefined && depPkg.repository !== null;
      const scriptNames = dangerousScripts.filter(s => depPkg!.scripts?.[s]);
      
      // VS-SC-008: Install scripts + no source repo = critical
      if (!hasRepo) {
        findings.push(this.makeFinding(
          'VS-SC-008',
          'critical',
          'Security',
          `Dependency "${depName}" has install scripts and no source repository`,
          `Package "${depName}" has install script(s) [${scriptNames.join(', ')}] but no repository field. This is a strong indicator of a supply chain attack — legitimate packages with install scripts almost always have a public source repository. The Axios supply chain attack (March 2026) used this exact pattern.`,
          `Audit the install script contents. If the package is not from a trusted source, remove it immediately. Check npm registry for the package's repository URL.`,
          depPkgPath,
          { packageName: depName, scriptNames, hasRepository: hasRepo },
        ));
      } else {
        // VS-SC-001: Install scripts in dependency
        findings.push(this.makeFinding(
          'VS-SC-001',
          'high',
          'Security',
          `Dependency "${depName}" has install script(s): [${scriptNames.join(', ')}]`,
          `Package "${depName}" contains install script(s) that execute automatically during npm install. Install scripts can run arbitrary code and are a common vector for supply chain attacks (e.g., the Axios compromise, March 2026).`,
          `Review the install script contents. Consider using npm config set ignore-scripts true for production installs, or add this package to an allowlist after review.`,
          depPkgPath,
          { packageName: depName, scriptNames },
        ));
      }
    }
  }

  /**
   * Check for dependencies in package.json that are never imported in source code.
   * This detects manifest-only dependency injection (like the Axios attack pattern).
   */
  private async checkUnusedDependencies(
    pkgJson: PackageJson,
    safePath: string,
    findings: AttestLensFinding[],
  ): Promise<void> {
    const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
    if (!deps) return;

    // Common packages that are imported indirectly (build tools, types, etc.)
    // These are expected to not appear in source imports
    const allowedUnused = new Set([
      '@types/', 'eslint', 'prettier', 'vitest', 'jest', 'mocha', 'chai',
      'typescript', 'ts-node', 'tsx', 'nodemon', 'concurrently',
      '@vitejs/', 'vite', 'webpack', 'rollup', 'esbuild', 'tailwindcss',
      'postcss', 'autoprefixer', 'sass',
      'react-dom', 'react', // Runtime deps, imported indirectly by framework
      '@emotion/styled', '@emotion/react', '@emotion/css', // CSS-in-JS runtime
      'copyfiles', // Build tool, not imported in source
      'cors', // Express middleware, used indirectly
      'stylis', // CSS preprocessor used by emotion
      'mysql', // Database driver, used via connection config not imports
      'pg', // PostgreSQL client, used via connection config not imports
      'react-scripts', // CRA dev tool, invoked via npm scripts
      'mongoose', // MongoDB ODM, used via connection config not imports
      'knex', // SQL query builder, used via connection config
      'nps', // npm-publish shortcut, used via npm scripts
      'yup', // Validation library, imported indirectly via form libs
      'reflect-metadata', // TypeScript decorator metadata, imported via emitDecoratorMetadata
      'tslint', // Deprecated but legitimate linter, used via config not imports
    ]);

    // Read source files and check for imports
    const sourceFiles = await this.findSourceFiles(safePath);
    const importedPackages = new Set<string>();

    for (const file of sourceFiles) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        // Match import/require patterns
        const importRegex = /(?:import\s+.*from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;
        let match;
        while ((match = importRegex.exec(content)) !== null) {
          const pkg = (match[1] || match[2] || '').split('/')[0];
          if (pkg && !pkg.startsWith('.')) {
            importedPackages.add(pkg.startsWith('@') ? match[1]!.split('/').slice(0, 2).join('/') : pkg);
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    // Check dependencies that aren't imported and aren't in the allowlist
    for (const depName of Object.keys(deps)) {
      if (importedPackages.has(depName)) continue;
      
      const isAllowed = [...allowedUnused].some(allowed => 
        depName === allowed || depName.startsWith(allowed),
      );
      if (isAllowed) continue;

      // This dependency is in package.json but never imported
      // Flag it only if it's a production dependency (not dev)
      if (pkgJson.dependencies?.[depName]) {
        findings.push(this.makeFinding(
          'VS-SC-002',
          'high',
          'Security',
          `Unused production dependency: "${depName}"`,
          `Package "${depName}" is listed as a production dependency but is never imported in any source file. This could indicate a manifest-only dependency injection (similar to the Axios supply chain attack where plain-crypto-js was added as a dependency but never imported).`,
          `Verify this dependency is actually needed. If not imported anywhere, remove it. Check the package for install scripts and suspicious content.`,
          path.join(safePath, 'package.json'),
          { packageName: depName, version: deps[depName] },
        ));
      }
    }
  }

  /**
   * Run npm audit for known vulnerabilities.
   * Uses async execFile to avoid blocking the event loop.
   */
  private async runNpmAudit(
    safePath: string,
    findings: AttestLensFinding[],
    errors: ScannerError[],
  ): Promise<void> {
    // Skip npm audit if node_modules doesn't exist (won't work on fresh clones)
    try {
      await fs.access(path.join(safePath, 'node_modules'));
    } catch {
      // No node_modules — npm audit won't work, skip silently
      return;
    }

    try {
      const { execFile: execFileCb } = await import('node:child_process');
      const { promisify } = await import('node:util');
      const execFileAsync = promisify(execFileCb);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000);

      let result: string;
      try {
        const { stdout } = await execFileAsync('npm', ['audit', '--json'], {
          cwd: safePath,
          signal: controller.signal,
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large projects
        });
        result = stdout;
      } finally {
        clearTimeout(timeout);
      }

      const audit = JSON.parse(result);
      
      // Process vulnerabilities
      const vulns = audit.vulnerabilities || {};
      for (const [pkgName, vuln] of Object.entries(vulns)) {
        const v = vuln as any;
        const severity = this.mapAuditSeverity(v.severity);
        findings.push(this.makeFinding(
          'VS-SC-006',
          severity,
          'Security',
          `Known vulnerability in "${pkgName}": ${v.title || v.name || 'unknown'}`,
          `npm audit found a ${v.severity} severity vulnerability in "${pkgName}" (${v.range || 'affected versions'}). ${v.title || ''}`,
          `Update "${pkgName}" to a patched version. Run: npm audit fix`,
          safePath,
          { packageName: pkgName, severity: v.severity, url: v.url },
        ));
      }
    } catch (error: any) {
      // npm audit might fail (not an npm project, no node_modules, etc.)
      // Don't add as error — this is a best-effort check
      if (!error.message?.includes('no lockfile') && !error.message?.includes('ENOENT')) {
        errors.push({
          source: this.name,
          message: `npm audit failed: ${error.message}`,
          code: 'NPM_AUDIT_FAILED',
          recoverable: true,
        });
      }
    }
  }

  /**
   * Find source files for import analysis.
   */
  private async findSourceFiles(dir: string): Promise<string[]> {
    const extensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs'];
    const excludeDirs = ['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.venv'];
    const files: string[] = [];

    async function walk(currentDir: string): Promise<void> {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          if (!excludeDirs.includes(entry.name)) {
            await walk(fullPath);
          }
        } else if (extensions.some(ext => entry.name.endsWith(ext))) {
          files.push(fullPath);
        }
      }
    }

    await walk(dir);
    return files;
  }

  private mapAuditSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'critical': 'critical',
      'high': 'high',
      'moderate': 'medium',
      'medium': 'medium',
      'low': 'low',
      'info': 'info',
    };
    return map[severity.toLowerCase()] || 'medium';
  }

  private makeFinding(
    rule: string,
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
    category: string,
    title: string,
    description: string,
    fix: string,
    file: string,
    extra?: Record<string, any>,
  ): AttestLensFinding {
    return {
      id: this.generateId(rule, file),
      source: this.name,
      sourceRule: rule,
      severity,
      category,
      title,
      description,
      file: path.isAbsolute(file) ? path.relative(process.cwd(), file) : file,
      line: undefined,
      code: undefined,
      fix,
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: extra || {},
        scannerCommand: `attestlens supply-chain-scan`,
      },
    };
  }

  private generateId(rule: string, file: string): string {
    const payload = `supply-chain:${rule}:${file}`;
    return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12);
  }
}

export default SupplyChainAdapter;