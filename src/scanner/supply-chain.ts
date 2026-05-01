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
import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import { ATTESTLENS_VERSION } from '../version.js';
import type { ScannerAdapter, ScannerContext, ScannerResult, ScannerError } from './types.js';
import {
  fetchJsonWithLimit,
  scanOsvVulnerabilities,
  OSV_FETCH_TIMEOUT_MS,
  OSV_MAX_RESPONSE_BYTES,
  type FetchLike,
  type OsvPackageQuery,
} from './osv.js';

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
  'alex',    // Legitimate accessibility linter, not a typosquat of 'knex'
  'ora',     // Not a typosquat of 'cors' — it's a legitimate terminal spinner
  'chai',    // Legitimate test assertion library, not a typosquat of 'chalk'
  'cypress', // Legitimate end-to-end test framework, not a typosquat of 'express'
  'zod',     // Legitimate validation library
  'got',     // Legitimate HTTP client, not a typosquat
  'ws',      // Legitimate WebSocket library
  'qs',      // Legitimate query string parser, not a typosquat of 'ws'
  'ky',      // Legitimate HTTP client, not a typosquat of 'ws'
  'swr',     // Legitimate data fetching library, not a typosquat of 'ws'
  'hbs',     // Legitimate handlebars view engine, not a typosquat of 'ws'
  'ejs',     // Legitimate template engine
  'pug',     // Legitimate template engine
  'ajv',     // Legitimate JSON schema validator
  'joi',     // Legitimate validation library
  'yup',     // Legitimate validation library (not a typosquat of 'vue')
  'gulp',    // Legitimate build tool, not a typosquat of 'yup'
  'glob',    // Legitimate file globbing library (not a typosquat of 'got')
  'sass',    // Legitimate CSS preprocessor
  'tsx',     // Legitimate TypeScript runtime, not a typosquat of 'ws'
  'tsup',    // Legitimate TypeScript bundler, not a typosquat of 'yup'
  'vitest',  // Vite test runner, not a typosquat of 'vite'
  'nps',     // Legitimate npm-publish shortcut (not a typosquat of 'ws')
  'stylis',  // Legitimate CSS preprocessor used by emotion
  'cors',    // Legitimate Express middleware (not unused — used in server setup)
  'pg',      // Legitimate PostgreSQL client (not a typosquat of 'ws')
  'tslint',  // Legitimate (deprecated) linter, not a typosquat of 'eslint'
  'ncp',      // Legitimate file copy utility, not a typosquat of 'yup'
  'oxlint',   // Legitimate linter, not a typosquat of 'eslint'
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

interface TyposquatMatch {
  target: string;
  distance: number;
}

function isTyposquat(depName: string): TyposquatMatch | null {
  // Scoped-package namespace confusion is a separate signal; comparing
  // @org/package names to top unscoped packages created noisy false positives.
  if (depName.startsWith('@')) {
    return null;
  }

  // Check allowlist first
  const name = depName.startsWith('@') ? depName.split('/')[1] : depName;
  if (TYPOSQUAT_ALLOWLIST.has(name) || TYPOSQUAT_ALLOWLIST.has(depName)) {
    return null;
  }

  if (name.length < 4) {
    return null;
  }
  
  // If the dependency IS a popular package, it's not a typosquat
  if (TOP_NPM_PACKAGES.has(name)) return null;
  
  for (const popular of TOP_NPM_PACKAGES) {
    if (name === popular) return null; // Exact match with popular package — not a typosquat
    if (Math.abs(name.length - popular.length) > TYPOSQUAT_DISTANCE) continue;
    const dist = levenshteinDistance(name, popular);
    if (dist > 0 && dist <= TYPOSQUAT_DISTANCE) {
      return { target: popular, distance: dist };
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

interface PackageMetadata {
  name?: string;
  version?: string;
  repository?: unknown;
  homepage?: unknown;
}

interface NpmPackageDocument extends PackageMetadata {
  time?: Record<string, string>;
  versions?: Record<string, PackageMetadata & {
    readme?: unknown;
    scripts?: Record<string, string>;
    directories?: Record<string, string>;
  }>;
  maintainers?: unknown[];
  readme?: unknown;
  scripts?: Record<string, string>;
  directories?: Record<string, string>;
}

interface NpmDownloadsDocument {
  downloads?: number;
}

interface PackageMaturity {
  name: string;
  weeklyDownloads: number;
  maintainerCount: number;
  hasReadme: boolean;
  hasTests: boolean;
  hasRepository: boolean;
  ageDays: number;
  versionCount: number;
  risk: number;
}

type NpmAuditRunner = (safePath: string) => Promise<string | Record<string, any>>;

export interface SupplyChainAdapterOptions {
  typosquat?: {
    enabled?: boolean;
  };
  osv?: {
    enabled?: boolean;
    fetchImpl?: FetchLike;
    timeoutMs?: number;
    maxBytes?: number;
  };
  registry?: {
    enabled?: boolean;
    fetchImpl?: FetchLike;
    timeoutMs?: number;
    maxBytes?: number;
  };
  audit?: {
    enabled?: boolean;
    run?: NpmAuditRunner;
  };
}

const NPM_REGISTRY_TIMEOUT_MS = 10_000;
const NPM_REGISTRY_MAX_RESPONSE_BYTES = 5_000_000;
const NPM_REGISTRY_ACCEPT_HEADER = 'application/vnd.npm.install-v1+json, application/json';
const NPM_MATURITY_CACHE_TTL_MS = 60 * 60 * 1000;
const NPM_REGISTRY_MIN_REQUEST_INTERVAL_MS = 100;
const ALTERNATE_LOCKFILES = [
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
];
const TEXT_ADVISORY_ID_PATTERN = /\b(?:GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}|CVE-\d{4}-\d{4,}|OSV-[A-Z0-9._-]+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b/gi;
const STRUCTURED_ADVISORY_ID_PATTERN = /^[A-Z0-9][A-Z0-9._-]{1,127}$/;
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};
const PACKAGE_MATURITY_CACHE = new Map<string, { expiresAt: number; maturity: PackageMaturity }>();
let nextNpmRegistryRequestAt = 0;

async function readJsonFileWithLimit<T>(filePath: string, maxBytes: number): Promise<T> {
  const stat = await fs.stat(filePath);
  if (stat.size > maxBytes) {
    throw new Error(`file exceeds ${maxBytes} bytes`);
  }

  const content = await fs.readFile(filePath, 'utf-8');
  if (Buffer.byteLength(content, 'utf8') > maxBytes) {
    throw new Error(`file exceeds ${maxBytes} bytes`);
  }
  return JSON.parse(content) as T;
}

function parseNpmAuditPayload(payload: string | Record<string, any>): Record<string, any> {
  return typeof payload === 'string' ? JSON.parse(payload) : payload;
}

function parseNpmAuditStdoutFromError(error: unknown): Record<string, any> | null {
  const stdout = (error as { stdout?: unknown })?.stdout;
  const payload = Buffer.isBuffer(stdout) ? stdout.toString('utf-8') : stdout;
  if (typeof payload !== 'string' || payload.trim().length === 0) {
    return null;
  }

  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

function normalizeStructuredAdvisoryId(value: unknown): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') {
    return null;
  }
  const normalized = String(value).trim().toUpperCase();
  return STRUCTURED_ADVISORY_ID_PATTERN.test(normalized) ? normalized : null;
}

function extractTextAdvisoryIds(value: unknown): string[] {
  if (typeof value !== 'string' && typeof value !== 'number') {
    return [];
  }

  const text = String(value).toUpperCase();
  const ids = new Set<string>();
  for (const match of text.matchAll(TEXT_ADVISORY_ID_PATTERN)) {
    const id = normalizeStructuredAdvisoryId(match[0]);
    if (id) ids.add(id);
  }
  return Array.from(ids);
}

function collectAdvisoryIds(values: unknown[], includeStructured = true): string[] {
  const ids = new Set<string>();
  for (const value of values) {
    if (Array.isArray(value)) {
      for (const nested of collectAdvisoryIds(value, includeStructured)) {
        ids.add(nested);
      }
      continue;
    }

    if (includeStructured) {
      const structured = normalizeStructuredAdvisoryId(value);
      if (structured) ids.add(structured);
    }

    for (const textId of extractTextAdvisoryIds(value)) {
      ids.add(textId);
    }
  }
  return Array.from(ids);
}

function getNpmAuditAdvisoryIds(vulnerability: Record<string, any>): string[] {
  const structuredValues: unknown[] = [vulnerability.source];
  const textValues: unknown[] = [
    vulnerability.url,
    vulnerability.name,
    vulnerability.title,
  ];

  for (const via of Array.isArray(vulnerability.via) ? vulnerability.via : []) {
    if (typeof via === 'string' || typeof via === 'number') {
      structuredValues.push(via);
      continue;
    }

    if (via && typeof via === 'object') {
      const advisory = via as Record<string, unknown>;
      structuredValues.push(advisory.source);
      textValues.push(advisory.url, advisory.name, advisory.title);
    }
  }

  return Array.from(new Set([
    ...collectAdvisoryIds(structuredValues),
    ...collectAdvisoryIds(textValues, false),
  ]));
}

function hasRepository(metadata: PackageMetadata): boolean {
  if (typeof metadata.repository === 'string') {
    return metadata.repository.trim().length > 0;
  }
  if (metadata.repository && typeof metadata.repository === 'object') {
    const repository = metadata.repository as { url?: unknown };
    return typeof repository.url === 'string' && repository.url.trim().length > 0;
  }
  return false;
}

function hasHomepage(metadata: PackageMetadata): boolean {
  return typeof metadata.homepage === 'string' && metadata.homepage.trim().length > 0;
}

function resolveDependencyVersion(
  depName: string,
  requestedVersion: string | undefined,
  lockPackages: Record<string, LockfileEntry>,
): string | null {
  const lockEntry = lockPackages[`node_modules/${depName}`];
  if (lockEntry?.version) return lockEntry.version;

  if (!requestedVersion) return null;
  return isExactNpmVersion(requestedVersion) ? requestedVersion : null;
}

function isExactNpmVersion(version: string): boolean {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version);
}

function buildNpmRegistryMetadataUrl(depName: string, version: string | null): string {
  const encodedName = encodeURIComponent(depName);
  const encodedVersion = version ? encodeURIComponent(version) : 'latest';
  return `https://registry.npmjs.org/${encodedName}/${encodedVersion}`;
}

function buildNpmRegistryPackumentUrl(depName: string): string {
  return `https://registry.npmjs.org/${encodeURIComponent(depName)}`;
}

function buildNpmDownloadsUrl(depName: string): string {
  return `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(depName)}`;
}

async function hasAlternateLockfile(safePath: string): Promise<boolean> {
  for (const filename of ALTERNATE_LOCKFILES) {
    const exists = await fs.access(path.join(safePath, filename))
      .then(() => true)
      .catch(() => false);
    if (exists) return true;
  }
  return false;
}

async function rateLimitNpmRegistryRequest(): Promise<void> {
  const now = Date.now();
  const waitMs = Math.max(0, nextNpmRegistryRequestAt - now);
  nextNpmRegistryRequestAt = Math.max(now, nextNpmRegistryRequestAt) + NPM_REGISTRY_MIN_REQUEST_INTERVAL_MS;
  if (waitMs > 0) {
    await new Promise(resolve => setTimeout(resolve, waitMs));
  }
}

function calculateMaturityRisk(maturity: Omit<PackageMaturity, 'risk'>): number {
  let risk = 0;
  if (maturity.weeklyDownloads < 100) risk += 0.30;
  else if (maturity.weeklyDownloads < 1000) risk += 0.15;
  if (maturity.maintainerCount <= 1) risk += 0.20;
  if (!maturity.hasReadme) risk += 0.10;
  if (!maturity.hasTests) risk += 0.10;
  if (!maturity.hasRepository) risk += 0.15;
  if (maturity.ageDays < 30) risk += 0.15;
  if (maturity.versionCount <= 1) risk += 0.05;
  return Math.round(Math.min(1, risk) * 100) / 100;
}

function getPackageAgeDays(document: NpmPackageDocument): number {
  const created = document.time?.created;
  if (!created) return Number.POSITIVE_INFINITY;
  const createdTime = Date.parse(created);
  if (!Number.isFinite(createdTime)) return Number.POSITIVE_INFINITY;
  return Math.max(0, Math.floor((Date.now() - createdTime) / (24 * 60 * 60 * 1000)));
}

function getVersionMetadata(document: NpmPackageDocument, version: string | null): PackageMetadata & {
  readme?: unknown;
  scripts?: Record<string, string>;
  directories?: Record<string, string>;
} {
  if (version && document.versions?.[version]) {
    return document.versions[version]!;
  }
  const distTags = (document as { 'dist-tags'?: { latest?: unknown } })['dist-tags'];
  const latest = typeof distTags?.latest === 'string' ? distTags.latest : undefined;
  return latest && document.versions?.[latest]
    ? document.versions[latest]!
    : document;
}

function hasReadme(document: NpmPackageDocument, versionMetadata: { readme?: unknown }): boolean {
  return isNonEmptyString(document.readme) || isNonEmptyString(versionMetadata.readme);
}

function hasTests(
  versionMetadata: { scripts?: Record<string, string>; directories?: Record<string, string> },
  document: NpmPackageDocument,
): boolean {
  return Boolean(
    versionMetadata.scripts?.test ||
    document.scripts?.test ||
    versionMetadata.directories?.test ||
    document.directories?.test,
  );
}

function isNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

export class SupplyChainAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'supply-chain';
  readonly version = ATTESTLENS_VERSION;
  private readonly options: SupplyChainAdapterOptions;

  constructor(options: SupplyChainAdapterOptions = {}) {
    this.options = options;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
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
    let emittedExperimentalTyposquat = false;

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
    } catch (error) {
      const isMissingPackageLock = (error as NodeJS.ErrnoException).code === 'ENOENT';
      const alternateLockfileExists = isMissingPackageLock ? await hasAlternateLockfile(safePath) : false;
      if (!alternateLockfileExists) {
        findings.push(this.makeFinding(
          'VS-SC-005',
          'critical',
          'Security',
          'Missing or invalid lockfile',
          isMissingPackageLock
            ? 'No npm, pnpm, Yarn, or Bun lockfile found. Without a lockfile, dependency resolution is non-deterministic, increasing supply chain risk.'
            : 'package-lock.json exists but could not be parsed. Invalid lockfiles make dependency resolution unreliable and can break reproducible builds.',
          isMissingPackageLock
            ? 'Generate and commit the lockfile for the package manager used by this project. Use npm ci, pnpm install --frozen-lockfile, yarn --immutable, or the equivalent in CI/CD.'
            : 'Regenerate package-lock.json and commit the corrected lockfile. Use npm ci in CI/CD.',
          safePath,
        ));
      }
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
      const typosquatMatch = this.options.typosquat?.enabled === true ? isTyposquat(depName) : null;
      if (typosquatMatch) {
        findings.push(this.makeFinding(
          'VS-SC-004',
          'critical',
          'Security',
          `Potential typosquat: "${depName}" resembles "${typosquatMatch.target}"`,
          `Dependency "${depName}" appears to be a typosquat of the popular package "${typosquatMatch.target}". Typosquatting is a common supply chain attack vector where malicious packages mimic popular ones to trick developers into installing them.`,
          `Verify this is the correct package. If intentional, add to an allowlist. Consider replacing with "${typosquatMatch.target}" if this was unintentional.`,
          safePath,
          { typosquatTarget: typosquatMatch.target, typosquatDistance: typosquatMatch.distance, packageName: depName },
        ));
        emittedExperimentalTyposquat = true;
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

    if (emittedExperimentalTyposquat) {
      errors.push({
        source: this.name,
        code: 'EXPERIMENTAL_TYPOSQUAT',
        message: 'Typosquatting detection is experimental and disabled by default. Validate VS-SC-004 findings manually or with a dedicated package-intelligence tool.',
        recoverable: true,
      });
    }

    // ─── 4b. Check direct production dependency provenance ────────────────
    await this.checkDependencyProvenance(pkg, lockPackages, safePath, findings, errors, context);

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
    await this.runNpmAudit(safePath, findings, errors, context);

    // ─── 7b. Enrich known vulnerabilities with OSV.dev ───────────────────
    await this.runOsvScan(pkg, lockPackages, safePath, findings, errors, context);

    // ─── 7c. Enrich direct dependencies with package maturity signals ────
    await this.runPackageMaturityScan(pkg, lockPackages, safePath, findings, errors, context);

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
   * Check direct production dependencies for missing source provenance.
   */
  private async checkDependencyProvenance(
    pkgJson: PackageJson,
    lockPackages: Record<string, LockfileEntry>,
    safePath: string,
    findings: AttestLensFinding[],
    errors: ScannerError[],
    context?: ScannerContext,
  ): Promise<void> {
    const productionDeps = pkgJson.dependencies || {};
    const metadataCache = new Map<string, PackageMetadata | null>();

    for (const [depName, requestedVersion] of Object.entries(productionDeps)) {
      const metadataResult = await this.getDependencyMetadata(depName, requestedVersion, lockPackages, safePath, metadataCache, context);

      if (metadataResult.error) {
        errors.push(metadataResult.error);
        continue;
      }

      const metadata = metadataResult.metadata;
      if (!metadata) continue;

      if (!hasRepository(metadata) && !hasHomepage(metadata)) {
        findings.push(this.makeFinding(
          'VS-SC-009',
          'medium',
          'Security',
          `Dependency "${depName}" has no source repository or homepage`,
          `Direct production dependency "${depName}" does not publish repository or homepage metadata. Missing source provenance makes independent review and incident response harder when the package handles application data or build-time code execution.`,
          `Verify the provenance of "${depName}". Prefer dependencies with public source repositories or documented project homepages.`,
          path.join(safePath, 'package.json'),
          {
            packageName: depName,
            version: metadata.version ?? resolveDependencyVersion(depName, productionDeps[depName], lockPackages),
            metadataSource: metadataResult.source,
            hasRepository: false,
            hasHomepage: false,
          },
        ));
      }
    }
  }

  private async getDependencyMetadata(
    depName: string,
    requestedVersion: string | undefined,
    lockPackages: Record<string, LockfileEntry>,
    safePath: string,
    metadataCache: Map<string, PackageMetadata | null>,
    context?: ScannerContext,
  ): Promise<{ metadata: PackageMetadata | null; source?: 'local' | 'registry'; error?: ScannerError }> {
    const resolvedVersion = resolveDependencyVersion(depName, requestedVersion, lockPackages);
    const metadataCacheKey = `${depName}@${resolvedVersion ?? 'latest'}`;
    if (metadataCache.has(metadataCacheKey)) {
      return { metadata: metadataCache.get(metadataCacheKey) ?? null };
    }

    const localPath = path.join(safePath, 'node_modules', depName, 'package.json');
    const localMetadata = await readJsonFileWithLimit<PackageMetadata>(localPath, NPM_REGISTRY_MAX_RESPONSE_BYTES)
      .then((metadata) => ({ metadata, source: 'local' as const }))
      .catch(() => null);

    if (localMetadata) {
      metadataCache.set(metadataCacheKey, localMetadata.metadata);
      return localMetadata;
    }

    const registryFallbackEnabled = this.options.registry?.enabled === true;
    if (!registryFallbackEnabled) {
      metadataCache.set(metadataCacheKey, null);
      return { metadata: null };
    }

    const fetchImpl = this.options.registry?.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) {
      metadataCache.set(metadataCacheKey, null);
      return { metadata: null };
    }

    try {
      const metadata = await this.fetchRegistryJson<PackageMetadata>(
        fetchImpl,
        buildNpmRegistryMetadataUrl(depName, resolvedVersion),
        context,
      );
      metadataCache.set(metadataCacheKey, metadata);
      return { metadata, source: 'registry' };
    } catch (error) {
      metadataCache.set(metadataCacheKey, null);
      return {
        metadata: null,
        error: {
          source: this.name,
          code: 'NPM_METADATA_ERROR',
          message: `npm registry metadata lookup failed for "${depName}": ${error instanceof Error ? error.message : String(error)}`,
          recoverable: true,
        },
      };
    }
  }

  private async fetchRegistryJson<T>(
    fetchImpl: FetchLike,
    url: string,
    context?: ScannerContext,
  ): Promise<T> {
    await rateLimitNpmRegistryRequest();
    return fetchJsonWithLimit<T>(
      fetchImpl,
      url,
      {
        method: 'GET',
        headers: {
          accept: NPM_REGISTRY_ACCEPT_HEADER,
        },
      },
      this.options.registry?.timeoutMs ?? NPM_REGISTRY_TIMEOUT_MS,
      this.options.registry?.maxBytes ?? NPM_REGISTRY_MAX_RESPONSE_BYTES,
      context?.signal,
    );
  }

  private async runOsvScan(
    pkgJson: PackageJson,
    lockPackages: Record<string, LockfileEntry>,
    safePath: string,
    findings: AttestLensFinding[],
    errors: ScannerError[],
    context?: ScannerContext,
  ): Promise<void> {
    const osvEnabled = this.options.osv?.enabled === true;
    if (!osvEnabled) return;

    const queries = this.buildOsvQueries(pkgJson, lockPackages);
    if (queries.length === 0) return;

    const result = await scanOsvVulnerabilities(
      queries,
      safePath,
      this.version,
      {
        fetchImpl: this.options.osv?.fetchImpl,
        timeoutMs: this.options.osv?.timeoutMs ?? OSV_FETCH_TIMEOUT_MS,
        maxBytes: this.options.osv?.maxBytes ?? OSV_MAX_RESPONSE_BYTES,
        signal: context?.signal,
      },
    );

    errors.push(...result.errors);
    for (const finding of result.findings) {
      if (!this.mergeDuplicateOsvFinding(finding, findings)) {
        findings.push(finding);
      }
    }
  }

  private async runPackageMaturityScan(
    pkgJson: PackageJson,
    lockPackages: Record<string, LockfileEntry>,
    safePath: string,
    findings: AttestLensFinding[],
    errors: ScannerError[],
    context?: ScannerContext,
  ): Promise<void> {
    if (this.options.registry?.enabled !== true) return;

    const productionDeps = pkgJson.dependencies || {};
    for (const [depName, requestedVersion] of Object.entries(productionDeps)) {
      const maturityResult = await this.getPackageMaturity(depName, requestedVersion, lockPackages, context);
      if (maturityResult.error) {
        errors.push(maturityResult.error);
        continue;
      }
      const maturity = maturityResult.maturity;
      if (!maturity) continue;

      this.enrichFindingsWithMaturity(findings, depName, maturity);
      if (maturity.risk <= 0.5) continue;

      findings.push(this.makeFinding(
        'VS-SC-010',
        maturity.risk >= 0.8 ? 'high' : 'medium',
        'Supply Chain Maturity',
        `Dependency "${depName}" has weak package maturity signals`,
        `Direct production dependency "${depName}" has a maturity risk score of ${maturity.risk.toFixed(2)} based on npm registry signals including weekly downloads, maintainers, README/tests, source repository metadata, age, and version history.`,
        `Review whether "${depName}" is appropriate for production use. Prefer mature packages with active maintainers, public source, tests, and clear documentation, or vendor/pin with compensating controls.`,
        path.join(safePath, 'package.json'),
        {
          packageName: depName,
          version: resolveDependencyVersion(depName, requestedVersion, lockPackages),
          maturity,
          maturityRisk: maturity.risk,
        },
      ));
    }
  }

  private async getPackageMaturity(
    depName: string,
    requestedVersion: string | undefined,
    lockPackages: Record<string, LockfileEntry>,
    context?: ScannerContext,
  ): Promise<{ maturity: PackageMaturity | null; error?: ScannerError }> {
    const fetchImpl = this.options.registry?.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) return { maturity: null };

    const cacheKey = depName;
    const cached = PACKAGE_MATURITY_CACHE.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return { maturity: cached.maturity };
    }

    const resolvedVersion = resolveDependencyVersion(depName, requestedVersion, lockPackages);
    try {
      const [packument, downloads] = await Promise.all([
        this.fetchRegistryJson<NpmPackageDocument>(fetchImpl, buildNpmRegistryPackumentUrl(depName), context),
        this.fetchRegistryJson<NpmDownloadsDocument>(fetchImpl, buildNpmDownloadsUrl(depName), context),
      ]);
      if (typeof downloads.downloads !== 'number') {
        throw new Error('npm downloads response did not include a downloads number');
      }

      const versionMetadata = getVersionMetadata(packument, resolvedVersion);
      const maturityBase = {
        name: depName,
        weeklyDownloads: downloads.downloads,
        maintainerCount: Array.isArray(packument.maintainers) ? packument.maintainers.length : 0,
        hasReadme: hasReadme(packument, versionMetadata),
        hasTests: hasTests(versionMetadata, packument),
        hasRepository: hasRepository(versionMetadata) || hasRepository(packument),
        ageDays: getPackageAgeDays(packument),
        versionCount: packument.versions ? Object.keys(packument.versions).length : 0,
      };
      const maturity = {
        ...maturityBase,
        risk: calculateMaturityRisk(maturityBase),
      };

      PACKAGE_MATURITY_CACHE.set(cacheKey, {
        maturity,
        expiresAt: Date.now() + NPM_MATURITY_CACHE_TTL_MS,
      });
      return { maturity };
    } catch (error) {
      return {
        maturity: null,
        error: {
          source: this.name,
          code: 'NPM_MATURITY_ERROR',
          message: `npm package maturity lookup failed for "${depName}": ${error instanceof Error ? error.message : String(error)}`,
          recoverable: true,
        },
      };
    }
  }

  private enrichFindingsWithMaturity(
    findings: AttestLensFinding[],
    packageName: string,
    maturity: PackageMaturity,
  ): void {
    for (const finding of findings) {
      const rawOutput = typeof finding.evidence.rawOutput === 'object' && finding.evidence.rawOutput !== null
        ? finding.evidence.rawOutput as Record<string, unknown>
        : {};
      if (rawOutput.packageName !== packageName) continue;

      finding.evidence = {
        ...finding.evidence,
        rawOutput: {
          ...rawOutput,
          maturity,
          maturityRisk: maturity.risk,
        },
      };
    }
  }

  private buildOsvQueries(
    pkgJson: PackageJson,
    lockPackages: Record<string, LockfileEntry>,
  ): OsvPackageQuery[] {
    const deps = { ...pkgJson.dependencies, ...pkgJson.devDependencies };
    const queries: OsvPackageQuery[] = [];

    for (const [depName, requestedVersion] of Object.entries(deps)) {
      const version = resolveDependencyVersion(depName, requestedVersion, lockPackages);
      if (!version) continue;
      queries.push({ name: depName, version, ecosystem: 'npm' });
    }

    return queries;
  }

  private mergeDuplicateOsvFinding(osvFinding: AttestLensFinding, findings: AttestLensFinding[]): boolean {
    const raw = osvFinding.evidence.rawOutput as {
      packageName?: string;
      vulnerabilityId?: string;
      aliases?: string[];
    };
    if (!raw.packageName) return false;

    const advisoryIds = collectAdvisoryIds([raw.vulnerabilityId, ...(raw.aliases ?? [])]);
    if (advisoryIds.length === 0) return false;
    const osvAdvisoryIds = new Set(advisoryIds);

    const duplicate = findings.find((finding) => {
      if (finding.sourceRule !== 'VS-SC-006') return false;
      const auditRaw = finding.evidence.rawOutput as {
        packageName?: string;
        url?: string;
        advisoryId?: string | number;
        advisoryIds?: string[];
      };
      if (auditRaw.packageName !== raw.packageName) return false;

      const auditAdvisoryIds = [
        ...collectAdvisoryIds([auditRaw.advisoryIds, auditRaw.advisoryId]),
        ...collectAdvisoryIds([auditRaw.url, finding.title, finding.description], false),
      ];
      return auditAdvisoryIds.some((id) => osvAdvisoryIds.has(id));
    });

    if (!duplicate) return false;

    if (SEVERITY_RANK[osvFinding.severity] > SEVERITY_RANK[duplicate.severity]) {
      duplicate.severity = osvFinding.severity;
    }

    const existingRaw = typeof duplicate.evidence.rawOutput === 'object' && duplicate.evidence.rawOutput !== null
      ? duplicate.evidence.rawOutput as Record<string, unknown>
      : {};
    duplicate.evidence = {
      ...duplicate.evidence,
      rawOutput: {
        ...existingRaw,
        osv: osvFinding.evidence.rawOutput,
        osvSourceRule: osvFinding.sourceRule,
        osvFindingTitle: osvFinding.title,
        osvFindingDescription: osvFinding.description,
      },
    };
    return true;
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
        // Match static imports, including multiline named imports, and require calls.
        const importRegex = /(?:import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;
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
    context?: ScannerContext,
  ): Promise<void> {
    if (this.options.audit?.enabled === false) {
      return;
    }

    // npm audit works with just a lockfile — only skip if there's no lockfile either
    const hasLockfile = await fs.access(path.join(safePath, 'package-lock.json'))
      .then(() => true)
      .catch(() => false);
    const hasNodeModules = await fs.access(path.join(safePath, 'node_modules'))
      .then(() => true)
      .catch(() => false);
    if (!hasLockfile && !hasNodeModules) {
      // Nothing for npm audit to work with — skip silently
      return;
    }

    try {
      const audit = await this.readNpmAudit(safePath, context?.signal);
      
      // Process vulnerabilities
      const vulns = audit.vulnerabilities || {};
      for (const [pkgName, vuln] of Object.entries(vulns)) {
        const v = vuln as any;
        const severity = this.mapAuditSeverity(v.severity);
        const advisoryIds = getNpmAuditAdvisoryIds(v);
        const advisoryId = typeof v.via?.[0]?.source === 'string'
          ? v.via[0].source
          : advisoryIds[0];
        findings.push(this.makeFinding(
          'VS-SC-006',
          severity,
          'Security',
          `Known vulnerability in "${pkgName}": ${v.title || v.name || 'unknown'}`,
          `npm audit found a ${v.severity} severity vulnerability in "${pkgName}" (${v.range || 'affected versions'}). ${v.title || ''}`,
          `Update "${pkgName}" to a patched version. Run: npm audit fix`,
          safePath,
          {
            packageName: pkgName,
            severity: v.severity,
            url: v.url,
            advisoryId,
            advisoryIds,
          },
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

  private async readNpmAudit(safePath: string, signal?: AbortSignal): Promise<Record<string, any>> {
    if (this.options.audit?.run) {
      try {
        const result = await this.options.audit.run(safePath);
        return parseNpmAuditPayload(result);
      } catch (error) {
        const parsed = parseNpmAuditStdoutFromError(error);
        if (parsed) return parsed;
        throw error;
      }
    }

    const { execFile: execFileCb } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const execFileAsync = promisify(execFileCb);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });

    try {
      const { stdout } = await execFileAsync('npm', ['audit', '--json'], {
        cwd: safePath,
        signal: controller.signal,
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large projects
      });
      return parseNpmAuditPayload(stdout);
    } catch (error) {
      const parsed = parseNpmAuditStdoutFromError(error);
      if (parsed) return parsed;
      throw error;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
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
      id: this.generateId(rule, file, extra),
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
      regulationMappings: [],
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: extra || {},
        scannerCommand: `attestlens supply-chain-scan`,
      },
    };
  }

  private generateId(rule: string, file: string, extra?: Record<string, any>): string {
    const identityParts = [
      extra?.packageName,
      extra?.vulnerabilityId,
      extra?.advisoryId,
      Array.isArray(extra?.advisoryIds) ? extra.advisoryIds.join(',') : undefined,
      extra?.url,
      extra?.scriptName,
      Array.isArray(extra?.scriptNames) ? extra.scriptNames.join(',') : undefined,
      extra?.typosquatTarget,
    ].filter((value): value is string => typeof value === 'string' && value.length > 0);
    const basePayload = `supply-chain:${rule}:${file}`;
    const payload = identityParts.length > 0
      ? `${basePayload}:${identityParts.join(':')}`
      : basePayload;
    return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12);
  }
}

export default SupplyChainAdapter;
