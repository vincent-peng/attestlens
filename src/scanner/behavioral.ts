/**
 * AttestLens — Behavioral Supply Chain Scanner
 *
 * Detects what direct production dependencies do at runtime.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import type { ScannerAdapter, ScannerContext, ScannerError, ScannerResult } from './types.js';

export interface BehavioralAdapterOptions {
  enabled?: boolean;
  includeDevDependencies?: boolean;
  maxPackageBytes?: number;
}

type BehavioralSignalType =
  | 'eval_usage'
  | 'network_access'
  | 'shell_access'
  | 'env_access'
  | 'obfuscation'
  | 'high_entropy';

interface PackageJson {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface BehavioralRule {
  ruleId: string;
  signal: BehavioralSignalType;
  severity: Severity;
  title: (packageName: string) => string;
  description: (packageName: string, relativeFile: string) => string;
  fix: (packageName: string) => string;
  patterns?: RegExp[];
}

interface DetectionMatch {
  line: number;
  snippet: string;
}

const DEFAULT_MAX_PACKAGE_BYTES = 1_000_000;
const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx']);
const SKIPPED_DIR_SEGMENTS = new Set([
  '.git',
  'node_modules',
  'test',
  'tests',
  '__tests__',
  'fixture',
  'fixtures',
  'example',
  'examples',
  'docs',
  'doc',
  'benchmark',
  'benchmarks',
  'coverage',
  'dist',
]);

const BEHAVIORAL_RULES: BehavioralRule[] = [
  {
    ruleId: 'VS-BH-001',
    signal: 'eval_usage',
    severity: 'high',
    title: (packageName) => `Dependency "${packageName}" uses dynamic code execution`,
    description: (packageName, relativeFile) => `Dependency "${packageName}" contains eval-like dynamic code execution in ${relativeFile}. This can bypass normal review and runtime controls.`,
    fix: (packageName) => `Review why "${packageName}" needs dynamic code execution. Replace it with a safer package or pin and monitor the dependency if the behavior is expected.`,
    patterns: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\bvm\.runIn(?:New)?Context\s*\(/,
      /\bvm\.runInThisContext\s*\(/,
    ],
  },
  {
    ruleId: 'VS-BH-002',
    signal: 'network_access',
    severity: 'medium',
    title: (packageName) => `Dependency "${packageName}" can make network requests`,
    description: (packageName, relativeFile) => `Dependency "${packageName}" contains network-access code in ${relativeFile}. Network-capable dependencies can create data exfiltration or cross-border disclosure pathways.`,
    fix: (packageName) => `Confirm "${packageName}" requires outbound network access and document the data destination. Replace or sandbox it if network access is unexpected.`,
    patterns: [
      /\bfetch\s*\(/,
      /\bhttps?\.request\s*\(/,
      /\bhttps?\.get\s*\(/,
      /\baxios\.\w+\s*\(/,
      /\bXMLHttpRequest\b/,
      /\bWebSocket\s*\(/,
      /\brequire\s*\(\s*['"](?:node:)?https?['"]\s*\)/,
      /\bfrom\s+['"](?:node:)?https?['"]/,
    ],
  },
  {
    ruleId: 'VS-BH-003',
    signal: 'shell_access',
    severity: 'high',
    title: (packageName) => `Dependency "${packageName}" can execute shell commands`,
    description: (packageName, relativeFile) => `Dependency "${packageName}" contains child-process execution code in ${relativeFile}. Shell-capable dependencies can bypass application controls.`,
    fix: (packageName) => `Verify the command-execution behavior in "${packageName}". Prefer packages that do not spawn shell commands in production paths.`,
    patterns: [
      /\bchild_process\.\w+\s*\(/,
      /\b(?:exec|execFile|execSync|spawn|spawnSync)\s*\(/,
      /\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)/,
      /\bfrom\s+['"](?:node:)?child_process['"]/,
    ],
  },
  {
    ruleId: 'VS-BH-004',
    signal: 'env_access',
    severity: 'medium',
    title: (packageName) => `Dependency "${packageName}" reads environment variables`,
    description: (packageName, relativeFile) => `Dependency "${packageName}" reads process environment data in ${relativeFile}. Dependencies that read environment variables may access secrets or credentials.`,
    fix: (packageName) => `Review "${packageName}" environment-variable access and limit exposed secrets in the runtime environment.`,
    patterns: [
      /\bprocess\.env\b/,
    ],
  },
  {
    ruleId: 'VS-BH-005',
    signal: 'obfuscation',
    severity: 'medium',
    title: (packageName) => `Dependency "${packageName}" contains obfuscation indicators`,
    description: (packageName, relativeFile) => `Dependency "${packageName}" contains obfuscation-like code in ${relativeFile}. Obfuscation makes package behavior harder to review.`,
    fix: (packageName) => `Review the obfuscated code path in "${packageName}" and prefer transparent source when the behavior is security-sensitive.`,
    patterns: [
      /\batob\s*\(/,
      /\bString\.fromCharCode\s*\(/,
      /(?:\\x[0-9a-f]{2}){3,}/i,
      /(?:\\u[0-9a-f]{4}){3,}/i,
    ],
  },
  {
    ruleId: 'VS-BH-006',
    signal: 'high_entropy',
    severity: 'medium',
    title: (packageName) => `Dependency "${packageName}" contains a high-entropy string`,
    description: (packageName, relativeFile) => `Dependency "${packageName}" contains a high-entropy string in ${relativeFile}. High-entropy literals may indicate embedded credentials, tokens, or packed payloads.`,
    fix: (packageName) => `Review the high-entropy literal in "${packageName}" and confirm it is not a credential or hidden payload.`,
  },
];

export class BehavioralAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'behavioral';
  readonly version = '0.2.0';
  private readonly options: Required<Pick<BehavioralAdapterOptions, 'includeDevDependencies' | 'maxPackageBytes'>>;

  constructor(options: BehavioralAdapterOptions = {}) {
    this.options = {
      includeDevDependencies: options.includeDevDependencies === true,
      maxPackageBytes: options.maxPackageBytes ?? DEFAULT_MAX_PACKAGE_BYTES,
    };
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(targetPath);
    const errors: ScannerError[] = [];
    const findings: AttestLensFinding[] = [];

    let pathStat;
    try {
      pathStat = await fs.stat(resolvedPath);
    } catch {
      return this.result(findings, [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }], startTime);
    }
    if (!pathStat.isDirectory()) {
      return this.result(findings, [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }], startTime);
    }

    let pkg: PackageJson;
    try {
      pkg = JSON.parse(await fs.readFile(path.join(resolvedPath, 'package.json'), 'utf-8'));
    } catch {
      return this.result(findings, [{ source: this.name, message: 'No package.json found — not an npm project', code: 'NOT_NPM_PROJECT', recoverable: true }], startTime);
    }

    const nodeModulesPath = path.join(resolvedPath, 'node_modules');
    const hasNodeModules = await fs.stat(nodeModulesPath)
      .then(stat => stat.isDirectory())
      .catch(() => false);
    if (!hasNodeModules) {
      return this.result(findings, [{
        source: this.name,
        message: 'node_modules not found — behavioral dependency analysis skipped',
        code: 'BEHAVIORAL_NODE_MODULES_MISSING',
        recoverable: true,
      }], startTime);
    }

    const dependencies = this.getDependencies(pkg);
    for (const [packageName, declaredVersion] of Object.entries(dependencies).sort(([a], [b]) => a.localeCompare(b))) {
      throwIfAborted(context);
      const packageDir = path.join(nodeModulesPath, packageName);
      const packageStat = await fs.lstat(packageDir).catch(() => null);
      if (!packageStat || !packageStat.isDirectory() || packageStat.isSymbolicLink()) {
        continue;
      }

      const packageBytes = await calculateDirectorySize(packageDir, this.options.maxPackageBytes, context);
      if (packageBytes > this.options.maxPackageBytes) {
        continue;
      }

      const installedVersion = await readInstalledVersion(packageDir) || declaredVersion;
      const files = await collectSourceFiles(packageDir, context);
      const emittedSignals = new Set<BehavioralSignalType>();

      for (const file of files) {
        throwIfAborted(context);
        if (emittedSignals.size === BEHAVIORAL_RULES.length) break;

        let content: string;
        try {
          content = await fs.readFile(file, 'utf-8');
        } catch {
          continue;
        }

        const relativeFile = path.relative(resolvedPath, file);
        for (const rule of BEHAVIORAL_RULES) {
          if (emittedSignals.has(rule.signal)) continue;

          const match = detectRule(content, rule);
          if (!match) continue;

          findings.push(this.makeFinding({
            rule,
            packageName,
            packageVersion: installedVersion,
            file,
            relativeFile,
            line: match.line,
            snippet: match.snippet,
          }));
          emittedSignals.add(rule.signal);
        }
      }
    }

    return this.result(findings, errors, startTime);
  }

  private getDependencies(pkg: PackageJson): Record<string, string> {
    return {
      ...pkg.dependencies,
      ...pkg.optionalDependencies,
      ...(this.options.includeDevDependencies ? pkg.devDependencies : {}),
    };
  }

  private result(findings: AttestLensFinding[], errors: ScannerError[], startTime: number): ScannerResult {
    return {
      source: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      findings,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  private makeFinding(input: {
    rule: BehavioralRule;
    packageName: string;
    packageVersion: string;
    file: string;
    relativeFile: string;
    line: number;
    snippet: string;
  }): AttestLensFinding {
    const { rule, packageName, packageVersion, file, relativeFile, line, snippet } = input;
    return {
      id: this.generateId(rule.ruleId, packageName, relativeFile, line),
      source: this.name,
      sourceRule: rule.ruleId,
      severity: rule.severity,
      category: 'Behavioral Supply Chain',
      title: rule.title(packageName),
      description: rule.description(packageName, relativeFile),
      file: path.isAbsolute(file) ? path.relative(process.cwd(), file) : file,
      line,
      code: snippet,
      fix: rule.fix(packageName),
      regulationMappings: [],
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: {
          packageName,
          packageVersion,
          signal: rule.signal,
          relativeFile,
          evidence: snippet,
        },
        scannerCommand: 'attestlens behavioral-scan',
      },
    };
  }

  private generateId(ruleId: string, packageName: string, relativeFile: string, line: number): string {
    return crypto
      .createHash('sha256')
      .update(`${this.name}:${ruleId}:${packageName}:${relativeFile}:${line}`)
      .digest('hex')
      .substring(0, 12);
  }
}

function detectRule(content: string, rule: BehavioralRule): DetectionMatch | null {
  if (rule.signal === 'high_entropy') {
    return detectHighEntropyString(content);
  }

  for (const pattern of rule.patterns || []) {
    const match = findPatternMatch(content, pattern);
    if (match) return match;
  }
  return null;
}

function findPatternMatch(content: string, pattern: RegExp): DetectionMatch | null {
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index]!)) {
      return { line: index + 1, snippet: truncateSnippet(lines[index]!.trim()) };
    }
  }
  return null;
}

function detectHighEntropyString(content: string): DetectionMatch | null {
  const lines = content.split(/\r?\n/);
  const stringPattern = /(['"`])([^'"`]{16,})\1/g;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex]!;
    stringPattern.lastIndex = 0;
    let match;
    while ((match = stringPattern.exec(line)) !== null) {
      const candidate = match[2]!.trim();
      if (candidate.length < 16 || /\s/.test(candidate)) continue;
      if (shannonEntropy(candidate) > 4.5) {
        return {
          line: lineIndex + 1,
          snippet: truncateSnippet(line.replace(candidate, '[high-entropy-string]').trim()),
        };
      }
    }
  }

  return null;
}

function shannonEntropy(value: string): number {
  const frequencies = new Map<string, number>();
  for (const character of value) {
    frequencies.set(character, (frequencies.get(character) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

async function calculateDirectorySize(dir: string, maxBytes: number, context?: ScannerContext): Promise<number> {
  let total = 0;

  async function walk(currentDir: string): Promise<void> {
    throwIfAborted(context);
    if (total > maxBytes) return;

    const entries = await fs.readdir(currentDir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        const stat = await fs.stat(fullPath).catch(() => null);
        total += stat?.size || 0;
        if (total > maxBytes) return;
      }
    }
  }

  await walk(dir);
  return total;
}

async function collectSourceFiles(packageDir: string, context?: ScannerContext): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    throwIfAborted(context);
    const entries = await fs.readdir(currentDir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIR_SEGMENTS.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;
      if (entry.name.endsWith('.d.ts') || entry.name.includes('.min.')) continue;
      if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
  }

  await walk(packageDir);
  return files.sort();
}

async function readInstalledVersion(packageDir: string): Promise<string | undefined> {
  try {
    const pkg = JSON.parse(await fs.readFile(path.join(packageDir, 'package.json'), 'utf-8'));
    return typeof pkg.version === 'string' ? pkg.version : undefined;
  } catch {
    return undefined;
  }
}

function throwIfAborted(context?: ScannerContext): void {
  if (context?.signal?.aborted) {
    throw new Error('Behavioral scan aborted');
  }
}

function truncateSnippet(snippet: string): string {
  return snippet.length > 180 ? `${snippet.slice(0, 177)}...` : snippet;
}

export default BehavioralAdapter;
