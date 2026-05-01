/**
 * AttestLens — IaC Misconfiguration Scanner
 *
 * Pure TypeScript checks for conservative Dockerfile and Terraform risks.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import { ATTESTLENS_VERSION } from '../version.js';
import type { ScannerAdapter, ScannerContext, ScannerError, ScannerResult } from './types.js';
import { shouldSkipRepoScanPath } from './rules/repo-stack-checks.js';

export interface IacAdapterOptions {
  enabled?: boolean;
  maxFileBytes?: number;
}

interface IacRule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  fix: string;
}

interface IacIssue {
  rule: IacRule;
  file: string;
  line: number;
  code?: string;
  rawOutput?: Record<string, unknown>;
}

interface TerraformBlock {
  type: string;
  name: string;
  content: string;
  startLine: number;
}

const DEFAULT_MAX_FILE_BYTES = 1_000_000;
const EXCLUDED_DIRS = new Set([
  '.git',
  '.terraform',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.venv',
]);

const DATABASE_PORTS = new Set([1433, 1521, 27017, 3306, 5432, 6379, 9200, 9300]);
const SECRET_NAME_PATTERN = /(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)/i;
const PLACEHOLDER_PATTERN = /^(?:changeme|change-me|example|placeholder|dummy|test|todo|your_|xxx+|\$\{[^}]+\})$/i;

const RULES: Record<string, IacRule> = {
  'VS-IAC-001': {
    id: 'VS-IAC-001',
    severity: 'critical',
    title: 'Dockerfile explicitly runs as root',
    description: 'The Docker image explicitly switches to the root user, increasing container breakout and host-impact risk.',
    fix: 'Run the application as a dedicated non-root user and grant only the required filesystem permissions.',
  },
  'VS-IAC-002': {
    id: 'VS-IAC-002',
    severity: 'low',
    title: 'Dockerfile uses ADD instead of COPY',
    description: 'ADD has extra archive and remote URL behavior that can make builds harder to reason about.',
    fix: 'Use COPY unless archive extraction or remote URL fetching is explicitly required.',
  },
  'VS-IAC-003': {
    id: 'VS-IAC-003',
    severity: 'low',
    title: 'Dockerfile has no HEALTHCHECK',
    description: 'Images without a health check are harder to monitor and recover safely in production.',
    fix: 'Add a HEALTHCHECK instruction that validates the application is ready to serve traffic.',
  },
  'VS-IAC-004': {
    id: 'VS-IAC-004',
    severity: 'medium',
    title: 'Dockerfile exposes a privileged port',
    description: 'Privileged ports below 1024 usually require elevated privileges or platform-specific capabilities.',
    fix: 'Expose an unprivileged application port and terminate privileged ports at the platform load balancer.',
  },
  'VS-IAC-005': {
    id: 'VS-IAC-005',
    severity: 'critical',
    title: 'Dockerfile contains a secret-like ENV or ARG',
    description: 'Secrets in Dockerfile ENV or ARG instructions can be baked into image layers and leaked through registries or build logs.',
    fix: 'Move secrets to runtime secret injection and rotate any value that was built into an image.',
  },
  'VS-IAC-006': {
    id: 'VS-IAC-006',
    severity: 'medium',
    title: 'Dockerfile uses a latest image tag',
    description: 'The :latest tag makes builds non-deterministic and can silently introduce vulnerable base images.',
    fix: 'Pin base images to a specific version or immutable digest.',
  },
  'VS-IAC-007': {
    id: 'VS-IAC-007',
    severity: 'high',
    title: 'Dockerfile has no USER instruction',
    description: 'Images without a USER instruction run as root by default in many runtimes.',
    fix: 'Create and switch to a least-privilege user before the final runtime command.',
  },
  'VS-IAC-008': {
    id: 'VS-IAC-008',
    severity: 'low',
    title: 'apt-get install lacks --no-install-recommends',
    description: 'Installing recommended packages expands the image attack surface with unnecessary software.',
    fix: 'Use apt-get install --no-install-recommends and install only required packages.',
  },
  'VS-IAC-009': {
    id: 'VS-IAC-009',
    severity: 'low',
    title: 'apt-get update cache is not cleaned',
    description: 'Package-manager cache left in images increases image size and can retain stale package metadata.',
    fix: 'Clean apt caches in the same RUN layer with rm -rf /var/lib/apt/lists/* or equivalent.',
  },
  'VS-IAC-010': {
    id: 'VS-IAC-010',
    severity: 'medium',
    title: 'Dockerfile exposes a database or infrastructure port',
    description: 'Exposing database and infrastructure ports from application containers can increase lateral movement and data-access risk.',
    fix: 'Avoid exposing database or infrastructure ports from application images unless the service is intentionally public.',
  },
  'VS-IAC-011': {
    id: 'VS-IAC-011',
    severity: 'low',
    title: 'Docker build context lacks .dockerignore',
    description: 'Missing .dockerignore can copy secrets, local artifacts, and development files into the Docker build context.',
    fix: 'Add a .dockerignore that excludes secrets, node_modules, build artifacts, and local-only files.',
  },
  'VS-IAC-012': {
    id: 'VS-IAC-012',
    severity: 'medium',
    title: 'Dockerfile COPY uses a wildcard',
    description: 'Wildcard COPY instructions can unintentionally include secrets or local-only files in the image.',
    fix: 'Copy explicit files or directories and verify .dockerignore excludes sensitive paths.',
  },
  'VS-IAC-013': {
    id: 'VS-IAC-013',
    severity: 'medium',
    title: 'Dockerfile contains a hardcoded IP address',
    description: 'Hardcoded IP addresses can encode brittle or internal network dependencies into the image.',
    fix: 'Move network endpoints to environment-specific configuration with validation and documentation.',
  },
  'VS-IAC-014': {
    id: 'VS-IAC-014',
    severity: 'high',
    title: 'Dockerfile uses sudo in a RUN instruction',
    description: 'sudo in image builds usually indicates unnecessary privilege escalation inside the container build.',
    fix: 'Run build steps with the correct user and remove sudo from the Dockerfile.',
  },
  'VS-IAC-015': {
    id: 'VS-IAC-015',
    severity: 'medium',
    title: 'Dockerfile makes filesystem paths world-writable',
    description: 'World-writable paths can allow dependency or runtime compromise to modify application files.',
    fix: 'Use least-privilege ownership and narrow write permissions to explicit runtime mount points.',
  },
  'VS-IAC-016': {
    id: 'VS-IAC-016',
    severity: 'critical',
    title: 'Terraform S3 bucket lacks server-side encryption',
    description: 'S3 buckets without server-side encryption can expose stored personal information if storage controls fail.',
    fix: 'Add aws_s3_bucket_server_side_encryption_configuration or equivalent bucket encryption controls.',
  },
  'VS-IAC-017': {
    id: 'VS-IAC-017',
    severity: 'critical',
    title: 'Terraform S3 bucket is publicly accessible',
    description: 'Public S3 bucket ACLs can disclose personal information to unauthorised or overseas recipients.',
    fix: 'Remove public ACLs and enforce S3 Block Public Access unless the bucket is intentionally public and contains no personal information.',
  },
  'VS-IAC-018': {
    id: 'VS-IAC-018',
    severity: 'high',
    title: 'Terraform RDS instance lacks storage encryption',
    description: 'RDS databases without encryption at rest weaken protection for stored personal information.',
    fix: 'Set storage_encrypted = true and configure a managed KMS key where required.',
  },
  'VS-IAC-019': {
    id: 'VS-IAC-019',
    severity: 'critical',
    title: 'Terraform security group allows public ingress',
    description: 'Security groups that allow 0.0.0.0/0 or ::/0 ingress can expose services and personal information to the internet.',
    fix: 'Restrict ingress CIDRs to trusted networks or place the service behind an authenticated edge layer.',
  },
  'VS-IAC-020': {
    id: 'VS-IAC-020',
    severity: 'high',
    title: 'Terraform IAM policy grants wildcard admin access',
    description: 'Wildcard IAM actions and resources create broad blast radius for credential compromise.',
    fix: 'Replace wildcard IAM permissions with least-privilege actions and resource scopes.',
  },
  'VS-IAC-021': {
    id: 'VS-IAC-021',
    severity: 'high',
    title: 'Terraform EBS volume lacks encryption',
    description: 'Unencrypted EBS volumes weaken protection for stored application and personal data.',
    fix: 'Set encrypted = true and use an approved KMS key for sensitive workloads.',
  },
  'VS-IAC-022': {
    id: 'VS-IAC-022',
    severity: 'medium',
    title: 'Terraform Lambda function lacks VPC configuration',
    description: 'Lambda functions without explicit network placement may bypass intended private-network data controls.',
    fix: 'Add vpc_config where the function accesses private data stores or document why public-network execution is acceptable.',
  },
  'VS-IAC-023': {
    id: 'VS-IAC-023',
    severity: 'medium',
    title: 'Terraform storage resource lacks visible logging',
    description: 'Storage resources without access logging reduce the ability to investigate unauthorised access or eligible data breaches.',
    fix: 'Enable storage access logging or equivalent audit telemetry for sensitive storage resources.',
  },
  'VS-IAC-024': {
    id: 'VS-IAC-024',
    severity: 'critical',
    title: 'Terraform contains a hardcoded secret default',
    description: 'Hardcoded Terraform secret defaults can leak through state files, plans, and source control.',
    fix: 'Remove hardcoded secret defaults, rotate exposed values, and inject secrets through a secret manager.',
  },
  'VS-IAC-025': {
    id: 'VS-IAC-025',
    severity: 'low',
    title: 'Terraform provider lacks a version constraint',
    description: 'Terraform providers without version constraints make infrastructure changes non-deterministic.',
    fix: 'Add required_providers version constraints and commit the lockfile used by CI.',
  },
};

export class IacAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'iac';
  readonly version = ATTESTLENS_VERSION;
  private readonly maxFileBytes: number;

  constructor(options: IacAdapterOptions = {}) {
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: AttestLensFinding[] = [];
    const errors: ScannerError[] = [];
    const resolvedPath = path.resolve(targetPath);

    let stat;
    try {
      stat = await fs.stat(resolvedPath);
    } catch {
      return this.result(findings, [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }], startTime);
    }
    if (!stat.isDirectory()) {
      return this.result(findings, [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }], startTime);
    }

    const files = await collectIacFiles(resolvedPath, context);
    const hasDockerignore = await fs.access(path.join(resolvedPath, '.dockerignore')).then(() => true).catch(() => false);
    const terraformFiles: Array<{ path: string; content: string }> = [];

    for (const file of files) {
      throwIfAborted(context);
      const fileStat = await fs.stat(file).catch(() => null);
      if (!fileStat || fileStat.size > this.maxFileBytes) {
        continue;
      }

      const content = await fs.readFile(file, 'utf-8').catch(() => '');
      if (!content) continue;

      if (isDockerfile(file)) {
        for (const issue of scanDockerfile(resolvedPath, file, content, hasDockerignore)) {
          findings.push(this.makeFinding(resolvedPath, issue));
        }
      } else if (file.endsWith('.tf')) {
        terraformFiles.push({ path: file, content });
      }
    }

    for (const issue of scanTerraformFiles(resolvedPath, terraformFiles)) {
      findings.push(this.makeFinding(resolvedPath, issue));
    }

    return this.result(findings, errors, startTime);
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

  private makeFinding(root: string, issue: IacIssue): AttestLensFinding {
    const relativeFile = path.relative(root, issue.file).replace(/\\/g, '/');
    const code = issue.code ? truncateSnippet(redactSensitiveLine(issue.code.trim())) : undefined;
    const rawOutput = {
      iacType: isDockerfile(issue.file) ? 'dockerfile' : 'terraform',
      file: relativeFile,
      line: issue.line,
      ...issue.rawOutput,
    };

    return {
      id: this.generateId(issue.rule.id, relativeFile, issue.line, code),
      source: this.name,
      sourceRule: issue.rule.id,
      severity: issue.rule.severity,
      category: 'Infrastructure as Code',
      title: issue.rule.title,
      description: issue.rule.description,
      file: relativeFile,
      line: issue.line,
      code,
      fix: issue.rule.fix,
      fixPrompt: `${issue.rule.fix} Add a regression fixture or IaC policy check so this misconfiguration cannot be reintroduced.`,
      regulationMappings: [],
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput,
        scannerCommand: 'attestlens iac-scan',
      },
    };
  }

  private generateId(ruleId: string, file: string, line: number, code?: string): string {
    return crypto
      .createHash('sha256')
      .update(`${this.name}:${ruleId}:${file}:${line}:${code || ''}`)
      .digest('hex')
      .substring(0, 12);
  }
}

async function collectIacFiles(root: string, context?: ScannerContext): Promise<string[]> {
  const files: string[] = [];

  async function walk(dir: string): Promise<void> {
    throwIfAborted(context);
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(root, fullPath);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name) && !shouldSkipRepoScanPath(relativePath)) {
          await walk(fullPath);
        }
        continue;
      }
      if (!entry.isFile()) continue;
      if (shouldSkipRepoScanPath(relativePath)) continue;
      if (isDockerfile(fullPath) || fullPath.endsWith('.tf')) {
        files.push(fullPath);
      }
    }
  }

  await walk(root);
  return files.sort();
}

function scanDockerfile(root: string, file: string, content: string, hasDockerignore: boolean): IacIssue[] {
  const issues: IacIssue[] = [];
  const lines = content.split(/\r?\n/);
  const effectiveLines = lines.map((line, index) => ({ line, index })).filter(({ line }) => !isCommentOrBlank(line));
  const hasUser = effectiveLines.some(({ line }) => /^\s*USER\b/i.test(line));
  const hasHealthcheck = effectiveLines.some(({ line }) => /^\s*HEALTHCHECK\b/i.test(line) && !/^\s*HEALTHCHECK\s+NONE\b/i.test(line));

  for (const { line, index } of effectiveLines) {
    const lineNo = index + 1;
    if (/^\s*USER\s+(?:root|0)\b/i.test(line)) {
      issues.push(issue('VS-IAC-001', file, lineNo, line));
    }
    if (/^\s*ADD\s+/i.test(line)) {
      issues.push(issue('VS-IAC-002', file, lineNo, line));
    }
    if (/^\s*(?:ENV|ARG)\s+/i.test(line) && hasSecretAssignment(line)) {
      issues.push(issue('VS-IAC-005', file, lineNo, line));
    }
    if (/^\s*FROM\s+\S+:latest(?:\s|$)/i.test(line)) {
      issues.push(issue('VS-IAC-006', file, lineNo, line));
    }
    if (/^\s*RUN\b/i.test(line) && /\bapt-get\s+install\b/i.test(line) && !/--no-install-recommends\b/i.test(line)) {
      issues.push(issue('VS-IAC-008', file, lineNo, line));
    }
    if (/^\s*RUN\b/i.test(line) && /\bapt-get\s+update\b/i.test(line) && !/(?:rm\s+-rf\s+\/var\/lib\/apt\/lists|apt-get\s+clean)/i.test(line)) {
      issues.push(issue('VS-IAC-009', file, lineNo, line));
    }
    if (/^\s*COPY\s+.*\*/i.test(line)) {
      issues.push(issue('VS-IAC-012', file, lineNo, line));
    }
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(line) && !/\b(?:0\.0\.0\.0|127\.0\.0\.1)\b/.test(line)) {
      issues.push(issue('VS-IAC-013', file, lineNo, line));
    }
    if (/^\s*RUN\b/i.test(line) && /\bsudo\b/i.test(line)) {
      issues.push(issue('VS-IAC-014', file, lineNo, line));
    }
    if (/^\s*RUN\b/i.test(line) && /\bchmod\b[^\n]*(?:\s|=)(?:0?777|a\+w)\b/i.test(line)) {
      issues.push(issue('VS-IAC-015', file, lineNo, line));
    }

    const exposedPorts = parseExposedPorts(line);
    for (const port of exposedPorts) {
      if (port > 0 && port < 1024) {
        issues.push(issue('VS-IAC-004', file, lineNo, line, { port }));
      }
      if (DATABASE_PORTS.has(port)) {
        issues.push(issue('VS-IAC-010', file, lineNo, line, { port }));
      }
    }
  }

  if (!hasHealthcheck) {
    issues.push(issue('VS-IAC-003', file, 1, firstInstruction(lines) || lines[0] || ''));
  }
  if (!hasUser) {
    issues.push(issue('VS-IAC-007', file, 1, firstInstruction(lines) || lines[0] || ''));
  }
  if (!hasDockerignore) {
    issues.push(issue('VS-IAC-011', file, 1, path.relative(root, file)));
  }

  return issues;
}

function scanTerraformFiles(_root: string, files: Array<{ path: string; content: string }>): IacIssue[] {
  const issues: IacIssue[] = [];
  if (files.length === 0) return issues;

  const projectContent = files.map((file) => file.content).join('\n');
  const firstTerraformFile = files[0]!;

  for (const file of files) {
    const resourceBlocks = extractBlocks(file.content, 'resource');
    const variableBlocks = extractBlocks(file.content, 'variable');

    for (const block of resourceBlocks) {
      const headerLine = getLine(file.content, block.startLine);
      if (block.type === 'aws_s3_bucket') {
        if (!hasS3Encryption(projectContent, block.name)) {
          issues.push(issue('VS-IAC-016', file.path, block.startLine, headerLine, { resourceType: block.type, resourceName: block.name }));
        }
        if (!hasS3Logging(projectContent, block.name)) {
          issues.push(issue('VS-IAC-023', file.path, block.startLine, headerLine, { resourceType: block.type, resourceName: block.name }));
        }
      }
      if ((block.type === 'aws_s3_bucket' || block.type === 'aws_s3_bucket_acl') && /acl\s*=\s*"(?:public-read|public-read-write|website)"/i.test(block.content)) {
        issues.push(issue('VS-IAC-017', file.path, lineForPattern(file.content, block, /acl\s*=\s*"(?:public-read|public-read-write|website)"/i), lineForPatternText(file.content, block, /acl\s*=/i), { resourceType: block.type, resourceName: block.name }));
      }
      if (block.type === 'aws_db_instance' && !/storage_encrypted\s*=\s*true/i.test(block.content)) {
        issues.push(issue('VS-IAC-018', file.path, block.startLine, headerLine, { resourceType: block.type, resourceName: block.name }));
      }
      if ((block.type === 'aws_security_group' || block.type === 'aws_security_group_rule') && /(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*(?:"0\.0\.0\.0\/0"|"::\/0")/is.test(block.content)) {
        issues.push(issue('VS-IAC-019', file.path, lineForPattern(file.content, block, /(?:cidr_blocks|ipv6_cidr_blocks)\s*=/i), lineForPatternText(file.content, block, /(?:cidr_blocks|ipv6_cidr_blocks)\s*=/i), { resourceType: block.type, resourceName: block.name }));
      }
      if (/^aws_iam_(?:policy|role_policy|user_policy|group_policy)$/.test(block.type) && hasWildcardIamPolicy(block.content)) {
        issues.push(issue('VS-IAC-020', file.path, lineForPattern(file.content, block, /(?:Action|actions|Resource|resources)\s*[:=]/i), lineForPatternText(file.content, block, /(?:Action|actions|Resource|resources)\s*[:=]/i), { resourceType: block.type, resourceName: block.name }));
      }
      if (block.type === 'aws_ebs_volume' && !/encrypted\s*=\s*true/i.test(block.content)) {
        issues.push(issue('VS-IAC-021', file.path, block.startLine, headerLine, { resourceType: block.type, resourceName: block.name }));
      }
      if (block.type === 'aws_lambda_function' && !/\bvpc_config\s*\{/i.test(block.content)) {
        issues.push(issue('VS-IAC-022', file.path, block.startLine, headerLine, { resourceType: block.type, resourceName: block.name }));
      }
      const secretLine = findSecretLine(block.content);
      if (secretLine) {
        issues.push(issue('VS-IAC-024', file.path, block.startLine + secretLine.line - 1, secretLine.text, { resourceType: block.type, resourceName: block.name }));
      }
    }

    for (const block of variableBlocks) {
      const variableName = block.type;
      if (!SECRET_NAME_PATTERN.test(variableName)) continue;
      const defaultLine = findDefaultLine(block.content);
      if (defaultLine && !isPlaceholderValue(defaultLine.value)) {
        issues.push(issue('VS-IAC-024', file.path, block.startLine + defaultLine.line - 1, defaultLine.text, { variableName }));
      }
    }
  }

  if (hasTerraformProviderWithoutVersionConstraint(projectContent)) {
    issues.push(issue('VS-IAC-025', firstTerraformFile.path, 1, firstTerraformFile.content.split(/\r?\n/)[0] || 'terraform', { provider: 'aws' }));
  }

  return issues;
}

function issue(ruleId: keyof typeof RULES, file: string, line: number, code?: string, rawOutput?: Record<string, unknown>): IacIssue {
  return { rule: RULES[ruleId], file, line, code, rawOutput };
}

function extractBlocks(content: string, blockKind: 'resource' | 'variable'): TerraformBlock[] {
  const blocks: TerraformBlock[] = [];
  const regex = blockKind === 'resource'
    ? /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g
    : /variable\s+"([^"]+)"\s*\{/g;

  let match;
  while ((match = regex.exec(content)) !== null) {
    const openBraceIndex = content.indexOf('{', match.index);
    const closeBraceIndex = findMatchingBrace(content, openBraceIndex);
    if (closeBraceIndex === -1) continue;
    blocks.push({
      type: match[1]!,
      name: blockKind === 'resource' ? match[2]! : match[1]!,
      content: content.slice(match.index, closeBraceIndex + 1),
      startLine: lineNumberAt(content, match.index),
    });
    regex.lastIndex = closeBraceIndex + 1;
  }
  return blocks;
}

function findMatchingBrace(content: string, openBraceIndex: number): number {
  let depth = 0;
  for (let index = openBraceIndex; index < content.length; index += 1) {
    const char = content[index];
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function hasS3Encryption(projectContent: string, bucketName: string): boolean {
  return new RegExp(`aws_s3_bucket_server_side_encryption_configuration[\\s\\S]+aws_s3_bucket\\.${escapeRegex(bucketName)}\\.`, 'i').test(projectContent)
    || new RegExp(`server_side_encryption_configuration[\\s\\S]+aws_s3_bucket\\.${escapeRegex(bucketName)}\\.`, 'i').test(projectContent);
}

function hasS3Logging(projectContent: string, bucketName: string): boolean {
  return new RegExp(`aws_s3_bucket_logging[\\s\\S]+aws_s3_bucket\\.${escapeRegex(bucketName)}\\.`, 'i').test(projectContent)
    || new RegExp(`logging\\s*\\{[\\s\\S]+aws_s3_bucket\\.${escapeRegex(bucketName)}\\.`, 'i').test(projectContent);
}

function hasWildcardIamPolicy(content: string): boolean {
  const normalized = content.replace(/\s+/g, ' ');
  return /(?:Action|actions)\s*["=:]+\s*(?:\[\s*)?["']\*["']/i.test(normalized)
    && /(?:Resource|resources)\s*["=:]+\s*(?:\[\s*)?["']\*["']/i.test(normalized);
}

function hasTerraformProviderWithoutVersionConstraint(projectContent: string): boolean {
  if (!/(?:provider\s+"aws"|required_providers|source\s*=\s*"hashicorp\/aws")/i.test(projectContent)) {
    return false;
  }
  return !/required_providers[\s\S]+aws\s*=\s*\{[\s\S]+version\s*=/i.test(projectContent);
}

function findSecretLine(content: string): { line: number; text: string } | null {
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (SECRET_NAME_PATTERN.test(line) && /=\s*["'][^"']{8,}["']/.test(line) && !isPlaceholderValue(extractAssignedValue(line))) {
      return { line: index + 1, text: line };
    }
  }
  return null;
}

function findDefaultLine(content: string): { line: number; text: string; value: string } | null {
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    const match = line.match(/\bdefault\s*=\s*["']([^"']+)["']/);
    if (match) return { line: index + 1, text: line, value: match[1]! };
  }
  return null;
}

function hasSecretAssignment(line: string): boolean {
  if (!SECRET_NAME_PATTERN.test(line)) return false;
  const assignedValue = extractAssignedValue(line);
  return assignedValue !== undefined && !isPlaceholderValue(assignedValue);
}

function extractAssignedValue(line: string): string | undefined {
  const quoted = line.match(/=\s*["']([^"']+)["']/);
  if (quoted) return quoted[1]!;
  const envStyle = line.match(/(?:ENV|ARG)\s+\S*=\s*([^\s]+)/i);
  if (envStyle) return envStyle[1]!;
  const shellStyle = line.match(/\b\w*(?:password|secret|token|key)\w*\s*=\s*([^\s]+)/i);
  return shellStyle?.[1];
}

function isPlaceholderValue(value: string | undefined): boolean {
  if (!value) return true;
  return PLACEHOLDER_PATTERN.test(value.trim());
}

function parseExposedPorts(line: string): number[] {
  if (!/^\s*EXPOSE\b/i.test(line)) return [];
  return line
    .replace(/^\s*EXPOSE\s+/i, '')
    .split(/\s+/)
    .map((value) => Number.parseInt(value.split('/')[0] || '', 10))
    .filter((port) => Number.isInteger(port));
}

function lineForPattern(fullContent: string, block: TerraformBlock, pattern: RegExp): number {
  const index = block.content.search(pattern);
  if (index === -1) return block.startLine;
  return block.startLine + lineNumberAt(block.content, index) - 1;
}

function lineForPatternText(fullContent: string, block: TerraformBlock, pattern: RegExp): string {
  return getLine(fullContent, lineForPattern(fullContent, block, pattern));
}

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split(/\r?\n/).length;
}

function getLine(content: string, lineNumber: number): string {
  return content.split(/\r?\n/)[lineNumber - 1] || '';
}

function firstInstruction(lines: string[]): string | undefined {
  return lines.find((line) => !isCommentOrBlank(line));
}

function isCommentOrBlank(line: string): boolean {
  return /^\s*(?:#.*)?$/.test(line);
}

function isDockerfile(file: string): boolean {
  const basename = path.basename(file);
  return basename === 'Dockerfile' || basename.endsWith('.Dockerfile');
}

function redactSensitiveLine(line: string): string {
  return line
    .replace(/((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)[\w-]*\s*=\s*["']?)[^"'\s]+/ig, '$1[redacted]')
    .replace(/((?:ENV|ARG)\s+\S*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)\S*\s+)[^\s]+/ig, '$1[redacted]');
}

function truncateSnippet(snippet: string): string {
  return snippet.length > 180 ? `${snippet.slice(0, 177)}...` : snippet;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function throwIfAborted(context?: ScannerContext): void {
  if (context?.signal?.aborted) {
    throw new Error('IaC scan aborted');
  }
}

export default IacAdapter;
