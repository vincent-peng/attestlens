import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { AttestLensFinding, Severity } from '../../schema/index.js';

interface RepoFile {
  relativePath: string;
  content: string;
}

const REPO_EXTENSIONS = [
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.env.test',
  '.json',
  '.sql',
] as const;

const EXCLUDE_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  'dist',
  'build',
  'coverage',
  '.venv',
  '__pycache__',
  'attestlens-reports',
]);

const DOC_PATH_SEGMENTS = new Set([
  'docs',
  'doc',
  'example',
  'examples',
  'fixture',
  'fixtures',
  'sample',
  'samples',
]);

const PUBLIC_SECRET_ENV_PATTERN = /\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|NUXT_PUBLIC_)(?:SUPABASE_SERVICE_ROLE_KEY|STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|CLERK_SECRET_KEY|CLERK_WEBHOOK_SECRET|AUTH0_CLIENT_SECRET|AUTH0_SECRET|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|FIREBASE_PRIVATE_KEY|FIREBASE_CLIENT_EMAIL|FIREBASE_PROJECT_ID)\b/i;
const PLATFORM_SECRET_PATTERN = /\b(STRIPE_(?:SECRET_KEY|WEBHOOK_SECRET)|CLERK_(?:SECRET_KEY|WEBHOOK_SECRET)|AUTH0_(?:CLIENT_SECRET|SECRET)|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN)\b\s*[:=]\s*['"][^'"]{8,}['"]/i;
const PLATFORM_SECRET_EXCLUDE = /process\.env|import\.meta\.env|YOUR_|example|placeholder|dummy|changeme|sk_test_|pk_test_/i;
const FIREBASE_SERVICE_ACCOUNT_MARKERS = [
  /"type"\s*:\s*"service_account"/i,
  /"private_key_id"\s*:/i,
  /"client_email"\s*:/i,
  /"private_key"\s*:/i,
] as const;
const RLS_POLICY_PATTERN = /ENABLE\s+ROW\s+LEVEL\s+SECURITY|CREATE\s+POLICY/i;
const SUPABASE_SIGNAL_PATTERN = /@supabase\/supabase-js|NEXT_PUBLIC_SUPABASE_URL|SUPABASE_(?:URL|ANON_KEY|SERVICE_ROLE_KEY)|createClient\s*\(/i;

export async function scanRepoStackChecks(
  targetPath: string,
  scannerVersion: string,
): Promise<AttestLensFinding[]> {
  const repoFiles = await collectRepoFiles(targetPath);
  const findings: AttestLensFinding[] = [];

  const supabaseFinding = detectMissingSupabaseRls(targetPath, scannerVersion, repoFiles);
  if (supabaseFinding) {
    findings.push(supabaseFinding);
  }

  for (const file of repoFiles) {
    const firebaseFinding = detectFirebaseServiceAccount(scannerVersion, file);
    if (firebaseFinding) {
      findings.push(firebaseFinding);
    }

    findings.push(...detectPublicSecretEnv(scannerVersion, file));
    findings.push(...detectPlatformSecrets(scannerVersion, file));
  }

  return findings;
}

async function collectRepoFiles(targetPath: string): Promise<RepoFile[]> {
  const files: RepoFile[] = [];
  const basePath = path.resolve(targetPath);

  async function walk(dir: string): Promise<void> {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name)) {
          await walk(path.join(dir, entry.name));
        }
        continue;
      }

      if (!REPO_EXTENSIONS.some((extension) => entry.name.endsWith(extension))) {
        continue;
      }

      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(basePath, fullPath);
      if (isDocumentationOrExamplePath(relativePath)) {
        continue;
      }

      try {
        const content = await fs.readFile(fullPath, 'utf-8');
        files.push({ relativePath, content });
      } catch {
        // Skip unreadable files.
      }
    }
  }

  await walk(basePath);
  return files;
}

function isDocumentationOrExamplePath(relativePath: string): boolean {
  const segments = relativePath.split(path.sep).map((segment) => segment.toLowerCase());
  return segments.some((segment) => DOC_PATH_SEGMENTS.has(segment));
}

function detectMissingSupabaseRls(
  targetPath: string,
  scannerVersion: string,
  repoFiles: RepoFile[],
): AttestLensFinding | null {
  const sqlFiles = repoFiles.filter((file) => file.relativePath.endsWith('.sql'));
  const hasSupabaseSignal = repoFiles.some((file) => SUPABASE_SIGNAL_PATTERN.test(file.content));
  const hasSqlSchema = sqlFiles.length > 0;
  const hasRlsPolicy = sqlFiles.some((file) => RLS_POLICY_PATTERN.test(file.content));

  if (!hasSupabaseSignal || !hasSqlSchema || hasRlsPolicy) {
    return null;
  }

  const sqlFile = sqlFiles[0];
  if (!sqlFile) {
    return null;
  }

  return makeFinding(
    scannerVersion,
    'VS-SUPA-RLS-MISSING',
    'high',
    'Database',
    'Missing Row Level Security in Supabase SQL migrations',
    'Supabase usage and SQL migrations were detected, but no ENABLE ROW LEVEL SECURITY or CREATE POLICY statements were found outside docs/examples. Personal-data tables may be readable without table-level access controls.',
    sqlFile.relativePath,
    1,
    'Add Row Level Security to each table that holds personal data and pair it with explicit CREATE POLICY statements before shipping the migration.',
  );
}

function detectFirebaseServiceAccount(
  scannerVersion: string,
  file: RepoFile,
): AttestLensFinding | null {
  const matches = FIREBASE_SERVICE_ACCOUNT_MARKERS.filter((pattern) => pattern.test(file.content));
  if (matches.length < 2 || !/"type"\s*:\s*"service_account"/i.test(file.content)) {
    return null;
  }

  return makeFinding(
    scannerVersion,
    'VS-FB-SERVICE-ACCOUNT',
    'critical',
    'Secrets',
    'Committed Firebase service account credentials',
    'Firebase Admin SDK service account material was found in the repository. This grants privileged access to Firebase resources and must never be committed to source control.',
    file.relativePath,
    findLineNumber(file.content, /"type"\s*:\s*"service_account"/i),
    'Remove the service account file from the repository, rotate the compromised credentials, and load Admin SDK credentials from a server-side secret manager instead.',
  );
}

function detectPublicSecretEnv(
  scannerVersion: string,
  file: RepoFile,
): AttestLensFinding[] {
  const findings: AttestLensFinding[] = [];
  const lines = file.content.split('\n');

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] || '';
    const match = line.match(PUBLIC_SECRET_ENV_PATTERN);
    if (!match) {
      continue;
    }

    findings.push(makeFinding(
      scannerVersion,
      'VS-PUBLIC-SECRET-ENV',
      'critical',
      'Secrets',
      `Client-exposed public env prefix on ${match[0]}`,
      'A public env prefix is exposing a secret-bearing variable name to the client bundle. This pattern often leaks privileged credentials into browser-accessible code.',
      file.relativePath,
      index + 1,
      'Remove the public prefix from this variable, move the secret to a server-only environment variable, and expose only publishable or anon-level values to the client.',
      line.trim(),
    ));
  }

  return findings;
}

function detectPlatformSecrets(
  scannerVersion: string,
  file: RepoFile,
): AttestLensFinding[] {
  const findings: AttestLensFinding[] = [];
  const lines = file.content.split('\n');

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] || '';

    if (PUBLIC_SECRET_ENV_PATTERN.test(line)) {
      continue;
    }

    const match = line.match(PLATFORM_SECRET_PATTERN);
    if (!match || PLATFORM_SECRET_EXCLUDE.test(line)) {
      continue;
    }

    const variableName = match[1] || 'platform secret';
    findings.push(makeFinding(
      scannerVersion,
      'VS-PLATFORM-SECRET',
      'critical',
      'Secrets',
      `Hardcoded ${formatPlatformSecretTitle(variableName)}`,
      'A platform secret or webhook signing secret is hardcoded in the repository. This grants direct access to vendor resources or allows forged inbound webhook traffic.',
      file.relativePath,
      index + 1,
      'Rotate the secret, move it to a server-side environment variable or secret manager, and keep webhook verification secrets out of client or committed source files.',
      line.trim(),
    ));
  }

  return findings;
}

function formatPlatformSecretTitle(variableName: string): string {
  return variableName
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function findLineNumber(content: string, pattern: RegExp): number {
  const lines = content.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index] || '')) {
      return index + 1;
    }
  }
  return 1;
}

function makeFinding(
  scannerVersion: string,
  sourceRule: string,
  severity: Severity,
  category: string,
  title: string,
  description: string,
  file: string,
  line: number,
  fix: string,
  code?: string,
): AttestLensFinding {
  const payload = `${sourceRule}:${file}:${line}`;

  return {
    id: crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12),
    source: 'guardvibe',
    sourceRule,
    severity,
    category,
    title,
    description,
    file,
    line,
    code,
    fix,
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion,
      rawOutput: {
        sourceRule,
        file,
        line,
      },
      scannerCommand: 'attestlens stack-checks',
    },
  };
}
