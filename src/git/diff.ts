import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { DiffContext } from '../schema/index.js';

type ExecResult = {
  stdout: string;
  stderr: string;
};

type GitCommandOptions = {
  cwd?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
};

const DEFAULT_GIT_TIMEOUT_MS = 30_000;

export async function getChangedFiles(
  baseRef: string,
  headRef: string,
  options: GitCommandOptions = {},
): Promise<string[]> {
  try {
    validateRefName(baseRef);
    validateRefName(headRef);
    const [baseOid, headOid] = await Promise.all([
      resolveGitCommit(baseRef, options),
      resolveGitCommit(headRef, options),
    ]);
    const { stdout } = await execGit(['diff', '--name-only', '--relative', baseOid, headOid], options);
    return normalizeChangedFiles(stdout.split(/\r?\n/));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to read git diff between ${baseRef} and ${headRef}: ${message}`);
  }
}

export async function buildDiffContext(options: {
  cwd: string;
  baseRef?: string;
  headRef?: string;
  changedFiles?: string[];
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<DiffContext> {
  const hasResolvedRefs = Boolean(options.baseRef && options.headRef);
  const changedFiles = options.changedFiles
    ? normalizeChangedFiles(options.changedFiles)
    : await getChangedFiles(requireRef(options.baseRef, 'diff base'), requireRef(options.headRef, 'diff head'), {
      cwd: options.cwd,
      signal: options.signal,
      timeoutMs: options.timeoutMs,
    });

  const [addedDependencies, addedRoutes] = hasResolvedRefs
    ? await Promise.all([
      detectAddedDependencies(options.cwd, options.baseRef, options.headRef, changedFiles, options),
      detectAddedRoutes(options.cwd, options.headRef, changedFiles, options),
    ])
    : [[], []];

  return {
    baseRef: options.baseRef,
    headRef: options.headRef,
    changedFiles,
    introducedFindings: [],
    addedDependencies,
    addedRoutes,
  };
}

export function normalizeChangedFiles(files: string[]): string[] {
  const normalized = files
    .map((file) => normalizeChangedFile(file))
    .filter((file): file is string => Boolean(file));
  return Array.from(new Set(normalized)).sort();
}

async function detectAddedDependencies(
  cwd: string,
  baseRef: string | undefined,
  headRef: string | undefined,
  changedFiles: string[],
  options: Pick<GitCommandOptions, 'signal' | 'timeoutMs'> = {},
): Promise<string[]> {
  const packageFiles = changedFiles.filter((file) => /(^|\/)package(?:-lock)?\.json$/.test(file));
  if (packageFiles.length === 0) {
    return [];
  }

  const dependencies = new Set<string>();
  for (const file of packageFiles) {
    if (file.endsWith('package.json')) {
      const [baseContent, headContent] = await Promise.all([
        baseRef ? readGitFile(cwd, baseRef, file, options).catch(() => undefined) : undefined,
        readHeadFile(cwd, headRef, file, options),
      ]);
      for (const name of diffPackageJsonDependencies(baseContent, headContent)) {
        dependencies.add(name);
      }
    } else if (file.endsWith('package-lock.json')) {
      const [baseContent, headContent] = await Promise.all([
        baseRef ? readGitFile(cwd, baseRef, file, options).catch(() => undefined) : undefined,
        readHeadFile(cwd, headRef, file, options),
      ]);
      for (const name of diffPackageLockDependencies(baseContent, headContent)) {
        dependencies.add(name);
      }
    }
  }

  return Array.from(dependencies).sort();
}

async function detectAddedRoutes(
  cwd: string,
  headRef: string | undefined,
  changedFiles: string[],
  options: Pick<GitCommandOptions, 'signal' | 'timeoutMs'> = {},
): Promise<string[]> {
  const routes = new Set<string>();
  const routeCandidates = changedFiles.filter((file) => (
    /\.(?:cjs|mjs|js|jsx|ts|tsx)$/.test(file)
    && !/(^|\/)(?:node_modules|dist|build|coverage)\//.test(file)
  ));

  for (const file of routeCandidates) {
    const pathRoute = inferRouteFromPath(file);
    if (pathRoute) {
      routes.add(pathRoute);
    }

    const content = await readHeadFile(cwd, headRef, file, options).catch(() => undefined);
    if (!content) {
      continue;
    }
    for (const route of inferRoutesFromContent(content)) {
      routes.add(route);
    }
  }

  return Array.from(routes).sort();
}

function diffPackageJsonDependencies(baseContent: string | undefined, headContent: string | undefined): string[] {
  const base = parseJsonObject(baseContent);
  const head = parseJsonObject(headContent);
  if (!head) {
    return [];
  }

  const baseDeps = collectPackageJsonDependencyNames(base ?? {});
  return Array.from(collectPackageJsonDependencyNames(head))
    .filter((dependency) => !baseDeps.has(dependency))
    .sort();
}

function diffPackageLockDependencies(baseContent: string | undefined, headContent: string | undefined): string[] {
  const base = parseJsonObject(baseContent);
  const head = parseJsonObject(headContent);
  if (!head) {
    return [];
  }

  const baseDeps = collectPackageLockDependencyNames(base ?? {});
  return Array.from(collectPackageLockDependencyNames(head))
    .filter((dependency) => !baseDeps.has(dependency))
    .sort();
}

function collectPackageJsonDependencyNames(manifest: Record<string, unknown>): Set<string> {
  const names = new Set<string>();
  for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const dependencies = manifest[key];
    if (dependencies && typeof dependencies === 'object' && !Array.isArray(dependencies)) {
      for (const name of Object.keys(dependencies)) {
        names.add(name);
      }
    }
  }
  return names;
}

function collectPackageLockDependencyNames(lockfile: Record<string, unknown>): Set<string> {
  const names = new Set<string>();
  const packages = lockfile.packages;
  if (packages && typeof packages === 'object' && !Array.isArray(packages)) {
    for (const packagePath of Object.keys(packages)) {
      const name = packagePath.replace(/^node_modules\//, '');
      if (name && name !== packagePath) {
        names.add(name);
      }
    }
  }

  const dependencies = lockfile.dependencies;
  if (dependencies && typeof dependencies === 'object' && !Array.isArray(dependencies)) {
    for (const name of Object.keys(dependencies)) {
      names.add(name);
    }
  }

  return names;
}

function inferRouteFromPath(file: string): string | undefined {
  const normalized = normalizeChangedFile(file);
  if (!normalized) {
    return undefined;
  }

  const nextApi = normalized.match(/^(?:src\/)?(?:app|pages)\/api\/(.+?)(?:\/route)?\.(?:cjs|mjs|js|jsx|ts|tsx)$/);
  if (nextApi) {
    return `/api/${cleanNextRoute(nextApi[1] || '')}`;
  }

  const nextAppRoute = normalized.match(/^(?:src\/)?app\/(.+?)\/route\.(?:cjs|mjs|js|jsx|ts|tsx)$/);
  if (nextAppRoute) {
    return `/${cleanNextRoute(nextAppRoute[1] || '')}`;
  }

  return undefined;
}

function inferRoutesFromContent(content: string): string[] {
  const routes = new Set<string>();
  const routePattern = /\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  for (const match of content.matchAll(routePattern)) {
    const method = (match[1] || 'route').toUpperCase();
    const route = match[2];
    if (route?.startsWith('/')) {
      routes.add(`${method} ${route}`);
    }
  }
  return Array.from(routes);
}

function cleanNextRoute(route: string): string {
  return route
    .replace(/\/index$/, '')
    .split('/')
    .filter((part) => part && !/^\(.+\)$/.test(part))
    .map((part) => part.replace(/^\[(.+)\]$/, ':$1'))
    .join('/');
}

async function readHeadFile(
  cwd: string,
  headRef: string | undefined,
  relativePath: string,
  options: Pick<GitCommandOptions, 'signal' | 'timeoutMs'> = {},
): Promise<string | undefined> {
  if (headRef) {
    return readGitFile(cwd, headRef, relativePath, options).catch(() => undefined);
  }
  return fs.readFile(path.join(cwd, relativePath), 'utf-8').catch(() => undefined);
}

async function readGitFile(
  cwd: string,
  ref: string,
  relativePath: string,
  options: Pick<GitCommandOptions, 'signal' | 'timeoutMs'> = {},
): Promise<string> {
  const [commitOid, objectPath] = await Promise.all([
    resolveGitCommit(ref, { cwd, ...options }),
    toGitObjectPath(cwd, relativePath, options),
  ]);
  const { stdout } = await execGit(['show', `${commitOid}:${objectPath}`], { cwd, ...options });
  return stdout;
}

async function toGitObjectPath(
  cwd: string,
  relativePath: string,
  options: Pick<GitCommandOptions, 'signal' | 'timeoutMs'> = {},
): Promise<string> {
  const { stdout } = await execGit(['rev-parse', '--show-prefix'], { cwd, ...options });
  return normalizeChangedFile(`${stdout.trim()}${relativePath}`) || relativePath;
}

function parseJsonObject(content: string | undefined): Record<string, unknown> | undefined {
  if (!content) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(content);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function normalizeChangedFile(file: string): string | undefined {
  const trimmed = file.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (!trimmed || path.posix.isAbsolute(trimmed)) {
    return undefined;
  }
  const normalized = path.posix.normalize(trimmed);
  if (normalized === '.' || normalized.startsWith('../') || normalized === '..') {
    return undefined;
  }
  return normalized;
}

function requireRef(value: string | undefined, label: string): string {
  if (!value) {
    throw new Error(`Missing ${label} ref`);
  }
  validateRefName(value);
  return value;
}

async function resolveGitCommit(ref: string, options: GitCommandOptions = {}): Promise<string> {
  validateRefName(ref);
  const { stdout } = await execGit(['rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`], options);
  const oid = stdout.trim();
  if (!/^[0-9a-f]{40,64}$/i.test(oid)) {
    throw new Error(`Git ref ${ref} did not resolve to a commit`);
  }
  return oid;
}

function validateRefName(ref: string): void {
  if (!ref || ref.startsWith('-')) {
    throw new Error(`Unsupported git ref: ${ref || '(empty)'}`);
  }
}

function execGit(args: string[], options: GitCommandOptions = {}): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    execFile('git', args, {
      cwd: options.cwd ?? process.cwd(),
      maxBuffer: 10 * 1024 * 1024,
      signal: options.signal,
      timeout: options.timeoutMs ?? DEFAULT_GIT_TIMEOUT_MS,
    }, (error, stdout, stderr) => {
      if (error) {
        const details = typeof stderr === 'string' && stderr.trim()
          ? stderr.trim()
          : error.message;
        reject(new Error(details));
        return;
      }
      resolve({
        stdout: String(stdout ?? ''),
        stderr: String(stderr ?? ''),
      });
    });
  });
}
