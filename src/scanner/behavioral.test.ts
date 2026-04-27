import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { BehavioralAdapter } from './behavioral.js';

let cleanupDirs: string[] = [];

describe('BehavioralAdapter', () => {
  afterEach(async () => {
    await Promise.all(cleanupDirs.map(dir => fs.rm(dir, { recursive: true, force: true })));
    cleanupDirs = [];
  });

  it('detects the six behavioral supply-chain signals', async () => {
    const projectDir = await createBehavioralProject({
      dependencies: {
        'behavior-pkg': {
          'eval.js': 'export const run = (code) => eval(code); new Function("return 1");',
          'network.js': 'import http from "node:http"; fetch("https://example.com/audit"); http.request({});',
          'shell.js': 'const child_process = require("child_process"); child_process.execSync("id");',
          'env.js': 'export const token = process.env.SECRET_TOKEN;',
          'obfuscation.js': 'const value = String.fromCharCode(65,66,67); const packed = "\\\\x61\\\\x62\\\\x63";',
          'entropy.js': 'const key = "uK8mN2vQ5xR7sT9wY3zA6bC1dE4fG7hJ";',
        },
      },
    });

    const result = await new BehavioralAdapter().scan(projectDir);

    expect(result.errors).toHaveLength(0);
    expect(result.findings.map(finding => finding.sourceRule).sort()).toEqual([
      'VS-BH-001',
      'VS-BH-002',
      'VS-BH-003',
      'VS-BH-004',
      'VS-BH-005',
      'VS-BH-006',
    ]);
    expect(result.findings.every(finding => finding.source === 'behavioral')).toBe(true);
    expect(result.findings.every(finding => finding.category === 'Behavioral Supply Chain')).toBe(true);
  });

  it('returns a recoverable skip when node_modules is absent', async () => {
    const projectDir = await createBehavioralProject({ dependencies: {}, installNodeModules: false });

    const result = await new BehavioralAdapter().scan(projectDir);

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toContainEqual(expect.objectContaining({
      code: 'BEHAVIORAL_NODE_MODULES_MISSING',
      recoverable: true,
    }));
  });

  it('skips dev dependencies by default', async () => {
    const projectDir = await createBehavioralProject({
      devDependencies: {
        'dev-only-pkg': {
          'index.js': 'eval("dev only");',
        },
      },
    });

    const result = await new BehavioralAdapter().scan(projectDir);

    expect(result.findings).toHaveLength(0);
  });

  it('skips symlinked packages, oversized packages, fixtures, and minified files', async () => {
    const projectDir = await createBehavioralProject({
      dependencies: {
        'oversized-pkg': {
          'index.js': 'eval("too large");',
          'large.txt': 'x'.repeat(256),
        },
        'fixture-pkg': {
          'fixtures/sample.js': 'eval("fixture only");',
          'dist/app.min.js': 'eval("minified only");',
        },
      },
    });
    const realPackageDir = path.join(projectDir, 'real-workspace-package');
    await fs.mkdir(realPackageDir, { recursive: true });
    await fs.writeFile(path.join(realPackageDir, 'index.js'), 'eval("workspace package");');
    await fs.symlink(realPackageDir, path.join(projectDir, 'node_modules', 'workspace-pkg'));
    await updatePackageJson(projectDir, {
      dependencies: {
        'oversized-pkg': '1.0.0',
        'fixture-pkg': '1.0.0',
        'workspace-pkg': '1.0.0',
      },
    });

    const result = await new BehavioralAdapter({ maxPackageBytes: 64 }).scan(projectDir);

    expect(result.findings).toHaveLength(0);
  });

  it('emits at most one finding per package per signal', async () => {
    const projectDir = await createBehavioralProject({
      dependencies: {
        'repeat-pkg': {
          'index.js': [
            'eval("one");',
            'new Function("return 2");',
            'eval("three");',
          ].join('\n'),
        },
      },
    });

    const result = await new BehavioralAdapter().scan(projectDir);

    expect(result.findings.filter(finding => finding.sourceRule === 'VS-BH-001')).toHaveLength(1);
  });
});

async function createBehavioralProject(options: {
  dependencies?: Record<string, Record<string, string>>;
  optionalDependencies?: Record<string, Record<string, string>>;
  devDependencies?: Record<string, Record<string, string>>;
  installNodeModules?: boolean;
}): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-behavioral-'));
  cleanupDirs.push(projectDir);

  const dependencies = toVersionMap(options.dependencies);
  const optionalDependencies = toVersionMap(options.optionalDependencies);
  const devDependencies = toVersionMap(options.devDependencies);
  await fs.writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'behavioral-project',
    version: '1.0.0',
    dependencies,
    optionalDependencies,
    devDependencies,
  }, null, 2));

  if (options.installNodeModules !== false) {
    await fs.mkdir(path.join(projectDir, 'node_modules'), { recursive: true });
    for (const [packageName, files] of Object.entries({
      ...options.dependencies,
      ...options.optionalDependencies,
      ...options.devDependencies,
    })) {
      await writeDependency(projectDir, packageName, files);
    }
  }

  return projectDir;
}

async function writeDependency(projectDir: string, packageName: string, files: Record<string, string>): Promise<void> {
  const packageDir = path.join(projectDir, 'node_modules', packageName);
  await fs.mkdir(packageDir, { recursive: true });
  await fs.writeFile(path.join(packageDir, 'package.json'), JSON.stringify({
    name: packageName,
    version: '1.0.0',
  }, null, 2));

  for (const [relativePath, content] of Object.entries(files)) {
    const filePath = path.join(packageDir, relativePath);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content);
  }
}

async function updatePackageJson(projectDir: string, patch: Record<string, unknown>): Promise<void> {
  const packageJsonPath = path.join(projectDir, 'package.json');
  const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf-8'));
  await fs.writeFile(packageJsonPath, JSON.stringify({ ...packageJson, ...patch }, null, 2));
}

function toVersionMap(packages: Record<string, Record<string, string>> | undefined): Record<string, string> | undefined {
  if (!packages || Object.keys(packages).length === 0) {
    return undefined;
  }
  return Object.fromEntries(Object.keys(packages).map(packageName => [packageName, '1.0.0']));
}
