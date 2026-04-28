import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { SupplyChainAdapter } from './supply-chain.js';
import { OSV_QUERY_BATCH_URL, OSV_VULN_URL, type FetchLike } from './osv.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

describe('SupplyChainAdapter', { timeout: 20000 }, () => {
  const adapter = new SupplyChainAdapter({
    osv: { enabled: false },
    registry: { enabled: false },
    audit: { enabled: false },
  });
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-sc-test-'));
  });

  afterAll(async () => {
    await fs.rm(tmpDir, { recursive: true }).catch(() => {});
  });

  it('should be available', async () => {
    expect(await adapter.isAvailable()).toBe(true);
  });

  it('should detect missing lockfile', async () => {
    // Create a minimal npm project with no lockfile
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: { express: '^4.18.0' },
    };
    await fs.writeFile(path.join(tmpDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    const result = await adapter.scan(tmpDir);
    const lockfileFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-005');
    expect(lockfileFindings.length).toBeGreaterThan(0);
    expect(lockfileFindings[0].title).toContain('lockfile');
  });

  it('should preserve legacy IDs for non-package-specific findings', async () => {
    const missingLockDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-sc-legacy-id-'));
    const pkgJson = {
      name: 'legacy-id-project',
      version: '1.0.0',
      dependencies: { express: '^4.18.0' },
    };
    await fs.writeFile(path.join(missingLockDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(missingLockDir);

    const missingLockFinding = result.findings.find(f => f.sourceRule === 'VS-SC-005');
    const expectedId = crypto
      .createHash('sha256')
      .update(`supply-chain:VS-SC-005:${missingLockDir}`)
      .digest('hex')
      .substring(0, 12);
    expect(missingLockFinding?.id).toBe(expectedId);

    await fs.rm(missingLockDir, { recursive: true }).catch(() => {});
  });

  it('should suppress typosquatting by default', async () => {
    const typosquatDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-typo-'));
    
    // Package with a typosquat dependency
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: { 'lodas': '^4.18.0' }, // typosquat of 'lodash'
    };
    await fs.writeFile(path.join(typosquatDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(typosquatDir, 'package-lock.json'), '{}');

    const result = await adapter.scan(typosquatDir);
    const typoFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-004');
    expect(typoFindings).toHaveLength(0);
    expect(result.errors.some(error => error.code === 'EXPERIMENTAL_TYPOSQUAT')).toBe(false);

    await fs.rm(typosquatDir, { recursive: true }).catch(() => {});
  });

  it('should detect typosquatting when explicitly enabled', async () => {
    const typosquatDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-typo-'));

    // Package with a typosquat dependency
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: { 'lodas': '^4.18.0' }, // typosquat of 'lodash'
    };
    await fs.writeFile(path.join(typosquatDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(typosquatDir, 'package-lock.json'), '{}');

    const localAdapter = new SupplyChainAdapter({
      typosquat: { enabled: true },
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(typosquatDir);
    const typoFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-004');
    expect(typoFindings.length).toBeGreaterThan(0);
    expect(typoFindings[0].title).toContain('typosquat');
    expect(typoFindings[0].title).toContain('lodas');
    expect(typoFindings[0].title).toContain('lodash');
    expect(typoFindings[0].evidence.rawOutput).toMatchObject({
      packageName: 'lodas',
      typosquatTarget: 'lodash',
      typosquatDistance: 1,
    });
    expect(result.errors.some(error => error.code === 'EXPERIMENTAL_TYPOSQUAT' && error.recoverable)).toBe(true);

    await fs.rm(typosquatDir, { recursive: true }).catch(() => {});
  });

  it('should not flag allowlisted packages as typosquats', async () => {
    const allowDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-allow-'));
    
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: { ora: '^6.0.0' }, // 'ora' looks like 'cors' but is legitimate
    };
    await fs.writeFile(path.join(allowDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(allowDir, 'package-lock.json'), '{}');

    const result = await new SupplyChainAdapter({
      typosquat: { enabled: true },
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    }).scan(allowDir);
    const oraFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-004' && f.title.includes('ora'));
    expect(oraFindings.length).toBe(0);

    await fs.rm(allowDir, { recursive: true }).catch(() => {});
  });

  it('should not flag common short, scoped, or same-ecosystem packages as typosquats', async () => {
    const allowDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-typo-fp-'));
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: {
        qs: '^6.0.0',
        ky: '^1.0.0',
        swr: '^2.0.0',
        chai: '^5.0.0',
        cypress: '^13.0.0',
        tsup: '^8.0.0',
        vitest: '^3.0.0',
        '@eslint/eslintrc': '^3.0.0',
        '@actions/core': '^1.0.0',
      },
    };
    await fs.writeFile(path.join(allowDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(allowDir, 'package-lock.json'), '{}');

    const result = await new SupplyChainAdapter({
      typosquat: { enabled: true },
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    }).scan(allowDir);
    expect(result.findings.filter(f => f.sourceRule === 'VS-SC-004')).toHaveLength(0);

    await fs.rm(allowDir, { recursive: true }).catch(() => {});
  });

  it('should accept non-npm lockfiles as deterministic lock evidence', async () => {
    const pnpmDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-pnpm-lock-'));
    const pkgJson = {
      name: 'pnpm-project',
      version: '1.0.0',
      dependencies: { express: '^4.18.0' },
    };
    await fs.writeFile(path.join(pnpmDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(pnpmDir, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n');
    await fs.writeFile(path.join(pnpmDir, 'index.js'), "import express from 'express';\n");

    const result = await adapter.scan(pnpmDir);
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-005')).toBe(false);

    await fs.rm(pnpmDir, { recursive: true }).catch(() => {});
  });

  it('should not flag popular packages as typosquats of other popular packages', async () => {
    const popularDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-popular-'));
    
    // jest is a popular package, should NOT be flagged as a typosquat of 'next'
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: { jest: '^29.0.0', next: '^14.0.0' },
    };
    await fs.writeFile(path.join(popularDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(popularDir, 'package-lock.json'), '{}');

    const result = await new SupplyChainAdapter({
      typosquat: { enabled: true },
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    }).scan(popularDir);
    const jestFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-004' && f.title.includes('jest'));
    expect(jestFindings.length).toBe(0);

    await fs.rm(popularDir, { recursive: true }).catch(() => {});
  });

  it('should detect install scripts in project package.json', async () => {
    const scriptDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-script-'));
    
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      scripts: {
        postinstall: 'node build.js',
      },
      dependencies: {},
    };
    await fs.writeFile(path.join(scriptDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(scriptDir, 'package-lock.json'), '{}');

    const result = await adapter.scan(scriptDir);
    const scriptFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-001');
    expect(scriptFindings.length).toBeGreaterThan(0);
    expect(scriptFindings[0].title).toContain('postinstall');

    await fs.rm(scriptDir, { recursive: true }).catch(() => {});
  });

  it('should not flag multiline named imports as unused dependencies', async () => {
    const importDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-multiline-import-'));
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      dependencies: { recharts: '^2.12.7' },
    };
    await fs.writeFile(path.join(importDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(importDir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'test-project',
          version: '1.0.0',
          dependencies: { recharts: '^2.12.7' },
        },
        'node_modules/recharts': {
          version: '2.12.7',
          resolved: 'https://registry.npmjs.org/recharts/-/recharts-2.12.7.tgz',
          integrity: 'sha512-test',
        },
      },
    }, null, 2));
    await fs.writeFile(path.join(importDir, 'chart.tsx'), [
      "import {",
      "  ResponsiveContainer,",
      "  LineChart",
      "} from 'recharts';",
      '',
      'export const Chart = LineChart;',
    ].join('\n'));

    const result = await adapter.scan(importDir);
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-002')).toBe(false);

    await fs.rm(importDir, { recursive: true }).catch(() => {});
  });

  it('should return empty findings for non-npm project', async () => {
    const emptyDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-empty-'));
    
    const result = await adapter.scan(emptyDir);
    expect(result.findings.length).toBe(0);
    expect(result.errors.some(e => e.code === 'NOT_NPM_PROJECT')).toBe(true);

    await fs.rm(emptyDir, { recursive: true }).catch(() => {});
  });

  it('should return error for invalid path', async () => {
    const result = await adapter.scan('/nonexistent/path/that/does/not/exist');
    expect(result.findings.length).toBe(0);
    expect(result.errors.some(e => e.code === 'INVALID_PATH' || e.code === 'NOT_DIRECTORY')).toBe(true);
  });

  it('should produce findings with required fields', async () => {
    const scriptDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-fields-'));
    
    const pkgJson = {
      name: 'test-project',
      version: '1.0.0',
      scripts: { postinstall: 'echo test' },
      dependencies: {},
    };
    await fs.writeFile(path.join(scriptDir, 'package.json'), JSON.stringify(pkgJson, null, 2));
    await fs.writeFile(path.join(scriptDir, 'package-lock.json'), '{}');

    const result = await adapter.scan(scriptDir);
    expect(result.source).toBe('supply-chain');
    expect(result.version).toBe('0.2.0');
    expect(result.timestamp).toBeDefined();
    expect(result.durationMs).toBeGreaterThanOrEqual(0);

    if (result.findings.length > 0) {
      const finding = result.findings[0];
      expect(finding.id).toBeDefined();
      expect(finding.source).toBe('supply-chain');
      expect(finding.sourceRule).toBeDefined();
      expect(finding.severity).toBeDefined();
      expect(finding.title).toBeDefined();
      expect(finding.description).toBeDefined();
      expect(finding.fix).toBeDefined();
      expect(finding.appMappings).toBeDefined();
    }

    await fs.rm(scriptDir, { recursive: true }).catch(() => {});
  });

  it('should emit VS-SC-009 for direct production dependencies with no repository or homepage', async () => {
    const provenanceDir = await createPackageProject({
      dependencyName: 'no-repo-package',
      dependencyPackageJson: {
        name: 'no-repo-package',
        version: '1.0.0',
      },
      installDependency: true,
    });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    const provenanceFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-009');
    expect(provenanceFindings).toHaveLength(1);
    expect(provenanceFindings[0].title).toContain('no source repository or homepage');
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-007')).toBe(false);
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-008')).toBe(false);

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should not emit VS-SC-009 when repository or homepage metadata exists', async () => {
    const provenanceDir = await createPackageProject({
      dependencyName: 'sourced-package',
      dependencyPackageJson: {
        name: 'sourced-package',
        version: '1.0.0',
        repository: { type: 'git', url: 'https://github.com/example/sourced-package.git' },
      },
      installDependency: true,
    });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    expect(result.findings.some(f => f.sourceRule === 'VS-SC-009')).toBe(false);

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should fall back to npm registry metadata for VS-SC-009 when local package metadata is absent', async () => {
    const provenanceDir = await createPackageProject({
      dependencyName: 'remote-no-repo',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({
      name: 'remote-no-repo',
      version: '1.0.0',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
      });
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    const provenanceFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-009');
    expect(provenanceFindings).toHaveLength(1);
    expect(provenanceFindings[0].evidence.rawOutput).toMatchObject({
      packageName: 'remote-no-repo',
      metadataSource: 'registry',
    });
    expect(calls).toContain('https://registry.npmjs.org/remote-no-repo/1.0.0');

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should use lightweight latest registry metadata when no exact dependency version is known', async () => {
    const provenanceDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-sc-registry-latest-'));
    await fs.writeFile(path.join(provenanceDir, 'package.json'), JSON.stringify({
      name: 'test-project',
      version: '1.0.0',
      dependencies: { 'range-only-package': '^1.0.0' },
    }, null, 2));
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({
        name: 'range-only-package',
        version: '1.2.3',
        repository: { type: 'git', url: 'https://github.com/example/range-only-package.git' },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    expect(calls).toContain('https://registry.npmjs.org/range-only-package/latest');
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-009')).toBe(false);

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should treat npm registry metadata failures as recoverable warnings, not findings', async () => {
    const provenanceDir = await createPackageProject({
      dependencyName: 'metadata-fails',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl: FetchLike = async () => new Response('not found', { status: 404 });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    expect(result.findings.some(f => f.sourceRule === 'VS-SC-009')).toBe(false);
    expect(result.errors.some(error => error.code === 'NPM_METADATA_ERROR' && error.recoverable)).toBe(true);

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should not call injected npm registry fetch when registry enrichment is disabled', async () => {
    const provenanceDir = await createPackageProject({
      dependencyName: 'registry-disabled',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }));

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: false, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-009')).toBe(false);

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should emit VS-SC-010 for low-maturity dependencies when registry enrichment is enabled', async () => {
    const dependencyName = uniquePackageName('low-maturity');
    const maturityDir = await createPackageProject({
      dependencyName,
      dependencyPackageJson: null,
      installDependency: false,
    });
    const calls: string[] = [];
    const fetchImpl = makeMaturityFetch(calls, dependencyName, {
      weeklyDownloads: 42,
      maintainerCount: 1,
      hasRepository: false,
      hasReadme: false,
      hasTests: false,
      created: '2026-04-20T00:00:00.000Z',
      versionCount: 1,
    });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(maturityDir);

    const maturityFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-010');
    expect(maturityFindings).toHaveLength(1);
    expect(maturityFindings[0].severity).toBe('high');
    expect(maturityFindings[0].evidence.rawOutput).toMatchObject({
      packageName: dependencyName,
      maturity: expect.objectContaining({
        weeklyDownloads: 42,
        maintainerCount: 1,
        hasRepository: false,
        risk: expect.any(Number),
      }),
    });
    expect((maturityFindings[0].evidence.rawOutput as any).maturity.risk).toBeGreaterThan(0.5);
    const provenanceFinding = result.findings.find(f => f.sourceRule === 'VS-SC-009');
    expect(provenanceFinding?.evidence.rawOutput).toMatchObject({
      packageName: dependencyName,
      maturityRisk: expect.any(Number),
    });
    expect(calls).toContain(`https://registry.npmjs.org/${dependencyName}/1.0.0`);
    expect(calls).toContain(`https://registry.npmjs.org/${dependencyName}`);
    expect(calls).toContain(`https://api.npmjs.org/downloads/point/last-week/${dependencyName}`);

    await fs.rm(maturityDir, { recursive: true }).catch(() => {});
  });

  it('should not emit VS-SC-010 for healthy package maturity signals', async () => {
    const dependencyName = uniquePackageName('healthy-maturity');
    const maturityDir = await createPackageProject({
      dependencyName,
      dependencyPackageJson: null,
      installDependency: false,
    });
    await fs.writeFile(path.join(maturityDir, 'index.js'), `import pkg from '${dependencyName}';\nexport default pkg;\n`);
    const calls: string[] = [];
    const fetchImpl = makeMaturityFetch(calls, dependencyName, {
      weeklyDownloads: 50_000,
      maintainerCount: 4,
      hasRepository: true,
      hasReadme: true,
      hasTests: true,
      created: '2020-01-01T00:00:00.000Z',
      versionCount: 20,
    });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(maturityDir);

    expect(result.findings.some(f => f.sourceRule === 'VS-SC-010')).toBe(false);
    expect(result.errors.some(error => error.code === 'NPM_MATURITY_ERROR')).toBe(false);

    await fs.rm(maturityDir, { recursive: true }).catch(() => {});
  });

  it('should not warn when healthy package maturity uses a large bounded packument', async () => {
    const dependencyName = uniquePackageName('large-maturity');
    const maturityDir = await createPackageProject({
      dependencyName,
      dependencyPackageJson: null,
      installDependency: false,
    });
    await fs.writeFile(path.join(maturityDir, 'index.js'), `import pkg from '${dependencyName}';\nexport default pkg;\n`);
    const largeReadme = `# ${dependencyName}\n${'a'.repeat(1_100_000)}`;
    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === `https://registry.npmjs.org/${dependencyName}/1.0.0`) {
        return new Response(JSON.stringify({
          name: dependencyName,
          version: '1.0.0',
          repository: { type: 'git', url: `https://github.com/example/${dependencyName}.git` },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url === `https://registry.npmjs.org/${dependencyName}`) {
        return new Response(JSON.stringify({
          name: dependencyName,
          'dist-tags': { latest: '1.0.0' },
          time: { created: '2020-01-01T00:00:00.000Z' },
          versions: {
            '1.0.0': {
              name: dependencyName,
              version: '1.0.0',
              repository: { type: 'git', url: `https://github.com/example/${dependencyName}.git` },
              scripts: { test: 'vitest run' },
            },
            '1.0.1': {
              name: dependencyName,
              version: '1.0.1',
            },
          },
          maintainers: [{ name: 'maintainer-a' }, { name: 'maintainer-b' }],
          readme: largeReadme,
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url === `https://api.npmjs.org/downloads/point/last-week/${dependencyName}`) {
        return new Response(JSON.stringify({ downloads: 50_000 }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('{}', { status: 404 });
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(maturityDir);

    expect(result.findings.some(f => f.sourceRule === 'VS-SC-010')).toBe(false);
    expect(result.errors.some(error => error.code === 'NPM_MATURITY_ERROR')).toBe(false);

    await fs.rm(maturityDir, { recursive: true }).catch(() => {});
  });

  it('should treat package maturity lookup failures as recoverable warnings', async () => {
    const dependencyName = uniquePackageName('maturity-fails');
    const maturityDir = await createPackageProject({
      dependencyName,
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === `https://registry.npmjs.org/${dependencyName}/1.0.0`) {
        return new Response(JSON.stringify({
          name: dependencyName,
          version: '1.0.0',
          repository: { type: 'git', url: `https://github.com/example/${dependencyName}.git` },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url === `https://api.npmjs.org/downloads/point/last-week/${dependencyName}`) {
        return new Response(JSON.stringify({ downloads: 10 }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response('rate limited', { status: 429 });
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(maturityDir);

    expect(result.findings.some(f => f.sourceRule === 'VS-SC-010')).toBe(false);
    expect(result.errors.some(error => error.code === 'NPM_MATURITY_ERROR' && error.recoverable)).toBe(true);

    await fs.rm(maturityDir, { recursive: true }).catch(() => {});
  });

  it('should cache package maturity data for repeated scans', async () => {
    const dependencyName = uniquePackageName('cached-maturity');
    const firstDir = await createPackageProject({
      dependencyName,
      dependencyPackageJson: null,
      installDependency: false,
    });
    const secondDir = await createPackageProject({
      dependencyName,
      dependencyPackageJson: null,
      installDependency: false,
    });
    const calls: string[] = [];
    const fetchImpl = makeMaturityFetch(calls, dependencyName, {
      weeklyDownloads: 10,
      maintainerCount: 1,
      hasRepository: false,
      hasReadme: false,
      hasTests: false,
      created: '2026-04-20T00:00:00.000Z',
      versionCount: 1,
    });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: true, fetchImpl },
      audit: { enabled: false },
    });
    await localAdapter.scan(firstDir);
    await localAdapter.scan(secondDir);

    expect(calls.filter(url => url === `https://registry.npmjs.org/${dependencyName}`).length).toBe(1);
    expect(calls.filter(url => url === `https://api.npmjs.org/downloads/point/last-week/${dependencyName}`).length).toBe(1);

    await fs.rm(firstDir, { recursive: true }).catch(() => {});
    await fs.rm(secondDir, { recursive: true }).catch(() => {});
  });

  it('should parse npm audit vulnerability stdout from non-zero exits', async () => {
    const auditDir = await createPackageProject({
      dependencyName: 'vulnerable-package',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const auditOutput = {
      vulnerabilities: {
        'vulnerable-package': {
          severity: 'high',
          title: 'Prototype pollution',
          range: '<1.0.1',
          url: 'https://github.com/advisories/GHSA-audit-0001',
          via: [{ source: 'GHSA-audit-0001' }],
        },
      },
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { enabled: false },
      audit: {
        run: async () => {
          const error = new Error('npm audit exited with vulnerabilities') as Error & { stdout: string };
          error.stdout = JSON.stringify(auditOutput);
          throw error;
        },
      },
    });
    const result = await localAdapter.scan(auditDir);

    const auditFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-006');
    expect(auditFindings).toHaveLength(1);
    expect(auditFindings[0]).toMatchObject({
      source: 'supply-chain',
      severity: 'high',
      category: 'Security',
    });
    expect(result.errors.some(error => error.code === 'NPM_AUDIT_FAILED')).toBe(false);

    await fs.rm(auditDir, { recursive: true }).catch(() => {});
  });

  it('should emit OSV findings as supply-chain findings and merge npm audit aliases without downgrading severity', async () => {
    const osvDir = await createPackageProject({
      dependencyName: 'vulnerable-package',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === OSV_QUERY_BATCH_URL) {
        return new Response(JSON.stringify({
          results: [{ vulns: [{ id: 'GHSA-test-9999' }] }],
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url === `${OSV_VULN_URL}GHSA-test-9999`) {
        return new Response(JSON.stringify({
          id: 'GHSA-test-9999',
          summary: 'Authentication bypass',
          aliases: ['CVE-2026-9999'],
          database_specific: { severity: 'CRITICAL' },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response('{}', { status: 404 });
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: true, fetchImpl },
      registry: { enabled: false },
      audit: {
        run: async () => ({
          vulnerabilities: {
            'vulnerable-package': {
              severity: 'high',
              title: 'Authentication bypass GHSA-test-9999',
              range: '<1.0.1',
              url: 'https://github.com/advisories/GHSA-test-9999',
              via: [{ source: 'GHSA-test-9999' }],
            },
          },
        }),
      },
    });
    const result = await localAdapter.scan(osvDir);

    const osvFindings = result.findings.filter(f => f.sourceRule === 'VS-OSV-GHSA-test-9999');
    expect(osvFindings).toHaveLength(0);

    const auditFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-006');
    expect(auditFindings).toHaveLength(1);
    expect(auditFindings[0]).toMatchObject({
      source: 'supply-chain',
      severity: 'critical',
      category: 'Security',
    });
    expect(auditFindings[0].evidence.rawOutput).toMatchObject({
      packageName: 'vulnerable-package',
      osvSourceRule: 'VS-OSV-GHSA-test-9999',
      osv: {
        vulnerabilityId: 'GHSA-test-9999',
        aliases: ['CVE-2026-9999'],
      },
    });

    await fs.rm(osvDir, { recursive: true }).catch(() => {});
  });

  it('should keep OSV and npm audit findings separate without an exact advisory ID match', async () => {
    const osvDir = await createPackageProject({
      dependencyName: 'vulnerable-package',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === OSV_QUERY_BATCH_URL) {
        return new Response(JSON.stringify({
          results: [{ vulns: [{ id: 'CVE-2026-1234' }] }],
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url === `${OSV_VULN_URL}CVE-2026-1234`) {
        return new Response(JSON.stringify({
          id: 'CVE-2026-1234',
          summary: 'Authentication bypass',
          database_specific: { severity: 'CRITICAL' },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response('{}', { status: 404 });
    };

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: true, fetchImpl },
      registry: { enabled: false },
      audit: {
        run: async () => ({
          vulnerabilities: {
            'vulnerable-package': {
              severity: 'high',
              title: 'Authentication bypass CVE-2026-12345',
              range: '<1.0.1',
              url: 'https://github.com/advisories/CVE-2026-12345',
              via: [{ source: 'CVE-2026-12345' }],
            },
          },
        }),
      },
    });
    const result = await localAdapter.scan(osvDir);

    expect(result.findings.filter(f => f.sourceRule === 'VS-SC-006')).toHaveLength(1);
    expect(result.findings.filter(f => f.sourceRule === 'VS-OSV-CVE-2026-1234')).toHaveLength(1);

    await fs.rm(osvDir, { recursive: true }).catch(() => {});
  });

  it('should keep other supply-chain checks when OSV fails', async () => {
    const osvDir = await createPackageProject({
      dependencyName: 'lodas',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl: FetchLike = async () => {
      throw new Error('OSV unavailable');
    };

    const localAdapter = new SupplyChainAdapter({
      typosquat: { enabled: true },
      osv: { enabled: true, fetchImpl },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(osvDir);

    expect(result.errors.some(error => error.code === 'OSV_API_ERROR' && error.recoverable)).toBe(true);
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-004')).toBe(true);

    await fs.rm(osvDir, { recursive: true }).catch(() => {});
  });

  it('should not call injected OSV fetch when OSV enrichment is disabled', async () => {
    const osvDir = await createPackageProject({
      dependencyName: 'osv-disabled',
      dependencyPackageJson: null,
      installDependency: false,
    });
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }));

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false, fetchImpl },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(osvDir);

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.errors.some(error => error.code === 'OSV_API_ERROR')).toBe(false);

    await fs.rm(osvDir, { recursive: true }).catch(() => {});
  });
});

function uniquePackageName(prefix: string): string {
  return `${prefix}-${crypto.randomBytes(4).toString('hex')}`;
}

function makeMaturityFetch(
  calls: string[],
  dependencyName: string,
  options: {
    weeklyDownloads: number;
    maintainerCount: number;
    hasRepository: boolean;
    hasReadme: boolean;
    hasTests: boolean;
    created: string;
    versionCount: number;
  },
): FetchLike {
  return async (input) => {
    const url = String(input);
    calls.push(url);

    if (url === `https://registry.npmjs.org/${dependencyName}/1.0.0`) {
      return new Response(JSON.stringify({
        name: dependencyName,
        version: '1.0.0',
        repository: options.hasRepository
          ? { type: 'git', url: `https://github.com/example/${dependencyName}.git` }
          : undefined,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }

    if (url === `https://registry.npmjs.org/${dependencyName}`) {
      const versions = Object.fromEntries(
        Array.from({ length: options.versionCount }, (_, index) => {
          const version = index === 0 ? '1.0.0' : `1.0.${index}`;
          return [version, {
            name: dependencyName,
            version,
            repository: options.hasRepository
              ? { type: 'git', url: `https://github.com/example/${dependencyName}.git` }
              : undefined,
            readme: options.hasReadme ? '# package\n' : '',
            scripts: options.hasTests ? { test: 'vitest run' } : {},
          }];
        }),
      );
      return new Response(JSON.stringify({
        name: dependencyName,
        'dist-tags': { latest: '1.0.0' },
        time: { created: options.created },
        versions,
        maintainers: Array.from({ length: options.maintainerCount }, (_, index) => ({ name: `maintainer-${index}` })),
        readme: options.hasReadme ? '# package\n' : '',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }

    if (url === `https://api.npmjs.org/downloads/point/last-week/${dependencyName}`) {
      return new Response(JSON.stringify({ downloads: options.weeklyDownloads }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    return new Response('{}', { status: 404 });
  };
}

async function createPackageProject(options: {
  dependencyName: string;
  dependencyPackageJson: Record<string, unknown> | null;
  installDependency: boolean;
}): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-sc-project-'));
  const { dependencyName, dependencyPackageJson, installDependency } = options;
  await fs.writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'test-project',
    version: '1.0.0',
    dependencies: { [dependencyName]: '1.0.0' },
  }, null, 2));
  await fs.writeFile(path.join(projectDir, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'test-project',
        version: '1.0.0',
        dependencies: { [dependencyName]: '1.0.0' },
      },
      [`node_modules/${dependencyName}`]: {
        version: '1.0.0',
        resolved: `https://registry.npmjs.org/${dependencyName}/-/${dependencyName}-1.0.0.tgz`,
        integrity: 'sha512-test',
      },
    },
  }, null, 2));

  if (installDependency && dependencyPackageJson) {
    const dependencyDir = path.join(projectDir, 'node_modules', dependencyName);
    await fs.mkdir(dependencyDir, { recursive: true });
    await fs.writeFile(
      path.join(dependencyDir, 'package.json'),
      JSON.stringify(dependencyPackageJson, null, 2),
    );
  }

  return projectDir;
}
