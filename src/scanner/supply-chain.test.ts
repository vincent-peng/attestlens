import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SupplyChainAdapter } from './supply-chain.js';
import { OSV_QUERY_BATCH_URL, OSV_VULN_URL, type FetchLike } from './osv.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

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

  it('should detect typosquatting', async () => {
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
    expect(typoFindings.length).toBeGreaterThan(0);
    expect(typoFindings[0].title).toContain('typosquat');
    expect(typoFindings[0].title).toContain('lodas');
    expect(typoFindings[0].title).toContain('lodash');

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

    const result = await adapter.scan(allowDir);
    const oraFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-004' && f.title.includes('ora'));
    expect(oraFindings.length).toBe(0);

    await fs.rm(allowDir, { recursive: true }).catch(() => {});
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

    const result = await adapter.scan(popularDir);
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
    const fetchImpl: FetchLike = async () => new Response(JSON.stringify({
      name: 'remote-no-repo',
      version: '1.0.0',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });

    const localAdapter = new SupplyChainAdapter({
      osv: { enabled: false },
      registry: { fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    const provenanceFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-009');
    expect(provenanceFindings).toHaveLength(1);
    expect(provenanceFindings[0].evidence.rawOutput).toMatchObject({
      packageName: 'remote-no-repo',
      metadataSource: 'registry',
    });

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
      registry: { fetchImpl },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(provenanceDir);

    expect(result.findings.some(f => f.sourceRule === 'VS-SC-009')).toBe(false);
    expect(result.errors.some(error => error.code === 'NPM_METADATA_ERROR' && error.recoverable)).toBe(true);

    await fs.rm(provenanceDir, { recursive: true }).catch(() => {});
  });

  it('should emit OSV findings as supply-chain findings and deduplicate npm audit aliases', async () => {
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
      osv: { fetchImpl },
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
      severity: 'high',
      category: 'Security',
    });

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
      osv: { fetchImpl },
      registry: { enabled: false },
      audit: { enabled: false },
    });
    const result = await localAdapter.scan(osvDir);

    expect(result.errors.some(error => error.code === 'OSV_API_ERROR' && error.recoverable)).toBe(true);
    expect(result.findings.some(f => f.sourceRule === 'VS-SC-004')).toBe(true);

    await fs.rm(osvDir, { recursive: true }).catch(() => {});
  });
});

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
