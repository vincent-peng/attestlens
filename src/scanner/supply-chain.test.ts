import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SupplyChainAdapter } from './supply-chain.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

describe('SupplyChainAdapter', () => {
  const adapter = new SupplyChainAdapter();
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
    expect(result.version).toBe('0.1.0');
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
});