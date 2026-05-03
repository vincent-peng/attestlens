import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildEmbeddedJurisdictionPack, buildEmbeddedRulePack } from './embedded.js';
import {
  RULE_PACK_FETCH_TIMEOUT_MS,
  RULE_PACK_MAX_BYTES,
  AVAILABLE_JURISDICTIONS,
  getValidatedJurisdictionPackPath,
  getValidatedJurisdictionRuntimePackPath,
  getJurisdictionUnavailableMessage,
  getRulePackCachePath,
  loadJurisdictionPacks,
  loadRulePack,
  loadValidatedJurisdictionPack,
  updateRuleCache,
} from './loader.js';

describe('rule pack loader', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    vi.useRealTimers();
    await Promise.all(tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
    tempDirs.length = 0;
  });

  async function makeTempDir(): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-rules-'));
    tempDirs.push(dir);
    return dir;
  }

  function makeRulePack(version = '2026.04.25') {
    return {
      ...buildEmbeddedRulePack(),
      version,
      generated: '2026-04-25T00:00:00.000Z',
    };
  }

  async function writeValidatedJurisdictionArtifacts(
    jurisdictionDir: string,
    options: {
      version?: string;
      runtimeRules?: any[];
      validatedRules?: any[];
    } = {},
  ): Promise<void> {
    const version = options.version || '2026.05.02';
    const runtimePath = getValidatedJurisdictionRuntimePackPath('sg-pdpa', path.dirname(jurisdictionDir));
    const validatedPath = getValidatedJurisdictionPackPath('sg-pdpa', path.dirname(jurisdictionDir));
    await fs.mkdir(path.dirname(runtimePath), { recursive: true });

    const runtimeRules = options.runtimeRules || [{
      id: 'SGPDPA-SEC-001',
      category: 'guardvibe-static',
      severity: 'critical',
      title: 'Validated override',
      description: 'Validated override description',
      pattern: 'HARDCODED_RUNTIME_SECRET',
      flags: 'g',
      fixPrompt: 'Rotate the secret',
      appMappings: [],
      regulationMappings: [{
        jurisdiction: 'sg-pdpa',
        principle: 'SGPDPA_24',
        obligation: 'Protect personal data',
        status: 'fail',
        confidence: 0.9,
      }],
      enabled: true,
      addedIn: version,
      tags: ['validated'],
    }];
    const validatedRules = options.validatedRules || runtimeRules.map((rule) => ({
      ...rule,
      source: {
        jurisdiction: 'sg-pdpa',
        citation: 'PDPA Section 24',
      },
      authoring: {
        author: 'human-validated',
        confidence: 'high',
        falsePositiveRisk: 'low',
      },
      provenance: {
        sourceDocumentHash: 'hash',
        approvedBy: 'reviewer',
        approvedAt: '2026-05-02T00:00:00.000Z',
        packVersion: version,
      },
      interpretation: {
        machineCheckable: true,
        determinism: 'deterministic',
        reviewRequired: false,
        falsePositiveRisk: 'low',
      },
      tests: {
        positive: [],
        negative: [],
        edgeCase: [],
      },
    }));

    await fs.writeFile(runtimePath, JSON.stringify({
      schemaVersion: '1.0',
      version,
      generated: '2026-05-02T00:00:00.000Z',
      jurisdiction: 'sg-pdpa',
      rules: runtimeRules,
    }, null, 2));
    await fs.writeFile(validatedPath, JSON.stringify({
      schemaVersion: '2.1',
      version,
      jurisdiction: 'sg-pdpa',
      generated: '2026-05-02T00:00:00.000Z',
      principles: [{
        id: 'SGPDPA_24',
        shortName: 'Protection',
        obligation: 'Protect personal data',
        citation: 'PDPA Section 24',
      }],
      rules: validatedRules,
      provenance: {
        proposedAt: '2026-05-01T00:00:00.000Z',
        reviewedBy: 'reviewer',
        reviewedAt: '2026-05-02T00:00:00.000Z',
        sourceDocumentHash: 'hash',
      },
      ruleProvenance: Object.fromEntries(validatedRules.map((rule) => [rule.id, rule.provenance])),
    }, null, 2));
  }

  it('loads the embedded rule pack deterministically when no cache exists', async () => {
    const cacheDir = await makeTempDir();
    const first = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });
    const second = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });

    expect(first.freshness.source).toBe('embedded');
    expect(first.freshness.stale).toBe(false);
    expect(first.freshness.ruleCount).toBeGreaterThanOrEqual(40);
    expect(first.manifest).toEqual(second.manifest);
  });

  it('uses a valid cached rule pack over the embedded pack', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const sourcePath = path.join(sourceDir, 'rules.json');
    const cachedPack = makeRulePack();
    await fs.writeFile(sourcePath, JSON.stringify(cachedPack, null, 2));

    const updated = await updateRuleCache({
      source: sourcePath,
      cacheDir,
      now: new Date('2026-04-25T01:00:00.000Z'),
    });
    const loaded = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-25T01:00:00.000Z'),
    });

    expect(updated.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect(loaded.freshness.source).toBe('cache');
    expect(loaded.freshness.version).toBe('2026.04.25');
    expect(loaded.jurisdictionManifest?.coverage).toBeUndefined();
    expect(loaded.jurisdictionManifest?.validation).toBeUndefined();
  });

  it('preserves an existing cache when update-rules has no source', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const sourcePath = path.join(sourceDir, 'rules.json');
    await fs.writeFile(sourcePath, JSON.stringify(makeRulePack('2026.04.25'), null, 2));
    await updateRuleCache({ source: sourcePath, cacheDir });

    const updated = await updateRuleCache({
      cacheDir,
      now: new Date('2026-04-25T01:00:00.000Z'),
    });
    const cached = JSON.parse(await fs.readFile(getRulePackCachePath(cacheDir), 'utf-8'));

    expect(updated.freshness.version).toBe('2026.04.25');
    expect(updated.freshness.source).toBe('cache');
    expect(cached.version).toBe('2026.04.25');
  });

  it('seeds embedded rules only when the cache is missing', async () => {
    const cacheDir = await makeTempDir();

    const updated = await updateRuleCache({
      cacheDir,
      now: new Date('2026-04-24T01:00:00.000Z'),
    });
    const cached = JSON.parse(await fs.readFile(getRulePackCachePath(cacheDir), 'utf-8'));

    expect(updated.freshness.version).toBe(buildEmbeddedRulePack().version);
    expect(updated.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect(cached.version).toBe(buildEmbeddedRulePack().version);
  });

  it('falls back to embedded rules when the cache is corrupt', async () => {
    const cacheDir = await makeTempDir();
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.writeFile(getRulePackCachePath(cacheDir), '{not-json');

    const loaded = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });

    expect(loaded.freshness.source).toBe('embedded');
    expect(loaded.warnings[0]).toContain('Cached rule pack ignored');
  });

  it('does not include local cache paths in public freshness metadata', async () => {
    const cacheDir = await makeTempDir();

    const loaded = await updateRuleCache({ cacheDir });

    expect(loaded.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect('cachePath' in loaded.freshness).toBe(false);
  });

  it('rejects oversized local rule pack sources before parsing', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const sourcePath = path.join(sourceDir, 'rules.json');
    await fs.writeFile(sourcePath, 'x'.repeat(RULE_PACK_MAX_BYTES + 1));

    await expect(updateRuleCache({ source: sourcePath, cacheDir })).rejects.toThrow(/too large/);
    await expect(fs.stat(getRulePackCachePath(cacheDir))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects oversized remote rule pack sources before parsing', async () => {
    const cacheDir = await makeTempDir();
    const fetchImpl = vi.fn(async () => new Response('{}', {
      headers: {
        'content-length': String(RULE_PACK_MAX_BYTES + 1),
      },
    }));

    await expect(updateRuleCache({
      source: 'https://example.com/rules.json',
      cacheDir,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })).rejects.toThrow(/too large/);
    await expect(fs.stat(getRulePackCachePath(cacheDir))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('times out remote rule pack fetches', async () => {
    vi.useFakeTimers();
    const cacheDir = await makeTempDir();
    const fetchImpl = vi.fn((_source: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        reject(new DOMException('Aborted', 'AbortError'));
      });
    }));

    const updatePromise = updateRuleCache({
      source: 'https://example.com/rules.json',
      cacheDir,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const rejection = expect(updatePromise).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(RULE_PACK_FETCH_TIMEOUT_MS);

    await rejection;
  });

  it('rejects malformed, duplicate, and non-HTTPS rule pack sources before caching', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const malformedPath = path.join(sourceDir, 'malformed.json');
    const duplicatePath = path.join(sourceDir, 'duplicate.json');
    const duplicatePack = makeRulePack();
    duplicatePack.rules = [duplicatePack.rules[0]!, duplicatePack.rules[0]!];
    await fs.writeFile(malformedPath, '{not-json');
    await fs.writeFile(duplicatePath, JSON.stringify(duplicatePack, null, 2));

    await expect(updateRuleCache({ source: 'http://example.com/rules.json', cacheDir })).rejects.toThrow(/HTTPS/);
    await expect(updateRuleCache({ source: malformedPath, cacheDir })).rejects.toThrow(/Invalid rule pack manifest/);
    await expect(updateRuleCache({ source: duplicatePath, cacheDir })).rejects.toThrow(/Duplicate rule id/);
    await expect(fs.stat(getRulePackCachePath(cacheDir))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('covers active hardcoded scanner rule ids in the embedded manifest', () => {
    const activeHardcodedRuleIds = [
      'AL-URL-013',
      'AL-URL-014',
      'AL-URL-015',
      'VS-SUPA-RLS-MISSING',
      'VS-FB-SERVICE-ACCOUNT',
      'VS-PUBLIC-SECRET-ENV',
      'VS-PLATFORM-SECRET',
    ];
    const embeddedRuleIds = new Set(buildEmbeddedRulePack().rules.map((rule) => rule.id));

    for (const ruleId of activeHardcodedRuleIds) {
      expect(embeddedRuleIds.has(ruleId), `${ruleId} is missing from embedded rules`).toBe(true);
    }
  });

  it('builds an AU jurisdiction pack from embedded APP metadata', () => {
    const jurisdictionPack = buildEmbeddedJurisdictionPack();

    expect(jurisdictionPack.schemaVersion).toBe('2.0');
    expect(jurisdictionPack.jurisdiction).toBe('au-privacy-act');
    expect(jurisdictionPack.principles.some((principle) => principle.id === 'APP_11')).toBe(true);
    expect(jurisdictionPack.rules.length).toBe(buildEmbeddedRulePack().rules.length);
    expect(jurisdictionPack.rules[0]!.regulationMappings?.[0]?.jurisdiction).toBe('au-privacy-act');
  });

  it('builds a CCPA jurisdiction pack from embedded CCPA metadata', () => {
    const jurisdictionPack = buildEmbeddedJurisdictionPack('us-ccpa');

    expect(jurisdictionPack.schemaVersion).toBe('2.0');
    expect(jurisdictionPack.version).toBe('2026.04.30');
    expect(jurisdictionPack.jurisdiction).toBe('us-ccpa');
    expect(jurisdictionPack.principles).toHaveLength(12);
    expect(jurisdictionPack.principles.some((principle) => principle.id === 'CCPA_150')).toBe(true);
    expect(jurisdictionPack.rules.some((rule) => rule.id === 'CCPA-SEC-001')).toBe(true);
    expect(jurisdictionPack.rules[0]!.regulationMappings?.[0]?.jurisdiction).toBe('us-ccpa');
  });

  it('builds a GDPR jurisdiction pack from embedded GDPR metadata', () => {
    const jurisdictionPack = buildEmbeddedJurisdictionPack('eu-gdpr');

    expect(jurisdictionPack.schemaVersion).toBe('2.0');
    expect(jurisdictionPack.version).toBe('2026.04.30');
    expect(jurisdictionPack.jurisdiction).toBe('eu-gdpr');
    expect(jurisdictionPack.principles).toHaveLength(14);
    expect(jurisdictionPack.principles.some((principle) => principle.id === 'GDPR_Art32')).toBe(true);
    expect(jurisdictionPack.rules.some((rule) => rule.id === 'GDPR-SEC-001')).toBe(true);
    expect(jurisdictionPack.rules[0]!.regulationMappings?.[0]?.jurisdiction).toBe('eu-gdpr');
  });

  it('builds an SG PDPA jurisdiction pack from embedded SG PDPA metadata', () => {
    const jurisdictionPack = buildEmbeddedJurisdictionPack('sg-pdpa');

    expect(jurisdictionPack.schemaVersion).toBe('2.0');
    expect(jurisdictionPack.version).toBe('2026.05.01');
    expect(jurisdictionPack.jurisdiction).toBe('sg-pdpa');
    expect(jurisdictionPack.principles).toHaveLength(3);
    expect(jurisdictionPack.principles.some((principle) => principle.id === 'SGPDPA_24')).toBe(true);
    expect(jurisdictionPack.rules.some((rule) => rule.id === 'SGPDPA-SEC-001')).toBe(true);
    expect(jurisdictionPack.rules[0]!.regulationMappings?.[0]?.jurisdiction).toBe('sg-pdpa');
  });

  it('includes coverage and validation metadata for every embedded jurisdiction pack', () => {
    const expectedStatuses = {
      'au-privacy-act': 'internal_validated',
      'us-ccpa': 'internal_validated',
      'eu-gdpr': 'internal_validated',
      'sg-pdpa': 'draft',
    } as const;

    for (const jurisdiction of AVAILABLE_JURISDICTIONS) {
      const jurisdictionPack = buildEmbeddedJurisdictionPack(jurisdiction);

      expect(jurisdictionPack.coverage?.summary.length).toBeGreaterThan(0);
      expect(jurisdictionPack.coverage?.includedPrinciples.length).toBeGreaterThan(0);
      expect(jurisdictionPack.coverage?.knownGaps.length).toBeGreaterThan(0);
      expect(jurisdictionPack.coverage?.evidenceTypes.length).toBeGreaterThan(0);
      expect(jurisdictionPack.validation?.status).toBe(expectedStatuses[jurisdiction]);
      expect(jurisdictionPack.validation?.notes.length).toBeGreaterThan(0);
    }

    expect(buildEmbeddedJurisdictionPack('us-ccpa').coverage?.summary).toContain('subset');
    expect(buildEmbeddedJurisdictionPack('eu-gdpr').coverage?.summary).toContain('subset');
    expect(buildEmbeddedJurisdictionPack('sg-pdpa').coverage?.summary).toContain('beta');
  });

  it('loads AU jurisdiction packs', async () => {
    const cacheDir = await makeTempDir();
    const packs = await loadJurisdictionPacks(['au-privacy-act'], {
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });
    const auPack = packs.get('au-privacy-act');

    expect(auPack).toBeDefined();
    expect(auPack!.manifest.jurisdiction).toBe('au-privacy-act');
    expect(auPack!.jurisdictionManifest?.schemaVersion).toBe('2.0');
    expect(auPack!.jurisdictionManifest?.validation?.status).toBe('internal_validated');
    expect(auPack!.warnings).toEqual([]);
  });

  it('loads the embedded CCPA jurisdiction pack', async () => {
    const packs = await loadJurisdictionPacks(['us-ccpa'], {
      now: new Date('2026-04-24T00:00:00.000Z'),
    });
    const ccpaPack = packs.get('us-ccpa');

    expect(ccpaPack).toBeDefined();
    expect(ccpaPack!.manifest.jurisdiction).toBe('us-ccpa');
    expect(ccpaPack!.manifest.rules.some((rule) => rule.id === 'CCPA-DNS-001')).toBe(true);
    expect(ccpaPack!.jurisdictionManifest?.principles.some((principle) => principle.id === 'CCPA_100')).toBe(true);
    expect(ccpaPack!.warnings).toEqual([]);
  });

  it('loads the embedded GDPR jurisdiction pack', async () => {
    const packs = await loadJurisdictionPacks(['eu-gdpr'], {
      now: new Date('2026-04-24T00:00:00.000Z'),
    });
    const gdprPack = packs.get('eu-gdpr');

    expect(gdprPack).toBeDefined();
    expect(gdprPack!.manifest.jurisdiction).toBe('eu-gdpr');
    expect(gdprPack!.manifest.rules.some((rule) => rule.id === 'GDPR-CONSENT-001')).toBe(true);
    expect(gdprPack!.jurisdictionManifest?.principles.some((principle) => principle.id === 'GDPR_Art3')).toBe(true);
    expect(gdprPack!.warnings).toEqual([]);
  });

  it('loads the embedded SG PDPA jurisdiction pack', async () => {
    const packs = await loadJurisdictionPacks(['sg-pdpa'], {
      now: new Date('2026-04-24T00:00:00.000Z'),
    });
    const sgPdpaPack = packs.get('sg-pdpa');

    expect(sgPdpaPack).toBeDefined();
    expect(sgPdpaPack!.manifest.jurisdiction).toBe('sg-pdpa');
    expect(sgPdpaPack!.manifest.rules.some((rule) => rule.id === 'SGPDPA-CONSENT-001')).toBe(true);
    expect(sgPdpaPack!.jurisdictionManifest?.principles.some((principle) => principle.id === 'SGPDPA_11')).toBe(true);
    expect(sgPdpaPack!.warnings).toEqual([]);
  });

  it('loads a validated runtime pack alongside validated manifest metadata', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'));

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.manifest.version).toBe('2026.05.02');
      expect(loaded.manifest.rules.some((rule) => rule.id === 'SGPDPA-SEC-001')).toBe(true);
      expect(loaded.validatedManifest?.schemaVersion).toBe('2.1');
      expect(loaded.authoredRulesById?.get('SGPDPA-SEC-001')?.authoring.author).toBe('human-validated');
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('falls back to embedded when the runtime pack exists but the validated manifest is missing', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'));
    await fs.rm(getValidatedJurisdictionPackPath('sg-pdpa', jurisdictionBaseDir), { force: true });

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.validatedManifest).toBeUndefined();
      expect(loaded.manifest.version).toBe('2026.05.01');
      expect(loaded.manifest.rules.find((rule) => rule.id === 'SGPDPA-SEC-001')?.title).not.toBe('Validated override');
      expect(loaded.warnings.some((warning) => warning.includes('matching validated manifest unavailable'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('falls back to embedded when the runtime pack exists but the validated manifest is corrupt', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'));
    await fs.writeFile(getValidatedJurisdictionPackPath('sg-pdpa', jurisdictionBaseDir), '{not-json', 'utf-8');

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings.some((warning) => warning.includes('Validated pack manifest ignored'))).toBe(true);
      expect(loaded.warnings.some((warning) => warning.includes('matching validated manifest unavailable'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('falls back to embedded when the validated manifest jurisdiction does not match the runtime pack', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'));

    const validatedPath = getValidatedJurisdictionPackPath('sg-pdpa', jurisdictionBaseDir);
    const validatedManifest = JSON.parse(await fs.readFile(validatedPath, 'utf-8'));
    validatedManifest.jurisdiction = 'eu-gdpr';
    await fs.writeFile(validatedPath, JSON.stringify(validatedManifest, null, 2));

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings.some((warning) => warning.includes('jurisdiction mismatch'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('falls back to embedded when the validated manifest version does not match the runtime pack', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'));

    const validatedPath = getValidatedJurisdictionPackPath('sg-pdpa', jurisdictionBaseDir);
    const validatedManifest = JSON.parse(await fs.readFile(validatedPath, 'utf-8'));
    validatedManifest.version = '2026.05.03';
    await fs.writeFile(validatedPath, JSON.stringify(validatedManifest, null, 2));

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings.some((warning) => warning.includes('version mismatch'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('falls back to embedded when the runtime pack contains rule ids not present in the validated manifest', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'), {
      runtimeRules: [{
        id: 'SGPDPA-RUNTIME-ONLY-001',
        category: 'guardvibe-static',
        severity: 'high',
        title: 'Runtime-only rule',
        description: 'not reviewed',
        pattern: 'RUNTIME_ONLY',
        appMappings: [],
        regulationMappings: [],
        enabled: true,
        addedIn: '2026.05.02',
      }],
      validatedRules: [{
        id: 'SGPDPA-SEC-001',
        category: 'guardvibe-static',
        severity: 'critical',
        title: 'Validated override',
        description: 'Validated override description',
        pattern: 'HARDCODED_RUNTIME_SECRET',
        flags: 'g',
        fixPrompt: 'Rotate the secret',
        appMappings: [],
        regulationMappings: [{
          jurisdiction: 'sg-pdpa',
          principle: 'SGPDPA_24',
          obligation: 'Protect personal data',
          status: 'fail',
          confidence: 0.9,
        }],
        enabled: true,
        addedIn: '2026.05.02',
        tags: ['validated'],
        source: {
          jurisdiction: 'sg-pdpa',
          citation: 'PDPA Section 24',
        },
        authoring: {
          author: 'human-validated',
          confidence: 'high',
          falsePositiveRisk: 'low',
        },
        provenance: {
          sourceDocumentHash: 'hash',
          approvedBy: 'reviewer',
          approvedAt: '2026-05-02T00:00:00.000Z',
          packVersion: '2026.05.02',
        },
        interpretation: {
          machineCheckable: true,
          determinism: 'deterministic',
          reviewRequired: false,
          falsePositiveRisk: 'low',
        },
        tests: {
          positive: [],
          negative: [],
          edgeCase: [],
        },
      }],
    });

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings.some((warning) => warning.includes('not present in the validated manifest'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('skips ai-draft rules from validated runtime metadata', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'), {
      runtimeRules: [{
        id: 'SGPDPA-AI-DRAFT-001',
        category: 'guardvibe-static',
        severity: 'high',
        title: 'AI draft runtime rule',
        description: 'should be skipped',
        pattern: 'SHOULD_NOT_LOAD',
        appMappings: [],
        regulationMappings: [],
        enabled: true,
        addedIn: '2026.05.02',
      }],
      validatedRules: [{
        id: 'SGPDPA-AI-DRAFT-001',
        category: 'guardvibe-static',
        severity: 'high',
        title: 'AI draft runtime rule',
        description: 'should be skipped',
        pattern: 'SHOULD_NOT_LOAD',
        appMappings: [],
        regulationMappings: [],
        enabled: true,
        addedIn: '2026.05.02',
        source: {
          jurisdiction: 'sg-pdpa',
          citation: 'PDPA Section 24',
        },
        authoring: {
          author: 'ai-draft',
          confidence: 'high',
          falsePositiveRisk: 'low',
        },
        provenance: {
          sourceDocumentHash: 'hash',
        },
        interpretation: {
          machineCheckable: true,
          determinism: 'deterministic',
          reviewRequired: true,
          falsePositiveRisk: 'low',
        },
        tests: {
          positive: [],
          negative: [],
          edgeCase: [],
        },
      }],
    });

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.manifest.rules.some((rule) => rule.id === 'SGPDPA-AI-DRAFT-001')).toBe(false);
      expect(loaded.warnings.some((warning) => warning.includes('Skipping AI-draft rule SGPDPA-AI-DRAFT-001'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('warns and falls back to embedded when the validated runtime pack is older than embedded', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'), {
      version: '2026.04.30',
    });

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.manifest.version).toBe('2026.05.01');
      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings.some((warning) => warning.includes('older than embedded'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('falls back to embedded when the validated artifact version is malformed', async () => {
    const jurisdictionBaseDir = await makeTempDir();
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;
    await writeValidatedJurisdictionArtifacts(path.join(jurisdictionBaseDir, 'sg-pdpa'), {
      version: '2026.05.01-beta',
    });

    try {
      const loaded = await loadValidatedJurisdictionPack('sg-pdpa', {
        now: new Date('2026-05-02T01:00:00.000Z'),
      });

      expect(loaded.freshness.source).toBe('embedded');
      expect(loaded.warnings.some((warning) => warning.includes('invalid version format'))).toBe(true);
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
    }
  });

  it('loads mixed AU, CCPA, GDPR, and SG PDPA packs', async () => {
    const cacheDir = await makeTempDir();
    const packs = await loadJurisdictionPacks(['au-privacy-act', 'us-ccpa', 'eu-gdpr', 'sg-pdpa'], {
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });

    expect(packs.get('au-privacy-act')!.manifest.rules.length).toBeGreaterThan(0);
    expect(packs.get('us-ccpa')!.manifest.rules.length).toBeGreaterThan(0);
    expect(packs.get('eu-gdpr')!.manifest.rules.length).toBeGreaterThan(0);
    expect(packs.get('sg-pdpa')!.manifest.rules.length).toBeGreaterThan(0);
    expect(packs.get('us-ccpa')!.warnings).toEqual([]);
    expect(packs.get('eu-gdpr')!.warnings).toEqual([]);
    expect(packs.get('sg-pdpa')!.warnings).toEqual([]);
  });

  it('loads mixed AU and GDPR packs without unavailable warnings', async () => {
    const cacheDir = await makeTempDir();
    const packs = await loadJurisdictionPacks(['au-privacy-act', 'eu-gdpr'], {
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });

    expect(packs.get('au-privacy-act')!.manifest.rules.length).toBeGreaterThan(0);
    expect(packs.get('eu-gdpr')!.manifest.rules.length).toBeGreaterThan(0);
    expect(packs.get('eu-gdpr')!.warnings).toEqual([]);
  });

  it('treats all declared jurisdictions as available', () => {
    expect(AVAILABLE_JURISDICTIONS).toEqual(['au-privacy-act', 'us-ccpa', 'eu-gdpr', 'sg-pdpa']);
    expect(getJurisdictionUnavailableMessage('eu-gdpr')).toBe(
      "No embedded rule pack loaded for requested jurisdiction 'eu-gdpr'. Available jurisdictions: au-privacy-act, us-ccpa, eu-gdpr, sg-pdpa",
    );
  });
});
