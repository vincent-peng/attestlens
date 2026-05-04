import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScannerOrchestrator, resolveEffectiveSeverity } from './orchestrator.js';
import { GuardVibeAdapter } from './guardvibe.js';
import type { ScannerAdapter, ScannerContext, ScannerProgressEvent, ScannerResult } from './types.js';
import { getValidatedJurisdictionPackPath, getValidatedJurisdictionRuntimePackPath } from './rules/loader.js';
import type { AttestLensFinding, AuthoredRule, ScanSource } from '../schema/index.js';

describe('ScannerOrchestrator', { timeout: 20000 }, () => {
  let scanResult: Awaited<ReturnType<ScannerOrchestrator['scan']>>;
  let fixtureDir: string;

  beforeAll(async () => {
    fixtureDir = await createVulnerableAppFixture();
    const orchestrator = new ScannerOrchestrator();
    orchestrator.register(new GuardVibeAdapter('__attestlens_missing_guardvibe__'));
    orchestrator.disable('mcp-scan');
    scanResult = await orchestrator.scan(fixtureDir);
  }, 30000);

  afterAll(async () => {
    if (fixtureDir) {
      await fs.rm(fixtureDir, { recursive: true, force: true });
    }
  });

  it('should register guardvibe and mcp-scan adapters by default', () => {
    const orchestrator = new ScannerOrchestrator();
    const registry = orchestrator.getRegistry();
    expect(registry.length).toBe(9);
    expect(registry.some(r => r.adapter.name === 'guardvibe')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'mcp-scan')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'supply-chain')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'behavioral')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'iac')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'data-flow-lite')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'url-scan')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'reform-2026')).toBe(true);
    expect(registry.find(r => r.adapter.name === 'gitleaks')?.enabled).toBe(false);
  });

  it('should allow disabling adapters', () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.disable('mcp-scan');
    const registry = orchestrator.getRegistry();
    const mcpScan = registry.find(r => r.adapter.name === 'mcp-scan');
    expect(mcpScan!.enabled).toBe(false);
  });

  it('should allow re-enabling adapters', () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.disable('mcp-scan');
    orchestrator.enable('mcp-scan');
    const registry = orchestrator.getRegistry();
    const mcpScan = registry.find(r => r.adapter.name === 'mcp-scan');
    expect(mcpScan!.enabled).toBe(true);
  });

  it('loads GDPR jurisdiction packs before scanning', async () => {
    const orchestrator = new ScannerOrchestrator({ jurisdictions: ['eu-gdpr'] });
    const result = await orchestrator.scan(fixtureDir, []);

    expect(result.ruleFreshness.version).toBe('2026.04.30');
    expect(result.errors.some((error) => error.message.includes('not yet available'))).toBe(false);
  });

  it('loads CCPA jurisdiction packs before scanning', async () => {
    const orchestrator = new ScannerOrchestrator({ jurisdictions: ['us-ccpa'] });
    const result = await orchestrator.scan(fixtureDir, []);

    expect(result.ruleFreshness.version).toBe('2026.04.30');
    expect(result.errors.some((error) => error.message.includes('not yet available'))).toBe(false);
  });

  it('loads SG PDPA jurisdiction packs before scanning', async () => {
    const orchestrator = new ScannerOrchestrator({ jurisdictions: ['sg-pdpa'] });
    const result = await orchestrator.scan(fixtureDir, []);

    expect(result.ruleFreshness.version).toBe('2026.05.01');
    expect(result.errors.some((error) => error.message.includes('not yet available'))).toBe(false);
  });

  it('produces SG PDPA findings with regulation mappings end-to-end', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-sg-pdpa-'));
    const orchestrator = new ScannerOrchestrator({ jurisdictions: ['sg-pdpa'] });

    try {
      await fs.writeFile(
        path.join(projectDir, 'privacy.html'),
        '<html><body><h1>Privacy Notice</h1><p>We collect personal data.</p></body></html>',
      );
      await fs.writeFile(
        path.join(projectDir, 'customer.json'),
        '{"nric":"S1234567D"}',
      );

      const result = await orchestrator.scan(projectDir, ['guardvibe']);

      expect(result.findings.some((finding) => finding.regulationMappings.some((mapping) => (
        mapping.jurisdiction === 'sg-pdpa' && mapping.principle === 'SGPDPA_24'
      )))).toBe(true);
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('should return findings from scan', async () => {
    // Should have findings from static scan
    expect(scanResult.findings.length).toBeGreaterThan(0);
    expect(scanResult.totalDurationMs).toBeGreaterThan(0);
  });

  it('does not run URL scanning for path targets by default', async () => {
    expect(scanResult.results.some(result => result.source === 'url-scan')).toBe(false);
    expect(scanResult.errors.some(error => error.source === 'url-scan')).toBe(false);
  });

  it('should deduplicate findings by rule+file+line', async () => {
    // Check no duplicate rule+file+line combinations
    const keys = scanResult.findings.map(f => `${f.sourceRule}:${f.file}:${f.line}`);
    const uniqueKeys = new Set(keys);
    expect(keys.length).toBe(uniqueKeys.size);
  });

  it('preserves package-scoped supply-chain findings that share package.json location', async () => {
    const projectDir = await createNoProvenanceDependencyFixture();
    const orchestrator = new ScannerOrchestrator({
      supplyChain: {
        audit: { enabled: false },
        osv: { enabled: false },
        registry: { enabled: false },
      },
    });

    try {
      const result = await orchestrator.scan(projectDir, ['supply-chain']);
      const provenanceFindings = result.findings.filter(f => f.sourceRule === 'VS-SC-009');
      const packageNames = provenanceFindings.map((finding) => {
        const raw = finding.evidence.rawOutput as { packageName?: string };
        return raw.packageName;
      });

      expect(provenanceFindings).toHaveLength(2);
      expect(packageNames.sort()).toEqual(['no-repo-one', 'no-repo-two']);
      expect(new Set(provenanceFindings.map(f => f.id)).size).toBe(2);
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('deduplicates cross-scanner findings with a canonical vulnerability key', async () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.register(makeFindingAdapter('manual', [
      makeFinding({
        id: 'manual-xss',
        source: 'manual',
        sourceRule: 'VS-XSS',
        severity: 'high',
        file: 'src/App.tsx',
        line: 10,
        code: '<div dangerouslySetInnerHTML={{ __html: html }} />',
        title: 'XSS vector',
      }),
    ]));
    orchestrator.register(makeFindingAdapter('questionnaire', [
      makeFinding({
        id: 'questionnaire-xss',
        source: 'questionnaire',
        sourceRule: 'AL-JS-001',
        severity: 'medium',
        file: 'src/App.tsx',
        line: 10,
        code: '<div dangerouslySetInnerHTML={{ __html: html }} />',
        title: 'dangerouslySetInnerHTML Usage Detected',
      }),
    ]));

    const result = await orchestrator.scan(fixtureDir, ['manual', 'questionnaire']);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      id: 'manual-xss',
      source: 'manual',
      sourceRule: 'VS-XSS',
      severity: 'high',
      corroboratedBy: ['questionnaire'],
    });
    expect((result.findings[0]!.evidence.rawOutput as any).corroboratingFindings).toEqual([
      expect.objectContaining({ source: 'questionnaire', sourceRule: 'AL-JS-001' }),
    ]);
  });

  it('keeps the highest severity finding when cross-scanner duplicates merge', async () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.register(makeFindingAdapter('manual', [
      makeFinding({
        id: 'manual-xss',
        source: 'manual',
        sourceRule: 'VS-XSS',
        severity: 'medium',
        file: 'src/App.tsx',
        line: 10,
        title: 'XSS vector',
      }),
    ]));
    orchestrator.register(makeFindingAdapter('questionnaire', [
      makeFinding({
        id: 'questionnaire-xss',
        source: 'questionnaire',
        sourceRule: 'AL-JS-001',
        severity: 'critical',
        file: 'src/App.tsx',
        line: 10,
        title: 'dangerouslySetInnerHTML Usage Detected',
      }),
    ]));

    const result = await orchestrator.scan(fixtureDir, ['manual', 'questionnaire']);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      id: 'questionnaire-xss',
      source: 'questionnaire',
      severity: 'critical',
      corroboratedBy: ['manual'],
    });
  });

  it('does not merge different vulnerability classes at the same location', async () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.register(makeFindingAdapter('manual', [
      makeFinding({
        id: 'manual-xss',
        source: 'manual',
        sourceRule: 'VS-XSS',
        file: 'src/App.tsx',
        line: 10,
        title: 'XSS vector',
      }),
    ]));
    orchestrator.register(makeFindingAdapter('questionnaire', [
      makeFinding({
        id: 'questionnaire-sqli',
        source: 'questionnaire',
        sourceRule: 'VS-SAST-004',
        file: 'src/App.tsx',
        line: 10,
        title: 'SQL query built from request input',
      }),
    ]));

    const result = await orchestrator.scan(fixtureDir, ['manual', 'questionnaire']);

    expect(result.findings.map(finding => finding.id).sort()).toEqual(['manual-xss', 'questionnaire-sqli']);
  });

  it('returns completed adapter results when another adapter times out', async () => {
    const progressEvents: ScannerProgressEvent[] = [];
    const orchestrator = new ScannerOrchestrator({
      adapterTimeoutMs: {
        manual: 100,
        questionnaire: 10,
      },
      onProgress: (event) => progressEvents.push(event),
    });
    orchestrator.register(makeFakeAdapter('manual', 0));
    orchestrator.register(makeFakeAdapter('questionnaire', 100));

    const result = await orchestrator.scan(fixtureDir, ['manual', 'questionnaire']);

    expect(result.results.map(scan => scan.source)).toEqual(['manual']);
    expect(result.errors).toContainEqual(expect.objectContaining({
      source: 'questionnaire',
      code: 'SCANNER_TIMEOUT',
      recoverable: true,
    }));
    expect(result.findings).toHaveLength(1);
    expect(progressEvents.map(event => `${event.source}:${event.phase}`)).toEqual([
      'manual:start',
      'questionnaire:start',
      'manual:complete',
      'questionnaire:timeout',
    ]);
  });

  it('keeps original severity for high-confidence deterministic authored rules', () => {
    expect(resolveEffectiveSeverity(makeAuthoredRule())).toBe('critical');
  });

  it('caps medium-confidence or heuristic authored rules at medium', () => {
    expect(resolveEffectiveSeverity(makeAuthoredRule({
      severity: 'critical',
      authoring: {
        author: 'human-validated',
        confidence: 'medium',
        falsePositiveRisk: 'medium',
      },
      interpretation: {
        machineCheckable: true,
        determinism: 'heuristic',
        reviewRequired: false,
        falsePositiveRisk: 'medium',
      },
    }))).toBe('medium');
  });

  it('caps low-confidence or manual-only authored rules at info', () => {
    expect(resolveEffectiveSeverity(makeAuthoredRule({
      severity: 'high',
      authoring: {
        author: 'human-validated',
        confidence: 'low',
        falsePositiveRisk: 'high',
      },
      interpretation: {
        machineCheckable: false,
        determinism: 'manual-only',
        reviewRequired: false,
        falsePositiveRisk: 'high',
      },
    }))).toBe('info');
  });

  it('throws if an ai-draft rule reaches severity resolution', () => {
    expect(() => resolveEffectiveSeverity(makeAuthoredRule({
      authoring: {
        author: 'ai-draft',
        confidence: 'high',
        falsePositiveRisk: 'low',
      },
      interpretation: {
        machineCheckable: true,
        determinism: 'deterministic',
        reviewRequired: true,
        falsePositiveRisk: 'low',
      },
      provenance: {
        sourceDocumentHash: 'hash',
      },
    }))).toThrow(/AI-draft rule/);
  });

  it('uses validated jurisdiction metadata to cap overridden embedded rule severity during scans', async () => {
    const jurisdictionBaseDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-jurisdiction-pack-'));
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-jurisdiction-project-'));
    process.env.ATTESTLENS_JURISDICTION_PACK_DIR = jurisdictionBaseDir;

    try {
      await writeValidatedGuardVibeOverride(jurisdictionBaseDir, {
        confidence: 'medium',
        determinism: 'heuristic',
      });
      await fs.writeFile(
        path.join(projectDir, '.env'),
        'api_key=\"1234567890abcdef1234567890abcdef\"',
      );
      const orchestrator = new ScannerOrchestrator({ jurisdictions: ['sg-pdpa'] });
      orchestrator.disable('mcp-scan');
      orchestrator.disable('supply-chain');
      orchestrator.disable('behavioral');
      orchestrator.disable('iac');
      orchestrator.disable('url-scan');
      orchestrator.disable('reform-2026');

      const result = await orchestrator.scan(projectDir, ['guardvibe']);
      const finding = result.findings.find((candidate) => candidate.sourceRule === 'VS-HARDKEY');

      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
      expect(finding?.title).toBe('Hardcoded secret key');
    } finally {
      delete process.env.ATTESTLENS_JURISDICTION_PACK_DIR;
      await fs.rm(jurisdictionBaseDir, { recursive: true, force: true });
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });

  it('annotates findings introduced in changed files', async () => {
    const orchestrator = new ScannerOrchestrator();
    const findings = [
      makeFinding({ id: 'changed-finding', file: 'src/changed.ts' }),
      makeFinding({ id: 'unchanged-finding', file: 'src/unchanged.ts' }),
    ];
    orchestrator.register(makeFindingAdapter('manual', findings));

    const result = await orchestrator.scan(fixtureDir, ['manual'], {
      diffContext: {
        baseRef: 'origin/main',
        headRef: 'HEAD',
        changedFiles: ['src/changed.ts'],
        introducedFindings: [],
        addedDependencies: [],
        addedRoutes: [],
      },
    });

    expect(result.findings.find((finding) => finding.id === 'changed-finding')?.introducedInDiff).toBe(true);
    expect(result.findings.find((finding) => finding.id === 'unchanged-finding')?.introducedInDiff).toBe(false);
    expect(result.diffContext?.introducedFindings).toEqual(['changed-finding']);
  });

  it('filters to changed-file findings when changedFilesOnly is set', async () => {
    const orchestrator = new ScannerOrchestrator();
    const findings = [
      makeFinding({ id: 'changed-finding', file: 'src/changed.ts' }),
      makeFinding({ id: 'unchanged-finding', file: 'src/unchanged.ts' }),
    ];
    orchestrator.register(makeFindingAdapter('manual', findings));

    const result = await orchestrator.scan(fixtureDir, ['manual'], {
      changedFilesOnly: true,
      diffContext: {
        changedFiles: ['src/changed.ts'],
        introducedFindings: [],
        addedDependencies: [],
        addedRoutes: [],
      },
    });

    expect(result.findings.map((finding) => finding.id)).toEqual(['changed-finding']);
    expect(result.diffContext?.introducedFindings).toEqual(['changed-finding']);
  });

  it('keeps added dependency findings when changedFilesOnly is set', async () => {
    const orchestrator = new ScannerOrchestrator();
    const findings = [
      makeFinding({
        id: 'added-dependency-finding',
        source: 'supply-chain',
        file: '.',
        evidence: {
          timestamp: new Date().toISOString(),
          scannerVersion: 'test',
          rawOutput: { packageName: 'risky-package' },
        },
      }),
      makeFinding({
        id: 'existing-dependency-finding',
        source: 'supply-chain',
        file: '.',
        evidence: {
          timestamp: new Date().toISOString(),
          scannerVersion: 'test',
          rawOutput: { packageName: 'existing-package' },
        },
      }),
    ];
    orchestrator.register(makeFindingAdapter('supply-chain', findings));

    const result = await orchestrator.scan(fixtureDir, ['supply-chain'], {
      changedFilesOnly: true,
      diffContext: {
        changedFiles: ['package.json'],
        introducedFindings: [],
        addedDependencies: ['risky-package'],
        addedRoutes: [],
      },
    });

    expect(result.findings.map((finding) => finding.id)).toEqual(['added-dependency-finding']);
    expect(result.findings[0]?.introducedInDiff).toBe(true);
    expect(result.diffContext?.introducedFindings).toEqual(['added-dependency-finding']);
  });
});

async function createVulnerableAppFixture(): Promise<string> {
  const fixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-vulnerable-app-'));
  await fs.mkdir(path.join(fixtureDir, 'src'), { recursive: true });

  await fs.writeFile(
    path.join(fixtureDir, '.env'),
    [
      'api_key="1234567890abcdef1234567890abcdef"',
      'NEXT_PUBLIC_SECRET=public-secret-value',
    ].join('\n'),
  );

  await fs.writeFile(
    path.join(fixtureDir, 'src', 'App.tsx'),
    [
      'export function App({ html, token }: { html: string; token: string }) {',
      '  console.log("token", token);',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n'),
  );

  return fixtureDir;
}

function makeFakeAdapter(source: 'manual' | 'questionnaire', delayMs: number): ScannerAdapter {
  return {
    name: source,
    version: 'test',
    async isAvailable() {
      return true;
    },
    async getVersion() {
      return 'test';
    },
    async scan(_targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(resolve, delayMs);
        context?.signal?.addEventListener('abort', () => {
          clearTimeout(timeout);
          resolve();
        }, { once: true });
      });
      if (context?.signal?.aborted) {
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
      return {
        source,
        version: 'test',
        timestamp: new Date().toISOString(),
        findings: source === 'manual'
          ? [{
            id: 'fake-finding',
            source: 'manual',
            sourceRule: 'FAKE-001',
            severity: 'low',
            category: 'Test',
            title: 'Fake finding',
            description: 'Fake finding',
            regulationMappings: [],
            appMappings: [],
            evidence: {
              timestamp: new Date().toISOString(),
              scannerVersion: 'test',
              rawOutput: {},
            },
          }]
          : [],
        errors: [],
        durationMs: delayMs,
      };
    },
  };
}

function makeFindingAdapter(source: ScanSource, findings: AttestLensFinding[]): ScannerAdapter {
  return {
    name: source,
    version: 'test',
    async isAvailable() {
      return true;
    },
    async getVersion() {
      return 'test';
    },
    async scan(): Promise<ScannerResult> {
      return {
        source,
        version: 'test',
        timestamp: new Date().toISOString(),
        findings,
        errors: [],
        durationMs: 1,
      };
    },
  };
}

function makeFinding(overrides: Partial<AttestLensFinding>): AttestLensFinding {
  return {
    id: overrides.id || 'finding',
    source: overrides.source || 'manual',
    sourceRule: overrides.sourceRule || 'TEST-001',
    severity: overrides.severity || 'high',
    category: overrides.category || 'Security',
    title: overrides.title || 'Test finding',
    description: overrides.description || 'Test finding',
    file: overrides.file,
    line: overrides.line,
    code: overrides.code,
    regulationMappings: [],
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion: 'test',
      rawOutput: {},
    },
    ...overrides,
  };
}

function makeAuthoredRule(overrides: Partial<AuthoredRule> = {}): AuthoredRule {
  return {
    id: 'VS-HARDKEY',
    category: 'guardvibe-static',
    severity: 'critical',
    title: 'Hardcoded secret key',
    description: 'A hardcoded secret key was found in source code.',
    pattern: String.raw`\b[A-Za-z0-9_]*(?:api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token)[A-Za-z0-9_]*\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{16,}['"]?`,
    flags: 'gi',
    fixPrompt: 'Move secrets to environment variables.',
    regulationMappings: [],
    appMappings: [],
    addedIn: '2026.05.02',
    enabled: true,
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
    ...overrides,
  };
}

async function writeValidatedGuardVibeOverride(
  baseDir: string,
  options: {
    confidence: 'high' | 'medium' | 'low';
    determinism: 'deterministic' | 'heuristic' | 'manual-only';
  },
): Promise<void> {
  const authoredRule = makeAuthoredRule({
    authoring: {
      author: 'human-validated',
      confidence: options.confidence,
      falsePositiveRisk: options.confidence === 'low' ? 'high' : 'medium',
    },
    interpretation: {
      machineCheckable: options.determinism !== 'manual-only',
      determinism: options.determinism,
      reviewRequired: false,
      falsePositiveRisk: options.confidence === 'low' ? 'high' : 'medium',
    },
  });
  const runtimePath = getValidatedJurisdictionRuntimePackPath('sg-pdpa', baseDir);
  const validatedPath = getValidatedJurisdictionPackPath('sg-pdpa', baseDir);
  await fs.mkdir(path.dirname(runtimePath), { recursive: true });
  await fs.writeFile(runtimePath, JSON.stringify({
    schemaVersion: '1.0',
    version: '2026.05.02',
    generated: '2026-05-02T00:00:00.000Z',
    jurisdiction: 'sg-pdpa',
    rules: [{
      id: authoredRule.id,
      category: authoredRule.category,
      severity: authoredRule.severity,
      title: authoredRule.title,
      description: authoredRule.description,
      pattern: authoredRule.pattern,
      flags: authoredRule.flags,
      fixPrompt: authoredRule.fixPrompt,
      regulationMappings: authoredRule.regulationMappings,
      appMappings: authoredRule.appMappings,
      addedIn: authoredRule.addedIn,
      enabled: authoredRule.enabled,
      tags: authoredRule.tags,
    }],
  }, null, 2));
  await fs.writeFile(validatedPath, JSON.stringify({
    schemaVersion: '2.1',
    version: '2026.05.02',
    jurisdiction: 'sg-pdpa',
    generated: '2026-05-02T00:00:00.000Z',
    principles: [{
      id: 'SGPDPA_24',
      shortName: 'Protection',
      obligation: 'Protect personal data',
      citation: 'PDPA Section 24',
    }],
    rules: [authoredRule],
    provenance: {
      proposedAt: '2026-05-01T00:00:00.000Z',
      reviewedBy: 'reviewer',
      reviewedAt: '2026-05-02T00:00:00.000Z',
      sourceDocumentHash: 'hash',
    },
    ruleProvenance: {
      [authoredRule.id]: authoredRule.provenance,
    },
  }, null, 2));
}

async function createNoProvenanceDependencyFixture(): Promise<string> {
  const fixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-provenance-'));
  const dependencies = {
    'no-repo-one': '1.0.0',
    'no-repo-two': '1.0.0',
  };

  await fs.writeFile(
    path.join(fixtureDir, 'package.json'),
    JSON.stringify({
      name: 'provenance-test',
      version: '1.0.0',
      dependencies,
    }, null, 2),
  );
  await fs.writeFile(
    path.join(fixtureDir, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'provenance-test',
          version: '1.0.0',
          dependencies,
        },
        'node_modules/no-repo-one': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/no-repo-one/-/no-repo-one-1.0.0.tgz',
          integrity: 'sha512-test',
        },
        'node_modules/no-repo-two': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/no-repo-two/-/no-repo-two-1.0.0.tgz',
          integrity: 'sha512-test',
        },
      },
    }, null, 2),
  );

  for (const [name, version] of Object.entries(dependencies)) {
    const dependencyDir = path.join(fixtureDir, 'node_modules', name);
    await fs.mkdir(dependencyDir, { recursive: true });
    await fs.writeFile(
      path.join(dependencyDir, 'package.json'),
      JSON.stringify({ name, version }, null, 2),
    );
  }

  return fixtureDir;
}
