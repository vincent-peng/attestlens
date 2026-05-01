import { describe, expect, it } from 'vitest';

import {
  AuthoredRule,
  CCPAPrinciple,
  GDPRPrinciple,
  JurisdictionPackManifest,
  ProposedPackManifest,
  RegulationMapping,
  RuleDefinition,
  RuleInterpretation,
  RuleProvenance,
  RuleFreshness,
  RulePackManifest,
  ScanSource,
  ValidatedPackManifest,
} from './index.js';

describe('ScanSource', () => {
  it('only exposes shipped scanner sources', () => {
    expect(ScanSource.options).toEqual([
      'guardvibe',
      'vibesafe',
      'mcp-scan',
      'vibe-check',
      'supply-chain',
      'behavioral',
      'gitleaks',
      'iac',
      'url-scan',
      'manual',
      'questionnaire',
      'reform-2026',
    ]);
    expect(ScanSource.options).not.toContain('shannon');
  });
});

describe('Rule pack schemas', () => {
  it('validates rule pack manifests and freshness metadata', () => {
    const manifest = RulePackManifest.parse({
      schemaVersion: '1.0',
      version: '2026.04.24',
      generated: '2026-04-24T00:00:00.000Z',
      rules: [
        {
          id: 'AL-TEST-001',
          category: 'test',
          severity: 'high',
          title: 'Test rule',
          description: 'A test rule',
          addedIn: '2026.04.24',
        },
      ],
    });

    expect(manifest.rules[0].enabled).toBe(true);
    expect(manifest.rules[0].tags).toEqual([]);

    const freshness = RuleFreshness.parse({
      version: '2026.04.24',
      generated: '2026-04-24T00:00:00.000Z',
      loadedAt: '2026-04-24T01:00:00.000Z',
      source: 'embedded',
      cachePath: '/Users/alice/.attestlens/rules/latest.json',
      ruleCount: 1,
      ageDays: 0,
      stale: false,
    });
    expect(freshness.source).toBe('embedded');
    expect('cachePath' in freshness).toBe(false);
  });

  it('validates jurisdiction-aware regulation mappings', () => {
    for (const jurisdiction of ['au-privacy-act', 'us-ccpa', 'eu-gdpr'] as const) {
      const mapping = RegulationMapping.parse({
        jurisdiction,
        principle: jurisdiction === 'au-privacy-act' ? 'APP_11' : `${jurisdiction}:security`,
        obligation: 'Protect personal information',
        status: 'fail',
        confidence: 0.8,
        rationale: 'Test mapping',
      });

      expect(mapping.jurisdiction).toBe(jurisdiction);
    }
  });

  it('validates CCPA principles', () => {
    expect(CCPAPrinciple.parse('CCPA_100')).toBe('CCPA_100');
    expect(CCPAPrinciple.parse('CCPA_150')).toBe('CCPA_150');
    expect(() => CCPAPrinciple.parse('CCPA_999')).toThrow();
  });

  it('validates GDPR subset principles', () => {
    expect(GDPRPrinciple.parse('GDPR_Art3')).toBe('GDPR_Art3');
    expect(GDPRPrinciple.parse('GDPR_Art44')).toBe('GDPR_Art44');
    expect(() => GDPRPrinciple.parse('GDPR_Art99')).toThrow();
  });

  it('validates v2 jurisdiction pack manifests', () => {
    const manifest = JurisdictionPackManifest.parse({
      schemaVersion: '2.0',
      version: '2026.04.30',
      jurisdiction: 'au-privacy-act',
      generated: '2026-04-30T00:00:00.000Z',
      principles: [{
        id: 'APP_11',
        shortName: 'Security',
        obligation: 'Take reasonable steps to protect personal information',
        citation: 'Privacy Act 1988 (Cth)',
      }],
      rules: [{
        id: 'AL-TEST-001',
        category: 'test',
        severity: 'high',
        title: 'Test rule',
        description: 'A test rule',
        addedIn: '2026.04.30',
        regulationMappings: [{
          jurisdiction: 'au-privacy-act',
          principle: 'APP_11',
          obligation: 'Take reasonable steps to protect personal information',
          status: 'fail',
          confidence: 0.9,
        }],
      }],
    });

    expect(manifest.schemaVersion).toBe('2.0');
    expect(manifest.rules[0]!.regulationMappings?.[0]?.principle).toBe('APP_11');
  });

  it('validates v2 CCPA jurisdiction pack manifests', () => {
    const manifest = JurisdictionPackManifest.parse({
      schemaVersion: '2.0',
      version: '2026.04.30',
      jurisdiction: 'us-ccpa',
      generated: '2026-04-30T00:00:00.000Z',
      principles: [{
        id: 'CCPA_100',
        shortName: 'General Duties',
        obligation: 'Maintain reasonable security',
        citation: 'Cal. Civ. Code §1798.100(e)',
      }],
      rules: [{
        id: 'CCPA-TEST-001',
        category: 'ccpa-security',
        severity: 'high',
        title: 'Test CCPA rule',
        description: 'A test CCPA rule',
        addedIn: '2026.04.30',
        regulationMappings: [{
          jurisdiction: 'us-ccpa',
          principle: 'CCPA_100',
          obligation: 'Maintain reasonable security',
          status: 'fail',
          confidence: 0.9,
          citation: 'Cal. Civ. Code §1798.100(e)',
        }],
      }],
    });

    expect(manifest.jurisdiction).toBe('us-ccpa');
    expect(manifest.rules[0]!.regulationMappings?.[0]?.principle).toBe('CCPA_100');
  });

  it('validates v2 GDPR jurisdiction pack manifests', () => {
    const manifest = JurisdictionPackManifest.parse({
      schemaVersion: '2.0',
      version: '2026.04.30',
      jurisdiction: 'eu-gdpr',
      generated: '2026-04-30T00:00:00.000Z',
      principles: [{
        id: 'GDPR_Art32',
        shortName: 'Security of Processing',
        obligation: 'Implement appropriate security controls',
        citation: 'GDPR Art. 32(1)',
      }],
      rules: [{
        id: 'GDPR-TEST-001',
        category: 'gdpr-security',
        severity: 'high',
        title: 'Test GDPR rule',
        description: 'A test GDPR rule',
        addedIn: '2026.04.30',
        regulationMappings: [{
          jurisdiction: 'eu-gdpr',
          principle: 'GDPR_Art32',
          obligation: 'Implement appropriate security controls',
          status: 'fail',
          confidence: 0.9,
          citation: 'GDPR Art. 32(1)',
        }],
      }],
    });

    expect(manifest.jurisdiction).toBe('eu-gdpr');
    expect(manifest.rules[0]!.regulationMappings?.[0]?.principle).toBe('GDPR_Art32');
  });

  it('accepts rule definitions with regulationMappings and appMappings', () => {
    const rule = RuleDefinition.parse({
      id: 'AL-TEST-002',
      category: 'test',
      severity: 'medium',
      title: 'Test rule',
      description: 'A test rule',
      addedIn: '2026.04.30',
      regulationMappings: [{
        jurisdiction: 'eu-gdpr',
        principle: 'GDPR_Art32',
        obligation: 'Implement appropriate security controls',
        status: 'fail',
        confidence: 0.7,
      }],
      appMappings: [{
        principle: 'APP_11',
        obligation: 'Take reasonable steps to protect personal information',
        status: 'fail',
        confidence: 0.8,
      }],
    });

    expect(rule.regulationMappings?.[0]?.jurisdiction).toBe('eu-gdpr');
    expect(rule.appMappings[0]?.principle).toBe('APP_11');
  });

  it('keeps backward compatibility for rules that only define appMappings', () => {
    const rule = RuleDefinition.parse({
      id: 'AL-TEST-003',
      category: 'test',
      severity: 'high',
      title: 'Legacy APP rule',
      description: 'A legacy rule',
      addedIn: '2026.04.30',
      appMappings: [{
        principle: 'APP_11',
        obligation: 'Take reasonable steps to protect personal information',
        status: 'fail',
        confidence: 0.9,
      }],
    });

    expect(rule.appMappings[0]?.principle).toBe('APP_11');
    expect(rule.regulationMappings).toBeUndefined();
  });

  it('validates authored rules and keeps them compatible with rule definitions', () => {
    const authoredRule = AuthoredRule.parse({
      id: 'SGPDPA-TEST-001',
      category: 'guardvibe-static',
      severity: 'high',
      title: 'Test authored rule',
      description: 'Detects hardcoded secrets',
      pattern: 'apiKey\\s*=',
      addedIn: '2026.05.01',
      source: {
        jurisdiction: 'sg-pdpa',
        citation: 'PDPA Section 24',
        legislationUrl: 'https://example.com/pdpa',
      },
      authoring: {
        author: 'ai-draft',
        confidence: 'medium',
        falsePositiveRisk: 'medium',
      },
      provenance: {
        draftedByModel: 'gpt-5.5',
        draftedAt: '2026-05-01T00:00:00.000Z',
        draftingPromptVersion: 'phase-11-v1',
        sourceDocumentHash: 'abc123',
      },
      interpretation: {
        machineCheckable: true,
        determinism: 'deterministic',
        reviewRequired: true,
        falsePositiveRisk: 'medium',
      },
      tests: {
        positive: [{ name: 'positive', input: 'const apiKey = "secret";', shouldTrigger: true }],
      },
    });

    const parsedRule = RuleDefinition.parse(authoredRule);
    expect(parsedRule.id).toBe('SGPDPA-TEST-001');
    expect(authoredRule.tests.negative).toEqual([]);
    expect(authoredRule.tests.edgeCase).toEqual([]);
  });

  it('rejects ai-draft authored rules that do not require review', () => {
    expect(() => AuthoredRule.parse({
      id: 'SGPDPA-TEST-002',
      category: 'guardvibe-static',
      severity: 'medium',
      title: 'Invalid authored rule',
      description: 'Should fail validation',
      addedIn: '2026.05.01',
      source: {
        jurisdiction: 'sg-pdpa',
        citation: 'PDPA Section 24',
      },
      authoring: {
        author: 'ai-draft',
        confidence: 'low',
        falsePositiveRisk: 'high',
      },
      provenance: {
        sourceDocumentHash: 'abc123',
      },
      interpretation: {
        machineCheckable: true,
        determinism: 'heuristic',
        reviewRequired: false,
        falsePositiveRisk: 'high',
      },
      tests: {},
    })).toThrow(/require review/);
  });

  it('validates proposed and validated pack manifests', () => {
    const provenance = RuleProvenance.parse({
      draftedByModel: 'gpt-5.5',
      draftedAt: '2026-05-01T00:00:00.000Z',
      draftingPromptVersion: 'phase-11-v1',
      sourceDocumentHash: 'abc123',
    });
    const interpretation = RuleInterpretation.parse({
      machineCheckable: true,
      determinism: 'deterministic',
      reviewRequired: true,
      falsePositiveRisk: 'low',
    });

    const proposed = ProposedPackManifest.parse({
      schemaVersion: '3.0',
      jurisdiction: 'sg-pdpa',
      generatedAt: '2026-05-01T00:00:00.000Z',
      sourceDocumentHash: 'abc123',
      principles: [{
        id: 'SGPDPA_24',
        shortName: 'Protection',
        obligation: 'Protect personal data',
      }],
      rules: [{
        id: 'SGPDPA-TEST-003',
        category: 'guardvibe-static',
        severity: 'high',
        title: 'Proposed rule',
        description: 'Detects secrets',
        pattern: 'secret',
        addedIn: '2026.05.01',
        source: {
          jurisdiction: 'sg-pdpa',
          citation: 'PDPA Section 24',
        },
        authoring: {
          author: 'ai-draft',
          confidence: 'high',
          falsePositiveRisk: 'low',
        },
        provenance,
        interpretation,
        tests: {},
      }],
      confidence: 'medium',
    });

    expect(proposed.rules[0]?.authoring.author).toBe('ai-draft');

    const validated = ValidatedPackManifest.parse({
      schemaVersion: '2.1',
      version: '2026.05.01',
      jurisdiction: 'sg-pdpa',
      generated: '2026-05-01T01:00:00.000Z',
      principles: [{
        id: 'SGPDPA_24',
        shortName: 'Protection',
        obligation: 'Protect personal data',
      }],
      rules: [{
        ...proposed.rules[0],
        authoring: {
          ...proposed.rules[0]!.authoring,
          author: 'human-validated',
        },
        provenance: {
          ...proposed.rules[0]!.provenance,
          approvedBy: 'reviewer',
          approvedAt: '2026-05-01T01:00:00.000Z',
          packVersion: '2026.05.01',
        },
        interpretation: {
          ...proposed.rules[0]!.interpretation,
          reviewRequired: false,
        },
      }],
      provenance: {
        proposedAt: '2026-05-01T00:00:00.000Z',
        reviewedBy: 'reviewer',
        reviewedAt: '2026-05-01T01:00:00.000Z',
        sourceDocumentHash: 'abc123',
      },
      ruleProvenance: {
        'SGPDPA-TEST-003': {
          ...proposed.rules[0]!.provenance,
          approvedBy: 'reviewer',
          approvedAt: '2026-05-01T01:00:00.000Z',
          packVersion: '2026.05.01',
        },
      },
    });

    expect(validated.schemaVersion).toBe('2.1');
    expect(validated.rules[0]?.authoring.author).toBe('human-validated');
  });
});
