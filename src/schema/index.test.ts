import { describe, expect, it } from 'vitest';

import {
  JurisdictionPackManifest,
  RegulationMapping,
  RuleDefinition,
  RuleFreshness,
  RulePackManifest,
  ScanSource,
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
});
