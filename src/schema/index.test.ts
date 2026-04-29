import { describe, expect, it } from 'vitest';

import { RulePackManifest, RuleFreshness, ScanSource } from './index.js';

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
});
