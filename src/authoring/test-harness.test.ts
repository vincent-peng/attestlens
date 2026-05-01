import { describe, expect, it } from 'vitest';

import { AuthoredRule as AuthoredRuleSchema, type AuthoredRule } from '../schema/index.js';
import { runRuleTestHarness } from './test-harness.js';

function makeRule(overrides: Partial<AuthoredRule> = {}): AuthoredRule {
  return AuthoredRuleSchema.parse({
    id: 'HARNESS-001',
    category: 'guardvibe-static',
    severity: 'high',
    title: 'Detect hardcoded key',
    description: 'Flags hardcoded keys',
    pattern: 'apiKey = [\'"]',
    addedIn: '2026.05.01',
    source: {
      jurisdiction: 'sg-pdpa',
      citation: 'PDPA Section 24',
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
      sourceDocumentHash: 'hash',
    },
    interpretation: {
      machineCheckable: true,
      determinism: 'deterministic',
      reviewRequired: true,
      falsePositiveRisk: 'medium',
    },
    tests: {
      positive: [],
      negative: [],
      edgeCase: [],
    },
    ...overrides,
  });
}

describe('runRuleTestHarness', () => {
  it('passes known-good rules', async () => {
    const rule = makeRule({
      tests: {
        positive: [{ name: 'positive', input: 'const apiKey = "secret";', shouldTrigger: true }],
        negative: [{ name: 'negative', input: 'const safeValue = process.env.SECRET_KEY;', shouldTrigger: false }],
        edgeCase: [],
      },
    });

    const [result] = await runRuleTestHarness({ rules: [rule] });

    expect(result.passed).toBe(true);
    expect(result.summary).toEqual({ total: 2, passed: 2, failed: 0 });
  });

  it('fails known-bad rules', async () => {
    const rule = makeRule({
      pattern: 'totallyDifferentPattern',
      tests: {
        positive: [{ name: 'positive', input: 'const apiKey = "secret";', shouldTrigger: true }],
        negative: [],
        edgeCase: [],
      },
    });

    const [result] = await runRuleTestHarness({ rules: [rule] });

    expect(result.passed).toBe(false);
    expect(result.summary.failed).toBe(1);
    expect(result.results[0]?.didTrigger).toBe(false);
  });

  it('returns empty results when a rule has no tests', async () => {
    const [result] = await runRuleTestHarness({ rules: [makeRule()] });

    expect(result.passed).toBe(true);
    expect(result.results).toEqual([]);
    expect(result.summary).toEqual({ total: 0, passed: 0, failed: 0 });
  });
});
