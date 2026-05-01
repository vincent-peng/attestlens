import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { GuardVibeAdapter } from '../scanner/guardvibe.js';
import type { AuthoredRule, RulePackManifest } from '../schema/index.js';

export interface TestHarnessOptions {
  rules: AuthoredRule[];
  basePath?: string;
  fixtureDir?: string;
}

export interface TestHarnessCaseResult {
  testName: string;
  category: 'positive' | 'negative' | 'edgeCase';
  input: string;
  shouldTrigger: boolean;
  didTrigger: boolean;
  passed: boolean;
  error?: string;
}

export interface TestHarnessResult {
  ruleId: string;
  passed: boolean;
  results: TestHarnessCaseResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
  };
}

export async function runRuleTestHarness(options: TestHarnessOptions): Promise<TestHarnessResult[]> {
  const harnessResults: TestHarnessResult[] = [];

  for (const rule of options.rules) {
    const results: TestHarnessCaseResult[] = [];
    const cases = [
      ...rule.tests.positive.map((testCase) => ({ category: 'positive' as const, testCase })),
      ...rule.tests.negative.map((testCase) => ({ category: 'negative' as const, testCase })),
      ...rule.tests.edgeCase.map((testCase) => ({ category: 'edgeCase' as const, testCase })),
    ];

    if (cases.length === 0) {
      harnessResults.push({
        ruleId: rule.id,
        passed: true,
        results: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
        },
      });
      continue;
    }

    for (const { category, testCase } of cases) {
      results.push(await runSingleRuleTest(rule, category, testCase, options));
    }

    const passedCount = results.filter((result) => result.passed).length;
    harnessResults.push({
      ruleId: rule.id,
      passed: passedCount === results.length,
      results,
      summary: {
        total: results.length,
        passed: passedCount,
        failed: results.length - passedCount,
      },
    });
  }

  return harnessResults;
}

async function runSingleRuleTest(
  rule: AuthoredRule,
  category: 'positive' | 'negative' | 'edgeCase',
  testCase: AuthoredRule['tests']['positive'][number],
  options: TestHarnessOptions,
): Promise<TestHarnessCaseResult> {
  let tempDir: string | undefined;

  try {
    tempDir = await fs.mkdtemp(path.join(options.basePath || os.tmpdir(), 'attestlens-rule-harness-'));
    const fixture = await resolveFixture(testCase.input, options.fixtureDir);
    const filename = `snippet${fixture.extension || '.ts'}`;
    await fs.writeFile(path.join(tempDir, filename), fixture.content, 'utf-8');

    const adapter = new GuardVibeAdapter('__attestlens_missing_guardvibe_binary__');
    const result = await adapter.scan(tempDir, {
      rulePack: buildSingleRulePack(rule),
      allowCustomRules: true,
    });
    const didTrigger = result.findings.some((finding) => finding.sourceRule === rule.id);

    return {
      testName: testCase.name,
      category,
      input: testCase.input,
      shouldTrigger: testCase.shouldTrigger,
      didTrigger,
      passed: didTrigger === testCase.shouldTrigger,
      error: result.errors.length > 0 ? result.errors.map((error) => error.message).join('; ') : undefined,
    };
  } catch (error: any) {
    return {
      testName: testCase.name,
      category,
      input: testCase.input,
      shouldTrigger: testCase.shouldTrigger,
      didTrigger: false,
      passed: false,
      error: error.message,
    };
  } finally {
    if (tempDir) {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  }
}

async function resolveFixture(
  input: string,
  fixtureDir?: string,
): Promise<{ content: string; extension: string }> {
  if (fixtureDir) {
    const candidatePath = path.resolve(fixtureDir, input);
    try {
      const stat = await fs.stat(candidatePath);
      if (stat.isFile()) {
        return {
          content: await fs.readFile(candidatePath, 'utf-8'),
          extension: path.extname(candidatePath),
        };
      }
    } catch {
      // Treat input as inline fixture text when the file is absent.
    }
  }

  return {
    content: input,
    extension: '.ts',
  };
}

function buildSingleRulePack(rule: AuthoredRule): RulePackManifest {
  return {
    schemaVersion: '1.0',
    version: rule.provenance.packVersion || rule.addedIn,
    generated: rule.provenance.approvedAt || rule.provenance.draftedAt || new Date(0).toISOString(),
    jurisdiction: rule.source.jurisdiction,
    rules: [rule],
  };
}
