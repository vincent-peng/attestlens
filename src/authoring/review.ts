import fs from 'node:fs/promises';
import path from 'node:path';

import { input, select } from '@inquirer/prompts';

import { runRuleTestHarness, type TestHarnessResult } from './test-harness.js';
import {
  AuthoredRule as AuthoredRuleSchema,
  ProposedPackManifest,
  RulePackManifest,
  ValidatedPackManifest,
  type AuthoredRule,
  type ProposedPackManifest as ProposedPackManifestType,
  type RuleDefinition,
  type ValidatedPackManifest as ValidatedPackManifestType,
} from '../schema/index.js';

type ReviewDecision = 'approve' | 'reject' | 'skip' | 'edit';

export interface ReviewPackOptions {
  proposedPath: string;
  reviewer: string;
  outputPath: string;
  approveAll?: boolean;
  rejectLowConfidence?: boolean;
  now?: Date;
  promptForDecision?: (rule: AuthoredRule, testResult?: TestHarnessResult) => Promise<ReviewDecision>;
  promptForEditedRule?: (rule: AuthoredRule) => Promise<AuthoredRule>;
}

export async function reviewPack(options: ReviewPackOptions): Promise<ValidatedPackManifestType> {
  const outputPaths = resolveReviewOutputPaths(path.resolve(options.outputPath));
  const proposed = ProposedPackManifest.parse(
    JSON.parse(await fs.readFile(path.resolve(options.proposedPath), 'utf-8')),
  );
  const harnessResults = await runRuleTestHarness({ rules: proposed.rules });
  const harnessByRuleId = new Map(harnessResults.map((result) => [result.ruleId, result]));
  const reviewedAt = (options.now || new Date()).toISOString();

  const approvedRules: AuthoredRule[] = [];
  const ruleProvenance: Record<string, AuthoredRule['provenance']> = {};

  for (const rule of proposed.rules) {
    if (options.rejectLowConfidence && rule.authoring.confidence === 'low') {
      continue;
    }

    let candidateRule = rule;
    let decision: ReviewDecision;
    if (options.approveAll) {
      decision = 'approve';
    } else {
      decision = await (options.promptForDecision || defaultPromptForDecision)(rule, harnessByRuleId.get(rule.id));
    }

    if (decision === 'edit') {
      candidateRule = await (options.promptForEditedRule || defaultPromptForEditedRule)(rule);
      decision = 'approve';
    }

    if (decision !== 'approve') {
      continue;
    }

    const approvedRule = markRuleApproved(candidateRule, options.reviewer, reviewedAt);
    approvedRules.push(approvedRule);
    ruleProvenance[approvedRule.id] = approvedRule.provenance;
  }

  const manifest = ValidatedPackManifest.parse({
    schemaVersion: '2.1',
    version: buildPackVersion(reviewedAt),
    jurisdiction: proposed.jurisdiction,
    generated: reviewedAt,
    principles: proposed.principles.map((principle) => ({
      id: principle.id,
      shortName: principle.shortName,
      obligation: principle.obligation,
      citation: principle.citation,
    })),
    rules: approvedRules,
    provenance: {
      proposedAt: proposed.generatedAt,
      reviewedBy: options.reviewer,
      reviewedAt,
      sourceDocumentHash: proposed.sourceDocumentHash,
    },
    ruleProvenance,
  });

  const runtimePack = buildRuntimePack(approvedRules, proposed.jurisdiction, reviewedAt);
  const validatedContents = `${JSON.stringify(manifest, null, 2)}\n`;
  const runtimeContents = `${JSON.stringify(runtimePack, null, 2)}\n`;
  const validatedTempPath = `${outputPaths.validatedPath}.tmp`;
  const runtimeTempPath = `${outputPaths.runtimePath}.tmp`;

  await fs.mkdir(path.dirname(outputPaths.validatedPath), { recursive: true });

  try {
    await fs.writeFile(validatedTempPath, validatedContents, 'utf-8');
    await fs.writeFile(runtimeTempPath, runtimeContents, 'utf-8');
    await fs.rename(runtimeTempPath, outputPaths.runtimePath);
    await fs.rename(validatedTempPath, outputPaths.validatedPath);
  } catch (error) {
    await Promise.all([
      fs.rm(validatedTempPath, { force: true }),
      fs.rm(runtimeTempPath, { force: true }),
    ]);
    throw error;
  }

  return manifest;
}

async function defaultPromptForDecision(rule: AuthoredRule, testResult?: TestHarnessResult): Promise<ReviewDecision> {
  const testSummary = testResult
    ? `${testResult.summary.passed}/${testResult.summary.total} tests passed`
    : 'No tests';
  console.log('');
  console.log(`${rule.id} — ${rule.title}`);
  console.log(`Severity: ${rule.severity}`);
  console.log(`Confidence: ${rule.authoring.confidence}`);
  console.log(`Citation: ${rule.source.citation}`);
  console.log(`Tests: ${testSummary}`);

  return select<ReviewDecision>({
    message: 'Review decision',
    choices: [
      { name: 'Approve', value: 'approve' },
      { name: 'Reject', value: 'reject' },
      { name: 'Edit citation/description JSON', value: 'edit' },
      { name: 'Skip', value: 'skip' },
    ],
  });
}

async function defaultPromptForEditedRule(rule: AuthoredRule): Promise<AuthoredRule> {
  const edited = await input({
    message: 'Paste the full edited rule JSON',
    default: JSON.stringify(rule, null, 2),
  });
  return AuthoredRuleSchema.parse(JSON.parse(edited));
}

function markRuleApproved(rule: AuthoredRule, reviewer: string, reviewedAt: string): AuthoredRule {
  const packVersion = buildPackVersion(reviewedAt);
  return {
    ...rule,
    authoring: {
      ...rule.authoring,
      author: 'human-validated',
    },
    provenance: {
      ...rule.provenance,
      approvedBy: reviewer,
      approvedAt: reviewedAt,
      packVersion,
    },
    interpretation: {
      ...rule.interpretation,
      reviewRequired: false,
    },
  };
}

function buildPackVersion(reviewedAt: string): string {
  return reviewedAt.slice(0, 10).replace(/-/g, '.');
}

function resolveReviewOutputPaths(outputPath: string): { validatedPath: string; runtimePath: string } {
  const parsed = path.parse(outputPath);
  if (parsed.ext !== '.json') {
    throw new Error(`review-pack output path must end in .json: ${outputPath}`);
  }
  if (parsed.name.endsWith('.runtime')) {
    throw new Error(`review-pack output path must not end in .runtime.json: ${outputPath}`);
  }

  return {
    validatedPath: outputPath,
    runtimePath: path.join(parsed.dir, `${parsed.name}.runtime${parsed.ext}`),
  };
}

/**
 * PH11-002: Build a runtime-consumable RulePackManifest (schema 1.0) from approved authored rules.
 * Strips authoring metadata, keeps only fields the scanner needs.
 */
function buildRuntimePack(
  approvedRules: AuthoredRule[],
  jurisdiction: string,
  reviewedAt: string,
) {
  const runtimeRules: RuleDefinition[] = approvedRules.map((rule) => ({
    id: rule.id,
    category: rule.category,
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    pattern: rule.pattern,
    flags: rule.flags,
    fixPrompt: rule.fixPrompt,
    regulationMappings: rule.regulationMappings,
    appMappings: rule.appMappings,
    cve: rule.cve,
    addedIn: rule.addedIn,
    enabled: rule.enabled,
    tags: rule.tags,
  }));
  return RulePackManifest.parse({
    schemaVersion: '1.0',
    version: buildPackVersion(reviewedAt),
    generated: reviewedAt,
    rules: runtimeRules,
    jurisdiction,
  });
}
