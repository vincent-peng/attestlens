import type { Jurisdiction } from '../schema/index.js';

export const RULE_DRAFTING_PROMPT_VERSION = 'phase-11-v1';

export interface PromptContext {
  jurisdiction: Jurisdiction;
  legislationText: string;
  sourceUrl?: string;
  existingPackSummary?: string;
}

export function buildObligationExtractionPrompt(context: PromptContext): string {
  return [
    'You are drafting a compliance rule pack from legislation.',
    `Jurisdiction: ${context.jurisdiction}`,
    context.sourceUrl ? `Source URL: ${context.sourceUrl}` : undefined,
    context.existingPackSummary ? `Existing pack summary:\n${context.existingPackSummary}` : undefined,
    'Pass 1 task:',
    'Extract the legal obligations, principles, ambiguities, and reviewer warnings from the legislation.',
    'Return strict JSON with keys: principles, warnings, gaps, confidence, obligationsSummary.',
    'Each principle must include: id, shortName, fullName (optional), obligation, citation (optional).',
    'Do not generate scanner rules yet.',
    'Legislation text follows:',
    context.legislationText,
  ].filter(Boolean).join('\n\n');
}

export function buildRuleGenerationPrompt(context: PromptContext, obligationJson: string): string {
  return [
    'You are drafting a proposed compliance pack from legislation and extracted obligations.',
    `Jurisdiction: ${context.jurisdiction}`,
    context.sourceUrl ? `Source URL: ${context.sourceUrl}` : undefined,
    context.existingPackSummary ? `Existing pack summary:\n${context.existingPackSummary}` : undefined,
    `Prompt version: ${RULE_DRAFTING_PROMPT_VERSION}`,
    'Pass 2 task:',
    'Generate strict JSON matching ProposedPackManifest schemaVersion 3.0.',
    'Each rule must be deterministic where possible, include citations, mappings, interpretation, and tests.',
    'All rule IDs must be unique. Do not include markdown fences.',
    'The final JSON must contain: schemaVersion, jurisdiction, generatedAt, sourceDocumentHash, sourceDocumentUrl, principles, rules, mappingRules, questions, confidence, warnings, gaps.',
    'Reuse the exact principles from pass 1 unless legislation clearly requires additions.',
    'Pass 1 JSON follows:',
    obligationJson,
    'Legislation text follows:',
    context.legislationText,
  ].filter(Boolean).join('\n\n');
}
