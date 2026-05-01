import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
  AuthoredRule as AuthoredRuleSchema,
  ProposedPackManifest,
  type AuthoredRule,
  type Jurisdiction,
  type ProposedPackManifest as ProposedPackManifestType,
  type RuleConfidence,
} from '../schema/index.js';
import {
  RULE_DRAFTING_PROMPT_VERSION,
  buildObligationExtractionPrompt,
  buildRuleGenerationPrompt,
} from './prompt.js';

export interface ProposeRulesOptions {
  jurisdiction: Jurisdiction;
  sourcePath: string;
  sourceUrl?: string;
  outputPath: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  existingPackPath?: string;
  fetchImpl?: typeof fetch;
  now?: Date;
}

interface LlmChatResponse {
  choices?: Array<{
    message?: {
      content?: string | Array<{ type?: string; text?: string }>;
    };
  }>;
}

interface ExtractedObligations {
  principles?: unknown[];
  warnings?: string[];
  gaps?: string[];
  confidence?: RuleConfidence;
  obligationsSummary?: string;
}

export async function proposeRules(options: ProposeRulesOptions): Promise<ProposedPackManifestType> {
  const apiKey = options.apiKey || process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error('An API key is required. Pass --api-key or set OPENAI_API_KEY.');
  }

  const legislationText = await fs.readFile(path.resolve(options.sourcePath), 'utf-8');
  const sourceDocumentHash = sha256(legislationText);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error('Fetch is not available in this runtime.');
  }

  const existingPackSummary = options.existingPackPath
    ? await buildExistingPackSummary(path.resolve(options.existingPackPath))
    : undefined;
  const promptContext = {
    jurisdiction: options.jurisdiction,
    legislationText,
    sourceUrl: options.sourceUrl,
    existingPackSummary,
  };

  const obligationsRaw = await callChatCompletion({
    apiKey,
    baseUrl: options.baseUrl,
    model: options.model || 'gpt-5.5',
    fetchImpl,
    prompt: buildObligationExtractionPrompt(promptContext),
  });
  const obligations = parseJson<ExtractedObligations>(obligationsRaw, 'obligation extraction');

  const proposalRaw = await callChatCompletion({
    apiKey,
    baseUrl: options.baseUrl,
    model: options.model || 'gpt-5.5',
    fetchImpl,
    prompt: buildRuleGenerationPrompt(promptContext, JSON.stringify(obligations, null, 2)),
  });
  const draft = parseJson<Record<string, unknown>>(proposalRaw, 'rule generation');

  const nowIso = (options.now || new Date()).toISOString();
  const normalized = ProposedPackManifest.parse({
    ...draft,
    schemaVersion: '3.0',
    jurisdiction: options.jurisdiction,
    generatedAt: typeof draft.generatedAt === 'string' ? draft.generatedAt : nowIso,
    sourceDocumentHash,
    sourceDocumentUrl: options.sourceUrl,
    principles: Array.isArray(draft.principles) ? draft.principles : obligations.principles || [],
    confidence: draft.confidence || obligations.confidence || 'medium',
    warnings: Array.isArray(draft.warnings) ? draft.warnings : obligations.warnings || [],
    gaps: Array.isArray(draft.gaps) ? draft.gaps : obligations.gaps || [],
    rules: normalizeAuthoredRules(draft.rules, {
      jurisdiction: options.jurisdiction,
      sourceUrl: options.sourceUrl,
      sourceDocumentHash,
      model: options.model || 'gpt-5.5',
      draftedAt: nowIso,
    }),
  });

  await fs.mkdir(path.dirname(path.resolve(options.outputPath)), { recursive: true });
  await fs.writeFile(path.resolve(options.outputPath), `${JSON.stringify(normalized, null, 2)}\n`, 'utf-8');
  return normalized;
}

async function callChatCompletion(params: {
  apiKey: string;
  baseUrl?: string;
  model: string;
  fetchImpl: typeof fetch;
  prompt: string;
}): Promise<string> {
  const baseUrl = (params.baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const response = await params.fetchImpl(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${params.apiKey}`,
    },
    body: JSON.stringify({
      model: params.model,
      temperature: 0,
      messages: [
        {
          role: 'system',
          content: 'Return strict JSON only. Do not wrap it in markdown.',
        },
        {
          role: 'user',
          content: params.prompt,
        },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`LLM request failed with HTTP ${response.status}`);
  }

  const payload = await response.json() as LlmChatResponse;
  const content = payload.choices?.[0]?.message?.content;
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    return content.map((part) => part.text || '').join('');
  }
  throw new Error('LLM response did not include message content');
}

function parseJson<T>(raw: string, stage: string): T {
  const cleaned = raw.trim().replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/i, '');
  try {
    return JSON.parse(cleaned) as T;
  } catch (error: any) {
    throw new Error(`Failed to parse ${stage} JSON: ${error.message}`);
  }
}

function normalizeAuthoredRules(
  rawRules: unknown,
  context: {
    jurisdiction: Jurisdiction;
    sourceUrl?: string;
    sourceDocumentHash: string;
    model: string;
    draftedAt: string;
  },
): AuthoredRule[] {
  if (!Array.isArray(rawRules)) {
    return [];
  }

  return rawRules.map((rule) => {
    const rawRule = (rule && typeof rule === 'object' ? rule : {}) as Record<string, any>;
    return AuthoredRuleSchema.parse({
      ...rawRule,
      source: {
        jurisdiction: context.jurisdiction,
        citation: rawRule.source?.citation || 'Citation required',
        legislationUrl: context.sourceUrl,
        effectiveDate: rawRule.source?.effectiveDate,
      },
      authoring: {
        author: 'ai-draft',
        confidence: rawRule.authoring?.confidence || 'medium',
        falsePositiveRisk: rawRule.authoring?.falsePositiveRisk || rawRule.interpretation?.falsePositiveRisk || 'medium',
      },
      provenance: {
        ...rawRule.provenance,
        draftedByModel: context.model,
        draftedAt: rawRule.provenance?.draftedAt || context.draftedAt,
        draftingPromptVersion: RULE_DRAFTING_PROMPT_VERSION,
        sourceDocumentHash: context.sourceDocumentHash,
      },
      interpretation: {
        machineCheckable: rawRule.interpretation?.machineCheckable ?? true,
        determinism: rawRule.interpretation?.determinism || 'deterministic',
        reviewRequired: true,
        falsePositiveRisk: rawRule.interpretation?.falsePositiveRisk || rawRule.authoring?.falsePositiveRisk || 'medium',
      },
      tests: {
        positive: rawRule.tests?.positive || [],
        negative: rawRule.tests?.negative || [],
        edgeCase: rawRule.tests?.edgeCase || [],
      },
    });
  });
}

async function buildExistingPackSummary(existingPackPath: string): Promise<string> {
  const raw = await fs.readFile(existingPackPath, 'utf-8');
  const parsed = JSON.parse(raw) as Record<string, any>;
  const rules = Array.isArray(parsed.rules) ? parsed.rules.length : 0;
  const principles = Array.isArray(parsed.principles) ? parsed.principles.length : 0;
  return `Existing pack has ${rules} rules and ${principles} principles. Version: ${parsed.version || 'unknown'}.`;
}

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}
