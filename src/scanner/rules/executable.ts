import type { RuleDefinition, RulePackManifest, Severity } from '../../schema/index.js';
import { buildEmbeddedRulePack } from './embedded.js';

const GUARDVIBE_STATIC_CATEGORY = 'guardvibe-static';
const GUARDVIBE_FINDING_CATEGORY = 'Security';

export interface ExecutableGuardVibeStaticRule {
  rule: string;
  regex: RegExp;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  fix: string;
}

export interface ExecutableGuardVibeStaticRuleSet {
  rules: ExecutableGuardVibeStaticRule[];
  warnings: string[];
}

export function getExecutableGuardVibeStaticRuleSet(
  activeRulePack?: RulePackManifest,
  options?: { allowCustomRules?: boolean },
): ExecutableGuardVibeStaticRuleSet {
  const embedded = buildEmbeddedRulePack();
  const embeddedDefinitions = getGuardVibeStaticDefinitions(embedded);
  const embeddedRules = compileDefinitions(embeddedDefinitions);

  if (!activeRulePack) {
    return { rules: embeddedRules, warnings: [] };
  }

  const activeResult = compileActiveDefinitions(activeRulePack, embeddedDefinitions, options);
  if (activeResult.warnings.length > 0) {
    return {
      rules: embeddedRules,
      warnings: activeResult.warnings,
    };
  }

  return {
    rules: activeResult.rules,
    warnings: [],
  };
}

export function getExecutableGuardVibeStaticRules(
  activeRulePack?: RulePackManifest,
): ExecutableGuardVibeStaticRule[] {
  return getExecutableGuardVibeStaticRuleSet(activeRulePack).rules;
}

function compileActiveDefinitions(
  activeManifest: RulePackManifest,
  embeddedDefinitions: RuleDefinition[],
  options?: { allowCustomRules?: boolean },
): ExecutableGuardVibeStaticRuleSet {
  const embeddedById = new Map(embeddedDefinitions.map((definition) => [definition.id, definition]));
  const activeDefinitions = activeManifest.rules
    .filter((definition) => definition.category === GUARDVIBE_STATIC_CATEGORY);
  const embeddedActiveDefinitions = activeDefinitions.filter((definition) => embeddedById.has(definition.id));
  const customDefinitions = activeDefinitions.filter((definition) => !embeddedById.has(definition.id));
  const activeById = new Map(embeddedActiveDefinitions.map((definition) => [definition.id, definition]));
  const warnings: string[] = [];

  if (embeddedActiveDefinitions.length === 0 && customDefinitions.length > 0) {
    if (!options?.allowCustomRules) {
      return { rules: [], warnings: ['Custom rules require allowCustomRules opt-in. Using embedded rules.'] };
    }
    return {
      rules: compileDefinitions(customDefinitions.filter((definition) => definition.enabled !== false)),
      warnings: [],
    };
  }

  for (const embeddedDefinition of embeddedDefinitions) {
    const activeDefinition = activeById.get(embeddedDefinition.id);
    if (!activeDefinition) {
      warnings.push(`Active rule pack is missing executable GuardVibe rule ${embeddedDefinition.id}.`);
      continue;
    }

    if (activeDefinition.enabled === false) {
      continue;
    }

    if (!activeDefinition.pattern) {
      warnings.push(`Active executable GuardVibe rule ${activeDefinition.id} is missing a regex pattern.`);
      continue;
    }

    if (activeDefinition.pattern !== embeddedDefinition.pattern || activeDefinition.flags !== embeddedDefinition.flags) {
      warnings.push(`Active executable GuardVibe rule ${activeDefinition.id} changed regex pattern or flags.`);
    }
  }

  if (warnings.length > 0) {
    return { rules: [], warnings };
  }

  return {
    rules: compileDefinitions(
      embeddedActiveDefinitions.filter((definition) => definition.enabled !== false),
    ),
    warnings: [],
  };
}

function compileDefinitions(ruleDefinitions: RuleDefinition[]): ExecutableGuardVibeStaticRule[] {
  const compiled: ExecutableGuardVibeStaticRule[] = [];
  for (const definition of ruleDefinitions) {
    if (!definition.pattern) {
      continue;
    }

    compiled.push({
      rule: definition.id,
      regex: new RegExp(definition.pattern, definition.flags),
      severity: definition.severity,
      category: GUARDVIBE_FINDING_CATEGORY,
      title: definition.title,
      description: definition.description,
      fix: definition.fixPrompt || '',
    });
  }

  return compiled;
}

function getGuardVibeStaticDefinitions(manifest: RulePackManifest): RuleDefinition[] {
  return manifest.rules.filter(isEnabledGuardVibeStaticDefinition);
}

function isEnabledGuardVibeStaticDefinition(definition: RuleDefinition): boolean {
  return definition.category === GUARDVIBE_STATIC_CATEGORY && definition.enabled !== false;
}
