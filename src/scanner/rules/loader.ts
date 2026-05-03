import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  APPInfo,
  JurisdictionPackManifest,
  RuleFreshness,
  RulePackManifest,
  ValidatedPackManifest,
  appMappingToRegulationMapping,
  type Jurisdiction,
  type AuthoredRule as AuthoredRuleType,
  type JurisdictionPackManifest as JurisdictionPackManifestType,
  type RuleFreshness as RuleFreshnessType,
  type RulePackManifest as RulePackManifestType,
  type RulePackSource,
  type ValidatedPackManifest as ValidatedPackManifestType,
} from '../../schema/index.js';
import { CCPAPrincipleInfo } from './ccpa-principles.js';
import { GDPRPrincipleInfo } from './gdpr-principles.js';
import {
  buildEmbeddedCCPARulePack,
  buildEmbeddedGDPRRulePack,
  buildEmbeddedJurisdictionPack,
  buildEmbeddedRulePack,
  buildEmbeddedSGPDPARulePack,
} from './embedded.js';

export const RULE_PACK_CACHE_FILENAME = 'latest.json';
export const JURISDICTION_PACK_CACHE_DIRNAME = 'jurisdictions';
export const VALIDATED_JURISDICTION_PACK_FILENAME = 'latest.json';
export const VALIDATED_JURISDICTION_RUNTIME_PACK_FILENAME = 'latest.runtime.json';
export const RULE_PACK_STALE_AFTER_DAYS = 14;
export const RULE_PACK_FETCH_TIMEOUT_MS = 10_000;
export const RULE_PACK_MAX_BYTES = 1_000_000;
export const AVAILABLE_JURISDICTIONS: readonly Jurisdiction[] = ['au-privacy-act', 'us-ccpa', 'eu-gdpr', 'sg-pdpa'];

export interface LoadedRulePack {
  manifest: RulePackManifestType;
  jurisdictionManifest?: JurisdictionPackManifestType | ValidatedPackManifestType;
  validatedManifest?: ValidatedPackManifestType;
  authoredRulesById?: Map<string, AuthoredRuleType>;
  freshness: RuleFreshnessType;
  warnings: string[];
  cachePath?: string;
}

export interface RulePackLoadOptions {
  cacheDir?: string;
  allowCache?: boolean;
  now?: Date;
}

export interface RulePackUpdateOptions {
  source?: string;
  cacheDir?: string;
  now?: Date;
  fetchImpl?: typeof fetch;
}

export function getDefaultRuleCacheDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.ATTESTLENS_RULE_CACHE_DIR) {
    return path.resolve(env.ATTESTLENS_RULE_CACHE_DIR);
  }

  if (env.XDG_CACHE_HOME) {
    return path.join(env.XDG_CACHE_HOME, 'attestlens', 'rules');
  }

  return path.join(os.homedir(), '.attestlens', 'rules');
}

export function getRulePackCachePath(cacheDir = getDefaultRuleCacheDir()): string {
  return path.join(cacheDir, RULE_PACK_CACHE_FILENAME);
}

export function getJurisdictionRuleCacheDir(
  jurisdiction: Jurisdiction,
  cacheDir = getDefaultRuleCacheDir(),
): string {
  return path.join(cacheDir, jurisdiction);
}

export function getDefaultJurisdictionPackDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.ATTESTLENS_JURISDICTION_PACK_DIR) {
    return path.resolve(env.ATTESTLENS_JURISDICTION_PACK_DIR);
  }

  return path.join(os.homedir(), '.attestlens', JURISDICTION_PACK_CACHE_DIRNAME);
}

export function getValidatedJurisdictionPackDir(
  jurisdiction: Jurisdiction,
  baseDir = getDefaultJurisdictionPackDir(),
): string {
  return path.join(baseDir, jurisdiction);
}

export function getValidatedJurisdictionPackPath(
  jurisdiction: Jurisdiction,
  baseDir = getDefaultJurisdictionPackDir(),
): string {
  return path.join(getValidatedJurisdictionPackDir(jurisdiction, baseDir), VALIDATED_JURISDICTION_PACK_FILENAME);
}

export function getValidatedJurisdictionRuntimePackPath(
  jurisdiction: Jurisdiction,
  baseDir = getDefaultJurisdictionPackDir(),
): string {
  return path.join(getValidatedJurisdictionPackDir(jurisdiction, baseDir), VALIDATED_JURISDICTION_RUNTIME_PACK_FILENAME);
}

export async function loadRulePack(options: RulePackLoadOptions = {}): Promise<LoadedRulePack> {
  const cacheDir = options.cacheDir || getDefaultRuleCacheDir();
  const cachePath = getRulePackCachePath(cacheDir);
  const now = options.now || new Date();
  const warnings: string[] = [];

  if (options.allowCache !== false) {
    try {
    const cached = await readRulePackFromFile(cachePath);
      return {
        manifest: cached,
        jurisdictionManifest: buildJurisdictionManifestFromRulePack(cached),
        freshness: buildRuleFreshness(cached, 'cache', now),
        warnings,
        cachePath,
      };
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        warnings.push(`Cached rule pack ignored: ${error.message}`);
      }
    }
  }

  const embedded = validateRulePackManifest(buildEmbeddedRulePack());
  return {
    manifest: embedded,
    jurisdictionManifest: buildEmbeddedJurisdictionPack(),
    freshness: buildRuleFreshness(embedded, 'embedded', now),
    warnings,
  };
}

export async function loadJurisdictionPacks(
  jurisdictions: Jurisdiction[],
  options: RulePackLoadOptions = {},
): Promise<Map<Jurisdiction, LoadedRulePack>> {
  const packs = new Map<Jurisdiction, LoadedRulePack>();
  const uniqueJurisdictions = Array.from(new Set(jurisdictions));
  const now = options.now || new Date();

  for (const jurisdiction of uniqueJurisdictions) {
    if (jurisdiction === 'au-privacy-act') {
      const loaded = await loadRulePack(options);
      packs.set(jurisdiction, {
        ...loaded,
        jurisdictionManifest: loaded.jurisdictionManifest ?? buildJurisdictionManifestFromRulePack(loaded.manifest),
      });
      continue;
    }

    if (jurisdiction === 'us-ccpa') {
      packs.set(jurisdiction, await loadValidatedJurisdictionPack(jurisdiction, options));
      continue;
    }

    if (jurisdiction === 'eu-gdpr') {
      packs.set(jurisdiction, await loadValidatedJurisdictionPack(jurisdiction, options));
      continue;
    }

    if (jurisdiction === 'sg-pdpa') {
      packs.set(jurisdiction, await loadValidatedJurisdictionPack(jurisdiction, options));
    }
  }

  return packs;
}

export async function loadValidatedJurisdictionPack(
  jurisdiction: Jurisdiction,
  options: RulePackLoadOptions = {},
): Promise<LoadedRulePack> {
  const now = options.now || new Date();
  const warnings: string[] = [];
  const embedded = getEmbeddedJurisdictionRulePack(jurisdiction);
  const jurisdictionManifest = buildEmbeddedJurisdictionPack(jurisdiction);
  const baseDir = getDefaultJurisdictionPackDir();
  const runtimePath = getValidatedJurisdictionRuntimePackPath(jurisdiction, baseDir);
  const validatedPath = getValidatedJurisdictionPackPath(jurisdiction, baseDir);

  let runtimeManifest: RulePackManifestType | undefined;
  let validatedManifest: ValidatedPackManifestType | undefined;

  try {
    runtimeManifest = await readRulePackFromFile(runtimePath);
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      warnings.push(`Validated runtime pack ignored for ${jurisdiction}: ${error.message}`);
    }
  }

  try {
    validatedManifest = await readValidatedPackFromFile(validatedPath);
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      warnings.push(`Validated pack manifest ignored for ${jurisdiction}: ${error.message}`);
    }
  }

  if (runtimeManifest && !validatedManifest) {
    warnings.push(
      `Validated runtime pack ignored for ${jurisdiction}: matching validated manifest unavailable. Using embedded rules.`,
    );
    runtimeManifest = undefined;
  }

  if (runtimeManifest && validatedManifest) {
    const consistencyError = getValidatedRuntimeConsistencyError(jurisdiction, runtimeManifest, validatedManifest);
    if (consistencyError) {
      warnings.push(
        `Validated runtime pack ignored for ${jurisdiction}: ${consistencyError}. Using embedded rules.`,
      );
      runtimeManifest = undefined;
      validatedManifest = undefined;
    }
  }

  if (runtimeManifest && comparePackVersions(runtimeManifest.version, embedded.version) < 0) {
    warnings.push(
      `Validated runtime pack for ${jurisdiction} is older than embedded (${runtimeManifest.version} < ${embedded.version}). Using embedded rules.`,
    );
    runtimeManifest = undefined;
    validatedManifest = undefined;
  }

  if (!runtimeManifest) {
    return {
      manifest: embedded,
      jurisdictionManifest,
      freshness: buildRuleFreshness(embedded, 'embedded', now),
      warnings,
    };
  }

  const authoredRulesById = new Map<string, AuthoredRuleType>();
  const aiDraftRuleIds = new Set<string>();
  if (validatedManifest) {
    for (const rule of validatedManifest.rules) {
      if (rule.authoring.author === 'ai-draft') {
        aiDraftRuleIds.add(rule.id);
        warnings.push(`Skipping AI-draft rule ${rule.id} from validated manifest for ${jurisdiction}.`);
        continue;
      }
      authoredRulesById.set(rule.id, rule);
    }
  }

  const filteredRuntimeRules = runtimeManifest.rules.filter((rule) => {
    if (aiDraftRuleIds.has(rule.id)) {
      warnings.push(`Skipping AI-draft rule ${rule.id} from validated runtime pack for ${jurisdiction}.`);
      return false;
    }
    const authoredRule = authoredRulesById.get(rule.id);
    if (authoredRule?.authoring.author === 'ai-draft') {
      warnings.push(`Skipping AI-draft rule ${rule.id} from validated runtime pack for ${jurisdiction}.`);
      return false;
    }
    return true;
  });

  const manifest = validateRulePackManifest({
    ...runtimeManifest,
    rules: filteredRuntimeRules,
  });

  return {
    manifest,
    jurisdictionManifest: validatedManifest || jurisdictionManifest,
    validatedManifest,
    authoredRulesById,
    freshness: buildRuleFreshness(manifest, 'cache', now),
    warnings,
  };
}

export async function updateRuleCache(options: RulePackUpdateOptions = {}): Promise<LoadedRulePack> {
  const cacheDir = options.cacheDir || getDefaultRuleCacheDir();
  const cachePath = getRulePackCachePath(cacheDir);
  const now = options.now || new Date();
  const source = options.source?.trim();

  if (!source) {
    try {
      const cached = await readRulePackFromFile(cachePath);
      return {
        manifest: cached,
        jurisdictionManifest: buildJurisdictionManifestFromRulePack(cached),
        freshness: buildRuleFreshness(cached, 'cache', now),
        warnings: [],
        cachePath,
      };
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        throw new Error(`Cached rule pack is invalid: ${error.message}`);
      }
    }

    const embedded = validateRulePackManifest(buildEmbeddedRulePack());
    await writeRulePackCache(cacheDir, cachePath, embedded);

    return {
      manifest: embedded,
      jurisdictionManifest: buildJurisdictionManifestFromRulePack(embedded),
      freshness: buildRuleFreshness(embedded, 'cache', now),
      warnings: [],
      cachePath,
    };
  }

  const manifest = await loadRulePackFromSource(source, options.fetchImpl);

  await writeRulePackCache(cacheDir, cachePath, manifest);

  return {
    manifest,
    jurisdictionManifest: buildJurisdictionManifestFromRulePack(manifest),
    freshness: buildRuleFreshness(manifest, isHttpsUrl(source) ? 'remote' : 'cache', now),
    warnings: [],
    cachePath,
  };
}

export async function refreshRulePackIfRequested(options: RulePackUpdateOptions & { autoUpdate?: boolean } = {}): Promise<LoadedRulePack> {
  if (options.autoUpdate && options.source?.trim()) {
    try {
      return await updateRuleCache(options);
    } catch {
      // Fall through to the normal loader. The caller can still proceed with
      // embedded or previously cached rules without making scans network-dependent.
    }
  }

  return loadRulePack(options);
}

async function loadRulePackFromSource(source: string, fetchImpl: typeof fetch = fetch): Promise<RulePackManifestType> {
  if (isHttpsUrl(source)) {
    return fetchRulePackFromHttps(source, fetchImpl);
  }

  if (source.startsWith('http://')) {
    throw new Error('Rule pack updates require HTTPS sources');
  }

  return readRulePackFromFile(path.resolve(source));
}

async function readRulePackFromFile(filePath: string): Promise<RulePackManifestType> {
  const stat = await fs.stat(filePath);
  if (stat.size > RULE_PACK_MAX_BYTES) {
    throw new Error(`Rule pack source is too large (${stat.size} bytes, max ${RULE_PACK_MAX_BYTES})`);
  }
  const raw = await fs.readFile(filePath, 'utf-8');
  return parseRulePackJson(raw, filePath);
}

async function readValidatedPackFromFile(filePath: string): Promise<ValidatedPackManifestType> {
  const stat = await fs.stat(filePath);
  if (stat.size > RULE_PACK_MAX_BYTES) {
    throw new Error(`Rule pack source is too large (${stat.size} bytes, max ${RULE_PACK_MAX_BYTES})`);
  }
  const raw = await fs.readFile(filePath, 'utf-8');
  return parseValidatedPackJson(raw, filePath);
}

async function fetchRulePackFromHttps(source: string, fetchImpl: typeof fetch): Promise<RulePackManifestType> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), RULE_PACK_FETCH_TIMEOUT_MS);

  try {
    const response = await fetchImpl(source, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`Rule pack fetch failed with HTTP ${response.status}`);
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && Number(contentLength) > RULE_PACK_MAX_BYTES) {
      throw new Error(`Rule pack source is too large (${contentLength} bytes, max ${RULE_PACK_MAX_BYTES})`);
    }

    const raw = await readResponseTextWithLimit(response, RULE_PACK_MAX_BYTES);
    return parseRulePackJson(raw, source);
  } catch (error: any) {
    if (error.name === 'AbortError') {
      throw new Error(`Rule pack fetch timed out after ${RULE_PACK_FETCH_TIMEOUT_MS}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function readResponseTextWithLimit(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf-8') > maxBytes) {
      throw new Error(`Rule pack source is too large (max ${maxBytes} bytes)`);
    }
    return text;
  }

  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new Error(`Rule pack source is too large (max ${maxBytes} bytes)`);
      }

      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }

  return text + decoder.decode();
}

function parseRulePackJson(raw: string, sourceLabel: string): RulePackManifestType {
  try {
    return validateRulePackManifest(JSON.parse(raw));
  } catch (error: any) {
    throw new Error(`Invalid rule pack manifest from ${sourceLabel}: ${error.message}`);
  }
}

function parseValidatedPackJson(raw: string, sourceLabel: string): ValidatedPackManifestType {
  try {
    return validateValidatedPackManifest(JSON.parse(raw));
  } catch (error: any) {
    throw new Error(`Invalid validated pack manifest from ${sourceLabel}: ${error.message}`);
  }
}

async function writeRulePackCache(cacheDir: string, cachePath: string, manifest: RulePackManifestType): Promise<void> {
  await fs.mkdir(cacheDir, { recursive: true });
  await fs.writeFile(cachePath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf-8');
}

function validateRulePackManifest(raw: unknown): RulePackManifestType {
  const manifest = RulePackManifest.parse(raw);
  const seen = new Set<string>();

  for (const rule of manifest.rules) {
    if (seen.has(rule.id)) {
      throw new Error(`Duplicate rule id in rule pack: ${rule.id}`);
    }
    seen.add(rule.id);
  }

  return {
    ...manifest,
    rules: manifest.rules.map((rule) => ({
      ...rule,
      regulationMappings: rule.regulationMappings && rule.regulationMappings.length > 0
        ? rule.regulationMappings
        : rule.appMappings.map(appMappingToRegulationMapping),
    })),
  };
}

function validateValidatedPackManifest(raw: unknown): ValidatedPackManifestType {
  const manifest = ValidatedPackManifest.parse(raw);
  const seen = new Set<string>();

  for (const rule of manifest.rules) {
    if (seen.has(rule.id)) {
      throw new Error(`Duplicate rule id in validated pack: ${rule.id}`);
    }
    seen.add(rule.id);
  }

  return manifest;
}

function getEmbeddedJurisdictionRulePack(jurisdiction: Jurisdiction): RulePackManifestType {
  if (jurisdiction === 'us-ccpa') {
    return validateRulePackManifest(buildEmbeddedCCPARulePack());
  }
  if (jurisdiction === 'eu-gdpr') {
    return validateRulePackManifest(buildEmbeddedGDPRRulePack());
  }
  if (jurisdiction === 'sg-pdpa') {
    return validateRulePackManifest(buildEmbeddedSGPDPARulePack());
  }
  return validateRulePackManifest(buildEmbeddedRulePack());
}

function getValidatedRuntimeConsistencyError(
  expectedJurisdiction: Jurisdiction,
  runtimeManifest: RulePackManifestType,
  validatedManifest: ValidatedPackManifestType,
): string | null {
  if (runtimeManifest.jurisdiction !== expectedJurisdiction || validatedManifest.jurisdiction !== expectedJurisdiction) {
    return `jurisdiction mismatch between validated artifacts and requested jurisdiction (${validatedManifest.jurisdiction} / ${runtimeManifest.jurisdiction} !== ${expectedJurisdiction})`;
  }

  if (runtimeManifest.jurisdiction !== validatedManifest.jurisdiction) {
    return `jurisdiction mismatch between validated manifest and runtime pack (${validatedManifest.jurisdiction} !== ${runtimeManifest.jurisdiction})`;
  }

  if (!isNumericDotVersion(runtimeManifest.version) || !isNumericDotVersion(validatedManifest.version)) {
    return `invalid version format in validated artifacts (${validatedManifest.version} / ${runtimeManifest.version})`;
  }

  if (runtimeManifest.version !== validatedManifest.version) {
    return `version mismatch between validated manifest and runtime pack (${validatedManifest.version} !== ${runtimeManifest.version})`;
  }

  const validatedRuleIds = new Set(validatedManifest.rules.map((rule) => rule.id));
  for (const rule of runtimeManifest.rules) {
    if (!validatedRuleIds.has(rule.id)) {
      return `runtime pack contains rule ${rule.id} that is not present in the validated manifest`;
    }
  }

  return null;
}

function comparePackVersions(left: string, right: string): number {
  const leftParts = parseNumericDotVersion(left);
  const rightParts = parseNumericDotVersion(right);

  if (!leftParts || !rightParts) {
    return 0;
  }

  const length = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < length; index += 1) {
    const delta = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (delta !== 0) {
      return delta;
    }
  }

  return 0;
}

function isNumericDotVersion(version: string): boolean {
  return parseNumericDotVersion(version) !== undefined;
}

function parseNumericDotVersion(version: string): number[] | undefined {
  if (!/^\d+(?:\.\d+)*$/.test(version)) {
    return undefined;
  }

  const parts = version.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.some((part) => Number.isNaN(part))) {
    return undefined;
  }

  return parts;
}

function buildJurisdictionManifestFromRulePack(manifest: RulePackManifestType): JurisdictionPackManifestType {
  if (manifest.jurisdiction === 'us-ccpa') {
    return JurisdictionPackManifest.parse({
      schemaVersion: '2.0',
      version: manifest.version,
      jurisdiction: 'us-ccpa',
      generated: manifest.generated,
      principles: Object.entries(CCPAPrincipleInfo).map(([id, info]) => ({
        id,
        shortName: info.shortName,
        obligation: info.obligation,
        citation: info.citation,
      })),
      rules: manifest.rules,
    });
  }

  if (manifest.jurisdiction === 'eu-gdpr') {
    return JurisdictionPackManifest.parse({
      schemaVersion: '2.0',
      version: manifest.version,
      jurisdiction: 'eu-gdpr',
      generated: manifest.generated,
      principles: Object.entries(GDPRPrincipleInfo).map(([id, info]) => ({
        id,
        shortName: info.shortName,
        obligation: info.obligation,
        citation: info.citation,
      })),
      rules: manifest.rules,
    });
  }

  if (manifest.jurisdiction !== 'au-privacy-act') {
    return JurisdictionPackManifest.parse({
      schemaVersion: '2.0',
      version: manifest.version,
      jurisdiction: manifest.jurisdiction,
      generated: manifest.generated,
      principles: [],
      rules: manifest.rules,
    });
  }

  return JurisdictionPackManifest.parse({
    schemaVersion: '2.0',
    version: manifest.version,
    jurisdiction: 'au-privacy-act',
    generated: manifest.generated,
    principles: Object.entries(APPInfo).map(([id, info]) => ({
      id,
      shortName: info.shortName,
      obligation: info.obligation,
    })),
    rules: manifest.rules,
  });
}

export function getJurisdictionUnavailableMessage(jurisdiction: Jurisdiction): string {
  return `No embedded rule pack loaded for requested jurisdiction '${jurisdiction}'. Available jurisdictions: ${AVAILABLE_JURISDICTIONS.join(', ')}`;
}

function buildRuleFreshness(
  manifest: RulePackManifestType,
  source: RulePackSource,
  now: Date,
): RuleFreshnessType {
  const generatedTime = new Date(manifest.generated).getTime();
  const ageDays = Math.max(0, Math.floor((now.getTime() - generatedTime) / 86_400_000));

  return RuleFreshness.parse({
    version: manifest.version,
    generated: manifest.generated,
    loadedAt: now.toISOString(),
    source,
    ruleCount: manifest.rules.filter((rule) => rule.enabled !== false).length,
    ageDays,
    stale: ageDays > RULE_PACK_STALE_AFTER_DAYS,
  });
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}
