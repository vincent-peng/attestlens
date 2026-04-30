import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  APPInfo,
  JurisdictionPackManifest,
  RuleFreshness,
  RulePackManifest,
  appMappingToRegulationMapping,
  type Jurisdiction,
  type JurisdictionPackManifest as JurisdictionPackManifestType,
  type RuleFreshness as RuleFreshnessType,
  type RulePackManifest as RulePackManifestType,
  type RulePackSource,
} from '../../schema/index.js';
import { buildEmbeddedJurisdictionPack, buildEmbeddedRulePack } from './embedded.js';

export const RULE_PACK_CACHE_FILENAME = 'latest.json';
export const RULE_PACK_STALE_AFTER_DAYS = 14;
export const RULE_PACK_FETCH_TIMEOUT_MS = 10_000;
export const RULE_PACK_MAX_BYTES = 1_000_000;
export const AVAILABLE_JURISDICTIONS: readonly Jurisdiction[] = ['au-privacy-act'];

export interface LoadedRulePack {
  manifest: RulePackManifestType;
  jurisdictionManifest?: JurisdictionPackManifestType;
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
        jurisdictionManifest: buildJurisdictionManifestFromRulePack(loaded.manifest),
      });
      continue;
    }

    const manifest = buildUnavailableRulePack(jurisdiction, now);
    packs.set(jurisdiction, {
      manifest,
      jurisdictionManifest: buildUnavailableJurisdictionPack(jurisdiction, now),
      freshness: buildRuleFreshness(manifest, 'embedded', now),
      warnings: [getJurisdictionUnavailableMessage(jurisdiction)],
    });
  }

  return packs;
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

function buildJurisdictionManifestFromRulePack(manifest: RulePackManifestType): JurisdictionPackManifestType {
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

function buildUnavailableRulePack(jurisdiction: Jurisdiction, now: Date): RulePackManifestType {
  return RulePackManifest.parse({
    schemaVersion: '1.0',
    version: 'unavailable',
    generated: now.toISOString(),
    jurisdiction,
    rules: [],
  });
}

function buildUnavailableJurisdictionPack(jurisdiction: Jurisdiction, now: Date): JurisdictionPackManifestType {
  return JurisdictionPackManifest.parse({
    schemaVersion: '2.0',
    version: 'unavailable',
    jurisdiction,
    generated: now.toISOString(),
    principles: [],
    rules: [],
  });
}

export function getJurisdictionUnavailableMessage(jurisdiction: Jurisdiction): string {
  return `jurisdiction '${jurisdiction}' is not yet available. Available jurisdictions: ${AVAILABLE_JURISDICTIONS.join(', ')}`;
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
