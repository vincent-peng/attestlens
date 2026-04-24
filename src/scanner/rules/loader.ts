import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  RuleFreshness,
  RulePackManifest,
  type RuleFreshness as RuleFreshnessType,
  type RulePackManifest as RulePackManifestType,
  type RulePackSource,
} from '../../schema/index.js';
import { buildEmbeddedRulePack } from './embedded.js';

export const RULE_PACK_CACHE_FILENAME = 'latest.json';
export const RULE_PACK_STALE_AFTER_DAYS = 14;

export interface LoadedRulePack {
  manifest: RulePackManifestType;
  freshness: RuleFreshnessType;
  warnings: string[];
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
        freshness: buildRuleFreshness(cached, 'cache', now, cachePath),
        warnings,
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
    freshness: buildRuleFreshness(embedded, 'embedded', now),
    warnings,
  };
}

export async function updateRuleCache(options: RulePackUpdateOptions = {}): Promise<LoadedRulePack> {
  const cacheDir = options.cacheDir || getDefaultRuleCacheDir();
  const cachePath = getRulePackCachePath(cacheDir);
  const now = options.now || new Date();
  const manifest = options.source
    ? await loadRulePackFromSource(options.source, options.fetchImpl)
    : validateRulePackManifest(buildEmbeddedRulePack());

  await fs.mkdir(cacheDir, { recursive: true });
  await fs.writeFile(cachePath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf-8');

  return {
    manifest,
    freshness: buildRuleFreshness(manifest, options.source && isHttpsUrl(options.source) ? 'remote' : 'cache', now, cachePath),
    warnings: [],
  };
}

export async function refreshRulePackIfRequested(options: RulePackUpdateOptions & { autoUpdate?: boolean } = {}): Promise<LoadedRulePack> {
  if (options.autoUpdate) {
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
    const response = await fetchImpl(source);
    if (!response.ok) {
      throw new Error(`Rule pack fetch failed with HTTP ${response.status}`);
    }
    return validateRulePackManifest(await response.json());
  }

  if (source.startsWith('http://')) {
    throw new Error('Rule pack updates require HTTPS sources');
  }

  return readRulePackFromFile(path.resolve(source));
}

async function readRulePackFromFile(filePath: string): Promise<RulePackManifestType> {
  const raw = await fs.readFile(filePath, 'utf-8');
  return validateRulePackManifest(JSON.parse(raw));
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

  return manifest;
}

function buildRuleFreshness(
  manifest: RulePackManifestType,
  source: RulePackSource,
  now: Date,
  cachePath?: string,
): RuleFreshnessType {
  const generatedTime = new Date(manifest.generated).getTime();
  const ageDays = Math.max(0, Math.floor((now.getTime() - generatedTime) / 86_400_000));

  return RuleFreshness.parse({
    version: manifest.version,
    generated: manifest.generated,
    loadedAt: now.toISOString(),
    source,
    cachePath,
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
