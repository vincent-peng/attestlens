import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildEmbeddedRulePack } from './embedded.js';
import {
  RULE_PACK_FETCH_TIMEOUT_MS,
  RULE_PACK_MAX_BYTES,
  getRulePackCachePath,
  loadRulePack,
  updateRuleCache,
} from './loader.js';

describe('rule pack loader', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    vi.useRealTimers();
    await Promise.all(tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
    tempDirs.length = 0;
  });

  async function makeTempDir(): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-rules-'));
    tempDirs.push(dir);
    return dir;
  }

  function makeRulePack(version = '2026.04.25') {
    return {
      ...buildEmbeddedRulePack(),
      version,
      generated: '2026-04-25T00:00:00.000Z',
    };
  }

  it('loads the embedded rule pack deterministically when no cache exists', async () => {
    const cacheDir = await makeTempDir();
    const first = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });
    const second = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });

    expect(first.freshness.source).toBe('embedded');
    expect(first.freshness.stale).toBe(false);
    expect(first.freshness.ruleCount).toBeGreaterThanOrEqual(40);
    expect(first.manifest).toEqual(second.manifest);
  });

  it('uses a valid cached rule pack over the embedded pack', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const sourcePath = path.join(sourceDir, 'rules.json');
    const cachedPack = makeRulePack();
    await fs.writeFile(sourcePath, JSON.stringify(cachedPack, null, 2));

    const updated = await updateRuleCache({
      source: sourcePath,
      cacheDir,
      now: new Date('2026-04-25T01:00:00.000Z'),
    });
    const loaded = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-25T01:00:00.000Z'),
    });

    expect(updated.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect(loaded.freshness.source).toBe('cache');
    expect(loaded.freshness.version).toBe('2026.04.25');
  });

  it('preserves an existing cache when update-rules has no source', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const sourcePath = path.join(sourceDir, 'rules.json');
    await fs.writeFile(sourcePath, JSON.stringify(makeRulePack('2026.04.25'), null, 2));
    await updateRuleCache({ source: sourcePath, cacheDir });

    const updated = await updateRuleCache({
      cacheDir,
      now: new Date('2026-04-25T01:00:00.000Z'),
    });
    const cached = JSON.parse(await fs.readFile(getRulePackCachePath(cacheDir), 'utf-8'));

    expect(updated.freshness.version).toBe('2026.04.25');
    expect(updated.freshness.source).toBe('cache');
    expect(cached.version).toBe('2026.04.25');
  });

  it('seeds embedded rules only when the cache is missing', async () => {
    const cacheDir = await makeTempDir();

    const updated = await updateRuleCache({
      cacheDir,
      now: new Date('2026-04-24T01:00:00.000Z'),
    });
    const cached = JSON.parse(await fs.readFile(getRulePackCachePath(cacheDir), 'utf-8'));

    expect(updated.freshness.version).toBe(buildEmbeddedRulePack().version);
    expect(updated.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect(cached.version).toBe(buildEmbeddedRulePack().version);
  });

  it('falls back to embedded rules when the cache is corrupt', async () => {
    const cacheDir = await makeTempDir();
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.writeFile(getRulePackCachePath(cacheDir), '{not-json');

    const loaded = await loadRulePack({
      cacheDir,
      now: new Date('2026-04-24T00:00:00.000Z'),
    });

    expect(loaded.freshness.source).toBe('embedded');
    expect(loaded.warnings[0]).toContain('Cached rule pack ignored');
  });

  it('does not include local cache paths in public freshness metadata', async () => {
    const cacheDir = await makeTempDir();

    const loaded = await updateRuleCache({ cacheDir });

    expect(loaded.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect('cachePath' in loaded.freshness).toBe(false);
  });

  it('rejects oversized local rule pack sources before parsing', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const sourcePath = path.join(sourceDir, 'rules.json');
    await fs.writeFile(sourcePath, 'x'.repeat(RULE_PACK_MAX_BYTES + 1));

    await expect(updateRuleCache({ source: sourcePath, cacheDir })).rejects.toThrow(/too large/);
    await expect(fs.stat(getRulePackCachePath(cacheDir))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects oversized remote rule pack sources before parsing', async () => {
    const cacheDir = await makeTempDir();
    const fetchImpl = vi.fn(async () => new Response('{}', {
      headers: {
        'content-length': String(RULE_PACK_MAX_BYTES + 1),
      },
    }));

    await expect(updateRuleCache({
      source: 'https://example.com/rules.json',
      cacheDir,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })).rejects.toThrow(/too large/);
    await expect(fs.stat(getRulePackCachePath(cacheDir))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('times out remote rule pack fetches', async () => {
    vi.useFakeTimers();
    const cacheDir = await makeTempDir();
    const fetchImpl = vi.fn((_source: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => {
        reject(new DOMException('Aborted', 'AbortError'));
      });
    }));

    const updatePromise = updateRuleCache({
      source: 'https://example.com/rules.json',
      cacheDir,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const rejection = expect(updatePromise).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(RULE_PACK_FETCH_TIMEOUT_MS);

    await rejection;
  });

  it('rejects malformed, duplicate, and non-HTTPS rule pack sources before caching', async () => {
    const cacheDir = await makeTempDir();
    const sourceDir = await makeTempDir();
    const malformedPath = path.join(sourceDir, 'malformed.json');
    const duplicatePath = path.join(sourceDir, 'duplicate.json');
    const duplicatePack = makeRulePack();
    duplicatePack.rules = [duplicatePack.rules[0]!, duplicatePack.rules[0]!];
    await fs.writeFile(malformedPath, '{not-json');
    await fs.writeFile(duplicatePath, JSON.stringify(duplicatePack, null, 2));

    await expect(updateRuleCache({ source: 'http://example.com/rules.json', cacheDir })).rejects.toThrow(/HTTPS/);
    await expect(updateRuleCache({ source: malformedPath, cacheDir })).rejects.toThrow(/Invalid rule pack manifest/);
    await expect(updateRuleCache({ source: duplicatePath, cacheDir })).rejects.toThrow(/Duplicate rule id/);
    await expect(fs.stat(getRulePackCachePath(cacheDir))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('covers active hardcoded scanner rule ids in the embedded manifest', () => {
    const activeHardcodedRuleIds = [
      'AL-URL-013',
      'AL-URL-014',
      'AL-URL-015',
      'VS-SUPA-RLS-MISSING',
      'VS-FB-SERVICE-ACCOUNT',
      'VS-PUBLIC-SECRET-ENV',
      'VS-PLATFORM-SECRET',
    ];
    const embeddedRuleIds = new Set(buildEmbeddedRulePack().rules.map((rule) => rule.id));

    for (const ruleId of activeHardcodedRuleIds) {
      expect(embeddedRuleIds.has(ruleId), `${ruleId} is missing from embedded rules`).toBe(true);
    }
  });
});
