import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { buildEmbeddedRulePack } from './embedded.js';
import {
  getRulePackCachePath,
  loadRulePack,
  updateRuleCache,
} from './loader.js';

describe('rule pack loader', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(tempDirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
    tempDirs.length = 0;
  });

  async function makeTempDir(): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-rules-'));
    tempDirs.push(dir);
    return dir;
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
    const cachedPack = {
      ...buildEmbeddedRulePack(),
      version: '2026.04.25',
      generated: '2026-04-25T00:00:00.000Z',
    };
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

    expect(updated.freshness.cachePath).toBe(getRulePackCachePath(cacheDir));
    expect(loaded.freshness.source).toBe('cache');
    expect(loaded.freshness.version).toBe('2026.04.25');
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
});
