import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkoutRepository } from './checkout.js';

const execFileAsync = promisify(execFile);

describe('checkoutRepository', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-checkout-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('clones a cached repo mirror, checks out a commit, and cleans up', async () => {
    const repoPath = path.join(tempDir, 'source');
    await fs.mkdir(repoPath);
    await git(['-C', repoPath, 'init', '--initial-branch=main']);
    await fs.writeFile(path.join(repoPath, 'README.md'), 'first\n', 'utf-8');
    await git(['-C', repoPath, 'add', 'README.md']);
    await git(['-C', repoPath, '-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-m', 'first']);
    const firstSha = await gitOutput(['-C', repoPath, 'rev-parse', 'HEAD']);
    await fs.writeFile(path.join(repoPath, 'README.md'), 'second\n', 'utf-8');
    await git(['-C', repoPath, 'add', 'README.md']);
    await git(['-C', repoPath, '-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-m', 'second']);

    const checkout = await checkoutRepository(repoPath, firstSha, {
      cacheRoot: path.join(tempDir, 'cache'),
      tempRoot: tempDir,
    });

    expect(await fs.readFile(path.join(checkout.path, 'README.md'), 'utf-8')).toBe('first\n');
    await checkout.cleanup();
    await expect(fs.access(checkout.path)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

async function git(args: string[]): Promise<void> {
  await execFileAsync('git', args);
}

async function gitOutput(args: string[]): Promise<string> {
  const { stdout } = await execFileAsync('git', args);
  return stdout.trim();
}
