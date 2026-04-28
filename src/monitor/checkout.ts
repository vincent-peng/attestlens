import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { hashRepoUrl, normalizeRepoUrl } from './baseline.js';
import type { CheckoutResult } from './types.js';

const execFileAsync = promisify(execFile);

export interface CheckoutOptions {
  cacheRoot?: string;
  tempRoot?: string;
  gitPath?: string;
}

export async function checkoutRepository(
  repoUrl: string,
  commitSha: string | undefined,
  options: CheckoutOptions = {},
): Promise<CheckoutResult> {
  const gitPath = options.gitPath || 'git';
  const cacheRoot = options.cacheRoot || getDefaultRepoCacheRoot();
  const tempRoot = options.tempRoot || os.tmpdir();
  const mirrorPath = path.join(cacheRoot, `${hashRepoUrl(repoUrl)}.git`);

  await ensureMirror(repoUrl, mirrorPath, gitPath);

  const checkoutRoot = await fs.mkdtemp(path.join(tempRoot, 'attestlens-checkout-'));
  try {
    await runGit(gitPath, ['clone', '--quiet', mirrorPath, checkoutRoot]);
    if (commitSha) {
      await runGit(gitPath, ['-C', checkoutRoot, 'checkout', '--quiet', commitSha]);
    }
  } catch (error) {
    await fs.rm(checkoutRoot, { recursive: true, force: true });
    throw error;
  }

  return {
    path: checkoutRoot,
    cleanup: async () => {
      await fs.rm(checkoutRoot, { recursive: true, force: true });
    },
  };
}

export function getDefaultRepoCacheRoot(): string {
  return path.join(os.homedir(), '.attestlens', 'repos');
}

async function ensureMirror(repoUrl: string, mirrorPath: string, gitPath: string): Promise<void> {
  await fs.mkdir(path.dirname(mirrorPath), { recursive: true });
  const exists = await pathExists(mirrorPath);

  if (!exists) {
    await runGit(gitPath, ['clone', '--mirror', '--quiet', normalizeRepoUrl(repoUrl), mirrorPath]);
    return;
  }

  await runGit(gitPath, ['-C', mirrorPath, 'remote', 'set-url', 'origin', normalizeRepoUrl(repoUrl)]);
  await runGit(gitPath, ['-C', mirrorPath, 'fetch', '--prune', '--quiet', 'origin']);
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function runGit(gitPath: string, args: string[]): Promise<void> {
  try {
    await execFileAsync(gitPath, args, { maxBuffer: 1024 * 1024 * 10 });
  } catch (error: any) {
    const stderr = typeof error?.stderr === 'string' ? error.stderr.trim() : '';
    const stdout = typeof error?.stdout === 'string' ? error.stdout.trim() : '';
    const detail = stderr || stdout || error?.message || 'unknown git error';
    throw new Error(`git ${args.join(' ')} failed: ${detail}`);
  }
}
