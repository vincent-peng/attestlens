import { execFile } from 'node:child_process';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { buildDiffContext, getChangedFiles, normalizeChangedFiles } from './diff.js';

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

const execFileMock = vi.mocked(execFile);

describe('git diff helpers', () => {
  beforeEach(() => {
    execFileMock.mockReset();
  });

  it('reads changed files with execFile args and normalizes output', async () => {
    execFileMock.mockImplementation((_command, args, _options, callback) => {
      const gitArgs = args as string[];
      if (gitArgs[0] === 'rev-parse') {
        callback!(null, gitArgs.includes('origin/main^{commit}') ? oid('1') : oid('2'), '');
      } else {
        callback!(null, 'src/api/users.ts\n./package.json\nsrc/api/users.ts\n\n', '');
      }
      return {} as ReturnType<typeof execFile>;
    });

    const files = await getChangedFiles('origin/main', 'HEAD', { cwd: '/repo' });

    expect(execFileMock).toHaveBeenCalledWith(
      'git',
      ['diff', '--name-only', '--relative', oid('1'), oid('2')],
      expect.objectContaining({ cwd: '/repo', timeout: 30000 }),
      expect.any(Function),
    );
    expect(files).toEqual(['package.json', 'src/api/users.ts']);
  });

  it('rejects option-looking refs before calling git', async () => {
    await expect(getChangedFiles('--output=/tmp/leak', 'HEAD', { cwd: '/repo' }))
      .rejects
      .toThrow('Unsupported git ref: --output=/tmp/leak');
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('fails invalid refs with a clear git diff error', async () => {
    execFileMock.mockImplementation((_command, _args, _options, callback) => {
      const error = new Error('git failed');
      callback!(error, '', 'fatal: ambiguous argument bad-ref');
      return {} as ReturnType<typeof execFile>;
    });

    await expect(getChangedFiles('bad-ref', 'HEAD', { cwd: '/repo' }))
      .rejects
      .toThrow('Unable to read git diff between bad-ref and HEAD: fatal: ambiguous argument bad-ref');
  });

  it('drops unsafe or empty changed paths', () => {
    expect(normalizeChangedFiles([
      '',
      './src/app.ts',
      '../outside.ts',
      '/absolute.ts',
      'src\\route.ts',
    ])).toEqual(['src/app.ts', 'src/route.ts']);
  });

  it('extracts simple dependency and route metadata from a diff', async () => {
    execFileMock.mockImplementation((_command, args, _options, callback) => {
      const gitArgs = args as string[];
      if (gitArgs[0] === 'rev-parse' && gitArgs.includes('origin/main^{commit}')) {
        callback!(null, oid('1'), '');
      } else if (gitArgs[0] === 'rev-parse' && gitArgs.includes('HEAD^{commit}')) {
        callback!(null, oid('2'), '');
      } else if (gitArgs[0] === 'diff') {
        callback!(null, [
          'package.json',
          'src/app/api/users/route.ts',
          'src/server.ts',
        ].join('\n'), '');
      } else if (gitArgs.join(' ') === 'rev-parse --show-prefix') {
        callback!(null, '', '');
      } else if (gitArgs[0] === 'show' && gitArgs[1] === `${oid('1')}:package.json`) {
        callback!(null, JSON.stringify({ dependencies: { '@old/pkg': '1.0.0' } }), '');
      } else if (gitArgs[0] === 'show' && gitArgs[1] === `${oid('2')}:package.json`) {
        callback!(null, JSON.stringify({ dependencies: { '@old/pkg': '1.0.0', zod: '^3.0.0' } }), '');
      } else if (gitArgs[0] === 'show' && gitArgs[1] === `${oid('2')}:src/app/api/users/route.ts`) {
        callback!(null, 'export async function POST() {}', '');
      } else if (gitArgs[0] === 'show' && gitArgs[1] === `${oid('2')}:src/server.ts`) {
        callback!(null, 'app.post("/api/profile", handler);', '');
      } else {
        callback!(new Error(`unexpected git args: ${gitArgs.join(' ')}`), '', 'unexpected git args');
      }
      return {} as ReturnType<typeof execFile>;
    });

    const context = await buildDiffContext({
      cwd: '/repo',
      baseRef: 'origin/main',
      headRef: 'HEAD',
    });

    expect(context.changedFiles).toEqual([
      'package.json',
      'src/app/api/users/route.ts',
      'src/server.ts',
    ]);
    expect(context.addedDependencies).toEqual(['zod']);
    expect(context.addedRoutes).toEqual(['/api/users', 'POST /api/profile']);
  });

  it('does not infer added dependency metadata from caller-supplied files without refs', async () => {
    const context = await buildDiffContext({
      cwd: '/repo',
      changedFiles: ['package.json'],
    });

    expect(execFileMock).not.toHaveBeenCalled();
    expect(context.addedDependencies).toEqual([]);
    expect(context.addedRoutes).toEqual([]);
  });
});

function oid(digit: string): string {
  return digit.repeat(40);
}
