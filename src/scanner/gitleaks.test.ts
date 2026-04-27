import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { GitleaksAdapter, type GitleaksRunner } from './gitleaks.js';

let cleanupDirs: string[] = [];

describe('GitleaksAdapter', () => {
  afterEach(async () => {
    await Promise.all(cleanupDirs.map(dir => fs.rm(dir, { recursive: true, force: true })));
    cleanupDirs = [];
  });

  it('reports unavailable when the gitleaks binary cannot be executed', async () => {
    const adapter = new GitleaksAdapter({
      path: '/definitely/not/gitleaks',
    });

    await expect(adapter.isAvailable()).resolves.toBe(false);
  });

  it('returns a recoverable skip for non-git repositories', async () => {
    const projectDir = await createProject({ git: false });
    const adapter = new GitleaksAdapter({ run: makeSarifRunner([]) });

    const result = await adapter.scan(projectDir);

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toContainEqual(expect.objectContaining({
      code: 'NOT_GIT_REPOSITORY',
      recoverable: true,
    }));
  });

  it('parses SARIF findings into redacted AttestLens findings', async () => {
    const projectDir = await createProject({ git: true });
    const secret = 'ghp_1234567890abcdefghijklmnopqrstuv';
    const adapter = new GitleaksAdapter({
      run: makeSarifRunner([{
        ruleId: 'github-pat',
        uri: 'src/token.ts',
        line: 3,
        message: `found GitHub token ${secret}`,
        snippet: `const token = "${secret}";`,
      }]),
    });

    const result = await adapter.scan(projectDir);

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      source: 'gitleaks',
      sourceRule: 'VS-GL-GITHUB-PAT',
      severity: 'high',
      category: 'Developer Credentials',
      code: '[redacted secret evidence]',
    });
    expect(JSON.stringify(result.findings)).not.toContain(secret);
  });

  it('treats a gitleaks findings exit as success when SARIF is produced', async () => {
    const projectDir = await createProject({ git: true });
    const runner = makeSarifRunner([{
      ruleId: 'aws-access-token',
      uri: 'config.js',
      line: 1,
      message: 'found AWS key',
      snippet: 'const key = "AKIA1234567890EXAMPLE";',
    }], { throwAfterWrite: true });
    const adapter = new GitleaksAdapter({ run: runner });

    const result = await adapter.scan(projectDir);

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].sourceRule).toBe('VS-GL-AWS-ACCESS-TOKEN');
  });
});

async function createProject(options: { git: boolean }): Promise<string> {
  const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-gitleaks-project-'));
  cleanupDirs.push(projectDir);
  if (options.git) {
    await fs.mkdir(path.join(projectDir, '.git'), { recursive: true });
  }
  await fs.mkdir(path.join(projectDir, 'src'), { recursive: true });
  await fs.writeFile(path.join(projectDir, 'src', 'token.ts'), 'export const token = process.env.TOKEN;');
  return projectDir;
}

function makeSarifRunner(results: Array<{
  ruleId: string;
  uri: string;
  line: number;
  message: string;
  snippet: string;
}>, options: { throwAfterWrite?: boolean } = {}): GitleaksRunner {
  return async (_binaryPath, args) => {
    if (args[0] === 'version') {
      return { stdout: 'gitleaks version test' };
    }

    const reportPath = args[args.indexOf('--report-path') + 1]!;
    await fs.writeFile(reportPath, JSON.stringify({
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'gitleaks',
            rules: results.map(result => ({
              id: result.ruleId,
              name: result.ruleId,
              shortDescription: { text: result.ruleId },
            })),
          },
        },
        results: results.map(result => ({
          ruleId: result.ruleId,
          message: { text: result.message },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: result.uri },
              region: {
                startLine: result.line,
                snippet: { text: result.snippet },
              },
            },
          }],
          partialFingerprints: {
            primaryLocationLineHash: `${result.ruleId}-${result.line}`,
          },
        })),
      }],
    }, null, 2));

    if (options.throwAfterWrite) {
      throw new Error('gitleaks detected leaks');
    }
    return { stdout: '' };
  };
}
