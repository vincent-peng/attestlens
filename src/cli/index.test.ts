import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const tsxBin = path.join(repoRoot, 'node_modules', '.bin', 'tsx');
const cliEntry = path.join(repoRoot, 'src', 'cli', 'index.ts');

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(tsxBin, [cliEntry, ...args], { cwd: repoRoot });
    return { code: 0, stdout, stderr };
  } catch (error: any) {
    return {
      code: error.code ?? 1,
      stdout: error.stdout ?? '',
      stderr: error.stderr ?? '',
    };
  }
}

describe('CLI URL handling', () => {
  it('fails URL scans when the target is blocked or unreachable', async () => {
    const result = await runCli(['scan', 'http://localhost:3000']);
    const output = `${result.stdout}\n${result.stderr}`;

    expect(result.code).toBe(1);
    expect(output).toContain('URL target is not allowed for scanning.');
    expect(output).not.toContain('No compliance findings detected.');
  });

  it('fails URL audits before writing a clean report when the scan does not complete', async () => {
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-audit-'));

    try {
      const result = await runCli(['audit', 'http://localhost:3000', '-n', 'Localhost', '-f', 'json', '-o', outputDir]);
      const output = `${result.stdout}\n${result.stderr}`;
      const files = await fs.readdir(outputDir);

      expect(result.code).toBe(1);
      expect(output).toContain('URL target is not allowed for scanning.');
      expect(files).toHaveLength(0);
    } finally {
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('regenerates reports from saved URL scan payloads using the original target URL', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-cli-report-'));
    const inputPath = path.join(tempDir, 'url-scan.json');
    const outputDir = path.join(tempDir, 'out');

    try {
      await fs.writeFile(inputPath, JSON.stringify({
        targetType: 'url',
        targetUrl: 'https://example.com/?token=secret#frag',
        findings: [],
      }, null, 2));

      const result = await runCli(['report', inputPath, '-f', 'markdown', '-o', outputDir]);
      expect(result.code).toBe(0);

      const files = await fs.readdir(outputDir);
      expect(files).toHaveLength(1);

      const reportPath = path.join(outputDir, files[0]!);
      const markdown = await fs.readFile(reportPath, 'utf-8');
      expect(markdown).toContain('**Target URL:** https://example.com/');
      expect(markdown).not.toContain('**Target Path:**');
      expect(markdown).toContain('# Privacy Act Compliance Report — example.com');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});
