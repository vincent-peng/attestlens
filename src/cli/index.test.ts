import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { describe, expect, it } from 'vitest';

import { loadQuestionnaireSession, loadScanSnapshot, type AttestationPromptRunner } from '../questionnaire/index.js';
import { executeAttestCommand } from './index.js';

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

function makePromptRunner(options: {
  saveAfter?: number;
  noteQuestionId?: string;
} = {}): AttestationPromptRunner {
  let answeredCount = 0;

  return {
    async prompt(question) {
      if (options.saveAfter !== undefined && answeredCount >= options.saveAfter) {
        return { kind: 'save_and_exit' };
      }

      answeredCount += 1;

      switch (question.type) {
        case 'yes_no':
          return {
            kind: 'answer',
            answer: true,
            note: options.noteQuestionId === question.id ? 'Reviewed internally' : undefined,
            evidenceRefs: options.noteQuestionId === question.id ? ['docs/privacy-policy.md'] : undefined,
          };
        case 'yes_no_na':
          return {
            kind: 'answer',
            answer: true,
          };
        case 'multi_choice':
          return {
            kind: 'answer',
            answer: (question.options || []).filter((option) => option !== 'None of the above').slice(0, 2),
          };
        case 'text':
          return {
            kind: 'answer',
            answer: 'Documented internally',
          };
      }
    },
  };
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

describe('CLI attest command', () => {
  it('creates session.json and scan-results.json when starting from a local path target', async () => {
    const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-project-'));
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-output-'));

    try {
      await fs.writeFile(path.join(projectDir, 'README.md'), '# Example project\n');

      const result = await executeAttestCommand(projectDir, {
        output: outputDir,
        format: 'json',
        strict: false,
      }, makePromptRunner({ saveAfter: 0 }));

      expect(result.status).toBe('saved');

      const session = await loadQuestionnaireSession(result.sessionPath);
      const snapshot = await loadScanSnapshot<any>(result.scanSnapshotPath);

      expect(session.target.kind).toBe('path');
      expect(session.target.path).toBe(projectDir);
      expect(snapshot.target.path).toBe(projectDir);
      await expect(fs.stat(result.sessionPath)).resolves.toBeTruthy();
      await expect(fs.stat(result.scanSnapshotPath)).resolves.toBeTruthy();
    } finally {
      await fs.rm(projectDir, { recursive: true, force: true });
      await fs.rm(outputDir, { recursive: true, force: true });
    }
  });

  it('starts from a saved URL scan, resumes, and writes merged report artifacts', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-session-'));
    const scanFile = path.join(tempDir, 'scan.json');

    try {
      await fs.writeFile(scanFile, JSON.stringify({
        targetType: 'url',
        targetUrl: 'https://example.com/',
        target: {
          name: 'example.com',
          url: 'https://example.com/',
        },
        findings: [],
        results: [],
        errors: [],
        totalDurationMs: 250,
      }, null, 2));

      const saved = await executeAttestCommand(undefined, {
        fromScan: scanFile,
        output: tempDir,
        format: 'json,html,markdown,pdf',
        strict: false,
      }, makePromptRunner({ saveAfter: 1 }));

      expect(saved.status).toBe('saved');

      const savedSession = await loadQuestionnaireSession(saved.sessionPath);
      const frozenSnapshot = await loadScanSnapshot<any>(saved.scanSnapshotPath);
      expect(savedSession.answers).toHaveLength(1);
      expect(frozenSnapshot.target.url).toBe('https://example.com/');

      const completed = await executeAttestCommand(undefined, {
        resume: saved.sessionPath,
        output: tempDir,
        format: 'json,html,markdown,pdf',
        strict: false,
      }, makePromptRunner({ noteQuestionId: 'Q-APP1-001' }));

      expect(completed.status).toBe('completed');
      expect(completed.reportPaths).toHaveLength(4);

      const completedSession = await loadQuestionnaireSession(saved.sessionPath);
      expect(completedSession.status).toBe('completed');
      expect(completedSession.answers.length).toBeGreaterThan(1);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });
});
