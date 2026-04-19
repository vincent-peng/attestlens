import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  buildValidationTargetDir,
  loadValidationCorpus,
  renderValidationSummary,
  runValidationCorpus,
  sanitizeValidationTargetId,
  type ValidationRunner,
} from './corpus.js';

describe('validation corpus', () => {
  it('loads the manifest and preserves all required targets', async () => {
    const manifest = await loadValidationCorpus(
      path.resolve(process.cwd(), 'docs', 'validation', 'corpus.yaml'),
    );

    expect(manifest.targets).toHaveLength(9);
    expect(manifest.targets.map((target) => target.url)).toEqual([
      'https://example.com/',
      'https://supabase.com/',
      'https://firebase.google.com/',
      'https://vercel.com/',
      'https://www.netlify.com/',
      'https://clerk.com/',
      'https://auth0.com/',
      'https://stripe.com/',
      'https://demo.owasp-juice.shop/',
    ]);
  });

  it('sanitizes validation target ids before building artifact paths', () => {
    expect(sanitizeValidationTargetId('Stripe / Live Site')).toBe('stripe-live-site');
    expect(buildValidationTargetDir('/tmp/output', '2026-04-19', 'Stripe / Live Site')).toBe(
      path.join('/tmp/output', '2026-04-19', 'stripe-live-site'),
    );
  });

  it('renders a markdown summary table', () => {
    const summary = renderValidationSummary('2026-04-19', 'abc1234', [
      {
        target: {
          id: 'example',
          name: 'Example',
          url: 'https://example.com/',
          expectedSurface: 'Baseline marketing site',
        },
        targetDir: '/tmp/out/example',
        status: 'passed',
        findingsCount: 2,
        grade: 'C',
        risk: 'medium',
        scanExitCode: 0,
        auditExitCode: 1,
        notes: 'Baseline marketing site',
        artifactPaths: [],
      },
    ]);

    expect(summary).toContain('# Validation Corpus Summary');
    expect(summary).toContain('| Example | PASSED | 2 | C | medium | Baseline marketing site |');
  });

  it('continues when one target scan fails and still writes the summary', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-validation-'));
    const manifestPath = path.join(tempDir, 'corpus.yaml');
    const staleFailureDir = path.join(tempDir, 'reports', '2026-04-19', 'failure');

    await fs.writeFile(manifestPath, `targets:
  - id: success
    name: Success
    url: https://example.com/
    expectedSurface: Baseline
  - id: failure
    name: Failure
    url: https://invalid.example/
    expectedSurface: Failure path
`, 'utf-8');

    await fs.mkdir(staleFailureDir, { recursive: true });
    await fs.writeFile(path.join(staleFailureDir, 'stale.json'), '{"stale":true}', 'utf-8');

    const runner: ValidationRunner = async (command, args, cwd) => {
      const targetUrl = args[0];

      if (targetUrl === 'https://invalid.example/') {
        return {
          code: 1,
          stdout: '',
          stderr: 'blocked',
        };
      }

      if (command === 'scan') {
        return {
          code: 0,
          stdout: 'scan ok',
          stderr: '',
        };
      }

      const outputDir = args[args.indexOf('-o') + 1]!;
      await fs.mkdir(outputDir, { recursive: true });
      await fs.writeFile(path.join(outputDir, 'success.json'), JSON.stringify({
        findings: [{ id: 'F-1' }],
        overallGrade: 'B',
        riskLevel: 'medium',
      }), 'utf-8');

      return {
        code: 1,
        stdout: 'audit ok',
        stderr: '',
      };
    };

    const result = await runValidationCorpus({
      repoRoot: process.cwd(),
      manifestPath,
      outputRoot: path.join(tempDir, 'reports'),
      runDate: '2026-04-19',
      commitSha: 'abc1234',
      runner,
    });

    expect(result.results).toHaveLength(2);
    expect(result.results[0]?.status).toBe('passed');
    expect(result.results[1]?.status).toBe('failed');
    expect(result.results[1]?.notes).toContain('scan command failed');
    await expect(fs.access(path.join(staleFailureDir, 'stale.json'))).rejects.toThrow();

    const summary = await fs.readFile(result.summaryPath, 'utf-8');
    expect(summary).toContain('| Success | PASSED | 1 | B | medium | Baseline |');
    expect(summary).toContain('| Failure | FAILED | 0 | - | - | scan command failed before audit could run |');
  });
});
