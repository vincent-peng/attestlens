import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  buildAttestValidationRunDir,
  loadAttestValidationManifest,
  prepareAttestValidation,
  resolveLatestValidationReportPath,
} from './attest.js';

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

function makeTemplate(): string {
  return [
    '# {{SCENARIO_LABEL}}',
    'Date: {{RUN_DATE}}',
    'Scan source: {{SCAN_SOURCE}}',
    'Source scan path: {{SOURCE_SCAN_PATH}}',
    'Target input: {{TARGET_INPUT}}',
    'Display name: {{DISPLAY_NAME}}',
    '{{OPERATOR_ASSUMPTIONS}}',
    '',
  ].join('\n');
}

async function writeFixtureFiles(tempDir: string): Promise<{
  manifestPath: string;
  templatePath: string;
  repoRoot: string;
  outputRoot: string;
}> {
  const repoRoot = path.join(tempDir, 'repo');
  const docsDir = path.join(repoRoot, 'docs', 'validation');
  const templateDir = path.join(docsDir, 'templates');
  const outputRoot = path.join(repoRoot, 'attestlens-reports', 'attest-validation');
  const manifestPath = path.join(docsDir, 'attest-scenarios.yaml');
  const templatePath = path.join(templateDir, 'attest-review.md');

  await fs.mkdir(templateDir, { recursive: true });
  await fs.mkdir(outputRoot, { recursive: true });
  await fs.writeFile(manifestPath, `scenarios:
  - id: example-baseline
    type: public
    label: Example Baseline
    corpusTargetId: example
    reviewGoal: Public baseline
    focusPrinciples: [APP_1, APP_11]
    operatorAssumptions:
      - Use saved artifacts only
    expectedOutcomePattern: Mostly questionnaire-driven
  - id: private-consultant-dry-run
    type: private_template
    label: Private Consultant Dry Run
    reviewGoal: Private dry run
    focusPrinciples: [APP_1, APP_11]
    operatorAssumptions:
      - Raw artifacts stay local
    expectedOutcomePattern: Realistic branch coverage
`, 'utf-8');
  await fs.writeFile(templatePath, makeTemplate(), 'utf-8');

  return {
    manifestPath,
    templatePath,
    repoRoot,
    outputRoot,
  };
}

describe('attestation validation helper', () => {
  it('loads the shipped attestation scenario manifest', async () => {
    const manifest = await loadAttestValidationManifest(
      path.resolve(process.cwd(), 'docs', 'validation', 'attest-scenarios.yaml'),
    );

    expect(manifest.scenarios.map((scenario) => scenario.id)).toEqual([
      'example-baseline',
      'vercel-marketing',
      'juice-shop-demo',
      'private-consultant-dry-run',
    ]);
  });

  it('builds attestation validation output paths under the scenario directory', () => {
    expect(buildAttestValidationRunDir('/tmp/output', '2026-04-22', 'Example Baseline')).toBe(
      path.join('/tmp/output', '2026-04-22', 'example-baseline'),
    );
  });

  it('finds the latest saved corpus report for a public scenario', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-validation-'));
    tempDirs.push(tempDir);

    const validationRoot = path.join(tempDir, 'attestlens-reports', 'validation');
    const olderDir = path.join(validationRoot, '2026-04-20', 'example');
    const newerDir = path.join(validationRoot, '2026-04-21', 'example');
    await fs.mkdir(olderDir, { recursive: true });
    await fs.mkdir(newerDir, { recursive: true });
    await fs.writeFile(path.join(olderDir, 'attestlens-report-example-2026-04-20.json'), '{}', 'utf-8');
    await fs.writeFile(path.join(newerDir, 'attestlens-report-example-2026-04-21.json'), '{}', 'utf-8');

    const resolved = await resolveLatestValidationReportPath(validationRoot, 'example');
    expect(resolved).toBe(path.join(newerDir, 'attestlens-report-example-2026-04-21.json'));
  });

  it('fails with a validate:corpus instruction when a public artifact is missing', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-validation-'));
    tempDirs.push(tempDir);

    await expect(resolveLatestValidationReportPath(
      path.join(tempDir, 'attestlens-reports', 'validation'),
      'example',
    )).rejects.toThrow(/npm run validate:corpus/i);
  });

  it('requires --target or --from-scan for private template scenarios', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-validation-'));
    tempDirs.push(tempDir);
    const fixtures = await writeFixtureFiles(tempDir);

    await expect(prepareAttestValidation({
      repoRoot: fixtures.repoRoot,
      manifestPath: fixtures.manifestPath,
      templatePath: fixtures.templatePath,
      outputRoot: fixtures.outputRoot,
      scenarioId: 'private-consultant-dry-run',
      runDate: '2026-04-22',
      name: 'Internal SaaS #1',
    })).rejects.toThrow(/--target is required/i);
  });

  it('requires --name for private template scenarios', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-validation-'));
    tempDirs.push(tempDir);
    const fixtures = await writeFixtureFiles(tempDir);

    await expect(prepareAttestValidation({
      repoRoot: fixtures.repoRoot,
      manifestPath: fixtures.manifestPath,
      templatePath: fixtures.templatePath,
      outputRoot: fixtures.outputRoot,
      scenarioId: 'private-consultant-dry-run',
      runDate: '2026-04-22',
      target: '/tmp/private-app',
    })).rejects.toThrow(/--name is required/i);
  });

  it('writes review scaffolding and an attest --from-scan command for public scenarios', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-validation-'));
    tempDirs.push(tempDir);
    const fixtures = await writeFixtureFiles(tempDir);
    const corpusDir = path.join(fixtures.repoRoot, 'attestlens-reports', 'validation', '2026-04-21', 'example');
    const corpusJson = path.join(corpusDir, 'attestlens-report-example-2026-04-21.json');
    await fs.mkdir(corpusDir, { recursive: true });
    await fs.writeFile(corpusJson, '{}', 'utf-8');

    const prepared = await prepareAttestValidation({
      repoRoot: fixtures.repoRoot,
      manifestPath: fixtures.manifestPath,
      templatePath: fixtures.templatePath,
      outputRoot: fixtures.outputRoot,
      scenarioId: 'example-baseline',
      runDate: '2026-04-22',
    });

    expect(prepared.runDir).toBe(
      path.join(fixtures.outputRoot, '2026-04-22', 'example-baseline'),
    );
    expect(prepared.scanSource).toBe('corpus report');
    expect(prepared.sourceScanPath).toBe(corpusJson);

    const commandFile = await fs.readFile(prepared.commandPath, 'utf-8');
    expect(commandFile).toContain('attestlens attest');
    expect(commandFile).toContain('--from-scan');
    expect(commandFile).toContain(corpusJson);

    const reviewFile = await fs.readFile(prepared.reviewPath, 'utf-8');
    expect(reviewFile).toContain('# Example Baseline');
    expect(reviewFile).toContain('Scan source: corpus report');
  });

  it('writes direct attestation commands for private template scenarios', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-attest-validation-'));
    tempDirs.push(tempDir);
    const fixtures = await writeFixtureFiles(tempDir);

    const prepared = await prepareAttestValidation({
      repoRoot: fixtures.repoRoot,
      manifestPath: fixtures.manifestPath,
      templatePath: fixtures.templatePath,
      outputRoot: fixtures.outputRoot,
      scenarioId: 'private-consultant-dry-run',
      runDate: '2026-04-22',
      target: '/tmp/private-app',
      name: 'Internal SaaS #1',
    });

    expect(prepared.scanSource).toBe('local scan');

    const commandFile = await fs.readFile(prepared.commandPath, 'utf-8');
    expect(commandFile).toContain('attestlens attest');
    expect(commandFile).toContain('/tmp/private-app');
    expect(commandFile).toContain('-n');
    expect(commandFile).toContain('Internal SaaS #1');
    expect(commandFile).not.toContain('--from-scan');
  });
});
