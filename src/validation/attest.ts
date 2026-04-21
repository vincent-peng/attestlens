import fs from 'node:fs/promises';
import path from 'node:path';

import YAML from 'yaml';

import { sanitizeValidationTargetId } from './corpus.js';

export interface AttestValidationScenario {
  id: string;
  type: 'public' | 'private_template';
  label: string;
  corpusTargetId?: string;
  reviewGoal: string;
  focusPrinciples: string[];
  operatorAssumptions: string[];
  expectedOutcomePattern: string;
}

export interface AttestValidationManifest {
  scenarios: AttestValidationScenario[];
}

export interface PrepareAttestValidationOptions {
  repoRoot: string;
  manifestPath: string;
  templatePath: string;
  outputRoot: string;
  scenarioId: string;
  runDate?: string;
  target?: string;
  name?: string;
  fromScan?: string;
}

export interface PreparedAttestValidation {
  scenario: AttestValidationScenario;
  runDate: string;
  runDir: string;
  reviewPath: string;
  metaPath: string;
  commandPath: string;
  scanSource: 'corpus report' | 'saved scan' | 'local scan';
  sourceScanPath?: string;
  target?: string;
  name?: string;
  installedCommand: string;
  repoLocalCommand: string;
}

export async function loadAttestValidationManifest(
  manifestPath: string,
): Promise<AttestValidationManifest> {
  const raw = await fs.readFile(manifestPath, 'utf-8');
  const parsed = YAML.parse(raw) as AttestValidationManifest;

  if (!parsed || !Array.isArray(parsed.scenarios)) {
    throw new Error('Attestation validation manifest must define a scenarios array.');
  }

  for (const scenario of parsed.scenarios) {
    if (
      !scenario.id
      || !scenario.type
      || !scenario.label
      || !scenario.reviewGoal
      || !Array.isArray(scenario.focusPrinciples)
      || !Array.isArray(scenario.operatorAssumptions)
      || !scenario.expectedOutcomePattern
    ) {
      throw new Error(`Attestation validation scenario is missing required fields: ${JSON.stringify(scenario)}`);
    }

    if (scenario.type === 'public' && !scenario.corpusTargetId) {
      throw new Error(`Public attestation validation scenario requires corpusTargetId: ${scenario.id}`);
    }
  }

  return parsed;
}

export function buildAttestValidationRunDir(
  outputRoot: string,
  runDate: string,
  scenarioId: string,
): string {
  return path.join(outputRoot, runDate, sanitizeValidationTargetId(scenarioId));
}

export async function resolveLatestValidationReportPath(
  validationOutputRoot: string,
  corpusTargetId: string,
): Promise<string> {
  const root = path.resolve(validationOutputRoot);
  const targetDirName = sanitizeValidationTargetId(corpusTargetId);
  const entries = await fs.readdir(root, { withFileTypes: true }).catch(() => []);
  const datedDirs = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .reverse();

  for (const dateDir of datedDirs) {
    const targetDir = path.join(root, dateDir, targetDirName);
    const targetEntries = await fs.readdir(targetDir, { withFileTypes: true }).catch(() => []);
    const jsonFiles = targetEntries
      .filter((entry) => entry.isFile() && entry.name.endsWith('.json') && entry.name.startsWith('attestlens-report-'))
      .map((entry) => entry.name)
      .sort()
      .reverse();

    if (jsonFiles.length > 0) {
      return path.join(targetDir, jsonFiles[0]!);
    }
  }

  throw new Error(
    `No saved validation corpus JSON artifact found for "${corpusTargetId}". Run \`npm run validate:corpus\` first.`,
  );
}

export function getDefaultRunDate(date = new Date()): string {
  return new Intl.DateTimeFormat('en-CA', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date);
}

function shellEscape(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function ensureNonEmptyFlag(flagName: string, value?: string): string {
  if (!value || value.trim().length === 0) {
    throw new Error(`${flagName} is required.`);
  }
  return value.trim();
}

async function ensureFreshRunDir(runDir: string): Promise<void> {
  const existingEntries = await fs.readdir(runDir).catch(() => []);
  if (existingEntries.length > 0) {
    throw new Error(`Attestation validation run directory already exists and is not empty: ${runDir}`);
  }

  await fs.mkdir(runDir, { recursive: true });
}

function renderBulletList(values: string[]): string {
  return values.map((value) => `- ${value}`).join('\n');
}

async function renderReviewTemplate(
  templatePath: string,
  params: {
    scenario: AttestValidationScenario;
    runDate: string;
    scanSource: PreparedAttestValidation['scanSource'];
    sourceScanPath?: string;
    target?: string;
    name?: string;
  },
): Promise<string> {
  const template = await fs.readFile(templatePath, 'utf-8');

  return template
    .replaceAll('{{RUN_DATE}}', params.runDate)
    .replaceAll('{{SCENARIO_ID}}', params.scenario.id)
    .replaceAll('{{SCENARIO_LABEL}}', params.scenario.label)
    .replaceAll('{{SCENARIO_TYPE}}', params.scenario.type)
    .replaceAll('{{REVIEW_GOAL}}', params.scenario.reviewGoal)
    .replaceAll('{{FOCUS_PRINCIPLES}}', params.scenario.focusPrinciples.join(', '))
    .replaceAll('{{EXPECTED_OUTCOME_PATTERN}}', params.scenario.expectedOutcomePattern)
    .replaceAll('{{OPERATOR_ASSUMPTIONS}}', renderBulletList(params.scenario.operatorAssumptions))
    .replaceAll('{{SCAN_SOURCE}}', params.scanSource)
    .replaceAll('{{SOURCE_SCAN_PATH}}', params.sourceScanPath || 'N/A')
    .replaceAll('{{TARGET_INPUT}}', params.target || 'N/A')
    .replaceAll('{{DISPLAY_NAME}}', params.name || 'N/A');
}

function buildInstalledCommand(args: string[]): string {
  return `attestlens attest ${args.map(shellEscape).join(' ')}`;
}

function buildRepoLocalCommand(args: string[]): string {
  return `npx tsx src/cli/index.ts attest ${args.map(shellEscape).join(' ')}`;
}

function findScenario(
  manifest: AttestValidationManifest,
  scenarioId: string,
): AttestValidationScenario {
  const scenario = manifest.scenarios.find((candidate) => candidate.id === scenarioId);
  if (!scenario) {
    throw new Error(
      `Unknown attestation validation scenario "${scenarioId}". Available scenarios: ${manifest.scenarios.map((candidate) => candidate.id).join(', ')}`,
    );
  }

  return scenario;
}

export async function prepareAttestValidation(
  options: PrepareAttestValidationOptions,
): Promise<PreparedAttestValidation> {
  const repoRoot = path.resolve(options.repoRoot);
  const manifest = await loadAttestValidationManifest(path.resolve(options.manifestPath));
  const scenario = findScenario(manifest, options.scenarioId);
  const runDate = options.runDate || getDefaultRunDate();
  const runDir = buildAttestValidationRunDir(path.resolve(options.outputRoot), runDate, scenario.id);
  await ensureFreshRunDir(runDir);

  let scanSource: PreparedAttestValidation['scanSource'];
  let sourceScanPath: string | undefined;
  let target: string | undefined;
  let name: string | undefined;
  const attestArgs: string[] = [];

  if (options.fromScan) {
    sourceScanPath = path.resolve(options.fromScan);
    scanSource = 'saved scan';
    attestArgs.push('--from-scan', sourceScanPath);

    if (scenario.type === 'private_template') {
      name = ensureNonEmptyFlag('--name', options.name);
      attestArgs.push('-n', name);
    }
  } else if (scenario.type === 'public') {
    sourceScanPath = await resolveLatestValidationReportPath(
      path.join(repoRoot, 'attestlens-reports', 'validation'),
      scenario.corpusTargetId!,
    );
    scanSource = 'corpus report';
    attestArgs.push('--from-scan', sourceScanPath);
  } else {
    target = ensureNonEmptyFlag('--target', options.target);
    name = ensureNonEmptyFlag('--name', options.name);
    scanSource = 'local scan';
    attestArgs.push(target, '-n', name);
  }

  attestArgs.push('-o', runDir);

  const reviewPath = path.join(runDir, 'REVIEW.md');
  const metaPath = path.join(runDir, 'meta.json');
  const commandPath = path.join(runDir, 'COMMAND.txt');
  const installedCommand = buildInstalledCommand(attestArgs);
  const repoLocalCommand = buildRepoLocalCommand(attestArgs);
  const reviewContent = await renderReviewTemplate(path.resolve(options.templatePath), {
    scenario,
    runDate,
    scanSource,
    sourceScanPath,
    target,
    name,
  });

  await fs.writeFile(reviewPath, reviewContent, 'utf-8');
  await fs.writeFile(metaPath, JSON.stringify({
    scenario,
    runDate,
    runDir,
    scanSource,
    sourceScanPath,
    target,
    name,
    installedCommand,
    repoLocalCommand,
  }, null, 2), 'utf-8');
  await fs.writeFile(
    commandPath,
    [
      '# Preferred command (installed CLI)',
      installedCommand,
      '',
      '# Repo-local fallback (run from the repository root)',
      repoLocalCommand,
      '',
    ].join('\n'),
    'utf-8',
  );

  return {
    scenario,
    runDate,
    runDir,
    reviewPath,
    metaPath,
    commandPath,
    scanSource,
    sourceScanPath,
    target,
    name,
    installedCommand,
    repoLocalCommand,
  };
}

export async function prepareAttestValidationCli(argv = process.argv.slice(2)): Promise<PreparedAttestValidation> {
  const [scenarioId, ...rawFlags] = argv;

  if (!scenarioId) {
    throw new Error('Usage: npm run validate:attest -- <scenario-id> [--date YYYY-MM-DD] [--target <path-or-url>] [--name <display-name>] [--from-scan <json>]');
  }

  const flags = new Map<string, string>();
  for (let index = 0; index < rawFlags.length; index += 2) {
    const flag = rawFlags[index];
    const value = rawFlags[index + 1];

    if (!flag?.startsWith('--') || !value) {
      throw new Error(`Invalid arguments. Expected flag/value pairs, received: ${rawFlags.join(' ')}`);
    }

    flags.set(flag, value);
  }

  const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  const result = await prepareAttestValidation({
    repoRoot,
    manifestPath: path.join(repoRoot, 'docs', 'validation', 'attest-scenarios.yaml'),
    templatePath: path.join(repoRoot, 'docs', 'validation', 'templates', 'attest-review.md'),
    outputRoot: path.join(repoRoot, 'attestlens-reports', 'attest-validation'),
    scenarioId,
    runDate: flags.get('--date'),
    target: flags.get('--target'),
    name: flags.get('--name'),
    fromScan: flags.get('--from-scan'),
  });

  process.stdout.write(
    [
      `Prepared attestation validation run for ${result.scenario.label}.`,
      `Run directory: ${result.runDir}`,
      `Review template: ${result.reviewPath}`,
      `Command file: ${result.commandPath}`,
      `Preferred command: ${result.installedCommand}`,
      '',
    ].join('\n'),
  );

  return result;
}
