/**
 * AttestLens — Privacy Act 2026 Reform Scanner
 *
 * Detects code patterns that are relevant to upcoming Australian privacy and
 * adjacent reform obligations.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { APPMapping, APPPrinciple, AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import type { ScannerAdapter, ScannerContext, ScannerError, ScannerResult } from './types.js';

export interface ReformAdapterOptions {
  enabled?: boolean;
}

type ReformProvision =
  | 'STATUTORY_TORT'
  | 'CHILDREN_PRIVACY_CODE'
  | 'AUTOMATED_DECISION_MAKING'
  | 'AML_CTF';

interface ReformRule {
  id: string;
  provision: ReformProvision;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  fix: string;
  detect: (file: SourceFile) => ReformMatch | null;
}

interface SourceFile {
  root: string;
  file: string;
  relativeFile: string;
  content: string;
  lines: string[];
}

interface ReformMatch {
  line: number;
  snippet: string;
  signal: string;
}

const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py']);
const SKIPPED_DIR_SEGMENTS = new Set([
  'node_modules',
  '.git',
  'dist',
  'coverage',
  'test',
  'tests',
  '__tests__',
  'fixture',
  'fixtures',
]);
const DEFAULT_MAX_FILE_BYTES = 1_000_000;

const EFFECTIVE_DATES: Record<ReformProvision, string> = {
  STATUTORY_TORT: '2026-07-01',
  CHILDREN_PRIVACY_CODE: '2026-12-10',
  AUTOMATED_DECISION_MAKING: '2026-12-10',
  AML_CTF: '2026-07-01',
};

const APP_MAPPINGS: Record<ReformProvision, APPPrinciple[]> = {
  STATUTORY_TORT: ['APP_3', 'APP_6', 'APP_13'],
  CHILDREN_PRIVACY_CODE: ['APP_3', 'APP_5', 'APP_6'],
  AUTOMATED_DECISION_MAKING: ['APP_6', 'APP_10'],
  AML_CTF: ['APP_6', 'APP_8', 'APP_11'],
};

const APP_OBLIGATIONS: Record<APPPrinciple, string> = {
  APP_1: 'Open and transparent management of personal information',
  APP_2: 'Anonymity option for individuals',
  APP_3: 'Lawful, fair, and necessary collection',
  APP_4: 'Deal with unsolicited personal information',
  APP_5: 'Notify individuals of collection',
  APP_6: 'Use or disclosure only for primary purpose',
  APP_7: 'Direct marketing restrictions and opt-out',
  APP_8: 'Reasonable steps for overseas disclosure',
  APP_9: 'Restricted use of government identifiers',
  APP_10: 'Accurate, up-to-date, and complete information',
  APP_11: 'Reasonable steps to protect personal information',
  APP_12: 'Individuals can access their information',
  APP_13: 'Individuals can correct their information',
  NDB: 'Assess, notify, and remediate eligible data breaches',
};

const PERSONAL_DATA_PATTERNS = [
  /\bpii\b/i,
  /\bpersonal[_\s-]?(?:data|info|information)\b/i,
  /\bemail(?:Address)?\b/i,
  /\bphone(?:Number)?\b/i,
  /\bmobile(?:Number)?\b/i,
  /\baddress\b/i,
  /\bdate[_\s-]?of[_\s-]?birth\b/i,
  /\bdob\b/i,
  /\bbirthdate\b/i,
  /\bpassport\b/i,
  /\bmedicare\b/i,
  /\btax[_\s-]?file[_\s-]?number\b/i,
  /\btfn\b/i,
  /\bssn\b/i,
  /\bbiometric/i,
  /\bgeo(?:location)?\b/i,
  /\blocation\b/i,
  /\bip[_\s-]?address\b/i,
  /\bdevice[_\s-]?id\b/i,
];

const COLLECTION_PATTERNS = [
  /\b(?:collect|harvest|scrape|capture|ingest)\w*\b/i,
];

const RETENTION_PATTERNS = [
  /\b(?:retain|store|persist|save|archive|cache)\w*\b/i,
];

const PURPOSE_SIGNALS = [
  /\bpurpose\b/i,
  /\bprimary[_\s-]?purpose\b/i,
  /\blawful[_\s-]?basis\b/i,
  /\bprivacy[_\s-]?notice\b/i,
  /\bnotice[_\s-]?of[_\s-]?collection\b/i,
  /\bconsent\b/i,
  /\bjustification\b/i,
  /\breason\b/i,
];

const RETENTION_CONTROL_SIGNALS = [
  /\bttl\b/i,
  /\bexpir(?:e|es|y|ation)\b/i,
  /\bretention\b/i,
  /\bdelete|deletion|purge|cleanup\b/i,
  /\banonymi[sz]e\b/i,
  /\bminimi[sz]e\b/i,
  /\bnecessary\b/i,
];

const DATA_ACCESS_SIGNALS = [
  /\bdata[_\s-]?access\b/i,
  /\bsubject[_\s-]?access\b/i,
  /\bdsar\b/i,
  /\bprivacy[_\s-]?request\b/i,
  /\baccess[_\s-]?request\b/i,
  /\bexport[_\s-]?(?:data|profile|account)\b/i,
  /\bdownload[_\s-]?(?:data|profile|account)\b/i,
  /\bcorrect(?:ion)?[_\s-]?(?:data|profile|account)?\b/i,
  /\bdelete[_\s-]?(?:data|profile|account)\b/i,
];

const CHILD_DATA_PATTERNS = [
  /\bchildren\b/i,
  /\bchild\b/i,
  /\bkids?\b/i,
  /\bminors?\b/i,
  /\bage\b/i,
  /\bdob\b/i,
  /\bdate[_\s-]?of[_\s-]?birth\b/i,
];

const AGE_VERIFICATION_SIGNALS = [
  /\bage[_\s-]?verification\b/i,
  /\bverify\w*Age\b/i,
  /\bageVerified\b/i,
  /\bverified[_\s-]?age\b/i,
  /\bage[_\s-]?check\b/i,
  /\bage[_\s-]?gate[_\s-]?passed\b/i,
  /\bbirthdateVerified\b/i,
  /\bminor[_\s-]?check\b/i,
];

const PARENTAL_CONSENT_SIGNALS = [
  /\bparental[_\s-]?consent\b/i,
  /\bguardian[_\s-]?consent\b/i,
  /\bparent[_\s-]?approval\b/i,
  /\bguardian[_\s-]?approval\b/i,
  /\bverifiable[_\s-]?parental\b/i,
];

const AGE_GATE_PATTERNS = [
  /\bage\s*[<>=!]=?\s*(?:13|15|16|18)\b/i,
  /\b(?:isMinor|minor|under[_\s-]?(?:13|16|18))\b/i,
  /\b(?:dob|date[_\s-]?of[_\s-]?birth|birthdate)\b/i,
];

const ML_INFERENCE_PATTERNS = [
  /\.\s*predict\s*\(/i,
  /\.\s*classify\s*\(/i,
  /\.\s*score\s*\(/i,
  /\bmodel\.load\b/i,
  /\btf\./i,
  /\bsklearn\b/i,
  /\btensorflow\b/i,
  /\btorch\./i,
  /\bpytorch\b/i,
  /\bxgboost\b/i,
  /\blightgbm\b/i,
];

const AUTOMATED_DECISION_PATTERNS = [
  /\bcredit[_\s-]?score\b/i,
  /\brisk[_\s-]?score\b/i,
  /\bfraud[_\s-]?score\b/i,
  /\bauto[_\s-]?(?:approve|reject|decline)\b/i,
  /\bautomated[_\s-]?decision\b/i,
  /\beligibility[_\s-]?decision\b/i,
];

const SCORING_PATTERNS = [
  /\b(?:credit|risk|fraud|eligibility)[_\s-]?score\b/i,
  /\bscore(?:Applicant|Customer|User)?\b/i,
  /\.\s*score\s*\(/i,
];

const TRANSPARENCY_SIGNALS = [
  /\btransparen(?:t|cy)\b/i,
  /\bexplain(?:able|ability|ed|er)?\b/i,
  /\breason(?:Code|s)?\b/i,
  /\bdecision[_\s-]?notice\b/i,
  /\badverse[_\s-]?action\b/i,
  /\bmodel[_\s-]?card\b/i,
  /\baudit[_\s-]?trail\b/i,
];

const HUMAN_REVIEW_SIGNALS = [
  /\bhuman[_\s-]?review\b/i,
  /\bmanual[_\s-]?review\b/i,
  /\breviewer\b/i,
  /\bcaseworker\b/i,
  /\boverride\b/i,
  /\bappeal\b/i,
  /\breview[_\s-]?queue\b/i,
];

const TRANSACTION_PATTERNS = [
  /\btransaction\b/i,
  /\btransfer\b/i,
  /\bpayment\b/i,
  /\bdeposit\b/i,
  /\bwithdrawal\b/i,
];

const KYC_SIGNALS = [
  /\bkyc\b/i,
  /\bknow[_\s-]?your[_\s-]?customer\b/i,
  /\bidentity[_\s-]?verification\b/i,
  /\bverify[_\s-]?identity\b/i,
  /\bverified[_\s-]?identity\b/i,
];

const CDD_SIGNALS = [
  /\bcustomer[_\s-]?due[_\s-]?diligence\b/i,
  /\bdue[_\s-]?diligence\b/i,
  /\bbeneficial[_\s-]?owner\b/i,
  /\bsource[_\s-]?of[_\s-]?funds\b/i,
  /\baml[_\s-]?screening\b/i,
  /\bsanctions?[_\s-]?screening\b/i,
];

const CROSS_BORDER_PATTERNS = [
  /\binternational[_\s-]?transfer\b/i,
  /\bforeign[_\s-]?exchange\b/i,
  /\bcross[_\s-]?border\b/i,
  /\boverseas[_\s-]?transfer\b/i,
  /\bremittance\b/i,
  /\bswift\b/i,
  /\biban\b/i,
];

const REFORM_RULES: ReformRule[] = [
  {
    id: 'RF-STAT-001',
    provision: 'STATUTORY_TORT',
    severity: 'critical',
    category: 'Privacy Act 2026 Reform - Statutory Tort',
    title: 'PII collection without clear purpose',
    description: 'Code appears to collect personal information without a nearby purpose, notice, consent, or lawful-basis signal.',
    fix: 'Document the collection purpose at the collection boundary and link it to consent, notice, or another lawful basis.',
    detect: (file) => findLineMissingSignals(file, COLLECTION_PATTERNS, PERSONAL_DATA_PATTERNS, PURPOSE_SIGNALS, 'pii_collection_without_purpose'),
  },
  {
    id: 'RF-STAT-002',
    provision: 'STATUTORY_TORT',
    severity: 'critical',
    category: 'Privacy Act 2026 Reform - Statutory Tort',
    title: 'Excessive personal data retention risk',
    description: 'Code appears to retain or persist personal information without a retention, expiry, minimisation, or deletion control signal.',
    fix: 'Add retention limits, expiry, deletion, or minimisation controls for stored personal information.',
    detect: (file) => findLineMissingSignals(file, RETENTION_PATTERNS, PERSONAL_DATA_PATTERNS, RETENTION_CONTROL_SIGNALS, 'pii_retention_without_controls'),
  },
  {
    id: 'RF-STAT-003',
    provision: 'STATUTORY_TORT',
    severity: 'medium',
    category: 'Privacy Act 2026 Reform - Statutory Tort',
    title: 'Missing data subject access mechanism',
    description: 'Code handles personal information, but the same file does not expose a data access, export, correction, or privacy request mechanism.',
    fix: 'Provide a data subject access, export, and correction path for personal information handled in this area.',
    detect: (file) => findHandlingWithoutFileSignals(file, [...COLLECTION_PATTERNS, ...RETENTION_PATTERNS], PERSONAL_DATA_PATTERNS, DATA_ACCESS_SIGNALS, 'personal_data_without_access_mechanism'),
  },
  {
    id: 'RF-CPC-001',
    provision: 'CHILDREN_PRIVACY_CODE',
    severity: 'critical',
    category: 'Privacy Act 2026 Reform - Children Privacy Code',
    title: 'Child data without age verification',
    description: 'Code appears to handle child, minor, age, or date-of-birth data without an age-verification signal.',
    fix: 'Add age verification appropriate to the service and document how child data paths are gated.',
    detect: (file) => findLineMissingFileSignals(file, CHILD_DATA_PATTERNS, AGE_VERIFICATION_SIGNALS, 'child_data_without_age_verification'),
  },
  {
    id: 'RF-CPC-002',
    provision: 'CHILDREN_PRIVACY_CODE',
    severity: 'critical',
    category: 'Privacy Act 2026 Reform - Children Privacy Code',
    title: 'Missing parental consent for child data handling',
    description: 'Code appears to handle child or minor data without a parental or guardian consent signal.',
    fix: 'Add verifiable parental or guardian consent for child-data handling where required.',
    detect: (file) => findLineMissingFileSignals(file, CHILD_DATA_PATTERNS, PARENTAL_CONSENT_SIGNALS, 'child_data_without_parental_consent'),
  },
  {
    id: 'RF-CPC-003',
    provision: 'CHILDREN_PRIVACY_CODE',
    severity: 'medium',
    category: 'Privacy Act 2026 Reform - Children Privacy Code',
    title: 'Inadequate age gate indicator',
    description: 'Code appears to rely on an age or date-of-birth gate without an explicit verification signal.',
    fix: 'Replace self-attested or weak age gates with a verified age-check flow where child privacy obligations apply.',
    detect: (file) => findLineMissingFileSignals(file, AGE_GATE_PATTERNS, AGE_VERIFICATION_SIGNALS, 'inadequate_age_gate'),
  },
  {
    id: 'RF-ADM-001',
    provision: 'AUTOMATED_DECISION_MAKING',
    severity: 'medium',
    category: 'Privacy Act 2026 Reform - Automated Decision Making',
    title: 'Automated decision without transparency signal',
    description: 'Code appears to make or support an automated decision without a transparency, explanation, or decision-notice signal.',
    fix: 'Add decision transparency, explanation, and notice metadata for automated decisions affecting individuals.',
    detect: (file) => findLineMissingFileSignals(file, AUTOMATED_DECISION_PATTERNS, TRANSPARENCY_SIGNALS, 'automated_decision_without_transparency'),
  },
  {
    id: 'RF-ADM-002',
    provision: 'AUTOMATED_DECISION_MAKING',
    severity: 'high',
    category: 'Privacy Act 2026 Reform - Automated Decision Making',
    title: 'Scoring without human review',
    description: 'Code appears to score a person or customer without a human review, appeal, override, or manual review signal.',
    fix: 'Route significant scores through human review, appeal, or documented override controls.',
    detect: (file) => findLineMissingFileSignals(file, SCORING_PATTERNS, HUMAN_REVIEW_SIGNALS, 'scoring_without_human_review'),
  },
  {
    id: 'RF-ADM-003',
    provision: 'AUTOMATED_DECISION_MAKING',
    severity: 'high',
    category: 'Privacy Act 2026 Reform - Automated Decision Making',
    title: 'ML inference in decision pipeline',
    description: 'Code appears to run model inference in a decision or scoring pipeline.',
    fix: 'Document model purpose, inputs, decision impact, explainability, and review controls for this inference path.',
    detect: (file) => findLineWithFileContext(file, ML_INFERENCE_PATTERNS, [...AUTOMATED_DECISION_PATTERNS, ...SCORING_PATTERNS], 'ml_inference_in_decision_pipeline'),
  },
  {
    id: 'RF-AML-001',
    provision: 'AML_CTF',
    severity: 'high',
    category: 'Privacy Act 2026 Reform - AML/CTF',
    title: 'Transaction processing without KYC signal',
    description: 'Code appears to process transactions, transfers, payments, deposits, or withdrawals without a KYC or identity-verification signal.',
    fix: 'Ensure transaction processing is gated by KYC or identity verification where AML/CTF obligations apply.',
    detect: (file) => findLineMissingFileSignals(file, TRANSACTION_PATTERNS, KYC_SIGNALS, 'transaction_without_kyc'),
  },
  {
    id: 'RF-AML-002',
    provision: 'AML_CTF',
    severity: 'high',
    category: 'Privacy Act 2026 Reform - AML/CTF',
    title: 'Missing customer due diligence signal',
    description: 'Code appears to process transaction activity without customer due diligence, source-of-funds, or screening signals.',
    fix: 'Add customer due diligence, source-of-funds, beneficial-owner, or screening controls for transaction activity.',
    detect: (file) => findLineMissingFileSignals(file, TRANSACTION_PATTERNS, CDD_SIGNALS, 'transaction_without_customer_due_diligence'),
  },
  {
    id: 'RF-AML-003',
    provision: 'AML_CTF',
    severity: 'high',
    category: 'Privacy Act 2026 Reform - AML/CTF',
    title: 'Cross-border transfer without verification signal',
    description: 'Code appears to handle cross-border, foreign exchange, remittance, SWIFT, or IBAN flows without KYC, due-diligence, or verification signals.',
    fix: 'Gate cross-border transaction flows with identity verification, due diligence, and AML screening controls.',
    detect: (file) => findLineMissingFileSignals(file, CROSS_BORDER_PATTERNS, [...KYC_SIGNALS, ...CDD_SIGNALS], 'cross_border_without_verification'),
  },
];

export class ReformAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'reform-2026';
  readonly version = '0.1.0';
  private readonly options: Required<Pick<ReformAdapterOptions, never>>;

  constructor(options: ReformAdapterOptions = {}) {
    this.options = options as Required<Pick<ReformAdapterOptions, never>>;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: AttestLensFinding[] = [];
    const errors: ScannerError[] = [];
    const resolvedPath = path.resolve(targetPath);

    let stat;
    try {
      stat = await fs.stat(resolvedPath);
    } catch {
      return this.result(findings, [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }], startTime);
    }
    if (!stat.isDirectory()) {
      return this.result(findings, [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }], startTime);
    }

    const files = await collectSourceFiles(resolvedPath, context);
    for (const file of files) {
      throwIfAborted(context);

      const fileStat = await fs.stat(file).catch(() => null);
      if (!fileStat || fileStat.size > DEFAULT_MAX_FILE_BYTES) {
        continue;
      }

      const content = await fs.readFile(file, 'utf-8').catch(() => '');
      if (!content) continue;

      const sourceFile: SourceFile = {
        root: resolvedPath,
        file,
        relativeFile: path.relative(resolvedPath, file).replace(/\\/g, '/'),
        content,
        lines: content.split(/\r?\n/),
      };

      for (const rule of REFORM_RULES) {
        throwIfAborted(context);
        const match = rule.detect(sourceFile);
        if (!match) continue;
        findings.push(this.makeFinding(rule, sourceFile, match));
      }
    }

    return this.result(findings, errors, startTime);
  }

  private result(findings: AttestLensFinding[], errors: ScannerError[], startTime: number): ScannerResult {
    return {
      source: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      findings,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  private makeFinding(rule: ReformRule, file: SourceFile, match: ReformMatch): AttestLensFinding {
    return {
      id: this.generateId(rule.id, file.relativeFile, match.line, match.snippet),
      source: this.name,
      sourceRule: rule.id,
      severity: rule.severity,
      category: rule.category,
      title: rule.title,
      description: rule.description,
      file: file.relativeFile,
      line: match.line,
      code: match.snippet,
      fix: rule.fix,
      fixPrompt: `${rule.fix} Add a focused regression fixture or policy check for ${rule.id}.`,
      appMappings: makeAppMappings(rule.provision, rule.id),
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: {
          provision: rule.provision,
          effectiveDate: EFFECTIVE_DATES[rule.provision],
          signal: match.signal,
          file: file.relativeFile,
          line: match.line,
          evidence: match.snippet,
        },
        scannerCommand: 'attestlens reform-scan',
      },
    };
  }

  private generateId(ruleId: string, file: string, line: number, code: string): string {
    return crypto
      .createHash('sha256')
      .update(`${this.name}:${ruleId}:${file}:${line}:${code}`)
      .digest('hex')
      .substring(0, 12);
  }
}

async function collectSourceFiles(root: string, context?: ScannerContext): Promise<string[]> {
  const files: string[] = [];

  async function walk(dir: string): Promise<void> {
    throwIfAborted(context);
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIR_SEGMENTS.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;
      if (entry.name.endsWith('.d.ts') || entry.name.includes('.min.')) continue;
      if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
  }

  await walk(root);
  return files.sort();
}

function findLineMissingSignals(
  file: SourceFile,
  actionPatterns: RegExp[],
  dataPatterns: RegExp[],
  controlSignals: RegExp[],
  signal: string,
): ReformMatch | null {
  for (let index = 0; index < file.lines.length; index += 1) {
    const line = file.lines[index] || '';
    if (!matchesAny(line, actionPatterns) || !matchesAny(line, dataPatterns)) continue;
    const localContext = getLineWindow(file.lines, index);
    if (matchesAny(localContext, controlSignals)) continue;
    return makeMatch(index, line, signal);
  }
  return null;
}

function findHandlingWithoutFileSignals(
  file: SourceFile,
  actionPatterns: RegExp[],
  dataPatterns: RegExp[],
  controlSignals: RegExp[],
  signal: string,
): ReformMatch | null {
  if (matchesAny(file.content, controlSignals)) {
    return null;
  }

  for (let index = 0; index < file.lines.length; index += 1) {
    const line = file.lines[index] || '';
    if (matchesAny(line, actionPatterns) && matchesAny(line, dataPatterns)) {
      return makeMatch(index, line, signal);
    }
  }
  return null;
}

function findLineMissingFileSignals(
  file: SourceFile,
  triggerPatterns: RegExp[],
  controlSignals: RegExp[],
  signal: string,
): ReformMatch | null {
  if (matchesAny(file.content, controlSignals)) {
    return null;
  }

  for (let index = 0; index < file.lines.length; index += 1) {
    const line = file.lines[index] || '';
    if (matchesAny(line, triggerPatterns)) {
      return makeMatch(index, line, signal);
    }
  }
  return null;
}

function findLineWithFileContext(
  file: SourceFile,
  triggerPatterns: RegExp[],
  contextPatterns: RegExp[],
  signal: string,
): ReformMatch | null {
  if (!matchesAny(file.content, contextPatterns)) {
    return null;
  }

  for (let index = 0; index < file.lines.length; index += 1) {
    const line = file.lines[index] || '';
    if (matchesAny(line, triggerPatterns)) {
      return makeMatch(index, line, signal);
    }
  }
  return null;
}

function makeMatch(index: number, line: string, signal: string): ReformMatch {
  return {
    line: index + 1,
    snippet: truncateSnippet(redactSensitiveLine(line.trim())),
    signal,
  };
}

function getLineWindow(lines: string[], index: number): string {
  const start = Math.max(0, index - 3);
  const end = Math.min(lines.length, index + 4);
  return lines.slice(start, end).join('\n');
}

function matchesAny(value: string, patterns: RegExp[]): boolean {
  return patterns.some(pattern => pattern.test(value));
}

function makeAppMappings(provision: ReformProvision, ruleId: string): APPMapping[] {
  return APP_MAPPINGS[provision].map((principle) => ({
    principle,
    obligation: APP_OBLIGATIONS[principle],
    status: 'fail',
    confidence: 0.82,
    rationale: `${ruleId} indicates a ${provision.toLowerCase()} reform-relevant control gap mapped to ${principle}.`,
  }));
}

function redactSensitiveLine(line: string): string {
  return line
    .replace(/(['"`])([^'"`]*(?:password|secret|token|api[_-]?key)[^'"`]*)\1/gi, '$1[redacted]$1')
    .replace(/=\s*(['"`])[^'"`]{16,}\1/g, '= $1[redacted]$1');
}

function throwIfAborted(context?: ScannerContext): void {
  if (context?.signal?.aborted) {
    throw new Error('Reform scan aborted');
  }
}

function truncateSnippet(snippet: string): string {
  return snippet.length > 180 ? `${snippet.slice(0, 177)}...` : snippet;
}

export default ReformAdapter;
