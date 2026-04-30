import crypto from 'node:crypto';

import type { AttestLensFinding, RuleDefinition, Severity } from '../../schema/index.js';
import { CCPAPrincipleInfo } from './ccpa-principles.js';

export interface CcpaCheckFile {
  relativePath: string;
  content: string;
}

const CCPA_RULE_VERSION = '2026.04.30';

function ccpaMapping(principle: keyof typeof CCPAPrincipleInfo, confidence: number, citation = CCPAPrincipleInfo[principle].citation) {
  return {
    jurisdiction: 'us-ccpa' as const,
    principle,
    obligation: CCPAPrincipleInfo[principle].obligation,
    status: 'fail' as const,
    confidence,
    citation,
  };
}

export const CCPA_CHECKS: RuleDefinition[] = [
  {
    id: 'CCPA-DNS-001',
    category: 'ccpa-notice',
    severity: 'high',
    title: 'Missing Do Not Sell link',
    description: 'No visible "Do Not Sell or Share My Personal Information" or equivalent DoNotSell link text was found in HTML or JavaScript surfaces.',
    pattern: String.raw`Do\s+Not\s+Sell|DoNotSell|Sell\s+or\s+Share\s+My\s+Personal\s+Information`,
    flags: 'i',
    fixPrompt: 'Add a clear "Do Not Sell or Share My Personal Information" link where CCPA opt-out rights must be presented.',
    appMappings: [],
    regulationMappings: [ccpaMapping('CCPA_120', 0.82, 'Cal. Civ. Code §1798.120')],
    addedIn: CCPA_RULE_VERSION,
    enabled: true,
    tags: ['ccpa', 'notice', 'opt-out'],
  },
  {
    id: 'CCPA-DNS-002',
    category: 'ccpa-notice',
    severity: 'high',
    title: 'Missing Limit Sensitive PI link',
    description: 'No visible "Limit the Use of My Sensitive Personal Information" link text was found in HTML or JavaScript surfaces.',
    pattern: String.raw`Limit\s+the\s+Use|Limit.*Sensitive.*Personal\s+Information`,
    flags: 'i',
    fixPrompt: 'Add a clear "Limit the Use of My Sensitive Personal Information" link where sensitive PI limitation rights apply.',
    appMappings: [],
    regulationMappings: [ccpaMapping('CCPA_121', 0.82, 'Cal. Civ. Code §1798.121')],
    addedIn: CCPA_RULE_VERSION,
    enabled: true,
    tags: ['ccpa', 'notice', 'sensitive-pi'],
  },
  {
    id: 'CCPA-PP-001',
    category: 'ccpa-notice',
    severity: 'medium',
    title: 'Privacy policy missing CCPA categories',
    description: 'A privacy policy surface was found, but it does not disclose categories of personal information.',
    pattern: String.raw`categories\s+of\s+personal\s+information`,
    flags: 'i',
    fixPrompt: 'Update the privacy policy to disclose categories of personal information collected under CCPA.',
    appMappings: [],
    regulationMappings: [ccpaMapping('CCPA_130', 0.74, 'Cal. Civ. Code §1798.130')],
    addedIn: CCPA_RULE_VERSION,
    enabled: true,
    tags: ['ccpa', 'privacy-policy'],
  },
  {
    id: 'CCPA-PP-002',
    category: 'ccpa-notice',
    severity: 'medium',
    title: 'Privacy policy missing sale/disclosure info',
    description: 'A privacy policy surface was found, but it does not describe sale/sharing opt-out rights or sale of personal information.',
    pattern: String.raw`do\s+not\s+sell|sale\s+of\s+personal\s+information|sell\s+or\s+share`,
    flags: 'i',
    fixPrompt: 'Update the privacy policy to disclose sale/sharing practices and opt-out rights under CCPA.',
    appMappings: [],
    regulationMappings: [ccpaMapping('CCPA_130', 0.72, 'Cal. Civ. Code §1798.130')],
    addedIn: CCPA_RULE_VERSION,
    enabled: true,
    tags: ['ccpa', 'privacy-policy', 'sale-sharing'],
  },
  {
    id: 'CCPA-GPC-001',
    category: 'ccpa-gpc',
    severity: 'medium',
    title: 'GPC signal not honored',
    description: 'No handling for navigator.globalPrivacyControl was found in JavaScript surfaces.',
    pattern: String.raw`navigator\.globalPrivacyControl|globalPrivacyControl`,
    flags: 'i',
    fixPrompt: 'Honor navigator.globalPrivacyControl as a valid opt-out signal where CCPA opt-out obligations apply.',
    appMappings: [],
    regulationMappings: [ccpaMapping('CCPA_135', 0.70, 'Cal. Civ. Code §1798.135')],
    addedIn: CCPA_RULE_VERSION,
    enabled: true,
    tags: ['ccpa', 'gpc', 'opt-out'],
  },
  {
    id: 'CCPA-SEC-001',
    category: 'ccpa-security',
    severity: 'critical',
    title: 'Unencrypted sensitive PI in storage',
    description: 'Plaintext SSN, payment card, or driver license-like sensitive PI was found in repository data stores.',
    pattern: String.raw`\b\d{3}-\d{2}-\d{4}\b|\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|driver[_ -]?licen[cs]e`,
    flags: 'i',
    fixPrompt: 'Encrypt sensitive personal information at rest, remove plaintext fixtures from production data stores, and rotate any exposed identifiers where needed.',
    appMappings: [],
    regulationMappings: [ccpaMapping('CCPA_150', 0.86, 'Cal. Civ. Code §1798.150(a)')],
    addedIn: CCPA_RULE_VERSION,
    enabled: true,
    tags: ['ccpa', 'security', 'sensitive-pi'],
  },
];

const WEB_SURFACE_PATTERN = /\.(?:html?|tsx?|jsx?|mjs|cjs)$/i;
const PRIVACY_POLICY_PATH_PATTERN = /privacy|policy|notice/i;
const PRIVACY_POLICY_CONTENT_PATTERN = /privacy\s+(?:policy|notice)|personal\s+information/i;
const DO_NOT_SELL_PATTERN = /do\s+not\s+sell|donotsell|sell\s+or\s+share\s+my\s+personal\s+information/i;
const LIMIT_SENSITIVE_PATTERN = /limit\s+the\s+use|limit.*sensitive.*personal\s+information/i;
const CCPA_CATEGORIES_PATTERN = /categories\s+of\s+personal\s+information/i;
const SALE_DISCLOSURE_PATTERN = /do\s+not\s+sell|sale\s+of\s+personal\s+information|sell\s+or\s+share/i;
const GPC_PATTERN = /navigator\.globalPrivacyControl|globalPrivacyControl/i;
const SENSITIVE_PI_PATTERN = /\b\d{3}-\d{2}-\d{4}\b|\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|driver[_ -]?licen[cs]e\s*[:=]\s*['"]?[A-Z0-9-]{5,}/i;

export function scanCcpaChecks(files: CcpaCheckFile[], scannerVersion: string): AttestLensFinding[] {
  const findings: AttestLensFinding[] = [];
  const webFiles = files.filter((file) => WEB_SURFACE_PATTERN.test(file.relativePath));
  const privacyFiles = files.filter((file) =>
    PRIVACY_POLICY_PATH_PATTERN.test(file.relativePath) || PRIVACY_POLICY_CONTENT_PATTERN.test(file.content),
  );

  if (webFiles.length > 0 && !webFiles.some((file) => DO_NOT_SELL_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'CCPA-DNS-001', webFiles[0]!, 'Expected CCPA opt-out link text was not found.'));
  }

  if (webFiles.length > 0 && !webFiles.some((file) => LIMIT_SENSITIVE_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'CCPA-DNS-002', webFiles[0]!, 'Expected sensitive PI limitation link text was not found.'));
  }

  if (privacyFiles.length > 0 && !privacyFiles.some((file) => CCPA_CATEGORIES_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'CCPA-PP-001', privacyFiles[0]!, 'Expected categories of personal information disclosure was not found.'));
  }

  if (privacyFiles.length > 0 && !privacyFiles.some((file) => SALE_DISCLOSURE_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'CCPA-PP-002', privacyFiles[0]!, 'Expected sale/sharing disclosure or opt-out language was not found.'));
  }

  if (webFiles.length > 0 && !webFiles.some((file) => GPC_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'CCPA-GPC-001', webFiles[0]!, 'Expected Global Privacy Control handling was not found.'));
  }

  for (const file of files) {
    const match = findFirstMatch(file.content, SENSITIVE_PI_PATTERN);
    if (!match) {
      continue;
    }
    findings.push(makeFinding(
      scannerVersion,
      'CCPA-SEC-001',
      file.relativePath,
      match.line,
      match.code,
    ));
  }

  return findings;
}

function makeMissingFinding(
  scannerVersion: string,
  ruleId: string,
  file: CcpaCheckFile,
  code: string,
): AttestLensFinding {
  return makeFinding(scannerVersion, ruleId, file.relativePath, 1, code);
}

function makeFinding(
  scannerVersion: string,
  ruleId: string,
  file: string,
  line: number,
  code: string,
): AttestLensFinding {
  const rule = CCPA_CHECKS.find((candidate) => candidate.id === ruleId);
  if (!rule) {
    throw new Error(`Unknown CCPA rule: ${ruleId}`);
  }

  const payload = `${ruleId}:${file}:${line}:${code}`;
  return {
    id: crypto.createHash('sha256').update(payload).digest('hex').substring(0, 12),
    source: 'guardvibe',
    sourceRule: rule.id,
    severity: rule.severity as Severity,
    category: rule.category,
    title: rule.title,
    description: rule.description,
    file,
    line,
    code,
    fix: rule.fixPrompt,
    appMappings: [],
    regulationMappings: rule.regulationMappings,
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion,
      rawOutput: {
        sourceRule: rule.id,
        file,
        line,
      },
      scannerCommand: 'attestlens ccpa-checks',
    },
  };
}

function findFirstMatch(content: string, pattern: RegExp): { line: number; code: string } | null {
  const lines = content.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    pattern.lastIndex = 0;
    const line = lines[index] || '';
    if (pattern.test(line)) {
      return { line: index + 1, code: line.trim() };
    }
  }
  return null;
}
