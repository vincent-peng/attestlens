import crypto from 'node:crypto';

import type { AttestLensFinding, ControlStatus, RuleDefinition, Severity } from '../../schema/index.js';
import { SGPDPAPrincipleInfo } from './sg-pdpa-principles.js';

export interface SgPdpaCheckFile {
  relativePath: string;
  content: string;
}

const SG_PDPA_RULE_VERSION = '2026.05.01';

function sgPdpaMapping(
  principle: keyof typeof SGPDPAPrincipleInfo,
  confidence: number,
  citation = SGPDPAPrincipleInfo[principle].citation,
  status: ControlStatus = 'fail',
) {
  return {
    jurisdiction: 'sg-pdpa' as const,
    principle,
    obligation: SGPDPAPrincipleInfo[principle].obligation,
    status,
    confidence,
    citation,
  };
}

export const SG_PDPA_CHECKS: RuleDefinition[] = [
  {
    id: 'SGPDPA-CONSENT-001',
    category: 'sg-pdpa-consent',
    severity: 'high',
    title: 'Missing consent or preference mechanism',
    description: 'No visible consent, preference, or personal data collection consent mechanism was found in HTML or JavaScript surfaces.',
    pattern: String.raw`consent|privacy\s+preferences|agree\s+to\s+the\s+collection|personal\s+data\s+consent`,
    flags: 'i',
    fixPrompt: 'Add a consent or preference mechanism where personal data collection relies on consent under the Singapore PDPA.',
    appMappings: [],
    regulationMappings: [sgPdpaMapping('SGPDPA_11', 0.55, SGPDPAPrincipleInfo.SGPDPA_11.citation, 'unknown')],
    addedIn: SG_PDPA_RULE_VERSION,
    enabled: true,
    tags: ['sg-pdpa', 'consent'],
  },
  {
    id: 'SGPDPA-PURPOSE-001',
    category: 'sg-pdpa-purpose',
    severity: 'medium',
    title: 'Privacy notice missing purpose statement',
    description: 'A privacy policy surface was found, but it does not clearly state the purposes for collecting, using, or disclosing personal data.',
    pattern: String.raw`purpose(?:s)?\s+of\s+(?:collection|use|disclosure)|collect(?:ion)?\s+of\s+personal\s+data`,
    flags: 'i',
    fixPrompt: 'Update the privacy notice to explain the purposes for collecting, using, and disclosing personal data under the Singapore PDPA.',
    appMappings: [],
    regulationMappings: [sgPdpaMapping('SGPDPA_12', 0.7)],
    addedIn: SG_PDPA_RULE_VERSION,
    enabled: true,
    tags: ['sg-pdpa', 'purpose', 'notice'],
  },
  {
    id: 'SGPDPA-SEC-001',
    category: 'sg-pdpa-security',
    severity: 'critical',
    title: 'Plaintext personal data in repository',
    description: 'Plaintext NRIC-like identifiers, passport references, or payment card-like values were found in repository data stores or fixtures.',
    pattern: String.raw`\b[STFG]\d{7}[A-Z]\b|\bpassport(?:_number)?\s*[:=]\s*['"][A-Z0-9]{6,}['"]|\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`,
    flags: 'i',
    fixPrompt: 'Remove plaintext personal data from repository fixtures, encrypt retained copies, and restrict access to production data under the Singapore PDPA protection obligation.',
    appMappings: [],
    regulationMappings: [sgPdpaMapping('SGPDPA_24', 0.88)],
    addedIn: SG_PDPA_RULE_VERSION,
    enabled: true,
    tags: ['sg-pdpa', 'security', 'personal-data'],
  },
];

const WEB_SURFACE_PATTERN = /\.(?:html?|tsx?|jsx?|mjs|cjs)$/i;
const PRIVACY_POLICY_PATH_PATTERN = /privacy|policy|notice/i;
const PRIVACY_POLICY_CONTENT_PATTERN = /privacy\s+(?:policy|notice)|personal\s+data/i;
const CONSENT_PATTERN = /consent|privacy\s+preferences|agree\s+to\s+the\s+collection|personal\s+data\s+consent/i;
const PURPOSE_PATTERN = /purpose(?:s)?\s+of\s+(?:collection|use|disclosure)|collect(?:ion)?\s+of\s+personal\s+data/i;
const PERSONAL_DATA_PATTERN = /\b[STFG]\d{7}[A-Z]\b|\bpassport(?:_number)?\s*[:=]\s*['"][A-Z0-9]{6,}['"]|\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/i;

export function scanSgPdpaChecks(files: SgPdpaCheckFile[], scannerVersion: string): AttestLensFinding[] {
  const findings: AttestLensFinding[] = [];
  const webFiles = files.filter((file) => WEB_SURFACE_PATTERN.test(file.relativePath));
  const privacyFiles = files.filter((file) =>
    PRIVACY_POLICY_PATH_PATTERN.test(file.relativePath) || PRIVACY_POLICY_CONTENT_PATTERN.test(file.content),
  );

  if (webFiles.length > 0 && !webFiles.some((file) => CONSENT_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'SGPDPA-CONSENT-001', webFiles[0]!, 'Expected PDPA consent mechanism was not found.'));
  }

  if (privacyFiles.length > 0 && !privacyFiles.some((file) => PURPOSE_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'SGPDPA-PURPOSE-001', privacyFiles[0]!, 'Expected PDPA purpose limitation disclosure was not found.'));
  }

  for (const file of files) {
    const match = findFirstMatch(file.content, PERSONAL_DATA_PATTERN);
    if (!match) {
      continue;
    }

    findings.push(makeFinding(
      scannerVersion,
      'SGPDPA-SEC-001',
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
  file: SgPdpaCheckFile,
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
  const rule = SG_PDPA_CHECKS.find((candidate) => candidate.id === ruleId);
  if (!rule) {
    throw new Error(`Unknown SG PDPA rule: ${ruleId}`);
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
    regulationMappings: rule.regulationMappings ?? [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion,
      rawOutput: {
        sourceRule: rule.id,
        file,
        line,
      },
      scannerCommand: 'attestlens sg-pdpa-checks',
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
