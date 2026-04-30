import crypto from 'node:crypto';

import type { AttestLensFinding, ControlStatus, RuleDefinition, Severity } from '../../schema/index.js';
import { GDPRPrincipleInfo } from './gdpr-principles.js';

export interface GdprCheckFile {
  relativePath: string;
  content: string;
}

const GDPR_RULE_VERSION = '2026.04.30';
const GDPR_APPLICABILITY_ADVISORY =
  'Advisory only: confirm GDPR applies and the business processes EU residents\' data before treating as a failure.';

function gdprMapping(
  principle: keyof typeof GDPRPrincipleInfo,
  confidence: number,
  citation = GDPRPrincipleInfo[principle].citation,
  status: ControlStatus = 'fail',
) {
  return {
    jurisdiction: 'eu-gdpr' as const,
    principle,
    obligation: GDPRPrincipleInfo[principle].obligation,
    status,
    confidence,
    citation,
  };
}

export const GDPR_CHECKS: RuleDefinition[] = [
  {
    id: 'GDPR-CONSENT-001',
    category: 'gdpr-consent',
    severity: 'high',
    title: 'Missing consent mechanism',
    description: `No cookie consent, consent banner, or consent preference mechanism was found in HTML or JavaScript surfaces. ${GDPR_APPLICABILITY_ADVISORY}`,
    pattern: String.raw`cookie\s+consent|consent\s+(?:banner|manager|notice|preference)|Cookiebot|OneTrust|Didomi|\bCMP\b|privacy\s+preferences`,
    flags: 'i',
    fixPrompt: 'Add a consent mechanism where consent is the lawful basis for processing, and record the legal basis for each processing purpose.',
    appMappings: [],
    regulationMappings: [gdprMapping('GDPR_Art6', 0.5, 'GDPR Art. 6(1)', 'unknown')],
    addedIn: GDPR_RULE_VERSION,
    enabled: true,
    tags: ['gdpr', 'consent', 'lawful-basis'],
  },
  {
    id: 'GDPR-PRIVACY-001',
    category: 'gdpr-notice',
    severity: 'high',
    title: 'Privacy policy missing GDPR Art 13 disclosures',
    description: `A privacy policy surface was found, but required GDPR notice signals such as DPO/contact, supervisory authority, right to object, or automated decision-making disclosures were incomplete. ${GDPR_APPLICABILITY_ADVISORY}`,
    pattern: String.raw`data\s+protection\s+officer|supervisory\s+authority|right\s+to\s+object|automated\s+decision(?:-making)?`,
    flags: 'i',
    fixPrompt: 'Update the privacy notice to include GDPR Art 13/14 disclosures, including controller identity, legal basis, recipients, transfers, retention, rights, DPA complaint rights, and automated decision-making logic.',
    appMappings: [],
    regulationMappings: [gdprMapping('GDPR_Art13', 0.5, 'GDPR Art. 13-14', 'unknown')],
    addedIn: GDPR_RULE_VERSION,
    enabled: true,
    tags: ['gdpr', 'privacy-notice', 'transparency'],
  },
  {
    id: 'GDPR-TRANSFER-001',
    category: 'gdpr-transfer',
    severity: 'high',
    title: 'International transfer without safeguards',
    description: `International or third-country transfer language was found, but Standard Contractual Clauses, Binding Corporate Rules, adequacy decisions, or equivalent safeguards were not found. ${GDPR_APPLICABILITY_ADVISORY}`,
    pattern: String.raw`standard\s+contractual\s+clauses|\bSCCs?\b|binding\s+corporate\s+rules|\bBCRs?\b|adequacy\s+decision|appropriate\s+safeguards`,
    flags: 'i',
    fixPrompt: 'Document the transfer mechanism for data sent outside the EEA, such as adequacy decision, SCCs, BCRs, or another Art 44-49 safeguard.',
    appMappings: [],
    regulationMappings: [gdprMapping('GDPR_Art44', 0.5, 'GDPR Art. 44-49', 'unknown')],
    addedIn: GDPR_RULE_VERSION,
    enabled: true,
    tags: ['gdpr', 'transfer', 'cross-border'],
  },
  {
    id: 'GDPR-DPIA-001',
    category: 'gdpr-dpia',
    severity: 'medium',
    title: 'High-risk processing without DPIA',
    description: `Profiling, systematic monitoring, large-scale sensitive processing, or new-technology signals were found without DPIA documentation. ${GDPR_APPLICABILITY_ADVISORY}`,
    pattern: String.raw`data\s+protection\s+impact\s+assessment|\bDPIA\b|impact\s+assessment`,
    flags: 'i',
    fixPrompt: 'Complete and retain a Data Protection Impact Assessment for high-risk processing before deployment.',
    appMappings: [],
    regulationMappings: [gdprMapping('GDPR_Art35', 0.5, 'GDPR Art. 35(1)', 'unknown')],
    addedIn: GDPR_RULE_VERSION,
    enabled: true,
    tags: ['gdpr', 'dpia', 'high-risk'],
  },
  {
    id: 'GDPR-ART22-001',
    category: 'gdpr-automated',
    severity: 'high',
    title: 'Automated decisions without safeguards',
    description: `Automated decision-making, profiling, or scoring signals were found without human review, appeal, or safeguard hooks. ${GDPR_APPLICABILITY_ADVISORY}`,
    pattern: String.raw`human\s+review|manual\s+review|human\s+intervention|appeal|contest|safeguard|meaningful\s+review`,
    flags: 'i',
    fixPrompt: 'Add human review, contest/appeal paths, and documented Art 22 safeguards for automated decisions with legal or similarly significant effects.',
    appMappings: [],
    regulationMappings: [gdprMapping('GDPR_Art22', 0.5, 'GDPR Art. 22(1)', 'unknown')],
    addedIn: GDPR_RULE_VERSION,
    enabled: true,
    tags: ['gdpr', 'automated-decisions', 'profiling'],
  },
  {
    id: 'GDPR-SEC-001',
    category: 'gdpr-security',
    severity: 'critical',
    title: 'Unencrypted special category data',
    description: 'Plaintext special category data such as health, biometric, racial, religious, or sexual orientation data was found in repository data stores or fixtures.',
    pattern: String.raw`['"]?(?:health[_ -]?(?:condition|data|record)?|medical[_ -]?record|diagnosis|biometric[_ -]?(?:template|data)|fingerprint|faceprint|racial[_ -]?origin|ethnic(?:ity|[_ -]?origin)?|religious?[_ -]?(?:belief|data)?|sexual[_ -]?orientation)['"]?\s*[:=]\s*['"][^'"]{2,}`,
    flags: 'i',
    fixPrompt: 'Remove plaintext special category data, encrypt required data at rest, and document explicit consent or the applicable Art 9(2) exemption.',
    appMappings: [],
    regulationMappings: [gdprMapping('GDPR_Art9', 0.85, 'GDPR Art. 9(1)')],
    addedIn: GDPR_RULE_VERSION,
    enabled: true,
    tags: ['gdpr', 'special-category', 'security'],
  },
];

const WEB_SURFACE_PATTERN = /\.(?:html?|tsx?|jsx?|mjs|cjs)$/i;
const PRIVACY_POLICY_PATH_PATTERN = /privacy|policy|notice/i;
const PRIVACY_POLICY_CONTENT_PATTERN = /privacy\s+(?:policy|notice)|personal\s+data|data\s+subject/i;
const CONSENT_PATTERN = /cookie\s+consent|consent\s+(?:banner|manager|notice|preference)|Cookiebot|OneTrust|Didomi|\bCMP\b|privacy\s+preferences/i;
const GDPR_NOTICE_PATTERNS = [
  /data\s+protection\s+officer|\bDPO\b/i,
  /supervisory\s+authority|data\s+protection\s+authority|\bDPA\b/i,
  /right\s+to\s+object/i,
  /automated\s+decision(?:-making)?|meaningful\s+information\s+about\s+the\s+logic/i,
] as const;
const TRANSFER_SIGNAL_PATTERN = /transfer.*(?:outside|third.?country|international|eea|european\s+economic\s+area)|outside\s+the\s+eea|third.?country|international\s+transfer|cross.?border|data\s+transfer/i;
const TRANSFER_SAFEGUARD_PATTERN = /standard\s+contractual\s+clauses|\bSCCs?\b|binding\s+corporate\s+rules|\bBCRs?\b|adequacy\s+decision|appropriate\s+safeguards|derogation|art(?:icle)?\.?\s*49/i;
const DPIA_TRIGGER_PATTERN = /profiling|automated\s+decision(?:-making)?|algorithmic\s+decision|large.?scale.*sensitive|systematic\s+monitoring|new\s+technolog/i;
const DPIA_DOCUMENTED_PATTERN = /data\s+protection\s+impact\s+assessment|\bDPIA\b|impact\s+assessment/i;
const AUTOMATED_DECISION_PATTERN = /solely\s+automated|automated\s*decision(?:-making)?|automatedDecision|algorithmic\s+decision|profiling|credit\s+scoring|risk\s+scoring|eligibility\s+score/i;
const HUMAN_REVIEW_PATTERN = /human\s+review|manual\s+review|human\s+intervention|appeal|contest|safeguard|meaningful\s+review|caseworker\s+review/i;
const SPECIAL_CATEGORY_PATTERN = /['"]?(?:health[_ -]?(?:condition|data|record)?|medical[_ -]?record|diagnosis|biometric[_ -]?(?:template|data)|fingerprint|faceprint|racial[_ -]?origin|ethnic(?:ity|[_ -]?origin)?|religious?[_ -]?(?:belief|data)?|sexual[_ -]?orientation)['"]?\s*[:=]\s*['"][^'"]{2,}/i;

export function scanGdprChecks(files: GdprCheckFile[], scannerVersion: string): AttestLensFinding[] {
  const findings: AttestLensFinding[] = [];
  const webFiles = files.filter((file) => WEB_SURFACE_PATTERN.test(file.relativePath));
  const privacyFiles = files.filter((file) =>
    PRIVACY_POLICY_PATH_PATTERN.test(file.relativePath) || PRIVACY_POLICY_CONTENT_PATTERN.test(file.content),
  );
  const combinedContent = files.map((file) => file.content).join('\n');

  if (webFiles.length > 0 && !webFiles.some((file) => CONSENT_PATTERN.test(file.content))) {
    findings.push(makeMissingFinding(scannerVersion, 'GDPR-CONSENT-001', webFiles[0]!, 'Expected GDPR consent mechanism was not found.'));
  }

  if (privacyFiles.length > 0 && !hasCompleteGdprNotice(privacyFiles.map((file) => file.content).join('\n'))) {
    findings.push(makeMissingFinding(scannerVersion, 'GDPR-PRIVACY-001', privacyFiles[0]!, 'Expected GDPR Art 13/14 disclosure signals were not found.'));
  }

  if (TRANSFER_SIGNAL_PATTERN.test(combinedContent) && !TRANSFER_SAFEGUARD_PATTERN.test(combinedContent)) {
    const file = files.find((candidate) => TRANSFER_SIGNAL_PATTERN.test(candidate.content)) || files[0];
    if (file) {
      findings.push(makeMissingFinding(scannerVersion, 'GDPR-TRANSFER-001', file, 'Expected GDPR international-transfer safeguards were not found.'));
    }
  }

  if (DPIA_TRIGGER_PATTERN.test(combinedContent) && !DPIA_DOCUMENTED_PATTERN.test(combinedContent)) {
    const file = files.find((candidate) => DPIA_TRIGGER_PATTERN.test(candidate.content)) || files[0];
    if (file) {
      findings.push(makeMissingFinding(scannerVersion, 'GDPR-DPIA-001', file, 'Expected DPIA documentation was not found for high-risk processing signals.'));
    }
  }

  if (AUTOMATED_DECISION_PATTERN.test(combinedContent) && !HUMAN_REVIEW_PATTERN.test(combinedContent)) {
    const file = files.find((candidate) => AUTOMATED_DECISION_PATTERN.test(candidate.content)) || files[0];
    if (file) {
      findings.push(makeMissingFinding(scannerVersion, 'GDPR-ART22-001', file, 'Expected human review or Art 22 safeguards were not found.'));
    }
  }

  for (const file of files) {
    const match = findFirstMatch(file.content, SPECIAL_CATEGORY_PATTERN);
    if (!match) {
      continue;
    }
    findings.push(makeFinding(
      scannerVersion,
      'GDPR-SEC-001',
      file.relativePath,
      match.line,
      match.code,
    ));
  }

  return findings;
}

function hasCompleteGdprNotice(content: string): boolean {
  return GDPR_NOTICE_PATTERNS.every((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(content);
  });
}

function makeMissingFinding(
  scannerVersion: string,
  ruleId: string,
  file: GdprCheckFile,
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
  const rule = GDPR_CHECKS.find((candidate) => candidate.id === ruleId);
  if (!rule) {
    throw new Error(`Unknown GDPR rule: ${ruleId}`);
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
      scannerCommand: 'attestlens gdpr-checks',
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
