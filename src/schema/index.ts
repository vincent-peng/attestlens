/**
 * AttestLens — Unified Finding Schema
 * 
 * All scanner outputs are normalized into this schema.
 * This is the core data contract of the entire system.
 */

import { z } from 'zod';

// ─── Enums ───────────────────────────────────────────────────────────────────

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof Severity>;

export const ControlStatus = z.enum(['pass', 'fail', 'unknown']);
export type ControlStatus = z.infer<typeof ControlStatus>;

export const ScanSource = z.enum([
  'guardvibe',
  'vibesafe',
  'mcp-scan',
  'vibe-check',
  'supply-chain',
  'url-scan',
  'manual',
  'questionnaire',
]);
export type ScanSource = z.infer<typeof ScanSource>;

export const ReportFormat = z.enum(['json', 'html', 'pdf', 'sarif', 'markdown']);
export type ReportFormat = z.infer<typeof ReportFormat>;

// ─── APP Principles ─────────────────────────────────────────────────────────

export const APPPrinciple = z.enum([
  'APP_1',   // Open & transparent management
  'APP_2',   // Anonymity
  'APP_3',   // Collection of personal info
  'APP_4',   // Handling unsolicited info
  'APP_5',   // Notification of collection
  'APP_6',   // Use or disclosure
  'APP_7',   // Direct marketing
  'APP_8',   // Cross-border disclosure
  'APP_9',   // Adoption, use, disclosure of Gov IDs
  'APP_10',  // Quality of personal info
  'APP_11',  // Security of personal info
  'APP_12',  // Access to personal info
  'APP_13',  // Correction of personal info
  'NDB',     // Notifiable Data Breaches
]);
export type APPPrinciple = z.infer<typeof APPPrinciple>;

export const APPInfo: Record<APPPrinciple, { shortName: string; obligation: string }> = {
  APP_1:  { shortName: 'Open & Transparent',   obligation: 'Open and transparent management of personal information' },
  APP_2:  { shortName: 'Anonymity',             obligation: 'Anonymity option for individuals' },
  APP_3:  { shortName: 'Collection',            obligation: 'Lawful, fair, and necessary collection' },
  APP_4:  { shortName: 'Unsolicited Info',       obligation: 'Deal with unsolicited personal information' },
  APP_5:  { shortName: 'Notification',           obligation: 'Notify individuals of collection' },
  APP_6:  { shortName: 'Use & Disclosure',       obligation: 'Use or disclosure only for primary purpose' },
  APP_7:  { shortName: 'Direct Marketing',       obligation: 'Direct marketing restrictions and opt-out' },
  APP_8:  { shortName: 'Cross-Border',           obligation: 'Reasonable steps for overseas disclosure' },
  APP_9:  { shortName: 'Gov Identifiers',        obligation: 'Restricted use of government identifiers' },
  APP_10: { shortName: 'Data Quality',           obligation: 'Accurate, up-to-date, and complete information' },
  APP_11: { shortName: 'Security',               obligation: 'Reasonable steps to protect personal information' },
  APP_12: { shortName: 'Access',                 obligation: 'Individuals can access their information' },
  APP_13: { shortName: 'Correction',             obligation: 'Individuals can correct their information' },
  NDB:    { shortName: 'Data Breach Notification', obligation: 'Assess, notify, and remediate eligible data breaches' },
};

// ─── Core Schemas ────────────────────────────────────────────────────────────

export const APPMapping = z.object({
  principle: APPPrinciple,
  obligation: z.string(),
  status: ControlStatus,
  confidence: z.number().min(0).max(1),
  rationale: z.string().optional(),
});
export type APPMapping = z.infer<typeof APPMapping>;

export const FindingEvidence = z.object({
  timestamp: z.string().datetime(),
  scannerVersion: z.string(),
  rawOutput: z.unknown(), // Original scanner output for audit trail
  scannerCommand: z.string().optional(),
});
export type FindingEvidence = z.infer<typeof FindingEvidence>;

export const AttestLensFinding = z.object({
  id: z.string(),                       // Deterministic hash
  source: ScanSource,
  sourceRule: z.string(),               // e.g., "VG-SEC-001", "VS-HARDKEY", "AL-KEY-001"
  severity: Severity,
  category: z.string(),                  // e.g., "Security", "Auth", "Data Flow"
  title: z.string(),
  description: z.string(),
  file: z.string().optional(),
  line: z.number().optional(),
  code: z.string().optional(),          // Offending code snippet
  url: z.string().optional(),            // Source URL (for url-scan findings)
  fix: z.string().optional(),           // Suggested fix
  fixPrompt: z.string().optional(),     // AI-ready fix prompt for Cursor/Copilot
  appMappings: z.array(APPMapping),
  evidence: FindingEvidence,
});
export type AttestLensFinding = z.infer<typeof AttestLensFinding>;

// ─── Questionnaire ──────────────────────────────────────────────────────────

export const QuestionType = z.enum(['yes_no', 'yes_no_na', 'text', 'multi_choice']);
export type QuestionType = z.infer<typeof QuestionType>;

export const QuestionDependency = z.object({
  questionId: z.string(),
  answers: z.array(z.union([z.boolean(), z.string()])),
});
export type QuestionDependency = z.infer<typeof QuestionDependency>;

export const QuestionRole = z.enum(['control', 'applicability_gate', 'evidence']);
export type QuestionRole = z.infer<typeof QuestionRole>;

export const QuestionPassValue = z.enum(['yes', 'no']);
export type QuestionPassValue = z.infer<typeof QuestionPassValue>;

export const Question = z.object({
  id: z.string(),
  appPrinciple: APPPrinciple,
  question: z.string(),
  type: QuestionType,
  options: z.array(z.string()).optional(),
  required: z.boolean(),
  role: QuestionRole.optional(),
  passOn: QuestionPassValue.optional(),
  blocking: z.boolean().optional(),
  minimumSelectedOptions: z.number().int().positive().optional(),
  failOnOptions: z.array(z.string()).optional(),
  helpText: z.string().optional(),
  dependsOn: QuestionDependency.optional(),
  relatedFindings: z.array(z.string()).optional(), // Finding IDs
});
export type Question = z.infer<typeof Question>;

export const QuestionnaireEvaluation = z.object({
  status: ControlStatus,
  confidence: z.number().min(0).max(1),
  rationale: z.string(),
});
export type QuestionnaireEvaluation = z.infer<typeof QuestionnaireEvaluation>;

export const QuestionnaireResponse = z.object({
  questionId: z.string(),
  answer: z.union([z.boolean(), z.string(), z.array(z.string())]),
  timestamp: z.string().datetime(),
  answeredBy: z.string().optional(),
  note: z.string().optional(),
  evidenceRefs: z.array(z.string()).optional(),
  evaluation: QuestionnaireEvaluation.optional(),
});
export type QuestionnaireResponse = z.infer<typeof QuestionnaireResponse>;

export const QuestionnairePrincipleResult = z.object({
  principle: APPPrinciple,
  status: ControlStatus,
  confidence: z.number().min(0).max(1),
  rationale: z.string(),
  answeredQuestionIds: z.array(z.string()),
});
export type QuestionnairePrincipleResult = z.infer<typeof QuestionnairePrincipleResult>;

export const QuestionnaireSessionStatus = z.enum(['in_progress', 'completed']);
export type QuestionnaireSessionStatus = z.infer<typeof QuestionnaireSessionStatus>;

const QuestionnaireSessionBase = z.object({
  id: z.string(),
  status: QuestionnaireSessionStatus,
  target: z.object({
    kind: z.enum(['path', 'url']),
    name: z.string(),
    path: z.string().optional(),
    url: z.string().optional(),
  }),
  startedAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  completedAt: z.string().datetime().optional(),
  strictMode: z.boolean(),
  scanSnapshotPath: z.string(),
  findingsHash: z.string(),
  answers: z.array(QuestionnaireResponse),
  principleResults: z.array(QuestionnairePrincipleResult),
  currentQuestionId: z.string().optional(),
});
export const LegacyQuestionnaireSession = QuestionnaireSessionBase.extend({
  version: z.literal('1.0'),
});
export type LegacyQuestionnaireSession = z.infer<typeof LegacyQuestionnaireSession>;

export const TransitionalQuestionnaireSession = QuestionnaireSessionBase.extend({
  version: z.literal('1.1'),
  questionnaireVersion: z.string(),
  principles: z.array(APPPrinciple),
  sessionQuestions: z.array(Question),
});
export type TransitionalQuestionnaireSession = z.infer<typeof TransitionalQuestionnaireSession>;

export const QuestionnaireSession = QuestionnaireSessionBase.extend({
  version: z.literal('1.2'),
  questionnaireVersion: z.string(),
  principles: z.array(APPPrinciple),
  sessionQuestions: z.array(Question),
  questionSetHash: z.string(),
});
export type QuestionnaireSession = z.infer<typeof QuestionnaireSession>;

export const AnyQuestionnaireSession = z.union([
  LegacyQuestionnaireSession,
  TransitionalQuestionnaireSession,
  QuestionnaireSession,
]);
export type AnyQuestionnaireSession = z.infer<typeof AnyQuestionnaireSession>;

// ─── APP Control Assessment ─────────────────────────────────────────────────

export const APPControl = z.object({
  principle: APPPrinciple,
  shortName: z.string(),
  obligation: z.string(),
  status: ControlStatus,
  score: z.number().min(0).max(100),
  findingCount: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number(),
  }),
  findings: z.array(z.string()), // Finding IDs
  questionnaireRequired: z.boolean(),
  lastAssessed: z.string().datetime(),
});
export type APPControl = z.infer<typeof APPControl>;

// ─── Remediation ─────────────────────────────────────────────────────────────

export const RemediationPriority = z.enum(['quick_win', 'medium_effort', 'structural']);
export type RemediationPriority = z.infer<typeof RemediationPriority>;

export const RemediationItem = z.object({
  id: z.string(),
  findingIds: z.array(z.string()),
  priority: RemediationPriority,
  estimatedTime: z.string(),             // e.g., "<5 min", "1-2 hours", "1+ days"
  title: z.string(),
  description: z.string(),
  appReferences: z.array(APPPrinciple),
  fix: z.string().optional(),
  impact: z.string(),                   // What happens if not fixed
});
export type RemediationItem = z.infer<typeof RemediationItem>;

// ─── Compliance Report ──────────────────────────────────────────────────────

export const ReportGrade = z.enum(['A', 'B', 'C', 'D', 'F']);
export type ReportGrade = z.infer<typeof ReportGrade>;

export const ComplianceReport = z.object({
  id: z.string(),
  timestamp: z.string().datetime(),
  target: z.object({
    name: z.string(),
    path: z.string().optional(),
    url: z.string().optional(),
    version: z.string().optional(),
  }),
  overallScore: z.number().min(0).max(100),
  overallGrade: ReportGrade,
  riskLevel: z.enum(['low', 'medium', 'high', 'critical']),
  appControls: z.array(APPControl),
  findings: z.array(AttestLensFinding),
  questionnaire: z.array(QuestionnaireResponse).optional(),
  questionnaireResults: z.array(QuestionnairePrincipleResult).optional(),
  remediation: z.array(RemediationItem),
  metadata: z.object({
    scannerVersions: z.record(z.string(), z.string()),
    deterministicHash: z.string(),
    scanDurationMs: z.number(),
    configHash: z.string(),
  }),
  disclaimer: z.string(),
});
export type ComplianceReport = z.infer<typeof ComplianceReport>;

// ─── Scan Configuration ─────────────────────────────────────────────────────

export const ScannerConfig = z.object({
  guardvibe: z.object({
    enabled: z.boolean().default(true),
    path: z.string().optional(),         // Custom path to guardvibe binary
    tools: z.array(z.string()).optional(), // Specific tools to run
  }),
  mcpScan: z.object({
    enabled: z.boolean().default(true),
    path: z.string().optional(),
  }),
  vibeSafe: z.object({
    enabled: z.boolean().default(false),  // Phase 2
    apiKey: z.string().optional(),
  }),
  vibeCheck: z.object({
    enabled: z.boolean().default(false),  // Phase 2
    licenseKey: z.string().optional(),
  }),
});

export const AttestLensConfig = z.object({
  version: z.literal('1.0'),
  target: z.string(),                    // Path or URL to scan
  scanners: ScannerConfig,
  output: z.object({
    formats: z.array(ReportFormat).default(['json', 'html']),
    directory: z.string().default('./attestlens-reports'),
    branding: z.object({
      logo: z.string().optional(),
      primaryColor: z.string().default('#1a2332'),
      accentColor: z.string().default('#00b4d8'),
      companyName: z.string().optional(),
      disclaimer: z.string().optional(),
    }).optional(),
  }),
  compliance: z.object({
    frameworks: z.array(z.enum(['APP_NDB'])).default(['APP_NDB']),
    // Future: add 'GDPR', 'SOC2', 'HIPAA'
    includeQuestionnaire: z.boolean().default(true),
    strictMode: z.boolean().default(false), // Treat UNKNOWN as FAIL
  }),
});

export type AttestLensConfig = z.infer<typeof AttestLensConfig>;

// ─── Utility ─────────────────────────────────────────────────────────────────

/** Generate a deterministic hash for a finding (for audit trail integrity) */
export function generateFindingHash(finding: Omit<AttestLensFinding, 'id' | 'evidence'>): string {
  const crypto = require('crypto');
  const payload = JSON.stringify({
    source: finding.source,
    sourceRule: finding.sourceRule,
    severity: finding.severity,
    file: finding.file,
    line: finding.line,
    code: finding.code,
  });
  return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 16);
}

/** Calculate overall grade from score */
export function calculateGrade(score: number): ReportGrade {
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/** Calculate risk level from findings */
export function calculateRiskLevel(findings: AttestLensFinding[]): 'low' | 'medium' | 'high' | 'critical' {
  const criticals = findings.filter(f => f.severity === 'critical').length;
  const highs = findings.filter(f => f.severity === 'high').length;
  
  if (criticals > 0) return 'critical';
  if (highs >= 3) return 'high';
  if (highs >= 1) return 'medium';
  return 'low';
}
