/**
 * AttestLens — Unified Finding Schema
 * 
 * All scanner outputs are normalized into this schema.
 * This is the core data contract of the entire system.
 */

import { z } from 'zod';
import { reformImpactAssessmentSchema } from './reform.js';

// ─── Enums ───────────────────────────────────────────────────────────────────

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof Severity>;

export const ControlStatus = z.enum(['pass', 'fail', 'unknown']);
export type ControlStatus = z.infer<typeof ControlStatus>;

export const Jurisdiction = z.enum(['au-privacy-act', 'us-ccpa', 'eu-gdpr']);
export type Jurisdiction = z.infer<typeof Jurisdiction>;

export const JurisdictionInfo: Record<Jurisdiction, { shortName: string; fullName: string; citation: string }> = {
  'au-privacy-act': {
    shortName: 'AU Privacy Act',
    fullName: 'Australian Privacy Act 1988 (APPs + NDB)',
    citation: 'Privacy Act 1988 (Cth)',
  },
  'us-ccpa': {
    shortName: 'US CCPA/CPRA',
    fullName: 'California Consumer Privacy Act / California Privacy Rights Act',
    citation: 'Cal. Civ. Code §1798.100-199.100',
  },
  'eu-gdpr': {
    shortName: 'EU GDPR',
    fullName: 'General Data Protection Regulation',
    citation: 'Regulation (EU) 2016/679',
  },
};

export const ScanSource = z.enum([
  'guardvibe',
  'vibesafe',
  'mcp-scan',
  'vibe-check',
  'supply-chain',
  'behavioral',
  'gitleaks',
  'iac',
  'url-scan',
  'manual',
  'questionnaire',
  'reform-2026',
]);
export type ScanSource = z.infer<typeof ScanSource>;

export const ReportFormat = z.enum(['json', 'html', 'pdf', 'sarif', 'markdown', 'agent', 'smb']);
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

export const CCPAPrinciple = z.enum([
  'CCPA_100',
  'CCPA_105',
  'CCPA_106',
  'CCPA_110',
  'CCPA_115',
  'CCPA_120',
  'CCPA_121',
  'CCPA_125',
  'CCPA_130',
  'CCPA_135',
  'CCPA_145',
  'CCPA_150',
]);
export type CCPAPrinciple = z.infer<typeof CCPAPrinciple>;

export const GDPRPrinciple = z.enum([
  'GDPR_Art3',
  'GDPR_Art5',
  'GDPR_Art6',
  'GDPR_Art9',
  'GDPR_Art13',
  'GDPR_Art15',
  'GDPR_Art17',
  'GDPR_Art22',
  'GDPR_Art25',
  'GDPR_Art32',
  'GDPR_Art33',
  'GDPR_Art34',
  'GDPR_Art35',
  'GDPR_Art44',
]);
export type GDPRPrinciple = z.infer<typeof GDPRPrinciple>;

// ─── Core Schemas ────────────────────────────────────────────────────────────

// Phase 7 will refine this into per-jurisdiction principle validation.
export const RegulationPrinciple = z.string().min(1);
export type RegulationPrinciple = z.infer<typeof RegulationPrinciple>;

export const APPMapping = z.object({
  principle: APPPrinciple,
  obligation: z.string(),
  status: ControlStatus,
  confidence: z.number().min(0).max(1),
  rationale: z.string().optional(),
});
export type APPMapping = z.infer<typeof APPMapping>;

export const RegulationMapping = z.object({
  jurisdiction: Jurisdiction,
  principle: RegulationPrinciple,
  obligation: z.string(),
  status: ControlStatus,
  confidence: z.number().min(0).max(1),
  rationale: z.string().optional(),
  citation: z.string().optional(),
});
export type RegulationMapping = z.infer<typeof RegulationMapping>;

export function appMappingToRegulationMapping(mapping: APPMapping): RegulationMapping {
  return {
    jurisdiction: 'au-privacy-act',
    principle: mapping.principle,
    obligation: mapping.obligation,
    status: mapping.status,
    confidence: mapping.confidence,
    rationale: mapping.rationale,
  };
}

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
  corroboratedBy: z.array(ScanSource).optional(), // Other scanner sources merged into this finding
  regulationMappings: z.array(RegulationMapping).optional(),
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

export const AssessmentMode = z.enum(['artifact_only', 'codebase_only', 'operator_attested']);
export type AssessmentMode = z.infer<typeof AssessmentMode>;

export const Question = z.object({
  id: z.string(),
  appPrinciple: RegulationPrinciple,
  question: z.string(),
  type: QuestionType,
  options: z.array(z.string()).optional(),
  required: z.boolean(),
  role: QuestionRole.optional(),
  passOn: QuestionPassValue.optional(),
  blocking: z.boolean().optional(),
  minimumSelectedOptions: z.number().int().positive().optional(),
  failOnOptions: z.array(z.string()).optional(),
  assessmentModes: z.array(AssessmentMode).optional(),
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
  principle: RegulationPrinciple,
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
  principles: z.array(RegulationPrinciple),
  sessionQuestions: z.array(Question),
});
export type TransitionalQuestionnaireSession = z.infer<typeof TransitionalQuestionnaireSession>;

export const FrozenQuestionnaireSession = QuestionnaireSessionBase.extend({
  version: z.literal('1.2'),
  questionnaireVersion: z.string(),
  principles: z.array(RegulationPrinciple),
  sessionQuestions: z.array(Question),
  questionSetHash: z.string(),
});
export type FrozenQuestionnaireSession = z.infer<typeof FrozenQuestionnaireSession>;

export const QuestionnaireSession = QuestionnaireSessionBase.extend({
  version: z.literal('1.3'),
  questionnaireVersion: z.string(),
  principles: z.array(RegulationPrinciple),
  sessionQuestions: z.array(Question),
  questionSetHash: z.string(),
  assessmentMode: AssessmentMode,
});
export type QuestionnaireSession = z.infer<typeof QuestionnaireSession>;

export const AnyQuestionnaireSession = z.union([
  LegacyQuestionnaireSession,
  TransitionalQuestionnaireSession,
  FrozenQuestionnaireSession,
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

export const RegulationControl = z.object({
  jurisdiction: Jurisdiction,
  principle: RegulationPrinciple,
  shortName: z.string(),
  obligation: z.string(),
  status: ControlStatus,
  score: z.number().min(0).max(100),
  findingCount: z.object({
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
    info: z.number().int().nonnegative(),
  }),
  findings: z.array(z.string()),
  questionnaireRequired: z.boolean(),
  lastAssessed: z.string(),
  citation: z.string().optional(),
});
export type RegulationControl = z.infer<typeof RegulationControl>;

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
  appReferences: z.array(RegulationPrinciple),
  fix: z.string().optional(),
  impact: z.string(),                   // What happens if not fixed
});
export type RemediationItem = z.infer<typeof RemediationItem>;

// ─── Compliance Report ──────────────────────────────────────────────────────

export const ReportGrade = z.enum(['A', 'B', 'C', 'D', 'F']);
export type ReportGrade = z.infer<typeof ReportGrade>;

export const ReportAssessment = z.object({
  mode: AssessmentMode,
  summary: z.string(),
  incomplete: z.boolean(),
  unknownPrinciples: z.array(RegulationPrinciple),
});
export type ReportAssessment = z.infer<typeof ReportAssessment>;

export const BreachReadinessEvidenceBasis = z.enum(['scanner_only', 'artifact_only', 'codebase_only', 'operator_attested']);
export type BreachReadinessEvidenceBasis = z.infer<typeof BreachReadinessEvidenceBasis>;

export const BreachReadinessLevel = z.enum(['strong', 'moderate', 'limited', 'weak']);
export type BreachReadinessLevel = z.infer<typeof BreachReadinessLevel>;

export const BreachReadinessFactor = z.object({
  type: z.enum(['scanner', 'questionnaire', 'assessment_gap']),
  principle: RegulationPrinciple.optional(),
  severity: Severity,
  title: z.string(),
  detail: z.string(),
  findingIds: z.array(z.string()).optional(),
});
export type BreachReadinessFactor = z.infer<typeof BreachReadinessFactor>;

export const BreachReadiness = z.object({
  evidenceBasis: BreachReadinessEvidenceBasis,
  score: z.number().min(0).max(100),
  level: BreachReadinessLevel,
  confidence: z.number().min(0).max(1),
  summary: z.string(),
  topFactors: z.array(BreachReadinessFactor),
});
export type BreachReadiness = z.infer<typeof BreachReadiness>;

export const ConsultantNarrativePriority = z.enum(['immediate', 'near_term', 'monitor']);
export type ConsultantNarrativePriority = z.infer<typeof ConsultantNarrativePriority>;

export const PrincipleNarrative = z.object({
  principle: RegulationPrinciple,
  status: ControlStatus,
  priority: ConsultantNarrativePriority,
  summary: z.string(),
});
export type PrincipleNarrative = z.infer<typeof PrincipleNarrative>;

export const ConsultantNarrative = z.object({
  executiveSummary: z.string(),
  evidenceBasis: z.string(),
  keyRisks: z.array(z.string()),
  principleNarratives: z.array(PrincipleNarrative),
  remediationFocus: z.string(),
});
export type ConsultantNarrative = z.infer<typeof ConsultantNarrative>;

export const ComplianceVerdict = z.enum(['COMPLIANT', 'PARTIALLY_COMPLIANT', 'NON_COMPLIANT']);
export type ComplianceVerdict = z.infer<typeof ComplianceVerdict>;

export const OpinionConfidence = z.enum(['HIGH', 'MODERATE', 'LOW']);
export type OpinionConfidence = z.infer<typeof OpinionConfidence>;

export const PrincipleOpinion = z.object({
  principle: RegulationPrinciple,
  verdict: ComplianceVerdict,
  confidence: OpinionConfidence,
  score: z.number().min(0).max(100),
  summary: z.string(),
  evidenceCount: z.number().int().nonnegative(),
  corroboratedCount: z.number().int().nonnegative(),
  keyFindings: z.array(z.string()),
});
export type PrincipleOpinion = z.infer<typeof PrincipleOpinion>;

export const ComplianceOpinion = z.object({
  overallVerdict: ComplianceVerdict,
  overallConfidence: OpinionConfidence,
  signedBy: z.string(),
  signedAt: z.string().datetime(),
  principles: z.array(PrincipleOpinion),
  riskLevel: z.enum(['low', 'medium', 'high', 'critical']),
  score: z.number().min(0).max(100),
  disclaimer: z.string(),
});
export type ComplianceOpinion = z.infer<typeof ComplianceOpinion>;

// ─── Rule Pack Metadata ─────────────────────────────────────────────────────

export const RulePackSource = z.enum(['embedded', 'cache', 'remote']);
export type RulePackSource = z.infer<typeof RulePackSource>;

export const RuleDefinition = z.object({
  id: z.string(),
  category: z.string(),
  severity: Severity,
  title: z.string(),
  description: z.string(),
  pattern: z.string().optional(),
  flags: z.string().optional(),
  fixPrompt: z.string().optional(),
  regulationMappings: z.array(RegulationMapping).optional(),
  appMappings: z.array(APPMapping).default([]),
  cve: z.string().nullable().optional(),
  addedIn: z.string(),
  enabled: z.boolean().default(true),
  tags: z.array(z.string()).default([]),
});
export type RuleDefinition = z.infer<typeof RuleDefinition>;

export const RulePackManifest = z.object({
  schemaVersion: z.literal('1.0'),
  version: z.string(),
  generated: z.string().datetime(),
  rules: z.array(RuleDefinition),
  jurisdiction: Jurisdiction.default('au-privacy-act'),
});
export type RulePackManifest = z.infer<typeof RulePackManifest>;

export const JurisdictionPackManifest = z.object({
  schemaVersion: z.literal('2.0'),
  version: z.string(),
  jurisdiction: Jurisdiction,
  generated: z.string().datetime(),
  principles: z.array(z.object({
    id: RegulationPrinciple,
    shortName: z.string(),
    obligation: z.string(),
    citation: z.string().optional(),
  })),
  rules: z.array(RuleDefinition),
});
export type JurisdictionPackManifest = z.infer<typeof JurisdictionPackManifest>;

export const RuleFreshness = z.object({
  version: z.string(),
  generated: z.string().datetime(),
  loadedAt: z.string().datetime(),
  source: RulePackSource,
  ruleCount: z.number().int().nonnegative(),
  ageDays: z.number().int().nonnegative(),
  stale: z.boolean(),
});
export type RuleFreshness = z.infer<typeof RuleFreshness>;

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
  regulationControls: z.array(RegulationControl).optional(),
  findings: z.array(AttestLensFinding),
  questionnaire: z.array(QuestionnaireResponse).optional(),
  questionnaireResults: z.array(QuestionnairePrincipleResult).optional(),
  assessment: ReportAssessment.optional(),
  breachReadiness: BreachReadiness.optional(),
  consultantNarrative: ConsultantNarrative.optional(),
  complianceOpinion: ComplianceOpinion.optional(),
  reformImpactAssessment: reformImpactAssessmentSchema.optional(),
  remediation: z.array(RemediationItem),
  metadata: z.object({
    scannerVersions: z.record(z.string(), z.string()),
    deterministicHash: z.string(),
    scanDurationMs: z.number(),
    configHash: z.string(),
    ruleFreshness: RuleFreshness.optional(),
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

export { ReformProvision, ReformProvisionInfo, reformProvisionSchema, reformFindingSchema, reformImpactAssessmentSchema } from './reform.js';
export type { ReformFinding, ReformImpactAssessment } from './reform.js';
