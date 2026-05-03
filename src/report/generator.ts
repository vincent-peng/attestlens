/**
 * AttestLens — Report Generator
 * 
 * Generates compliance reports in HTML, JSON, Markdown, and PDF formats.
 * Takes scanner findings + mapping results and produces the final deliverable.
 */

import crypto from 'node:crypto';
import { PassThrough } from 'node:stream';
import type PDFDocument from 'pdfkit';
import type {
  AnyJurisdictionPackManifest,
  AttestLensFinding,
  APPControl,
  APPPrinciple,
  Jurisdiction,
  JurisdictionCoverage,
  PackValidation,
  PackValidationStatus,
  ReportAssessment,
  ComplianceReport,
  AssessmentMode,
  RemediationItem,
  ControlStatus,
  Severity,
  QuestionnaireSession,
  RuleFreshness,
  RegulationControl,
  ReformImpactAssessment,
  ReformProvision as ReformProvisionName,
  ScopeQualifiedVerdict,
} from '../schema/index.js';
import {
  APPInfo,
  ReformProvision,
  ReformProvisionInfo,
  RuleFreshness as RuleFreshnessSchema,
  calculateGrade,
  calculateRiskLevel,
  reformProvisionSchema,
} from '../schema/index.js';
import { mapAllFindings } from '../mapping/engine.js';
import { getRegistry } from '../jurisdiction/registry.js';
import { getQuestionById } from '../questionnaire/index.js';
import { buildComplianceOpinion } from '../opinion/engine.js';
import { buildEmbeddedJurisdictionPack } from '../scanner/rules/embedded.js';
import { sanitizeTargetPathForOutput, sanitizeTargetUrlForOutput } from '../utils/target.js';
import { buildSMBComplianceResult } from './smb-generator.js';
import type { SMBComplianceResult } from './smb-generator.js';
import { ATTESTLENS_VERSION } from '../version.js';
const GDPR_SCOPE_NOTE =
  'This assessment covers a subset of GDPR articles (Art 3,5,6,9,13-14,15,17,22,25,32,33-34,35,44-49). Other articles are deferred.';

export const SUPPORTED_REPORT_FORMATS = ['json', 'html', 'markdown', 'pdf', 'sarif', 'agent', 'smb'] as const;
export type ReportFormat = (typeof SUPPORTED_REPORT_FORMATS)[number];
type BreachReadiness = NonNullable<ComplianceReport['breachReadiness']>;
type BreachReadinessFactor = BreachReadiness['topFactors'][number];
type ConsultantNarrative = NonNullable<ComplianceReport['consultantNarrative']>;
export type ComplianceReportWithSMB = ComplianceReport & { smbCompliance?: SMBComplianceResult };

function getPrincipleInfo(jurisdiction: Jurisdiction, principle: RegulationControl['principle']) {
  return getRegistry(jurisdiction).principles[principle];
}

// ─── Report Builder ─────────────────────────────────────────────────────────

export interface ReportOptions {
  targetName: string;
  targetPath?: string;
  targetUrl?: string;
  targetVersion?: string;
  formats: ReportFormat[];
  outputDir: string;
  strictMode?: boolean; // Treat UNKNOWN as FAIL
  includeOpinion?: boolean; // Include compliance opinion in report
  includeReform?: boolean; // Include Privacy Act 2026 reform impact assessment
  includeSMB?: boolean; // Include plain-English SMB compliance result
  ruleFreshness?: RuleFreshness;
  jurisdiction?: Jurisdiction;
  jurisdictionPack?: AnyJurisdictionPackManifest;
  packCoverage?: JurisdictionCoverage;
  packValidation?: PackValidation;
  packValidationTrusted?: boolean;
  branding?: {
    logo?: string;
    primaryColor?: string;
    accentColor?: string;
    companyName?: string;
    disclaimer?: string;
  };
}

export function buildComplianceReport(
  findings: AttestLensFinding[],
  options: ReportOptions,
  durationMs: number,
  questionnaireSession?: QuestionnaireSession,
): ComplianceReport {
  const jurisdiction = options.jurisdiction ?? 'au-privacy-act';
  const packMetadata = resolvePackMetadata(jurisdiction, options);

  // Step 1: Map findings to regulation obligations.
  // When questionnaire results are present, keep UNKNOWN controls as-is
  // until the questionnaire merge has a chance to resolve them.
  const { controls: regulationControls } = mapAllFindings(findings, {
    strictMode: questionnaireSession ? false : options.strictMode,
    jurisdictions: [jurisdiction],
  });
  const activeControls = regulationControls;
  const mappedFindings = findings; // findings now have appMappings populated by mapAllFindings

  // Step 2: Merge questionnaire outcomes, then apply strict mode to anything
  // still unresolved.
  if (questionnaireSession) {
    mergeQuestionnaireResults(activeControls, questionnaireSession);

    if (options.strictMode) {
      applyStrictModeToUnknownControls(activeControls);
    }
  }

  const appControls = activeControls
    .filter((control): control is RegulationControl & { jurisdiction: 'au-privacy-act'; principle: APPPrinciple } => (
      control.jurisdiction === 'au-privacy-act'
      && Object.prototype.hasOwnProperty.call(APPInfo, control.principle)
    ))
    .map(regulationControlToAPPControl);

  const assessment = buildReportAssessment(questionnaireSession, activeControls);

  // Step 3: Calculate overall score and grade
  const overallScore = applyIncompleteAssessmentScoreCap(calculateOverallScore(activeControls), assessment);
  const overallGrade = calculateGrade(overallScore);
  const riskLevel = applyIncompleteAssessmentRiskFloor(calculateRiskLevel(mappedFindings), assessment);

  // Step 4: Generate M2 consultant-facing assessment layers
  const breachReadiness = buildBreachReadiness(mappedFindings, activeControls, assessment, questionnaireSession);
  const remediation = generateRemediation(mappedFindings);
  const consultantNarrative = buildConsultantNarrative(
    activeControls,
    mappedFindings,
    remediation,
    assessment,
    breachReadiness,
  );
  const targetPath = sanitizeTargetPathForOutput(options.targetPath);
  const targetUrl = sanitizeTargetUrlForOutput(options.targetUrl);

  const timestamp = new Date().toISOString();

  // Step 5: Build the report
  const baseDisclaimer = options.branding?.disclaimer ||
    'This report is generated by AttestLens and does not constitute legal advice. ' +
    'Consult a qualified privacy professional for formal compliance assessment.';
  const disclaimer = jurisdiction === 'eu-gdpr'
    ? `${baseDisclaimer} ${GDPR_SCOPE_NOTE}`
    : baseDisclaimer;

  const report: ComplianceReportWithSMB = {
    id: crypto.randomUUID(),
    timestamp,
    target: {
      name: options.targetName,
      path: targetPath,
      url: targetUrl,
      version: options.targetVersion,
    },
    overallScore,
    overallGrade,
    riskLevel,
    appControls,
    regulationControls,
    findings: mappedFindings,
    questionnaire: questionnaireSession?.answers,
    questionnaireResults: questionnaireSession?.principleResults,
    assessment,
    breachReadiness,
    consultantNarrative,
    reformImpactAssessment: options.includeReform
      ? buildReformImpactAssessment(mappedFindings, timestamp)
      : undefined,
    remediation,
    metadata: {
      scannerVersions: {},
      deterministicHash: buildDeterministicHash(mappedFindings, assessment, breachReadiness),
      scanDurationMs: durationMs,
      configHash: '',
      ruleFreshness: options.ruleFreshness ? RuleFreshnessSchema.parse(options.ruleFreshness) : undefined,
      packCoverage: packMetadata.coverage,
      packValidation: packMetadata.validation,
    },
    disclaimer,
  };

  // Attach compliance opinion if requested
  if (options.includeOpinion) {
    report.complianceOpinion = buildComplianceOpinion(report, { strictMode: options.strictMode });
    applyPackTrustToOpinion(report, packMetadata.validationTrusted);
  }

  if (options.formats.includes('smb') || options.includeSMB) {
    report.smbCompliance = buildSMBComplianceResult(report, questionnaireSession);
  }

  return report;
}

function resolvePackMetadata(
  jurisdiction: Jurisdiction,
  options: ReportOptions,
): { coverage?: JurisdictionCoverage; validation?: PackValidation; validationTrusted: boolean } {
  if (options.packCoverage || options.packValidation) {
    return {
      coverage: options.packCoverage ?? buildUnknownCoverage(jurisdiction),
      validation: options.packValidation ?? buildUnvalidatedPackMetadata(),
      validationTrusted: options.packValidationTrusted === true,
    };
  }

  if (options.jurisdictionPack) {
    return {
      coverage: options.jurisdictionPack.coverage ?? buildUnknownCoverage(jurisdiction, options.jurisdictionPack),
      validation: options.jurisdictionPack.validation ?? buildUnvalidatedPackMetadata(),
      validationTrusted: options.packValidationTrusted === true,
    };
  }

  const embedded = buildEmbeddedJurisdictionPack(jurisdiction);
  return {
    coverage: embedded.coverage,
    validation: embedded.validation,
    validationTrusted: true,
  };
}

function buildUnknownCoverage(
  jurisdiction: Jurisdiction,
  jurisdictionPack?: AnyJurisdictionPackManifest,
): JurisdictionCoverage {
  return {
    summary: `No explicit coverage metadata was supplied for the ${jurisdiction} jurisdiction pack. Treat results as limited to the configured deterministic rule set.`,
    includedPrinciples: jurisdictionPack?.principles.map((principle) => principle.id) ?? [],
    excludedPrinciples: [],
    knownGaps: ['Coverage boundary metadata was not supplied by this pack.'],
    evidenceTypes: [],
  };
}

function buildUnvalidatedPackMetadata(): PackValidation {
  return {
    status: 'draft',
    notes: ['No explicit validation metadata was supplied by this pack.'],
  };
}

function applyPackTrustToOpinion(report: ComplianceReport, validationTrusted: boolean): void {
  const opinion = report.complianceOpinion;
  const validation = report.metadata.packValidation;
  if (!opinion || !validation) {
    return;
  }
  if (validationTrusted && isExternallyValidated(validation.status)) {
    return;
  }

  if (opinion.overallVerdict === 'COMPLIANT') {
    opinion.scopedVerdict = report.findings.length === 0
      ? 'NO_FINDINGS_IN_SCOPE'
      : 'PASS_NO_IN_SCOPE_BLOCKERS';
    opinion.scopeReason = `Pack validation status is ${validation.status}${validationTrusted ? '' : ' from untrusted pack metadata'}; this is a scoped technical result, not a broad compliance conclusion.`;
    opinion.overallVerdict = 'PARTIALLY_COMPLIANT';
  } else if (validation.status === 'draft') {
    opinion.scopedVerdict = 'NEEDS_REVIEW';
    opinion.scopeReason = 'Draft jurisdiction pack results are advisory and require human review before production gating.';
  }
}

function isExternallyValidated(status: PackValidationStatus): boolean {
  return status === 'external_reviewed'
    || status === 'customer_validated'
    || status === 'legal_partner_validated';
}

function buildDeterministicHash(
  findings: AttestLensFinding[],
  assessment?: ReportAssessment,
  breachReadiness?: BreachReadiness,
): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify({
      findings: findings.map((finding) => finding.id).sort(),
      assessment: assessment
        ? {
          mode: assessment.mode,
          incomplete: assessment.incomplete,
          unknownPrinciples: [...assessment.unknownPrinciples],
        }
        : null,
      breachReadiness: breachReadiness
        ? {
          evidenceBasis: breachReadiness.evidenceBasis,
          score: breachReadiness.score,
          level: breachReadiness.level,
          confidence: breachReadiness.confidence,
          topFactors: breachReadiness.topFactors.map((factor) => ({
            type: factor.type,
            principle: factor.principle,
            severity: factor.severity,
            title: factor.title,
            findingIds: factor.findingIds,
          })),
        }
        : null,
    }))
    .digest('hex')
    .substring(0, 32);
}

function mergeQuestionnaireResults(
  controls: RegulationControl[],
  questionnaireSession: QuestionnaireSession,
): void {
  const resultMap = new Map<string, QuestionnaireSession['principleResults'][number]>(
    questionnaireSession.principleResults.map((result) => [result.principle, result]),
  );

  for (const control of controls) {
    if (control.status !== 'unknown') {
      continue;
    }

    const questionnaireResult = resultMap.get(control.principle);
    if (!questionnaireResult || questionnaireResult.status === 'unknown') {
      continue;
    }

    control.status = questionnaireResult.status;
    control.questionnaireRequired = false;
    control.lastAssessed = new Date().toISOString();

    if (questionnaireResult.status === 'fail') {
      control.score = 0;
    }
  }
}

function applyStrictModeToUnknownControls(controls: RegulationControl[]): void {
  for (const control of controls) {
    if (control.status !== 'unknown') {
      continue;
    }

    control.status = 'fail';
    control.score = 0;
    control.questionnaireRequired = false;
  }
}

function buildReportAssessment(
  questionnaireSession: QuestionnaireSession | undefined,
  controls: RegulationControl[],
): ReportAssessment | undefined {
  if (!questionnaireSession) {
    return undefined;
  }

  const unknownPrinciples = controls
    .filter((control) => control.status === 'unknown')
    .map((control) => control.principle);

  return {
    mode: questionnaireSession.assessmentMode,
    summary: getAssessmentModeSummary(questionnaireSession.assessmentMode),
    incomplete: unknownPrinciples.length > 0,
    unknownPrinciples,
  };
}

function regulationControlToAPPControl(
  control: RegulationControl & { jurisdiction: 'au-privacy-act'; principle: APPPrinciple },
): APPControl {
  const info = getPrincipleInfo(control.jurisdiction, control.principle);
  return {
    principle: control.principle,
    shortName: info?.shortName ?? control.shortName,
    obligation: info?.obligation ?? control.obligation,
    status: control.status,
    score: control.score,
    findingCount: control.findingCount,
    findings: control.findings,
    questionnaireRequired: control.questionnaireRequired,
    lastAssessed: control.lastAssessed,
  };
}

function appControlToRegulationControl(control: APPControl): RegulationControl {
  const info = getPrincipleInfo('au-privacy-act', control.principle);
  return {
    jurisdiction: 'au-privacy-act',
    principle: control.principle,
    shortName: info?.shortName ?? control.shortName,
    obligation: info?.obligation ?? control.obligation,
    status: control.status,
    score: control.score,
    findingCount: control.findingCount,
    findings: control.findings,
    questionnaireRequired: control.questionnaireRequired,
    lastAssessed: control.lastAssessed,
  };
}

function getReportControls(report: ComplianceReport): RegulationControl[] {
  if (
    report.regulationControls
    && report.regulationControls.length > 0
    && report.regulationControls.some((control) => control.jurisdiction !== 'au-privacy-act')
  ) {
    return report.regulationControls;
  }

  return report.appControls.map(appControlToRegulationControl);
}

function getReportJurisdiction(report: ComplianceReport): Jurisdiction {
  return getReportControls(report)[0]?.jurisdiction ?? 'au-privacy-act';
}

function getFrameworkLabel(report: ComplianceReport): string {
  const jurisdiction = getReportJurisdiction(report);
  if (jurisdiction === 'us-ccpa') {
    return 'CCPA / CPRA (California Consumer Privacy Act)';
  }
  if (jurisdiction === 'eu-gdpr') {
    return 'General Data Protection Regulation (GDPR)';
  }
  if (jurisdiction === 'sg-pdpa') {
    return 'Singapore Personal Data Protection Act (PDPA)';
  }
  return 'APP / NDB (Privacy Act 1988)';
}

function getReportTitle(report: ComplianceReport): string {
  const jurisdiction = getReportJurisdiction(report);
  if (jurisdiction === 'us-ccpa') {
    return 'California Consumer Privacy Act (CCPA/CPRA) Compliance Report';
  }
  if (jurisdiction === 'eu-gdpr') {
    return 'General Data Protection Regulation (GDPR) — Subset Compliance Report';
  }
  if (jurisdiction === 'sg-pdpa') {
    return 'Singapore Personal Data Protection Act (PDPA) Compliance Report';
  }
  return 'Privacy Act Compliance Report';
}

function getControlChecklistTitle(report: ComplianceReport): string {
  const jurisdiction = getReportJurisdiction(report);
  if (jurisdiction === 'us-ccpa') {
    return 'CCPA/CPRA Control Checklist';
  }
  if (jurisdiction === 'eu-gdpr') {
    return 'GDPR Subset Control Checklist';
  }
  if (jurisdiction === 'sg-pdpa') {
    return 'SG PDPA Control Checklist';
  }
  return 'APP Control Checklist';
}

function getReportScopeNote(report: ComplianceReport): string | null {
  return report.metadata.packCoverage?.summary
    ?? (getReportJurisdiction(report) === 'eu-gdpr' ? GDPR_SCOPE_NOTE : null);
}

function getPackValidationLine(validation?: PackValidation): string | null {
  if (!validation) {
    return null;
  }
  return `${formatPackValidationStatus(validation.status)}${validation.reviewedBy ? ` (${validation.reviewedBy})` : ''}`;
}

function formatPackValidationStatus(status: PackValidationStatus): string {
  return status
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function formatScopedVerdict(verdict: ScopeQualifiedVerdict): string {
  return verdict.replace(/_/g, ' ');
}

function getOpinionDisplayVerdict(opinion: NonNullable<ComplianceReport['complianceOpinion']>): string {
  return opinion.scopedVerdict ? formatScopedVerdict(opinion.scopedVerdict) : opinion.overallVerdict.replace(/_/g, ' ');
}

function applyIncompleteAssessmentScoreCap(
  overallScore: number,
  assessment?: ReportAssessment,
): number {
  if (!assessment?.incomplete) {
    return overallScore;
  }

  return Math.min(overallScore, 69);
}

function applyIncompleteAssessmentRiskFloor(
  riskLevel: ComplianceReport['riskLevel'],
  assessment?: ReportAssessment,
): ComplianceReport['riskLevel'] {
  if (!assessment?.incomplete || riskLevel !== 'low') {
    return riskLevel;
  }

  return 'medium';
}

// ─── Breach Readiness ───────────────────────────────────────────────────────

type InternalBreachReadinessFactor = BreachReadinessFactor & { deduction: number };

const BREACH_RELEVANT_PRINCIPLES = new Set<string>([
  'APP_6',
  'APP_8',
  'APP_11',
  'NDB',
  'CCPA_100',
  'CCPA_150',
  'GDPR_Art9',
  'GDPR_Art32',
  'GDPR_Art33',
  'GDPR_Art34',
]);
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};
const SCANNER_DEDUCTIONS: Record<Severity, number> = {
  critical: 25,
  high: 16,
  medium: 8,
  low: 3,
  info: 1,
};

function buildBreachReadiness(
  findings: AttestLensFinding[],
  controls: RegulationControl[],
  assessment: ReportAssessment | undefined,
  questionnaireSession?: QuestionnaireSession,
): BreachReadiness {
  const evidenceBasis = getBreachReadinessEvidenceBasis(questionnaireSession);
  const factors: InternalBreachReadinessFactor[] = [];

  for (const finding of findings.filter(isBreachRelevantFinding)) {
    const regulationMappings = finding.regulationMappings ?? [];
    const principle = regulationMappings.find((mapping) =>
      BREACH_RELEVANT_PRINCIPLES.has(mapping.principle),
    )?.principle ?? finding.appMappings.find((mapping) =>
      BREACH_RELEVANT_PRINCIPLES.has(mapping.principle),
    )?.principle;
    factors.push({
      type: 'scanner',
      principle,
      severity: finding.severity,
      title: finding.title,
      detail: `${finding.sourceRule} indicates ${finding.severity} breach exposure in ${finding.category}.`,
      findingIds: [finding.id],
      deduction: SCANNER_DEDUCTIONS[finding.severity],
    });
  }

  if (!questionnaireSession) {
    factors.push({
      type: 'assessment_gap',
      severity: 'medium',
      title: 'Questionnaire attestation not completed',
      detail: 'Breach readiness is based on scanner evidence only, without operator or evidence-basis attestation.',
      deduction: 12,
    });
  }

  for (const control of controls) {
    if (control.status === 'pass') {
      continue;
    }

    if (control.status === 'fail') {
      const severity = getQuestionnaireFactorSeverity(control, 'fail');
      factors.push({
        type: 'questionnaire',
        principle: control.principle,
        severity,
        title: `${control.principle} ${control.shortName} failed`,
        detail: `${control.obligation} is not satisfied in the merged assessment.`,
        findingIds: control.findings.length > 0 ? control.findings : undefined,
        deduction: getQuestionnaireDeduction(control, 'fail'),
      });
      continue;
    }

    if (assessment?.incomplete) {
      const severity = getQuestionnaireFactorSeverity(control, 'unknown');
      factors.push({
        type: 'assessment_gap',
        principle: control.principle,
        severity,
        title: `${control.principle} remains unresolved`,
        detail: `${control.obligation} could not be resolved under the ${getAssessmentModeLabel(assessment.mode).toLowerCase()}.`,
        findingIds: control.findings.length > 0 ? control.findings : undefined,
        deduction: getQuestionnaireDeduction(control, 'unknown'),
      });
    }
  }

  const rawScore = factors.reduce((score, factor) => score - factor.deduction, 100);
  const cappedScore = applyBreachReadinessEvidenceCap(Math.max(0, rawScore), evidenceBasis, assessment);
  const topFactors = factors
    .sort((left, right) => {
      const severityDelta = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
      if (severityDelta !== 0) return severityDelta;
      return right.deduction - left.deduction;
    })
    .slice(0, 5)
    .map(({ deduction: _deduction, ...factor }) => factor);
  const level = getBreachReadinessLevel(cappedScore);
  const confidence = calculateBreachReadinessConfidence(evidenceBasis, assessment, topFactors);

  return {
    evidenceBasis,
    score: cappedScore,
    level,
    confidence,
    summary: getBreachReadinessSummary(cappedScore, level, confidence, evidenceBasis, assessment, topFactors),
    topFactors,
  };
}

function getBreachReadinessEvidenceBasis(
  questionnaireSession?: QuestionnaireSession,
): BreachReadiness['evidenceBasis'] {
  return questionnaireSession?.assessmentMode || 'scanner_only';
}

function isBreachRelevantFinding(finding: AttestLensFinding): boolean {
  if ((finding.regulationMappings ?? []).some((mapping) => BREACH_RELEVANT_PRINCIPLES.has(mapping.principle))) {
    return true;
  }

  if (finding.appMappings.some((mapping) => BREACH_RELEVANT_PRINCIPLES.has(mapping.principle))) {
    return true;
  }

  return /security|secret|credential|auth|data flow|infrastructure/i.test(finding.category);
}

function getQuestionnaireFactorSeverity(control: RegulationControl, status: 'fail' | 'unknown'): Severity {
  if (
    status === 'fail'
    && (control.principle === 'APP_11'
      || control.principle === 'NDB'
      || control.principle === 'CCPA_150'
      || control.principle === 'GDPR_Art32'
      || control.principle === 'GDPR_Art33')
  ) {
    return 'critical';
  }

  if (status === 'fail' || BREACH_RELEVANT_PRINCIPLES.has(control.principle)) {
    return 'high';
  }

  return 'medium';
}

function getQuestionnaireDeduction(control: RegulationControl, status: 'fail' | 'unknown'): number {
  if (status === 'fail') {
    if (
      control.principle === 'APP_11'
      || control.principle === 'NDB'
      || control.principle === 'CCPA_150'
      || control.principle === 'GDPR_Art32'
      || control.principle === 'GDPR_Art33'
    ) return 18;
    if (BREACH_RELEVANT_PRINCIPLES.has(control.principle)) return 14;
    return 8;
  }

  if (
    control.principle === 'APP_11'
    || control.principle === 'NDB'
    || control.principle === 'CCPA_150'
    || control.principle === 'GDPR_Art32'
    || control.principle === 'GDPR_Art33'
  ) return 10;
  if (BREACH_RELEVANT_PRINCIPLES.has(control.principle)) return 8;
  return 4;
}

function applyBreachReadinessEvidenceCap(
  score: number,
  evidenceBasis: BreachReadiness['evidenceBasis'],
  assessment?: ReportAssessment,
): number {
  if (evidenceBasis === 'scanner_only') {
    return Math.min(score, 74);
  }

  if (!assessment?.incomplete) {
    return score;
  }

  if (evidenceBasis === 'artifact_only' || evidenceBasis === 'codebase_only') {
    return Math.min(score, 69);
  }

  return Math.min(score, 79);
}

function getBreachReadinessLevel(score: number): BreachReadiness['level'] {
  if (score >= 85) return 'strong';
  if (score >= 70) return 'moderate';
  if (score >= 50) return 'limited';
  return 'weak';
}

function calculateBreachReadinessConfidence(
  evidenceBasis: BreachReadiness['evidenceBasis'],
  assessment: ReportAssessment | undefined,
  topFactors: BreachReadinessFactor[],
): number {
  const basisConfidence: Record<BreachReadiness['evidenceBasis'], number> = {
    scanner_only: 0.45,
    artifact_only: 0.7,
    codebase_only: 0.7,
    operator_attested: 0.9,
  };
  const confidenceCap = evidenceBasis === 'scanner_only'
    ? 0.45
    : assessment?.incomplete && (evidenceBasis === 'artifact_only' || evidenceBasis === 'codebase_only')
      ? 0.65
      : assessment?.incomplete
        ? 0.8
        : basisConfidence[evidenceBasis];
  const severeFactorPenalty = topFactors.some((factor) => factor.severity === 'critical') ? 0.08 : 0;
  const incompletePenalty = assessment?.incomplete ? 0.05 : 0;
  return Math.round(Math.max(0.2, Math.min(confidenceCap, basisConfidence[evidenceBasis] - severeFactorPenalty - incompletePenalty)) * 100) / 100;
}

function getBreachReadinessSummary(
  score: number,
  level: BreachReadiness['level'],
  confidence: number,
  evidenceBasis: BreachReadiness['evidenceBasis'],
  assessment: ReportAssessment | undefined,
  topFactors: BreachReadinessFactor[],
): string {
  const basisLabel = evidenceBasis === 'scanner_only'
    ? 'scanner-only review'
    : getAssessmentModeLabel(evidenceBasis);
  const primaryRisk = topFactors[0]?.title;
  const confidencePercent = Math.round(confidence * 100);
  const incompleteNote = assessment?.incomplete
    ? ' Unresolved controls cap the score until the evidence basis is completed.'
    : '';

  return `Breach readiness is ${level} at ${score}/100 with ${confidencePercent}% confidence under a ${basisLabel.toLowerCase()}.${primaryRisk ? ` Primary factor: ${primaryRisk}.` : ''}${incompleteNote}`;
}

function buildConsultantNarrative(
  controls: RegulationControl[],
  findings: AttestLensFinding[],
  remediation: RemediationItem[],
  assessment: ReportAssessment | undefined,
  breachReadiness: BreachReadiness,
): ConsultantNarrative {
  const failedControls = controls.filter((control) => control.status === 'fail');
  const unknownControls = controls.filter((control) => control.status === 'unknown');
  const severeFindings = findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high');
  const keyRisks = breachReadiness.topFactors.length > 0
    ? breachReadiness.topFactors.map((factor) => factor.detail)
    : ['No high-priority breach-readiness factors were identified in the available evidence.'];

  return {
    executiveSummary: buildExecutiveNarrative(breachReadiness, failedControls, unknownControls, severeFindings),
    evidenceBasis: assessment?.summary || 'This run used scanner evidence only. Organisational process controls still require operator attestation.',
    keyRisks,
    principleNarratives: controls.map((control) => buildPrincipleNarrative(control)),
    remediationFocus: buildRemediationFocus(remediation, breachReadiness),
  };
}

function buildExecutiveNarrative(
  breachReadiness: BreachReadiness,
  failedControls: RegulationControl[],
  unknownControls: RegulationControl[],
  severeFindings: AttestLensFinding[],
): string {
  return `This assessment shows ${breachReadiness.level} breach readiness (${breachReadiness.score}/100). ` +
    `${failedControls.length} privacy control${failedControls.length === 1 ? '' : 's'} failed, ` +
    `${unknownControls.length} remain unresolved, and ${severeFindings.length} critical/high technical finding${severeFindings.length === 1 ? '' : 's'} should be prioritised before external delivery.`;
}

function buildPrincipleNarrative(control: RegulationControl): ConsultantNarrative['principleNarratives'][number] {
  const findingTotal =
    control.findingCount.critical +
    control.findingCount.high +
    control.findingCount.medium +
    control.findingCount.low +
    control.findingCount.info;
  const priority = control.status === 'fail'
    ? 'immediate'
    : control.status === 'unknown'
      ? 'near_term'
      : 'monitor';
  const findingSummary = findingTotal > 0
    ? `${findingTotal} linked finding${findingTotal === 1 ? '' : 's'}`
    : 'no linked scanner findings';

  return {
    principle: control.principle,
    status: control.status,
    priority,
    summary: `${control.shortName} is ${control.status.toUpperCase()} at ${control.score}/100 with ${findingSummary}. ${control.obligation}.`,
  };
}

function buildRemediationFocus(
  remediation: RemediationItem[],
  breachReadiness: BreachReadiness,
): string {
  const firstImmediate = remediation.find((item) => item.priority === 'quick_win') || remediation[0];
  if (!firstImmediate) {
    return `Maintain current controls and resolve any evidence gaps before claiming stronger than ${breachReadiness.level} breach readiness.`;
  }

  return `Start with "${firstImmediate.title}" because it addresses ${firstImmediate.appReferences.join(', ')} and improves the highest-priority breach-readiness factors.`;
}

// ─── Score Calculation ────────────────────────────────────────────────────────

function calculateOverallScore(controls: RegulationControl[]): number {
  // Weighted average — security principles (APP 11, NDB) are heavier
  const weights: Record<string, number> = {
    APP_1: 5,
    APP_2: 2,
    APP_3: 8,
    APP_4: 3,
    APP_5: 6,
    APP_6: 8,
    APP_7: 4,
    APP_8: 10, // Cross-border is high risk
    APP_9: 3,
    APP_10: 6,
    APP_11: 15, // Security is the most important
    APP_12: 4,
    APP_13: 4,
    NDB: 15, // Data breach notification is critical
    CCPA_100: 15,
    CCPA_105: 6,
    CCPA_106: 6,
    CCPA_110: 6,
    CCPA_115: 8,
    CCPA_120: 10,
    CCPA_121: 10,
    CCPA_125: 8,
    CCPA_130: 10,
    CCPA_135: 8,
    CCPA_145: 3,
    CCPA_150: 15,
    GDPR_Art3: 3,
    GDPR_Art5: 12,
    GDPR_Art6: 12,
    GDPR_Art9: 12,
    GDPR_Art13: 10,
    GDPR_Art15: 6,
    GDPR_Art17: 6,
    GDPR_Art22: 10,
    GDPR_Art25: 8,
    GDPR_Art32: 15,
    GDPR_Art33: 12,
    GDPR_Art34: 8,
    GDPR_Art35: 8,
    GDPR_Art44: 12,
  };

  let totalWeight = 0;
  let weightedScore = 0;

  for (const control of controls) {
    const weight = weights[control.principle] || 5;
    totalWeight += weight;
    weightedScore += control.score * weight;
  }

  return Math.round(weightedScore / totalWeight);
}

// ─── Remediation Generator ───────────────────────────────────────────────────

function generateRemediation(findings: AttestLensFinding[]): RemediationItem[] {
  const items: RemediationItem[] = [];
  
  // Group by severity for prioritization
  const criticals = findings.filter(f => f.severity === 'critical');
  const highs = findings.filter(f => f.severity === 'high');
  const mediums = findings.filter(f => f.severity === 'medium');

  // Quick wins — critical and high severity with known fixes
  for (const finding of criticals) {
    items.push({
      id: `REM-${items.length + 1}`,
      findingIds: [finding.id],
      priority: 'quick_win',
      estimatedTime: '<5 min',
      title: finding.fix ? `Fix: ${finding.title}` : finding.title,
      description: finding.description,
      appReferences: getFindingRegulationReferences(finding),
      fix: finding.fix,
      impact: finding.severity === 'critical' 
        ? 'Immediate compliance risk — APP 11 breach likely' 
        : 'Significant compliance risk',
    });
  }

  for (const finding of highs) {
    items.push({
      id: `REM-${items.length + 1}`,
      findingIds: [finding.id],
      priority: 'medium_effort',
      estimatedTime: '1-2 hours',
      title: finding.fix ? `Fix: ${finding.title}` : finding.title,
      description: finding.description,
      appReferences: getFindingRegulationReferences(finding),
      fix: finding.fix,
      impact: 'Compliance risk if not addressed',
    });
  }

  // Structural improvements — group related mediums
  const mediumGroups = groupByCategory(mediums);
  for (const [category, categoryFindings] of mediumGroups) {
    items.push({
      id: `REM-${items.length + 1}`,
      findingIds: categoryFindings.map(f => f.id),
      priority: 'structural',
      estimatedTime: '1+ days',
      title: `Review ${category} practices`,
      description: `${categoryFindings.length} medium-severity findings in ${category}. Requires systematic review.`,
      appReferences: [...new Set(categoryFindings.flatMap(getFindingRegulationReferences))],
      impact: 'Ongoing compliance improvement',
    });
  }

  return items;
}

function getFindingRegulationReferences(finding: AttestLensFinding): string[] {
  const regulationReferences = (finding.regulationMappings ?? []).map((mapping) => mapping.principle);
  if (regulationReferences.length > 0) {
    return regulationReferences;
  }

  return finding.appMappings.map((mapping) => mapping.principle);
}

function groupByCategory(findings: AttestLensFinding[]): Map<string, AttestLensFinding[]> {
  const groups = new Map<string, AttestLensFinding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.category) || [];
    existing.push(finding);
    groups.set(finding.category, existing);
  }
  return groups;
}

// ─── Reform Impact Assessment ───────────────────────────────────────────────

const REFORM_PROVISION_ORDER: ReformProvisionName[] = [
  ReformProvision.STATUTORY_TORT,
  ReformProvision.CHILDREN_PRIVACY_CODE,
  ReformProvision.AUTOMATED_DECISION_MAKING,
  ReformProvision.AML_CTF,
];

const REFORM_IMPACT_DISCLAIMER =
  'Privacy Act 2026 reform provisions may have future effective dates. ' +
  'This assessment is a planning aid for implementation readiness and does not constitute legal advice.';

function buildReformImpactAssessment(
  findings: AttestLensFinding[],
  assessmentDate: string,
): ReformImpactAssessment {
  const reformFindings = findings
    .map((finding) => ({ finding, provision: getReformProvision(finding) }))
    .filter((entry): entry is { finding: AttestLensFinding; provision: ReformProvisionName } => Boolean(entry.provision));

  const provisions = REFORM_PROVISION_ORDER.map((provision) => {
    const provisionFindings = reformFindings
      .filter((entry) => entry.provision === provision)
      .map((entry) => entry.finding);
    const info = ReformProvisionInfo[provision];

    return {
      provision,
      shortName: info.shortName,
      effectiveDate: info.effectiveDate,
      findingCount: provisionFindings.length,
      status: provisionFindings.length > 0 ? 'gap' as const : 'unknown' as const,
      findings: provisionFindings.map((finding) => ({
        id: finding.id,
        sourceRule: finding.sourceRule,
        severity: finding.severity,
        title: finding.title,
        description: finding.description,
        file: finding.file,
        line: finding.line,
        remediation: finding.fix,
      })),
      summary: provisionFindings.length > 0
        ? `${provisionFindings.length} reform finding${provisionFindings.length === 1 ? '' : 's'} detected for ${info.shortName}.`
        : `No reform-specific scanner findings detected for ${info.shortName}; verify applicability before ${info.effectiveDate}.`,
    };
  });

  return {
    overallImpact: getReformOverallImpact(reformFindings.map((entry) => entry.finding)),
    provisions,
    actionItems: provisions
      .filter((provision) => provision.findingCount > 0)
      .map((provision) => ({
        priority: getReformActionPriority(provision.findings.map((finding) => finding.severity)),
        provision: provision.provision,
        title: `Address ${provision.shortName} readiness gaps`,
        description: `${provision.findingCount} finding${provision.findingCount === 1 ? '' : 's'} should be resolved before the reform provision takes effect.`,
        deadline: provision.effectiveDate,
      })),
    assessmentDate,
    disclaimer: REFORM_IMPACT_DISCLAIMER,
  };
}

function getReformProvision(finding: AttestLensFinding): ReformProvisionName | undefined {
  if (finding.source !== 'reform-2026') {
    return undefined;
  }

  const directProvision = reformProvisionSchema.safeParse((finding as AttestLensFinding & { provision?: unknown }).provision);
  if (directProvision.success) {
    return directProvision.data;
  }

  const rawOutput = finding.evidence.rawOutput;
  if (!rawOutput || typeof rawOutput !== 'object' || !('provision' in rawOutput)) {
    return undefined;
  }

  const rawProvision = reformProvisionSchema.safeParse((rawOutput as { provision?: unknown }).provision);
  return rawProvision.success ? rawProvision.data : undefined;
}

function getReformOverallImpact(findings: AttestLensFinding[]): 'high' | 'medium' | 'low' {
  if (findings.some((finding) => finding.severity === 'critical')) {
    return 'high';
  }
  if (findings.some((finding) => finding.severity === 'high')) {
    return 'medium';
  }
  return 'low';
}

function getReformActionPriority(severities: Severity[]): 'immediate' | 'before_deadline' | 'recommended' {
  if (severities.includes('critical')) {
    return 'immediate';
  }
  if (severities.includes('high') || severities.includes('medium')) {
    return 'before_deadline';
  }
  return 'recommended';
}

// ─── HTML Report Generator ───────────────────────────────────────────────────

export function generateHTMLReport(
  report: ComplianceReport,
  options: ReportOptions,
  questionnaireSession?: QuestionnaireSession,
): string {
  const primary = options.branding?.primaryColor || '#1a2332';
  const accent = options.branding?.accentColor || '#00b4d8';
  const failRed = '#e63946';
  const unknownAmber = '#f4a261';
  const passGreen = '#2a9d8f';
  const incompleteSummary = getAssessmentIncompleteSummary(report.assessment);
  const reportControls = getReportControls(report);
  const reportTitle = getReportTitle(report);
  const frameworkLabel = getFrameworkLabel(report);
  const checklistTitle = getControlChecklistTitle(report);
  const scopeNote = getReportScopeNote(report);

  const escapedTargetName = escapeHtml(report.target.name);
  const escapedTargetVersion = report.target.version ? escapeHtml(report.target.version) : undefined;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AttestLens Compliance Report — ${escapedTargetName}</title>
  <style>
    :root {
      --dark-navy: ${primary};
      --teal-accent: ${accent};
      --fail-red: ${failRed};
      --unknown-amber: ${unknownAmber};
      --pass-green: ${passGreen};
      --light-bg: #f8fafc;
      --border-color: #e2e8f0;
      --text-main: #334155;
      --text-light: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: var(--text-main);
      line-height: 1.6;
      background: #e2e8f0;
    }
    .page { width: 210mm; min-height: 297mm; background: white; margin: 20px auto; padding: 20mm; box-shadow: 0 4px 6px rgba(0,0,0,0.1); page-break-after: always; }
    @media print { body { background: white; } .page { margin: 0; box-shadow: none; page-break-after: always; } @page { size: A4; margin: 0; } }
    h1, h2, h3, h4 { color: var(--dark-navy); margin-bottom: 12px; }
    h1 { font-size: 28pt; margin-bottom: 24px; font-weight: 700; }
    h2 { font-size: 18pt; margin-top: 24px; border-bottom: 2px solid var(--teal-accent); padding-bottom: 8px; }
    h3 { font-size: 14pt; margin-top: 16px; }
    p { margin-bottom: 12px; }
    .cover-page { display: flex; flex-direction: column; justify-content: center; height: calc(297mm - 40mm); }
    .logo-placeholder { width: 80px; height: 80px; background: var(--dark-navy); color: var(--teal-accent); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; margin-bottom: 40px; letter-spacing: -2px; }
    .cover-title { font-size: 36pt; line-height: 1.2; color: var(--dark-navy); margin-bottom: 10px; }
    .cover-subtitle { font-size: 18pt; color: var(--text-light); margin-bottom: 60px; }
    .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
    .meta-table th { text-align: left; color: var(--text-light); padding: 8px 0; font-weight: 600; width: 30%; }
    .meta-table td { padding: 8px 0; font-weight: 500; }
    .confidential-badge { display: inline-block; background: var(--fail-red); color: white; padding: 6px 12px; border-radius: 4px; font-weight: bold; font-size: 12px; letter-spacing: 1px; margin-top: auto; }
    .exec-grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-bottom: 30px; }
    .grade-box { background: var(--dark-navy); color: white; border-radius: 8px; padding: 24px; text-align: center; }
    .grade-letter { font-size: 72pt; font-weight: 900; line-height: 1; }
    .grade-score { font-size: 14pt; opacity: 0.8; margin-top: 8px; }
    .grade-label { font-size: 10pt; text-transform: uppercase; letter-spacing: 2px; opacity: 0.6; margin-top: 4px; }
    .risk-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: 600; font-size: 12px; }
    .risk-critical { background: #fef2f2; color: var(--fail-red); }
    .risk-high { background: #fff7ed; color: #c2410c; }
    .risk-medium { background: #fefce8; color: #a16207; }
    .risk-low { background: #f0fdf4; color: #15803d; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: var(--light-bg); border-radius: 8px; padding: 16px; text-align: center; }
    .stat-number { font-size: 24pt; font-weight: 700; }
    .stat-label { font-size: 10pt; color: var(--text-light); text-transform: uppercase; letter-spacing: 1px; }
    .checklist { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    .checklist th { text-align: left; padding: 10px 12px; border-bottom: 2px solid var(--dark-navy); color: var(--dark-navy); font-size: 11pt; }
    .checklist td { padding: 10px 12px; border-bottom: 1px solid var(--border-color); font-size: 10pt; }
    .checklist tr:hover { background: var(--light-bg); }
    .status-pass { color: var(--pass-green); font-weight: 600; }
    .status-fail { color: var(--fail-red); font-weight: 600; }
    .status-unknown { color: var(--unknown-amber); font-weight: 600; }
    .finding { background: var(--light-bg); border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid var(--fail-red); }
    .finding.critical { border-left-color: var(--fail-red); }
    .finding.high { border-left-color: #c2410c; }
    .finding.medium { border-left-color: var(--unknown-amber); }
    .finding.low { border-left-color: var(--pass-green); }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .finding-id { font-family: monospace; font-size: 9pt; color: var(--text-light); }
    .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 9pt; font-weight: 600; text-transform: uppercase; }
    .severity-critical { background: #fef2f2; color: var(--fail-red); }
    .severity-high { background: #fff7ed; color: #c2410c; }
    .severity-medium { background: #fefce8; color: #a16207; }
    .severity-low { background: #f0fdf4; color: #15803d; }
    .code-block { background: #1e293b; color: #e2e8f0; padding: 12px 16px; border-radius: 6px; font-family: "SF Mono", "Fira Code", monospace; font-size: 9pt; overflow-x: auto; margin: 8px 0; }
    .fix-box { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 12px; margin-top: 8px; }
    .fix-label { font-weight: 600; color: #15803d; font-size: 10pt; }
    .remediation-item { background: var(--light-bg); border-radius: 8px; padding: 16px; margin-bottom: 12px; }
    .remediation-header { display: flex; justify-content: space-between; align-items: center; }
    .priority-quick_win { background: #fef2f2; color: var(--fail-red); padding: 2px 8px; border-radius: 4px; font-size: 9pt; font-weight: 600; }
    .priority-medium_effort { background: #fff7ed; color: #c2410c; padding: 2px 8px; border-radius: 4px; font-size: 9pt; font-weight: 600; }
    .priority-structural { background: #fefce8; color: #a16207; padding: 2px 8px; border-radius: 4px; font-size: 9pt; font-weight: 600; }
    .app-tag { display: inline-block; background: var(--dark-navy); color: white; padding: 2px 6px; border-radius: 3px; font-size: 8pt; margin-right: 4px; }
    .disclaimer { font-size: 9pt; color: var(--text-light); border-top: 1px solid var(--border-color); padding-top: 16px; margin-top: 24px; }
    .report-footer { text-align: center; font-size: 9pt; color: var(--text-light); padding-top: 16px; }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="page">
    <div class="cover-page">
      <div class="logo-placeholder">AL</div>
      <h1 class="cover-title">${escapeHtml(reportTitle).replace(/\s+\(/, '<br>(')}</h1>
      <p class="cover-subtitle">${escapedTargetName}</p>
      <table class="meta-table">
        <tr><th>Report ID</th><td>${escapeHtml(report.id)}</td></tr>
        <tr><th>Date</th><td>${new Date(report.timestamp).toLocaleDateString('en-AU', { year: 'numeric', month: 'long', day: 'numeric' })}</td></tr>
        <tr><th>Target</th><td>${escapedTargetName}${escapedTargetVersion ? ` v${escapedTargetVersion}` : ''}</td></tr>
        <tr><th>Framework</th><td>${escapeHtml(frameworkLabel)}</td></tr>
	        <tr><th>Scanner</th><td>AttestLens v${ATTESTLENS_VERSION}</td></tr>
	        ${report.metadata.ruleFreshness ? `<tr><th>Rule Pack</th><td>${escapeHtml(formatRuleFreshnessLine(report.metadata.ruleFreshness))}</td></tr>` : ''}
	        ${report.metadata.packValidation ? `<tr><th>Pack Validation</th><td>${escapeHtml(getPackValidationLine(report.metadata.packValidation) || '')}</td></tr>` : ''}
	        ${questionnaireSession ? `<tr><th>Assessment Basis</th><td>${escapeHtml(getAssessmentModeLabel(questionnaireSession.assessmentMode))}</td></tr>` : ''}
	        ${report.target.url ? `<tr><th>URL</th><td>${escapeHtml(report.target.url)}</td></tr>` : ''}
        ${report.target.path ? `<tr><th>Path</th><td>${escapeHtml(report.target.path)}</td></tr>` : ''}
      </table>
      <div class="confidential-badge">CONFIDENTIAL</div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="page">
    <h2>Executive Summary</h2>
    <div class="exec-grid">
      <div class="grade-box">
        <div class="grade-letter">${report.overallGrade}</div>
        <div class="grade-score">${report.overallScore}/100</div>
        <div class="grade-label">Overall Compliance</div>
      </div>
      <div>
	        <p><strong>Risk Level:</strong> <span class="risk-badge risk-${report.riskLevel}">${report.riskLevel.toUpperCase()}</span></p>
	        <p style="margin-top: 12px;">${getRiskSummary(report)}</p>
	        ${scopeNote ? `<p style="margin-top: 12px;"><strong>Scope:</strong> ${escapeHtml(scopeNote)}</p>` : ''}
	        ${report.metadata.packCoverage?.knownGaps.length ? `<p style="margin-top: 12px;"><strong>Known pack gaps:</strong> ${escapeHtml(report.metadata.packCoverage.knownGaps.join(' '))}</p>` : ''}
	        ${incompleteSummary ? `<p style="margin-top: 12px; color: #a16207;"><strong>Assessment incomplete:</strong> ${escapeHtml(incompleteSummary)}</p>` : ''}
        <div class="stats-grid" style="margin-top: 16px;">
          <div class="stat-card">
            <div class="stat-number" style="color: var(--fail-red);">${report.findings.filter(f => f.severity === 'critical').length}</div>
            <div class="stat-label">Critical</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color: #c2410c;">${report.findings.filter(f => f.severity === 'high').length}</div>
            <div class="stat-label">High</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color: var(--unknown-amber);">${report.findings.filter(f => f.severity === 'medium').length}</div>
            <div class="stat-label">Medium</div>
          </div>
          <div class="stat-card">
            <div class="stat-number" style="color: var(--pass-green);">${report.findings.filter(f => f.severity === 'low' || f.severity === 'info').length}</div>
            <div class="stat-label">Low/Info</div>
          </div>
        </div>
      </div>
    </div>

    ${generateHTMLConsultantNarrativeSection(report)}
    ${generateHTMLOpinionSection(report)}
    ${generateHTMLBreachReadinessSection(report)}
    ${generateHTMLReformImpactAssessmentSection(report)}

    <!-- Control Checklist -->
    <h2>${escapeHtml(checklistTitle)}</h2>
    <table class="checklist">
      <thead>
        <tr>
          <th>Principle</th>
          <th>Obligation</th>
          <th>Status</th>
          <th>Score</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
        ${reportControls.map(c => `
          <tr>
            <td><strong>${c.principle}</strong></td>
            <td>${c.shortName}</td>
            <td><span class="status-${c.status}">${c.status.toUpperCase()}</span></td>
            <td>${c.score}/100</td>
            <td>${c.findingCount.critical + c.findingCount.high + c.findingCount.medium + c.findingCount.low + c.findingCount.info}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ${generateHTMLQuestionnaireSection(report, questionnaireSession)}
  </div>

  <!-- Findings -->
  <div class="page">
    <h2>Technical Findings</h2>
    ${report.findings.map(f => `
      <div class="finding ${f.severity}">
        <div class="finding-header">
          <div>
            <span class="severity-badge severity-${f.severity}">${f.severity}</span>
            <strong style="margin-left: 8px;">${escapeHtml(f.title)}</strong>
          </div>
          <span class="finding-id">${escapeHtml(f.id)}</span>
        </div>
        <p>${escapeHtml(f.description)}</p>
        ${f.file ? `<p style="font-size: 9pt; color: var(--text-light);">${escapeHtml(f.file)}${f.line ? `:${f.line}` : ''}</p>` : ''}
        ${f.code ? `<div class="code-block">${escapeHtml(f.code)}</div>` : ''}
        ${getFindingRegulationReferences(f).map(ref => `<span class="app-tag">${escapeHtml(ref)}</span>`).join('')}
        ${f.fix ? `
          <div class="fix-box">
            <div class="fix-label">✓ Suggested Fix</div>
            <p style="font-size: 10pt; margin-top: 4px;">${escapeHtml(f.fix)}</p>
          </div>
        ` : ''}
      </div>
    `).join('')}
  </div>

  <!-- Remediation -->
  <div class="page">
    <h2>Remediation Playbook</h2>
    ${report.remediation.map(r => `
      <div class="remediation-item">
        <div class="remediation-header">
          <div>
            <strong>${escapeHtml(r.title)}</strong>
            <span style="margin-left: 8px;" class="priority-${r.priority}">${r.priority.replace('_', ' ').toUpperCase()}</span>
          </div>
          <span style="font-size: 10pt; color: var(--text-light);">${escapeHtml(r.estimatedTime)}</span>
        </div>
        <p style="margin-top: 8px;">${escapeHtml(r.description)}</p>
        ${r.fix ? `<p style="margin-top: 4px; color: #15803d;"><strong>Fix:</strong> ${escapeHtml(r.fix)}</p>` : ''}
        <div style="margin-top: 8px;">
          ${r.appReferences.map(ref => `<span class="app-tag">${escapeHtml(ref)}</span>`).join('')}
        </div>
        <p style="font-size: 9pt; color: var(--text-light); margin-top: 4px;"><strong>Impact:</strong> ${escapeHtml(r.impact)}</p>
      </div>
    `).join('')}
    
    <div class="disclaimer">
      <p>${report.disclaimer}</p>
      <p style="margin-top: 8px;">Report generated by AttestLens v${ATTESTLENS_VERSION} — ${new Date(report.timestamp).toLocaleString('en-AU')}</p>
      ${report.metadata.ruleFreshness ? `<p>Rule pack: ${escapeHtml(formatRuleFreshnessLine(report.metadata.ruleFreshness))}</p>` : ''}
      <p>Deterministic hash: <code>${report.metadata.deterministicHash}</code></p>
    </div>
    
    <div class="report-footer">
      <p>AttestLens — AI-Powered Privacy Act Compliance Scanner</p>
    </div>
  </div>
</body>
</html>`;
}

function generateHTMLReformImpactAssessmentSection(report: ComplianceReport): string {
  const assessment = report.reformImpactAssessment;
  if (!assessment) {
    return '';
  }

  return `
    <h2>Reform Impact Assessment</h2>
    <p><strong>Overall Impact:</strong> <span class="risk-badge risk-${assessment.overallImpact}">${assessment.overallImpact.toUpperCase()}</span></p>
    <p>${escapeHtml(assessment.disclaimer)}</p>
    <table class="checklist">
      <thead>
        <tr>
          <th>Provision</th>
          <th>Effective Date</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
        ${assessment.provisions.map((provision) => `
          <tr>
            <td><strong>${escapeHtml(provision.shortName)}</strong><br><span style="font-size: 9pt; color: var(--text-light);">${escapeHtml(provision.provision)}</span></td>
            <td>${escapeHtml(provision.effectiveDate)}</td>
            <td>${provision.findingCount}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    ${assessment.provisions.map((provision) => `
      <h3>${escapeHtml(provision.shortName)}</h3>
      <p>${escapeHtml(provision.summary)}</p>
      ${provision.findings.length > 0 ? provision.findings.map((finding) => `
        <div class="finding ${finding.severity}">
          <div class="finding-header">
            <div>
              <span class="severity-badge severity-${finding.severity}">${finding.severity}</span>
              <strong style="margin-left: 8px;">${escapeHtml(finding.title)}</strong>
            </div>
            <span class="finding-id">${escapeHtml(finding.id)}</span>
          </div>
          <p>${escapeHtml(finding.description)}</p>
          ${finding.file ? `<p style="font-size: 9pt; color: var(--text-light);">${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ''}</p>` : ''}
          ${finding.remediation ? `
            <div class="fix-box">
              <div class="fix-label">Suggested Fix</div>
              <p style="font-size: 10pt; margin-top: 4px;">${escapeHtml(finding.remediation)}</p>
            </div>
          ` : ''}
        </div>
      `).join('') : '<p style="font-size: 10pt; color: var(--text-light);">No findings for this provision.</p>'}
    `).join('')}
  `;
}

function getRiskSummary(report: ComplianceReport): string {
  const criticals = report.findings.filter(f => f.severity === 'critical').length;
  const highs = report.findings.filter(f => f.severity === 'high').length;
  const controls = getReportControls(report);
  const unknowns = controls.filter(c => c.status === 'unknown').length;
  const jurisdiction = getReportJurisdiction(report);
  const framework = jurisdiction === 'us-ccpa'
    ? 'CCPA/CPRA'
    : jurisdiction === 'eu-gdpr'
      ? 'GDPR'
      : jurisdiction === 'sg-pdpa'
        ? 'PDPA'
      : 'APP';

  if (report.riskLevel === 'critical') {
    return `This project has ${criticals} critical finding${criticals > 1 ? 's' : ''} requiring immediate attention. ` +
      `${framework} security obligations are likely breached. Immediate remediation is required.`;
  }
  if (report.riskLevel === 'high') {
    return `${highs} high-severity finding${highs > 1 ? 's' : ''} identified. ` +
      `${unknowns} ${framework} control${unknowns > 1 ? 's' : ''} require${unknowns === 1 ? 's' : ''} attestation questionnaire completion.`;
  }
  if (report.riskLevel === 'medium') {
    return `Moderate risk identified. ${unknowns} ${framework} control${unknowns > 1 ? 's' : ''} need attestation. ` +
      `Address findings to improve compliance posture.`;
  }
  return `Low risk. All identified ${framework} controls are passing. Continue monitoring and complete attestation questionnaires for unknown controls.`;
}

function generateHTMLConsultantNarrativeSection(report: ComplianceReport): string {
  const narrative = report.consultantNarrative;
  if (!narrative) {
    return '';
  }

  const priorityRows = narrative.principleNarratives.filter((row) => row.priority !== 'monitor').slice(0, 6);
  return `
    <h2>Consultant Narrative</h2>
    <p>${escapeHtml(narrative.executiveSummary)}</p>
    <p><strong>Evidence basis:</strong> ${escapeHtml(narrative.evidenceBasis)}</p>
    <h3>Key Risks</h3>
    <ul>
      ${narrative.keyRisks.map((risk) => `<li>${escapeHtml(risk)}</li>`).join('')}
    </ul>
    <h3>Priority Principles</h3>
    <table class="checklist">
      <thead>
        <tr>
          <th>Principle</th>
          <th>Priority</th>
          <th>Summary</th>
        </tr>
      </thead>
      <tbody>
        ${(priorityRows.length > 0 ? priorityRows : narrative.principleNarratives.slice(0, 4)).map((row) => `
          <tr>
            <td><strong>${row.principle}</strong></td>
            <td>${row.priority.replace('_', ' ').toUpperCase()}</td>
            <td>${escapeHtml(row.summary)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <p><strong>Remediation focus:</strong> ${escapeHtml(narrative.remediationFocus)}</p>
  `;
}

function generateHTMLOpinionSection(report: ComplianceReport): string {
  const opinion = report.complianceOpinion;
  if (!opinion) {
    return '';
  }
  const displayVerdict = getOpinionDisplayVerdict(opinion);

  const verdictColor: Record<string, string> = {
    COMPLIANT: '#16a34a',
    PARTIALLY_COMPLIANT: '#d97706',
    NON_COMPLIANT: '#dc2626',
  };

  const confidenceLabel: Record<string, string> = {
    HIGH: 'High',
    MODERATE: 'Moderate',
    LOW: 'Low',
  };

  return `
    <h2>Compliance Opinion</h2>
    <div style="margin-bottom: 24px;">
      <div style="display: inline-block; background: ${verdictColor[opinion.overallVerdict] || '#6b7280'}; color: white; padding: 8px 20px; border-radius: 6px; font-size: 18px; font-weight: 700; letter-spacing: 0.5px;">
        ${escapeHtml(displayVerdict)}
      </div>
      <span style="margin-left: 12px; color: #64748b;">Confidence: ${escapeHtml(confidenceLabel[opinion.overallConfidence])}</span>
      <span style="margin-left: 12px; color: #64748b;">Score: ${opinion.score}/100</span>
    </div>
    ${opinion.scopeReason ? `<p style="margin-bottom: 16px; color: #64748b;"><strong>Scope note:</strong> ${escapeHtml(opinion.scopeReason)}</p>` : ''}
    <table class="checklist">
      <thead>
        <tr>
          <th>Principle</th>
          <th>Verdict</th>
          <th>Confidence</th>
          <th>Score</th>
          <th>Evidence</th>
          <th>Summary</th>
        </tr>
      </thead>
      <tbody>
        ${opinion.principles.map(p => `
          <tr>
            <td><strong>${escapeHtml(p.principle)}</strong></td>
            <td><span style="color: ${verdictColor[p.verdict] || '#6b7280'}; font-weight: 600;">${escapeHtml(p.verdict.replace(/_/g, ' '))}</span></td>
            <td>${escapeHtml(confidenceLabel[p.confidence])}</td>
            <td>${p.score}/100</td>
            <td>${p.evidenceCount} (${p.corroboratedCount} corroborated)</td>
            <td style="font-size: 0.85em;">${escapeHtml(p.summary)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <div style="margin-top: 16px; padding: 12px 16px; background: #f1f5f9; border-radius: 6px; font-size: 0.85em; color: #475569;">
      <strong>Signed:</strong> ${escapeHtml(opinion.signedBy)} @ ${escapeHtml(opinion.signedAt)}<br>
      <strong>Disclaimer:</strong> ${escapeHtml(opinion.disclaimer)}
    </div>
  `;
}

function generateHTMLBreachReadinessSection(report: ComplianceReport): string {
  const readiness = report.breachReadiness;
  if (!readiness) {
    return '';
  }

  return `
    <h2>Breach Readiness</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-number">${readiness.score}</div>
        <div class="stat-label">Score</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="font-size: 16pt;">${readiness.level.toUpperCase()}</div>
        <div class="stat-label">Level</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">${Math.round(readiness.confidence * 100)}%</div>
        <div class="stat-label">Confidence</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="font-size: 12pt;">${readiness.evidenceBasis.replace('_', ' ').toUpperCase()}</div>
        <div class="stat-label">Evidence</div>
      </div>
    </div>
    <p>${escapeHtml(readiness.summary)}</p>
    ${readiness.topFactors.length > 0 ? `
      <h3>Top Readiness Factors</h3>
      <ul>
        ${readiness.topFactors.map((factor) => `
          <li><strong>${factor.severity.toUpperCase()}</strong> — ${escapeHtml(factor.title)}${factor.principle ? ` (${factor.principle})` : ''}: ${escapeHtml(factor.detail)}</li>
        `).join('')}
      </ul>
    ` : ''}
  `;
}

function getQuestionnaireSummaryRows(report: ComplianceReport): Array<{
  principle: string;
  status: ControlStatus;
  rationale: string;
}> {
  if (!report.questionnaireResults || report.questionnaireResults.length === 0) {
    return [];
  }

  return report.questionnaireResults.map((result) => ({
    principle: result.principle,
    status: result.status,
    rationale: result.rationale,
  }));
}

function getAssessmentModeLabel(mode?: AssessmentMode): string {
  switch (mode) {
    case 'artifact_only':
      return 'Artifact-only review';
    case 'codebase_only':
      return 'Codebase-only review';
    case 'operator_attested':
      return 'Operator-attested review';
    default:
      return 'Operator-attested review';
  }
}

function getAssessmentModeSummary(mode?: AssessmentMode): string {
  switch (mode) {
    case 'artifact_only':
      return 'This run used saved or public-facing artifacts only. Governance-heavy controls may remain unresolved where the review did not include live organisational attestations.';
    case 'codebase_only':
      return 'This run reviewed source code or repository evidence without direct observation of a live service or organisational process controls.';
    case 'operator_attested':
    default:
      return 'This run included live operator or organisational attestations for questionnaire-backed controls.';
  }
}

function getAssessmentBasisUnknownSummary(
  unresolvedRows: Array<{ principle: string; status: ControlStatus; rationale: string }>,
  questionnaireSession?: QuestionnaireSession,
): string | null {
  if (!questionnaireSession || questionnaireSession.assessmentMode === 'operator_attested' || unresolvedRows.length === 0) {
    return null;
  }

  return `These principles remain UNKNOWN because the ${getAssessmentModeLabel(questionnaireSession.assessmentMode).toLowerCase()} did not include enough live governance/process evidence to safely resolve them: ${unresolvedRows.map((row) => row.principle).join(', ')}.`;
}

function getAssessmentIncompleteSummary(assessment?: ReportAssessment): string | null {
  if (!assessment?.incomplete) {
    return null;
  }

  return `This assessment remains incomplete because ${getAssessmentModeLabel(assessment.mode).toLowerCase()} left these principles unresolved: ${assessment.unknownPrinciples.join(', ')}. The overall summary is capped until those controls are resolved or explicitly attested.`;
}

function getScannerDerivedApp11Findings(report: ComplianceReport): AttestLensFinding[] {
  return report.findings.filter((finding) =>
    finding.appMappings.some((mapping) => mapping.principle === 'APP_11'),
  );
}

function resolveQuestionForEvidence(
  questionId: string,
  questionnaireSession?: QuestionnaireSession,
) {
  return questionnaireSession?.sessionQuestions.find((question) => question.id === questionId)
    || getQuestionById(questionId);
}

function getQuestionnaireEvidenceRowsWithLookup(
  report: ComplianceReport,
  questionnaireSession?: QuestionnaireSession,
): Array<{
  principle: string;
  questionId: string;
  question: string;
  note?: string;
  evidenceRefs: string[];
}> {
  if (!report.questionnaire || report.questionnaire.length === 0) {
    return [];
  }

  return report.questionnaire
    .filter((response) => response.note || response.evidenceRefs?.length)
    .map((response) => {
      const question = resolveQuestionForEvidence(response.questionId, questionnaireSession);
      return {
        principle: question?.appPrinciple || 'UNKNOWN',
        questionId: response.questionId,
        question: question?.question || response.questionId,
        note: response.note,
        evidenceRefs: response.evidenceRefs || [],
      };
    });
}

function generateHTMLQuestionnaireSection(
  report: ComplianceReport,
  questionnaireSession?: QuestionnaireSession,
): string {
  if (!report.questionnaire || report.questionnaire.length === 0) {
    return '';
  }

  const questionnaireRows = getQuestionnaireSummaryRows(report);
  const unresolvedRows = questionnaireRows.filter((row) => row.status === 'unknown');
  const evidenceRows = getQuestionnaireEvidenceRowsWithLookup(report, questionnaireSession);
  const assessmentLabel = questionnaireSession ? getAssessmentModeLabel(questionnaireSession.assessmentMode) : null;
  const assessmentSummary = questionnaireSession ? getAssessmentModeSummary(questionnaireSession.assessmentMode) : null;
  const unresolvedSummary = getAssessmentBasisUnknownSummary(unresolvedRows, questionnaireSession);
  const incompleteSummary = getAssessmentIncompleteSummary(report.assessment);
  const app11Findings = getScannerDerivedApp11Findings(report);
  return `
    <h2>Questionnaire Attestation</h2>
    ${assessmentLabel ? `<p><strong>Assessment basis:</strong> ${escapeHtml(assessmentLabel)}</p>` : ''}
    ${assessmentSummary ? `<p>${escapeHtml(assessmentSummary)}</p>` : ''}
    ${incompleteSummary ? `<p><strong>Assessment incomplete:</strong> ${escapeHtml(incompleteSummary)}</p>` : ''}
    <p>${report.questionnaire.length} questionnaire response${report.questionnaire.length === 1 ? '' : 's'} captured.</p>
    ${app11Findings.length > 0 ? `
      <h3>Scanner-Derived APP 11 Evidence</h3>
      <ul>
        ${app11Findings.map((finding) => `
          <li><strong>${finding.severity.toUpperCase()}</strong> — ${escapeHtml(finding.title)} (${escapeHtml(finding.id)})</li>
        `).join('')}
      </ul>
    ` : ''}
    <h3>Questionnaire Principle Outcomes</h3>
    <table class="checklist">
      <thead>
        <tr>
          <th>Principle</th>
          <th>Status</th>
          <th>Summary</th>
        </tr>
      </thead>
      <tbody>
        ${questionnaireRows.map((row) => `
          <tr>
            <td><strong>${row.principle}</strong></td>
            <td><span class="status-${row.status}">${row.status.toUpperCase()}</span></td>
            <td>${escapeHtml(row.rationale)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    ${unresolvedRows.length > 0 ? `
      <p><strong>Unresolved principles:</strong> ${unresolvedRows.map((row) => row.principle).join(', ')}</p>
    ` : ''}
    ${unresolvedSummary ? `
      <p><strong>Evidence-limited unknowns:</strong> ${escapeHtml(unresolvedSummary)}</p>
    ` : ''}
    ${evidenceRows.length > 0 ? `
      <h3>Evidence Notes</h3>
      <ul>
        ${evidenceRows.map((row) => `
          <li>
            <strong>${row.principle}</strong> — ${escapeHtml(row.question)}
            ${row.note ? `<br>${escapeHtml(row.note)}` : ''}
            ${row.evidenceRefs.length > 0 ? `<br><em>Refs:</em> ${row.evidenceRefs.map(escapeHtml).join(', ')}` : ''}
          </li>
        `).join('')}
      </ul>
    ` : ''}
  `;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatRuleFreshnessLine(ruleFreshness: RuleFreshness): string {
  const age = ruleFreshness.ageDays === 1 ? '1 day old' : `${ruleFreshness.ageDays} days old`;
  const status = ruleFreshness.stale ? 'stale' : 'fresh';
  return `${ruleFreshness.version} (${ruleFreshness.source}, ${ruleFreshness.ruleCount} rules, ${age}, ${status})`;
}

// ─── JSON Report Generator ───────────────────────────────────────────────────

export function generateJSONReport(report: ComplianceReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── Agent Report Generator ───────────────────────────────────────────────────

export function generateAgentReport(
  report: ComplianceReport,
  controls: Array<APPControl | RegulationControl> = getReportControls(report),
): string {
  const opinion = report.complianceOpinion;
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const reportControls = controls;
  const scopedOutput = Boolean(opinion?.scopedVerdict);
  const actions: Array<{
    principle: string;
    verdict: string;
    score: number;
    action: string;
    remediation: string | null;
  }> = [];

  for (const control of reportControls) {
    if (control.status === 'pass') {
      continue;
    }

    const topFinding = control.findings
      .map((id) => report.findings.find((finding) => finding.id === id))
      .filter((finding): finding is AttestLensFinding => Boolean(finding))
      .sort((left, right) => (
        severityOrder.indexOf(left.severity) - severityOrder.indexOf(right.severity)
      ))[0];

    actions.push({
      principle: control.principle,
      verdict: control.status === 'fail' ? 'NON_COMPLIANT' : 'UNKNOWN',
      score: control.score,
      action: control.status === 'fail'
        ? scopedOutput
          ? `Fix ${control.findings.length} in-scope finding(s)`
          : `Fix ${control.findings.length} finding(s) to achieve compliance`
        : `Provide evidence for ${control.shortName}`,
      remediation: topFinding?.fix ?? null,
    });
  }

  const result = {
    schema: 'attestlens-agent-v1',
    verdict: opinion?.overallVerdict ?? 'UNKNOWN',
    scopedVerdict: opinion?.scopedVerdict,
    scopeReason: opinion?.scopeReason,
    displayVerdict: opinion ? getOpinionDisplayVerdict(opinion) : 'UNKNOWN',
    confidence: opinion?.overallConfidence ?? 'LOW',
    score: report.overallScore,
    riskLevel: report.riskLevel,
    packValidationStatus: report.metadata.packValidation?.status,
    packValidation: report.metadata.packValidation,
    packCoverage: report.metadata.packCoverage
      ? {
        summary: report.metadata.packCoverage.summary,
        includedPrinciples: report.metadata.packCoverage.includedPrinciples,
        excludedPrinciples: report.metadata.packCoverage.excludedPrinciples,
        knownGaps: report.metadata.packCoverage.knownGaps,
        evidenceTypes: report.metadata.packCoverage.evidenceTypes,
      }
      : undefined,
    actions,
    summary: opinion
      ? `${getOpinionDisplayVerdict(opinion)} - ${opinion.principles.filter((principle) => principle.verdict === 'NON_COMPLIANT').length} of ${opinion.principles.length} principles non-compliant`
      : 'No opinion available',
  };

  return JSON.stringify(result, null, 2);
}

// ─── Markdown Report Generator ────────────────────────────────────────────────

export function generateMarkdownReport(
  report: ComplianceReport,
  questionnaireSession?: QuestionnaireSession,
): string {
  const lines: string[] = [];
  const reportControls = getReportControls(report);

  lines.push(`# ${getReportTitle(report)} — ${report.target.name}`);
  lines.push('');
  lines.push(`**Report ID:** ${report.id}`);
  lines.push(`**Date:** ${new Date(report.timestamp).toLocaleDateString('en-AU')}`);
  lines.push(`**Framework:** ${getFrameworkLabel(report)}`);
  const scopeNote = getReportScopeNote(report);
  if (scopeNote) lines.push(`**Scope:** ${scopeNote}`);
  if (report.metadata.ruleFreshness) lines.push(`**Rule Pack:** ${formatRuleFreshnessLine(report.metadata.ruleFreshness)}`);
  const packValidationLine = getPackValidationLine(report.metadata.packValidation);
  if (packValidationLine) lines.push(`**Pack Validation:** ${packValidationLine}`);
  if (report.metadata.packCoverage?.knownGaps.length) {
    lines.push(`**Known Pack Gaps:** ${report.metadata.packCoverage.knownGaps.join(' ')}`);
  }
  if (report.target.url) lines.push(`**Target URL:** ${report.target.url}`);
  if (report.target.path) lines.push(`**Target Path:** ${report.target.path}`);
  if (questionnaireSession) lines.push(`**Assessment Basis:** ${getAssessmentModeLabel(questionnaireSession.assessmentMode)}`);
  lines.push('');
  lines.push(`## Executive Summary`);
  lines.push('');
  lines.push(`- **Overall Grade:** ${report.overallGrade} (${report.overallScore}/100)`);
  lines.push(`- **Risk Level:** ${report.riskLevel.toUpperCase()}`);
  lines.push(`- **Total Findings:** ${report.findings.length}`);
  if (report.assessment?.incomplete) {
    lines.push(`- **Assessment Incomplete:** ${getAssessmentIncompleteSummary(report.assessment)}`);
  }
  lines.push('');

  if (report.consultantNarrative) {
    lines.push(`### Consultant Narrative`);
    lines.push('');
    lines.push(report.consultantNarrative.executiveSummary);
    lines.push('');
    lines.push(`**Evidence Basis:** ${report.consultantNarrative.evidenceBasis}`);
    lines.push('');
    lines.push(`**Key Risks:**`);
    for (const risk of report.consultantNarrative.keyRisks) {
      lines.push(`- ${risk}`);
    }
    lines.push('');
    lines.push(`**Remediation Focus:** ${report.consultantNarrative.remediationFocus}`);
    lines.push('');
  }

  if (report.complianceOpinion) {
    const opinion = report.complianceOpinion;
    lines.push(`### Compliance Opinion`);
    lines.push('');
    lines.push(`**Verdict:** ${getOpinionDisplayVerdict(opinion)} | **Confidence:** ${opinion.overallConfidence} | **Score:** ${opinion.score}/100`);
    if (opinion.scopeReason) {
      lines.push(`**Scope Note:** ${opinion.scopeReason}`);
    }
    lines.push('');
    lines.push(`| Principle | Verdict | Confidence | Score | Evidence |`);
    lines.push(`|-----------|--------|------------|-------|----------|`);
    for (const p of opinion.principles) {
      lines.push(`| ${p.principle} | ${p.verdict.replace(/_/g, ' ')} | ${p.confidence} | ${p.score}/100 | ${p.evidenceCount} (${p.corroboratedCount} corrob.) |`);
    }
    lines.push('');
    lines.push(`*Signed: ${opinion.signedBy} @ ${opinion.signedAt}*`);
    lines.push('');
    lines.push(`*${opinion.disclaimer}*`);
    lines.push('');
  }

  if (report.breachReadiness) {
    lines.push(`### Breach Readiness`);
    lines.push('');
    lines.push(`- **Score:** ${report.breachReadiness.score}/100`);
    lines.push(`- **Level:** ${report.breachReadiness.level.toUpperCase()}`);
    lines.push(`- **Confidence:** ${Math.round(report.breachReadiness.confidence * 100)}%`);
    lines.push(`- **Evidence Basis:** ${report.breachReadiness.evidenceBasis}`);
    lines.push(`- **Summary:** ${report.breachReadiness.summary}`);
    if (report.breachReadiness.topFactors.length > 0) {
      lines.push('');
      lines.push(`**Top Readiness Factors:**`);
      for (const factor of report.breachReadiness.topFactors) {
        lines.push(`- **${factor.severity.toUpperCase()} / ${factor.type}:** ${factor.title}${factor.principle ? ` (${factor.principle})` : ''} — ${factor.detail}`);
      }
    }
    lines.push('');
  }

  appendMarkdownReformImpactAssessment(lines, report.reformImpactAssessment);

  lines.push(`### ${getControlChecklistTitle(report).replace('Checklist', 'Status')}`);
  lines.push('');
  lines.push(`| Principle | Obligation | Status | Score |`);
  lines.push(`|---|---|---|---|`);
  for (const c of reportControls) {
    lines.push(`| ${c.principle} | ${c.shortName} | ${c.status.toUpperCase()} | ${c.score}/100 |`);
  }
  lines.push('');

  if (report.questionnaire && report.questionnaire.length > 0) {
    lines.push(`### Questionnaire Attestation`);
    lines.push('');
    if (questionnaireSession) {
      lines.push(`- **Assessment Basis:** ${getAssessmentModeLabel(questionnaireSession.assessmentMode)}`);
      lines.push(`- **Assessment Summary:** ${getAssessmentModeSummary(questionnaireSession.assessmentMode)}`);
    }
    lines.push(`- **Responses Captured:** ${report.questionnaire.length}`);
    const questionnaireRows = getQuestionnaireSummaryRows(report);
    const unresolvedControls = questionnaireRows
      .filter((row) => row.status === 'unknown')
      .map((row) => row.principle);
    if (unresolvedControls.length > 0) {
      lines.push(`- **Unresolved Principles:** ${unresolvedControls.join(', ')}`);
    }
    lines.push('');
    const app11Findings = getScannerDerivedApp11Findings(report);
    if (app11Findings.length > 0) {
      lines.push(`#### Scanner-Derived APP 11 Evidence`);
      lines.push('');
      for (const finding of app11Findings) {
        lines.push(`- **${finding.severity.toUpperCase()} / ${finding.id}:** ${finding.title}`);
      }
      lines.push('');
    }
    lines.push(`#### Questionnaire Principle Outcomes`);
    lines.push('');
    lines.push(`| Principle | Status | Summary |`);
    lines.push(`|---|---|---|`);
    for (const row of questionnaireRows) {
      lines.push(`| ${row.principle} | ${row.status.toUpperCase()} | ${row.rationale.replace(/\|/g, '\\|')} |`);
    }
    const unresolvedSummary = getAssessmentBasisUnknownSummary(questionnaireRows.filter((row) => row.status === 'unknown'), questionnaireSession);
    const incompleteSummary = getAssessmentIncompleteSummary(report.assessment);
    if (unresolvedSummary) {
      lines.push('');
      lines.push(`#### Evidence-Limited Unknowns`);
      lines.push('');
      lines.push(unresolvedSummary);
    }
    if (incompleteSummary) {
      lines.push('');
      lines.push(`#### Assessment Incomplete`);
      lines.push('');
      lines.push(incompleteSummary);
    }
    const evidenceRows = getQuestionnaireEvidenceRowsWithLookup(report, questionnaireSession);
    if (evidenceRows.length > 0) {
      lines.push('');
      lines.push(`#### Evidence Notes`);
      lines.push('');
      for (const row of evidenceRows) {
        lines.push(`- **${row.principle} / ${row.questionId}:** ${row.question}`);
        if (row.note) {
          lines.push(`  Note: ${row.note}`);
        }
        if (row.evidenceRefs.length > 0) {
          lines.push(`  Refs: ${row.evidenceRefs.join(', ')}`);
        }
      }
    }
    lines.push('');
  }

  lines.push(`## Findings`);
  lines.push('');
  for (const f of report.findings) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`- **ID:** ${f.id}`);
    lines.push(`- **Rule:** ${f.sourceRule}`);
    lines.push(`- **Category:** ${f.category}`);
    lines.push(`- **File:** ${f.file || 'N/A'}${f.line ? `:${f.line}` : ''}`);
    lines.push('');
    lines.push(f.description);
    if (f.code) {
      lines.push('');
      lines.push('```');
      lines.push(f.code);
      lines.push('```');
    }
    if (f.fix) {
      lines.push('');
      lines.push(`**Suggested Fix:** ${f.fix}`);
    }
    lines.push('');
  }

  lines.push(`## Remediation`);
  lines.push('');
  for (const r of report.remediation) {
    lines.push(`### ${r.title} [${r.priority.toUpperCase()}]`);
    lines.push(`- **Estimated Time:** ${r.estimatedTime}`);
    lines.push(`- **Impact:** ${r.impact}`);
    lines.push(`- **Regulation References:** ${r.appReferences.join(', ')}`);
    lines.push('');
    lines.push(r.description);
    if (r.fix) lines.push(`\n**Fix:** ${r.fix}`);
    lines.push('');
  }

  lines.push(`---`);
  lines.push(`*${report.disclaimer}*`);
  lines.push(`*Generated by AttestLens v${ATTESTLENS_VERSION} — ${new Date(report.timestamp).toLocaleString('en-AU')}*`);

  return lines.join('\n');
}

function appendMarkdownReformImpactAssessment(
  lines: string[],
  assessment: ReformImpactAssessment | undefined,
): void {
  if (!assessment) {
    return;
  }

  lines.push(`### Reform Impact Assessment`);
  lines.push('');
  lines.push(`- **Overall Impact:** ${assessment.overallImpact.toUpperCase()}`);
  lines.push(`- **Disclaimer:** ${assessment.disclaimer}`);
  lines.push('');
  lines.push(`| Provision | Effective Date | Findings |`);
  lines.push(`|---|---|---|`);
  for (const provision of assessment.provisions) {
    lines.push(`| ${provision.shortName} (${provision.provision}) | ${provision.effectiveDate} | ${provision.findingCount} |`);
  }
  lines.push('');

  for (const provision of assessment.provisions) {
    lines.push(`#### ${provision.shortName}`);
    lines.push('');
    lines.push(provision.summary);
    lines.push('');
    if (provision.findings.length === 0) {
      lines.push(`- No findings for this provision.`);
      lines.push('');
      continue;
    }

    for (const finding of provision.findings) {
      const location = finding.file ? ` (${finding.file}${finding.line ? `:${finding.line}` : ''})` : '';
      lines.push(`- **${finding.severity.toUpperCase()} / ${finding.sourceRule}:** ${finding.title}${location}`);
      if (finding.remediation) {
        lines.push(`  Suggested fix: ${finding.remediation}`);
      }
    }
    lines.push('');
  }
}

// ─── PDF Report Generator ────────────────────────────────────────────────────

export async function generatePDFReport(
  report: ComplianceReport,
  options: ReportOptions,
  questionnaireSession?: QuestionnaireSession,
): Promise<Buffer> {
  const { default: PDFDocument } = await import('pdfkit');
  const doc = new PDFDocument({
    size: 'A4',
    margin: 50,
    info: {
      Title: `AttestLens Compliance Report — ${report.target.name}`,
      Author: options.branding?.companyName || 'AttestLens',
      Subject: getFrameworkLabel(report),
      Keywords: `AttestLens, ${getReportJurisdiction(report)}, privacy, compliance`,
      Producer: 'AttestLens',
      Creator: 'AttestLens',
      CreationDate: new Date(report.timestamp),
      ModDate: new Date(report.timestamp),
    },
  });

  const stream = new PassThrough();
  const chunks: Buffer[] = [];

  const bufferPromise = new Promise<Buffer>((resolve, reject) => {
    stream.on('data', (chunk: Buffer | string) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
    doc.on('error', reject);
  });

  doc.pipe(stream);

  renderPDFCover(doc, report, options, questionnaireSession);
  doc.addPage();
  renderPDFExecutiveSummary(doc, report, questionnaireSession);
  doc.addPage();
  renderPDFFindings(doc, report);
  doc.addPage();
  renderPDFRemediation(doc, report);
  doc.end();

  return bufferPromise;
}

function renderPDFCover(
  doc: PDFDocument,
  report: ComplianceReport,
  options: ReportOptions,
  questionnaireSession?: QuestionnaireSession,
): void {
  doc.fillColor('#1a2332').fontSize(26).text(getReportTitle(report));
  doc.moveDown(0.5);
  doc.fillColor('#334155').fontSize(18).text(report.target.name);
  doc.moveDown(1.5);

  doc.fontSize(11).fillColor('#0f172a');
  writePDFLabelValue(doc, 'Report ID', report.id);
  writePDFLabelValue(
    doc,
    'Date',
    new Date(report.timestamp).toLocaleDateString('en-AU', { year: 'numeric', month: 'long', day: 'numeric' }),
  );
  writePDFLabelValue(doc, 'Framework', getFrameworkLabel(report));
  writePDFLabelValue(doc, 'Scope', getReportScopeNote(report) || undefined);
  writePDFLabelValue(doc, 'Scanner', `AttestLens v${ATTESTLENS_VERSION}`);
  writePDFLabelValue(
    doc,
    'Rule Pack',
    report.metadata.ruleFreshness ? formatRuleFreshnessLine(report.metadata.ruleFreshness) : undefined,
  );
  writePDFLabelValue(doc, 'Pack Validation', getPackValidationLine(report.metadata.packValidation) || undefined);
  writePDFLabelValue(doc, 'Target URL', report.target.url);
  writePDFLabelValue(doc, 'Target Path', report.target.path);
  writePDFLabelValue(doc, 'Assessment Basis', questionnaireSession ? getAssessmentModeLabel(questionnaireSession.assessmentMode) : undefined);
  writePDFLabelValue(doc, 'Version', report.target.version);
  if (options.branding?.companyName) {
    writePDFLabelValue(doc, 'Prepared For', options.branding.companyName);
  }

  doc.moveDown(2);
  doc.fillColor('#dc2626').fontSize(12).text('CONFIDENTIAL');
}

function renderPDFExecutiveSummary(
  doc: PDFDocument,
  report: ComplianceReport,
  questionnaireSession?: QuestionnaireSession,
): void {
  doc.fillColor('#1a2332').fontSize(22).text('Executive Summary');
  doc.moveDown();

  doc.fontSize(14).fillColor('#0f172a').text(`Overall Grade: ${report.overallGrade} (${report.overallScore}/100)`);
  doc.text(`Risk Level: ${report.riskLevel.toUpperCase()}`);
  doc.moveDown(0.5);
  doc.fontSize(11).fillColor('#334155').text(getRiskSummary(report));
  const scopeNote = getReportScopeNote(report);
  if (scopeNote) {
    doc.moveDown(0.5);
    doc.fillColor('#334155').text(`Scope: ${scopeNote}`);
  }
  if (report.assessment?.incomplete) {
    doc.moveDown(0.5);
    doc.fillColor('#a16207').text(getAssessmentIncompleteSummary(report.assessment)!);
  }
  doc.moveDown();

  if (report.consultantNarrative) {
    doc.fontSize(16).fillColor('#1a2332').text('Consultant Narrative');
    doc.moveDown(0.5);
    doc.fontSize(11).fillColor('#334155').text(report.consultantNarrative.executiveSummary);
    doc.moveDown(0.3);
    doc.text(`Evidence basis: ${report.consultantNarrative.evidenceBasis}`);
    doc.moveDown(0.3);
    doc.text(`Remediation focus: ${report.consultantNarrative.remediationFocus}`);
    doc.moveDown();
  }

  if (report.breachReadiness) {
    doc.fontSize(16).fillColor('#1a2332').text('Breach Readiness');
    doc.moveDown(0.5);
    doc.fontSize(11).fillColor('#0f172a').text(`Score: ${report.breachReadiness.score}/100`);
    doc.text(`Level: ${report.breachReadiness.level.toUpperCase()}`);
    doc.text(`Confidence: ${Math.round(report.breachReadiness.confidence * 100)}%`);
    doc.text(`Evidence basis: ${report.breachReadiness.evidenceBasis}`);
    doc.moveDown(0.3);
    doc.fillColor('#334155').text(report.breachReadiness.summary);
    if (report.breachReadiness.topFactors.length > 0) {
      doc.moveDown(0.3);
      doc.fillColor('#0f172a').text('Top readiness factors:');
      for (const factor of report.breachReadiness.topFactors) {
        doc
          .fontSize(10)
          .fillColor('#334155')
          .text(`${factor.severity.toUpperCase()} / ${factor.type}: ${factor.title}${factor.principle ? ` (${factor.principle})` : ''}`);
      }
    }
    doc.moveDown();
  }

  doc.fontSize(16).fillColor('#1a2332').text('Finding Summary');
  doc.moveDown(0.5);
  writePDFLabelValue(doc, 'Critical', String(report.findings.filter(f => f.severity === 'critical').length));
  writePDFLabelValue(doc, 'High', String(report.findings.filter(f => f.severity === 'high').length));
  writePDFLabelValue(doc, 'Medium', String(report.findings.filter(f => f.severity === 'medium').length));
  writePDFLabelValue(doc, 'Low / Info', String(report.findings.filter(f => f.severity === 'low' || f.severity === 'info').length));

  doc.moveDown();
  const reportControls = getReportControls(report);
  doc.fontSize(16).fillColor('#1a2332').text(getControlChecklistTitle(report).replace('Checklist', 'Status'));
  doc.moveDown(0.5);

  for (const control of reportControls) {
    const findingCount =
      control.findingCount.critical +
      control.findingCount.high +
      control.findingCount.medium +
      control.findingCount.low +
      control.findingCount.info;
    doc
      .fontSize(10)
      .fillColor('#0f172a')
      .text(
        `${control.principle} — ${control.shortName}: ${control.status.toUpperCase()} (${control.score}/100, ${findingCount} findings)`,
      );
  }

  if (report.questionnaire && report.questionnaire.length > 0) {
    const questionnaireRows = getQuestionnaireSummaryRows(report);
    const unresolvedRows = questionnaireRows.filter((row) => row.status === 'unknown');
    const evidenceRows = getQuestionnaireEvidenceRowsWithLookup(report, questionnaireSession);
    const app11Findings = getScannerDerivedApp11Findings(report);
    const unresolvedSummary = getAssessmentBasisUnknownSummary(unresolvedRows, questionnaireSession);
    const incompleteSummary = getAssessmentIncompleteSummary(report.assessment);
    doc.moveDown();
    doc.fontSize(16).fillColor('#1a2332').text('Questionnaire Attestation');
    doc.moveDown(0.5);
    if (questionnaireSession) {
      doc.text(`Assessment basis: ${getAssessmentModeLabel(questionnaireSession.assessmentMode)}`);
      doc.text(getAssessmentModeSummary(questionnaireSession.assessmentMode));
    }
    doc.fontSize(10).fillColor('#0f172a').text(`Responses captured: ${report.questionnaire.length}`);
    doc.text(`Resolved principles: ${questionnaireRows.filter((row) => row.status !== 'unknown').length}`);
    if (unresolvedRows.length > 0) {
      doc.text(`Unresolved principles: ${unresolvedRows.map((row) => row.principle).join(', ')}`);
    }

    if (app11Findings.length > 0) {
      doc.moveDown();
      doc.fontSize(12).fillColor('#1a2332').text('Scanner-Derived APP 11 Evidence');
      for (const finding of app11Findings) {
        doc
          .fontSize(10)
          .fillColor('#334155')
          .text(`${finding.severity.toUpperCase()} / ${finding.id}: ${finding.title}`);
      }
    }

    doc.moveDown();
    doc.fontSize(12).fillColor('#1a2332').text('Questionnaire Principle Outcomes');
    for (const row of questionnaireRows) {
      doc
        .fontSize(10)
        .fillColor('#334155')
        .text(`${row.principle}: ${row.status.toUpperCase()} — ${row.rationale}`);
    }

    if (unresolvedSummary) {
      doc.moveDown();
      doc.fontSize(12).fillColor('#1a2332').text('Evidence-Limited Unknowns');
      doc.fontSize(10).fillColor('#334155').text(unresolvedSummary);
    }

    if (incompleteSummary) {
      doc.moveDown();
      doc.fontSize(12).fillColor('#1a2332').text('Assessment Incomplete');
      doc.fontSize(10).fillColor('#334155').text(incompleteSummary);
    }

    if (evidenceRows.length > 0) {
      doc.moveDown();
      doc.fontSize(12).fillColor('#1a2332').text('Evidence Notes');
      for (const row of evidenceRows) {
        doc
          .fontSize(10)
          .fillColor('#334155')
          .text(`${row.principle} / ${row.questionId}: ${row.question}`);
        if (row.note) {
          doc.text(`Note: ${row.note}`);
        }
        if (row.evidenceRefs.length > 0) {
          doc.text(`Refs: ${row.evidenceRefs.join(', ')}`);
        }
      }
    }
  }
}

function renderPDFFindings(doc: PDFDocument, report: ComplianceReport): void {
  doc.fillColor('#1a2332').fontSize(22).text('Technical Findings');
  doc.moveDown();

  if (report.findings.length === 0) {
    doc.fontSize(11).fillColor('#334155').text('No findings were detected in this scan.');
    return;
  }

  for (const finding of report.findings) {
    doc.fillColor('#0f172a').fontSize(14).text(`[${finding.severity.toUpperCase()}] ${finding.title}`);
    doc.fontSize(10).fillColor('#475569').text(`${finding.id} • ${finding.sourceRule} • ${finding.category}`);
    if (finding.file) {
      doc.text(`${finding.file}${finding.line ? `:${finding.line}` : ''}`);
    }
    doc.moveDown(0.25);
    doc.fontSize(11).fillColor('#334155').text(finding.description);

    const references = getFindingRegulationReferences(finding);
    if (references.length > 0) {
      doc.moveDown(0.25);
      doc
        .fontSize(10)
        .fillColor('#0f172a')
        .text(`Regulation references: ${references.join(', ')}`);
    }

    if (finding.fix) {
      doc.moveDown(0.25);
      doc.fontSize(10).fillColor('#15803d').text(`Suggested fix: ${finding.fix}`);
    }

    if (finding.fixPrompt) {
      doc.moveDown(0.25);
      doc.fontSize(9).fillColor('#475569').text(`Fix prompt: ${finding.fixPrompt}`);
    }

    doc.moveDown();
  }
}

function renderPDFRemediation(doc: PDFDocument, report: ComplianceReport): void {
  doc.fillColor('#1a2332').fontSize(22).text('Remediation Playbook');
  doc.moveDown();

  for (const item of report.remediation) {
    doc.fillColor('#0f172a').fontSize(13).text(item.title);
    doc
      .fontSize(10)
      .fillColor('#475569')
      .text(
        `${item.priority.replace('_', ' ').toUpperCase()} • ${item.estimatedTime} • ${item.appReferences.join(', ')}`,
      );
    doc.moveDown(0.25);
    doc.fontSize(11).fillColor('#334155').text(item.description);
    if (item.fix) {
      doc.moveDown(0.25);
      doc.fontSize(10).fillColor('#15803d').text(`Fix: ${item.fix}`);
    }
    doc.moveDown();
  }

  doc.moveDown();
  doc.fontSize(9).fillColor('#64748b').text(report.disclaimer);
  doc.moveDown(0.5);
  doc
    .fontSize(9)
    .fillColor('#64748b')
    .text(`Generated by AttestLens v${ATTESTLENS_VERSION} — ${new Date(report.timestamp).toLocaleString('en-AU')}`);
  if (report.metadata.ruleFreshness) {
    doc.text(`Rule pack: ${formatRuleFreshnessLine(report.metadata.ruleFreshness)}`);
  }
  if (report.metadata.packValidation) {
    doc.text(`Pack validation: ${getPackValidationLine(report.metadata.packValidation)}`);
  }
  doc.text(`Deterministic hash: ${report.metadata.deterministicHash}`);
}

function writePDFLabelValue(doc: PDFDocument, label: string, value?: string): void {
  if (!value) {
    return;
  }

  doc.font('Helvetica-Bold').text(`${label}: `, { continued: true });
  doc.font('Helvetica').text(value);
}
