import type {
  ComplianceReport,
  ComplianceOpinion,
  PrincipleOpinion,
  ComplianceVerdict,
  OpinionConfidence,
  APPControl,
  RegulationControl,
} from '../schema/index.js';

// Keep in sync with package.json and src/report/generator.ts
const OPINION_VERSION = '0.2.0';

// ─── Options ─────────────────────────────────────────────────────────────────

export interface OpinionOptions {
  /** Treat UNKNOWN controls as NON_COMPLIANT (mirrors existing strict mode) */
  strictMode?: boolean;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function buildComplianceOpinion(
  report: ComplianceReport,
  options: OpinionOptions = {},
): ComplianceOpinion {
  const { strictMode = false } = options;

  const controls = getOpinionControls(report);

  // Guard: empty controls → no basis for an opinion
  if (controls.length === 0) {
    return {
      overallVerdict: 'PARTIALLY_COMPLIANT',
      overallConfidence: 'LOW',
      signedBy: `AttestLens v${OPINION_VERSION}`,
      signedAt: new Date().toISOString(),
      principles: [],
      riskLevel: report.riskLevel,
      score: report.overallScore,
      disclaimer:
        "This compliance opinion is generated deterministically from automated scanning and optional questionnaire data. It does not constitute legal advice. An organisation's compliance posture depends on factors beyond automated detection. Consult a qualified privacy professional for formal compliance assessment.",
    };
  }

  const principleOpinions: PrincipleOpinion[] = controls.map(
    (control) => {
      const verdict = controlStatusToVerdict(control.status, strictMode);
      const confidence = calculateConfidence(control, report);
      const summary = buildPrincipleSummary(control, verdict);
      const keyFindings = control.findings.slice(0, 3);

      return {
        principle: control.principle,
        verdict,
        confidence,
        score: control.score,
        summary,
        evidenceCount: control.findings.length,
        corroboratedCount: countCorroborated(control, report),
        keyFindings,
      };
    },
  );

  const overallVerdict = aggregateVerdict(principleOpinions);
  const overallConfidence = aggregateConfidence(principleOpinions, report);

  return {
    overallVerdict,
    overallConfidence,
    signedBy: `AttestLens v${OPINION_VERSION}`,
    signedAt: new Date().toISOString(),
    principles: principleOpinions,
    riskLevel: report.riskLevel,
    score: report.overallScore,
    disclaimer:
      "This compliance opinion is generated deterministically from automated scanning and optional questionnaire data. It does not constitute legal advice. An organisation's compliance posture depends on factors beyond automated detection. Consult a qualified privacy professional for formal compliance assessment.",
  };
}

// ─── Per-Principle Logic ──────────────────────────────────────────────────────

function controlStatusToVerdict(
  status: APPControl['status'],
  strictMode: boolean,
): ComplianceVerdict {
  if (status === 'pass') return 'COMPLIANT';
  if (status === 'fail') return 'NON_COMPLIANT';
  // status === 'unknown'
  return strictMode ? 'NON_COMPLIANT' : 'PARTIALLY_COMPLIANT';
}

function calculateConfidence(
  control: RegulationControl,
  report: ComplianceReport,
): OpinionConfidence {
  let score = 0;

  // Finding count → confidence in the assessment
  if (control.findings.length >= 3) score += 2;
  else if (control.findings.length >= 1) score += 1;

  // Questionnaire / operator data boosts confidence
  if (report.assessment?.mode === 'operator_attested') score += 2;
  else if (
    report.questionnaireResults &&
    report.questionnaireResults.length > 0
  )
    score += 1;

  // Known status is better than unknown
  if (control.status !== 'unknown') score += 2;

  // Breach readiness evidence basis adds context
  if (report.breachReadiness?.evidenceBasis === 'operator_attested')
    score += 1;

  if (score >= 4) return 'HIGH';
  if (score >= 2) return 'MODERATE';
  return 'LOW';
}

function countCorroborated(
  control: RegulationControl,
  report: ComplianceReport,
): number {
  return control.findings.reduce((count, findingId) => {
    const finding = report.findings.find((f) => f.id === findingId);
    if (finding && finding.corroboratedBy && finding.corroboratedBy.length > 0) {
      return count + 1;
    }
    return count;
  }, 0);
}

function buildPrincipleSummary(
  control: RegulationControl,
  verdict: ComplianceVerdict,
): string {
  const statusText =
    verdict === 'COMPLIANT'
      ? 'appears compliant based on available evidence'
      : verdict === 'NON_COMPLIANT'
        ? 'is NOT MET — remediation required'
        : 'cannot be fully determined — additional evidence needed';

  return `${control.shortName} (${control.principle}): ${control.status.toUpperCase()} — ${statusText}. Score: ${control.score}/100. ${control.findings.length} finding(s).`;
}

// ─── Aggregation Logic ───────────────────────────────────────────────────────

function aggregateVerdict(opinions: PrincipleOpinion[]): ComplianceVerdict {
  if (opinions.some((o) => o.verdict === 'NON_COMPLIANT'))
    return 'NON_COMPLIANT';
  if (opinions.every((o) => o.verdict === 'COMPLIANT')) return 'COMPLIANT';
  return 'PARTIALLY_COMPLIANT';
}

function aggregateConfidence(
  opinions: PrincipleOpinion[],
  report: ComplianceReport,
): OpinionConfidence {
  const confidenceRank: Record<OpinionConfidence, number> = {
    LOW: 0,
    MODERATE: 1,
    HIGH: 2,
  };

  // If any high-risk principle (has critical or high findings) has LOW confidence → overall LOW
  const highRiskOpinions = opinions.filter((o) => {
    const control = getOpinionControls(report).find(
      (c) => c.principle === o.principle,
    );
    if (!control) return false;
    return (
      control.findingCount.critical > 0 || control.findingCount.high > 0
    );
  });

  if (highRiskOpinions.some((o) => o.confidence === 'LOW')) return 'LOW';

  // Otherwise, minimum confidence across all principles
  const minRank = Math.min(
    ...opinions.map((o) => confidenceRank[o.confidence]),
  );

  if (minRank >= 2) return 'HIGH';
  if (minRank >= 1) return 'MODERATE';
  return 'LOW';
}

function getOpinionControls(report: ComplianceReport): RegulationControl[] {
  if (
    report.regulationControls
    && report.regulationControls.length > 0
    && report.regulationControls.some((control) => control.jurisdiction !== 'au-privacy-act')
  ) {
    return report.regulationControls;
  }

  return report.appControls.map((control: APPControl): RegulationControl => ({
    jurisdiction: 'au-privacy-act',
    principle: control.principle,
    shortName: control.shortName,
    obligation: control.obligation,
    status: control.status,
    score: control.score,
    findingCount: control.findingCount,
    findings: control.findings,
    questionnaireRequired: control.questionnaireRequired,
    lastAssessed: control.lastAssessed,
  }));
}
