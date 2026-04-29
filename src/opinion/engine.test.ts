import { describe, it, expect } from 'vitest';
import { buildComplianceOpinion } from './engine.js';
import type { OpinionOptions } from './engine.js';
import type {
  ComplianceReport,
  APPControl,
  AttestLensFinding,
  ControlStatus,
} from '../schema/index.js';
import { APPInfo } from '../schema/index.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeAPPControl(
  principle: string,
  status: ControlStatus,
  overrides: Partial<APPControl> = {},
): APPControl {
  const info = APPInfo[principle as keyof typeof APPInfo];
  return {
    principle: principle as APPControl['principle'],
    shortName: info?.shortName ?? 'Test',
    obligation: info?.obligation ?? 'Test obligation',
    status,
    score: status === 'pass' ? 90 : status === 'fail' ? 30 : 50,
    findingCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings: [],
    questionnaireRequired: false,
    lastAssessed: new Date().toISOString(),
    ...overrides,
  };
}

function makeReport(
  controls: APPControl[],
  overrides: Partial<ComplianceReport> = {},
): ComplianceReport {
  return {
    id: 'report-001',
    timestamp: new Date().toISOString(),
    target: { name: 'TestApp', path: '/tmp/test' },
    overallScore: 75,
    overallGrade: 'B',
    riskLevel: 'medium',
    appControls: controls,
    findings: [],
    remediation: [],
    metadata: {
      scannerVersions: {},
      deterministicHash: 'abc123',
      scanDurationMs: 1000,
      configHash: 'cfg123',
    },
    disclaimer: 'Test disclaimer',
    ...overrides,
  };
}

function makeFinding(
  id: string,
  corroborated = false,
): AttestLensFinding {
  return {
    id,
    source: 'guardvibe',
    sourceRule: 'VS-HARDKEY',
    severity: 'high',
    category: 'Security',
    title: 'Test finding',
    description: 'A test finding',
    file: 'app.ts',
    line: 1,
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion: '0.1.0',
      rawOutput: {},
    },
    ...(corroborated ? { corroboratedBy: ['mcp-scan'] } : {}),
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('buildComplianceOpinion', () => {
  it('returns COMPLIANT when all principles pass', () => {
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, 'pass'),
    );
    const report = makeReport(controls, { overallScore: 95, riskLevel: 'low' });
    const opinion = buildComplianceOpinion(report);

    expect(opinion.overallVerdict).toBe('COMPLIANT');
    expect(opinion.principles.every((p) => p.verdict === 'COMPLIANT')).toBe(true);
  });

  it('returns NON_COMPLIANT when any principle fails', () => {
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, p === 'APP_11' ? 'fail' : 'pass'),
    );
    const report = makeReport(controls);
    const opinion = buildComplianceOpinion(report);

    expect(opinion.overallVerdict).toBe('NON_COMPLIANT');
    const app11 = opinion.principles.find((p) => p.principle === 'APP_11');
    expect(app11?.verdict).toBe('NON_COMPLIANT');
  });

  it('returns PARTIALLY_COMPLIANT with mixed pass and unknown', () => {
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, p === 'APP_2' ? 'unknown' : 'pass'),
    );
    const report = makeReport(controls);
    const opinion = buildComplianceOpinion(report);

    expect(opinion.overallVerdict).toBe('PARTIALLY_COMPLIANT');
    const app2 = opinion.principles.find((p) => p.principle === 'APP_2');
    expect(app2?.verdict).toBe('PARTIALLY_COMPLIANT');
  });

  it('treats UNKNOWN as NON_COMPLIANT in strict mode', () => {
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, 'unknown'),
    );
    const report = makeReport(controls);
    const opinion = buildComplianceOpinion(report, { strictMode: true });

    expect(opinion.overallVerdict).toBe('NON_COMPLIANT');
    expect(
      opinion.principles.every((p) => p.verdict === 'NON_COMPLIANT'),
    ).toBe(true);
  });

  it('calculates confidence based on evidence and assessment mode', () => {
    // operator_attested with findings → HIGH
    const controlsHigh = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, 'pass', {
        findings: ['F-001', 'F-002', 'F-003'],
        findingCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      }),
    );
    const reportHigh = makeReport(controlsHigh, {
      assessment: { mode: 'operator_attested', summary: 'Test', incomplete: false, unknownPrinciples: [] },
    });
    const opinionHigh = buildComplianceOpinion(reportHigh);
    expect(opinionHigh.overallConfidence).toBe('HIGH');

    // Unknown status, no questionnaire → LOW
    const controlsLow = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, 'unknown'),
    );
    const reportLow = makeReport(controlsLow);
    const opinionLow = buildComplianceOpinion(reportLow);
    expect(opinionLow.overallConfidence).toBe('LOW');
  });

  it('counts corroborated findings correctly', () => {
    const findings = [
      makeFinding('F-001', true),
      makeFinding('F-002', false),
      makeFinding('F-003', true),
    ];
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, p === 'APP_11' ? 'fail' : 'pass', {
        findings: p === 'APP_11' ? ['F-001', 'F-002', 'F-003'] : [],
        findingCount: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      }),
    );
    const report = makeReport(controls, { findings });
    const opinion = buildComplianceOpinion(report);

    const app11 = opinion.principles.find((p) => p.principle === 'APP_11');
    expect(app11?.corroboratedCount).toBe(2);
    expect(app11?.evidenceCount).toBe(3);
    expect(app11?.keyFindings).toEqual(['F-001', 'F-002', 'F-003']);
  });

  it('limits keyFindings to 3', () => {
    const findingIds = ['F-001', 'F-002', 'F-003', 'F-004', 'F-005'];
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, p === 'APP_11' ? 'fail' : 'pass', {
        findings: p === 'APP_11' ? findingIds : [],
        findingCount: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      }),
    );
    const report = makeReport(controls);
    const opinion = buildComplianceOpinion(report);

    const app11 = opinion.principles.find((p) => p.principle === 'APP_11');
    expect(app11?.keyFindings.length).toBeLessThanOrEqual(3);
  });

  it('includes signature and disclaimer', () => {
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, 'pass'),
    );
    const report = makeReport(controls);
    const opinion = buildComplianceOpinion(report);

    expect(opinion.signedBy).toBe('AttestLens v0.2.0');
    expect(opinion.signedAt).toBeTruthy();
    expect(opinion.disclaimer).toContain('deterministically');
    expect(opinion.disclaimer).toContain('legal advice');
  });

  it('produces deterministic output for the same input', () => {
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, 'pass'),
    );
    const report = makeReport(controls);
    const opinion1 = buildComplianceOpinion(report);
    const opinion2 = buildComplianceOpinion(report);

    // Verdict, confidence, principles should be identical (timestamps differ)
    expect(opinion1.overallVerdict).toBe(opinion2.overallVerdict);
    expect(opinion1.overallConfidence).toBe(opinion2.overallConfidence);
    expect(opinion1.principles.map((p) => p.verdict)).toEqual(
      opinion2.principles.map((p) => p.verdict),
    );
  });

  it('returns LOW overall confidence when high-risk principle has LOW confidence', () => {
    // APP_11 with critical findings but unknown status → LOW confidence
    const controls = Object.keys(APPInfo).map((p) =>
      makeAPPControl(p, p === 'APP_11' ? 'unknown' : 'pass', {
        findingCount:
          p === 'APP_11'
            ? { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
            : { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      }),
    );
    const report = makeReport(controls, { riskLevel: 'critical' });
    const opinion = buildComplianceOpinion(report);

    // APP_11 unknown + critical findings → LOW confidence for that principle
    const app11 = opinion.principles.find((p) => p.principle === 'APP_11');
    expect(app11?.confidence).toBe('LOW');
    // Overall should also be LOW because high-risk principle has LOW confidence
    expect(opinion.overallConfidence).toBe('LOW');
  });

  it('returns PARTIALLY_COMPLIANT with LOW confidence for empty appControls', () => {
    const report = makeReport([]);
    const opinion = buildComplianceOpinion(report);

    expect(opinion.overallVerdict).toBe('PARTIALLY_COMPLIANT');
    expect(opinion.overallConfidence).toBe('LOW');
    expect(opinion.principles).toEqual([]);
    expect(opinion.signedBy).toContain('AttestLens');
  });
});
