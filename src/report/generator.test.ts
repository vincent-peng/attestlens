import { describe, it, expect } from 'vitest';
import { buildComplianceReport, generateJSONReport, generateMarkdownReport, generatePDFReport } from './generator.js';
import type { AttestLensFinding, QuestionnaireSession } from '../schema/index.js';
import type { ReportOptions } from './generator.js';

function makeFinding(overrides: Partial<AttestLensFinding> = {}): AttestLensFinding {
  return {
    id: overrides.id || 'FIND-001',
    source: overrides.source || 'guardvibe',
    sourceRule: overrides.sourceRule || 'VS-HARDKEY',
    severity: overrides.severity || 'critical',
    category: overrides.category || 'Security',
    title: overrides.title || 'Test finding',
    description: overrides.description || 'A test finding',
    file: overrides.file || 'app.ts',
    line: overrides.line || 1,
    appMappings: [],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion: '0.1.0',
      rawOutput: {},
    },
  };
}

const defaultOptions: ReportOptions = {
  targetName: 'TestApp',
  targetPath: '/tmp/test',
  formats: ['json'],
  outputDir: '/tmp/attestlens-test',
  strictMode: false,
};

function makeQuestionnaireSession(
  overrides: Partial<QuestionnaireSession> = {},
): QuestionnaireSession {
  return {
    id: overrides.id || 'session-001',
    version: '1.0',
    status: overrides.status || 'completed',
    target: overrides.target || {
      kind: 'path',
      name: 'TestApp',
      path: '/tmp/test',
    },
    startedAt: overrides.startedAt || new Date().toISOString(),
    updatedAt: overrides.updatedAt || new Date().toISOString(),
    completedAt: overrides.completedAt || new Date().toISOString(),
    strictMode: overrides.strictMode ?? false,
    scanSnapshotPath: overrides.scanSnapshotPath || '/tmp/test/scan-results.json',
    findingsHash: overrides.findingsHash || 'hash-123',
    answers: overrides.answers || [],
    principleResults: overrides.principleResults || [],
    currentQuestionId: overrides.currentQuestionId,
  };
}

describe('buildComplianceReport', () => {
  it('should generate a report with all 14 APP controls', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.appControls.length).toBe(14);
  });

  it('should score 100 with no findings', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.overallScore).toBe(100);
    expect(report.overallGrade).toBe('A');
    expect(report.riskLevel).toBe('low');
  });

  it('should reduce score with critical findings', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY' }),
      makeFinding({ id: 'F-2', severity: 'critical', sourceRule: 'VS-ENV' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    expect(report.overallScore).toBeLessThan(100);
    expect(report.riskLevel).toBe('critical');
  });

  it('should mark APP_11 as fail for security findings', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    const app11 = report.appControls.find(c => c.principle === 'APP_11');
    expect(app11!.status).toBe('fail');
  });

  it('should include remediation items', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    expect(report.remediation.length).toBeGreaterThan(0);
  });

  it('should include scanner metadata', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.metadata.scanDurationMs).toBe(1000);
    expect(report.metadata.deterministicHash).toBeTruthy();
  });

  it('should include disclaimer', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    expect(report.disclaimer).toContain('does not constitute legal advice');
  });

  it('should sanitize target URLs and paths before storing them in the report', () => {
    const report = buildComplianceReport([], {
      ...defaultOptions,
      targetPath: '/Users/alice/private/secret-project',
      targetUrl: 'https://user:pass@example.com/private?token=secret#frag',
    }, 1000);

    expect(report.target.path).toBe('secret-project');
    expect(report.target.url).toBe('https://example.com/private');
  });

  it('merges questionnaire results into unknown controls only', () => {
    const report = buildComplianceReport([], defaultOptions, 1000, makeQuestionnaireSession({
      answers: [
        {
          questionId: 'Q-APP1-001',
          answer: true,
          timestamp: new Date().toISOString(),
          note: 'Published on website',
          evidenceRefs: ['docs/privacy-policy.md'],
          evaluation: {
            status: 'pass',
            confidence: 0.85,
            rationale: 'Policy is public.',
          },
        },
      ],
      principleResults: [
        {
          principle: 'APP_1',
          status: 'pass',
          confidence: 0.85,
          rationale: 'Policy is public.',
          answeredQuestionIds: ['Q-APP1-001'],
        },
        {
          principle: 'APP_8',
          status: 'fail',
          confidence: 0.9,
          rationale: 'No overseas disclosure controls documented.',
          answeredQuestionIds: ['Q-APP8-001'],
        },
      ],
    }));

    const app1 = report.appControls.find((control) => control.principle === 'APP_1');
    const app8 = report.appControls.find((control) => control.principle === 'APP_8');
    const app11 = report.appControls.find((control) => control.principle === 'APP_11');

    expect(app1?.status).toBe('pass');
    expect(app8?.status).toBe('fail');
    expect(app8?.score).toBe(0);
    expect(app11?.status).toBe('unknown');
  });

  it('applies strict mode after questionnaire merge for unresolved controls', () => {
    const report = buildComplianceReport([], {
      ...defaultOptions,
      strictMode: true,
    }, 1000, makeQuestionnaireSession({
      strictMode: true,
      principleResults: [
        {
          principle: 'APP_1',
          status: 'pass',
          confidence: 0.85,
          rationale: 'Policy is public.',
          answeredQuestionIds: ['Q-APP1-001'],
        },
      ],
    }));

    const app1 = report.appControls.find((control) => control.principle === 'APP_1');
    const app11 = report.appControls.find((control) => control.principle === 'APP_11');

    expect(app1?.status).toBe('pass');
    expect(app11?.status).toBe('fail');
    expect(app11?.score).toBe(0);
  });

  it('does not override scan-derived failures with questionnaire pass results', () => {
    const report = buildComplianceReport([
      makeFinding({ id: 'F-SEC-001', severity: 'critical', sourceRule: 'VS-HARDKEY' }),
    ], defaultOptions, 1000, makeQuestionnaireSession({
      principleResults: [
        {
          principle: 'APP_11',
          status: 'pass',
          confidence: 0.9,
          rationale: 'Security controls are documented.',
          answeredQuestionIds: ['Q-APP1-001'],
        },
      ],
    }));

    const app11 = report.appControls.find((control) => control.principle === 'APP_11');
    expect(app11?.status).toBe('fail');
  });
});

describe('generateJSONReport', () => {
  it('should produce valid JSON', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    const json = generateJSONReport(report);
    const parsed = JSON.parse(json);
    expect(parsed.id).toBeTruthy();
    expect(parsed.appControls.length).toBe(14);
  });
});

describe('generateMarkdownReport', () => {
  it('should produce markdown with key sections', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    const md = generateMarkdownReport(report);
    expect(md).toContain('# Privacy Act Compliance Report');
    expect(md).toContain('APP_11');
    expect(md).toContain('Hardcoded key');
  });

  it('includes questionnaire outcomes and evidence notes in merged markdown reports', () => {
    const report = buildComplianceReport([], defaultOptions, 1000, makeQuestionnaireSession({
      answers: [
        {
          questionId: 'Q-APP1-001',
          answer: true,
          timestamp: new Date().toISOString(),
          note: 'Published on website',
          evidenceRefs: ['docs/privacy-policy.md'],
          evaluation: {
            status: 'pass',
            confidence: 0.85,
            rationale: 'Policy is public.',
          },
        },
      ],
      principleResults: [
        {
          principle: 'APP_1',
          status: 'pass',
          confidence: 0.85,
          rationale: 'Policy is public.',
          answeredQuestionIds: ['Q-APP1-001'],
        },
      ],
    }));

    const md = generateMarkdownReport(report);
    expect(md).toContain('### Questionnaire Attestation');
    expect(md).toContain('Policy is public.');
    expect(md).toContain('#### Evidence Notes');
    expect(md).toContain('docs/privacy-policy.md');
  });
});

describe('generatePDFReport', () => {
  it('should produce a PDF buffer for path or URL reports', async () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'high', sourceRule: 'AL-URL-001', title: 'Missing CSP header' }),
    ];
    const report = buildComplianceReport(findings, {
      ...defaultOptions,
      targetPath: undefined,
      targetUrl: 'https://example.com',
      formats: ['pdf'],
    }, 1000);

    const pdf = await generatePDFReport(report, {
      ...defaultOptions,
      targetPath: undefined,
      targetUrl: 'https://example.com',
      formats: ['pdf'],
    });

    expect(pdf.subarray(0, 4).toString()).toBe('%PDF');
    expect(pdf.length).toBeGreaterThan(500);
  });
});
