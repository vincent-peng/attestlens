import { describe, it, expect } from 'vitest';
import { buildComplianceReport, generateAgentReport, generateHTMLReport, generateJSONReport, generateMarkdownReport, generatePDFReport } from './generator.js';
import type { AttestLensFinding, QuestionnaireSession } from '../schema/index.js';
import type { ReportOptions } from './generator.js';
import {
  LEGACY_QUESTIONNAIRE_VERSION,
  QUESTIONNAIRE_VERSION,
  buildFindingsHash,
  buildFrozenSessionQuestions,
  buildQuestionSetHash,
} from '../questionnaire/index.js';

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
    code: overrides.code,
    fix: overrides.fix,
    fixPrompt: overrides.fixPrompt,
  };
}

const defaultOptions: ReportOptions = {
  targetName: 'TestApp',
  targetPath: '/tmp/test',
  formats: ['json'],
  outputDir: '/tmp/attestlens-test',
  strictMode: false,
};

const defaultRuleFreshness = {
  version: '2026.04.24',
  generated: '2026-04-24T00:00:00.000Z',
  loadedAt: '2026-04-24T00:00:00.000Z',
  source: 'embedded' as const,
  ruleCount: 42,
  ageDays: 0,
  stale: false,
};

function makeQuestionnaireSession(
  overrides: Partial<QuestionnaireSession> = {},
): QuestionnaireSession {
  const principles = overrides.principles || ['APP_1'];
  const findingsHash = overrides.findingsHash || buildFindingsHash([]);
  const sessionQuestions = overrides.sessionQuestions || buildFrozenSessionQuestions(principles);
  const questionnaireVersion = overrides.questionnaireVersion || QUESTIONNAIRE_VERSION;
  const assessmentMode = overrides.assessmentMode || 'operator_attested';
  return {
    id: overrides.id || 'session-001',
    version: '1.3',
    questionnaireVersion,
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
    findingsHash,
    principles,
    sessionQuestions,
    questionSetHash: overrides.questionSetHash || buildQuestionSetHash({
      questionnaireVersion,
      findingsHash,
      principles,
      sessionQuestions,
      assessmentMode,
    }),
    assessmentMode,
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

  it('adds scanner-only breach readiness and consultant narrative without changing the overall score', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);

    expect(report.overallScore).toBe(100);
    expect(report.breachReadiness).toEqual(expect.objectContaining({
      evidenceBasis: 'scanner_only',
      score: 74,
      level: 'moderate',
      confidence: 0.45,
    }));
    expect(report.consultantNarrative).toEqual(expect.objectContaining({
      executiveSummary: expect.stringContaining('moderate breach readiness'),
      remediationFocus: expect.any(String),
    }));
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

  it('generates CCPA/CPRA reports with CCPA controls', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, {
      ...defaultOptions,
      jurisdiction: 'us-ccpa',
      includeOpinion: true,
    }, 1000);
    const markdown = generateMarkdownReport(report);

    expect(report.appControls).toEqual([]);
    expect(report.regulationControls?.some((control) => control.principle === 'CCPA_100' && control.status === 'fail')).toBe(true);
    expect(report.regulationControls?.some((control) => control.principle === 'CCPA_150' && control.status === 'fail')).toBe(true);
    expect(markdown).toContain('California Consumer Privacy Act (CCPA/CPRA) Compliance Report');
    expect(markdown).toContain('CCPA_100');
    expect(report.complianceOpinion?.principles.some((principle) => principle.principle === 'CCPA_100')).toBe(true);
  });

  it('should include remediation items', () => {
    const findings = [
      makeFinding({ id: 'F-1', severity: 'critical', sourceRule: 'VS-HARDKEY', title: 'Hardcoded key' }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    expect(report.remediation.length).toBeGreaterThan(0);
  });

  it('should include scanner metadata', () => {
    const report = buildComplianceReport([], {
      ...defaultOptions,
      ruleFreshness: defaultRuleFreshness,
    }, 1000);
    expect(report.metadata.scanDurationMs).toBe(1000);
    expect(report.metadata.deterministicHash).toBeTruthy();
    expect(report.metadata.ruleFreshness).toEqual(defaultRuleFreshness);
  });

  it('strips internal cache paths from serialized rule freshness metadata', () => {
    const report = buildComplianceReport([], {
      ...defaultOptions,
      ruleFreshness: {
        ...defaultRuleFreshness,
        cachePath: '/Users/alice/.attestlens/rules/latest.json',
      } as any,
    }, 1000);
    const json = generateJSONReport(report);

    expect(report.metadata.ruleFreshness).toEqual(defaultRuleFreshness);
    expect(json).not.toContain('cachePath');
    expect(json).not.toContain('/Users/alice');
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

  it('caps evidence-limited questionnaire reports and marks them incomplete', () => {
    const report = buildComplianceReport([], defaultOptions, 1000, makeQuestionnaireSession({
      assessmentMode: 'artifact_only',
      answers: [],
      principleResults: [],
    }));

    expect(report.overallScore).toBe(69);
    expect(report.overallGrade).toBe('C');
    expect(report.riskLevel).toBe('medium');
    expect(report.assessment).toEqual(expect.objectContaining({
      mode: 'artifact_only',
      incomplete: true,
    }));
    expect(report.assessment?.unknownPrinciples.length).toBeGreaterThan(0);
    expect(report.breachReadiness).toEqual(expect.objectContaining({
      evidenceBasis: 'artifact_only',
      score: expect.any(Number),
    }));
    expect(report.breachReadiness!.score).toBeLessThanOrEqual(69);
    expect(report.breachReadiness!.confidence).toBeLessThanOrEqual(0.65);
  });

  it('changes the deterministic hash when questionnaire assessment metadata changes', () => {
    const artifactOnlyReport = buildComplianceReport([], defaultOptions, 1000, makeQuestionnaireSession({
      assessmentMode: 'artifact_only',
      answers: [],
      principleResults: [],
    }));
    const codebaseOnlyReport = buildComplianceReport([], defaultOptions, 1000, makeQuestionnaireSession({
      assessmentMode: 'codebase_only',
      answers: [],
      principleResults: [],
    }));

    expect(artifactOnlyReport.metadata.deterministicHash).not.toBe(codebaseOnlyReport.metadata.deterministicHash);
  });
});

describe('generateJSONReport', () => {
  it('should produce valid JSON', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    const json = generateJSONReport(report);
    const parsed = JSON.parse(json);
    expect(parsed.id).toBeTruthy();
    expect(parsed.appControls.length).toBe(14);
    expect(parsed.assessment).toBeUndefined();
    expect(parsed.breachReadiness).toEqual(expect.objectContaining({
      evidenceBasis: 'scanner_only',
    }));
    expect(parsed.consultantNarrative).toEqual(expect.objectContaining({
      executiveSummary: expect.any(String),
    }));
  });

  it('includes assessment metadata for merged questionnaire reports', () => {
    const report = buildComplianceReport([], defaultOptions, 1000, makeQuestionnaireSession({
      assessmentMode: 'artifact_only',
      answers: [],
      principleResults: [],
    }));
    const json = generateJSONReport(report);
    const parsed = JSON.parse(json);

    expect(parsed.assessment).toEqual(expect.objectContaining({
      mode: 'artifact_only',
      incomplete: true,
    }));
  });
});

describe('generateAgentReport', () => {
  it('returns the agent schema version', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    const parsed = JSON.parse(generateAgentReport(report));

    expect(parsed.schema).toBe('attestlens-agent-v1');
  });

  it('returns no actions when all controls pass', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    report.appControls = report.appControls.map((control) => ({
      ...control,
      status: 'pass',
      score: 100,
      findings: [],
    }));
    const parsed = JSON.parse(generateAgentReport(report));

    expect(parsed.actions).toEqual([]);
  });

  it('includes actions only for non-compliant controls', () => {
    const report = buildComplianceReport([
      makeFinding({ id: 'F-APP11-001', severity: 'critical', sourceRule: 'VS-HARDKEY' }),
    ], defaultOptions, 1000);
    const parsed = JSON.parse(generateAgentReport(report));

    expect(parsed.actions.length).toBeGreaterThan(0);
    expect(parsed.actions.some((action: any) => (
      action.verdict === 'NON_COMPLIANT' || action.verdict === 'UNKNOWN'
    ))).toBe(true);
    for (const action of parsed.actions) {
      expect(action).toEqual(expect.objectContaining({
        principle: expect.any(String),
        verdict: expect.stringMatching(/^(NON_COMPLIANT|UNKNOWN)$/),
        score: expect.any(Number),
        action: expect.any(String),
      }));
      expect(action).toHaveProperty('remediation');
      expect(action.remediation === null || typeof action.remediation === 'string').toBe(true);
    }
  });

  it('includes remediation from the most severe linked finding fix', () => {
    const report = buildComplianceReport([
      makeFinding({
        id: 'F-APP11-HIGH',
        severity: 'high',
        sourceRule: 'VS-HARDKEY',
        fix: 'Rotate the exposed key.',
      }),
      makeFinding({
        id: 'F-APP11-CRITICAL',
        severity: 'critical',
        sourceRule: 'VS-ENV',
        fix: 'Move the credential into a managed secret store.',
      }),
    ], defaultOptions, 1000);
    const parsed = JSON.parse(generateAgentReport(report));

    expect(parsed.actions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        remediation: 'Move the credential into a managed secret store.',
      }),
    ]));
  });

  it('includes opinion verdict, confidence, and summary when available', () => {
    const report = buildComplianceReport([
      makeFinding({ id: 'F-APP11-001', severity: 'critical', sourceRule: 'VS-HARDKEY' }),
    ], {
      ...defaultOptions,
      includeOpinion: true,
    }, 1000);
    const parsed = JSON.parse(generateAgentReport(report));

    expect(parsed.verdict).toBe('NON_COMPLIANT');
    expect(parsed.confidence).toBe(report.complianceOpinion?.overallConfidence);
    expect(parsed.summary).toContain('NON COMPLIANT');
    expect(parsed.summary).toContain('principles non-compliant');
  });

  it('uses fallback values when no opinion is available', () => {
    const report = buildComplianceReport([], defaultOptions, 1000);
    const parsed = JSON.parse(generateAgentReport(report));

    expect(parsed.verdict).toBe('UNKNOWN');
    expect(parsed.confidence).toBe('LOW');
    expect(parsed.summary).toBe('No opinion available');
  });
});

describe('generateHTMLReport', () => {
  it('escapes finding and remediation text derived from rule-pack metadata', () => {
    const findings = [
      makeFinding({
        id: 'F-<script>alert("id")</script>',
        severity: 'critical',
        sourceRule: 'VS-XSS',
        title: '<img src=x onerror=alert("title")>',
        description: '<script>alert("description")</script>',
        file: 'src/<b>App</b>.tsx',
        code: 'const html = "<p>safe as code</p>";',
        fix: 'Remove <script>alert("fix")</script>',
      }),
    ];
    const report = buildComplianceReport(findings, defaultOptions, 1000);
    const html = generateHTMLReport(report, defaultOptions);

    expect(html).not.toContain('<script>alert("id")</script>');
    expect(html).not.toContain('<script>alert("description")</script>');
    expect(html).not.toContain('<script>alert("fix")</script>');
    expect(html).not.toContain('<img src=x onerror=alert("title")>');
    expect(html).not.toContain('src/<b>App</b>.tsx');
    expect(html).toContain('&lt;script&gt;alert(&quot;description&quot;)&lt;/script&gt;');
    expect(html).toContain('&lt;img src=x onerror=alert(&quot;title&quot;)&gt;');
    expect(html).toContain('src/&lt;b&gt;App&lt;/b&gt;.tsx');
    expect(html).toContain('const html = &quot;&lt;p&gt;safe as code&lt;/p&gt;&quot;');
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
    expect(md).toContain('### Consultant Narrative');
    expect(md).toContain('### Breach Readiness');
    expect(md).toContain('APP_11');
    expect(md).toContain('Hardcoded key');
  });

  it('renders rule freshness metadata when present', () => {
    const report = buildComplianceReport([], {
      ...defaultOptions,
      ruleFreshness: defaultRuleFreshness,
    }, 1000);
    const md = generateMarkdownReport(report);

    expect(md).toContain('**Rule Pack:** 2026.04.24');
    expect(md).toContain('42 rules');
  });

  it('includes questionnaire outcomes and evidence notes in merged markdown reports', () => {
    const session = makeQuestionnaireSession({
      assessmentMode: 'artifact_only',
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
    });
    const report = buildComplianceReport([], defaultOptions, 1000, session);

    const md = generateMarkdownReport(report, session);
    expect(md).toContain('### Questionnaire Attestation');
    expect(md).toContain('**Assessment Basis:** Artifact-only review');
    expect(md).toContain('**Assessment Incomplete:**');
    expect(md).toContain('Policy is public.');
    expect(md).toContain('#### Evidence Notes');
    expect(md).toContain('docs/privacy-policy.md');
  });

  it('separates scanner-derived APP 11 evidence from questionnaire outcomes in markdown reports', () => {
    const session = makeQuestionnaireSession({
      assessmentMode: 'codebase_only',
      answers: [
        {
          questionId: 'Q-APP11-001',
          answer: true,
          timestamp: new Date().toISOString(),
          evaluation: {
            status: 'pass',
            confidence: 0.8,
            rationale: 'Access controls reviewed.',
          },
        },
      ],
      principleResults: [
        {
          principle: 'APP_11',
          status: 'unknown',
          confidence: 0.35,
          rationale: 'No applicable blocking questionnaire answers have been recorded yet.',
          answeredQuestionIds: ['Q-APP11-001'],
        },
      ],
    });
    const report = buildComplianceReport([
      makeFinding({
        id: 'F-APP11-001',
        severity: 'high',
        sourceRule: 'AL-KEY-011',
        title: 'Exposed secret material',
        appMappings: [{
          principle: 'APP_11',
          obligation: 'Reasonable steps to protect personal information',
          status: 'fail',
          confidence: 0.9,
        }],
      }),
    ], defaultOptions, 1000, session);

    const md = generateMarkdownReport(report, session);
    expect(md).toContain('#### Scanner-Derived APP 11 Evidence');
    expect(md).toContain('F-APP11-001');
    expect(md).toContain('#### Questionnaire Principle Outcomes');
    expect(md).toContain('#### Evidence-Limited Unknowns');
    expect(md).toContain('#### Assessment Incomplete');
    expect(md).toContain('Codebase-only review');
  });

  it('uses frozen session question text for evidence notes when provided', () => {
    const session = makeQuestionnaireSession({
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
      sessionQuestions: buildFrozenSessionQuestions(['APP_1']).map((question) => (
        question.id === 'Q-APP1-001'
          ? { ...question, question: 'Frozen session wording for APP 1' }
          : question
      )),
    });
    const report = buildComplianceReport([], defaultOptions, 1000, session);

    const md = generateMarkdownReport(report, session);
    expect(md).toContain('Frozen session wording for APP 1');
    expect(md).not.toContain('Do you have a publicly available privacy policy');
  });

  it('renders legacy frozen question wording for preserved legacy sessions', () => {
    const session = makeQuestionnaireSession({
      questionnaireVersion: LEGACY_QUESTIONNAIRE_VERSION,
      answers: [
        {
          questionId: 'Q-APP1-001',
          answer: true,
          timestamp: new Date().toISOString(),
          note: 'Legacy evidence note',
          evaluation: {
            status: 'pass',
            confidence: 0.8,
            rationale: 'Legacy control satisfied.',
          },
        },
      ],
      principleResults: [
        {
          principle: 'APP_1',
          status: 'pass',
          confidence: 0.8,
          rationale: 'Legacy control satisfied.',
          answeredQuestionIds: ['Q-APP1-001'],
        },
      ],
      sessionQuestions: buildFrozenSessionQuestions(['APP_1']).map((question) => (
        question.id === 'Q-APP1-001'
          ? { ...question, question: 'Legacy preserved prompt text' }
          : question
      )),
    });
    const report = buildComplianceReport([], defaultOptions, 1000, session);

    const md = generateMarkdownReport(report, session);
    expect(md).toContain('Legacy preserved prompt text');
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
