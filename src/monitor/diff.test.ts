import { describe, expect, it } from 'vitest';

import type { APPControl, AttestLensFinding, ComplianceReport } from '../schema/index.js';
import { compareReports } from './diff.js';

describe('compareReports', () => {
  it('detects new findings, resolved findings, score changes, and new APP failures', () => {
    const baselineReport = makeReport({
      score: 90,
      grade: 'A',
      findings: [makeFinding('resolved', 'Resolved issue', 'low')],
      controls: [makeControl('APP_11', 'pass', 100)],
    });
    const currentReport = makeReport({
      score: 70,
      grade: 'B',
      findings: [makeFinding('new', 'New issue', 'high')],
      controls: [makeControl('APP_11', 'fail', 0, ['new'])],
    });

    const diff = compareReports({
      repoUrl: 'https://github.com/example/repo.git',
      branch: 'main',
      baselineReport,
      currentReport,
    });

    expect(diff.hasRegression).toBe(true);
    expect(diff.hasImprovement).toBe(true);
    expect(diff.scoreChange.delta).toBe(-20);
    expect(diff.gradeChange).toEqual({ previous: 'A', current: 'B' });
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(1);
    expect(diff.newAppFailures).toHaveLength(1);
    expect(diff.summary).toContain('New APP failures');
  });
});

function makeReport(input: {
  score: number;
  grade: ComplianceReport['overallGrade'];
  findings: AttestLensFinding[];
  controls: APPControl[];
}): ComplianceReport {
  return {
    id: `report-${input.score}`,
    timestamp: new Date().toISOString(),
    target: { name: 'repo' },
    overallScore: input.score,
    overallGrade: input.grade,
    riskLevel: 'medium',
    appControls: input.controls,
    findings: input.findings,
    remediation: [],
    metadata: {
      scannerVersions: {},
      deterministicHash: `hash-${input.score}`,
      scanDurationMs: 1,
      configHash: '',
    },
    disclaimer: 'test',
  };
}

function makeControl(
  principle: APPControl['principle'],
  status: APPControl['status'],
  score: number,
  findings: string[] = [],
): APPControl {
  return {
    principle,
    shortName: principle,
    obligation: principle,
    status,
    score,
    findingCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings,
    questionnaireRequired: false,
    lastAssessed: new Date().toISOString(),
  };
}

function makeFinding(
  id: string,
  title: string,
  severity: AttestLensFinding['severity'],
): AttestLensFinding {
  return {
    id,
    source: 'manual',
    sourceRule: 'TEST-001',
    severity,
    category: 'Security',
    title,
    description: title,
    file: 'src/app.ts',
    line: 1,
    regulationMappings: [],
    appMappings: [{
      principle: 'APP_11',
      obligation: 'Security',
      status: 'fail',
      confidence: 1,
    }],
    evidence: {
      timestamp: new Date().toISOString(),
      scannerVersion: 'test',
      rawOutput: {},
    },
  };
}
