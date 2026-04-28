import type { APPPrinciple, AttestLensFinding, ComplianceReport } from '../schema/index.js';
import type {
  AppControlStatusChange,
  Baseline,
  FindingDelta,
  RegressionDiff,
} from './types.js';

export function compareReportToBaseline(
  baseline: Baseline,
  currentReport: ComplianceReport,
  currentCommitSha?: string,
): RegressionDiff {
  return compareReports({
    repoUrl: baseline.repoUrl,
    branch: baseline.branch,
    baselineReport: baseline.report,
    currentReport,
    baselineCommitSha: baseline.commitSha,
    currentCommitSha,
  });
}

export function compareReports(input: {
  repoUrl: string;
  branch: string;
  baselineReport: ComplianceReport;
  currentReport: ComplianceReport;
  baselineCommitSha?: string;
  currentCommitSha?: string;
}): RegressionDiff {
  const baselineFindings = new Map(input.baselineReport.findings.map((finding) => [finding.id, finding]));
  const currentFindings = new Map(input.currentReport.findings.map((finding) => [finding.id, finding]));
  const newFindings = input.currentReport.findings
    .filter((finding) => !baselineFindings.has(finding.id))
    .map(toFindingDelta);
  const resolvedFindings = input.baselineReport.findings
    .filter((finding) => !currentFindings.has(finding.id))
    .map(toFindingDelta);

  const statusChanges = getAppControlStatusChanges(input.baselineReport, input.currentReport);
  const newAppFailures = statusChanges.filter(
    (change) => change.previousStatus !== 'fail' && change.currentStatus === 'fail',
  );
  const resolvedAppFailures = statusChanges.filter(
    (change) => change.previousStatus === 'fail' && change.currentStatus !== 'fail',
  );
  const gradeChange = input.baselineReport.overallGrade === input.currentReport.overallGrade
    ? undefined
    : {
      previous: input.baselineReport.overallGrade,
      current: input.currentReport.overallGrade,
    };
  const scoreDelta = input.currentReport.overallScore - input.baselineReport.overallScore;
  const hasRegression = newFindings.length > 0 || newAppFailures.length > 0 || scoreDelta < 0;
  const hasImprovement = resolvedFindings.length > 0 || resolvedAppFailures.length > 0 || scoreDelta > 0;

  const diffWithoutSummary = {
    repoUrl: input.repoUrl,
    branch: input.branch,
    baselineCommitSha: input.baselineCommitSha,
    currentCommitSha: input.currentCommitSha,
    comparedAt: new Date().toISOString(),
    scoreChange: {
      previous: input.baselineReport.overallScore,
      current: input.currentReport.overallScore,
      delta: scoreDelta,
    },
    gradeChange,
    newFindings,
    resolvedFindings,
    newAppFailures,
    resolvedAppFailures,
    statusChanges,
    hasRegression,
    hasImprovement,
  };

  return {
    ...diffWithoutSummary,
    summary: formatDiffSummary(diffWithoutSummary),
  };
}

export function formatDiffSummary(diff: Omit<RegressionDiff, 'summary'>): string {
  const lines: string[] = [];
  const scorePrefix = diff.scoreChange.delta > 0 ? '+' : '';
  lines.push(`Compliance diff for ${diff.branch}`);
  lines.push(`Score: ${diff.scoreChange.previous} -> ${diff.scoreChange.current} (${scorePrefix}${diff.scoreChange.delta})`);

  if (diff.gradeChange) {
    lines.push(`Grade: ${diff.gradeChange.previous} -> ${diff.gradeChange.current}`);
  }

  lines.push(`Findings: ${diff.newFindings.length} new, ${diff.resolvedFindings.length} resolved`);
  lines.push(`APP failures: ${diff.newAppFailures.length} new, ${diff.resolvedAppFailures.length} resolved`);

  if (diff.newFindings.length > 0) {
    lines.push('');
    lines.push('New findings:');
    for (const finding of diff.newFindings) {
      lines.push(`- [${finding.severity}] ${finding.title} (${finding.sourceRule})${formatLocation(finding)}`);
    }
  }

  if (diff.newAppFailures.length > 0) {
    lines.push('');
    lines.push('New APP failures:');
    for (const change of diff.newAppFailures) {
      lines.push(`- ${change.principle}: ${change.previousStatus} -> ${change.currentStatus} (${change.previousScore} -> ${change.currentScore})`);
    }
  }

  if (!diff.hasRegression && !diff.hasImprovement) {
    lines.push('');
    lines.push('No compliance changes detected.');
  }

  return lines.join('\n');
}

function getAppControlStatusChanges(
  baselineReport: ComplianceReport,
  currentReport: ComplianceReport,
): AppControlStatusChange[] {
  const baselineControls = new Map(baselineReport.appControls.map((control) => [control.principle, control]));
  const changes: AppControlStatusChange[] = [];

  for (const currentControl of currentReport.appControls) {
    const baselineControl = baselineControls.get(currentControl.principle);
    if (!baselineControl) {
      continue;
    }
    if (baselineControl.status === currentControl.status && baselineControl.score === currentControl.score) {
      continue;
    }

    changes.push({
      principle: currentControl.principle,
      previousStatus: baselineControl.status,
      currentStatus: currentControl.status,
      previousScore: baselineControl.score,
      currentScore: currentControl.score,
    });
  }

  return changes;
}

function toFindingDelta(finding: AttestLensFinding): FindingDelta {
  return {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    source: finding.source,
    sourceRule: finding.sourceRule,
    file: finding.file,
    line: finding.line,
    appPrinciples: getFindingPrinciples(finding),
  };
}

function getFindingPrinciples(finding: AttestLensFinding): APPPrinciple[] {
  return Array.from(new Set(finding.appMappings.map((mapping) => mapping.principle)));
}

function formatLocation(finding: FindingDelta): string {
  if (!finding.file) {
    return '';
  }
  return finding.line ? ` at ${finding.file}:${finding.line}` : ` at ${finding.file}`;
}
