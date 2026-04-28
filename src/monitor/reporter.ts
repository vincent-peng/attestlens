import type { ComplianceReport } from '../schema/index.js';
import type { MonitorJob, RegressionDiff } from './types.js';

export interface ReporterOptions {
  githubToken?: string;
  githubApiBaseUrl?: string;
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
}

export async function reportMonitorResult(
  job: MonitorJob,
  report: ComplianceReport,
  diff: RegressionDiff | undefined,
  options: ReporterOptions = {},
): Promise<void> {
  const tasks: Array<Promise<void>> = [];
  if (job.pullRequestNumber) {
    tasks.push(postGitHubPullRequestComment(job, report, diff, options));
  }
  tasks.push(sendWebhookNotifications(report, diff, options));
  await Promise.all(tasks);
}

export async function postGitHubPullRequestComment(
  job: MonitorJob,
  report: ComplianceReport,
  diff: RegressionDiff | undefined,
  options: ReporterOptions = {},
): Promise<void> {
  const token = options.githubToken || process.env.GITHUB_TOKEN || process.env.GITHUB_APP_TOKEN;
  if (!token || !job.pullRequestNumber) {
    return;
  }

  const repo = parseGitHubRepo(job.repoUrl);
  if (!repo) {
    throw new Error(`Cannot derive GitHub owner/repo from ${job.repoUrl}`);
  }

  const apiBaseUrl = options.githubApiBaseUrl || 'https://api.github.com';
  const response = await fetch(`${apiBaseUrl}/repos/${repo.owner}/${repo.name}/issues/${job.pullRequestNumber}/comments`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'user-agent': 'attestlens-monitor',
      'x-github-api-version': '2022-11-28',
    },
    body: JSON.stringify({ body: formatPullRequestComment(report, diff) }),
  });

  if (!response.ok) {
    throw new Error(`GitHub PR comment failed: ${response.status} ${await response.text()}`);
  }
}

export async function sendWebhookNotifications(
  report: ComplianceReport,
  diff: RegressionDiff | undefined,
  options: ReporterOptions = {},
): Promise<void> {
  const text = formatNotification(report, diff);
  const slackWebhookUrl = options.slackWebhookUrl || process.env.ATTESTLENS_SLACK_WEBHOOK_URL;
  const discordWebhookUrl = options.discordWebhookUrl || process.env.ATTESTLENS_DISCORD_WEBHOOK_URL;

  await Promise.all([
    slackWebhookUrl ? postJsonWebhook(slackWebhookUrl, { text }) : Promise.resolve(),
    discordWebhookUrl ? postJsonWebhook(discordWebhookUrl, { content: text }) : Promise.resolve(),
  ]);
}

export function formatPullRequestComment(report: ComplianceReport, diff?: RegressionDiff): string {
  const counts = countControls(report);
  const lines = [
    '## AttestLens compliance monitor',
    '',
    `Score: **${report.overallScore}/100**`,
    `Grade: **${report.overallGrade}**`,
    `APP controls: **${counts.pass} pass**, **${counts.fail} fail**, **${counts.unknown} unknown**`,
    `Findings: **${report.findings.length}**`,
  ];

  if (diff?.hasRegression) {
    lines.push('', `Regression warning: ${diff.newFindings.length} new finding(s), ${diff.newAppFailures.length} new APP failure(s).`);
  }

  if (diff) {
    lines.push('', '```text', diff.summary, '```');
  }

  return lines.join('\n');
}

export function formatNotification(report: ComplianceReport, diff?: RegressionDiff): string {
  const counts = countControls(report);
  const status = diff?.hasRegression ? 'Regression detected' : 'Compliance scan complete';
  return [
    `AttestLens: ${status}`,
    `Score ${report.overallScore}/100, grade ${report.overallGrade}`,
    `APP controls: ${counts.pass} pass, ${counts.fail} fail, ${counts.unknown} unknown`,
    diff ? `Diff: ${diff.newFindings.length} new finding(s), ${diff.resolvedFindings.length} resolved` : undefined,
  ].filter(Boolean).join('\n');
}

function countControls(report: ComplianceReport): { pass: number; fail: number; unknown: number } {
  return {
    pass: report.appControls.filter((control) => control.status === 'pass').length,
    fail: report.appControls.filter((control) => control.status === 'fail').length,
    unknown: report.appControls.filter((control) => control.status === 'unknown').length,
  };
}

async function postJsonWebhook(url: string, payload: unknown): Promise<void> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Webhook notification failed: ${response.status} ${await response.text()}`);
  }
}

function parseGitHubRepo(repoUrl: string): { owner: string; name: string } | undefined {
  const sshMatch = /^git@github\.com:([^/]+)\/(.+?)(?:\.git)?$/.exec(repoUrl);
  if (sshMatch) {
    return { owner: sshMatch[1], name: sshMatch[2] };
  }

  try {
    const parsed = new URL(repoUrl);
    if (parsed.hostname !== 'github.com') {
      return undefined;
    }
    const [owner, rawName] = parsed.pathname.replace(/^\/+/, '').split('/');
    if (!owner || !rawName) {
      return undefined;
    }
    return { owner, name: rawName.replace(/\.git$/, '') };
  } catch {
    return undefined;
  }
}
