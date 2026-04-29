import {
  ReformProvision,
  type APPControl,
  type APPPrinciple,
  type ComplianceReport,
  type QuestionnaireSession,
  type ReformProvision as ReformProvisionName,
} from '../schema/index.js';
import { escapeHtml } from '../utils/target.js';

export interface SMBComplianceResult {
  readinessScore: number;
  readinessLabel: 'Ready' | 'Nearly Ready' | 'Needs Work' | 'Not Ready' | 'Unknown';
  verdict: 'compliant' | 'partially_compliant' | 'non_compliant' | 'unknown';
  summary: string;
  actions: SMBAction[];
  gaps: SMBGap[];
  reformWarnings?: SMBReformWarning[];
}

export interface SMBAction {
  priority: 'urgent' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  deadline?: string;
  principle: APPPrinciple;
}

export interface SMBGap {
  area: string;
  status: 'missing' | 'partial' | 'unknown';
  description: string;
}

export interface SMBReformWarning {
  provision: string;
  deadline: string;
  impact: 'critical' | 'high' | 'medium';
  description: string;
}

interface PrincipleCopy {
  area: string;
  failTitle: string;
  unknownTitle: string;
  failDescription: string;
  unknownDescription: string;
  gapDescription: string;
  priority: SMBAction['priority'];
}

type ReformAssessment = NonNullable<ComplianceReport['reformImpactAssessment']>;
type ReformActionItem = ReformAssessment['actionItems'][number];
type ReformProvisionAssessment = ReformAssessment['provisions'][number];

const PRINCIPLE_ORDER: APPPrinciple[] = [
  'APP_1',
  'APP_2',
  'APP_3',
  'APP_4',
  'APP_5',
  'APP_6',
  'APP_7',
  'APP_8',
  'APP_9',
  'APP_10',
  'APP_11',
  'APP_12',
  'APP_13',
  'NDB',
];

const PRIORITY_ORDER: Record<SMBAction['priority'], number> = {
  urgent: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const PRINCIPLE_COPY: Record<APPPrinciple, PrincipleCopy> = {
  APP_1: {
    area: 'Privacy policy',
    failTitle: 'Add a privacy policy',
    unknownTitle: 'Confirm your privacy policy is easy to find',
    failDescription: 'Publish a short, clear privacy policy that explains what customer information you collect, why you collect it, how you use it, and how people can contact you.',
    unknownDescription: 'The scan could not confirm that customers can find a clear privacy policy. Check the website, app, and signup flow.',
    gapDescription: 'We could not confirm whether customers can find a clear privacy policy and privacy contact point.',
    priority: 'urgent',
  },
  APP_2: {
    area: 'Anonymous or minimal-use options',
    failTitle: 'Offer a low-information option where practical',
    unknownTitle: 'Check whether customers can use the service with less information',
    failDescription: 'Review forms and account flows so customers are not forced to provide more personal information than the service really needs.',
    unknownDescription: 'The scan could not tell whether customers can use the service with less personal information where that is practical.',
    gapDescription: 'We could not confirm whether the service lets people avoid unnecessary personal details where practical.',
    priority: 'low',
  },
  APP_3: {
    area: 'Information collection',
    failTitle: 'Only collect information you need',
    unknownTitle: 'Check what customer information you collect',
    failDescription: 'List the personal information you collect and remove fields, tracking, or uploads that do not have a clear business reason.',
    unknownDescription: 'The scan could not confirm that each item of customer information has a clear business reason.',
    gapDescription: 'We could not confirm whether all collected customer information is needed for the service.',
    priority: 'high',
  },
  APP_4: {
    area: 'Unexpected personal information',
    failTitle: 'Set a process for unexpected personal information',
    unknownTitle: 'Check how unexpected personal information is handled',
    failDescription: 'Create a simple process for reviewing personal information you receive by mistake and deleting or routing it safely.',
    unknownDescription: 'The scan could not confirm how the business handles personal information it did not ask for.',
    gapDescription: 'We could not confirm whether unexpected personal information is reviewed and handled safely.',
    priority: 'medium',
  },
  APP_5: {
    area: 'Collection notices',
    failTitle: 'Explain why you collect customer information',
    unknownTitle: 'Check your forms and signup notices',
    failDescription: 'Add short notices near forms, checkout, onboarding, or signup steps so people understand why you need their information.',
    unknownDescription: 'The scan could not confirm that customers are told why their information is collected.',
    gapDescription: 'We could not confirm whether collection points explain why customer information is needed.',
    priority: 'high',
  },
  APP_6: {
    area: 'Use and sharing',
    failTitle: 'Check how you use and share customer information',
    unknownTitle: 'Confirm customer information is only used as expected',
    failDescription: 'Map where customer information goes, who receives it, and whether each use matches what customers were told.',
    unknownDescription: 'The scan could not confirm whether customer information is only used or shared in expected ways.',
    gapDescription: 'We could not confirm whether customer information use and sharing matches what customers are told.',
    priority: 'high',
  },
  APP_7: {
    area: 'Marketing opt-out',
    failTitle: 'Make marketing opt-out easy',
    unknownTitle: 'Check marketing consent and opt-out paths',
    failDescription: 'If you send marketing messages, make the unsubscribe or opt-out path clear and make sure requests are actioned promptly.',
    unknownDescription: 'The scan could not confirm whether marketing messages have a clear opt-out path.',
    gapDescription: 'We could not confirm whether customers can easily stop marketing messages.',
    priority: 'medium',
  },
  APP_8: {
    area: 'Overseas service providers',
    failTitle: 'Check overseas service providers',
    unknownTitle: 'Confirm where customer information is sent',
    failDescription: 'List cloud tools, analytics, support, payment, and hosting providers that can access customer information, then confirm where that information is stored or processed.',
    unknownDescription: 'The scan found possible third-party or overseas services, but could not confirm whether customer information is sent outside Australia.',
    gapDescription: 'We could not confirm whether customer information is sent to overseas providers.',
    priority: 'high',
  },
  APP_9: {
    area: 'Government identifiers',
    failTitle: 'Limit government identifier use',
    unknownTitle: 'Check government identifier handling',
    failDescription: 'Review any Medicare, passport, driver licence, tax file, or other government identifier fields and keep only what the business genuinely needs.',
    unknownDescription: 'The scan could not confirm whether government identifiers are avoided or tightly controlled.',
    gapDescription: 'We could not confirm whether government identifiers are avoided or tightly controlled.',
    priority: 'high',
  },
  APP_10: {
    area: 'Information accuracy',
    failTitle: 'Keep customer details accurate',
    unknownTitle: 'Check how customer details are kept up to date',
    failDescription: 'Create a simple way to review, update, and correct customer details before they are used for important business decisions.',
    unknownDescription: 'The scan could not confirm how customer information is checked for accuracy.',
    gapDescription: 'We could not confirm whether customer details can be kept accurate and up to date.',
    priority: 'medium',
  },
  APP_11: {
    area: 'Security',
    failTitle: 'Strengthen personal information security',
    unknownTitle: 'Confirm security measures for customer information',
    failDescription: 'Fix the security issues found by the scan and check access controls, encryption, backups, logging, and old data stores.',
    unknownDescription: 'The scan could not confirm enough security measures for customer information.',
    gapDescription: 'We could not confirm whether customer information is protected with suitable security measures.',
    priority: 'high',
  },
  APP_12: {
    area: 'Customer access requests',
    failTitle: 'Set up customer access requests',
    unknownTitle: 'Check how customers can access their information',
    failDescription: 'Give customers a clear way to ask what information you hold about them and make sure staff know how to respond.',
    unknownDescription: 'The scan could not confirm whether customers have a clear way to access their information.',
    gapDescription: 'We could not confirm whether customers can ask what information the business holds about them.',
    priority: 'medium',
  },
  APP_13: {
    area: 'Correction requests',
    failTitle: 'Set up correction requests',
    unknownTitle: 'Check how customers can correct their information',
    failDescription: 'Create a simple correction process and make sure updates flow through the systems where customer details are stored.',
    unknownDescription: 'The scan could not confirm whether customers can correct wrong or outdated information.',
    gapDescription: 'We could not confirm whether customers can correct wrong or outdated information.',
    priority: 'medium',
  },
  NDB: {
    area: 'Data breach response',
    failTitle: 'Create a data breach response plan',
    unknownTitle: 'Confirm your data breach response plan',
    failDescription: 'Write a practical plan for investigating a data breach, limiting harm, deciding who must be told, and recording what happened.',
    unknownDescription: 'The scan could not confirm that the business has a practical plan for exposed or lost customer information.',
    gapDescription: 'We could not confirm whether the business has a practical plan for exposed or lost customer information.',
    priority: 'high',
  },
};

const REFORM_COPY: Record<ReformProvisionName, {
  provision: string;
  actionTitle: string;
  actionDescription: string;
  warningDescription: string;
  principle: APPPrinciple;
}> = {
  [ReformProvision.STATUTORY_TORT]: {
    provision: 'Serious privacy harm claims',
    actionTitle: 'Prepare for serious privacy harm claims',
    actionDescription: 'Review collection, sharing, correction, and complaint handling so the business can reduce the chance of serious privacy harm.',
    warningDescription: 'The scan found signals that could increase exposure if a customer claims serious privacy harm.',
    principle: 'APP_6',
  },
  [ReformProvision.CHILDREN_PRIVACY_CODE]: {
    provision: 'Children\'s privacy rules',
    actionTitle: 'Prepare for children\'s privacy rules',
    actionDescription: 'If children may use the service, check age handling, consent, notices, and any data sharing that affects young users.',
    warningDescription: 'The scan found signals that the service may collect or use information about children.',
    principle: 'APP_3',
  },
  [ReformProvision.AUTOMATED_DECISION_MAKING]: {
    provision: 'Automated decision notices',
    actionTitle: 'Explain important automated decisions',
    actionDescription: 'If automated systems approve, reject, rank, or score people, document what they do and how a person can review important outcomes.',
    warningDescription: 'The scan found signals that automated systems may make or support decisions that affect people.',
    principle: 'APP_10',
  },
  [ReformProvision.AML_CTF]: {
    provision: 'AML/CTF customer checks',
    actionTitle: 'Review customer identity and transaction checks',
    actionDescription: 'If the business handles payments, transfers, lending, crypto, or identity checks, review how customer data is collected, protected, and shared.',
    warningDescription: 'The scan found signals that identity or transaction checks may need extra privacy and security review.',
    principle: 'APP_11',
  },
};

export function buildSMBComplianceResult(
  report: ComplianceReport,
  questionnaireSession?: QuestionnaireSession,
): SMBComplianceResult {
  const hasEvaluatedControls = report.appControls.some((control) =>
    control.status !== 'unknown' || control.findings.length > 0,
  );
  const readinessScore = hasEvaluatedControls ? clampScore(report.overallScore) : 0;
  const readinessLabel = hasEvaluatedControls ? getReadinessLabel(readinessScore) : 'Unknown';
  const verdict = getSMBVerdict(report.appControls);
  const actions = buildSMBActions(report);
  const gaps = buildSMBGaps(report.appControls, questionnaireSession);
  const reformWarnings = buildSMBReformWarnings(report.reformImpactAssessment);
  const summary = buildSMBSummary({
    readinessLabel,
    readinessScore,
    verdict,
    failedCount: report.appControls.filter((control) => control.status === 'fail').length,
    unknownCount: gaps.length,
    actionCount: actions.length,
    hasQuestionnaire: Boolean(questionnaireSession),
    hasControls: hasEvaluatedControls,
  });

  return {
    readinessScore,
    readinessLabel,
    verdict,
    summary,
    actions,
    gaps,
    reformWarnings: reformWarnings.length > 0 ? reformWarnings : undefined,
  };
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function getReadinessLabel(score: number): SMBComplianceResult['readinessLabel'] {
  if (score >= 80) return 'Ready';
  if (score >= 60) return 'Nearly Ready';
  if (score >= 40) return 'Needs Work';
  return 'Not Ready';
}

function getSMBVerdict(controls: APPControl[]): SMBComplianceResult['verdict'] {
  if (controls.length === 0) {
    return 'unknown';
  }

  const failCount = controls.filter((control) => control.status === 'fail').length;
  const unknownCount = controls.filter((control) => control.status === 'unknown').length;

  if (failCount === 0 && unknownCount === 0) {
    return 'compliant';
  }

  if (failCount > 0) {
    return failCount / controls.length > 0.5 ? 'non_compliant' : 'partially_compliant';
  }

  return unknownCount === controls.length ? 'unknown' : 'partially_compliant';
}

function buildSMBSummary(params: {
  readinessLabel: SMBComplianceResult['readinessLabel'];
  readinessScore: number;
  verdict: SMBComplianceResult['verdict'];
  failedCount: number;
  unknownCount: number;
  actionCount: number;
  hasQuestionnaire: boolean;
  hasControls: boolean;
}): string {
  if (!params.hasControls || params.readinessLabel === 'Unknown' || params.verdict === 'unknown') {
    return 'There is not enough evidence to give a clear readiness view yet. Complete the business questions and review the gaps before relying on this check.';
  }

  if (params.readinessLabel === 'Ready') {
    return 'Your project looks ready based on the checks completed. Keep the privacy policy, security controls, and customer request processes under regular review.';
  }

  if (params.readinessLabel === 'Nearly Ready') {
    return params.failedCount > 0
      ? 'Your project has most privacy basics in place, but a few important items still need attention. Start with the highest-priority actions below.'
      : 'Your project has most privacy basics in place, but some areas still need confirmation. Resolve the gaps before presenting this as complete.';
  }

  if (params.readinessLabel === 'Needs Work') {
    return 'Your project needs several privacy basics fixed before it is ready for customers or external review. Focus on the urgent and high-priority actions first.';
  }

  return 'Your project is not ready from a privacy standpoint yet. Fix the urgent items first, then rerun the check once the core controls are in place.';
}

function buildSMBActions(report: ComplianceReport): SMBAction[] {
  const actions: SMBAction[] = [];

  for (const control of report.appControls) {
    if (control.status !== 'fail' && control.status !== 'unknown') {
      continue;
    }

    const copy = PRINCIPLE_COPY[control.principle];
    actions.push({
      priority: copy.priority,
      title: control.status === 'fail' ? copy.failTitle : copy.unknownTitle,
      description: control.status === 'fail'
        ? appendFindingContext(copy.failDescription, control)
        : copy.unknownDescription,
      principle: control.principle,
    });
  }

  for (const actionItem of report.reformImpactAssessment?.actionItems || []) {
    actions.push(buildReformAction(actionItem));
  }

  return sortSMBActions(actions);
}

function appendFindingContext(description: string, control: APPControl): string {
  if (control.findings.length === 0) {
    return description;
  }

  return `${description} The scan linked ${control.findings.length} issue${control.findings.length === 1 ? '' : 's'} to this area.`;
}

function buildReformAction(actionItem: ReformActionItem): SMBAction {
  const copy = REFORM_COPY[actionItem.provision];
  return {
    priority: getReformActionPriority(actionItem.priority),
    title: copy.actionTitle,
    description: copy.actionDescription,
    deadline: `By ${formatReformDeadline(actionItem.deadline)}`,
    principle: copy.principle,
  };
}

function getReformActionPriority(priority: ReformActionItem['priority']): SMBAction['priority'] {
  switch (priority) {
    case 'immediate':
      return 'urgent';
    case 'before_deadline':
      return 'high';
    case 'recommended':
    default:
      return 'medium';
  }
}

function sortSMBActions(actions: SMBAction[]): SMBAction[] {
  return [...actions].sort((left, right) => {
    const priorityDelta = PRIORITY_ORDER[left.priority] - PRIORITY_ORDER[right.priority];
    if (priorityDelta !== 0) return priorityDelta;
    return PRINCIPLE_ORDER.indexOf(left.principle) - PRINCIPLE_ORDER.indexOf(right.principle);
  });
}

function buildSMBGaps(
  controls: APPControl[],
  questionnaireSession?: QuestionnaireSession,
): SMBGap[] {
  const hasQuestionnaire = Boolean(questionnaireSession);

  return controls
    .filter((control) => control.status === 'unknown')
    .map((control) => {
      const copy = PRINCIPLE_COPY[control.principle];
      return {
        area: copy.area,
        status: 'unknown',
        description: hasQuestionnaire
          ? `${copy.gapDescription} The questionnaire did not fully resolve this area.`
          : `${copy.gapDescription} A scan alone usually cannot confirm this business process.`,
      };
    });
}

function buildSMBReformWarnings(
  assessment: ComplianceReport['reformImpactAssessment'],
): SMBReformWarning[] {
  if (!assessment) {
    return [];
  }

  return assessment.provisions
    .filter((provision) => provision.findingCount > 0)
    .map((provision) => {
      const copy = REFORM_COPY[provision.provision];
      return {
        provision: copy.provision,
        deadline: formatReformDeadline(provision.effectiveDate),
        impact: getProvisionImpact(provision),
        description: `${copy.warningDescription} Review ${provision.findingCount} flagged item${provision.findingCount === 1 ? '' : 's'} before the change starts.`,
      };
    });
}

function getProvisionImpact(provision: ReformProvisionAssessment): SMBReformWarning['impact'] {
  const severities = provision.findings.map((finding) => finding.severity);
  if (severities.includes('critical')) {
    return 'critical';
  }
  if (severities.includes('high')) {
    return 'high';
  }
  return 'medium';
}

function formatReformDeadline(rawDate: string): string {
  const parsed = new Date(`${rawDate}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) {
    return rawDate;
  }

  return new Intl.DateTimeFormat('en-AU', {
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(parsed);
}

function getPriorityBadge(priority: SMBAction['priority']): string {
  return priority;
}

function getImpactBadge(impact: SMBReformWarning['impact']): string {
  return impact;
}

function escapeMarkdownTable(text: string): string {
  return text.replace(/\|/g, '\\|');
}

export function generateSMBMarkdownReport(result: SMBComplianceResult): string {
  const lines: string[] = [];

  lines.push('# Compliance Check Report');
  lines.push('');
  lines.push(`## Compliance Readiness: ${result.readinessScore}/100 — ${result.readinessLabel}`);
  lines.push('');
  lines.push(result.summary);
  lines.push('');
  lines.push('## ⚡ Priority Actions');
  lines.push('');
  if (result.actions.length === 0) {
    lines.push('No priority actions found.');
  } else {
    result.actions.forEach((action, index) => {
      const deadline = action.deadline ? ` ${action.deadline}.` : '';
      lines.push(`${index + 1}. **${escapeMarkdownTable(action.title)}** (${getPriorityBadge(action.priority)}) — ${escapeMarkdownTable(action.description)}${deadline}`);
    });
  }
  lines.push('');
  lines.push('## 🔍 Gaps');
  lines.push('');
  if (result.gaps.length === 0) {
    lines.push('No unresolved gaps found.');
  } else {
    for (const gap of result.gaps) {
      lines.push(`- **${escapeMarkdownTable(gap.area)}**: ${gap.status} — ${escapeMarkdownTable(gap.description)}`);
    }
  }
  lines.push('');
  lines.push('## ⚠️ Upcoming Law Changes');
  lines.push('');
  if (!result.reformWarnings || result.reformWarnings.length === 0) {
    lines.push('No upcoming law change warnings found in this run.');
  } else {
    for (const warning of result.reformWarnings) {
      lines.push(`- **${escapeMarkdownTable(warning.provision)}** (by ${escapeMarkdownTable(warning.deadline)}) — ${escapeMarkdownTable(warning.description)} (${getImpactBadge(warning.impact)})`);
    }
  }

  return lines.join('\n');
}

export function generateSMBHTMLReport(result: SMBComplianceResult): string {
  const scoreClass = getScoreClass(result.readinessLabel);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Compliance Check Report</title>
</head>
<body style="margin:0;background:#f4f7fb;color:#18212f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55;">
  <main style="max-width:920px;margin:0 auto;padding:28px 18px 48px;">
    <section style="background:#ffffff;border:1px solid #dbe4ef;border-radius:12px;padding:28px;box-shadow:0 14px 34px rgba(20,32,50,0.08);">
      <h1 style="margin:0 0 20px;font-size:32px;line-height:1.15;color:#101827;">Compliance Check Report</h1>
      <div style="display:flex;flex-wrap:wrap;gap:14px;align-items:center;margin-bottom:18px;">
        <div style="font-size:44px;font-weight:800;color:${getScoreColor(scoreClass)};">${result.readinessScore}/100</div>
        <div>
          <div style="font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;font-weight:700;">Compliance Readiness</div>
          <div style="font-size:22px;font-weight:750;color:#101827;">${escapeHtml(result.readinessLabel)}</div>
        </div>
      </div>
      <p style="font-size:17px;margin:0;color:#334155;">${escapeHtml(result.summary)}</p>
    </section>

    <section style="background:#ffffff;border:1px solid #dbe4ef;border-radius:12px;padding:24px;margin-top:18px;">
      <h2 style="margin:0 0 16px;font-size:22px;color:#101827;">⚡ Priority Actions</h2>
      ${generateHTMLActions(result.actions)}
    </section>

    <section style="background:#ffffff;border:1px solid #dbe4ef;border-radius:12px;padding:24px;margin-top:18px;">
      <h2 style="margin:0 0 16px;font-size:22px;color:#101827;">🔍 Gaps</h2>
      ${generateHTMLGaps(result.gaps)}
    </section>

    <section style="background:#ffffff;border:1px solid #dbe4ef;border-radius:12px;padding:24px;margin-top:18px;">
      <h2 style="margin:0 0 16px;font-size:22px;color:#101827;">⚠️ Upcoming Law Changes</h2>
      ${generateHTMLReformWarnings(result.reformWarnings || [])}
    </section>
  </main>
</body>
</html>`;
}

function generateHTMLActions(actions: SMBAction[]): string {
  if (actions.length === 0) {
    return '<p style="margin:0;color:#475569;">No priority actions found.</p>';
  }

  return `<ol style="margin:0;padding-left:22px;">
    ${actions.map((action) => `
      <li style="margin:0 0 14px;padding-left:6px;">
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <strong style="font-size:16px;color:#101827;">${escapeHtml(action.title)}</strong>
          <span style="${getPriorityBadgeStyle(action.priority)}">${escapeHtml(action.priority)}</span>
        </div>
        <p style="margin:6px 0 0;color:#334155;">${escapeHtml(action.description)}${action.deadline ? ` <strong>${escapeHtml(action.deadline)}.</strong>` : ''}</p>
      </li>
    `).join('')}
  </ol>`;
}

function generateHTMLGaps(gaps: SMBGap[]): string {
  if (gaps.length === 0) {
    return '<p style="margin:0;color:#475569;">No unresolved gaps found.</p>';
  }

  return `<ul style="margin:0;padding-left:20px;">
    ${gaps.map((gap) => `
      <li style="margin:0 0 12px;">
        <strong style="color:#101827;">${escapeHtml(gap.area)}</strong>:
        <span style="font-weight:700;color:#9a3412;">${escapeHtml(gap.status)}</span>
        <span style="color:#334155;">— ${escapeHtml(gap.description)}</span>
      </li>
    `).join('')}
  </ul>`;
}

function generateHTMLReformWarnings(warnings: SMBReformWarning[]): string {
  if (warnings.length === 0) {
    return '<p style="margin:0;color:#475569;">No upcoming law change warnings found in this run.</p>';
  }

  return `<ul style="margin:0;padding-left:20px;">
    ${warnings.map((warning) => `
      <li style="margin:0 0 12px;">
        <strong style="color:#101827;">${escapeHtml(warning.provision)}</strong>
        <span style="color:#64748b;">(by ${escapeHtml(warning.deadline)})</span>
        <span style="color:#334155;">— ${escapeHtml(warning.description)}</span>
        <span style="${getImpactBadgeStyle(warning.impact)}">${escapeHtml(warning.impact)}</span>
      </li>
    `).join('')}
  </ul>`;
}

function getScoreClass(label: SMBComplianceResult['readinessLabel']): 'green' | 'yellow' | 'orange' | 'red' | 'gray' {
  switch (label) {
    case 'Ready':
      return 'green';
    case 'Nearly Ready':
      return 'yellow';
    case 'Needs Work':
      return 'orange';
    case 'Not Ready':
      return 'red';
    case 'Unknown':
    default:
      return 'gray';
  }
}

function getScoreColor(scoreClass: ReturnType<typeof getScoreClass>): string {
  switch (scoreClass) {
    case 'green':
      return '#15803d';
    case 'yellow':
      return '#b45309';
    case 'orange':
      return '#c2410c';
    case 'red':
      return '#dc2626';
    case 'gray':
    default:
      return '#64748b';
  }
}

function getPriorityBadgeStyle(priority: SMBAction['priority']): string {
  const base = 'display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:800;text-transform:uppercase;';
  switch (priority) {
    case 'urgent':
      return `${base}background:#fee2e2;color:#b91c1c;`;
    case 'high':
      return `${base}background:#ffedd5;color:#c2410c;`;
    case 'medium':
      return `${base}background:#fef3c7;color:#a16207;`;
    case 'low':
    default:
      return `${base}background:#e0f2fe;color:#0369a1;`;
  }
}

function getImpactBadgeStyle(impact: SMBReformWarning['impact']): string {
  const base = 'display:inline-block;margin-left:8px;border-radius:999px;padding:2px 8px;font-size:11px;font-weight:800;text-transform:uppercase;';
  switch (impact) {
    case 'critical':
      return `${base}background:#fee2e2;color:#b91c1c;`;
    case 'high':
      return `${base}background:#ffedd5;color:#c2410c;`;
    case 'medium':
    default:
      return `${base}background:#fef3c7;color:#a16207;`;
  }
}
