import type {
  APPPrinciple,
  AttestLensFinding,
  ComplianceReport,
  ControlStatus,
  RegulationPrinciple,
  ReportGrade,
} from '../schema/index.js';

export type MonitorJobState = 'pending' | 'running' | 'completed' | 'failed';

export type MonitorTrigger =
  | { type: 'manual'; actor?: string }
  | { type: 'github_push'; actor?: string; deliveryId?: string }
  | { type: 'github_pull_request'; actor?: string; deliveryId?: string; pullRequestNumber?: number };

export interface MonitorJob {
  id: string;
  repoUrl: string;
  branch: string;
  commitSha?: string;
  pullRequestNumber?: number;
  installationId?: number;
  triggeredBy: MonitorTrigger;
  state: MonitorJobState;
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
  failedAt?: string;
  error?: string;
  checkoutPath?: string;
  baselinePath?: string;
  report?: ComplianceReport;
  diff?: RegressionDiff;
}

export interface BaselineControlSnapshot {
  principle: APPPrinciple;
  status: ControlStatus;
  score: number;
  findingCount: ComplianceReport['appControls'][number]['findingCount'];
  findings: string[];
}

export interface Baseline {
  schemaVersion: '1.0';
  repoUrl: string;
  repoHash: string;
  branch: string;
  commitSha?: string;
  createdAt: string;
  updatedAt: string;
  report: ComplianceReport;
  summary: {
    overallScore: number;
    overallGrade: ReportGrade;
    riskLevel: ComplianceReport['riskLevel'];
    findingCount: number;
    appControls: BaselineControlSnapshot[];
  };
}

export interface FindingDelta {
  id: string;
  title: string;
  severity: AttestLensFinding['severity'];
  source: AttestLensFinding['source'];
  sourceRule: string;
  file?: string;
  line?: number;
  appPrinciples: APPPrinciple[];
  regulationPrinciples: RegulationPrinciple[];
}

export interface AppControlStatusChange {
  principle: APPPrinciple;
  previousStatus: ControlStatus;
  currentStatus: ControlStatus;
  previousScore: number;
  currentScore: number;
}

export interface RegressionDiff {
  repoUrl: string;
  branch: string;
  baselineCommitSha?: string;
  currentCommitSha?: string;
  comparedAt: string;
  scoreChange: {
    previous: number;
    current: number;
    delta: number;
  };
  gradeChange?: {
    previous: ReportGrade;
    current: ReportGrade;
  };
  newFindings: FindingDelta[];
  resolvedFindings: FindingDelta[];
  newAppFailures: AppControlStatusChange[];
  resolvedAppFailures: AppControlStatusChange[];
  statusChanges: AppControlStatusChange[];
  hasRegression: boolean;
  hasImprovement: boolean;
  summary: string;
}

export interface CheckoutResult {
  path: string;
  cleanup: () => Promise<void>;
}

export interface MonitorScanResult {
  job: MonitorJob;
  report: ComplianceReport;
  baseline?: Baseline;
  diff?: RegressionDiff;
}
