import { Command } from 'commander';
import path from 'node:path';

import { ScannerOrchestrator } from '../scanner/orchestrator.js';
import { buildComplianceReport } from '../report/generator.js';
import { BaselineStore } from './baseline.js';
import { checkoutRepository } from './checkout.js';
import { compareReportToBaseline } from './diff.js';
import { MonitorJobQueue } from './queue.js';
import { reportMonitorResult } from './reporter.js';
import { startWebhookReceiver } from './receiver.js';
import type { Baseline, MonitorJob, MonitorScanResult, RegressionDiff } from './types.js';

export interface RunMonitorScanOptions {
  baselineStore?: BaselineStore;
  tempRoot?: string;
  cacheRoot?: string;
  report?: boolean;
}

export function registerMonitorCommands(program: Command): void {
  const monitor = program
    .command('monitor')
    .description('Continuous compliance monitoring commands');

  monitor
    .command('start')
    .description('Start the GitHub webhook receiver server')
    .option('-p, --port <port>', 'Webhook receiver port', '8787')
    .option('--host <host>', 'Webhook receiver host', '0.0.0.0')
    .option('--secret <secret>', 'GitHub webhook secret. Defaults to ATTESTLENS_WEBHOOK_SECRET')
    .action(async (options: any) => {
      const secret = options.secret || process.env.ATTESTLENS_WEBHOOK_SECRET;
      if (!secret) {
        throw new Error('Missing webhook secret. Set ATTESTLENS_WEBHOOK_SECRET or pass --secret.');
      }

      const queue = new MonitorJobQueue({
        processor: async (job) => {
          const result = await runMonitorScanJob(job, { report: true });
          return {
            report: result.report,
            diff: result.diff,
            baselinePath: result.baseline ? new BaselineStore().getPath(job.repoUrl, job.branch) : undefined,
          };
        },
      });
      await queue.loadPersistedJobs();
      queue.start();

      const server = await startWebhookReceiver({
        secret,
        queue,
        port: Number.parseInt(options.port, 10),
        hostname: options.host,
      });
      const address = server.address();
      console.log(`AttestLens monitor listening on ${typeof address === 'object' && address ? address.port : options.port}`);
    });

  monitor
    .command('scan')
    .description('Manually run a monitored scan and update the branch baseline')
    .argument('<repo-url>', 'Git repository URL')
    .argument('<branch>', 'Branch or commit ref to scan')
    .action(async (repoUrl: string, branch: string) => {
      const job = createManualJob(repoUrl, branch);
      const result = await runMonitorScanJob(job, { report: true });
      console.log(formatScanResult(result));
    });

  monitor
    .command('baseline')
    .description('Show the current stored baseline for a repo branch')
    .argument('<repo-url>', 'Git repository URL')
    .argument('<branch>', 'Branch name')
    .action(async (repoUrl: string, branch: string) => {
      const baseline = await new BaselineStore().load(repoUrl, branch);
      if (!baseline) {
        console.log('No baseline stored.');
        return;
      }
      console.log(JSON.stringify(baseline, null, 2));
    });

  monitor
    .command('diff')
    .description('Scan a repo branch and show the regression diff against the current baseline without updating it')
    .argument('<repo-url>', 'Git repository URL')
    .argument('<branch>', 'Branch or commit ref to scan')
    .action(async (repoUrl: string, branch: string) => {
      const job = createManualJob(repoUrl, branch);
      const result = await runMonitorScanJob(job, { report: false });
      if (!result.diff) {
        console.log('No baseline stored; diff unavailable.');
        return;
      }
      console.log(result.diff.summary);
    });
}

export async function runMonitorScanJob(
  job: MonitorJob,
  options: RunMonitorScanOptions = {},
): Promise<MonitorScanResult> {
  const baselineStore = options.baselineStore || new BaselineStore();
  const checkout = await checkoutRepository(job.repoUrl, job.commitSha || job.branch, {
    tempRoot: options.tempRoot,
    cacheRoot: options.cacheRoot,
  });

  try {
    const orchestrator = new ScannerOrchestrator({
      behavioral: { enabled: true },
      iac: { enabled: true },
      gitleaks: { enabled: false },
    });
    const scanResult = await orchestrator.scan(checkout.path);
    const report = buildComplianceReport(scanResult.findings, {
      targetName: path.basename(checkout.path),
      targetPath: checkout.path,
      targetVersion: job.commitSha,
      formats: ['json'],
      outputDir: '',
      ruleFreshness: scanResult.ruleFreshness,
    }, scanResult.totalDurationMs);
    report.metadata.scannerVersions = Object.fromEntries(scanResult.results.map((result) => [result.source, result.version]));

    const baseline = await baselineStore.load(job.repoUrl, job.branch);
    const diff = baseline ? compareReportToBaseline(baseline, report, job.commitSha) : undefined;

    if (options.report !== false) {
      await reportMonitorResult(job, report, diff);
      await baselineStore.save(job.repoUrl, job.branch, report, job.commitSha);
    }

    return { job, report, baseline, diff };
  } finally {
    await checkout.cleanup();
  }
}

function createManualJob(repoUrl: string, branch: string): MonitorJob {
  const now = new Date().toISOString();
  return {
    id: `manual-${Date.now()}`,
    repoUrl,
    branch,
    triggeredBy: { type: 'manual' },
    state: 'running',
    createdAt: now,
    updatedAt: now,
    startedAt: now,
  };
}

function formatScanResult(result: MonitorScanResult): string {
  const lines = [
    `Score: ${result.report.overallScore}/100`,
    `Grade: ${result.report.overallGrade}`,
    `Findings: ${result.report.findings.length}`,
  ];
  if (result.diff) {
    lines.push('', result.diff.summary);
  } else {
    lines.push('', 'No previous baseline; stored current report as baseline.');
  }
  return lines.join('\n');
}
