import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import type { MonitorJob, MonitorJobState, MonitorTrigger } from './types.js';

export type MonitorJobProcessor = (job: MonitorJob) => Promise<Partial<MonitorJob> | void>;

export interface MonitorJobQueueOptions {
  rootDir?: string;
  processor?: MonitorJobProcessor;
}

export interface EnqueueJobInput {
  repoUrl: string;
  branch: string;
  commitSha?: string;
  pullRequestNumber?: number;
  installationId?: number;
  triggeredBy: MonitorTrigger;
}

export class MonitorJobQueue {
  private readonly rootDir: string;
  private readonly processor?: MonitorJobProcessor;
  private jobs = new Map<string, MonitorJob>();
  private started = false;
  private processing = false;

  constructor(options: MonitorJobQueueOptions = {}) {
    this.rootDir = options.rootDir || getDefaultQueueRoot();
    this.processor = options.processor;
  }

  async loadPersistedJobs(): Promise<void> {
    await fs.mkdir(this.rootDir, { recursive: true });
    const entries = await fs.readdir(this.rootDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) {
        continue;
      }

      const raw = await fs.readFile(path.join(this.rootDir, entry.name), 'utf-8');
      const job = parseJob(JSON.parse(raw));
      if (job.state === 'running') {
        job.state = 'pending';
        job.updatedAt = new Date().toISOString();
      }
      this.jobs.set(job.id, job);
    }
  }

  async enqueue(input: EnqueueJobInput): Promise<MonitorJob> {
    const now = new Date().toISOString();
    const job: MonitorJob = {
      id: crypto.randomUUID(),
      repoUrl: input.repoUrl,
      branch: input.branch,
      commitSha: input.commitSha,
      pullRequestNumber: input.pullRequestNumber,
      installationId: input.installationId,
      triggeredBy: input.triggeredBy,
      state: 'pending',
      createdAt: now,
      updatedAt: now,
    };

    this.jobs.set(job.id, job);
    await this.persist(job);
    void this.processNext();
    return job;
  }

  start(): void {
    this.started = true;
    void this.processNext();
  }

  stop(): void {
    this.started = false;
  }

  get(id: string): MonitorJob | undefined {
    return this.jobs.get(id);
  }

  list(): MonitorJob[] {
    return Array.from(this.jobs.values()).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async waitForIdle(): Promise<void> {
    while (this.processing || this.list().some((job) => job.state === 'pending')) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  private async processNext(): Promise<void> {
    if (!this.started || this.processing || !this.processor) {
      return;
    }

    const job = this.list().find((candidate) => candidate.state === 'pending');
    if (!job) {
      return;
    }

    this.processing = true;
    await this.transition(job, 'running', { startedAt: new Date().toISOString() });

    try {
      const updates = await this.processor(job);
      await this.transition(job, 'completed', {
        ...updates,
        completedAt: new Date().toISOString(),
      });
    } catch (error: any) {
      await this.transition(job, 'failed', {
        failedAt: new Date().toISOString(),
        error: error?.message || String(error),
      });
    } finally {
      this.processing = false;
      void this.processNext();
    }
  }

  private async transition(job: MonitorJob, state: MonitorJobState, updates: Partial<MonitorJob> = {}): Promise<void> {
    const updated: MonitorJob = {
      ...job,
      ...updates,
      state,
      updatedAt: new Date().toISOString(),
    };
    this.jobs.set(updated.id, updated);
    Object.assign(job, updated);
    await this.persist(updated);
  }

  private async persist(job: MonitorJob): Promise<void> {
    await fs.mkdir(this.rootDir, { recursive: true });
    await fs.writeFile(this.getJobPath(job.id), `${JSON.stringify(job, null, 2)}\n`, 'utf-8');
  }

  private getJobPath(id: string): string {
    return path.join(this.rootDir, `${id}.json`);
  }
}

export function getDefaultQueueRoot(): string {
  return path.join(os.homedir(), '.attestlens', 'queue');
}

function parseJob(value: unknown): MonitorJob {
  if (!value || typeof value !== 'object') {
    throw new Error('Invalid monitor job file: expected object');
  }

  const job = value as MonitorJob;
  if (!job.id || !job.repoUrl || !job.branch || !job.state) {
    throw new Error('Invalid monitor job file: missing required fields');
  }
  if (!['pending', 'running', 'completed', 'failed'].includes(job.state)) {
    throw new Error(`Invalid monitor job file: unsupported state ${job.state}`);
  }
  return job;
}
