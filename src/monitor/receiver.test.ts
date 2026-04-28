import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MonitorJobQueue } from './queue.js';
import { createWebhookReceiver } from './receiver.js';

describe('createWebhookReceiver', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-receiver-test-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('validates GitHub signatures and queues push scan jobs', async () => {
    const secret = 'test-secret';
    const queue = new MonitorJobQueue({ rootDir: tempDir });
    await queue.loadPersistedJobs();
    const app = createWebhookReceiver({ secret, queue });
    const body = JSON.stringify({
      ref: 'refs/heads/main',
      after: 'abc123',
      repository: { clone_url: 'https://github.com/example/repo.git' },
      sender: { login: 'octocat' },
      installation: { id: 42 },
    });

    const response = await app.fetch(new Request('http://localhost/webhook/github', {
      method: 'POST',
      headers: {
        'x-github-event': 'push',
        'x-github-delivery': 'delivery-1',
        'x-hub-signature-256': sign(body, secret),
      },
      body,
    }));

    expect(response.status).toBe(202);
    const jobs = queue.list();
    expect(jobs).toHaveLength(1);
    expect(jobs[0]).toMatchObject({
      repoUrl: 'https://github.com/example/repo.git',
      branch: 'main',
      commitSha: 'abc123',
      installationId: 42,
    });
  });

  it('rejects invalid signatures', async () => {
    const queue = new MonitorJobQueue({ rootDir: tempDir });
    const app = createWebhookReceiver({ secret: 'test-secret', queue });

    const response = await app.fetch(new Request('http://localhost/webhook/github', {
      method: 'POST',
      headers: {
        'x-github-event': 'push',
        'x-hub-signature-256': 'sha256=bad',
      },
      body: '{}',
    }));

    expect(response.status).toBe(401);
    expect(queue.list()).toHaveLength(0);
  });
});

function sign(body: string, secret: string): string {
  return `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;
}
