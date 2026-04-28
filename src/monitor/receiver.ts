import crypto from 'node:crypto';
import http from 'node:http';

import { Hono } from 'hono';

import { MonitorJobQueue } from './queue.js';
import type { MonitorJob } from './types.js';

export interface WebhookReceiverOptions {
  secret: string;
  queue: MonitorJobQueue;
}

export interface WebhookServerOptions extends WebhookReceiverOptions {
  port?: number;
  hostname?: string;
}

export function createWebhookReceiver(options: WebhookReceiverOptions): Hono {
  const app = new Hono();

  app.get('/health', (c) => c.json({ ok: true }));
  app.post('/webhook/github', async (c) => {
    const rawBody = await c.req.text();
    const signature = c.req.header('x-hub-signature-256');
    if (!validateGitHubSignature(rawBody, signature, options.secret)) {
      return c.json({ error: 'invalid signature' }, 401);
    }

    const eventName = c.req.header('x-github-event');
    const deliveryId = c.req.header('x-github-delivery');
    const payload = JSON.parse(rawBody);
    const jobInput = parseGitHubWebhookEvent(eventName, payload, deliveryId);
    if (!jobInput) {
      return c.json({ ok: true, ignored: true });
    }

    const job = await options.queue.enqueue(jobInput);
    return c.json({ ok: true, jobId: job.id }, 202);
  });

  return app;
}

export async function startWebhookReceiver(options: WebhookServerOptions): Promise<http.Server> {
  const app = createWebhookReceiver(options);
  const port = options.port || 8787;
  const hostname = options.hostname || '0.0.0.0';

  const server = http.createServer(async (req, res) => {
    try {
      const body = await readRequestBody(req);
      const request = new Request(`http://${req.headers.host || `${hostname}:${port}`}${req.url || '/'}`, {
        method: req.method,
        headers: req.headers as HeadersInit,
        body: body.length > 0 ? body.toString('utf-8') : undefined,
      });
      const response = await app.fetch(request);
      res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error: any) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: error?.message || 'internal server error' }));
    }
  });

  await new Promise<void>((resolve) => {
    server.listen(port, hostname, resolve);
  });
  return server;
}

export function validateGitHubSignature(
  rawBody: string,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith('sha256=') || secret.length === 0) {
    return false;
  }

  const expected = `sha256=${crypto.createHmac('sha256', secret).update(rawBody).digest('hex')}`;
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signatureHeader);
  return expectedBuffer.length === actualBuffer.length && crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

export function parseGitHubWebhookEvent(
  eventName: string | undefined,
  payload: any,
  deliveryId?: string,
): Parameters<MonitorJobQueue['enqueue']>[0] | undefined {
  if (eventName === 'push') {
    const branch = parseBranchFromRef(payload.ref);
    const repoUrl = payload.repository?.clone_url || payload.repository?.html_url;
    const commitSha = payload.after;
    if (!branch || !repoUrl || !commitSha || commitSha === '0000000000000000000000000000000000000000') {
      return undefined;
    }

    return {
      repoUrl,
      branch,
      commitSha,
      installationId: payload.installation?.id,
      triggeredBy: {
        type: 'github_push',
        actor: payload.sender?.login,
        deliveryId,
      },
    };
  }

  if (eventName === 'pull_request') {
    const action = payload.action;
    if (!['opened', 'synchronize', 'reopened', 'ready_for_review'].includes(action)) {
      return undefined;
    }

    const pullRequest = payload.pull_request;
    const repoUrl = pullRequest?.head?.repo?.clone_url || payload.repository?.clone_url || payload.repository?.html_url;
    const branch = pullRequest?.head?.ref;
    const commitSha = pullRequest?.head?.sha;
    if (!repoUrl || !branch || !commitSha) {
      return undefined;
    }

    return {
      repoUrl,
      branch,
      commitSha,
      pullRequestNumber: pullRequest?.number,
      installationId: payload.installation?.id,
      triggeredBy: {
        type: 'github_pull_request',
        actor: payload.sender?.login,
        deliveryId,
        pullRequestNumber: pullRequest?.number,
      },
    };
  }

  return undefined;
}

function parseBranchFromRef(ref: string | undefined): string | undefined {
  const prefix = 'refs/heads/';
  if (!ref?.startsWith(prefix)) {
    return undefined;
  }
  return ref.slice(prefix.length);
}

async function readRequestBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
