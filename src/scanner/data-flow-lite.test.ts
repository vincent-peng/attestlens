import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { DataFlowLiteAdapter } from './data-flow-lite.js';

const FIXTURE_ROOT = path.resolve('tests/fixtures/data-flow-lite');
const DEMO_ROOT = path.resolve('demo/agent-pr-privacy-risk');

describe('DataFlowLiteAdapter', () => {
  it('detects email logged in the same route', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-log'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-LOG');
    expect(finding).toBeDefined();
    expect(finding?.source).toBe('data-flow-lite');
    expect(finding?.file).toBe('app/api/users/route.ts');
    expect(finding?.evidence.rawOutput).toMatchObject({
      fields: ['email'],
      confidence: 'high',
      sink: 'log',
    });
  });

  it('detects phone sent to analytics instrumentation', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-analytics'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-ANALYTICS');
    expect(finding).toBeDefined();
    expect(finding?.code).toContain('payload.phone');
    expect(finding?.evidence.rawOutput).toMatchObject({
      fields: ['phone'],
      confidence: 'high',
      sink: 'analytics',
    });
  });

  it('detects health data sent to an LLM prompt', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-llm'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-LLM');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.evidence.rawOutput).toMatchObject({
      fields: ['health'],
      confidence: 'high',
      sink: 'llm',
    });
  });

  it('detects email sent to an external request', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-external'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-EXTERNAL');
    expect(finding).toBeDefined();
    expect(finding?.evidence.rawOutput).toMatchObject({
      fields: ['email'],
      confidence: 'high',
      sink: 'external',
    });
  });

  it('detects Hono request body sources', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-hono'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-LOG');
    expect(finding).toBeDefined();
    expect(finding?.evidence.rawOutput).toMatchObject({
      fields: ['phone'],
      confidence: 'high',
    });
  });

  it('detects typed request body variables', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-typed'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-LOG');
    expect(finding).toBeDefined();
    expect(finding?.evidence.rawOutput).toMatchObject({
      fields: ['phone'],
      confidence: 'high',
    });
  });

  it('redacts sensitive free-text literals from snippets', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'pii-llm'));

    const finding = result.findings.find(candidate => candidate.sourceRule === 'DATAFLOW-PII-LLM');
    expect(finding?.code).toContain('[REDACTED]');
    expect(finding?.code).not.toContain('Summarize symptoms');
  });

  it('does not flag unrelated variable names', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'negative'));

    expect(result.findings).toEqual([]);
  });

  it('does not carry request body sources across handlers', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'negative'));

    expect(result.findings.some(finding => finding.file === 'multi-handler.ts')).toBe(false);
  });

  it('does not attribute unrelated PII-shaped sink properties to another field', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'negative'));

    expect(result.findings.some(finding => finding.file === 'unrelated-property.ts')).toBe(false);
  });

  it('does not flag documentation examples', async () => {
    const result = await new DataFlowLiteAdapter().scan(path.join(FIXTURE_ROOT, 'docs-example'));

    expect(result.findings).toEqual([]);
  });

  it('keeps the PII logging demo fixture failing and remediated fixture clean', async () => {
    const failResult = await new DataFlowLiteAdapter().scan(path.join(DEMO_ROOT, 'pii-log-fail'));
    const passResult = await new DataFlowLiteAdapter().scan(path.join(DEMO_ROOT, 'pii-log-pass'));

    expect(failResult.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceRule: 'DATAFLOW-PII-LOG',
        file: 'server.js',
      }),
    ]));
    expect(passResult.findings).toEqual([]);
  });
});
