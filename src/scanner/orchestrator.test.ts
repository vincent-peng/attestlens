import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScannerOrchestrator } from './orchestrator.js';

describe('ScannerOrchestrator', { timeout: 20000 }, () => {
  let scanResult: Awaited<ReturnType<ScannerOrchestrator['scan']>>;
  let fixtureDir: string;

  beforeAll(async () => {
    fixtureDir = await createVulnerableAppFixture();
    const orchestrator = new ScannerOrchestrator();
    scanResult = await orchestrator.scan(fixtureDir);
  });

  afterAll(async () => {
    if (fixtureDir) {
      await fs.rm(fixtureDir, { recursive: true, force: true });
    }
  });

  it('should register guardvibe and mcp-scan adapters by default', () => {
    const orchestrator = new ScannerOrchestrator();
    const registry = orchestrator.getRegistry();
    expect(registry.length).toBe(4);
    expect(registry.some(r => r.adapter.name === 'guardvibe')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'mcp-scan')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'supply-chain')).toBe(true);
    expect(registry.some(r => r.adapter.name === 'url-scan')).toBe(true);
  });

  it('should allow disabling adapters', () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.disable('mcp-scan');
    const registry = orchestrator.getRegistry();
    const mcpScan = registry.find(r => r.adapter.name === 'mcp-scan');
    expect(mcpScan!.enabled).toBe(false);
  });

  it('should allow re-enabling adapters', () => {
    const orchestrator = new ScannerOrchestrator();
    orchestrator.disable('mcp-scan');
    orchestrator.enable('mcp-scan');
    const registry = orchestrator.getRegistry();
    const mcpScan = registry.find(r => r.adapter.name === 'mcp-scan');
    expect(mcpScan!.enabled).toBe(true);
  });

  it('should return findings from scan', async () => {
    // Should have findings from static scan
    expect(scanResult.findings.length).toBeGreaterThan(0);
    expect(scanResult.totalDurationMs).toBeGreaterThan(0);
  });

  it('should deduplicate findings by rule+file+line', async () => {
    // Check no duplicate rule+file+line combinations
    const keys = scanResult.findings.map(f => `${f.sourceRule}:${f.file}:${f.line}`);
    const uniqueKeys = new Set(keys);
    expect(keys.length).toBe(uniqueKeys.size);
  });
});

async function createVulnerableAppFixture(): Promise<string> {
  const fixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-vulnerable-app-'));
  await fs.mkdir(path.join(fixtureDir, 'src'), { recursive: true });

  await fs.writeFile(
    path.join(fixtureDir, '.env'),
    [
      'api_key="1234567890abcdef1234567890abcdef"',
      'NEXT_PUBLIC_SECRET=public-secret-value',
    ].join('\n'),
  );

  await fs.writeFile(
    path.join(fixtureDir, 'src', 'App.tsx'),
    [
      'export function App({ html, token }: { html: string; token: string }) {',
      '  console.log("token", token);',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n'),
  );

  return fixtureDir;
}
