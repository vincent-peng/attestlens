import { beforeAll, describe, expect, it } from 'vitest';
import { ScannerOrchestrator } from './orchestrator.js';

describe('ScannerOrchestrator', { timeout: 20000 }, () => {
  let scanResult: Awaited<ReturnType<ScannerOrchestrator['scan']>>;

  beforeAll(async () => {
    const orchestrator = new ScannerOrchestrator();
    scanResult = await orchestrator.scan('/tmp/vulnerable-app');
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
