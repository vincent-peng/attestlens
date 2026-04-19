import { describe, it, expect } from 'vitest';
import { ScannerOrchestrator } from './orchestrator.js';

describe('ScannerOrchestrator', () => {
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
    const orchestrator = new ScannerOrchestrator();
    const result = await orchestrator.scan('/tmp/vulnerable-app');
    // Should have findings from static scan
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.totalDurationMs).toBeGreaterThan(0);
  });

  it('should deduplicate findings by rule+file+line', async () => {
    const orchestrator = new ScannerOrchestrator();
    const result = await orchestrator.scan('/tmp/vulnerable-app');
    // Check no duplicate rule+file+line combinations
    const keys = result.findings.map(f => `${f.sourceRule}:${f.file}:${f.line}`);
    const uniqueKeys = new Set(keys);
    expect(keys.length).toBe(uniqueKeys.size);
  });
});