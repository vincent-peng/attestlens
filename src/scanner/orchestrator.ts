/**
 * AttestLens — Scanner Orchestrator
 * 
 * Coordinates all scanner adapters, merges findings, and deduplicates results.
 */

import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type { ScannerResult, ScannerAdapter, ScannerError, ScannerRegistryEntry } from './types.js';
import { GuardVibeAdapter } from './guardvibe.js';
import { McpScanAdapter } from './mcp-scan.js';
import { SupplyChainAdapter } from './supply-chain.js';

export class ScannerOrchestrator {
  private registry: Map<ScanSource, ScannerRegistryEntry> = new Map();

  constructor() {
    // Register default scanners
    this.register(new GuardVibeAdapter());
    this.register(new McpScanAdapter());
    this.register(new SupplyChainAdapter());
  }

  register(adapter: ScannerAdapter, enabled = true): void {
    this.registry.set(adapter.name, { adapter, enabled });
  }

  enable(source: ScanSource): void {
    const entry = this.registry.get(source);
    if (entry) entry.enabled = true;
  }

  disable(source: ScanSource): void {
    const entry = this.registry.get(source);
    if (entry) entry.enabled = false;
  }

  async scan(targetPath: string, sources?: ScanSource[]): Promise<{
    findings: AttestLensFinding[];
    results: ScannerResult[];
    errors: ScannerError[];
    totalDurationMs: number;
  }> {
    const startTime = Date.now();
    const allFindings: AttestLensFinding[] = [];
    const results: ScannerResult[] = [];
    const allErrors: ScannerError[] = [];

    const enabledAdapters = Array.from(this.registry.values())
      .filter(entry => entry.enabled)
      .filter(entry => !sources || sources.includes(entry.adapter.name));

    // Run all enabled scanners in parallel
    const scanPromises = enabledAdapters.map(async (entry) => {
      const available = await entry.adapter.isAvailable();
      if (!available) {
        allErrors.push({
          source: entry.adapter.name,
          message: `${entry.adapter.name} is not available. Skipping.`,
          code: 'SCANNER_UNAVAILABLE',
          recoverable: true,
        });
        return null;
      }

      try {
        const result = await entry.adapter.scan(targetPath);
        entry.lastRun = new Date().toISOString();
        entry.lastResult = result;
        return result;
      } catch (error: any) {
        allErrors.push({
          source: entry.adapter.name,
          message: `Scanner error: ${error.message}`,
          code: 'SCANNER_ERROR',
          recoverable: true,
        });
        return null;
      }
    });

    const scanResults = await Promise.allSettled(scanPromises);

    for (const result of scanResults) {
      if (result.status === 'fulfilled' && result.value) {
        results.push(result.value);
        allFindings.push(...result.value.findings);
        allErrors.push(...result.value.errors);
      }
    }

    // Deduplicate findings
    const deduplicated = this.deduplicateFindings(allFindings);

    return {
      findings: deduplicated,
      results,
      errors: allErrors,
      totalDurationMs: Date.now() - startTime,
    };
  }

  /**
   * Deduplicate findings based on source, rule, file, and line.
   * Keeps the highest severity if duplicates exist.
   */
  private deduplicateFindings(findings: AttestLensFinding[]): AttestLensFinding[] {
    const seen = new Map<string, AttestLensFinding>();
    const severityOrder: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1,
    };

    for (const finding of findings) {
      const key = `${finding.sourceRule}:${finding.file || ''}:${finding.line || ''}`;
      const existing = seen.get(key);
      
      if (!existing) {
        seen.set(key, finding);
      } else {
        // Keep the one with higher severity
        if ((severityOrder[finding.severity] || 0) > (severityOrder[existing.severity] || 0)) {
          seen.set(key, finding);
        }
      }
    }

    return Array.from(seen.values());
  }

  getRegistry(): ScannerRegistryEntry[] {
    return Array.from(this.registry.values());
  }
}

export default ScannerOrchestrator;