/**
 * AttestLens — Scanner Orchestrator
 * 
 * Coordinates all scanner adapters, merges findings, and deduplicates results.
 */

import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type { ScannerResult, ScannerAdapter, ScannerError, ScannerRegistryEntry, OrchestratedScanResult } from './types.js';
import { GuardVibeAdapter } from './guardvibe.js';
import { McpScanAdapter } from './mcp-scan.js';
import { SupplyChainAdapter } from './supply-chain.js';
import { UrlScanAdapter } from './url-scan.js';
import { loadRulePack, type RulePackLoadOptions } from './rules/index.js';

export interface ScannerOrchestratorOptions {
  rulePack?: RulePackLoadOptions;
}

export class ScannerOrchestrator {
  private registry: Map<ScanSource, ScannerRegistryEntry> = new Map();
  private rulePackOptions: RulePackLoadOptions;

  constructor(options: ScannerOrchestratorOptions = {}) {
    this.rulePackOptions = options.rulePack || {};
    // Register default scanners
    this.register(new GuardVibeAdapter());
    this.register(new McpScanAdapter());
    this.register(new SupplyChainAdapter());
    // URL scanner registered but only activated when URL input detected
    this.register(new UrlScanAdapter());
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

  async scan(targetPath: string, sources?: ScanSource[]): Promise<OrchestratedScanResult> {
    const startTime = Date.now();
    const allFindings: AttestLensFinding[] = [];
    const results: ScannerResult[] = [];
    const allErrors: ScannerError[] = [];
    const rulePack = await loadRulePack(this.rulePackOptions);

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
        const result = await entry.adapter.scan(targetPath, { rulePack: rulePack.manifest });
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
      ruleFreshness: rulePack.freshness,
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
