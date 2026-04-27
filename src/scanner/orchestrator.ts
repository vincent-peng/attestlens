/**
 * AttestLens — Scanner Orchestrator
 * 
 * Coordinates all scanner adapters, merges findings, and deduplicates results.
 */

import type { AttestLensFinding, ScanSource } from '../schema/index.js';
import type {
  ScannerResult,
  ScannerAdapter,
  ScannerError,
  ScannerRegistryEntry,
  OrchestratedScanResult,
  ScannerProgressEvent,
} from './types.js';
import { GuardVibeAdapter } from './guardvibe.js';
import { McpScanAdapter } from './mcp-scan.js';
import { SupplyChainAdapter, type SupplyChainAdapterOptions } from './supply-chain.js';
import { UrlScanAdapter } from './url-scan.js';
import { loadRulePack, type RulePackLoadOptions } from './rules/index.js';

export interface ScannerOrchestratorOptions {
  rulePack?: RulePackLoadOptions;
  supplyChain?: SupplyChainAdapterOptions;
  adapterTimeoutMs?: number | Partial<Record<ScanSource, number>>;
  onProgress?: (event: ScannerProgressEvent) => void;
}

export class ScannerOrchestrator {
  private registry: Map<ScanSource, ScannerRegistryEntry> = new Map();
  private rulePackOptions: RulePackLoadOptions;
  private adapterTimeoutMs?: number | Partial<Record<ScanSource, number>>;
  private onProgress?: (event: ScannerProgressEvent) => void;

  constructor(options: ScannerOrchestratorOptions = {}) {
    this.rulePackOptions = options.rulePack || {};
    this.adapterTimeoutMs = options.adapterTimeoutMs;
    this.onProgress = options.onProgress;
    // Register default scanners
    this.register(new GuardVibeAdapter());
    this.register(new McpScanAdapter());
    this.register(new SupplyChainAdapter(options.supplyChain));
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
      const source = entry.adapter.name;
      const adapterStartTime = Date.now();
      this.emitProgress({
        source,
        phase: 'start',
        message: `Starting ${source}`,
      });

      const available = await entry.adapter.isAvailable();
      if (!available) {
        const error = {
          source,
          message: `${entry.adapter.name} is not available. Skipping.`,
          code: 'SCANNER_UNAVAILABLE',
          recoverable: true,
        };
        allErrors.push(error);
        this.emitProgress({
          source,
          phase: 'skip',
          message: error.message,
          elapsedMs: Date.now() - adapterStartTime,
        });
        return null;
      }

      const timeoutMs = this.getAdapterTimeoutMs(source);
      const controller = new AbortController();
      let timeout: ReturnType<typeof setTimeout> | undefined;

      try {
        const timeoutPromise = new Promise<never>((_, reject) => {
          timeout = setTimeout(() => {
            reject(new ScannerTimeoutError(source, timeoutMs));
            controller.abort();
          }, timeoutMs);
        });
        const result = await Promise.race([
          entry.adapter.scan(targetPath, {
            rulePack: rulePack.manifest,
            signal: controller.signal,
            onProgress: (event) => this.emitProgress(event),
          }),
          timeoutPromise,
        ]);
        if (timeout) clearTimeout(timeout);
        entry.lastRun = new Date().toISOString();
        entry.lastResult = result;
        this.emitProgress({
          source,
          phase: 'complete',
          message: `${source} complete`,
          elapsedMs: Date.now() - adapterStartTime,
        });
        for (const error of result.errors) {
          this.emitProgress({
            source,
            phase: 'warning',
            message: error.message,
            elapsedMs: Date.now() - adapterStartTime,
          });
        }
        return result;
      } catch (error: any) {
        if (timeout) clearTimeout(timeout);
        if (error instanceof ScannerTimeoutError) {
          const scannerError = {
            source,
            message: `${source} timed out after ${timeoutMs}ms`,
            code: 'SCANNER_TIMEOUT',
            recoverable: true,
          };
          allErrors.push(scannerError);
          this.emitProgress({
            source,
            phase: 'timeout',
            message: scannerError.message,
            elapsedMs: Date.now() - adapterStartTime,
          });
          return null;
        }

        const scannerError = {
          source,
          message: `Scanner error: ${error.message}`,
          code: 'SCANNER_ERROR',
          recoverable: true,
        };
        allErrors.push(scannerError);
        this.emitProgress({
          source,
          phase: 'warning',
          message: scannerError.message,
          elapsedMs: Date.now() - adapterStartTime,
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
      const key = this.getDeduplicationKey(finding);
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

  private getDeduplicationKey(finding: AttestLensFinding): string {
    const rawOutput = finding.evidence.rawOutput as Record<string, unknown> | undefined;
    const packageName = typeof rawOutput?.packageName === 'string' ? rawOutput.packageName : '';
    const vulnerabilityId = typeof rawOutput?.vulnerabilityId === 'string' ? rawOutput.vulnerabilityId : '';
    const advisoryId = typeof rawOutput?.advisoryId === 'string' ? rawOutput.advisoryId : '';
    const advisoryUrl = typeof rawOutput?.url === 'string' ? rawOutput.url : '';
    const packageIdentity = [packageName, vulnerabilityId, advisoryId, advisoryUrl]
      .filter(Boolean)
      .join(':');

    return [
      finding.sourceRule,
      finding.file || '',
      finding.line || '',
      packageIdentity,
    ].join(':');
  }

  getRegistry(): ScannerRegistryEntry[] {
    return Array.from(this.registry.values());
  }

  private getAdapterTimeoutMs(source: ScanSource): number {
    if (typeof this.adapterTimeoutMs === 'number') {
      return this.adapterTimeoutMs;
    }
    if (this.adapterTimeoutMs?.[source]) {
      return this.adapterTimeoutMs[source]!;
    }
    return DEFAULT_ADAPTER_TIMEOUT_MS[source] ?? 60_000;
  }

  private emitProgress(event: ScannerProgressEvent): void {
    this.onProgress?.(event);
  }
}

const DEFAULT_ADAPTER_TIMEOUT_MS: Record<ScanSource, number> = {
  guardvibe: 120_000,
  'mcp-scan': 60_000,
  'supply-chain': 60_000,
  'url-scan': 60_000,
  vibesafe: 60_000,
  'vibe-check': 60_000,
  manual: 60_000,
  questionnaire: 60_000,
};

class ScannerTimeoutError extends Error {
  constructor(
    readonly source: ScanSource,
    readonly timeoutMs: number,
  ) {
    super(`${source} timed out after ${timeoutMs}ms`);
    this.name = 'ScannerTimeoutError';
  }
}

export default ScannerOrchestrator;
