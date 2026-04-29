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
import { BehavioralAdapter, type BehavioralAdapterOptions } from './behavioral.js';
import { GitleaksAdapter, type GitleaksAdapterOptions } from './gitleaks.js';
import { IacAdapter, type IacAdapterOptions } from './iac.js';
import { UrlScanAdapter } from './url-scan.js';
import { ReformAdapter } from './reform.js';
import { loadRulePack, type RulePackLoadOptions } from './rules/index.js';

export interface ScannerOrchestratorOptions {
  rulePack?: RulePackLoadOptions;
  supplyChain?: SupplyChainAdapterOptions;
  behavioral?: BehavioralAdapterOptions;
  gitleaks?: GitleaksAdapterOptions;
  iac?: IacAdapterOptions;
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
    this.register(new BehavioralAdapter(options.behavioral), options.behavioral?.enabled !== false);
    this.register(new GitleaksAdapter(options.gitleaks), options.gitleaks?.enabled === true);
    this.register(new IacAdapter(options.iac), options.iac?.enabled !== false);
    // URL scanner registered but only activated when URL input detected
    this.register(new UrlScanAdapter());
    this.register(new ReformAdapter());
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

    const targetKind = getTargetKind(targetPath);
    const enabledAdapters = Array.from(this.registry.values())
      .filter(entry => entry.enabled)
      .filter(entry => {
        if (sources) {
          return sources.includes(entry.adapter.name);
        }
        if (targetKind === 'url') {
          return entry.adapter.name === 'url-scan';
        }
        return entry.adapter.name !== 'url-scan';
      });

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
   * Deduplicate findings by canonical vulnerability, location, and package
   * identity. Keeps the strongest finding and annotates multi-source merges.
   */
  private deduplicateFindings(findings: AttestLensFinding[]): AttestLensFinding[] {
    const groups = new Map<string, AttestLensFinding[]>();

    for (const finding of findings) {
      const key = this.getDeduplicationKey(finding);
      const existing = groups.get(key) || [];
      existing.push(finding);
      groups.set(key, existing);
    }

    return Array.from(groups.values()).map((group) => this.mergeDuplicateFindings(group));
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
    const vulnType = this.getCanonicalVulnerabilityType(finding);

    if (packageIdentity) {
      return [
        vulnType,
        'package',
        packageIdentity,
      ].join(':');
    }

    return [
      vulnType,
      normalizeFindingFile(finding.file),
      finding.line || '',
      normalizeFindingUrl(finding.url || (typeof rawOutput?.url === 'string' ? rawOutput.url : undefined)),
      normalizeFindingCode(finding.code),
    ].join(':');
  }

  private mergeDuplicateFindings(group: AttestLensFinding[]): AttestLensFinding {
    if (group.length === 1) {
      return group[0]!;
    }

    const sorted = [...group].sort((a, b) => {
      const severityDelta = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
      if (severityDelta !== 0) return severityDelta;
      return SOURCE_PRIORITY[a.source] - SOURCE_PRIORITY[b.source];
    });
    const strongest = sorted[0]!;
    const corroboratingSources = uniqueSources(group.map(finding => finding.source))
      .filter(source => source !== strongest.source);

    if (corroboratingSources.length === 0) {
      return strongest;
    }

    const rawOutput = typeof strongest.evidence.rawOutput === 'object' && strongest.evidence.rawOutput !== null
      ? strongest.evidence.rawOutput as Record<string, unknown>
      : {};

    return {
      ...strongest,
      corroboratedBy: corroboratingSources,
      evidence: {
        ...strongest.evidence,
        rawOutput: {
          ...rawOutput,
          corroboratedBy: corroboratingSources,
          corroboratingFindings: group
            .filter(finding => finding !== strongest)
            .map(finding => ({
              id: finding.id,
              source: finding.source,
              sourceRule: finding.sourceRule,
              severity: finding.severity,
              file: finding.file,
              line: finding.line,
              title: finding.title,
            })),
        },
      },
    };
  }

  private getCanonicalVulnerabilityType(finding: AttestLensFinding): string {
    const exact = CANONICAL_RULE_TYPES[finding.sourceRule];
    if (exact) return exact;

    const rawOutput = finding.evidence.rawOutput as Record<string, unknown> | undefined;
    if (finding.sourceRule === 'VS-SC-006') {
      const advisoryId = getString(rawOutput?.vulnerabilityId) || getString(rawOutput?.advisoryId) || getString(rawOutput?.url);
      if (advisoryId) return `dependency-vulnerability:${advisoryId}`;
    }
    if (/^AL-KEY-\d+$/.test(finding.sourceRule) || /^VS-GL-/.test(finding.sourceRule)) {
      return 'secret-exposure';
    }
    if (/^VS-OSV-/.test(finding.sourceRule)) {
      const vulnerabilityId = getString(rawOutput?.vulnerabilityId) || finding.sourceRule;
      return `dependency-vulnerability:${vulnerabilityId}`;
    }
    if (/^VS-IAC-\d+$/.test(finding.sourceRule)) {
      return `iac:${finding.sourceRule}`;
    }

    const text = `${finding.title} ${finding.description}`.toLowerCase();
    if (text.includes('dangerouslysetinnerhtml') || text.includes('cross-site scripting') || /\bxss\b/.test(text)) {
      return 'xss';
    }
    if (text.includes('eval()') || text.includes('dynamic code execution')) {
      return 'eval-usage';
    }
    if (/hardcoded|secret|credential|api key|token/.test(text)) {
      return 'secret-exposure';
    }
    if (text.includes('sql injection')) {
      return 'sql-injection';
    }
    if (text.includes('cors') && text.includes('wildcard')) {
      return 'wildcard-cors';
    }

    return finding.sourceRule;
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
  behavioral: 60_000,
  gitleaks: 60_000,
  iac: 60_000,
  'url-scan': 60_000,
  vibesafe: 60_000,
  'vibe-check': 60_000,
  manual: 60_000,
  questionnaire: 60_000,
  'reform-2026': 60_000,
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const SOURCE_PRIORITY: Record<ScanSource, number> = {
  guardvibe: 1,
  'mcp-scan': 2,
  'supply-chain': 3,
  behavioral: 4,
  iac: 5,
  gitleaks: 6,
  'url-scan': 7,
  vibesafe: 8,
  'vibe-check': 9,
  manual: 10,
  questionnaire: 11,
  'reform-2026': 13,
};

const CANONICAL_RULE_TYPES: Record<string, string> = {
  'AL-JS-001': 'xss',
  'VS-XSS': 'xss',
  'AL-JS-002': 'eval-usage',
  'VS-BH-001': 'eval-usage',
  'VS-HARDKEY': 'secret-exposure',
  'VS-ENV': 'secret-exposure',
  'VS-PUBLIC-SECRET-ENV': 'secret-exposure',
  'VS-PLATFORM-SECRET': 'secret-exposure',
  'VS-FB-SERVICE-ACCOUNT': 'secret-exposure',
  'VS-SAST-001': 'secret-exposure',
  'VS-SAST-004': 'sql-injection',
  'VS-SQLI': 'sql-injection',
  'VS-SAST-005': 'path-traversal',
  'VS-SAST-006': 'ssrf',
  'VS-SAST-010': 'wildcard-cors',
  'VS-CORS': 'wildcard-cors',
  'AL-URL-013': 'wildcard-cors',
  'VS-SAST-012': 'client-side-secret-storage',
  'VS-SAST-015': 'missing-auth-sensitive-route',
  'VS-SAST-017': 'csrf-gap',
  'VS-SAST-018': 'open-redirect',
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

function normalizeFindingFile(file: string | undefined): string {
  return (file || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function normalizeFindingUrl(url: string | undefined): string {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return url;
  }
}

function normalizeFindingCode(code: string | undefined): string {
  return (code || '').replace(/\s+/g, ' ').trim().slice(0, 240);
}

function uniqueSources(sources: ScanSource[]): ScanSource[] {
  return Array.from(new Set(sources));
}

function getString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function getTargetKind(target: string): 'path' | 'url' {
  try {
    const parsed = new URL(target);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return 'url';
    }
  } catch {
    // Not a URL; treat as filesystem path.
  }
  return 'path';
}

export default ScannerOrchestrator;
