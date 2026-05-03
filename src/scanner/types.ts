/**
 * AttestLens — Scanner Adapter Types
 * 
 * Unified interface for all scanner integrations.
 * Each scanner adapter normalizes its output into AttestLensFinding format.
 */

import type {
  AnyJurisdictionPackManifest,
  AttestLensFinding,
  Jurisdiction,
  Severity,
  ScanSource,
  RuleFreshness,
  RulePackManifest,
} from '../schema/index.js';

// ─── Scanner Result ──────────────────────────────────────────────────────────

export interface ScannerResult {
  source: ScanSource;
  version: string;
  timestamp: string;
  findings: AttestLensFinding[];
  errors: ScannerError[];
  durationMs: number;
}

export interface ScannerError {
  source: ScanSource;
  message: string;
  code?: string;
  recoverable: boolean;
}

export interface OrchestratedScanResult {
  findings: AttestLensFinding[];
  results: ScannerResult[];
  errors: ScannerError[];
  totalDurationMs: number;
  ruleFreshness: RuleFreshness;
  jurisdictionManifests?: Partial<Record<Jurisdiction, AnyJurisdictionPackManifest>>;
}

export type ScannerProgressPhase = 'start' | 'complete' | 'skip' | 'warning' | 'timeout';

export interface ScannerProgressEvent {
  source: ScanSource;
  phase: ScannerProgressPhase;
  message: string;
  elapsedMs?: number;
}

export interface ScannerContext {
  rulePack: RulePackManifest;
  allowCustomRules?: boolean;
  signal?: AbortSignal;
  onProgress?: (event: ScannerProgressEvent) => void;
}

// ─── Scanner Adapter Interface ───────────────────────────────────────────────

export interface ScannerAdapter {
  readonly name: ScanSource;
  readonly version: string;
  
  /** Check if the scanner is available and properly configured */
  isAvailable(): Promise<boolean>;
  
  /** Run the scanner and return normalized findings */
  scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult>;
  
  /** Get the raw scanner version string */
  getVersion(): Promise<string>;
}

// ─── GuardVibe Types ─────────────────────────────────────────────────────────

export interface GuardVibeFinding {
  rule: string;           // e.g., "VG-SEC-001"
  severity: string;        // "critical" | "high" | "medium" | "low" | "info"
  category: string;        // e.g., "Security", "Auth"
  title: string;
  description: string;
  file?: string;
  line?: number;
  code?: string;
  fix?: string;
  tool?: string;           // GuardVibe tool name that generated this
}

export interface GuardVibeAuditResult {
  findings: GuardVibeFinding[];
  tool?: string;
  timestamp: string;
  version?: string;
}

// ─── mcp-scan Types ─────────────────────────────────────────────────────────

export interface McpScanResult {
  scanner: string;
  version: string;
  findings: {
    id: string;
    severity: string;
    category: string;
    title: string;
    description: string;
    file?: string;
    line?: number;
    remediation?: string;
  }[];
  config_path?: string;
  timestamp: string;
}

// ─── Scanner Registry ───────────────────────────────────────────────────────

export interface ScannerRegistryEntry {
  adapter: ScannerAdapter;
  enabled: boolean;
  lastRun?: string;
  lastResult?: ScannerResult;
}
