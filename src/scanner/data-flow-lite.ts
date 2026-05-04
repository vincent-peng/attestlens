/**
 * AttestLens - Data Flow Lite Scanner
 *
 * Conservative, deterministic source-to-sink checks for obvious personal-data
 * flows. This is not full taint tracking.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import type { AttestLensFinding, ScanSource, Severity } from '../schema/index.js';
import { ATTESTLENS_VERSION } from '../version.js';
import type { ScannerAdapter, ScannerContext, ScannerError, ScannerResult } from './types.js';

export interface DataFlowLiteAdapterOptions {
  enabled?: boolean;
  maxFileBytes?: number;
}

type DataFlowRuleId =
  | 'DATAFLOW-PII-LOG'
  | 'DATAFLOW-PII-ANALYTICS'
  | 'DATAFLOW-PII-EXTERNAL'
  | 'DATAFLOW-PII-LLM';

type SinkKind = 'log' | 'analytics' | 'external' | 'llm';
type FlowConfidence = 'high' | 'medium';

interface DataFlowRule {
  id: DataFlowRuleId;
  sink: SinkKind;
  severity: Severity;
  title: string;
  destination: string;
}

interface FlowSource {
  field: string;
  symbol?: string;
  member?: string;
  line: number;
  scopeId: number;
  kind: 'schema' | 'type' | 'request_body';
}

interface BodyVariable {
  name: string;
  line: number;
  scopeId: number;
}

interface FlowIssue {
  rule: DataFlowRule;
  relativeFile: string;
  line: number;
  snippet: string;
  fields: string[];
  confidence: FlowConfidence;
  confidenceReason: string;
  sourceLines: number[];
}

const DEFAULT_MAX_FILE_BYTES = 750_000;
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
const SKIPPED_DIR_SEGMENTS = new Set([
  '.git',
  '.next',
  '.turbo',
  'node_modules',
  'dist',
  'build',
  'coverage',
  'docs',
  'doc',
  'example',
  'examples',
  'test',
  'tests',
  '__tests__',
  'fixture',
  'fixtures',
]);

const PII_FIELD_ALIASES: Record<string, string[]> = {
  email: ['email', 'emailAddress', 'userEmail'],
  phone: ['phone', 'phoneNumber', 'mobile'],
  name: ['name', 'firstName', 'lastName', 'fullName'],
  address: ['address', 'streetAddress', 'postalAddress'],
  dateOfBirth: ['dateOfBirth', 'dob', 'birthDate'],
  health: ['health', 'healthData', 'healthCondition', 'medical', 'diagnosis'],
  ssn: ['ssn', 'socialSecurityNumber'],
  nric: ['nric'],
  medicare: ['medicare', 'medicareNumber'],
  payment: ['payment', 'paymentMethod', 'billing'],
  card: ['card', 'cardNumber', 'creditCard'],
};

const PII_IDENTIFIERS = Object.values(PII_FIELD_ALIASES).flat();
const PII_IDENTIFIER_PATTERN = new RegExp(`\\b(?:${PII_IDENTIFIERS.map(escapeRegExp).join('|')})\\b`, 'i');

const DATA_FLOW_RULES: DataFlowRule[] = [
  {
    id: 'DATAFLOW-PII-LOG',
    sink: 'log',
    severity: 'medium',
    title: 'Personal data flows into application logs',
    destination: 'console logging',
  },
  {
    id: 'DATAFLOW-PII-ANALYTICS',
    sink: 'analytics',
    severity: 'medium',
    title: 'Personal data flows into analytics instrumentation',
    destination: 'analytics instrumentation',
  },
  {
    id: 'DATAFLOW-PII-EXTERNAL',
    sink: 'external',
    severity: 'medium',
    title: 'Personal data flows into an external request',
    destination: 'external HTTP request',
  },
  {
    id: 'DATAFLOW-PII-LLM',
    sink: 'llm',
    severity: 'high',
    title: 'Personal data flows into an LLM prompt or message',
    destination: 'LLM prompt or message',
  },
];

export class DataFlowLiteAdapter implements ScannerAdapter {
  readonly name: ScanSource = 'data-flow-lite';
  readonly version = ATTESTLENS_VERSION;
  private readonly maxFileBytes: number;

  constructor(options: DataFlowLiteAdapterOptions = {}) {
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async getVersion(): Promise<string> {
    return this.version;
  }

  async scan(targetPath: string, context?: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(targetPath);
    const errors: ScannerError[] = [];
    const findings: AttestLensFinding[] = [];

    let pathStat;
    try {
      pathStat = await fs.stat(resolvedPath);
    } catch {
      return this.result(findings, [{ source: this.name, message: `Invalid path: ${targetPath}`, code: 'INVALID_PATH', recoverable: false }], startTime);
    }
    if (!pathStat.isDirectory()) {
      return this.result(findings, [{ source: this.name, message: `Path is not a directory: ${targetPath}`, code: 'NOT_DIRECTORY', recoverable: false }], startTime);
    }

    const files = await collectSourceFiles(resolvedPath, context);
    for (const file of files) {
      throwIfAborted(context);
      const stat = await fs.stat(file).catch(() => null);
      if (!stat || stat.size > this.maxFileBytes) continue;

      const content = await fs.readFile(file, 'utf-8').catch(() => '');
      if (!content) continue;

      const relativeFile = normalizePath(path.relative(resolvedPath, file));
      const issues = detectDataFlows(content, relativeFile);
      findings.push(...issues.map(issue => this.makeFinding(issue)));
    }

    return this.result(findings, errors, startTime);
  }

  private result(findings: AttestLensFinding[], errors: ScannerError[], startTime: number): ScannerResult {
    return {
      source: this.name,
      version: this.version,
      timestamp: new Date().toISOString(),
      findings,
      errors,
      durationMs: Date.now() - startTime,
    };
  }

  private makeFinding(issue: FlowIssue): AttestLensFinding {
    const fields = issue.fields.sort();
    return {
      id: this.generateId(issue.rule.id, issue.relativeFile, issue.line, fields, issue.rule.sink),
      source: this.name,
      sourceRule: issue.rule.id,
      severity: issue.rule.severity,
      category: 'Data Flow Lite',
      title: issue.rule.title,
      description: [
        `Clearway detected a same-file personal-data flow from ${formatFieldList(fields)} to ${issue.rule.destination}.`,
        'This is a deterministic source-to-sink heuristic and does not claim full taint tracking.',
      ].join(' '),
      file: issue.relativeFile,
      line: issue.line,
      code: redactSnippet(issue.snippet),
      fix: `Avoid sending raw ${formatFieldList(fields)} to ${issue.rule.destination}. Minimise, redact, or hash the value and document the destination before shipping.`,
      regulationMappings: [],
      appMappings: [],
      evidence: {
        timestamp: new Date().toISOString(),
        scannerVersion: this.version,
        rawOutput: {
          ruleId: issue.rule.id,
          sink: issue.rule.sink,
          fields,
          confidence: issue.confidence,
          confidenceReason: issue.confidenceReason,
          file: issue.relativeFile,
          line: issue.line,
          sourceLines: issue.sourceLines.sort((a, b) => a - b),
        },
        scannerCommand: 'attestlens data-flow-lite',
      },
    };
  }

  private generateId(ruleId: string, relativeFile: string, line: number, fields: string[], sink: SinkKind): string {
    return crypto
      .createHash('sha256')
      .update(`${this.name}:${ruleId}:${relativeFile}:${line}:${sink}:${fields.sort().join(',')}`)
      .digest('hex')
      .substring(0, 12);
  }
}

function detectDataFlows(content: string, relativeFile: string): FlowIssue[] {
  const originalLines = content.split(/\r?\n/);
  const executable = stripCommentsPreserveLines(content);
  const lines = executable.split(/\r?\n/);
  const lineScopes = computeLineScopes(lines);
  const sources = collectSources(lines, lineScopes);
  if (sources.length === 0) return [];

  const issues: FlowIssue[] = [];
  const emitted = new Set<string>();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (!lineContainsSink(line)) continue;

    const statement = collectStatement(lines, index);
    const rule = DATA_FLOW_RULES.find(candidate => matchesSink(candidate.sink, statement));
    if (!rule) continue;

    const match = matchSourceReference(statement, index + 1, lineScopes[index] ?? 0, sources);
    if (!match) continue;

    const key = `${rule.id}:${relativeFile}:${index + 1}:${match.fields.sort().join(',')}`;
    if (emitted.has(key)) continue;
    emitted.add(key);

    issues.push({
      rule,
      relativeFile,
      line: index + 1,
      snippet: collectStatement(originalLines, index),
      fields: match.fields,
      confidence: match.confidence,
      confidenceReason: match.confidenceReason,
      sourceLines: match.sourceLines,
    });
  }
  return issues;
}

function collectSources(lines: string[], lineScopes: number[]): FlowSource[] {
  const sources: FlowSource[] = [];
  const bodyVariables: BodyVariable[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    const lineNumber = index + 1;
    const scopeId = lineScopes[index] ?? 0;

    for (const field of extractSchemaOrTypeFields(line)) {
      sources.push({ field, line: lineNumber, scopeId, kind: line.includes('z.') ? 'schema' : 'type' });
    }

    const bodyVariable = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+?)?\s*=\s*(?:await\s+)?(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.json\s*\(\s*\)|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.body)/);
    if (bodyVariable?.[1]) {
      bodyVariables.push({ name: bodyVariable[1], line: lineNumber, scopeId });
    }

    const destructured = line.match(/\b(?:const|let|var)\s*\{([^}]+)\}\s*(?:\s*:\s*[^=]+?)?=\s*(?:await\s+)?(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.json\s*\(\s*\)|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.body|[A-Za-z_$][\w$]*)/);
    if (destructured?.[1]) {
      for (const field of extractDestructuredFields(destructured[1])) {
        sources.push({ field, symbol: field, line: lineNumber, scopeId, kind: 'request_body' });
      }
    }

    for (const bodyVar of bodyVariables) {
      if (bodyVar.scopeId !== scopeId) continue;

      const assignmentPattern = new RegExp(`\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)(?:\\s*:\\s*[^=]+?)?\\s*=\\s*${escapeRegExp(bodyVar.name)}\\.(${PII_IDENTIFIERS.map(escapeRegExp).join('|')})\\b`, 'i');
      const assignment = line.match(assignmentPattern);
      if (assignment?.[1] && assignment[2]) {
        sources.push({
          field: normalizeFieldName(assignment[2]),
          symbol: assignment[1],
          member: `${bodyVar.name}.${assignment[2]}`,
          line: lineNumber,
          scopeId,
          kind: 'request_body',
        });
      }

      const directMemberPattern = new RegExp(`\\b${escapeRegExp(bodyVar.name)}\\.(${PII_IDENTIFIERS.map(escapeRegExp).join('|')})\\b`, 'ig');
      let memberMatch;
      while ((memberMatch = directMemberPattern.exec(line)) !== null) {
        const rawField = memberMatch[1]!;
        sources.push({
          field: normalizeFieldName(rawField),
          member: `${bodyVar.name}.${rawField}`,
          line: lineNumber,
          scopeId,
          kind: 'request_body',
        });
      }

      if (containsIdentifier(line, bodyVar.name)) {
        sources.push({
          field: '__request_body__',
          symbol: bodyVar.name,
          line: bodyVar.line,
          scopeId,
          kind: 'request_body',
        });
      }
    }

    const requestBodyMemberPattern = /\b(?:[A-Za-z_$][\w$]*\.)*(?:req|request)\.body\.([A-Za-z_$][\w$]*)\b/ig;
    let requestMember;
    while ((requestMember = requestBodyMemberPattern.exec(line)) !== null) {
      const field = requestMember[1]!;
      if (!isPiiIdentifier(field)) continue;
      sources.push({
        field: normalizeFieldName(field),
        member: requestMember[0],
        line: lineNumber,
        scopeId,
        kind: 'request_body',
      });
    }
  }

  return dedupeSources(sources);
}

function matchSourceReference(statement: string, lineNumber: number, scopeId: number, sources: FlowSource[]): {
  fields: string[];
  confidence: FlowConfidence;
  confidenceReason: string;
  sourceLines: number[];
} | null {
  const directMatches = sources.filter((source) => {
    if (source.scopeId !== scopeId || source.field === '__request_body__') return false;
    if (source.member && containsIdentifierPath(statement, source.member)) return true;
    if (source.symbol && containsIdentifier(statement, source.symbol)) return true;
    return false;
  });
  if (directMatches.length > 0) {
    return {
      fields: uniqueSorted(directMatches.map(source => source.field)),
      confidence: 'high',
      confidenceReason: 'Direct personal-data variable or field reference reaches the sink in the same file.',
      sourceLines: uniqueNumbers(directMatches.map(source => source.line)),
    };
  }

  const wholeBodyMatches = sources.filter((source) => (
    source.scopeId === scopeId
    && source.field === '__request_body__'
    && source.symbol
    && containsIdentifier(statement, source.symbol)
  ));
  if (wholeBodyMatches.length > 0) {
    const sameScopePiiFields = uniqueSorted(sources
      .filter(source => (
        source.field !== '__request_body__'
        && (source.scopeId === scopeId || source.kind === 'schema' || source.kind === 'type')
      ))
      .map(source => source.field));
    if (sameScopePiiFields.length > 0) {
      return {
        fields: sameScopePiiFields,
        confidence: 'medium',
        confidenceReason: 'Whole request body reaches the sink in a scope with personal-data fields.',
        sourceLines: uniqueNumbers([...wholeBodyMatches.map(source => source.line), lineNumber]),
      };
    }
  }

  const statementFields = extractStatementPiiProperties(statement);
  const indirectMatches = sources.filter(source => (
    source.field !== '__request_body__'
    && (containsIdentifier(statement, source.field) || statementFields.has(source.field))
  ));
  if (indirectMatches.length > 0) {
    return {
      fields: uniqueSorted(indirectMatches.map(source => source.field)),
      confidence: 'medium',
      confidenceReason: 'Personal-data field name appears in a same-file sink payload after a schema or type source declaration.',
      sourceLines: uniqueNumbers(indirectMatches.map(source => source.line)),
    };
  }

  return null;
}

function computeLineScopes(lines: string[]): number[] {
  const scopes: number[] = [];
  const stack: Array<{ id: number; parentDepth: number }> = [];
  let depth = 0;

  for (let index = 0; index < lines.length; index += 1) {
    scopes[index] = stack[stack.length - 1]?.id ?? 0;
    const line = lines[index]!;
    const openCount = countChar(line, '{');
    const closeCount = countChar(line, '}');

    if (openCount > 0 && isFunctionLikeScopeStart(line)) {
      stack.push({ id: index + 1, parentDepth: depth });
    }

    depth += openCount - closeCount;
    while (stack.length > 0 && depth <= stack[stack.length - 1]!.parentDepth) {
      stack.pop();
    }
  }

  return scopes;
}

function isFunctionLikeScopeStart(line: string): boolean {
  return /\bfunction\b/.test(line)
    || /=>\s*\{/.test(line)
    || /\b(?:GET|POST|PUT|PATCH|DELETE)\s*\([^)]*\)\s*\{/.test(line);
}

function extractStatementPiiProperties(statement: string): Set<string> {
  const fields = new Set<string>();
  const propertyPattern = new RegExp(`(?:^|[,{;\\s])(${PII_IDENTIFIERS.map(escapeRegExp).join('|')})\\??\\s*:`, 'ig');
  let match;
  while ((match = propertyPattern.exec(statement)) !== null) {
    if (match[1]) {
      fields.add(normalizeFieldName(match[1]));
    }
  }
  return fields;
}

function extractSchemaOrTypeFields(line: string): string[] {
  const fields: string[] = [];
  const propertyPattern = new RegExp(`\\b(${PII_IDENTIFIERS.map(escapeRegExp).join('|')})\\??\\s*:\\s*(?:z\\.|string\\b|number\\b|boolean\\b|Date\\b|unknown\\b|any\\b|Array\\b|Record\\b)`, 'ig');
  let match;
  while ((match = propertyPattern.exec(line)) !== null) {
    if (match[1]) fields.push(normalizeFieldName(match[1]));
  }
  return fields;
}

function extractDestructuredFields(value: string): string[] {
  return value
    .split(',')
    .map(part => part.trim().split(/[:=]/)[0]?.trim())
    .filter((field): field is string => Boolean(field && isPiiIdentifier(field)))
    .map(normalizeFieldName);
}

function matchesSink(sink: SinkKind, statement: string): boolean {
  switch (sink) {
    case 'log':
      return /\bconsole\.(?:log|debug|info)\s*\(/.test(statement);
    case 'analytics':
      return /\b(?:posthog|segment|mixpanel|amplitude)\.(?:capture|track|identify|logEvent|people\.set)\s*\(/i.test(statement)
        || /\b(?:gtag|ga)\s*\(/i.test(statement);
    case 'external':
      return /\baxios(?:\.[a-z]+)?\s*\(/i.test(statement)
        || /\bfetch\s*\(\s*['"`]https?:\/\//i.test(statement);
    case 'llm':
      return /\b(?:openai|anthropic)\b/i.test(statement)
        || /\b(?:prompt|messages)\s*:/.test(statement) && /\b(?:chat\.completions|messages\.create|responses\.create)\b/i.test(statement);
  }
}

function lineContainsSink(line: string): boolean {
  return /\bconsole\.(?:log|debug|info)\s*\(/.test(line)
    || /\b(?:posthog|segment|mixpanel|amplitude)\./i.test(line)
    || /\b(?:gtag|ga)\s*\(/i.test(line)
    || /\b(?:fetch|axios)\b/i.test(line)
    || /\b(?:openai|anthropic|chat\.completions|messages\.create|responses\.create)\b/i.test(line);
}

function collectStatement(lines: string[], startIndex: number): string {
  const parts: string[] = [];
  let parenBalance = 0;
  let braceBalance = 0;
  for (let index = startIndex; index < Math.min(lines.length, startIndex + 8); index += 1) {
    const line = lines[index]!;
    parts.push(line.trim());
    parenBalance += countChar(line, '(') - countChar(line, ')');
    braceBalance += countChar(line, '{') - countChar(line, '}');
    if (parts.length > 1 && parenBalance <= 0 && braceBalance <= 0) break;
    if (line.includes(';') && parenBalance <= 0) break;
  }
  return parts.join(' ').trim();
}

async function collectSourceFiles(rootDir: string, context?: ScannerContext): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    throwIfAborted(context);
    const entries = await fs.readdir(currentDir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIR_SEGMENTS.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }
      if (!entry.isFile()) continue;
      if (entry.name.endsWith('.d.ts') || entry.name.includes('.min.')) continue;
      if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
  }

  await walk(rootDir);
  return files.sort();
}

function stripCommentsPreserveLines(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, block => block.replace(/[^\n]/g, ' '))
    .split(/\r?\n/)
    .map(line => line.replace(/(^|[^:])\/\/.*$/, '$1'))
    .join('\n');
}

function redactSnippet(snippet: string): string {
  let redacted = snippet;
  redacted = redacted.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]');
  redacted = redacted.replace(/\b(?:\d[ -]?){13,19}\b/g, '[REDACTED_NUMBER]');
  redacted = redacted.replace(
    new RegExp(`\\b(${PII_IDENTIFIERS.map(escapeRegExp).join('|')})\\b\\s*:\\s*(['"\`])[^'"\`]{1,160}\\2`, 'ig'),
    '$1: "[REDACTED]"',
  );
  redacted = redactStringLiterals(redacted);
  return redacted.length > 220 ? `${redacted.slice(0, 217)}...` : redacted;
}

function redactStringLiterals(value: string): string {
  return value
    .replace(/`(?:\\.|[^`\\])*`/g, '`[REDACTED]`')
    .replace(/'[^'\\]*(?:\\.[^'\\]*)*'/g, '"[REDACTED]"')
    .replace(/"[^"\\]*(?:\\.[^"\\]*)*"/g, '"[REDACTED]"');
}

function dedupeSources(sources: FlowSource[]): FlowSource[] {
  const seen = new Set<string>();
  const deduped: FlowSource[] = [];
  for (const source of sources) {
    const key = `${source.field}:${source.symbol || ''}:${source.member || ''}:${source.line}:${source.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(source);
  }
  return deduped;
}

function normalizeFieldName(field: string): string {
  const lower = field.toLowerCase();
  for (const [canonical, aliases] of Object.entries(PII_FIELD_ALIASES)) {
    if (aliases.some(alias => alias.toLowerCase() === lower)) {
      return canonical;
    }
  }
  return field;
}

function isPiiIdentifier(identifier: string): boolean {
  return PII_IDENTIFIER_PATTERN.test(identifier);
}

function containsIdentifier(value: string, identifier: string): boolean {
  return new RegExp(`\\b${escapeRegExp(identifier)}\\b`, 'i').test(value);
}

function containsIdentifierPath(value: string, member: string): boolean {
  return new RegExp(`\\b${member.split('.').map(escapeRegExp).join('\\s*\\.\\s*')}\\b`, 'i').test(value);
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values)).sort();
}

function uniqueNumbers(values: number[]): number[] {
  return Array.from(new Set(values)).sort((a, b) => a - b);
}

function formatFieldList(fields: string[]): string {
  return fields.join(', ');
}

function countChar(value: string, character: string): number {
  return value.split(character).length - 1;
}

function normalizePath(value: string): string {
  return value.split(path.sep).join('/');
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function throwIfAborted(context?: ScannerContext): void {
  if (context?.signal?.aborted) {
    throw new Error('Data Flow Lite scan aborted');
  }
}

export default DataFlowLiteAdapter;
