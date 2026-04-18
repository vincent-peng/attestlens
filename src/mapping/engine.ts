/**
 * AttestLens — APP/NDB Compliance Mapping Engine
 * 
 * Maps technical security findings to Australian Privacy Act (APP)
 * and Notifiable Data Breach (NDB) obligations.
 * 
 * This is the MOAT. The legal expertise encoded here requires specialist
 * knowledge of Australian privacy law, OAIC guidelines, and case law.
 */

import { z } from 'zod';
import {
  APPPrinciple,
  APPInfo,
  Severity,
  ControlStatus,
  type AttestLensFinding,
  type APPMapping,
  type APPControl,
} from '../schema/index.js';

// ─── Mapping Rules ──────────────────────────────────────────────────────────

/**
 * A mapping rule defines how a scanner finding category maps to APP obligations.
 * Each rule has:
 * - sourcePatterns: regex patterns to match scanner rule IDs and categories
 * - appPrinciple: which APP principle this maps to
 * - status: whether this finding causes PASS, FAIL, or UNKNOWN
 * - confidence: how confident we are in this mapping (0-1)
 * - rationale: why this finding maps to this APP
 */
export interface MappingRule {
  id: string;
  name: string;
  sourcePatterns: {
    ruleId?: RegExp;
    category?: RegExp;
    title?: RegExp;
    description?: RegExp;
    severity?: Severity[];
  };
  appPrinciple: APPPrinciple;
  status: ControlStatus;
  confidence: number;
  rationale: string;
  oaicReference?: string;  // OAIC guideline reference
}

// ─── APP 11: Security of Personal Info ──────────────────────────────────────
// APP 11.1: "An APP entity must take reasonable steps to protect personal 
// information it holds from misuse, interference and loss, and from 
// unauthorised access, modification or disclosure."

const APP_11_RULES: MappingRule[] = [
  // Hardcoded secrets/credentials
  {
    id: 'MAP-001',
    name: 'Hardcoded Credentials → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-001|^VS-HARDKEY|^MC-EXP-SEC$/,
      category: /^(Secrets?|Credentials?)$/i,
      title: /hardcoded.*(key|secret|token|password|credential|api.?key)/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'Hardcoded credentials in source code constitute a failure to take reasonable steps to protect personal information. OAIC considers this a serious breach of APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // SQL Injection
  {
    id: 'MAP-002',
    name: 'SQL Injection → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-002|^VS-SQLI$/,
      category: /^Security$/i,
      title: /sql.?injection/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'SQL injection vulnerabilities allow unauthorised access to personal information stored in databases, constituting a failure to take reasonable steps under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6; Notifiable Data Breaches s26WE',
  },
  // Missing Row Level Security (Supabase)
  {
    id: 'MAP-003',
    name: 'Missing RLS → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SUPA-RLS|^VS-RLS$/,
      category: /^Database$/i,
      title: /missing.*(row.?level|rls)|rls.*(disabled|not.?enabled)/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Missing Row Level Security on database tables containing personal information allows any authenticated user to access all records, violating APP 11.1 reasonable steps requirement.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // XSS / dangerouslySetInnerHTML
  {
    id: 'MAP-004',
    name: 'XSS Vulnerability → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-006|^VS-XSS$/,
      category: /^Security$/i,
      title: /cross.?site.?scripting|xss|dangerously.?set.?inner.?html/i,
      severity: ['high', 'medium'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Cross-site scripting vulnerabilities can lead to unauthorised access to or disclosure of personal information, constituting a breach of APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // Debug mode in production
  {
    id: 'MAP-005',
    name: 'Debug Mode Enabled → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-004|^VS-DEBUG$/,
      category: /^Security$/i,
      title: /debug.?mode|debug.?enabled/i,
      severity: ['medium', 'low'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Debug mode in production can expose sensitive information including personal data through error messages and stack traces, violating APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.4',
  },
  // .env not in .gitignore
  {
    id: 'MAP-006',
    name: 'Environment Files Exposed → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-011|^VS-ENV$/,
      category: /^Secrets?$/i,
      title: /\.env.*(not.*gitignore|exposed|committed)/i,
      severity: ['high', 'critical'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Exposing .env files containing secrets and configuration in version control constitutes a failure to protect personal information under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // Command injection / shell=True
  {
    id: 'MAP-007',
    name: 'Command Injection → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-009|^VG-SEC-003$/,
      category: /^Security$/i,
      title: /command.?injection|shell.*=.*true|os\.system|subprocess.*shell/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.93,
    rationale: 'Command injection vulnerabilities allow attackers to execute arbitrary commands on the server, directly compromising personal information.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // CORS wildcard
  {
    id: 'MAP-008',
    name: 'CORS Wildcard → APP 11.1',
    sourcePatterns: {
      ruleId: /^VG-SEC-005|^VS-CORS$/,
      category: /^Security$/i,
      title: /cors.*wildcard|access.?control.*allow.?origin.*\*/i,
      severity: ['medium', 'high'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.80,
    rationale: 'Wildcard CORS headers can allow unauthorised cross-origin access to APIs containing personal information, undermining reasonable steps to protect data under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.4',
  },
  // Auth coverage gaps
  {
    id: 'MAP-009',
    name: 'Auth Coverage Gaps → APP 11.1',
    sourcePatterns: {
      category: /^Auth$/i,
      title: /missing.*(auth|middleware|guard)|unauthorized.*route|unprotected.*endpoint/i,
      severity: ['high', 'critical'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Missing authentication on endpoints that access personal information constitutes a failure to take reasonable steps to protect data under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
];

// ─── APP 6: Use or Disclosure ───────────────────────────────────────────────
// APP 6.1: "If an APP entity holds personal information about an individual 
// that was collected for a particular purpose, the entity must not use or 
// disclose the information for another purpose."

const APP_6_RULES: MappingRule[] = [
  // CORS wildcard also maps to APP 6 (unauthorised disclosure)
  {
    id: 'MAP-010',
    name: 'CORS Wildcard → APP 6',
    sourcePatterns: {
      ruleId: /^VG-SEC-005|^VS-CORS$/,
      category: /^Security$/i,
      title: /cors.*wildcard|access.?control.*allow.*origin.*\*/i,
      severity: ['medium', 'high'],
    },
    appPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.75,
    rationale: 'Wildcard CORS can lead to unauthorised disclosure of personal information to third-party origins, violating APP 6.1 purpose limitation.',
    oaicReference: 'APP Guidelines Chapter 6.1',
  },
  // Missing auth on admin routes (unauthorised use)
  {
    id: 'MAP-011',
    name: 'Unauthorised Access to Admin Routes → APP 6',
    sourcePatterns: {
      category: /^Auth$/i,
      title: /missing.*(auth|admin|guard)|unauthorized.*admin/i,
      severity: ['high', 'critical'],
    },
    appPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Missing authorisation on admin routes allows unauthorised use and disclosure of personal information, violating APP 6.',
    oaicReference: 'APP Guidelines Chapter 6.1',
  },
  // Data exfiltration / external API calls
  {
    id: 'MAP-012',
    name: 'Data Exfiltration Risk → APP 6',
    sourcePatterns: {
      ruleId: /^MC-DATA-EXFIL$/,
      category: /^Data Flow$/i,
      title: /data.*(exfiltration|leak|sent.*external)|external.*endpoint/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.78,
    rationale: 'Data exfiltration risks indicate personal information may be disclosed to unauthorised external parties, violating APP 6.1.',
    oaicReference: 'APP Guidelines Chapter 6.3',
  },
];

// ─── APP 1: Open & Transparent Management ────────────────────────────────────
// APP 1.2: "An APP entity must take reasonable steps to make its privacy 
// policy available."

const APP_1_RULES: MappingRule[] = [
  // Missing privacy policy (detected by code analysis)
  {
    id: 'MAP-013',
    name: 'Missing Privacy Policy → APP 1',
    sourcePatterns: {
      category: /^Config$/i,
      title: /missing.*(privacy.?policy|privacy.?notice|privacy.?page)/i,
      severity: ['medium'],
    },
    appPrinciple: 'APP_1',
    status: 'fail',
    confidence: 0.70,
    rationale: 'Absence of a privacy policy page or notice in the application violates APP 1.2 requirement to make privacy policy available.',
    oaicReference: 'APP Guidelines Chapter 1.3',
  },
  // Architecture/documentation score
  {
    id: 'MAP-014',
    name: 'Architecture Quality → APP 1',
    sourcePatterns: {
      category: /^(Architecture|Code Quality)$/i,
      title: /architecture.*(score|quality|issue)/i,
      severity: ['low', 'info'],
    },
    appPrinciple: 'APP_1',
    status: 'pass',
    confidence: 0.50,
    rationale: 'Good architecture practices support open and transparent management of personal information under APP 1.',
    oaicReference: 'APP Guidelines Chapter 1.2',
  },
];

// ─── APP 8: Cross-Border Disclosure ─────────────────────────────────────────
// APP 8.1: "Before an APP entity discloses personal information about an 
// individual to an overseas recipient, the entity must take reasonable steps 
// to ensure the overseas recipient does not breach the APPs."

const APP_8_RULES: MappingRule[] = [
  // External API endpoints (potential cross-border data flows)
  {
    id: 'MAP-015',
    name: 'External API Endpoints → APP 8',
    sourcePatterns: {
      ruleId: /^MC-DATA-EXFIL$/,
      category: /^(Data Flow|Network)$/i,
      title: /external.*(api|endpoint|service)|third.?party.*(api|sdk)/i,
      severity: ['medium', 'high'],
    },
    appPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.60,
    rationale: 'External API endpoints may involve cross-border disclosure of personal information. Requires manual assessment to determine if overseas recipients are involved and whether reasonable steps have been taken under APP 8.1.',
    oaicReference: 'APP Guidelines Chapter 8.3',
  },
  // Analytics/tracking SDKs (potential cross-border)
  {
    id: 'MAP-016',
    name: 'Analytics SDK Data Flows → APP 8',
    sourcePatterns: {
      category: /^(Services|Network)$/i,
      title: /analytics.*(sdk|tracking)|posthog|google.?analytics|mixpanel|segment/i,
      severity: ['medium', 'low'],
    },
    appPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'Analytics and tracking SDKs may transmit personal information to overseas servers. Requires questionnaire to determine if data flows cross borders and whether APP 8.1 obligations are met.',
    oaicReference: 'APP Guidelines Chapter 8.1',
  },
];

// ─── APP 12: Access to Personal Info ────────────────────────────────────────
// APP 12.1: "If an APP entity holds personal information about an individual, 
// the entity must, on request by the individual, give the individual access 
// to the information."

const APP_12_RULES: MappingRule[] = [
  // Auth coverage (good auth = access control = supports APP 12)
  {
    id: 'MAP-017',
    name: 'Authentication Coverage → APP 12',
    sourcePatterns: {
      category: /^Auth$/i,
      title: /auth.*coverage.*(100|complete)|fully.*protected/i,
      severity: ['info'],
    },
    appPrinciple: 'APP_12',
    status: 'pass',
    confidence: 0.65,
    rationale: 'Comprehensive authentication coverage supports the individual access right under APP 12, ensuring individuals can securely access their personal information.',
    oaicReference: 'APP Guidelines Chapter 12.3',
  },
];

// ─── NDB: Notifiable Data Breaches ──────────────────────────────────────────
// s26WE: "An entity must prepare and maintain a data breach response plan."

const NDB_RULES: MappingRule[] = [
  // Missing logging/monitoring (breach detection)
  {
    id: 'MAP-018',
    name: 'Missing Audit Logging → NDB',
    sourcePatterns: {
      category: /^(Architecture|Security)$/i,
      title: /missing.*(audit.?log|monitoring|logging)|no.*(log|monitor)/i,
      severity: ['medium', 'high'],
    },
    appPrinciple: 'NDB',
    status: 'fail',
    confidence: 0.72,
    rationale: 'Missing audit logging undermines the ability to detect and assess eligible data breaches, which is required under NDB s26WE.',
    oaicReference: 'NDB Guidelines s26WE',
  },
  // Data exfiltration paths (breach risk)
  {
    id: 'MAP-019',
    name: 'Data Exfiltration Risk → NDB',
    sourcePatterns: {
      ruleId: /^MC-DATA-EXFIL$/,
      title: /data.*(exfiltration|leak|breach)|exposure.*personal/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'NDB',
    status: 'fail',
    confidence: 0.80,
    rationale: 'Data exfiltration vulnerabilities create an immediate risk of eligible data breaches requiring notification under NDB scheme.',
    oaicReference: 'NDB Guidelines s26WE',
  },
  // ─── Supply Chain Rules ──────────────────────────────────────────────
  {
    id: 'MAP-020',
    name: 'Install Script in Dependency → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-001$/,
      category: /^Security$/i,
      severity: ['critical', 'high', 'medium'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Dependencies with install scripts (postinstall, preinstall) can execute arbitrary code during npm install, posing a significant supply chain risk. Under APP 11.1, entities must take reasonable steps to protect personal information, which includes vetting dependencies for supply chain attack vectors.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-021',
    name: 'Manifest-Only Dependency Injection → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-002$/,
      category: /^Security$/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Unused production dependencies may indicate manifest-only dependency injection — the exact technique used in the Axios supply chain attack (March 2026). Under APP 11.1, this represents a failure to take reasonable steps to secure the software supply chain.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-022',
    name: 'Typosquat Package → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-004$/,
      category: /^Security$/i,
      severity: ['critical'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'Typosquatting packages mimic popular packages to trick developers into installing malicious code. This is a direct supply chain attack vector violating APP 11.1 reasonable steps to protect personal information.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-023',
    name: 'Install Script + No Source Repo → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-008$/,
      category: /^Security$/i,
      severity: ['critical'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.97,
    rationale: 'A dependency with install scripts and no source repository is a strong indicator of a supply chain attack. The Axios compromise (March 2026) used exactly this pattern — a package with postinstall scripts and no public source repository. This violates APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-024',
    name: 'Known Vulnerability in Dependency → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-006$/,
      category: /^Security$/i,
      severity: ['critical', 'high', 'medium'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Known vulnerabilities in dependencies represent a failure to take reasonable steps to protect personal information. Under APP 11.1, entities must keep dependencies up to date and address known security issues.',
    oaicReference: 'APP Guidelines Chapter 11.4',
  },
  {
    id: 'MAP-025',
    name: 'Missing Lockfile → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-005$/,
      category: /^Security$/i,
      severity: ['critical'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Missing or invalid lockfiles make dependency resolution non-deterministic, increasing supply chain risk. Under APP 11.1, entities must ensure reproducible builds to maintain the security of personal information.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
];

// ─── All Rules ───────────────────────────────────────────────────────────────

export const ALL_MAPPING_RULES: MappingRule[] = [
  ...APP_11_RULES,
  ...APP_6_RULES,
  ...APP_1_RULES,
  ...APP_8_RULES,
  ...APP_12_RULES,
  ...NDB_RULES,
];

// ─── Mapping Engine ──────────────────────────────────────────────────────────

export interface MappingResult {
  mappings: APPMapping[];
  unmappedFindings: AttestLensFinding[];
}

/**
 * Map a single finding to APP obligations using the mapping rules.
 */
export function mapFindingToAPP(finding: AttestLensFinding): APPMapping[] {
  const mappings: APPMapping[] = [];

  for (const rule of ALL_MAPPING_RULES) {
    const matches = matchRule(finding, rule);
    if (matches) {
      mappings.push({
        principle: rule.appPrinciple,
        obligation: APPInfo[rule.appPrinciple].obligation,
        status: rule.status,
        confidence: rule.confidence,
        rationale: rule.rationale,
      });
    }
  }

  // If no rules match, flag as unknown for APP 11 (default security bucket)
  if (mappings.length === 0 && (finding.severity === 'critical' || finding.severity === 'high')) {
    mappings.push({
      principle: 'APP_11',
      obligation: APPInfo.APP_11.obligation,
      status: 'unknown',
      confidence: 0.40,
      rationale: 'High/critical severity finding without explicit APP mapping. Requires manual assessment to determine which APP obligation is affected.',
    });
  }

  return mappings;
}

/**
 * Check if a finding matches a mapping rule.
 */
function matchRule(finding: AttestLensFinding, rule: MappingRule): boolean {
  const { sourcePatterns } = rule;
  
  // Check rule ID
  if (sourcePatterns.ruleId && sourcePatterns.ruleId.test(finding.sourceRule)) {
    if (!sourcePatterns.severity || sourcePatterns.severity.includes(finding.severity)) {
      return true;
    }
  }

  // Check category
  if (sourcePatterns.category && sourcePatterns.category.test(finding.category)) {
    if (!sourcePatterns.severity || sourcePatterns.severity.includes(finding.severity)) {
      return true;
    }
  }

  // Check title
  if (sourcePatterns.title && sourcePatterns.title.test(finding.title)) {
    if (!sourcePatterns.severity || sourcePatterns.severity.includes(finding.severity)) {
      return true;
    }
  }

  // Check description
  if (sourcePatterns.description && sourcePatterns.description.test(finding.description)) {
    if (!sourcePatterns.severity || sourcePatterns.severity.includes(finding.severity)) {
      return true;
    }
  }

  return false;
}

/**
 * Map all findings and produce APP control assessments.
 */
export function mapAllFindings(findings: AttestLensFinding[], strictMode = false): {
  controls: APPControl[];
  unmapped: AttestLensFinding[];
} {
  const controlMap = new Map<APPPrinciple, APPControl>();
  const unmapped: AttestLensFinding[] = [];

  // Initialize all APP controls as UNKNOWN
  for (const principle of Object.keys(APPInfo) as APPPrinciple[]) {
    controlMap.set(principle, {
      principle,
      shortName: APPInfo[principle].shortName,
      obligation: APPInfo[principle].obligation,
      status: 'unknown',
      score: 100,
      findingCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      questionnaireRequired: true, // Default: questionnaire required
      lastAssessed: new Date().toISOString(),
    });
  }

  for (const finding of findings) {
    const mappings = mapFindingToAPP(finding);
    
    if (mappings.length === 0) {
      unmapped.push(finding);
      continue;
    }

    // Update finding's appMappings
    finding.appMappings = mappings;

    for (const mapping of mappings) {
      const control = controlMap.get(mapping.principle);
      if (!control) continue;

      control.findings.push(finding.id);
      control.findingCount[finding.severity]++;
      
      // Update status based on mapping
      if (mapping.status === 'fail') {
        control.status = 'fail';
      } else if (mapping.status === 'pass' && control.status !== 'fail') {
        control.status = 'pass';
        control.questionnaireRequired = false;
      }

      // Deduct score
      const deduction = {
        critical: 15,
        high: 10,
        medium: 5,
        low: 2,
        info: 1,
      }[finding.severity] || 0;
      
      control.score = Math.max(0, control.score - deduction);
    }
  }

  // Apply strict mode: UNKNOWN controls become FAIL
  if (strictMode) {
    for (const [principle, control] of controlMap) {
      if (control.status === 'unknown') {
        control.status = 'fail';
        control.score = 0;
        control.questionnaireRequired = false; // No point asking if it's already failed
      }
    }
  }

  // Final pass: set questionnaire requirements
  for (const [principle, control] of controlMap) {
    if (control.findings.length === 0 && control.status === 'unknown') {
      control.questionnaireRequired = true;
    } else if (control.status === 'fail') {
      control.questionnaireRequired = false;
    } else if (control.findings.length > 0) {
      control.questionnaireRequired = false;
    }
  }

  return {
    controls: Array.from(controlMap.values()),
    unmapped,
  };
}

export default { ALL_MAPPING_RULES, mapFindingToAPP, mapAllFindings };