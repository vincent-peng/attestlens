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
import { calculateMappingConfidence } from './confidence.js';

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
  /**
   * 'and' = all defined pattern fields must match (default for new rules).
   * 'or' = any defined pattern field can match (legacy behavior).
   */
  matchMode?: 'and' | 'or';
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
    appPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.78,
    rationale: 'Data exfiltration risks indicate personal information may be disclosed to unauthorised external parties, violating APP 6.1.',
    oaicReference: 'APP Guidelines Chapter 6.3',
  },
  {
    id: 'MAP-034',
    name: 'Dependency Without Source Provenance → APP 6',
    sourcePatterns: {
      ruleId: /^VS-SC-009$/,
      category: /^Security$/i,
    },
    appPrinciple: 'APP_6',
    status: 'unknown',
    confidence: 0.60,
    rationale: 'A direct production dependency without source repository or homepage metadata may make downstream disclosure and incident-impact assessment harder. Manual review is required to determine whether the dependency processes or discloses personal information.',
    oaicReference: 'APP Guidelines Chapter 6.1',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
    appPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'Analytics and tracking SDKs may transmit personal information to overseas servers. Requires questionnaire to determine if data flows cross borders and whether APP 8.1 obligations are met.',
    oaicReference: 'APP Guidelines Chapter 8.1',
  },
  {
    id: 'MAP-035',
    name: 'OSV Network Disclosure Vulnerability → APP 8',
    sourcePatterns: {
      ruleId: /^VS-OSV-/,
      category: /^Security$/i,
      title: /(ssrf|server.?side request forgery|exfiltrat|external request|open redirect)/i,
      severity: ['critical', 'high', 'medium'],
    },
    appPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.58,
    rationale: 'The vulnerable dependency class may enable external requests or data exfiltration. Manual review is required to determine whether personal information could be disclosed to overseas recipients under APP 8.',
    oaicReference: 'APP Guidelines Chapter 8.3',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
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
    matchMode: 'or',
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Known vulnerabilities in dependencies represent a failure to take reasonable steps to protect personal information. Under APP 11.1, entities must keep dependencies up to date and address known security issues.',
    oaicReference: 'APP Guidelines Chapter 11.4',
  },
  {
    id: 'MAP-032',
    name: 'OSV Vulnerability in Dependency → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-OSV-/,
      category: /^Security$/i,
      severity: ['critical', 'high', 'medium', 'low'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.90,
    rationale: 'OSV.dev reports a known vulnerability in a project dependency. Keeping dependencies patched is part of taking reasonable steps to protect personal information under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.4',
  },
  {
    id: 'MAP-033',
    name: 'Dependency Without Source Provenance → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-009$/,
      category: /^Security$/i,
      severity: ['medium', 'high', 'critical'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Direct production dependencies without source repository or homepage metadata weaken package provenance review and incident response, increasing supply-chain risk under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-025',
    name: 'Missing Lockfile → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-005$/,
      category: /^Security$/i,
      severity: ['critical'],
    },
    matchMode: 'or',
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Missing or invalid lockfiles make dependency resolution non-deterministic, increasing supply chain risk. Under APP 11.1, entities must ensure reproducible builds to maintain the security of personal information.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  {
    id: 'MAP-037',
    name: 'Behavioral Dependency Signal → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-BH-\d+$/,
      category: /^Behavioral Supply Chain$/i,
      severity: ['critical', 'high', 'medium', 'low'],
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Runtime-capable dependency behavior can affect whether reasonable steps are being taken to protect personal information under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-038',
    name: 'Network-Capable Dependency → APP 8',
    sourcePatterns: {
      ruleId: /^VS-BH-002$/,
      category: /^Behavioral Supply Chain$/i,
    },
    appPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.70,
    rationale: 'A dependency with outbound network capability may create cross-border disclosure pathways. APP 8 impact depends on runtime configuration and actual data destinations.',
    oaicReference: 'APP Guidelines Chapter 8',
  },
  {
    id: 'MAP-039',
    name: 'Secret-Adjacent Dependency Behavior → NDB',
    sourcePatterns: {
      ruleId: /^VS-BH-00[46]$/,
      category: /^Behavioral Supply Chain$/i,
    },
    appPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.68,
    rationale: 'Dependency access to environment secrets or high-entropy embedded strings may create a breach pathway. NDB impact depends on whether credentials or personal information are exposed.',
    oaicReference: 'NDB Guidelines s26WE',
  },
  {
    id: 'MAP-040',
    name: 'Git History Secret → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-GL-/,
      category: /(credential|secret|key|token)/i,
      severity: ['critical', 'high', 'medium'],
    },
    matchMode: 'or',
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Secrets committed to git history can remain exposed after deletion from the current tree. Reasonable security steps under APP 11.1 include detecting and rotating exposed credentials.',
    oaicReference: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-041',
    name: 'Git History Secret → NDB',
    sourcePatterns: {
      ruleId: /^VS-GL-/,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.82,
    rationale: 'A credential exposed in git history may create a data-breach pathway. NDB impact depends on whether the credential was valid, accessed, and connected to personal information.',
    oaicReference: 'NDB Guidelines s26WE',
  },
  {
    id: 'MAP-036',
    name: 'OSV Breach-Relevant Vulnerability → NDB',
    sourcePatterns: {
      ruleId: /^VS-OSV-/,
      title: /(remote code execution|rce|authentication bypass|information disclosure|sensitive data|exfiltrat|sql injection|cross.?site scripting|xss)/i,
      severity: ['critical', 'high'],
    },
    appPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.70,
    rationale: 'The dependency vulnerability class may create a realistic data-breach pathway. NDB impact depends on exploitability, exposed systems, and whether personal information is affected.',
    oaicReference: 'NDB Guidelines s26WE',
  },

  // ── URL Scan Findings ──────────────────────────────────────────────────────

  // Missing security headers
  {
    id: 'MAP-026',
    name: 'Missing Security Headers → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-URL-\d+$/,
      category: /^Security Headers$/i,
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) constitute a failure to take reasonable steps to protect personal information in transit and prevent common web attacks under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6; OAIC Guide to Securing Personal Information',
  },
  // Exposed API keys
  {
    id: 'MAP-027',
    name: 'Exposed API Keys → APP 11.1 + APP 6.1',
    sourcePatterns: {
      ruleId: /^AL-KEY-\d+$/,
      category: /^Exposed Keys$/i,
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'Exposed API keys in client-side code constitute a serious failure to protect personal information (APP 11.1) and may lead to unauthorised use or disclosure of data (APP 6.1). This is one of the most common causes of data breaches in vibe-coded applications.',
    oaicReference: 'APP Guidelines Chapter 11.6; Notifiable Data Breaches s26WE',
  },
  // Infrastructure misconfigurations
  {
    id: 'MAP-028',
    name: 'Infrastructure Misconfiguration → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-INFRA-\d+$/,
      category: /^Infrastructure$/i,
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.93,
    rationale: 'Exposed infrastructure files (.git, .env, debug endpoints) provide attackers with source code, secrets, and internal application structure, constituting a failure to take reasonable steps under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // JS vulnerability patterns
  {
    id: 'MAP-029',
    name: 'JS Vulnerability Patterns → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-JS-\d+$/,
      category: /^JS Security$/i,
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Client-side JavaScript vulnerabilities (XSS via innerHTML, eval usage, etc.) can lead to unauthorised access to personal information, constituting a failure to take reasonable steps under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6',
  },
  // CORS wildcard
  {
    id: 'MAP-030',
    name: 'Wildcard CORS → APP 11.1 + APP 6.1',
    sourcePatterns: {
      ruleId: /^AL-URL-013$/,
      category: /^CORS$/i,
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Wildcard CORS allows any origin to access API responses, potentially exposing personal information to malicious websites. This violates both APP 11.1 (reasonable steps) and APP 6.1 (use/disclosure).',
    oaicReference: 'APP Guidelines Chapter 11.6; APP Guidelines Chapter 6',
  },
  // Cookie security flags
  {
    id: 'MAP-031',
    name: 'Insecure Cookie Flags → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-URL-\d+$/,
      category: /^Cookie Security$/i,
    },
    appPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.87,
    rationale: 'Cookies without Secure and HttpOnly flags can be intercepted or accessed via JavaScript, potentially exposing session tokens and personal information. This constitutes a failure to take reasonable steps under APP 11.1.',
    oaicReference: 'APP Guidelines Chapter 11.6; OAIC Guide to Securing Personal Information',
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
        confidence: calculateMappingConfidence(rule.confidence, finding),
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
  const { sourcePatterns, matchMode } = rule;
  const definedFields = [sourcePatterns.ruleId, sourcePatterns.category, sourcePatterns.title, sourcePatterns.description].filter(Boolean).length;

  // If no source patterns defined, no match
  if (definedFields === 0) return false;

  // Check severity filter first (applies regardless of match mode)
  const severityOk = !sourcePatterns.severity || sourcePatterns.severity.includes(finding.severity);

  // Evaluate each defined pattern field
  const ruleIds = getRuleIdsForMatching(finding);
  const title = getTitleForMatching(finding);
  const description = getDescriptionForMatching(finding);
  const ruleIdMatch = !sourcePatterns.ruleId || ruleIds.some((ruleId) => patternMatches(sourcePatterns.ruleId!, ruleId));
  const categoryMatch = !sourcePatterns.category || patternMatches(sourcePatterns.category, finding.category);
  const titleMatch = !sourcePatterns.title || patternMatches(sourcePatterns.title, title);
  const descriptionMatch = !sourcePatterns.description || patternMatches(sourcePatterns.description, description);

  // 'or' mode (legacy): any defined field matches
  // 'and' mode (default for new rules): all defined fields must match
  if (matchMode === 'or') {
    // OR: if ANY defined field matches, the rule matches
    const anyMatch = !!(
      (sourcePatterns.ruleId && ruleIdMatch) ||
      (sourcePatterns.category && categoryMatch) ||
      (sourcePatterns.title && titleMatch) ||
      (sourcePatterns.description && descriptionMatch)
    );
    return anyMatch && severityOk;
  }

  // AND (default): all defined fields must match
  return ruleIdMatch && categoryMatch && titleMatch && descriptionMatch && severityOk;
}

function getRawOutputObject(finding: AttestLensFinding): Record<string, unknown> {
  return typeof finding.evidence.rawOutput === 'object' && finding.evidence.rawOutput !== null
    ? finding.evidence.rawOutput as Record<string, unknown>
    : {};
}

function getRuleIdsForMatching(finding: AttestLensFinding): string[] {
  const rawOutput = getRawOutputObject(finding);
  const ruleIds = [finding.sourceRule];
  if (typeof rawOutput.osvSourceRule === 'string' && rawOutput.osvSourceRule.length > 0) {
    ruleIds.push(rawOutput.osvSourceRule);
  }
  return ruleIds;
}

function getTitleForMatching(finding: AttestLensFinding): string {
  const rawOutput = getRawOutputObject(finding);
  return [
    finding.title,
    typeof rawOutput.osvFindingTitle === 'string' ? rawOutput.osvFindingTitle : undefined,
  ].filter(Boolean).join(' ');
}

function getDescriptionForMatching(finding: AttestLensFinding): string {
  const rawOutput = getRawOutputObject(finding);
  return [
    finding.description,
    typeof rawOutput.osvFindingDescription === 'string' ? rawOutput.osvFindingDescription : undefined,
  ].filter(Boolean).join(' ');
}

function patternMatches(pattern: RegExp, value: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(value);
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
