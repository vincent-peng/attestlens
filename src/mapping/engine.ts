/**
 * AttestLens — APP/NDB Compliance Mapping Engine
 * 
 * Maps technical security findings to Australian Privacy Act (APP)
 * and Notifiable Data Breach (NDB) obligations.
 * 
 * This is the MOAT. The legal expertise encoded here requires specialist
 * knowledge of Australian privacy law, OAIC guidelines, and case law.
 */

import {
  APPPrinciple,
  APPInfo,
  Severity,
  ControlStatus,
  JurisdictionInfo,
  type AttestLensFinding,
  type APPMapping,
  type APPControl,
  type Jurisdiction,
  type RegulationControl,
  type RegulationMapping,
  type RegulationPrinciple,
} from '../schema/index.js';
import { getRegistry } from '../jurisdiction/registry.js';
import { calculateMappingConfidence } from './confidence.js';

// ─── Mapping Rules ──────────────────────────────────────────────────────────

/**
 * A mapping rule defines how a scanner finding category maps to APP obligations.
 * Each rule has:
 * - sourcePatterns: regex patterns to match scanner rule IDs and categories
 * - regulationPrinciple: which regulation principle this maps to
 * - status: whether this finding causes PASS, FAIL, or UNKNOWN
 * - confidence: how confident we are in this mapping (0-1)
 * - rationale: why this finding maps to this regulation
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
  jurisdiction: Jurisdiction;
  regulationPrinciple: RegulationPrinciple;
  status: ControlStatus;
  confidence: number;
  rationale: string;
  citation?: string;
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'Hardcoded credentials in source code constitute a failure to take reasonable steps to protect personal information. OAIC considers this a serious breach of APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'SQL injection vulnerabilities allow unauthorised access to personal information stored in databases, constituting a failure to take reasonable steps under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6; Notifiable Data Breaches s26WE',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Missing Row Level Security on database tables containing personal information allows any authenticated user to access all records, violating APP 11.1 reasonable steps requirement.',
    citation: 'APP Guidelines Chapter 11.6',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Cross-site scripting vulnerabilities can lead to unauthorised access to or disclosure of personal information, constituting a breach of APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Debug mode in production can expose sensitive information including personal data through error messages and stack traces, violating APP 11.1.',
    citation: 'APP Guidelines Chapter 11.4',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Exposing .env files containing secrets and configuration in version control constitutes a failure to protect personal information under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.93,
    rationale: 'Command injection vulnerabilities allow attackers to execute arbitrary commands on the server, directly compromising personal information.',
    citation: 'APP Guidelines Chapter 11.6',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.80,
    rationale: 'Wildcard CORS headers can allow unauthorised cross-origin access to APIs containing personal information, undermining reasonable steps to protect data under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.4',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Missing authentication on endpoints that access personal information constitutes a failure to take reasonable steps to protect data under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.75,
    rationale: 'Wildcard CORS can lead to unauthorised disclosure of personal information to third-party origins, violating APP 6.1 purpose limitation.',
    citation: 'APP Guidelines Chapter 6.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Missing authorisation on admin routes allows unauthorised use and disclosure of personal information, violating APP 6.',
    citation: 'APP Guidelines Chapter 6.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_6',
    status: 'fail',
    confidence: 0.78,
    rationale: 'Data exfiltration risks indicate personal information may be disclosed to unauthorised external parties, violating APP 6.1.',
    citation: 'APP Guidelines Chapter 6.3',
  },
  {
    id: 'MAP-034',
    name: 'Dependency Without Source Provenance → APP 6',
    sourcePatterns: {
      ruleId: /^VS-SC-009$/,
      category: /^Security$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_6',
    status: 'unknown',
    confidence: 0.60,
    rationale: 'A direct production dependency without source repository or homepage metadata may make downstream disclosure and incident-impact assessment harder. Manual review is required to determine whether the dependency processes or discloses personal information.',
    citation: 'APP Guidelines Chapter 6.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_1',
    status: 'fail',
    confidence: 0.70,
    rationale: 'Absence of a privacy policy page or notice in the application violates APP 1.2 requirement to make privacy policy available.',
    citation: 'APP Guidelines Chapter 1.3',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_1',
    status: 'pass',
    confidence: 0.50,
    rationale: 'Good architecture practices support open and transparent management of personal information under APP 1.',
    citation: 'APP Guidelines Chapter 1.2',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.60,
    rationale: 'External API endpoints may involve cross-border disclosure of personal information. Requires manual assessment to determine if overseas recipients are involved and whether reasonable steps have been taken under APP 8.1.',
    citation: 'APP Guidelines Chapter 8.3',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'Analytics and tracking SDKs may transmit personal information to overseas servers. Requires questionnaire to determine if data flows cross borders and whether APP 8.1 obligations are met.',
    citation: 'APP Guidelines Chapter 8.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.58,
    rationale: 'The vulnerable dependency class may enable external requests or data exfiltration. Manual review is required to determine whether personal information could be disclosed to overseas recipients under APP 8.',
    citation: 'APP Guidelines Chapter 8.3',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_12',
    status: 'pass',
    confidence: 0.65,
    rationale: 'Comprehensive authentication coverage supports the individual access right under APP 12, ensuring individuals can securely access their personal information.',
    citation: 'APP Guidelines Chapter 12.3',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'fail',
    confidence: 0.72,
    rationale: 'Missing audit logging undermines the ability to detect and assess eligible data breaches, which is required under NDB s26WE.',
    citation: 'NDB Guidelines s26WE',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'fail',
    confidence: 0.80,
    rationale: 'Data exfiltration vulnerabilities create an immediate risk of eligible data breaches requiring notification under NDB scheme.',
    citation: 'NDB Guidelines s26WE',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Dependencies with install scripts (postinstall, preinstall) can execute arbitrary code during npm install, posing a significant supply chain risk. Under APP 11.1, entities must take reasonable steps to protect personal information, which includes vetting dependencies for supply chain attack vectors.',
    citation: 'APP Guidelines Chapter 11.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Unused production dependencies may indicate manifest-only dependency injection — the exact technique used in the Axios supply chain attack (March 2026). Under APP 11.1, this represents a failure to take reasonable steps to secure the software supply chain.',
    citation: 'APP Guidelines Chapter 11.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'Typosquatting packages mimic popular packages to trick developers into installing malicious code. This is a direct supply chain attack vector violating APP 11.1 reasonable steps to protect personal information.',
    citation: 'APP Guidelines Chapter 11.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.97,
    rationale: 'A dependency with install scripts and no source repository is a strong indicator of a supply chain attack. The Axios compromise (March 2026) used exactly this pattern — a package with postinstall scripts and no public source repository. This violates APP 11.1.',
    citation: 'APP Guidelines Chapter 11.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Known vulnerabilities in dependencies represent a failure to take reasonable steps to protect personal information. Under APP 11.1, entities must keep dependencies up to date and address known security issues.',
    citation: 'APP Guidelines Chapter 11.4',
  },
  {
    id: 'MAP-032',
    name: 'OSV Vulnerability in Dependency → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-OSV-/,
      category: /^Security$/i,
      severity: ['critical', 'high', 'medium', 'low'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.90,
    rationale: 'OSV.dev reports a known vulnerability in a project dependency. Keeping dependencies patched is part of taking reasonable steps to protect personal information under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.4',
  },
  {
    id: 'MAP-033',
    name: 'Dependency Without Source Provenance → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-009$/,
      category: /^Security$/i,
      severity: ['medium', 'high', 'critical'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Direct production dependencies without source repository or homepage metadata weaken package provenance review and incident response, increasing supply-chain risk under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-051',
    name: 'Low-Maturity Dependency → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SC-010$/,
      category: /^Supply Chain Maturity$/i,
      severity: ['medium', 'high', 'critical'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'unknown',
    confidence: 0.74,
    rationale: 'Low package maturity is a supply-chain risk indicator. Manual review is required to determine whether the dependency is appropriate for production systems handling personal information.',
    citation: 'APP Guidelines Chapter 11.1',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Missing or invalid lockfiles make dependency resolution non-deterministic, increasing supply chain risk. Under APP 11.1, entities must ensure reproducible builds to maintain the security of personal information.',
    citation: 'APP Guidelines Chapter 11.6',
  },
  {
    id: 'MAP-037',
    name: 'Behavioral Dependency Signal → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-BH-\d+$/,
      category: /^Behavioral Supply Chain$/i,
      severity: ['critical', 'high', 'medium', 'low'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Runtime-capable dependency behavior can affect whether reasonable steps are being taken to protect personal information under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-038',
    name: 'Network-Capable Dependency → APP 8',
    sourcePatterns: {
      ruleId: /^VS-BH-002$/,
      category: /^Behavioral Supply Chain$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.70,
    rationale: 'A dependency with outbound network capability may create cross-border disclosure pathways. APP 8 impact depends on runtime configuration and actual data destinations.',
    citation: 'APP Guidelines Chapter 8',
  },
  {
    id: 'MAP-039',
    name: 'Secret-Adjacent Dependency Behavior → NDB',
    sourcePatterns: {
      ruleId: /^VS-BH-00[46]$/,
      category: /^Behavioral Supply Chain$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.68,
    rationale: 'Dependency access to environment secrets or high-entropy embedded strings may create a breach pathway. NDB impact depends on whether credentials or personal information are exposed.',
    citation: 'NDB Guidelines s26WE',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Secrets committed to git history can remain exposed after deletion from the current tree. Reasonable security steps under APP 11.1 include detecting and rotating exposed credentials.',
    citation: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-041',
    name: 'Git History Secret → NDB',
    sourcePatterns: {
      ruleId: /^VS-GL-/,
      severity: ['critical', 'high'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.82,
    rationale: 'A credential exposed in git history may create a data-breach pathway. NDB impact depends on whether the credential was valid, accessed, and connected to personal information.',
    citation: 'NDB Guidelines s26WE',
  },
  {
    id: 'MAP-042',
    name: 'SAST Lite Security Pattern → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-SAST-\d+$/,
      category: /^SAST Lite$/i,
      severity: ['critical', 'high', 'medium', 'low'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.78,
    rationale: 'Compliance-critical source patterns can indicate missing reasonable security controls for personal information under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-043',
    name: 'SAST Lite Cross-Border/Data Flow Pattern → APP 8',
    sourcePatterns: {
      ruleId: /^VS-SAST-00[6]|^VS-SAST-010$/,
      category: /^SAST Lite$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.65,
    rationale: 'Outbound request and wildcard CORS patterns may create cross-border disclosure pathways. APP 8 impact depends on actual destinations and data sent.',
    citation: 'APP Guidelines Chapter 8',
  },
  {
    id: 'MAP-044',
    name: 'SAST Lite Secret/Data Exposure Pattern → NDB',
    sourcePatterns: {
      ruleId: /^VS-SAST-00[17]|^VS-SAST-011|^VS-SAST-012|^VS-SAST-013$/,
      category: /^SAST Lite$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.72,
    rationale: 'Secrets, sensitive logging, URL-exposed data, localStorage secrets, and unencrypted object storage may create a breach pathway requiring NDB assessment.',
    citation: 'NDB Guidelines s26WE',
  },
  {
    id: 'MAP-045',
    name: 'Personal Data Collection Pattern → APP 3',
    sourcePatterns: {
      ruleId: /^VS-SAST-019$/,
      category: /^SAST Lite$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_3',
    status: 'unknown',
    confidence: 0.65,
    rationale: 'Personal data collection without a visible consent, notice, or lawful-basis check may affect whether collection is lawful, fair, and necessary.',
    citation: 'APP Guidelines Chapter 3',
  },
  {
    id: 'MAP-046',
    name: 'Personal Data Retention Pattern → APP 12',
    sourcePatterns: {
      ruleId: /^VS-SAST-020$/,
      category: /^SAST Lite$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_12',
    status: 'unknown',
    confidence: 0.60,
    rationale: 'Personal data writes without visible retention or deletion controls may affect access and lifecycle handling obligations.',
    citation: 'APP Guidelines Chapter 12',
  },
  {
    id: 'MAP-047',
    name: 'IaC Misconfiguration → APP 11.1',
    sourcePatterns: {
      ruleId: /^VS-IAC-\d+$/,
      category: /^Infrastructure as Code$/i,
      severity: ['critical', 'high', 'medium', 'low'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.82,
    rationale: 'Infrastructure-as-code misconfigurations can weaken reasonable technical controls used to protect personal information under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.1',
  },
  {
    id: 'MAP-048',
    name: 'IaC Secret Exposure → NDB',
    sourcePatterns: {
      ruleId: /^VS-IAC-00[5]|^VS-IAC-024$/,
      category: /^Infrastructure as Code$/i,
      severity: ['critical', 'high'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.76,
    rationale: 'Secrets embedded in infrastructure configuration may create a data-breach pathway. NDB impact depends on credential validity, access, and connected personal information.',
    citation: 'NDB Guidelines s26WE',
  },
  {
    id: 'MAP-049',
    name: 'Public IaC Storage Exposure → APP 8',
    sourcePatterns: {
      ruleId: /^VS-IAC-017$/,
      category: /^Infrastructure as Code$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.78,
    rationale: 'Public storage infrastructure can disclose personal information to unauthorised or overseas recipients. APP 8 impact depends on the data stored and recipient locations.',
    citation: 'APP Guidelines Chapter 8',
  },
  {
    id: 'MAP-050',
    name: 'IaC Logging Gap → NDB',
    sourcePatterns: {
      ruleId: /^VS-IAC-023$/,
      category: /^Infrastructure as Code$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.70,
    rationale: 'Missing infrastructure logging can limit the ability to detect, assess, and respond to eligible data breaches.',
    citation: 'NDB Guidelines s26WE',
  },
  {
    id: 'MAP-036',
    name: 'OSV Breach-Relevant Vulnerability → NDB',
    sourcePatterns: {
      ruleId: /^VS-OSV-/,
      title: /(remote code execution|rce|authentication bypass|information disclosure|sensitive data|exfiltrat|sql injection|cross.?site scripting|xss)/i,
      severity: ['critical', 'high'],
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.70,
    rationale: 'The dependency vulnerability class may create a realistic data-breach pathway. NDB impact depends on exploitability, exposed systems, and whether personal information is affected.',
    citation: 'NDB Guidelines s26WE',
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
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.92,
    rationale: 'Missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) constitute a failure to take reasonable steps to protect personal information in transit and prevent common web attacks under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6; OAIC Guide to Securing Personal Information',
  },
  // Exposed API keys
  {
    id: 'MAP-027',
    name: 'Exposed API Keys → APP 11.1 + APP 6.1',
    sourcePatterns: {
      ruleId: /^AL-KEY-\d+$/,
      category: /^Exposed Keys$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.95,
    rationale: 'Exposed API keys in client-side code constitute a serious failure to protect personal information (APP 11.1) and may lead to unauthorised use or disclosure of data (APP 6.1). This is one of the most common causes of data breaches in vibe-coded applications.',
    citation: 'APP Guidelines Chapter 11.6; Notifiable Data Breaches s26WE',
  },
  // Infrastructure misconfigurations
  {
    id: 'MAP-028',
    name: 'Infrastructure Misconfiguration → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-INFRA-\d+$/,
      category: /^Infrastructure$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.93,
    rationale: 'Exposed infrastructure files (.git, .env, debug endpoints) provide attackers with source code, secrets, and internal application structure, constituting a failure to take reasonable steps under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6',
  },
  // JS vulnerability patterns
  {
    id: 'MAP-029',
    name: 'JS Vulnerability Patterns → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-JS-\d+$/,
      category: /^JS Security$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.88,
    rationale: 'Client-side JavaScript vulnerabilities (XSS via innerHTML, eval usage, etc.) can lead to unauthorised access to personal information, constituting a failure to take reasonable steps under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6',
  },
  // CORS wildcard
  {
    id: 'MAP-030',
    name: 'Wildcard CORS → APP 11.1 + APP 6.1',
    sourcePatterns: {
      ruleId: /^AL-URL-013$/,
      category: /^CORS$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Wildcard CORS allows any origin to access API responses, potentially exposing personal information to malicious websites. This violates both APP 11.1 (reasonable steps) and APP 6.1 (use/disclosure).',
    citation: 'APP Guidelines Chapter 11.6; APP Guidelines Chapter 6',
  },
  // Cookie security flags
  {
    id: 'MAP-031',
    name: 'Insecure Cookie Flags → APP 11.1',
    sourcePatterns: {
      ruleId: /^AL-URL-\d+$/,
      category: /^Cookie Security$/i,
    },
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.87,
    rationale: 'Cookies without Secure and HttpOnly flags can be intercepted or accessed via JavaScript, potentially exposing session tokens and personal information. This constitutes a failure to take reasonable steps under APP 11.1.',
    citation: 'APP Guidelines Chapter 11.6; OAIC Guide to Securing Personal Information',
  },
];

export const CCPA_MAPPING_RULES: MappingRule[] = [
  {
    id: 'MAP-CCPA-001',
    name: 'Hardcoded Credentials → CCPA_100',
    sourcePatterns: {
      ruleId: /^VG-SEC-001|^VS-HARDKEY|^MC-EXP-SEC$/,
      category: /^(Secrets?|Credentials?)$/i,
      title: /hardcoded.*(key|secret|token|password|credential|api.?key)/i,
      severity: ['critical', 'high'],
    },
    matchMode: 'or',
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Hardcoded credentials indicate missing reasonable security safeguards for consumer personal information.',
    citation: 'Cal. Civ. Code §1798.100(e)',
  },
  {
    id: 'MAP-CCPA-002',
    name: 'SQL Injection → CCPA_100',
    sourcePatterns: {
      ruleId: /^VG-SEC-002|^VS-SQLI|^VS-SAST-004$/,
      category: /^(Security|SAST Lite)$/i,
      title: /sql.?injection|sql query built from request input/i,
      severity: ['critical', 'high'],
    },
    matchMode: 'or',
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'fail',
    confidence: 0.90,
    rationale: 'SQL injection can expose consumer personal information and indicates a failure to maintain reasonable security.',
    citation: 'Cal. Civ. Code §1798.100(e)',
  },
  {
    id: 'MAP-CCPA-003',
    name: 'XSS → CCPA_100',
    sourcePatterns: {
      ruleId: /^VG-SEC-006|^VS-XSS|^AL-JS-001$/,
      category: /^(Security|JS Security)$/i,
      title: /cross.?site.?scripting|xss|dangerously.?set.?inner.?html/i,
      severity: ['high', 'medium'],
    },
    matchMode: 'or',
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'fail',
    confidence: 0.85,
    rationale: 'XSS can lead to unauthorized access to consumer personal information and indicates missing reasonable security controls.',
    citation: 'Cal. Civ. Code §1798.100(e)',
  },
  {
    id: 'MAP-CCPA-004',
    name: 'Insecure Transport → CCPA_100',
    sourcePatterns: {
      ruleId: /^AL-URL-002$/,
      category: /^Security Headers$/i,
      title: /strict.?transport|hsts|https|insecure transport/i,
      severity: ['critical', 'high', 'medium'],
    },
    matchMode: 'or',
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Missing transport security can expose consumer personal information in transit and indicates missing reasonable security.',
    citation: 'Cal. Civ. Code §1798.100(e)',
  },
  {
    id: 'MAP-CCPA-005',
    name: 'Exposed API Keys → CCPA_150',
    sourcePatterns: {
      ruleId: /^VG-SEC-001|^VS-HARDKEY|^MC-EXP-SEC|^AL-KEY-\d+|^VS-GL-|^VS-PUBLIC-SECRET-ENV|^VS-PLATFORM-SECRET|^VS-FB-SERVICE-ACCOUNT|^VS-SAST-001$/,
      category: /^(Secrets?|Credentials?|Exposed Keys|Developer Credentials|SAST Lite)$/i,
      title: /(hardcoded|exposed|committed).*(key|secret|token|credential|api.?key)|secret detected/i,
      severity: ['critical'],
    },
    matchMode: 'or',
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_150',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Critical exposed credentials can create a breach pathway for unencrypted consumer personal information.',
    citation: 'Cal. Civ. Code §1798.150(a)',
  },
  {
    id: 'MAP-CCPA-006',
    name: 'Data Breach Vulnerabilities → CCPA_150',
    sourcePatterns: {
      category: /breach|leak|expos/i,
    },
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_150',
    status: 'fail',
    confidence: 0.80,
    rationale: 'Breach, leak, or exposure findings may trigger CCPA private-right-of-action risk when unencrypted personal information is affected.',
    citation: 'Cal. Civ. Code §1798.150(a)',
  },
  {
    id: 'MAP-CCPA-007',
    name: 'Unencrypted PI Storage → CCPA_150',
    sourcePatterns: {
      title: /unencrypted.*personal|plaintext.*(pii|sensitive|ssn)/i,
    },
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_150',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Plaintext or unencrypted sensitive personal information increases CCPA breach exposure.',
    citation: 'Cal. Civ. Code §1798.150(a)',
  },
  {
    id: 'MAP-CCPA-008',
    name: 'Cross-Border Transfer → CCPA_100',
    sourcePatterns: {
      category: /third.party|sharing|transfer/i,
    },
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'fail',
    confidence: 0.70,
    rationale: 'Third-party sharing or transfer findings may indicate missing contractual service provider restrictions.',
    citation: 'Cal. Civ. Code §1798.100(d)',
  },
  {
    id: 'MAP-CCPA-009',
    name: 'Excessive Data Collection → CCPA_100',
    sourcePatterns: {
      title: /overcollection|excessive.*collection|unnecessary.*data/i,
    },
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'fail',
    confidence: 0.65,
    rationale: 'Excessive collection can conflict with CCPA purpose limitation and data minimization duties.',
    citation: 'Cal. Civ. Code §1798.100(c)',
  },
  {
    id: 'MAP-CCPA-010',
    name: 'Personal Data Collection Without Visible Notice → CCPA_100',
    sourcePatterns: {
      ruleId: /^VS-SAST-019$/,
      title: /personal data collected without visible consent check/i,
    },
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'Personal-information collection without a visible notice, purpose, or minimization signal requires review under CCPA collection, purpose-limitation, and retention duties.',
    citation: 'Cal. Civ. Code §1798.100(b)-(c)',
  },
];

export const GDPR_MAPPING_RULES: MappingRule[] = [
  {
    id: 'MAP-GDPR-001',
    name: 'Hardcoded Credentials → GDPR_Art32',
    sourcePatterns: {
      ruleId: /^VG-SEC-001|^VS-HARDKEY|^MC-EXP-SEC$/,
      category: /^(Secrets?|Credentials?)$/i,
      title: /hardcoded.*(key|secret|token|password|credential|api.?key)/i,
      severity: ['critical', 'high'],
    },
    matchMode: 'or',
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art32',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Hardcoded credentials indicate missing appropriate technical and organisational security measures for personal data.',
    citation: 'GDPR Art. 32(1)',
  },
  {
    id: 'MAP-GDPR-002',
    name: 'SQL Injection → GDPR_Art32',
    sourcePatterns: {
      ruleId: /^VG-SEC-002|^VS-SQLI|^VS-SAST-004$/,
      category: /^(Security|SAST Lite)$/i,
      title: /sql.?injection|sql query built from request input/i,
      severity: ['critical', 'high'],
    },
    matchMode: 'or',
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art32',
    status: 'fail',
    confidence: 0.90,
    rationale: 'SQL injection can compromise confidentiality, integrity, and availability of personal data under GDPR security-of-processing obligations.',
    citation: 'GDPR Art. 32(1)',
  },
  {
    id: 'MAP-GDPR-003',
    name: 'XSS → GDPR_Art32',
    sourcePatterns: {
      ruleId: /^VG-SEC-006|^VS-XSS|^AL-JS-001$/,
      category: /^(Security|JS Security)$/i,
      title: /cross.?site.?scripting|xss|dangerously.?set.?inner.?html/i,
      severity: ['high', 'medium'],
    },
    matchMode: 'or',
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art32',
    status: 'fail',
    confidence: 0.85,
    rationale: 'XSS can allow unauthorised access to personal data and indicates missing appropriate security controls.',
    citation: 'GDPR Art. 32(1)',
  },
  {
    id: 'MAP-GDPR-004',
    name: 'Insecure Transport → GDPR_Art32',
    sourcePatterns: {
      ruleId: /^AL-URL-002$/,
      category: /^Security Headers$/i,
      title: /strict.?transport|hsts|https|insecure transport/i,
      severity: ['critical', 'high', 'medium'],
    },
    matchMode: 'or',
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art32',
    status: 'fail',
    confidence: 0.90,
    rationale: 'Missing transport security can expose personal data in transit and indicates missing security-of-processing measures.',
    citation: 'GDPR Art. 32(1)',
  },
  {
    id: 'MAP-GDPR-005',
    name: 'Unencrypted PI → GDPR_Art32',
    sourcePatterns: {
      title: /unencrypted.*personal|plaintext.*(pii|sensitive|ssn)/i,
    },
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art32',
    status: 'fail',
    confidence: 0.85,
    rationale: 'Plaintext or unencrypted personal data indicates missing encryption or equivalent protection under GDPR Art. 32.',
    citation: 'GDPR Art. 32(1)(a)',
  },
  {
    id: 'MAP-GDPR-006',
    name: 'Data Breach Vulns → GDPR_Art33',
    sourcePatterns: {
      category: /breach|leak|expos/i,
    },
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art33',
    status: 'unknown',
    confidence: 0.50,
    rationale: 'Breach, leak, or exposure findings may indicate a personal data breach pathway requiring supervisory authority notification assessment.',
    citation: 'GDPR Art. 33(1)',
  },
  {
    id: 'MAP-GDPR-007',
    name: 'Cross-Border Transfer → GDPR_Art44',
    sourcePatterns: {
      category: /third.party|sharing|transfer/i,
    },
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art44',
    status: 'unknown',
    confidence: 0.60,
    rationale: 'Third-party sharing or transfer findings require manual review to determine whether personal data leaves the EEA and whether an Art. 44-49 transfer mechanism applies.',
    citation: 'GDPR Art. 44',
  },
  {
    id: 'MAP-GDPR-008',
    name: 'Excessive Data Collection → GDPR_Art5',
    sourcePatterns: {
      title: /overcollection|excessive.*collection|unnecessary.*data/i,
    },
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art5',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'Potential overcollection requires context to determine whether data collection is limited to what is necessary for the specific purpose.',
    citation: 'GDPR Art. 5(1)(c)',
  },
  {
    id: 'MAP-GDPR-009',
    name: 'Automated Decisions → GDPR_Art22',
    sourcePatterns: {
      category: /automated.*decision|profiling|algorithm/i,
    },
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art22',
    status: 'unknown',
    confidence: 0.50,
    rationale: 'Automated decision or profiling findings require context to determine whether decisions are solely automated and produce legal or similarly significant effects.',
    citation: 'GDPR Art. 22(1)',
  },
  {
    id: 'MAP-GDPR-010',
    name: 'Personal Data Collection Without Visible Lawful Basis → GDPR_Art5',
    sourcePatterns: {
      ruleId: /^VS-SAST-019$/,
      title: /personal data collected without visible consent check/i,
    },
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art5',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'Personal-data collection without a visible notice, purpose, consent, or lawful-basis signal requires review against GDPR processing principles.',
    citation: 'GDPR Art. 5(1)(a)-(c)',
  },
];

export const DATA_FLOW_LITE_MAPPING_RULES: MappingRule[] = [
  {
    id: 'MAP-DF-AU-001',
    name: 'Data Flow Lite personal-data sink → APP 11.1',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(LOG|ANALYTICS|EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
      severity: ['critical', 'high', 'medium'],
    },
    matchMode: 'and',
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_11',
    status: 'fail',
    confidence: 0.82,
    rationale: 'A deterministic same-file personal-data flow into logs, analytics, external requests, or LLM prompts indicates a security-of-personal-information control gap requiring review before deployment.',
    citation: 'APP Guidelines Chapter 11.6',
  },
  {
    id: 'MAP-DF-AU-002',
    name: 'Data Flow Lite disclosure sink → APP 6',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(ANALYTICS|EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
    },
    matchMode: 'and',
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_6',
    status: 'unknown',
    confidence: 0.64,
    rationale: 'Personal data sent to an analytics, external, or LLM destination may be a use or disclosure outside the primary purpose; the scanner cannot determine purpose, notice, or consent context.',
    citation: 'APP Guidelines Chapter 6',
  },
  {
    id: 'MAP-DF-AU-003',
    name: 'Data Flow Lite external destination → APP 8',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
    },
    matchMode: 'and',
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'APP_8',
    status: 'unknown',
    confidence: 0.58,
    rationale: 'External or LLM destinations can create overseas disclosure questions, but code alone does not identify hosting region, recipient controls, or APP 8 exceptions.',
    citation: 'APP Guidelines Chapter 8',
  },
  {
    id: 'MAP-DF-AU-004',
    name: 'Data Flow Lite exposure pathway → NDB',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(LOG|ANALYTICS|EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
    },
    matchMode: 'and',
    jurisdiction: 'au-privacy-act',
    regulationPrinciple: 'NDB',
    status: 'unknown',
    confidence: 0.55,
    rationale: 'A personal-data exposure pathway may require breach-readiness review if exploited or released, but eligible data breach notification depends on actual access, harm, and remediation facts.',
    citation: 'Privacy Act 1988 (Cth), Part IIIC',
  },
  {
    id: 'MAP-DF-CCPA-001',
    name: 'Data Flow Lite personal information sink → CCPA_100',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(LOG|ANALYTICS|EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
    },
    matchMode: 'and',
    jurisdiction: 'us-ccpa',
    regulationPrinciple: 'CCPA_100',
    status: 'unknown',
    confidence: 0.62,
    rationale: 'A same-file flow of personal information to logs, analytics, external requests, or LLM prompts requires review against notice, purpose, retention, and disclosure limits; code alone cannot prove CCPA/CPRA compliance.',
    citation: 'Cal. Civ. Code §1798.100',
  },
  {
    id: 'MAP-DF-GDPR-001',
    name: 'Data Flow Lite personal data sink → GDPR_Art32',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(LOG|ANALYTICS|EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
    },
    matchMode: 'and',
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art32',
    status: 'fail',
    confidence: 0.80,
    rationale: 'A deterministic same-file personal-data flow into logs, analytics, external requests, or LLM prompts indicates a security-of-processing control gap requiring review before deployment.',
    citation: 'GDPR Art. 32(1)',
  },
  {
    id: 'MAP-DF-GDPR-002',
    name: 'Data Flow Lite external personal data destination → GDPR_Art44',
    sourcePatterns: {
      ruleId: /^DATAFLOW-PII-(EXTERNAL|LLM)$/,
      category: /^Data Flow Lite$/i,
    },
    matchMode: 'and',
    jurisdiction: 'eu-gdpr',
    regulationPrinciple: 'GDPR_Art44',
    status: 'unknown',
    confidence: 0.58,
    rationale: 'External or LLM destinations may involve international transfers, but code alone cannot establish destination geography or transfer mechanism.',
    citation: 'GDPR Art. 44',
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
  ...CCPA_MAPPING_RULES,
  ...GDPR_MAPPING_RULES,
  ...DATA_FLOW_LITE_MAPPING_RULES,
];

// ─── Mapping Engine ──────────────────────────────────────────────────────────

export interface MappingResult {
  mappings: RegulationMapping[];
  unmappedFindings: AttestLensFinding[];
}

export interface MapAllFindingsOptions {
  strictMode?: boolean;
  jurisdictions?: Jurisdiction[];
}

type MapAllFindingsInput = boolean | MapAllFindingsOptions;

/**
 * Map a single finding to regulation obligations using the mapping rules.
 */
export function mapFindingToRegulation(
  finding: AttestLensFinding,
  jurisdictions: Jurisdiction[] = ['au-privacy-act'],
): RegulationMapping[] {
  const mappings: RegulationMapping[] = [];
  const selectedJurisdictions = new Set(jurisdictions);

  for (const mapping of finding.regulationMappings ?? []) {
    if (selectedJurisdictions.has(mapping.jurisdiction)) {
      mappings.push(mapping);
    }
  }

  for (const rule of ALL_MAPPING_RULES) {
    if (!selectedJurisdictions.has(rule.jurisdiction)) {
      continue;
    }

    const matches = matchRule(finding, rule);
    if (matches) {
      mappings.push({
        jurisdiction: rule.jurisdiction,
        principle: rule.regulationPrinciple,
        obligation: getRegulationObligation(rule.jurisdiction, rule.regulationPrinciple),
        status: rule.status,
        confidence: calculateMappingConfidence(rule.confidence, finding),
        rationale: rule.rationale,
        citation: rule.citation,
      });
    }
  }

  // Preserve the existing AU default: high-risk unmapped security findings
  // remain manual-review APP 11 candidates. Other jurisdictions wait until
  // their rule packs define equivalent default buckets.
  if (
    mappings.length === 0
    && selectedJurisdictions.has('au-privacy-act')
    && (finding.severity === 'critical' || finding.severity === 'high')
  ) {
    mappings.push({
      jurisdiction: 'au-privacy-act',
      principle: 'APP_11',
      obligation: APPInfo.APP_11.obligation,
      status: 'unknown',
      confidence: 0.40,
      rationale: 'High/critical severity finding without explicit APP mapping. Requires manual assessment to determine which APP obligation is affected.',
    });
  }

  return deduplicateRegulationMappings(mappings);
}

/**
 * Backward-compatible APP-only mapping wrapper.
 */
export function mapFindingToAPP(finding: AttestLensFinding): APPMapping[] {
  return mapFindingToRegulation(finding, ['au-privacy-act'])
    .filter(isAURegulationMapping)
    .map(regulationMappingToAPPMapping);
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

function deduplicateRegulationMappings(mappings: RegulationMapping[]): RegulationMapping[] {
  const byKey = new Map<string, RegulationMapping>();

  for (const mapping of mappings) {
    const key = `${mapping.jurisdiction}:${mapping.principle}:${mapping.status}:${mapping.citation || ''}`;
    const existing = byKey.get(key);
    if (!existing || mapping.confidence > existing.confidence) {
      byKey.set(key, mapping);
    }
  }

  return Array.from(byKey.values());
}

/**
 * Map all findings and produce jurisdiction-agnostic control assessments.
 */
export function mapAllFindings(
  findings: AttestLensFinding[],
  strictMode: boolean,
): {
  controls: RegulationControl[];
  unmapped: AttestLensFinding[];
};
export function mapAllFindings(
  findings: AttestLensFinding[],
  options?: MapAllFindingsOptions,
): {
  controls: RegulationControl[];
  unmapped: AttestLensFinding[];
};
export function mapAllFindings(
  findings: AttestLensFinding[],
  optionsOrStrictMode: MapAllFindingsInput = {},
): {
  controls: RegulationControl[];
  unmapped: AttestLensFinding[];
} {
  const options = normalizeMapAllFindingsOptions(optionsOrStrictMode);
  const jurisdictions = options.jurisdictions ?? ['au-privacy-act'];
  const strictMode = options.strictMode === true;
  const controlMap = new Map<string, RegulationControl>();
  const unmapped: AttestLensFinding[] = [];

  for (const jurisdiction of jurisdictions) {
    const registry = getRegistry(jurisdiction);
    for (const principle of registry.order) {
      const info = registry.principles[principle];
      controlMap.set(getControlKey(jurisdiction, principle), {
        jurisdiction,
        principle,
        shortName: info.shortName,
        obligation: info.obligation,
        status: 'unknown',
        score: 100,
        findingCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
        questionnaireRequired: true,
        lastAssessed: new Date().toISOString(),
        citation: info.citation,
      });
    }
  }

  for (const rule of ALL_MAPPING_RULES) {
    if (!jurisdictions.includes(rule.jurisdiction)) {
      continue;
    }

    const key = getControlKey(rule.jurisdiction, rule.regulationPrinciple);
    if (controlMap.has(key)) {
      continue;
    }

    controlMap.set(key, {
      jurisdiction: rule.jurisdiction,
      principle: rule.regulationPrinciple,
      shortName: getRegulationShortName(rule.jurisdiction, rule.regulationPrinciple),
      obligation: getRegulationObligation(rule.jurisdiction, rule.regulationPrinciple),
      status: 'unknown',
      score: 100,
      findingCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      questionnaireRequired: true,
      lastAssessed: new Date().toISOString(),
    });
  }

  for (const finding of findings) {
    const mappings = mapFindingToRegulation(finding, jurisdictions);
    
    if (mappings.length === 0) {
      unmapped.push(finding);
      continue;
    }

    finding.regulationMappings = mappings;
    finding.appMappings = mappings
      .filter(isAURegulationMapping)
      .map(regulationMappingToAPPMapping);

    for (const mapping of mappings) {
      const control = controlMap.get(getControlKey(mapping.jurisdiction, mapping.principle));
      if (!control) continue;

      if (mapping.citation && !control.citation) {
        control.citation = mapping.citation;
      }
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
    for (const control of controlMap.values()) {
      if (control.status === 'unknown') {
        control.status = 'fail';
        control.score = 0;
        control.questionnaireRequired = false; // No point asking if it's already failed
      }
    }
  }

  // Final pass: set questionnaire requirements
  for (const control of controlMap.values()) {
    if (control.status === 'fail') {
      control.questionnaireRequired = false;
    } else if (control.status === 'unknown') {
      control.questionnaireRequired = true;
    } else if (control.findings.length > 0) {
      control.questionnaireRequired = false;
    }
  }

  return {
    controls: Array.from(controlMap.values()),
    unmapped,
  };
}

function normalizeMapAllFindingsOptions(options: MapAllFindingsInput): MapAllFindingsOptions {
  return typeof options === 'boolean'
    ? { strictMode: options }
    : options;
}

export function mapAllFindingsAU(findings: AttestLensFinding[], strictMode = false): {
  controls: APPControl[];
  unmapped: AttestLensFinding[];
} {
  const { controls, unmapped } = mapAllFindings(findings, {
    strictMode,
    jurisdictions: ['au-privacy-act'],
  });

  return {
    controls: controls
      .filter((control): control is RegulationControl & { jurisdiction: 'au-privacy-act'; principle: APPPrinciple } => (
        control.jurisdiction === 'au-privacy-act'
        && Object.prototype.hasOwnProperty.call(APPInfo, control.principle)
      ))
      .map(regulationControlToAPPControl),
    unmapped,
  };
}

function getRegulationObligation(jurisdiction: Jurisdiction, principle: RegulationPrinciple): string {
  const info = getRegistry(jurisdiction).principles[principle];
  if (info) {
    return info.obligation;
  }

  return JurisdictionInfo[jurisdiction].fullName;
}

function getRegulationShortName(jurisdiction: Jurisdiction, principle: RegulationPrinciple): string {
  const info = getRegistry(jurisdiction).principles[principle];
  if (info) {
    return info.shortName;
  }

  return principle;
}

function getControlKey(jurisdiction: Jurisdiction, principle: RegulationPrinciple): string {
  return `${jurisdiction}:${principle}`;
}

function isAURegulationMapping(
  mapping: RegulationMapping,
): mapping is RegulationMapping & { jurisdiction: 'au-privacy-act'; principle: APPPrinciple } {
  return mapping.jurisdiction === 'au-privacy-act'
    && Object.prototype.hasOwnProperty.call(APPInfo, mapping.principle);
}

function regulationMappingToAPPMapping(mapping: RegulationMapping & { principle: APPPrinciple }): APPMapping {
  return {
    principle: mapping.principle,
    obligation: mapping.obligation,
    status: mapping.status,
    confidence: mapping.confidence,
    rationale: mapping.rationale,
  };
}

function regulationControlToAPPControl(
  control: RegulationControl & { jurisdiction: 'au-privacy-act'; principle: APPPrinciple },
): APPControl {
  return {
    principle: control.principle,
    shortName: control.shortName,
    obligation: control.obligation,
    status: control.status,
    score: control.score,
    findingCount: control.findingCount,
    findings: control.findings,
    questionnaireRequired: control.questionnaireRequired,
    lastAssessed: control.lastAssessed,
  };
}

export default {
  ALL_MAPPING_RULES,
  CCPA_MAPPING_RULES,
  GDPR_MAPPING_RULES,
  DATA_FLOW_LITE_MAPPING_RULES,
  mapFindingToAPP,
  mapFindingToRegulation,
  mapAllFindings,
  mapAllFindingsAU,
};
