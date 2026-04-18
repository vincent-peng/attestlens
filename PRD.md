# AttestLens — Product Requirements Document (PRD)

**Version:** 1.0  
**Date:** 2026-04-18  
**Author:** Vincent Peng / ADA  
**Status:** Draft — Pre-validation

---

## 1. Problem Statement

72% of open-source MCP servers have critical/high vulnerabilities. 65% of vibe-coded apps have at least one critical security flaw. Yet **zero existing scanners map technical findings to regulatory compliance obligations** — specifically the Australian Privacy Act 1988 (APPs) and Notifiable Data Breach (NDB) scheme.

Consultants and MSPs serving Australian businesses need to answer: *"Is this application compliant? What evidence do I have?"* Current tools list 47 CVEs in a terminal. Nobody says *"this CORS misconfiguration means you fail APP 11.1."*

---

## 2. Product Vision

**AttestLens** is an AI-powered compliance attestation tool that:

1. **Scans** codebases using composed open-source scanners (not reinventing the wheel)
2. **Maps** every technical finding to Australian Privacy Act APP/NDB obligations
3. **Produces** evidence-grade compliance reports designed for consultant-to-client handoff

**What we are NOT:** A generic security scanner. A legal certification engine. A replacement for professional compliance advice.

**What we ARE:** The compliance evidence layer on top of existing scanners. We compose the best OSS scanning tools and own the synthesis + reporting layer above them.

---

## 3. Target Users (ICP)

### Primary: AU Compliance Consultants & MSPs
- Sell compliance readiness assessments to clients
- Currently cobble together manual checklists + scanner outputs
- Willing to pay $149-499 per scan or $299-499/mo subscription
- Need client-ready deliverables (PDF/HTML reports with branding)

### Secondary: In-house Privacy Officers & CISOs
- Need to demonstrate APP compliance internally
- Want evidence artifacts for OAIC audits
- $49-99/mo self-serve tier

### Tertiary: Agencies & White-Label Partners
- Bundle AttestLens reports into their service offerings
- Need white-label, custom branding, bulk pricing
- $299-499/mo with volume discounts

---

## 4. Key Differentiators

| What Others Do | What AttestLens Does |
|---|---|
| Find exposed API key | Maps to **APP 11.1** — "Reasonable steps to protect personal information" |
| Flag missing CORS | Maps to **APP 6** — "Open and transparent management" + NDB readiness |
| List 47 findings in terminal | **Pass/fail/unknown checklist** organized by APP principle |
| Suggest `npm install helmet` | "Implement CORS hardening. APP 11.1. Evidence: scan timestamp. Status: FAIL." |
| No questionnaire | Asks "Do you have a documented data breach response plan?" → NDB s26WE = UNKNOWN |
| No report format | **Client-ready PDF** — exec summary, per-control findings, evidence, remediation priority |
| Developer-oriented | **Consultant-oriented** — designed as a deliverable to hand to clients |
| Compliance mapping? None. | **APP/NDB → GDPR/SOC2 later** — regulatory mapping as a first-class feature |

---

## 5. Architecture

### Three-Layer Design

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: COMPLIANCE EVIDENCE & REPORTING               │  ← THE PRODUCT
│                                                          │
│  • APP/NDB pass/fail/unknown mapping per control        │
│  • Evidence snapshots (finding + timestamp + source)     │
│  • Remediation playbooks with APP references             │
│  • Guided attestation questionnaire (fills UNKNOWN)     │
│  • PDF/HTML export for client handoff                    │
│  • White-label branding for agencies                     │
│  • Deterministic result hashes for audit trails          │
├─────────────────────────────────────────────────────────┤
│  Layer 2: COMPLIANCE SYNTHESIS ENGINE                    │  ← THE MOAT
│                                                          │
│  • Maps technical findings → APP obligations             │
│  • Assigns pass/fail/unknown per control                 │
│  • Flags "unknown" states (drives questionnaire)         │
│  • Correlates findings across scan sources               │
│  • Maintains regulatory mapping as versioned rules       │
│  • Produces structured compliance evidence schema        │
├─────────────────────────────────────────────────────────┤
│  Layer 1: SCANNING (compose, don't build)                │  ← COMMODITY
│                                                          │
│  • GuardVibe (335 rules, 36 tools, MCP server)          │
│  • VibeSafe (SAST + secrets + accessibility, GH Action) │
│  • mcp-scan (MCP config security, 17+ checks)           │
│  • vibe-check (HIPAA compliance module, letter grades)  │
│  • Normalize all output into unified finding schema     │
│  • Store raw results as evidence artifacts               │
└─────────────────────────────────────────────────────────┘
```

---

## 6. OSS Scanner Integration Analysis

### 6.1 GuardVibe (`npx guardvibe`) — PRIMARY SCANNER ⭐

**Why primary:** Most comprehensive — 335 rules, 36 tools, MCP-native, covers the entire modern AI stack.

| Attribute | Detail |
|---|---|
| **Stars** | 2 (new, low visibility) |
| **npm** | `guardvibe` v3.0.19 |
| **License** | Apache-2.0 ✅ |
| **Rules** | 335 security rules across 25+ categories |
| **Tools** | 36 MCP tools (check_code, scan_directory, full_audit, compliance_report, etc.) |
| **Stack Coverage** | Next.js, Supabase, Clerk, Stripe, Prisma, tRPC, Hono, GraphQL, Convex, Turso, Uploadthing, AI SDK |
| **Compliance** | SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EU AI Act mapping (BUILT-IN!) |
| **MCP** | Full MCP server — `npx -y guardvibe` |
| **CLI** | `npx guardvibe scan/audit/doctor` |
| **Output** | JSON, Markdown, SARIF, "buddy" format |
| **Auto-fix** | `fix_code` tool returns patches |
| **Unique** | `guardvibe doctor` scans host for CVE-2025-59536, CVE-2026-21852 |

**What we USE:**
- `full_audit` — single-call all-checks scan with PASS/FAIL/WARN verdict + score + deterministic hash
- `compliance_report` — already maps to SOC2/HIPAA/GDPR (we extend to APP/NDB)
- `scan_secrets` — hardcoded key detection (APP 11.1 evidence)
- `auth_coverage` — route-level auth coverage map (APP 11.1, APP 6)
- `analyze_dataflow` — taint tracking (APP 11.1 evidence for data handling)
- `remediation_plan` — section-by-section fix checklist (feeds our remediation playbook)
- `verify_fix` — re-scan to confirm remediation (evidence of remediation)

**What we DON'T use:**
- GuardVibe's own compliance report (SOC2/HIPAA/etc) — we build our own APP/NDB mapping layer
- `deep_scan` (requires API key, LLM-powered) — may offer as premium later

**Integration method:** MCP server — `npx -y guardvibe` as a subprocess/tool server

---

### 6.2 VibeSafe (`vibesafeio/vibesafe-action`) — CI/CD + Web Scanner

| Attribute | Detail |
|---|---|
| **Stars** | 4 |
| **License** | Open source |
| **Format** | GitHub Action + Web (paste URL) + MCP server |
| **Checks** | SAST, secrets, SCA (pip-audit + npm audit), config, accessibility |
| **Domains** | Auto-detect: ecommerce, fintech, healthcare, platform, game, education |
| **Unique** | AI Fix Prompt — generates prompts to paste back into AI coders |
| **Scoring** | A-F grade with Certified badge option |
| **Diff scan** | Only scans new code in PRs (baseline approach) |

**What we USE:**
- Web API for quick ad-hoc scans (paste a repo URL)
- GitHub Action for CI/CD integration (recommend to clients)
- SCA (dependency CVE scanning) — supplements GuardVibe's CVE check
- Accessibility checks — maps to APP 6 (transparency) and discrimination law
- AI Fix Prompts — feed into our remediation playbook

**What we DON'T use:**
- Their scoring/grading system — we have our own APP/NDB scoring

**Integration method:** Web API for ad-hoc + GitHub Action recommendation for clients' CI/CD

---

### 6.3 mcp-scan (`rodolfboctor/mcp-scan`) — MCP Config Security

| Attribute | Detail |
|---|---|
| **Stars** | 21 |
| **npm** | `mcp-scan` |
| **License** | MIT ✅ |
| **Checks** | 17+ checks (secrets, CVEs, permissions, exfiltration, prompt injection, typosquatting) |
| **Unique** | Scans MCP server *configurations* (not app code) — detects credential relay, prompt injection via tool descriptions, typosquatting |
| **Clients** | 16+ AI tool clients (Claude, Cursor, VS Code, Gemini, Codex, etc.) |
| **Compliance** | SOC2, GDPR, HIPAA, PCI-DSS, NIST 800-53 mapping |
| **Output** | JSON, SARIF |
| **Privacy** | `npx mcp-scan@latest privacy` — PII and compliance report |

**What we USE:**
- MCP config scanning — essential for APP 11.1 (reasonable steps to protect) when client uses AI coding tools
- Privacy assessment mode (`mcp-scan privacy`) — maps to APP 6/APP 11
- Policy engine (`.mcp-scan-policy.yml`) — we can embed APP-specific policies

**What we DON'T use:**
- Their compliance mapping (SOC2/GDPR/etc) — we build APP/NDB-specific

**Integration method:** CLI — `npx mcp-scan@latest` as a scan step

---

### 6.4 vibe-check (`NyxToolsDev/vibe-check`) — HIPAA + Letter Grades

| Attribute | Detail |
|---|---|
| **PyPI** | `vibe-code-check` v0.2.6 |
| **Downloads** | ~251/week |
| **License** | MIT ✅ |
| **Categories** | Security (11 rules), Testing (4), Code Quality (4), Architecture (4), Dependencies (4), HIPAA (6 Pro) |
| **Unique** | Letter grades (A-F), weighted scoring, HIPAA Pro module (paid) |
| **Output** | Terminal, JSON, Markdown, All |

**What we USE:**
- HIPAA module (Pro) — HIPAA and APP overlap significantly for health data handlers
- Testing category — useful for APP 8 (APP quality of data)
- Architecture checks — useful for APP 1 (open and transparent management)

**What we DON'T use:**
- Their scoring — we compose our own

**Integration method:** CLI — `pip install vibe-code-check && vibe-check scan .`

---

### 6.5 Other Notable Scanners (Future Integration)

| Tool | What It Adds | When to Integrate |
|---|---|---|
| **Vibeship Scanner** (117⭐) | 2000+ rules, web UI, quick ad-hoc scans | Phase 2 — web scan API |
| **Oculum** | 40+ AI-specific checks, GitHub Actions | Phase 2 — AI-specific findings |
| **mcp-security-scanner** (12⭐) | 5 MCP tools, JS/TS focused, Docker-ready | Phase 2 — supplementary |
| **CheckVibe** | 100+ checks, web UI, MCP server | Phase 2 — web scan fallback |
| **VibeCheck Pro** | AI Enforcement Security — audits if AI code *actually enforces* security claims | Phase 2 — unique enforcement angle |

---

## 7. Compliance Mapping Engine (The Moat)

### 7.1 Australian Privacy Act APP Obligations → Technical Findings

| APP Principle | Key Obligation | Scanner Findings That Map | AttestLens Status |
|---|---|---|---|
| **APP 1** | Open and transparent management | Architecture score, documentation checks, code quality | PASS/FAIL/UNKNOWN |
| **APP 3** | Collection of personal info | Data collection points, form inputs, analytics tracking | UNKNOWN (questionnaire) |
| **APP 5** | Notification of collection | Privacy policy presence, consent mechanisms | UNKNOWN (questionnaire) |
| **APP 6** | Use or disclosure | CORS misconfig, auth coverage gaps, data flow analysis | PASS/FAIL/UNKNOWN |
| **APP 7** | Direct marketing | Marketing SDK presence, email service integration | PASS/FAIL/UNKNOWN |
| **APP 8** | Cross-border disclosure | External API endpoints, data exfiltration paths | PASS/FAIL/UNKNOWN |
| **APP 10** | Quality of personal info | Input validation, data sanitization | PASS/FAIL/UNKNOWN |
| **APP 11** | Security of personal info | Hardcoded secrets, SQL injection, XSS, auth gaps, CORS, RLS | PASS/FAIL/UNKNOWN |
| **APP 12** | Access to personal info | API endpoint exposure, auth coverage | PASS/FAIL/UNKNOWN |
| **APP 13** | Correction of personal info | Data modification endpoints, auth coverage | UNKNOWN (questionnaire) |
| **NDB s26WE** | Data breach notification | Breach response plan, logging, monitoring | UNKNOWN (questionnaire) |

### 7.2 Status Definitions

- **PASS** — Scanner found evidence of proper implementation
- **FAIL** — Scanner found a vulnerability or misconfiguration that violates this APP
- **UNKNOWN** — Cannot be determined by automated scan alone (requires questionnaire or manual review)

### 7.3 Questionnaire Module

For UNKNOWN states, AttestLens presents a guided attestation questionnaire:

```
APP 5 — Notification of Collection
├─ Do you have a publicly available privacy policy? [Y/N]
├─ Does it state what personal information you collect? [Y/N]
├─ Does it explain the purpose of collection? [Y/N]
└─ Is it accessible from every page that collects data? [Y/N]

NDB s26WE — Data Breach Notification
├─ Do you have a documented data breach response plan? [Y/N]
├─ Does it include notification procedures for eligible breaches? [Y/N]
├─ Is there a process for assessing breach severity? [Y/N]
└─ Have you designated a contact for OAIC notifications? [Y/N]
```

Answers convert UNKNOWN → PASS/FAIL with evidence trail.

---

## 8. Unified Finding Schema

All scanner outputs are normalized into a single schema:

```typescript
interface AttestLensFinding {
  id: string;                    // Unique finding ID (deterministic hash)
  source: 'guardvibe' | 'vibesafe' | 'mcp-scan' | 'vibe-check' | 'manual';
  sourceRule: string;            // e.g., "VG-SEC-001", "VS-HARDKEY"
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;               // e.g., "Security", "Auth", "Data Flow"
  title: string;
  description: string;
  file?: string;
  line?: number;
  code?: string;                  // Offending code snippet
  fix?: string;                   // Suggested fix (from scanner or our playbook)
  appMapping: APPMapping[];      // Which APP obligations this maps to
  evidence: {
    timestamp: string;            // ISO 8601
    scannerVersion: string;
    rawOutput: any;               // Original scanner output for audit trail
  };
}

interface APPMapping {
  principle: string;              // e.g., "APP 11.1"
  obligation: string;             // e.g., "Reasonable steps to protect personal information"
  status: 'pass' | 'fail' | 'unknown';
  confidence: number;             // 0-1, how confident the mapping is
}

interface ComplianceReport {
  id: string;
  timestamp: string;
  target: string;                 // Repo/path scanned
  overallScore: number;           // 0-100
  overallGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  appControls: APPControl[];     // Per-APP assessment
  findings: AttestLensFinding[];
  questionnaire?: QuestionnaireResponse;
  remediation: RemediationPlan;
  metadata: {
    scannerVersions: Record<string, string>;
    deterministicHash: string;   // For audit trail integrity
  };
}
```

---

## 9. MCP Server Specification

AttestLens exposes an MCP server for integration with AI coding agents:

### Core Tools

| Tool | Description |
|---|---|
| `attestlens_scan` | Run full compliance scan (all composed scanners) |
| `attestlens_audit` | Full audit with PASS/FAIL verdict per APP control |
| `attestlens_compliance_report` | Generate APP/NDB compliance report |
| `attestlens_questionnaire` | Start/resume attestation questionnaire |
| `attestlens_remediation` | Get remediation playbook for failing controls |
| `attestlens_verify_fix` | Re-scan to verify remediation was applied |
| `attestlens_export` | Export report as PDF/HTML/JSON/SARIF |
| `attestlens_app_map` | List APP obligations with current status |

### Setup

```json
{
  "mcpServers": {
    "attestlens": {
      "command": "npx",
      "args": ["-y", "attestlens"]
    }
  }
}
```

---

## 10. Reporting & Deliverables

### 10.1 Compliance Report (PDF/HTML)

**Structure:**
1. Executive Summary — overall grade, risk level, key findings
2. APP Control Checklist — pass/fail/unknown per APP principle
3. Technical Findings — grouped by APP obligation, severity-ordered
4. Evidence Artifacts — timestamps, scanner versions, raw output references
5. Remediation Playbook — prioritized fixes with APP references
6. Attestation Questionnaire — responses for UNKNOWN states
7. Appendix — full scanner output, methodology

**White-label options:** Logo, brand colors, consultant name/contact, disclaimer text

### 10.2 Attestation Checklist (standalone)

Client-ready one-pager:
```
AttestLens Compliance Checklist — [Target]
Date: 2026-04-18 | Grade: C (62/100)

APP 1  — Open & Transparent Management     ✅ PASS
APP 3  — Collection of Personal Info         ⚠️ UNKNOWN (questionnaire required)
APP 5  — Notification of Collection          ⚠️ UNKNOWN (questionnaire required)
APP 6  — Use or Disclosure                    ❌ FAIL (2 findings)
APP 8  — Cross-Border Disclosure              ⚠️ UNKNOWN (questionnaire required)
APP 10 — Quality of Personal Info              ⚠️ UNKNOWN (questionnaire required)
APP 11 — Security of Personal Info            ❌ FAIL (7 findings)
APP 12 — Access to Personal Info              ✅ PASS
NDB    — Data Breach Notification             ⚠️ UNKNOWN (questionnaire required)

Overall: 2 PASS, 3 FAIL, 5 UNKNOWN
Action Required: Complete questionnaire for 5 UNKNOWN controls
```

---

## 11. Pricing

| Tier | Price | Includes |
|---|---|---|
| **Single Scan** | $149-199 | One-time full compliance audit + PDF report |
| **Monthly** | $49-99/mo | Unlimited scans, questionnaire, basic reporting |
| **Agency** | $299-499/mo | White-label, bulk scans, priority support, custom branding |
| **Enterprise** | Custom | On-prem, custom compliance packs, API access |

---

## 12. MVP Scope (Weeks 3-5)

### In Scope (v0.1)
- [ ] GuardVibe integration as primary scanner (MCP)
- [ ] mcp-scan integration for MCP config checks (CLI)
- [ ] Unified finding schema normalizer
- [ ] APP/NDB compliance mapping rules (11 APPs + NDB)
- [ ] Attestation questionnaire for UNKNOWN states
- [ ] PDF/HTML report generation
- [ ] MCP server with 7 core tools
- [ ] CLI interface (`npx attestlens scan/audit/report`)

### Out of Scope (v0.1)
- VibeSafe web API integration (Phase 2)
- GDPR/SOC2 compliance packs (Phase 2)
- White-label branding (Phase 2)
- Web UI / dashboard (Phase 3)
- VibeCheck Pro HIPAA module integration (Phase 2)
- Real-time monitoring / continuous compliance (Phase 3)

---

## 13. Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | TypeScript | MCP SDK is TS-native, all target scanners are JS/TS, same ecosystem |
| Scanner Integration | MCP (GuardVibe) + CLI (others) | GuardVibe is MCP-native; others run as CLI subprocesses |
| Output Schema | JSON Schema (typed with Zod) | Interoperable, type-safe, compatible with SARIF |
| Report Generation | PDF (Puppeteer/Playwright) + HTML | Client-ready deliverables |
| Storage | Local filesystem (SQLite later) | MVP simplicity, audit trail |
| Config | `.attestlensrc.yml` | Per-project config for scanner selection, policy overrides |

---

## 14. Success Metrics

| Metric | Target (v0.1) | Target (v0.3) |
|---|---|---|
| Paid scans | 10 in first month | 50/mo |
| Monthly subscribers | 5 | 20 |
| Consultant validation | 3+ "yes, I'd pay for this" | 10+ active consultants |
| App coverage | 11 APPs + NDB | + GDPR + SOC2 packs |
| Scanner integration | GuardVibe + mcp-scan | + VibeSafe + VibeCheck |
| False positive rate | <15% | <10% |

---

## 15. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| GuardVibe is new (2⭐) — could be abandoned | High | Pin versions, fork if needed, schema normalizer isolates us |
| APP/NDB mapping accuracy | High | Start conservative (more UNKNOWN), lawyer review of mapping rules |
| Liability from "compliance" claims | Critical | Position as "decision support" — require human review, strong disclaimers |
| Scanner dependency breakage | Medium | Unified schema + adapter pattern — easy to swap scanners |
| AU-only scope too narrow | Medium | Niche is defensible; GDPR/SOC2 expansion planned for Phase 2 |
| MCP server compatibility | Low | Follow MCP SDK spec, test against Claude Code / Cursor / VS Code |

---

## 16. Validation Plan (Weeks 1-2)

Before writing production code:

1. **Create mock report** — APP checklist, pass/fail/unknown, evidence snippets
2. **Find 5-10 AU consultants/MSPs** on LinkedIn
3. **Show mock report** and ask: "Would you pay $199 for this? $499/mo for unlimited?"
4. **3+ yes** → build. Crickets → pivot or kill.
5. **Run 5 real scans** on open-source projects using GuardVibe + mcp-scan
6. **Manually map findings** to APP obligations — validate mapping accuracy
7. **Share results** with validation group for feedback

---

## Appendix A: GuardVibe Tool Inventory (Primary Scanner)

| Tool | What It Returns | APP Relevance |
|---|---|---|
| `full_audit` | PASS/FAIL/WARN + score + hash | Core — feeds all controls |
| `scan_secrets` | Hardcoded keys, tokens, env leaks | APP 11.1, APP 6 |
| `auth_coverage` | Route-level auth coverage % | APP 11.1, APP 12 |
| `analyze_dataflow` | Taint tracking: input → sink | APP 11.1, APP 8 |
| `compliance_report` | SOC2/HIPAA/GDPR mapping | Base for APP mapping |
| `remediation_plan` | Section-by-section fix checklist | All controls |
| `verify_fix` | Re-scan to confirm remediation | Evidence of remediation |
| `audit_config` | Cross-file config misconfigurations | APP 1, APP 11 |
| `scan_dependencies` | Known CVEs in dependencies | APP 11.1 |
| `guardvibe_doctor` | Host security (CVEs, MCP config) | APP 11.1 |
| `check_code` | Single snippet analysis | Any control |
| `scan_directory` | Full directory scan | All controls |

---

## Appendix B: APP/NDB Quick Reference

| Principle | Short Name | Key Obligation |
|---|---|---|
| APP 1 | Open & transparent | Privacy policy, practices |
| APP 2 | Anonymity | Right to act anonymously |
| APP 3 | Collection | Lawful, fair, necessary |
| APP 4 | Handling unsolicited | Destroy or use |
| APP 5 | Notification | Tell individuals you collect |
| APP 6 | Use or disclosure | Purpose limitation |
| APP 7 | Direct marketing | Opt-out, consent |
| APP 8 | Cross-border disclosure | Reasonable steps overseas |
| APP 9 | Adoption, use, disclosure of Gov IDs | Restricted |
| APP 10 | Quality of personal info | Accurate, up-to-date |
| APP 11 | Security of personal info | Reasonable steps to protect |
| APP 12 | Access | Individuals can access their info |
| APP 13 | Correction | Individuals can correct their info |
| NDB | Notifiable Data Breaches | Assess, notify, remediate |

---

*This PRD is a living document. Update as validation results come in.*