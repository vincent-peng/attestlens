# AttestLens — Product Requirements Document (PRD)

**Version:** 1.2  
**Date:** 2026-04-19  
**Author:** Vincent Peng / ADA  
**Status:** Phase 1.5 in progress — pre-validation

---

## 1. Problem Statement

72% of open-source MCP servers have critical/high vulnerabilities. 65% of vibe-coded apps have at least one critical security flaw. Zero existing scanners map technical findings to Australian Privacy Act (APP/NDB) obligations.

Consultants and MSPs need: *"Is this app compliant? What evidence do I have?"* Current tools list CVEs. Nobody says *"this CORS misconfiguration means you fail APP 11.1."*

---

## 2. Product Vision

**AttestLens** is a compliance attestation tool that:
1. **Scans** codebases and live URLs using composed open-source scanners (GuardVibe, mcp-scan, supply-chain, url-scan)
2. **Maps** every technical finding to APP/NDB obligations with confidence scoring
3. **Produces** evidence-grade compliance reports for consultant-to-client handoff

We are **NOT** a generic security scanner. We compose the best OSS tools and own the **synthesis + reporting layer** above them. Compliance mapping is the moat.

---

## 3. Target Users

| Segment | Profile | Willingness |
|---------|---------|------------|
| **AU Compliance Consultants & MSPs** | Sell readiness assessments, need client-ready deliverables | $149-499/scan or $299-499/mo |
| **In-house Privacy Officers / CISOs** | Need APP compliance evidence for OAIC audits | $49-99/mo self-serve |
| **Agencies & White-Label Partners** | Bundle reports into their service offerings | $299-499/mo volume |

---

## 4. Key Differentiators

| What Others Do | What AttestLens Does |
|---|---|
| Find exposed API key | Map to **APP 11.1** — "reasonable steps to protect" |
| Flag missing CORS | Map to **APP 6** + NDB readiness |
| List 47 findings in terminal | **Pass/fail/unknown checklist** by APP principle |
| Suggest `npm install helmet` | "Implement CORS hardening. APP 11.1. Status: FAIL." |
| No questionnaire | Guided attestation converts UNKNOWN → PASS/FAIL |
| No report format | Client-ready HTML/JSON/PDF with evidence, remediation, APP refs |

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: COMPLIANCE EVIDENCE & REPORTING               │
│  • APP/NDB pass/fail/unknown per control                │
│  • Evidence snapshots (finding + timestamp + source)     │
│  • Remediation playbooks with APP references             │
│  • Guided attestation questionnaire (fills UNKNOWN)     │
│  • PDF/HTML export for client handoff                    │
├─────────────────────────────────────────────────────────┤
│  Layer 2: COMPLIANCE SYNTHESIS ENGINE                    │
│  • 31 mapping rules: finding → APP obligations          │
│  • Confidence-weighted scoring (0-1)                    │
│  • Deduplication across scan sources                    │
│  • Strict mode: UNKNOWN → FAIL for formal audits       │
├─────────────────────────────────────────────────────────┤
│  Layer 1: SCANNING (compose, don't build)               │
│  • GuardVibe (static regex + MCP fallback)              │
│  • mcp-scan (MCP config security)                       │
│  • supply-chain (npm dependency risks, 7 rules)        │
│  • url-scan (headers, JS, infra, cookies, source maps) │
│  • Normalize all output into unified finding schema     │
└─────────────────────────────────────────────────────────┘
```

---

## 6. Scanner Integration

### GuardVibe — Primary Scanner

- 335 rules, 36 MCP tools, covers entire modern AI stack
- Static fallback (8 regex rules) when MCP unavailable
- Used: full_audit, scan_secrets, auth_coverage, analyze_dataflow, compliance_report

### mcp-scan — MCP Config Security

- 17+ checks (secrets, CVEs, permissions, exfiltration, prompt injection, typosquatting)
- CLI integration: `npx mcp-scan scan`

### Supply Chain — npm Dependency Risk

- 7 detection rules (VS-SC-001 through VS-SC-008, no VS-SC-003/009/010 yet)
- Catches Axios-style supply chain attacks (5/7 indicators)
- Parses package.json + package-lock.json
- Typosquatting detection with allowlist for known legitimate packages
- Runs `npm audit` for known CVEs

### Future Scanners (Phase 2+)

| Tool | What It Adds | When |
|---|---|---|
| VibeSafe | SAST + secrets + SCA, CI/CD integration | Phase 2 |
| vibe-check | HIPAA module, letter grades | Phase 2 |
| Socket.dev API | Real-time supply chain intelligence | Phase 3 |
| OSV.dev API | Known vulnerability database | Phase 3 |

---

## 7. Compliance Mapping Engine

### APP Principles → Scanner Findings

| Principle | Obligation | Scanner Coverage | Status Source |
|---|---|---|---|
| APP 1 | Open & transparent | Architecture, documentation | UNKNOWN (questionnaire) |
| APP 6 | Use or disclosure | CORS, auth coverage, data flow | PASS/FAIL (scan) |
| APP 8 | Cross-border disclosure | External APIs, data exfiltration | UNKNOWN (questionnaire) |
| APP 11 | Security | Hardcoded secrets, XSS, SQLi, CORS, RLS, supply chain | PASS/FAIL (scan) |
| APP 12 | Access | API endpoint exposure, auth | PASS/FAIL (scan) |
| NDB | Data breach notification | Breach plan, logging | UNKNOWN (questionnaire) |

### Status Definitions
- **PASS** — Scanner found evidence of proper implementation
- **FAIL** — Scanner found vulnerability/misconfiguration violating this APP
- **UNKNOWN** — Cannot be determined by automated scan (requires questionnaire)

---

## 8. Current Scope (Phase 1 ✅)

### Shipped
- [x] Core schema (Zod-validated unified finding schema)
- [x] Mapping engine (31 rules, confidence-weighted scoring)
- [x] Scanner adapters (GuardVibe static + mcp-scan + supply-chain + url-scan)
- [x] Scanner orchestrator (parallel execution + dedup + disable flags)
- [x] CLI (scan, audit, report commands)
- [x] Report generation (HTML, JSON, Markdown, PDF)
- [x] MCP server (4 tools: scan, scan_url, audit, map)
- [x] Supply chain scanner (7 rules, Axios-attack coverage)
- [x] URL scanner with hardened outbound request handling
- [x] Strict mode (UNKNOWN → FAIL)
- [x] 107 tests
- [x] Security hardening (execFileSync, path validation, no command injection)

### Not Yet Shipped (Phase 2+)
- [ ] Interactive attestation questionnaire (UNKNOWN → PASS/FAIL)
- [ ] Web dashboard (React + real-time scan progress)
- [ ] Live GuardVibe MCP integration (not just static fallback)
- [ ] Additional compliance packs (GDPR, SOC 2)

---

## 9. Validation Plan

Before building Phase 2:
1. **Create mock report** — APP checklist, pass/fail/unknown, evidence snippets
2. **Find 5-10 AU consultants/MSPs** on LinkedIn
3. **Show mock report** and ask: "Would you pay $199 for this? $499/mo for unlimited?"
4. **3+ yes** → build. Crickets → pivot or kill.
5. **Run 5 real scans** on open-source projects, manually validate mapping accuracy

---

## 10. Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | TypeScript | MCP SDK is TS-native, all scanners are JS/TS |
| Scanner Integration | Internal adapters + MCP server surface | Keep local execution simple; expose capabilities to editors through MCP |
| Output Schema | JSON Schema (typed with Zod) | Interoperable, type-safe, compatible with SARIF |
| Report Generation | HTML + JSON + Markdown + PDF (PDFKit) | Client-ready deliverables |
| Security | execFileSync, path validation, allowlist | Command injection prevention, path traversal protection |

---

## 11. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| GuardVibe is new (2⭐) | High | Static fallback exists; schema normalizer isolates us |
| APP/NDB mapping accuracy | High | Conservative defaults (more UNKNOWN); lawyer review planned |
| Liability from "compliance" claims | Critical | "Decision support" positioning; strong disclaimers; require human review |
| Supply chain false positives | Medium | Allowlist for known legitimate packages (ora, zod, etc.); typosquat threshold tuning |

---

## Appendix A: APP/NDB Quick Reference

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
| APP 9 | Gov Identifiers | Restricted |
| APP 10 | Quality of personal info | Accurate, up-to-date |
| APP 11 | Security | Reasonable steps to protect |
| APP 12 | Access | Individuals can access their info |
| APP 13 | Correction | Individuals can correct their info |
| NDB | Notifiable Data Breaches | Assess, notify, remediate |

---

*This PRD is a living document. Last updated 2026-04-19 (Phase 1.5 in progress).*
