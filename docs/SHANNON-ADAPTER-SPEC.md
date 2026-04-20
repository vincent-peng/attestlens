# Shannon -> AttestLens Research Note

**Date:** 2026-04-19
**Status:** Deferred research
**Priority:** Post-v0.2.0 candidate only

---

## 1. Purpose

Evaluate whether AttestLens should eventually import Shannon (Keygraph) pentest results and translate them into APP/NDB evidence.

This note is intentionally **not** a committed roadmap item or an implementation spec for the current product.

Current guardrails:
- no shipped schema changes
- no current CLI or MCP surface changes
- no adapter implementation from this note
- no widening of the live `ScanSource` contract

Shannon remains an external future import concept until a complete design, provenance model, and sanitization layer are approved.

---

## 2. Why This Matters

- Shannon is a strong AI pentest benchmark with exploit-validated findings
- it produces high-signal security evidence that could complement AttestLens's compliance mapping
- agencies may eventually want a "pentest to attestation" workflow
- no current pentest tool closes the compliance paperwork gap for APP/NDB

The opportunity is real, but the trust boundary is also real: imported pentest output is third-party, untrusted input.

---

## 3. Observed Shannon Input Shape

Shannon appears to emit structured JSON reports with fields like:

```json
{
  "target": "juice-shop",
  "assessment_date": "2025-09-01",
  "scope": ["Authentication", "XSS", "SQL Injection", "SSRF", "Authorization"],
  "findings": [
    {
      "id": "AUTH-VULN-01",
      "category": "Authentication",
      "title": "SQL Injection Authentication Bypass",
      "severity": "critical",
      "vulnerability_location": "POST /rest/user/login (email field)",
      "overview": "Direct string interpolation in SQL query enables complete authentication bypass",
      "impact": "Administrative access bypass, complete system compromise",
      "prerequisites": "None - publicly accessible endpoint",
      "exploitation_steps": "curl -X POST ...",
      "proof_of_impact": "Successfully obtained admin JWT token...",
      "notes": "Vulnerability exists due to direct string interpolation at /routes/login.ts:34",
      "source_code_reference": "/routes/login.ts:34"
    }
  ]
}
```

This is reference material only. AttestLens should not depend directly on Shannon's raw report shape without an internal normalization layer.

---

## 4. Potential Mapping Direction

| Shannon Category | Example Finding | APP/NDB Mapping | Rationale |
|---|---|---|---|
| **Authentication** | SQLi auth bypass, brute force, weak passwords | APP 11.1, APP 6 | Unauthorized access to personal information is primarily a security and disclosure problem |
| **Authorization** | IDOR, privilege escalation, business logic bypass | APP 6, APP 11.1 | Out-of-scope access becomes unauthorized use/disclosure |
| **XSS** | Reflected/stored XSS, JSONP injection | APP 11.1, NDB | Client-side compromise can enable exfiltration and breach scenarios |
| **SQL/Command Injection** | SQLi, NoSQL injection, XXE | APP 11.1, APP 10, NDB | Injection can expose or corrupt personal information |
| **SSRF** | Internal service access, metadata exposure | APP 11.1, APP 8 | SSRF can expose protected services and cross-border data paths |
| **Secrets Exposure** | Hardcoded credentials, API keys in JS | APP 11.1, NDB | Credential leakage creates a direct breach path |
| **Security Misconfiguration** | Missing headers, wildcard CORS | APP 11.1 | Weak controls increase compromise likelihood |
| **Info Disclosure** | Stack traces, .env exposure, debug endpoints | APP 11.1, APP 6 | Disclosures can facilitate attacks or expose protected data |

These mappings are a starting point only. They must remain confidence-scored and conservative.

---

## 5. Preferred Future Architecture

If this work is ever scheduled, the preferred shape is:

1. Accept imported pentest output through a separate internal import boundary.
2. Normalize it into an internal import schema such as `PentestImport`.
3. Map sanitized import findings into normal AttestLens findings and APP/NDB controls.
4. Keep raw external evidence separate from standard report payloads.

Important contract rule:
- **Do not add external tools like Shannon to the live `ScanSource` enum until the adapter ships end-to-end with tests and provenance handling.**

Preferred provenance model:
- native scanner output continues to use the shipped `ScanSource` values
- imported external evidence carries explicit tool provenance in a separate import layer first
- only after the adapter is real should AttestLens decide whether an imported source deserves first-class treatment in the live schema

---

## 6. Security and Trust-Boundary Rules

Any future Shannon import must follow these rules:

### Imported evidence handling

- imported pentest reports are **untrusted and sensitive by default**
- normalized findings may contain only sanitized summary fields
- raw PoCs, proof artifacts, cookies, bearer tokens, query strings, internal URLs, exploit payloads, and exfiltrated data must not flow into standard reports or normal MCP output
- if raw evidence is retained at all, it must live in a separate opt-in evidence artifact path with tighter access controls than the normal report path

### AI remediation handling

- AI remediation from imported pentest content is **off by default**
- if future fix-prompt generation is enabled, imported evidence must be sanitized first
- any imported text included in prompts must be quoted as data, not treated as operative instructions
- untrusted third-party notes or exploit steps must never be interpolated directly into the active instruction layer of a remediation prompt

### File import boundary

- any future import path must reuse the existing allowed-roots model
- imports must be limited to regular files under configured roots
- reject symlinks and escaped paths
- require `.json` input unless a specific parser is later approved
- validate file size before parsing
- validate top-level shape before normalization
- prefer async file reads and bounded parsing over blocking whole-file examples

### Output safety

- reports and MCP responses should surface only sanitized evidence summaries
- sensitive proof details should be replaced with redacted summaries or evidence references
- report generation must preserve the same URL/path sanitization standards already used elsewhere in AttestLens

---

## 7. Future Design Options (Uncommitted)

The following are placeholders only. They are not accepted product interfaces:

- a CLI import path for external pentest artifacts
- an MCP tool for importing vetted pentest evidence
- a report mode that merges imported pentest results with APP/NDB mapping

Names such as `shannon_import` or flags such as `--shannon-report` should be treated as draft examples only. Final interface names should be chosen only when the feature is actually scheduled.

---

## 8. Report Design Direction

If AttestLens ever generates a compliance report from imported pentest results, the report should emphasize:

- target and assessment scope
- APP/NDB control impact
- sanitized vulnerability summaries
- remediation guidance and attestation language
- evidence references, not raw exploit dumps

Default report behavior should be:
- include finding location, overview, impact, APP/NDB mapping, and remediation summary
- exclude raw exploit commands and proof artifacts from the normal PDF body
- use an optional separate appendix or evidence bundle only when explicitly requested

---

## 9. What We Can Borrow from Shannon

Shannon is AGPL-3.0. We can study ideas and patterns, but not copy code into AttestLens.

Safe to borrow conceptually:

| What | How It Helps |
|---|---|
| **Report structure** | Location -> overview -> impact -> severity -> proof -> notes is a strong reporting pattern |
| **PoC-driven quality bar** | Verified findings are a useful standard for high-confidence output |
| **Open-core model** | Validates the commercial shape of local tools plus paid workflows |
| **Sample report as marketing** | Public example artifacts can be a strong conversion asset |

Not safe to copy directly:

- Shannon source code
- Shannon exploit logic
- Shannon's evolving internal JSON shape as if it were a stable public API

---

## 10. Future Input Format Direction

A better long-term direction is an AttestLens-owned import schema that can normalize multiple external tools, for example:

```typescript
// Future concept only. Not implemented in AttestLens today.
export const PentestImportFinding = z.object({
  id: z.string(),
  category: z.enum([
    'authentication',
    'authorization',
    'xss',
    'injection',
    'ssrf',
    'secrets',
    'misconfiguration',
    'info-disclosure',
    'supply-chain',
    'other',
  ]),
  title: z.string(),
  severity: Severity,
  location: z.string(),
  overview: z.string(),
  impact: z.string(),
  evidenceSummary: z.string().optional(),
  sourceReference: z.string().optional(),
  toolSource: z.string(),
  toolVersion: z.string().optional(),
});
```

This remains a future design direction only. It does not land in code from this note.

---

## 11. Prioritization and Entry Criteria

This work is **not scheduled** for the shipped roadmap today.

Earliest revisit point:
- after `v0.2.0` validation feedback exists
- after current M2 questionnaire and assessment foundation work is stable

Entry criteria before implementation:

1. design-partner demand for imported pentest evidence is confirmed
2. provenance and sanitization rules are approved
3. import boundary and allowed-roots behavior are specified end-to-end
4. report treatment of sensitive evidence is explicitly decided

Until those conditions are met, this remains research only.

---

## 12. Risks

1. **Schema drift risk**: importing Shannon too early pressures the live schema before the trust boundary is designed.
2. **Evidence leakage risk**: raw PoCs and proof artifacts can leak sensitive material into reports or MCP output.
3. **Prompt-injection risk**: imported third-party evidence must not become live AI instruction text by default.
4. **Format drift risk**: Shannon output may change, so AttestLens should own the normalization layer.
5. **Compliance overclaim risk**: pentest evidence can inform compliance assessment, but it does not replace questionnaire or procedural evidence.

---

## 13. Future Extensions

- **SARIF as a preferred research direction** (see §11 of COMPETITIVE-GAP-ANALYSIS.md) — explore whether a quarantined SARIF intake can cover output from Pentest-Swarm-AI, Semgrep, CodeQL, SonarQube, Snyk, GitHub Code Scanning, etc.
- **Shannon JSON → SARIF converter** — research whether Shannon's native JSON can be normalized into a quarantined SARIF-shaped intake before any later import design is approved
- optional evidence bundle generation with stronger access controls
- richer provenance tracking for imported versus native findings
- a later live Shannon integration only if real demand justifies it

### Why SARIF Over Per-Tool Adapters

The original design in §10 of this spec proposed a `PentestImport` schema with per-tool parsers. That approach doesn't scale — every new pentest tool needs a new adapter.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard (v2.1.0) with wide adoption:
- Pentest-Swarm-AI outputs SARIF natively
- Semgrep, CodeQL, SonarQube, Snyk, Checkmarx, GitHub Code Scanning all support SARIF
- One importer handles 80%+ of tools instead of N per-tool adapters
- Shannon JSON could use an **offline research normalization step** into a quarantined SARIF-shaped intake if that later proves useful

Guardrails that still apply if this research continues:

- parsing must fail closed on malformed or version-incompatible input
- schema-version checks are mandatory before normalization
- any future import path must keep existing root restrictions, reject symlinks/escaped paths, and validate file type/size before parsing
- raw imported evidence must stay isolated from normal PDF/HTML/Markdown reports and public MCP payloads
- producer-specific metadata such as tags, rule IDs, levels, and locations remain advisory; fallback classification is required when they are missing or weak
- no live `ScanSource`, CLI, MCP, or report-schema changes are approved by this note

See `docs/COMPETITIVE-GAP-ANALYSIS.md` §11 for the broader research architecture and market context.
