# AttestLens — Rule Update Pipeline & Rapid Response Design

> **Note:** This design doc describes the rule update pipeline architecture. The foundation (typed manifests, embedded rules, cache fallback, update command) is shipped in Phase 2.5. Future rapid-response features (HEU-001 through HEU-003, Socket.dev-style real-time) are not yet implemented. For current status, see `docs/STATUS.md`.

**Date:** 2026-04-18
**Status:** Foundation started

---

## The Problem

When Axios got compromised on March 31, 2026, Socket.dev flagged it in **6 minutes**. Most projects auto-installed it before anyone could react. CheckVibe, VibeSecurity, GuardVibe — they all had to manually update their rules.

**Our challenge:** How do we ensure AttestLens detects new vulnerabilities faster than competitors, and how do we *prove* that to customers?

---

## How the Pros Do It

| Scanner | Update Model | Speed | Community? |
|---|---|---|---|
| **Snyk** | Proprietary vuln DB + 24/7 research team | Hours (CVE), days (0-day) | No — closed DB |
| **Semgrep** | Community rules registry (1.1K+ stars) + Semgrep Inc team | Days (community PRs), hours (critical) | Yes — PR-based contributions |
| **npm audit** | npm advisory DB (GitHub security advisories) | Hours (coordinated disclosure) | Partial — npm team curated |
| **Socket.dev** | Proprietary real-time analysis + heuristics | **Minutes** (automated detection) | No — closed ML |
| **GitHub Secret Scanning** | Proprietary patterns + partner programs | Hours | Partial — partner tokens only |
| **CheckVibe** | Manual rule additions by team | Days-weeks | No |
| **Medusa (Pantheon)** | 9,600+ rules, versioned releases | Weeks (batch releases) | Partial — PR-based |

**Key insight:** Socket.dev won the Axios race because they don't wait for rules — they use **behavioral heuristics** (install scripts, manifest-only changes, pre-staged packages) that catch novel attacks without needing a specific CVE rule. This is exactly what our supply-chain scanner already does for the static provenance layer (VS-SC-001→009) and can enrich with OSV.dev for known vulnerabilities when `--external-enrichment` is enabled.

---

## Our Strategy: 3-Layer Defense

### Layer 1: Behavioral Heuristics (Catch Unknowns Without Rules)

**What it is:** Pattern-based detection that catches *classes* of attacks, not specific CVEs.

**We already have this:**
- VS-SC-001: Install scripts in dependencies (catches Axios-style RAT delivery)
- VS-SC-002: Manifest-only changes (catches stealth version bumps)
- VS-SC-004: Typosquatting detection (catches decoy packages)
- VS-SC-005: Lockfile integrity (catches dependency swaps)
- VS-SC-007: Lockfile entry with no resolved URL (catches non-registry or ambiguous sources)
- VS-SC-008: Install scripts + no repo (compound risk)
- VS-SC-009: No repository or homepage metadata for direct production dependencies

**Expand with:**
- **HEU-001:** Pre-staged packages (new dep appears <24h before suspicious activity)
- **HEU-002:** Self-destructing code (code that deletes itself after execution)
- **HEU-003:** Obfuscated install scripts (base64, hex encoding in postinstall)
- **HEU-004:** Rapid version bumps (>3 versions in 24h)
- **HEU-005:** New maintainer + immediate publish (account age <7 days)
- **HEU-006:** Dependency count anomaly (package suddenly adds many deps)
- **HEU-007:** DNS/exfil patterns in code (hardcoded IPs, fetch to unknown domains)

**Advantage:** These catch *novel* attacks without needing a rule for the specific CVE. Axios would have been caught by HEU-001, HEU-002, HEU-003, HEU-005 even if we'd never heard of it.

### Layer 2: Rapid Rule Publishing (Hours, Not Days)

**Architecture:**

```
attestlens/
├── src/
│   └── scanner/
│       └── rules/           ← NEW: rule pack system
│           ├── core.ts      ← bundled with npm package
│           ├── supply-chain.ts
│           ├── url-headers.ts
│           └── index.ts     ← rule loader
├── rules/                   ← NEW: remote rule packs
│   ├── v1/
│   │   ├── core.json        ← stable rules (versioned)
│   │   ├── supply-chain.json
│   │   ├── url-headers.json
│   │   └── manifest.json   ← rule pack index
│   └── latest.json          ← symlink to current version
└── scripts/
    └── publish-rules.ts     ← CI: validate + publish rules
```

**Rule pack format:**
```json
{
  "version": "2026.4.18",
  "generated": "2026-04-18T12:00:00Z",
  "rules": [
    {
      "id": "AL-SEC-015",
      "category": "exposed-keys",
      "severity": "critical",
      "title": "Exposed Anthropic Claude API Key",
      "description": "Detects Anthropic API keys (sk-ant-*) in source code",
      "pattern": "sk-ant-api03-[A-Za-z0-9_-]{95}",
      "fixPrompt": "Move the Anthropic API key to an environment variable...",
      "appMapping": ["APP-11.1"],
      "cve": null,
      "addedIn": "2026.4.18"
    }
  ]
}
```

**Update mechanism:**
1. **npm package** ships with an embedded rule pack generated from current TypeScript rule definitions
2. **`attestlens update-rules`** refreshes the local cache from local JSON or HTTPS JSON sources, or seeds the embedded pack only when no cache exists
3. **`--auto-update`** is available on scan/audit/attest scan flows, remains opt-in, and only fetches when `ATTESTLENS_RULE_SOURCE` is configured
4. **Rule freshness metadata** is attached to scan summaries, MCP output, snapshots, JSON reports, Markdown, HTML, and PDF without exposing local cache paths
5. **Webhook/Poll** for Pro tier (future): push notifications when new rules available

**Speed target:** New rule for a public CVE → published within **4 hours** of advisory.

### Layer 3: Vulnerability Intelligence Feed (The Moat)

**What it is:** Automated monitoring of security sources → rule generation → publish.

**Sources to monitor:**
- **npm security advisories** (GitHub Security Advisories API)
- **Snyk vulnerability DB** (public subset via snyk.io)
- **CVE database** (NVD API)
- **Socket.dev blog** (they publish first analysis)
- **HackerOne** (public disclosures)
- **Reddit r/netsec, r/micro_saas** (early signals)
- **GitHub trending** (new attack repos)
- **npm weekly stats** (anomaly detection)

**Pipeline:**
```
Security Advisory → Monitor (cron) → Parse → Generate Rule → Test → Publish
     ↓                    ↓              ↓           ↓         ↓         ↓
  CVE-2026-XXXX    every 2 hours   extract     pattern   CI test   GitHub Release
  npm advisory      (GitHub         key info    + map to  against   → auto-update
  Socket alert       Actions        → rule     APP/NDB  test      → changelog
  blog post          cron)          template              suite
```

**GitHub Actions workflow (new):**
```yaml
name: Rule Update
on:
  schedule:
    - cron: '0 */4 * * *'  # Every 4 hours
  workflow_dispatch:         # Manual trigger for 0-days
jobs:
  check-sources:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: node scripts/check-advisories.mjs
      - run: node scripts/generate-rules.mjs
      - run: npm test
      - run: node scripts/publish-rules.mjs
      - uses: softprops/action-gh-release@v2
        with:
          tag: rules-${{ github.run_number }}
```

---

## Advertising "First to Detect"

### Trust Signals

**1. Rules Freshness Badge (in every scan output)**
```
╔══════════════════════════════════════════╗
║  AttestLens v0.3.0                       ║
║  Rules: 2026.4.18 (2 days old)           ║
║  Checks: 68 security + 8 supply chain    ║
║  Coverage: APP 1-13, NDB s26WE          ║
╚══════════════════════════════════════════╝
```

**2. Rule Changelog (public, searchable)**
- `CHANGELOG-RULES.md` in the repo
- Every rule addition tagged with date + source (CVE, advisory, research)
- Example: `2026-04-18: Added AL-SEC-015 (Anthropic API key) — source: npm advisory GHSA-xxxx`

**3. CVE Coverage Page (`attestlens.dev/cves`)**
- Public page listing all CVEs we detect
- Timestamp showing when each CVE rule was added
- Time-from-advisory-to-rule metric
- Example: "CVE-2026-XXXX: Rule added 2h 14m after advisory published"

**4. Rapid Response Promise (marketing)**
> "When a critical vulnerability drops, AttestLens has a detection rule within hours — not weeks. Our behavioral heuristics catch novel attacks even before specific rules exist."

**5. Real-time Status Page**
- Current rule version
- Last checked timestamp
- Number of active rules
- System status
- Inspired by status.github.com

**6. Community Rule Submissions**
- GitHub Issues template: "New Rule Request"
- PR template for rule contributions
- Community rules reviewed and merged within 48h
- Contributor badge on README
- Named credit in rule metadata

---

## Competitive Speed Comparison

| Scenario | Snyk | Socket.dev | CheckVibe | GuardVibe | **AttestLens** |
|---|---|---|---|---|---|
| Known CVE (npm advisory) | 4-12h | 1-4h | Days | Days | **4h (target)** |
| Novel supply chain (like Axios) | 12-24h | **6 min** | Days | Days | **Immediate** (behavioral heuristics catch it before rule exists) |
| New exposed key pattern | 1-2 days | Hours | Days | Days | **4h** + community PRs |
| AU Privacy Act change | N/A | N/A | N/A | N/A | **Same day** (we're the only scanner with APP/NDB mapping) |

**Our unique advantage:** Behavioral heuristics catch *unknown* attacks immediately (like Socket.dev), AND we have APP/NDB compliance mapping that nobody else has.

---

## Implementation Plan

### Phase 1: Rule Pack System (Week 1)

Foundation shipped:

- `RuleDefinition`, `RulePackManifest`, and `RuleFreshness` schemas
- embedded rule pack generated from shipped GuardVibe static, supply-chain, URL header, infra, key, and JS definitions
- deterministic loader with valid-cache overlay and corrupt-cache fallback to embedded rules
- `attestlens update-rules`
- opt-in `--auto-update`
- rule freshness metadata in scan/report surfaces

Still remaining:

- migrate the next scanner family after allowlisted GuardVibe fallback static regex execution
- finalize remote publishing and trust policy
- add advisory monitors and generated-rule publishing

- [x] Create `src/scanner/rules/` directory structure
- [x] Define rule schema (id, pattern, severity, APP mapping, fixPrompt, CVE, addedIn)
- [x] Build rule loader that reads from embedded + cached rule packs
- [x] Add `attestlens update-rules` CLI command
- [x] Add opt-in `--auto-update` flag (refresh cache before scanning)
- [x] Add rule freshness metadata to scan and report output
- [x] Harden cache preservation, public metadata redaction, and bounded local/HTTPS manifest loading
- [x] Execute allowlisted GuardVibe fallback static regex rules from the active rule pack with metadata overrides, explicit disables, and visible fallback warnings

### Phase 2: Behavioral Heuristics Expansion (Week 2)

- [ ] Implement HEU-001 through HEU-007 (7 new heuristic rules)
- [ ] Each heuristic: pattern + explanation + confidence score
- [ ] Add heuristic category to findings (differentiate from signature rules)
- [ ] Test against Axios attack reproduction
- [ ] Test against known supply chain incidents (ua-parser-js, event-stream, colors.js)

### Phase 3: Intelligence Pipeline (Week 3-4)

- [ ] Create `scripts/check-advisories.mjs` (npm advisory monitor)
- [ ] Create `scripts/generate-rules.mjs` (template-based rule generation)
- [ ] Create `scripts/publish-rules.mjs` (GitHub Release publisher)
- [ ] Set up GitHub Actions cron (every 4 hours)
- [ ] Add manual trigger for 0-day rapid response
- [ ] Create `CHANGELOG-RULES.md` with initial entries

### Phase 4: Trust & Marketing (Week 4-5)

- [ ] Build CVE coverage page (static, auto-generated from rules)
- [ ] Add "First to Detect" section to README
- [ ] Create rule submission GitHub Issue template
- [ ] Create rule contribution PR template
- [ ] Add contributor credits to rule metadata
- [ ] Blog post: "How AttestLens Catches Zero-Day Supply Chain Attacks"

---

## The "First to Detect" Playbook

When a new vulnerability drops (like Axios March 31, 2026):

**Step 1: Detect (0-30 min)**
- Advisory monitor picks up new CVE/advisory
- Or: manual trigger via `workflow_dispatch`

**Step 2: Rule (30 min - 2 hours)**
- Generate rule from template
- Map to APP/NDB obligations
- Write fix prompt
- Add test case (positive + negative)

**Step 3: Test (2-3 hours)**
- Run against test fixtures
- Verify no false positives
- Run full test suite

**Step 4: Publish (3-4 hours)**
- Merge to main
- Publish rule pack to GitHub Release
- `--auto-update` picks it up when `ATTESTLENS_RULE_SOURCE` points at the published HTTPS manifest

**Step 5: Announce (4-6 hours)**
- Tweet/X post: "AttestLens now detects [CVE]. Rule added X hours after advisory."
- Update CVE coverage page
- Post to r/netsec, r/micro_saas, Hacker News

**Step 6: Blog (1-2 days)**
- Technical writeup: detection methodology, what we caught, how our heuristics would have caught it
- Include Axios-like analysis showing our supply chain scanner detecting the attack pattern

---

## Rule Pack Versioning Strategy

```
Major.Minor.Patch-YYYY.MM.DD

Examples:
  1.0.0-2026.04.18  ← initial rule pack release
  1.1.0-2026.04.25  ← new rules added
  1.1.1-2026.04.28  ← bug fix in existing rule pattern
  1.2.0-2026.05.01  ← new heuristic rules
```

- **Major:** Breaking change to rule schema format
- **Minor:** New rules or changed patterns
- **Patch:** Bug fixes in existing rules
- **Date:** When the pack was published

**npm package:** Ships with embedded `core.json` at current version. Users can `attestlens update-rules` to get latest.

---

## Key Metrics to Track

| Metric | Target | How |
|---|---|---|
| Time from advisory to rule | <4 hours | GitHub Actions + manual trigger |
| Time from novel attack to heuristic detection | Immediate | Behavioral heuristics catch patterns, not signatures |
| Rule freshness (days since last update) | <7 days | Cron monitoring + community PRs |
| False positive rate | <5% | Test suite with positive + negative cases |
| Community rule contributions | 5+ per month (goal) | GitHub Issues + PR templates |
| CVE coverage | Top 50 npm CVEs per quarter | Advisory pipeline |

---

## Why This Beats Competitors

1. **Behavioral heuristics catch the unknown** — Socket.dev proved this with Axios. We have the same approach built into our supply chain scanner. CheckVibe and GuardVibe don't have this.

2. **Rule packs update independently** — npm package doesn't need a new version for new rules. `attestlens update-rules` fetches latest. Competitors require full app updates.

3. **Community contributions** — Semgrep's 1.1K stars prove community rules work. We'll have the same model with faster merge times (48h target vs Semgrep's weeks).

4. **APP/NDB mapping updates with rules** — When we add a rule for a new vulnerability, we also add which APP obligations it violates. No competitor does this.

5. **Transparent speed** — Every rule shows when it was added and what advisory triggered it. "First to detect" is a verifiable claim, not marketing fluff.

6. **Australian Privacy Act responsiveness** — When the Privacy Act changes (Tranche 2, new NDB requirements), we update compliance mappings same-day. Every other scanner is generic and region-agnostic.
