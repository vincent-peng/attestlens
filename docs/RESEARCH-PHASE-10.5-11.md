# Research: Phase 10.5 (GitHub Action + MCP Distribution) & Phase 11 (Rule Authoring Pipeline)

**Date:** 2026-05-01
**Purpose:** Best practices and modern workflows research before implementation
**Status:** Merged — original research + Codex cross-examination corrections

---

## 1. GitHub Actions for Compliance Scanning

### 1.1 SARIF Integration with GitHub Code Scanning

**Standard Pattern** (used by CodeQL, Snyk, Semgrep, Trivy, Checkov):
1. Run scanner in CI
2. Output results as SARIF v2.1.0 JSON
3. Upload via `github/codeql-action/upload-sarif@v4`
4. Results appear in GitHub Security → Code scanning alerts
5. PR check annotations on affected lines

**GitHub SARIF Requirements:**
- Schema version: SARIF v2.1.0 (OASIS Standard)
- Max file size: 10 MB (gzip-compressed)
- Max results per run: 25,000 (top 5,000 displayed, prioritized by severity)
- Max rules per run: 25,000
- Max runs per file: 20
- File paths must be relative to repo root (absolute URIs converted)
- Symlinks must be resolved before reporting
- `partialFingerprints.primaryLocationLineHash` needed for deduplication (auto-generated if missing, but manual is more reliable)

**⚠️ Critical: SARIF Severity ≠ CI Blocking**

Three separate concerns that should NOT be conflated:
1. **SARIF `result.level`** → affects how GitHub displays the finding (error/red, warning/yellow, note/blue)
2. **GitHub severity properties** → `properties.problem.severity`, `properties.security-severity`, `properties.precision` affect ranking
3. **CI blocking behavior** → determined by workflow exit code + branch protection, NOT by SARIF level

`error` in SARIF does NOT automatically block PRs. Blocking requires the workflow step to exit non-zero AND branch protection to require that check.

**Design implication:** Clearway must implement `--fail-on-severity` / `--severity-threshold` as a separate CLI concern from SARIF output level.

### 1.2 SARIF Field Mapping for Compliance Scanners

For Clearway, most findings are better modeled as **non-security** unless a rule clearly involves application security or secret exposure.

| Clearway Concept | SARIF Field | Values |
|---|---|---|
| Blocking/high-confidence rule | `defaultConfiguration.level` | `error` |
| Advisory rule | `defaultConfiguration.level` | `warning` |
| Low-confidence/informational | `defaultConfiguration.level` | `note` |
| Legal/regulatory material breach | `properties.problem.severity` | `error` |
| Medium operational risk | `properties.problem.severity` | `warning` |
| Improvement/recommendation | `properties.problem.severity` | `recommendation` |
| Human-validated deterministic check | `properties.precision` | `high` or `very-high` |
| Heuristic check | `properties.precision` | `medium` |
| Broad text heuristic | `properties.precision` | `low` |

⚠️ **Do NOT set `properties.security-severity`** unless a finding is genuinely a security finding. Overusing it misclassifies the product in GitHub's security UI.

**SARIF Structure for Compliance Findings:**
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Clearway",
        "version": "0.4.0",
        "informationUri": "https://clearway.ai",
        "rules": [
          {
            "id": "AU.APP.11.1.policy-accessible",
            "name": "SensitiveDataExposure",
            "shortDescription": { "text": "Sensitive data collection without adequate disclosure" },
            "fullDescription": { "text": "APP 11.1: Sensitive data is collected without a clear and accessible privacy policy" },
            "helpUri": "https://clearway.ai/rules/AU.APP.11.1.policy-accessible",
            "properties": {
              "tags": ["privacy", "au-privacy-act", "app-11", "notice-and-transparency"],
              "precision": "high",
              "problem.severity": "error"
            }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "AU.APP.11.1.policy-accessible",
        "ruleIndex": 0,
        "level": "error",
        "message": { "text": "Privacy policy not found or not accessible from homepage" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/pages/index.tsx" },
            "region": { "startLine": 42, "startColumn": 1 }
          }
        }],
        "partialFingerprints": {
          "primaryLocationLineHash": "<deterministic-hash-from-ruleId+filePath+line>"
        }
      }
    ]
  }]
}
```

**Partial Fingerprints Best Practice:**
- Generate `primaryLocationLineHash` yourself from deterministic inputs: normalized rule ID + normalized file path + stable location anchor
- Do NOT rely on upload-time generation as primary dedup strategy

### 1.3 CodeQL Action Architecture (What We Actually Learned)

CodeQL does NOT use a composite action pattern for real work:
- Root `action.yml` is a stub that exits with "don't use directly"
- `init/action.yml` is a Node action (`runs.using: node24`)
- `analyze/action.yml` is a Node action
- `upload-sarif/action.yml` is a Node action

**Implication:** Don't overfit to "CodeQL uses composite actions." The useful precedent is CodeQL's **separation of concerns** (setup → analyze → upload), not the action type.

For Clearway Phase 10.5, a **composite action** is fine since we're wrapping a CLI invocation, not building multi-step orchestration.

### 1.4 What Other Scanners Do

**Semgrep:**
- `semgrep/semgrep-action` is **deprecated and archived**
- Current pattern: run `semgrep ci` directly in GitHub Actions, upload SARIF
- Reinforces CLI-first approach: scanner CLI is the product, action is convenience wrapper

**Trivy:**
- Runs scanner with `format: sarif`
- Writes SARIF file
- Uploads with CodeQL upload action
- Uses `if: always()` so SARIF is uploaded even when scanner exits non-zero
- Supports vulnerabilities, misconfigurations, secrets, licenses

**Checkov:**
- Populates `defaultConfiguration.level` and `properties.security-severity`
- Treats policies as rules with stable IDs
- Supports soft-fail and hard-fail behavior **separately from SARIF** (key pattern)

**Recommendation for Clearway docs: show both patterns:**
- Strict fail-fast workflow (exit non-zero → block PR)
- "Always upload SARIF" workflow for visibility (exit 0 always, SARIF shows findings)

### 1.5 Composite Action Structure for Clearway

```
clearway-action/
├── action.yml              # Action metadata, inputs, outputs
├── dist/
│   └── index.js            # Bundled JS (or call CLI directly)
└── README.md
```

**action.yml:**
```yaml
name: 'Clearway Privacy Compliance Scanner'
description: 'Scan for privacy compliance violations (AU Privacy Act, US CCPA, EU GDPR)'
inputs:
  jurisdiction:
    description: 'Jurisdiction pack(s) to scan (au-privacy-act, us-ccpa, eu-gdpr, all)'
    required: false
    default: 'all'
  severity-threshold:
    description: 'Minimum severity to fail the action (error, warning, note)'
    required: false
    default: 'error'
  sarif-output:
    description: 'Path to write SARIF output'
    required: false
    default: '${{ runner.temp }}/clearway-results.sarif'
  fail-on-violations:
    description: 'Whether to fail the action on violations above threshold'
    required: false
    default: 'true'
  config-path:
    description: 'Path to clearway config file'
    required: false
    default: ''
outputs:
  sarif-file:
    description: 'Path to the generated SARIF file'
  violation-count:
    description: 'Number of violations found'
  error-count:
    description: 'Number of error-level violations'
  warning-count:
    description: 'Number of warning-level violations'
runs:
  using: 'composite'
  steps:
    - ...
```

**Example Caller Workflows:**

Strict (blocks PR):
```yaml
name: Privacy Compliance
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  privacy-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Clearway
        id: clearway
        uses: clearway/clearway-action@v1
        with:
          jurisdiction: 'all'
          severity-threshold: 'error'
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.clearway.outputs.sarif-file }}
          category: clearway-privacy
```

Always-upload (visibility, no blocking):
```yaml
name: Privacy Compliance (Advisory)
on: [push, pull_request]

jobs:
  privacy-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Clearway
        id: clearway
        uses: clearway/clearway-action@v1
        with:
          jurisdiction: 'all'
          severity-threshold: 'note'
          fail-on-violations: 'false'
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.clearway.outputs.sarif-file }}
          category: clearway-privacy
```

Matrix (per-jurisdiction):
```yaml
jobs:
  privacy-scan:
    strategy:
      matrix:
        jurisdiction: [au-privacy-act, us-ccpa, eu-gdpr]
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: clearway/clearway-action@v1
        id: clearway
        with:
          jurisdiction: ${{ matrix.jurisdiction }}
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.clearway.outputs.sarif-file }}
          category: clearway-${{ matrix.jurisdiction }}
```

### 1.6 Compliance-Specific SARIF Taxonomies

⚠️ **There is no widely adopted privacy-compliance SARIF extension.** No equivalent of CWE for privacy law exists.

Best path — use three layers:
1. **Stable rule IDs** with jurisdiction namespace: `AU.APP.11.1.policy-accessible`, `GDPR.ART.13.privacy-notice`
2. **Tags** for filtering: `privacy`, `au-privacy-act`, `app-11`, `notice-and-transparency`
3. **Optional SARIF taxonomy objects** for future consumers

GitHub will mostly surface tags, descriptions, locations, levels, and fingerprints. For legal taxonomy depth, keep a **first-class Clearway-native JSON output** alongside SARIF for audit/reporting workflows.

Possible taxonomy alignment sources for future enterprise mapping:
- OWASP ASVS (overlapping technical/privacy controls)
- NIST control libraries
- Clearway's own jurisdiction/control hierarchy

---

## 2. MCP Server Distribution

### 2.1 Distribution Priority (Updated)

| Priority | Channel | Method | Status | Best For |
|----------|---------|--------|--------|----------|
| 1 | **npm** | `npm install -g @attestlens/cli` | Ship first | CLI users, `npx`, CI |
| 2 | **MCP Registry** | `server.json` + `mcpName` in package.json | Ship with npm | Official registry, discovery |
| 3 | **Smithery** | `npx @smithery/cli install` | After npm | Marketplace discovery |
| 4 | **MCPB** | Bundle for Claude Desktop | After demand | Desktop one-click install |
| 5 | **Docker** | `docker run attestlens/mcp` | Future | Remote/streamable HTTP |

### 2.2 npm Package Structure (Updated)

The original research proposed a large `mcp` block in `package.json`. That is **not** the current official pattern.

**Current MCP Registry pattern:**
- `package.json` should include `mcpName` for npm ownership verification
- Public MCP metadata belongs in `server.json` for the official MCP Registry
- Do NOT invent a private `package.json.mcp` schema

```json
{
  "name": "@attestlens/cli",
  "version": "0.4.0",
  "description": "Clearway — AI Compliance Scanner & Privacy Deploy Gate",
  "bin": {
    "attestlens": "./bin/cli.js",
    "attestlens-mcp": "./bin/mcp.js"
  },
  "mcpName": "io.github.attestlens/clearway",
  "keywords": ["mcp", "mcp-server", "model-context-protocol", "privacy", "compliance", "sarif", "clearway", "attestlens"]
}
```

### 2.3 Official MCP Registry (New — 2025-11-25+)

Since the MCP 2025-11-25 release, there is now an official MCP Registry in preview:
- **Metadata registry** (not artifact registry) — publishes `server.json`
- Artifacts can point to npm, PyPI, OCI, NuGet, or MCPB
- npm ownership verified via `mcpName` in `package.json`
- Registry is still in preview — breaking changes possible

**`server.json` for Clearway:**
```json
{
  "name": "io.github.attestlens/clearway",
  "version": "0.4.0",
  "description": "Clearway MCP server — Privacy compliance scanning for AI agents",
  "transport": "stdio",
  "tools": [
    { "name": "attestlens_scan", "description": "Scan a local project for privacy compliance violations" },
    { "name": "attestlens_scan_url", "description": "Scan a URL for privacy compliance violations" },
    { "name": "attestlens_audit", "description": "Audit a project's privacy compliance posture" },
    { "name": "attestlens_opinion", "description": "Generate a compliance opinion" },
    { "name": "attestlens_check", "description": "Check a single regulation principle" },
    { "name": "attestlens_compliance_check", "description": "Run SMB compliance questionnaire" },
    { "name": "attestlens_map", "description": "Map findings to regulation principles" },
    { "name": "attestlens_reform", "description": "Generate reform recommendations" }
  ],
  "repository": "https://github.com/vincent-peng/attestlens",
  "npmPackage": "@attestlens/cli"
}
```

### 2.4 Smithery's Current Role (Corrected)

Smithery is viable, but its role must be described precisely:
- Provides discovery, gateway distribution, analytics, and OAuth UI
- Docs emphasize **URL publishing** for Streamable HTTP servers
- For local stdio distribution, Smithery documents a path, but the platform center of gravity is **remote/gateway-backed**
- **Treat Smithery as a secondary discovery channel, NOT the canonical packaging model**

Add Smithery when you either:
- Ship a remote Streamable HTTP server, OR
- Want marketplace-style discovery and are willing to support its publishing/scanning flow

### 2.5 MCPB Current State (Updated)

MCPB was adopted into the MCP project in November 2025 (no longer Anthropic-only):
- `.mcpb` is now part of the MCP project
- Registry supports MCPB package entries with SHA-256 integrity
- **Production-ready for targeted local distribution, NOT as your only distribution channel**
- Client support varies — don't assume every MCP client can consume MCPB yet

### 2.6 Transport Guidance (Updated)

- **stdio**: recommended for local, process-spawned integrations (Clearway's default)
- **Streamable HTTP**: recommended for remote servers (future: hosted Clearway)
- **HTTP + SSE**: deprecated, retained for backward compatibility only

### 2.7 CLI Installer Pattern

The highest-adoption pattern (per Grizzly Peak research) is a one-command installer:
1. Detects installed MCP clients (Claude Desktop, Cline, Continue, etc.)
2. Auto-configures the client's MCP settings
3. Falls back to manual configuration instructions

```bash
npx @attestlens/cli install
# → Detects Claude Desktop, Cline, etc.
# → Adds MCP server config
# → Verifies connection

npx @attestlens/cli install --client claude-desktop
# → Configures specific client

npx @attestlens/cli uninstall
# → Removes MCP server config from all clients
```

---

## 3. Rule Authoring Pipeline (Phase 11)

### 3.1 The Semgrep Model: AI-Assisted, Human-Validated

**Semgrep's approach** (96% researcher agreement):
- AI proposes rules based on vulnerability patterns
- Human security researchers validate before rules ship
- "Pro Rules" are curated, tested, and versioned
- Community rules are separate (lower trust tier)
- Deterministic runtime executes validated rules (zero AI at scan time)
- `semgrep/semgrep-action` is **deprecated** — current pattern is CLI-first

**This is exactly our Phase 11 thesis: "AI writes rules, humans validate them, runtime is deterministic"**

### 3.2 Artifact Boundaries (Critical Design Decision)

Use **four distinct artifacts** — never execute draft rules in production CI:

```
legislation-source → draft-rule → validated-rule → released-pack
     (1)                (2)           (3)            (4)
```

1. **legislation-source**: canonical legal text, source URL, effective date, jurisdiction
2. **draft-rule**: LLM-produced proposal with rationale, citations, heuristics, explicit uncertainty notes
3. **validated-rule**: human-approved deterministic rule with final severity/confidence, test cases
4. **released-pack**: versioned immutable pack used by scanner runtime

### 3.3 Rule Schema (Extended with Provenance + Interpretation)

```typescript
interface AuthoredRule extends ScannerRule {
  id: string;                                    // e.g., "AU.APP.11.1.policy-accessible"
  name: string;
  description: string;
  severity: 'error' | 'warning' | 'note';

  source: {
    jurisdiction: Jurisdiction;
    citation: string;                            // "Privacy Act 1988 (Cth) Schedule 1, APP 11.1"
    legislationUrl: string;                      // Link to official source
    effectiveDate: string;                        // When this version of the law takes effect
  };

  authoring: {
    author: 'ai-draft' | 'human-validated' | 'community';
    confidence: 'high' | 'medium' | 'low';
    falsePositiveRisk: 'low' | 'medium' | 'high';
  };

  provenance: {
    draftedByModel?: string;                     // e.g., "gpt-5.5" — which model drafted
    draftedAt?: string;                           // ISO timestamp
    draftingPromptVersion?: string;              // Version of the drafting prompt
    sourceDocumentHash: string;                  // Hash of the legislation text used
    approvedBy?: string;                         // Reviewer identifier
    approvedAt?: string;                         // ISO timestamp
    packVersion?: string;                        // Pack version when released
  };

  interpretation: {
    machineCheckable: boolean;                   // Can this be deterministically checked?
    determinism: 'deterministic' | 'heuristic' | 'manual-only';
    reviewRequired: boolean;                     // Always true for ai-draft
  };

  tests: {
    positive: TestCase[];                        // Should trigger
    negative: TestCase[];                        // Should NOT trigger
    edgeCase: TestCase[];                        // Advisory findings
  };
}
```

### 3.4 Release Policy (Strict)

| Stage | Author | Confidence | Default Behavior | CI Action |
|-------|--------|-----------|-----------------|-----------|
| Draft | AI | Any | **Never ships as blocking** | Not included in scanner |
| Validated + deterministic | Human | High | Blocking | Fail the build |
| Validated + heuristic | Human | Medium | Advisory | Warning annotation |
| Manual-only obligation | Human | Low | Informational | Note annotation / coverage gap |

**AI-drafted rules NEVER ship as blocking.** This is non-negotiable for legal defensibility.

### 3.5 Confidence-Based Release Strategy

| Confidence | FP Risk | Default Behavior | CI Gate |
|-----------|---------|-----------------|---------|
| High | Low | Blocking | Fail build |
| Medium | Medium | Advisory | Warning annotation |
| Low | High | Informational | Note annotation |

Users can override via config:
```yaml
# clearway.config.yml
rules:
  AU.APP.11.1.policy-accessible:
    confidence: high
    override-severity: warning  # downgrade from error to warning
  GDPR.ART.13.privacy-notice:
    confidence: medium
    enabled: true
```

---

## 4. Security Model for CI/CD

### 4.1 MCP-specific Security

From MCP specification:
- stdio servers use environment-provided credentials (not HTTP auth)
- token passthrough is explicitly forbidden
- local servers execute with host privileges — security-sensitive
- remote servers should use least-privilege scopes and audience-bound tokens

### 4.2 CI-specific Security for Clearway

- **CI scanner path must be deterministic and offline** once installed
- **MCP server mode is for interactive use**, not required for CI scans
- Minimize `GITHUB_TOKEN` permissions (only `security-events: write` for SARIF upload)
- Never log prompt inputs that may include secrets or source excerpts
- Do not permit arbitrary outbound network access during deterministic scan execution
- Pin third-party actions by SHA, not just tag
- Use OIDC instead of long-lived cloud secrets where possible
- Do not expose secrets to workflows triggered from forks
- Keep "scan local repo" permissions narrower than "scan URL" permissions

---

## 5. Implementation Plan

### Phase 10.5: GitHub Action + MCP Distribution (1-2 days)

| Step | What | Priority |
|------|------|----------|
| 1 | **SARIF exporter** — Add `--format sarif` to CLI, generate valid SARIF v2.1.0 | Must |
| 2 | **CLI exit-threshold controls** — `--fail-on-severity` / `--severity-threshold` separate from SARIF level | Must |
| 3 | **GitHub composite action** — `clearway-action` repo, wraps CLI, outputs SARIF path + counts | Must |
| 4 | **npm package polish** — Add `mcpName` to package.json, verify bin entries | Must |
| 5 | **MCP Registry** — Create `server.json`, publish to official registry | Should |
| 6 | **CLI installer** — `attestlens install` for MCP client auto-config | Should |
| 7 | **CI integration guide** — Update docs with Action examples, SARIF patterns | Should |
| 8 | **Smithery listing** — Publish after npm publish | Could |
| 9 | **MCPB bundle** — After client demand justifies it | Later |

### Phase 11: Rule Authoring Pipeline (1-2 weeks)

| Step | What | Priority |
|------|------|----------|
| 1 | **AuthoredRule schema** — Extend ScannerRule with source, provenance, interpretation, tests | Must |
| 2 | **Deterministic test harness** — Fixture-based positive/negative/edge-case validation | Must |
| 3 | **AI drafting flow** — LLM prompt → proposed rule from legislation text | Must |
| 4 | **Human approval flow** — CLI command to review/approve/reject drafted rules | Must |
| 5 | **Versioned jurisdiction packs** — Semantic versioning for packs (v1.0.0-au-privacy-act) | Should |
| 6 | **Confidence + release gates** — High→blocking, Medium→advisory, Low→informational | Should |
| 7 | **Clearway-native JSON output** — Legal taxonomy depth beyond SARIF | Could |

---

## 6. Open Questions

1. **SARIF rule ID namespace** — Use `AU.APP.11.1.policy-accessible` format, or a flat `clearway/APP-11-1`?
2. **MCP auth for CI** — Should we support OAuth2 for remote deployments, or stay stdio-only for v1?
3. **Rule testing CI** — Separate GitHub Action for rule tests, or integrate into main CI?
4. **MCP Registry preview stability** — Registry is in preview; should we hold off on `server.json` until stable?
5. **MCPB timing** — Wait for broader client support, or invest now?
6. **AI-drafted default confidence** — Should all AI-drafted rules start at `low` confidence, requiring human validation to promote?

---

## 7. Sources

- GitHub CodeQL Action: https://github.com/github/codeql-action
- GitHub SARIF support: https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning
- GitHub SARIF upload: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
- Semgrep docs: https://semgrep.dev/docs/ (semgrep-action deprecated)
- Trivy SARIF: https://trivy.dev/docs/latest/configuration/reporting/
- Checkov SARIF: https://www.checkov.io/8.Outputs/SARIF.html
- Snyk Actions: https://github.com/snyk/actions
- MCP Specification (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic
- MCP Transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- MCP Registry: https://modelcontextprotocol.io/registry/about
- MCPB adoption: https://blog.modelcontextprotocol.io/posts/2025-11-20-adopting-mcpb/
- Smithery docs: https://smithery.ai/docs/build/publish
- Grizzly Peak MCP distribution guide: https://www.grizzlypeaksoftware.com/library/mcp-server-marketplace-publishing-and-distribution-4rlxx8j5
- GitHub Actions security: https://docs.github.com/en/actions/reference/security/secure-use