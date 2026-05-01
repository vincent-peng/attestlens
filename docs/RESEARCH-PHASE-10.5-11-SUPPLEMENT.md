# Supplementary Research: Phase 10.5 and Phase 11

**Date:** 2026-05-01  
**Scope:** Validation and supplementation of `RESEARCH-PHASE-10.5-11.md`

## Executive Summary

The original research is directionally strong, but several implementation details are stale or incomplete:

- `github/codeql-action/upload-sarif` is now `@v4`, not `@v3`.
- CodeQL’s real actions are not modeled the way the draft implies. The top-level `action.yml` is a stub composite action; the operational actions (`init`, `analyze`, `upload-sarif`) are Node actions.
- GitHub Code Scanning does **not** block pull requests based on SARIF `level` alone. Blocking requires your workflow exit code and branch protection configuration.
- GitHub severity presentation uses more than `result.level`. For ranking and default display, GitHub also uses `properties.problem.severity`, `properties.security-severity`, and `properties.precision`.
- The MCP distribution ecosystem changed materially after the 2025-11-25 MCP release. There is now an **official MCP Registry** in preview with `server.json` metadata and package verification flows. That should be treated as first-class, not only npm/Smithery.
- Smithery is viable, but its current primary publishing path is strongly oriented around **Streamable HTTP** and gateway distribution. It is no longer safe to treat Smithery as the canonical answer for local stdio distribution.
- MCPB is no longer just an Anthropic-specific experiment. It was adopted into the MCP project in November 2025, but client support is still the gating factor.
- There is no widely adopted “compliance SARIF extension” for privacy law. The standards-compliant path is to use SARIF taxonomies and tags, knowing GitHub UI support is limited to a documented subset of fields.

## 1. Corrections to the Original Research

### 1.1 GitHub Action versioning

The draft uses `github/codeql-action/upload-sarif@v3`. Current GitHub documentation uses `@v4` for upload examples. New examples should use:

```yaml
- uses: github/codeql-action/upload-sarif@v4
```

This is not cosmetic. The CodeQL Action repository currently lists `v4` as latest and `v3` as older-but-supported.

### 1.2 “CodeQL composite action” claim

The draft asks how CodeQL structures its composite action. The important finding is: **it mostly does not**.

- The repository root `action.yml` is a stub composite action that exits with an instruction not to use it directly.
- `init/action.yml` is a Node action (`runs.using: node24`, `main: ../lib/init-action.js`, `post: ../lib/init-action-post.js`).
- `upload-sarif/action.yml` is also a Node action (`runs.using: node24`, `main: ../lib/upload-sarif-action.js`, `post: ../lib/upload-sarif-action-post.js`).

Implication for Clearway:

- Do not overfit to “CodeQL uses a composite action” as an architectural precedent.
- If Clearway wants a lightweight user-facing wrapper, a composite action is still reasonable.
- If Clearway needs richer logic, post-processing, dedup helpers, or multi-step orchestration, a JavaScript action may be the cleaner long-term shape.

### 1.3 Severity mapping and blocking behavior

The draft compresses three separate concerns into one:

1. SARIF `result.level`
2. GitHub Code Scanning severity display/ranking
3. CI blocking behavior

They are related, but not the same.

What GitHub actually uses:

- `result.level` or `reportingDescriptor.defaultConfiguration.level` for result severity (`error`, `warning`, `note`)
- `properties.problem.severity` for non-security ranking (`error`, `warning`, `recommendation`)
- `properties.security-severity` for security scoring (`0.1` to `10.0`)
- `properties.precision` for ranking (`very-high`, `high`, `medium`, `low`)

What this means:

- `error` does **not** automatically mean “PR blocked.”
- `warning` does **not** automatically mean “advisory only.”
- `note` does **not** automatically mean “informational only.”
- Pull request blocking comes from the workflow failing and branch protection requiring that check to pass.

Recommendation:

- Keep SARIF levels for UI semantics.
- Independently implement `--fail-on-severity` or `--severity-threshold` in the Clearway CLI/action to determine exit code.
- Document that SARIF severity and action failure threshold are intentionally separate knobs.

### 1.4 Partial fingerprints

The original note is broadly correct but should be sharpened:

- GitHub Code Scanning only uses `partialFingerprints.primaryLocationLineHash`.
- If missing, `upload-sarif` can generate partial fingerprints, but only when it can inspect both the SARIF and the source tree.

Recommendation:

- Generate `primaryLocationLineHash` yourself from deterministic inputs:
  - normalized rule ID
  - normalized file path
  - stable location anchor
  - optionally a stable semantic snippet hash
- Do not rely on upload-time generation as your primary dedup strategy.

### 1.5 Semgrep action status

The original document references “standard pattern” via Semgrep, but the current situation is:

- `semgrep/semgrep-action` is deprecated and archived.
- Current Semgrep guidance is to run `semgrep ci` directly in GitHub Actions, often in a Semgrep container, then upload SARIF with `github/codeql-action/upload-sarif`.

Implication:

- The modern pattern is increasingly “CLI-first, thin workflow wrapper,” not necessarily “publish and maintain a bespoke GitHub Action.”
- That supports a Clearway design where the CLI is the product and the action is a convenience wrapper, not the main integration surface.

### 1.6 MCP metadata in `package.json`

The draft proposes a large `mcp` block in `package.json`. That is not aligned with current official MCP Registry publication.

Current official registry pattern:

- `package.json` should include `mcpName` for npm ownership verification.
- Public MCP metadata belongs in `server.json` for the official MCP Registry.

Example direction:

```json
{
  "name": "@attestlens/cli",
  "version": "0.4.0",
  "mcpName": "io.github.attestlens/clearway"
}
```

Implication:

- Do not invent a private `package.json.mcp` schema and expect ecosystem interoperability.
- Use `server.json` for registry metadata.
- Use your own runtime manifest only if needed internally.

## 2. Deep Dive: CodeQL Action Structure

### 2.1 What the upstream repository actually does

From `github/codeql-action`:

- Root `action.yml`: stub composite action that exits immediately
- `init/action.yml`: Node action
- `analyze/action.yml`: Node action
- `upload-sarif/action.yml`: Node action
- `autobuild/action.yml`: separate action for build automation

### 2.2 What matters architecturally

CodeQL splits responsibilities across distinct actions:

- environment/tool setup
- analysis execution
- SARIF upload

This is the useful precedent for Clearway, not “composite vs JS” alone.

Recommendation for Clearway:

Option A: one convenience action

- installs/runs Clearway
- writes SARIF
- optionally fails by threshold
- leaves SARIF upload to caller

Option B: two-action split

- `setup-clearway`
- `scan-clearway`

Option A is probably enough for Phase 10.5 unless install cost or auth setup becomes non-trivial.

## 3. Deep Dive: GitHub Code Scanning SARIF Semantics

### 3.1 Supported SARIF fields that matter most for Clearway

GitHub’s documented supported subset makes these the most valuable fields:

- `tool.driver.rules[].id`
- `tool.driver.rules[].name`
- `tool.driver.rules[].shortDescription.text`
- `tool.driver.rules[].fullDescription.text`
- `tool.driver.rules[].help.markdown`
- `tool.driver.rules[].properties.tags[]`
- `tool.driver.rules[].properties.precision`
- `tool.driver.rules[].properties.problem.severity`
- `tool.driver.rules[].properties.security-severity` when using security semantics
- `results[].ruleId`
- `results[].level`
- `results[].message.text`
- `results[].locations[]`
- `results[].partialFingerprints.primaryLocationLineHash`

### 3.2 Best mapping for a compliance scanner

For Clearway, most findings are better modeled as **non-security** unless a rule clearly belongs in application security or secret exposure.

Recommended mapping:

- `defaultConfiguration.level`
  - blocking/high-confidence rule: `error`
  - advisory rule: `warning`
  - low-confidence or informational rule: `note`
- `properties.problem.severity`
  - legal/regulatory material breach: `error`
  - medium operational risk: `warning`
  - improvement/recommendation: `recommendation`
- `properties.precision`
  - human-validated deterministic checks: `high` or `very-high`
  - heuristic checks: `medium`
  - broad text heuristics: `low`

Avoid setting `properties.security-severity` unless a finding is genuinely a security finding. Overusing it will misclassify the product in GitHub’s security UI.

### 3.3 Upload categories

The draft is right that category separation matters. The current GitHub docs are explicit:

- multiple uploads for the same commit need unique categories
- CodeQL’s own analyze action auto-derives category from workflow name and matrix vars

Recommendation:

- always set category explicitly for Clearway uploads
- use a stable pattern such as:
  - `clearway/au-privacy-act`
  - `clearway/us-ccpa`
  - `clearway/eu-gdpr`
  - `clearway/all`

## 4. Deep Dive: Semgrep, Trivy, and Checkov Patterns

### 4.1 Semgrep

Current Semgrep guidance is effectively:

1. checkout
2. run `semgrep ci`
3. emit SARIF
4. upload SARIF via `github/codeql-action/upload-sarif`

This is important because it reinforces a strong pattern for Clearway:

- the scanner CLI should be the stable interface
- the GitHub Action should mostly orchestrate installation, invocation, and outputs

### 4.2 Trivy

Trivy supports SARIF output directly for:

- vulnerabilities
- misconfigurations
- secrets
- licenses

The Trivy action pattern is:

- run scanner with `format: sarif`
- write SARIF file
- upload with CodeQL upload action
- optionally use `if: always()` so SARIF is uploaded even when scanner exits non-zero

This is a useful precedent for Clearway.

Recommendation:

- in Clearway docs, show both patterns:
  - strict fail-fast workflow
  - “always upload SARIF” workflow for visibility

### 4.3 Checkov

Checkov’s SARIF output is notable for:

- populating `defaultConfiguration.level`
- populating `properties.security-severity`
- treating policies as rules with stable IDs
- supporting soft-fail and hard-fail behavior separately from SARIF

The key design lesson is good:

- output semantics and process exit semantics should remain separate

## 5. MCP Distribution: Current Official Best Practices

### 5.1 Official MCP Registry now matters

Since the 2025-11-25 MCP release, the ecosystem has an official MCP Registry in preview.

Important facts:

- It is a metadata registry, not an artifact registry.
- You publish metadata in `server.json`.
- Underlying artifacts can point to npm, PyPI, OCI, NuGet, or MCPB.
- npm ownership verification is based on `mcpName` in `package.json`.
- The registry is still in preview, so breaking changes or resets are explicitly possible.

Recommendation:

For public distribution, prioritize:

1. npm package
2. official MCP Registry metadata (`server.json`)
3. optional Smithery listing
4. optional MCPB artifact

This is a stronger 2026 distribution story than “npm + Smithery” alone.

### 5.2 Transport guidance changed

From the current MCP docs / SDK guidance:

- **stdio**: recommended for local, process-spawned integrations
- **Streamable HTTP**: recommended for remote servers
- **HTTP + SSE**: deprecated, retained for backward compatibility

Implication:

- For Clearway local developer tooling, stdio is still the right base transport.
- For a future hosted compliance server, use Streamable HTTP, not SSE.

### 5.3 Local package distribution

For an npm-distributed stdio server, the official-first pattern is:

- publish npm artifact
- include `mcpName` in `package.json`
- publish `server.json` to MCP Registry
- expose execution instructions through registry metadata

This is more interoperable than relying on a custom installer alone.

### 5.4 Smithery’s current role

Smithery is viable, but its role should be described precisely:

- It provides discovery, gateway distribution, analytics, and OAuth UI.
- Its docs emphasize **URL publishing** for public Streamable HTTP servers.
- For local distribution, Smithery documents a stdio/MCPB path, but the platform center of gravity is currently remote/gateway-backed distribution.

Practical recommendation:

- Treat Smithery as a secondary discovery channel, not the canonical packaging model.
- If Clearway is initially stdio-only and local-first, npm + official MCP Registry is the cleaner default.
- Add Smithery when you either:
  - ship a remote Streamable HTTP server, or
  - want marketplace-style discovery and are willing to support its publishing/scanning flow.

## 6. MCPB: Current State

### 6.1 What changed

MCPB was adopted into the MCP project in November 2025. It is no longer only an Anthropic-side format.

Officially supported facts:

- `.mcpb` is now part of the MCP project
- it packages local MCP servers as installable bundles
- the official MCP Registry supports MCPB package entries
- registry metadata for MCPB includes a SHA-256 integrity field
- clients validate the hash before installation

### 6.2 Is it production-ready?

My assessment: **yes for targeted local distribution, no as your only distribution channel**.

Why:

- The format is official and supported by the registry model.
- The remaining risk is ecosystem support variance across clients.
- Official MCP documentation still says the registry itself is preview, and SDK/client adoption continues at different speeds.

Recommendation:

- Do not block Phase 10.5 on MCPB.
- Ship npm + stdio first.
- Add MCPB when you want one-click local install for supported clients.
- Do not assume every MCP client your users care about can consume MCPB yet.

## 7. Compliance-Specific SARIF Taxonomies and Extensions

### 7.1 There is no dominant privacy-compliance SARIF extension

I did not find a broadly adopted privacy-law-specific SARIF extension comparable to CWE for vulnerabilities.

What SARIF itself supports:

- standard or custom taxonomies via `run.taxonomies`
- relationships between rules and taxa

What GitHub Code Scanning supports in practice:

- a documented subset of SARIF properties
- not a rich UI model for arbitrary compliance taxonomies

### 7.2 Best path for Clearway

Use three layers:

1. Stable rule IDs
   - `AU.APP.11.1.policy-accessible`
   - `GDPR.ART.13.privacy-notice`
2. Tags
   - `privacy`
   - `au-privacy-act`
   - `app-11`
   - `notice-and-transparency`
3. Optional SARIF taxonomy objects
   - custom privacy/control taxonomy for future consumers

Recommendation:

- Build internal richness into SARIF now, but assume GitHub will mostly surface tags, descriptions, locations, levels, and fingerprints.
- Keep a first-class Clearway-native JSON output for audit/reporting workflows where legal taxonomy matters more than GitHub UI.

Possible taxonomy sources to align with:

- your own jurisdiction/control hierarchy
- OWASP ASVS for overlapping technical/privacy controls
- NIST or internal control libraries if enterprise mapping becomes important later

## 8. Security Considerations for MCP Servers in CI/CD

### 8.1 MCP-specific considerations

From the MCP specification and security guidance:

- stdio servers should use environment-provided credentials rather than the HTTP authorization flow
- HTTP auth is for HTTP transports, not stdio
- token passthrough is explicitly forbidden
- remote servers should use least-privilege scopes and audience-bound tokens
- local servers are security-sensitive because they execute with host privileges

### 8.2 CI-specific considerations for Clearway

If Clearway runs as an MCP server or CLI inside GitHub Actions:

- minimize `GITHUB_TOKEN` permissions
- avoid passing secrets unless the scan truly needs them
- never log prompt inputs that may include secrets or source excerpts
- do not permit arbitrary outbound network access during deterministic scan execution if avoidable
- if LLM-assisted rule drafting exists, keep that out of the runtime scan path
- do not run privileged or unpinned third-party install scripts in the action
- pin third-party actions by version or SHA according to org policy
- use OIDC instead of long-lived cloud secrets where cloud access is necessary
- do not expose secrets to workflows triggered from forks

### 8.3 Runtime model recommendation

For Phase 10.5:

- CI scanner path should be deterministic and preferably offline once installed
- MCP server mode should be for interactive use, not required for CI scans
- keep “scan local repo” permissions narrower than “scan URL” permissions if both exist

This is important because an MCP server surface can tempt scope creep. The CI action should invoke the narrowest execution path possible.

## 9. Rule Authoring Pipeline: Additional Design Guidance

The original Phase 11 direction is sound. The main missing piece is a stronger separation between:

- authoring-time AI
- review-time governance
- runtime execution

### 9.1 Recommended artifact boundaries

Use distinct artifacts:

1. `legislation-source`
   - canonical legal text
   - source URL
   - effective date
   - jurisdiction metadata
2. `draft-rule`
   - LLM-produced proposal
   - rationale
   - extracted citations
   - proposed heuristics
   - explicit uncertainty notes
3. `validated-rule`
   - human-approved deterministic rule
   - final severity/confidence
   - test cases
4. `released-pack`
   - versioned immutable pack used by scanner runtime

### 9.2 Keep the AI output non-authoritative

The rule draft should never be executed directly in production CI.

Promotion path should require:

- human sign-off
- passing deterministic tests
- fixture-based regression tests
- explicit versioning

### 9.3 Add provenance fields

The proposed schema should add immutable provenance:

```ts
provenance: {
  draftedByModel?: string;
  draftedAt?: string;
  draftingPromptVersion?: string;
  sourceDocumentHash: string;
  approvedBy?: string;
  approvedAt?: string;
  packVersion?: string;
}
```

This matters for auditability and legal defensibility.

### 9.4 Add “interpretation status”

Not every legal obligation is machine-checkable.

Add an explicit field such as:

```ts
interpretation: {
  machineCheckable: boolean;
  determinism: 'deterministic' | 'heuristic' | 'manual-only';
  reviewRequired: boolean;
}
```

This prevents pressure to fake precision for requirements that are inherently contextual.

### 9.5 Release policy recommendation

Default release policy:

- AI-drafted: never ships as blocking
- Human-validated + deterministic + low FP risk: can ship as blocking
- Human-validated but heuristic: advisory by default
- Manual-only legal obligations: keep out of scanner or emit informational “coverage gap” findings

## 10. Recommended Changes to the Build Plan

### 10.1 Phase 10.5

Recommended order:

1. Add stable Clearway SARIF exporter
2. Add CLI exit-threshold controls separate from SARIF severity
3. Ship GitHub Action wrapper
4. Publish npm package with `mcpName`
5. Publish official MCP Registry `server.json`
6. Add Smithery if useful
7. Add MCPB only after client demand justifies it

### 10.2 Phase 11

Recommended order:

1. Define authored rule schema with provenance and determinism fields
2. Build deterministic fixture-based test harness
3. Build AI drafting flow
4. Build human approval flow
5. Version jurisdiction packs
6. Add confidence and release gates

## 11. Gaps, Risks, and Outdated Assumptions in the Original Document

### High-priority gaps

- No mention of the official MCP Registry and `server.json`
- No distinction between SARIF severity and workflow failure semantics
- No mention that `upload-sarif@v4` is current
- No mention that Semgrep’s old wrapper action is deprecated
- No explicit security model for CI-time MCP execution
- No provenance model for AI-authored rules

### Medium-priority gaps

- Overstates Smithery as the default registry answer
- Overstates MCPB maturity as if client support were universal
- Does not address when a legal requirement should be marked non-machine-checkable
- Does not recommend a Clearway-native output format alongside SARIF

### Specific assumptions to correct

- “CodeQL composite action” should be replaced with “CodeQL splits behavior across multiple dedicated actions, mostly implemented as Node actions.”
- “error = blocking” should be replaced with “blocking depends on workflow exit status and branch protection; SARIF severity affects presentation.”
- `package.json.mcp` should be replaced or demoted in favor of official MCP Registry metadata.

## Sources

- GitHub CodeQL Action repository: https://github.com/github/codeql-action
- `upload-sarif` action definition: https://github.com/github/codeql-action/blob/main/upload-sarif/action.yml
- `init` action definition: https://github.com/github/codeql-action/blob/main/init/action.yml
- GitHub SARIF support docs: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- GitHub SARIF upload docs: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
- Semgrep docs: https://semgrep.dev/docs/
- Semgrep GHAS upload example: https://semgrep.dev/docs/kb/semgrep-ci/upload-ci-findings-to-github
- Deprecated Semgrep Action repo: https://github.com/semgrep/semgrep-action
- Trivy reporting docs: https://trivy.dev/docs/latest/configuration/reporting/ and https://trivy.dev/docs/latest/target/repository/
- Trivy GitHub Action: https://github.com/aquasecurity/trivy-action
- Checkov SARIF docs: https://www.checkov.io/8.Outputs/SARIF.html
- MCP specification overview (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic
- MCP transports guidance: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP authorization guidance: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- MCP Registry overview: https://modelcontextprotocol.io/registry/about
- MCP Registry package types: https://modelcontextprotocol.io/registry/package-types
- MCP Registry quickstart: https://modelcontextprotocol.io/registry/quickstart
- MCP Registry versioning: https://modelcontextprotocol.io/registry/versioning
- MCPB adoption post: https://blog.modelcontextprotocol.io/posts/2025-11-20-adopting-mcpb/
- MCPB repository: https://github.com/modelcontextprotocol/mcpb
- GitHub Actions security hardening: https://docs.github.com/en/actions/reference/security/secure-use
- GitHub secrets guidance: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
