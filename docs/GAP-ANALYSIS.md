# Gap Analysis — Clearway (2026-05-01)

Deep audit of the codebase, debate findings, and product strategy to identify
risks, missing pieces, and things we might have overlooked.

---

## 🔴 Critical Gaps

### 1. `attestlens check` is AU-only for principle validation

The MCP `check` tool uses `validatePrinciple()` which validates against `APPInfo`
keys for AU, and hardcoded regex for CCPA/GDPR. The Phase 10-lite plan adds
`PrincipleRegistry` but the `check` tool needs to use it for jurisdiction-aware
validation. Currently, calling `check` with `--jurisdiction us-ccpa` and a
CCPA principle works, but the validation path is inconsistent — AU uses `APPInfo`,
CCPA uses regex, GDPR uses `GDPRPrincipleInfo`. No single validation function.

**Impact:** MCP consumers (agents) calling `check` with different jurisdictions
get inconsistent error messages and validation behavior.

**Fix:** Add `validateRegulationPrinciple(jurisdiction, principle)` that uses
`PrincipleRegistry` in Phase 10-lite.

### 2. `attestlens compliance_check` and `attestlens reform` are AU-only

- `compliance_check` (SMB tool) hard-fails for non-AU jurisdictions:
  `"SMB compliance check is currently AU-only"`
- `reform` (Privacy Act 2026 reform assessment) is inherently AU-only

These are **8 → 6 multi-jurisdiction tools**. Phase 10-lite doesn't address this.
But more importantly: the YC demo and the "deploy gate" story don't need these
tools to be multi-jurisdiction. The core workflow (scan → map → opinion → check)
already works for all 3 jurisdictions.

**Impact:** Low for YC. High for product completeness post-launch.

**Decision:** Leave these as AU-only for now. Add `--jurisdiction` support
later. Document the limitation in MCP tool descriptions.

### 3. `Question.appPrinciple` field name is misleading

The field is **named** `appPrinciple` but **typed** as `RegulationPrinciple`
(which is `z.string()`). This means CCPA/GDPR questions store CCPA_100, GDPR_Art3
etc. in a field called `appPrinciple`. It works at runtime but is confusing and
will trip up anyone reading the code or building on the API.

**Impact:** Code readability and Phase 11 rule-authoring pipeline. When AI
generates questions, it needs to know which field to populate.

**Fix:** Phase 10-lite adds `regulationPrinciple` as a parallel field. CCPA/GDPR
questions should populate `regulationPrinciple` instead of `appPrinciple`.
`appPrinciple` becomes AU-only backward compat.

### 4. URL scan has NO jurisdiction awareness

`UrlScanAdapter` doesn't accept or use a jurisdiction parameter. The MCP tool
`scan_url` DOES accept `--jurisdiction` and creates an orchestrator with it,
but the URL scan itself doesn't filter findings by jurisdiction — it just
checks HTTP headers (CSP, HSTS, etc.) which are jurisdiction-agnostic.

**Impact:** Medium. URL scan findings are always jurisdiction-agnostic (headers
apply to all privacy laws), so this works in practice. But the report should
still map them to the correct jurisdiction's controls.

**Fix:** URL scan findings need `regulationMappings` populated by the mapping
engine based on the selected jurisdiction. This should work automatically
after Phase 10-lite.

---

## 🟡 Strategic Gaps (from Debate)

### 5. No design partner yet

All 3 debate agents flagged this. Clearway has no external user, pilot, or
design partner. The YC story is much stronger with even one company running
Clearway in CI.

**Impact:** High for YC credibility. "Consulting in a CLI" objection is harder
to preempt without external proof.

**Action:** Start design partner outreach immediately. Target: AU tech companies
shipping AI features that touch customer data. Use the July 1 deadline as urgency.

### 6. No CI/CD integration

Clearway is a CLI tool and MCP server. There's no GitHub Action, no CI
integration, no `pre-commit` hook. The "deploy gate" story requires being
in the CI pipeline.

**Impact:** Critical for the pitch. "The deploy gate for AI privacy risk"
doesn't work if you can't actually gate a deploy.

**Action:** Add a GitHub Action (`.github/workflows/attestlens.yml`) that
runs `attestlens audit` on PRs and fails on high-severity findings.
This is the YC demo artifact.

### 7. No GitHub Actions workflows at all

The repo has `.github/` with no workflow files. No CI, no automated testing,
no release automation.

**Impact:** Medium for product, high for YC perception. YC expects CI/CD.

**Action:** Add at minimum: test workflow (run vitest on push), lint workflow,
and the attestlens scan workflow.

### 8. Version string in URL scan user agent is stale

`AttestLens/0.2.0` in the URL scan user agent. Should be dynamic (reads from
package.json like the CLI version fix).

**Impact:** Low, but looks amateurish in server logs.

**Fix:** Quick one-liner. Import `ATTESTLENS_VERSION` or read from package.json.

### 9. `appMappings` is required, `regulationMappings` is optional

In the finding schema:
```typescript
appMappings: z.array(APPMapping),           // required
regulationMappings: z.array(RegulationMapping).optional(), // optional
```

This means every finding MUST have `appMappings` but regulation mappings are
optional. Phase 10-lite wants to flip this priority — `regulationMappings`
should become the primary, `appMappings` should become optional/deprecated.

**Impact:** Medium. If we don't flip the required status, downstream consumers
will keep relying on `appMappings` as the canonical field.

**Fix:** Phase 10-lite Step 3 should make `appMappings` optional and
`regulationMappings` required (with a default empty array for backward compat).

### 10. No false-positive severity classification

The debate identified false-positive economics as critical for CI gate adoption.
Currently, findings have `severity` (critical/high/medium/low) but no
`confidence` or `falsePositiveRisk` field. There's no way to distinguish
"definitely a violation" from "probably worth reviewing" from "might be noise".

**Impact:** High for the "deploy gate" story. You can't gate deploys on findings
that include low-confidence noise.

**Action:** Add `confidence` field to findings (high/medium/low). Phase 10-lite
or Phase 11. High-confidence findings = release-blocking. Low-confidence = advisory.

---

## 🟡 Product Gaps

### 11. No `--format agent` + jurisdiction combination test

The `--format agent` output was tested for AU but not verified to work correctly
with `--jurisdiction us-ccpa` or `--jurisdiction eu-gdpr`. The agent format
might reference APP principles in its output even when scanning CCPA/GDPR.

**Impact:** Medium. Agents consuming `--format agent` output need jurisdiction-
aware principle references.

**Action:** Test `attestlens audit --jurisdiction us-ccpa -f agent` and verify
output references CCPA principles, not APP principles.

### 12. MCP tool descriptions still say "APP/NDB" in places

- `scan_url` description: "Scan a public URL for live-site APP/NDB compliance findings"
- `compliance_check` description: "Run a plain-English compliance check for Australian businesses"
- `reform` description: "Run a Privacy Act 2026 reform impact assessment"

These are accurate for AU-only tools but misleading for multi-jurisdiction tools
that accept `--jurisdiction`.

**Impact:** Medium. Agents using the MCP server will be confused by AU-specific
descriptions on tools that support multiple jurisdictions.

**Action:** Update tool descriptions to be jurisdiction-agnostic where
applicable. Add `(jurisdiction-specific)` tag to AU-only tools.

### 13. No packaged binary distribution

Clearway is `npm install -g @attestlens/cli`. For CI/CD adoption, a standalone
binary (via `pkg` or `nexe` or Deno compile) would eliminate the Node.js
dependency for non-JS teams.

**Impact:** Medium for adoption. Many security/DevOps teams don't want to
install Node.js just for a compliance tool.

**Action:** Consider adding a `dist-bin` target or shipping via Docker.

### 14. No Docker image

Related to #13. A Docker image would make CI integration trivial:
`docker run attestlens/cli audit /project`. Also useful for MCP server deployment.

**Impact:** Medium for CI adoption story.

**Action:** Add `Dockerfile` and publish to Docker Hub or GitHub Container Registry.

---

## 🟡 Documentation Gaps

### 15. No CI/CD integration guide

`docs/CI-INTEGRATION.md` exists but may be stale after Phase 8. Verify it
covers all 3 jurisdictions and the new MCP tools.

**Impact:** Low for code, medium for adoption story.

### 16. No architecture decision records (ADRs)

Major decisions (jurisdiction packs, opinion engine, Phase 10-lite vs full
decoupling) have no ADRs. Future contributors (or YC diligence) will need
to understand WHY decisions were made.

**Impact:** Low short-term, medium long-term.

**Action:** Add `docs/adr/` directory for key decisions.

### 17. No API stability guarantees

MCP tool signatures, CLI flags, and JSON output schemas have no versioning
or stability guarantees. Breaking changes in Phase 10-lite (adding fields)
are backward-compatible, but future breaking changes need a versioning strategy.

**Impact:** Medium for MCP consumers (AI agents) who rely on stable schemas.

**Action:** Document API stability policy. Consider adding `apiVersion` field
to MCP responses.

---

## 🟢 Already Handled (No Gap)

- ✅ DNS rebinding protection (`ATTESTLENS_URL_SCAN_DNS_PIN`)
- ✅ TOCTOU revalidation (`revalidatePathBeforeScan`)
- ✅ Symlink blocking in path validation
- ✅ MCP tool annotations (readOnlyHint, openWorldHint, title)
- ✅ `isError` on all MCP error responses
- ✅ MCP SDK bumped to `^1.29.0`
- ✅ Version reads from package.json dynamically
- ✅ 504 tests passing
- ✅ TypeScript strict mode
- ✅ License (MIT)
- ✅ CHANGELOG.md
- ✅ `files` whitelist in package.json

---

## Priority Actions (Ordered)

1. **CI/CD GitHub Action** — The "deploy gate" story needs an actual gate
2. **Add `confidence` field to findings** — Required for severity-based blocking
3. **Phase 10-lite** — Already scoped, ready to execute
4. **Design partner outreach** — Start parallel with Phase 10-lite
5. **MCP tool description updates** — Quick fix, high impact for MCP consumers
6. **Flip `appMappings`/`regulationMappings` required status** — Part of Phase 10-lite
7. **Test `--format agent` with non-AU jurisdictions** — Quick verification
8. **URL scan user agent version** — One-liner fix
9. **Docker image** — For CI adoption story
10. **ADR directory** — For future contributors and YC diligence