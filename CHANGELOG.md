# Changelog

## 0.4.0-beta (2026-05-01)

### Phase 11: Rule Authoring Pipeline

- Added the AuthoredRule schema and authored-pack review flow
- Added AI-assisted rule drafting via `propose-rules`
- Added human approval and pack promotion via `review-pack`
- Added authored-rule test harness coverage and scanner integration
- Added confidence gates so drafted rules never ship as blocking by default
- Added SG PDPA demo coverage for the authoring workflow

### Phase 10.5: SARIF, Installers, and npm Polish

- Added SARIF exporter support for CLI audit and scan flows
- Added exit-threshold controls for CI gating
- Added CLI installer and uninstaller commands for supported MCP clients
- Added `mcp` subcommand for stdio server launch
- Rebuilt the publish artifact from current source and aligned CLI help with shipped commands
- Hardened npm package metadata for first public beta release

### Phase 10-lite: Schema Decoupling

- Added PrincipleRegistry for jurisdiction-aware principle lookup
- Added SG PDPA jurisdiction pack support without changing APPPrinciple
- Proved zero APPPrinciple schema churn while expanding multi-jurisdiction coverage
- Kept multi-jurisdiction report generation aligned across AU, US, EU, and SG surfaces

### Phase 9: YC App Prep

- Added the multi-jurisdiction demo flow for YC and design-partner conversations
- Rewrote the README and supporting public docs around the deploy-gate positioning
- Added YC application support docs and product thesis material

### Security and Release Hardening

- Included all prior MCP hardening and security review fixes in the beta release line
- Preserved DNS pinning, TOCTOU revalidation, opaque MCP resources, and sanitized scanner errors
- Excluded compiled test artifacts from the published build output
- Aligned runtime version reads to `package.json` so CLI, MCP, reports, and scanners ship the same version metadata

## 0.3.0 (2026-04-30)

### Phase 8: EU GDPR Subset Pack

- 14 GDPR principles (GDPR_Art3 through GDPR_Art44)
- 9 GDPR mapping rules (MAP-GDPR-001 through MAP-GDPR-009)
- 6 GDPR scanner rules (GDPR-CONSENT-001, GDPR-PRIVACY-001, GDPR-TRANSFER-001, GDPR-DPIA-001, GDPR-ART22-001, GDPR-SEC-001)
- 17 GDPR questionnaire questions (4 applicability gates)
- Embedded GDPR jurisdiction pack
- Multi-jurisdiction report generator (AU + US + EU sections)
- Special-category value redaction in scanner findings
- Advisory findings preserve questionnaire routing

### Phase 7: US CCPA/CPRA Pack

- 12 CCPA/CPRA principles (CCPA_100 through CCPA_150)
- 9 CCPA mapping rules
- 6 CCPA scanner rules (DNS, privacy policy, GPC, sensitive PI, security)
- 11 CCPA questionnaire questions (including applicability gates)
- Embedded CCPA jurisdiction pack

### Phase 6: Jurisdiction Abstraction

- Jurisdiction, RegulationPrinciple, RegulationMapping schemas
- JurisdictionPackManifest v2
- --jurisdiction flag on all CLI commands and MCP tools
- Multi-jurisdiction report framework
- Fail-closed jurisdiction pack loading
- Backward-compatible AU-only defaults preserved

### Phase 5A: MCP Protocol Hardening

- McpServer migration with Zod input/output schemas
- Structured content on all 8 tool responses
- Fail-closed filesystem validation
- Symlink escape blocking
- DNS rebinding protection (ATTESTLENS_URL_SCAN_DNS_PIN)
- TOCTOU path revalidation
- Opaque attestlens://root/<id> resource URIs
- Error sanitization in MCP responses
- AbortSignal cancellation support
- Contract tests for annotations, isError, structuredContent

### Phase 5A: Security Audit Fixes

- Removed gitleaksPath from MCP input schemas (P0)
- DNS rebinding protection with fetchWithPinnedDns (P1)
- TOCTOU revalidation before scan (P1)
- Opaque resource URIs to prevent path disclosure (P2)
- Sanitized scanner errors in MCP boundary (P2)
- resources/read uses -32002 for not-found (MCP spec)
- Tightened scannerTimeoutMs Zod schema

### Phase 4: SMB Compliance Tier

- 15-question SMB questionnaire
- compliance-check CLI command
- SMB plain-English report generator
- attestlens_compliance_check MCP tool

### Phase 3: Reform Module

- Automated remediation suggestions
- attestlens_reform MCP tool

### Phase 2: Agent-Native Enhancements

- Agent report format (--format agent)
- attestlens_check MCP tool (single-principle check)
- CI/CD integration guide

### Phase 1: Opinion-Grade Assessments

- ComplianceOpinion schema (NOT_COMPLIANT / NEEDS_REVIEW / COMPLIANT)
- Deterministic opinion engine
- CLI --opinion flag
- attestlens_opinion MCP tool
