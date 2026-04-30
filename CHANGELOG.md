# Changelog

## 0.3.0 (2026-04-30)

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
