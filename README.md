# AttestLens ⚡️

**AI-Powered Australian Privacy Act Compliance Scanner**

AttestLens automatically scans your codebase for Australian Privacy Act (APP/NDB) compliance issues, maps findings to specific statutory obligations, and generates Big 4-grade compliance reports — in seconds, not weeks.

## Why AttestLens?

- **Hard moat**: Questionnaire questions reflect actual *statutory requirements* from the Australian Privacy Act, not generic compliance checkboxes
- **Automated mapping**: Security findings → APP obligations with confidence scoring
- **Consultant-grade reports**: HTML/JSON/Markdown/PDF output that looks like a Big 4 deliverable
- **Strict mode**: Treat all UNKNOWN controls as FAIL — no hiding behind "we don't know"
- **AI-native**: MCP server for Cursor/Windsurf integration, including direct URL scans in-context

## Quick Start

```bash
# Install
npm install -g attestlens

# Scan a project
attestlens scan ./my-project

# Full compliance audit (scan + report)
attestlens audit ./my-project -n "MyApp"

# Live-site compliance audit
attestlens audit https://example.com -n "Example" -f html,json,pdf

# Strict mode — UNKNOWN controls become FAIL
attestlens audit ./my-project -n "MyApp" --strict

# Disable individual scanners
attestlens audit ./my-project -n "MyApp" --no-guardvibe
attestlens audit ./my-project -n "MyApp" --no-mcp-scan
attestlens audit ./my-project -n "MyApp" --no-supply-chain

# Generate report from existing scan data
attestlens report ./scan-results.json -f html
```

## CLI Reference

### `attestlens scan <target>`

Scan a project directory or public URL for privacy compliance findings.

```bash
attestlens scan ./my-project
attestlens scan https://example.com
attestlens scan ./my-project --no-guardvibe   # Skip GuardVibe scanner
attestlens scan ./my-project --no-mcp-scan     # Skip MCP config scanner
```

Output: List of findings with severity, rule ID, file location, and affected APP principles.

### `attestlens audit <target>`

Full compliance audit — scan + APP mapping + weighted scoring + report. Supports either a project directory or a live URL.

```bash
attestlens audit ./my-project -n "MyApp"
attestlens audit ./my-project -n "MyApp" -f html,json,markdown,pdf
attestlens audit https://example.com -n "Example" -f json,pdf
attestlens audit ./my-project -n "MyApp" -o ./reports --strict
```

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --name <name>` | Project name for the report | Directory or hostname |
| `-f, --format <formats>` | Output formats: json, html, markdown, pdf | `html,json` |
| `-o, --output <dir>` | Output directory | `./attestlens-reports` |
| `--strict` | Treat UNKNOWN controls as FAIL | `false` |
| `--no-guardvibe` | Disable GuardVibe scanner | — |
| `--no-mcp-scan` | Disable MCP config scanner | — |
| `--no-supply-chain` | Disable supply chain scanner | — |

### `attestlens report <file>`

Generate a report from an existing scan JSON file.

```bash
attestlens report ./scan-results.json -f html
```

## MCP Server (AI Editor Integration)

AttestLens runs as an MCP server so AI editors like Cursor and Windsurf can run compliance scans in-context.

### Configuration

Add to your editor's MCP settings:

```json
{
  "mcpServers": {
    "attestlens": {
      "command": "npx",
      "args": ["attestlens-mcp"]
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `attestlens_scan` | Scan a project for privacy findings. Returns findings with APP mappings. |
| `attestlens_scan_url` | Scan a live URL for privacy findings. Returns findings with APP mappings keyed by `targetUrl`. |
| `attestlens_audit` | Full APP/NDB audit. Returns a complete compliance report. |
| `attestlens_map` | Map a list of findings to APP obligations. Useful for custom scanners. |

## APP Principles & Scoring

AttestLens evaluates compliance against all 14 Australian Privacy Principles and the Notifiable Data Breaches scheme, with weighted scoring that reflects real-world risk:

| Principle | Name | Weight | Rationale |
|-----------|------|--------|-----------|
| APP_1 | Open & Transparent | 5 | Fundamental but procedural |
| APP_2 | Anonymity | 2 | Lower enforcement focus |
| APP_3 | Collection | 8 | Core data handling |
| APP_4 | Unsolicited Info | 3 | Narrow scope |
| APP_5 | Notification | 6 | Compliance-critical |
| APP_6 | Use & Disclosure | 8 | High-risk area |
| APP_7 | Direct Marketing | 4 | Moderate risk |
| APP_8 | Cross-Border | 10 | Major risk for AU businesses |
| APP_9 | Gov Identifiers | 3 | Narrow scope |
| APP_10 | Data Quality | 6 | Important but less enforced |
| **APP_11** | **Security** | **15** | **Highest weight — most breached** |
| APP_12 | Access | 4 | Moderate risk |
| APP_13 | Correction | 4 | Moderate risk |
| **NDB** | **Data Breach Notification** | **15** | **Highest weight — regulatory focus** |

### Grade Thresholds

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | ≥ 85 | Strong compliance posture |
| **B** | ≥ 70 | Minor gaps, addressable |
| **C** | ≥ 55 | Notable deficiencies |
| **D** | ≥ 40 | Significant risk |
| **F** | < 40 | Critical non-compliance |

### Risk Levels

| Level | Condition |
|-------|-----------|
| **CRITICAL** | Any critical-severity findings |
| **HIGH** | 3+ high-severity findings |
| **MEDIUM** | 1+ high-severity findings |
| **LOW** | No high or critical findings |

## Scanner Rules

### Static Scanner (GuardVibe fallback)

Runs when the GuardVibe MCP server is unavailable. Scans source files for common security patterns:

| Rule ID | Severity | What It Detects |
|---------|----------|----------------|
| `VG-SEC-001` | Critical | Exposed Supabase credentials |
| `VG-SEC-002` | Critical | Service role key in client code |
| `VS-HARDKEY` | Critical | Hardcoded API keys, secret keys, private keys |
| `VS-SQLI` | High | SQL injection via string interpolation |
| `VS-XSS` | Medium | XSS vectors (`dangerouslySetInnerHTML`, `v-html`) |
| `VS-DEBUG` | Medium | Debug logging of sensitive data |
| `VS-ENV` | Critical | Sensitive env vars exposed to client (`NEXT_PUBLIC_`) |
| `VS-CORS` | Medium | Wildcard CORS (`origin: '*'`) |
| `VS-SUPA-RLS-MISSING` | High | Supabase SQL migrations without RLS policies |
| `VS-FB-SERVICE-ACCOUNT` | Critical | Committed Firebase service account material |
| `VS-PUBLIC-SECRET-ENV` | Critical | Public client prefixes applied to secret env vars |
| `VS-PLATFORM-SECRET` | Critical | Hardcoded Stripe/Clerk/Auth0/Vercel/Netlify secrets |

### MCP Config Scanner (mcp-scan)

Checks MCP server configurations for:
- Insecure transport (non-HTTPS endpoints)
- Missing authentication
- Overly broad permissions
- Unencrypted secrets in config files

### Supply Chain Scanner

Detects supply chain risks in npm projects — designed to catch attacks like the Axios npm compromise (March 2026):

| Rule ID | Severity | What It Detects |
|---------|----------|----------------|
| `VS-SC-001` | Critical | Install scripts in dependencies (postinstall, preinstall) |
| `VS-SC-002` | High | Unused production dependencies (manifest-only injection) |
| `VS-SC-004` | Critical | Typosquatting against top npm packages |
| `VS-SC-005` | Critical | Missing or invalid lockfile |
| `VS-SC-006` | High | Known vulnerabilities via `npm audit` |
| `VS-SC-007` | Medium | Dependencies with no repository URL |
| `VS-SC-008` | Critical | Install scripts + no source repo (critical combo) |

The Axios attack would have been caught on **5-7 of 7 indicators** (manifest-only dependency, install scripts, pre-staged package, typosquatting, no repo, and the critical combo). See [`docs/SUPPLY-CHAIN-DETECTION.md`](docs/SUPPLY-CHAIN-DETECTION.md) for full analysis.

## Strict Mode

By default, controls with no findings are marked **UNKNOWN** (questionnaire required). With `--strict`, all UNKNOWN controls become **FAIL** — this is the conservative approach for formal audits where the absence of evidence is evidence of absence.

```bash
# Default: UNKNOWN controls stay UNKNOWN
attestlens audit ./my-project -n "MyApp"

# Strict: UNKNOWN controls become FAIL (score 0)
attestlens audit ./my-project -n "MyApp" --strict
```

## Architecture

```
src/
├── schema/             # Core types (AttestLensFinding, APPMapping, etc.)
├── mapping/            # APP/NDB mapping engine with confidence scoring
├── scanner/            # Scanner adapters + orchestrator
│   ├── guardvibe.ts    # GuardVibe adapter (MCP + static fallback)
│   ├── mcp-scan.ts     # MCP config scanner adapter
│   ├── supply-chain.ts # Supply chain risk detector (npm)
│   ├── orchestrator.ts # Parallel execution + dedup
│   └── types.ts        # Scanner interfaces
├── questionnaire/       # Interactive attestation (Phase 2 scaffold)
├── report/             # Report generation (HTML, JSON, Markdown, PDF)
├── cli/               # CLI entry point (scan, audit, report)
└── mcp/               # MCP server (AI editor tools)
```

## Development

```bash
# Install
npm install

# Build
npm run build

# Test (125 tests)
npm test

# Run the live validation corpus
npm run validate:corpus

# Run locally
npx tsx src/cli/index.ts audit ./my-project -n "MyApp"

# Type check
npm run lint
```

## Roadmap

### Phase 1.5 ✅ (v0.2.0)
- Core schema + APP/NDB mapping engine (31 rules)
- Scanner adapters (GuardVibe static + mcp-scan + supply-chain + url-scan)
- Scanner orchestrator (parallel + dedup)
- CLI (scan, audit, report)
- URL scanning + hardened outbound fetch path
- Report generation (HTML, JSON, Markdown, PDF)
- MCP server (4 tools, including URL scan)
- Validation corpus runner + findings log
- Stack-specific repo security checks for Supabase, Firebase, Stripe, Clerk/Auth0, Vercel/Netlify secrets
- 125 tests
- Strict mode
- Supply chain detection (7 rules, Axios-attack coverage)

### Phase 2 (Next)
- Interactive attestation questionnaire (UNKNOWN → PASS/FAIL)
- Design-partner validation and consultant outreach
- Breach-readiness scoring and richer consultant deliverables
- GuardVibe MCP integration (live scanner, not just fallback)
- Additional framework support (GDPR, SOC 2, HIPAA)

### Phase 3 (Future)
- Web dashboard (React + real-time scan progress)
- CI/CD integration (GitHub Actions, GitLab CI)
- Team collaboration features
- Historical trend tracking
- OAIC alignment updates
- API gateway for SaaS deployment

## Disclaimer

Reports generated by AttestLens do **not** constitute legal advice. Always consult a qualified privacy professional for formal compliance assessment under the Australian Privacy Act 1988.

## License

MIT
