# MCP Multi-Jurisdiction Demo

This walkthrough shows the same Phase 9 demo through MCP tools. It assumes the
MCP server is configured as `clearway` and the demo project path is inside the
server's allowed roots.

Create the fixture first:

```bash
KEEP_DEMO_PROJECT=1 bash demo/multi-jurisdiction.sh
```

Use the printed `Demo project:` path in the calls below.

## 1. Full Audit, Three Jurisdictions

AU Privacy Act:

```json
{
  "tool": "attestlens_audit",
  "arguments": {
    "path": "/absolute/path/to/demo-project",
    "jurisdiction": "au-privacy-act",
    "opinion": true,
    "format": "agent"
  }
}
```

Expected jurisdiction surface:

- `APP_6` for use and disclosure risk from logging/disclosure signals.
- `APP_11` for security risk from the Dockerfile and source findings.

US CCPA/CPRA:

```json
{
  "tool": "attestlens_audit",
  "arguments": {
    "path": "/absolute/path/to/demo-project",
    "jurisdiction": "us-ccpa",
    "opinion": true,
    "format": "agent"
  }
}
```

Expected jurisdiction surface:

- `CCPA_100` for collection/security duties.
- `CCPA_120` for missing opt-out rights.
- `CCPA_135` for missing Global Privacy Control handling.

EU GDPR:

```json
{
  "tool": "attestlens_audit",
  "arguments": {
    "path": "/absolute/path/to/demo-project",
    "jurisdiction": "eu-gdpr",
    "opinion": true,
    "format": "agent"
  }
}
```

Expected jurisdiction surface:

- `GDPR_Art5` for personal-data processing principles.
- `GDPR_Art32` for security of processing.
- `GDPR_Art44` for international transfer safeguards.

## 2. Opinion Tool

Use `attestlens_opinion` when the client wants the verdict object rather than a
rendered report:

```json
{
  "tool": "attestlens_opinion",
  "arguments": {
    "path": "/absolute/path/to/demo-project",
    "jurisdiction": "au-privacy-act",
    "strict": false
  }
}
```

Repeat with:

```json
{ "jurisdiction": "us-ccpa" }
{ "jurisdiction": "eu-gdpr" }
```

The useful comparison is the per-principle verdict list. The same source files
produce AU APP controls, US CCPA controls, or EU GDPR controls depending on the
`jurisdiction` input.

## 3. AU-Only Compliance Check

`attestlens_compliance_check` is intentionally AU-only. Use it for the SMB
Privacy Act workflow:

```json
{
  "tool": "attestlens_compliance_check",
  "arguments": {
    "path": "/absolute/path/to/demo-project",
    "jurisdiction": "au-privacy-act",
    "strict": false,
    "reform": true
  }
}
```

For US or EU, use `attestlens_audit`, `attestlens_opinion`, or
`attestlens_map` instead.

## 4. Map Supplied Findings Across Jurisdictions

Use `attestlens_map` when another scanner or agent already has findings and
wants Clearway's jurisdiction mapping.

AU mapping:

```json
{
  "tool": "attestlens_map",
  "arguments": {
    "jurisdiction": "au-privacy-act",
    "findings": [
      {
        "source": "demo",
        "sourceRule": "VS-SAST-007",
        "severity": "medium",
        "category": "Security",
        "title": "Sensitive data logged",
        "description": "Email and token fields are written to application logs.",
        "file": "server.js",
        "line": 8
      },
      {
        "source": "demo",
        "sourceRule": "VS-IAC-001",
        "severity": "critical",
        "category": "Infrastructure as Code",
        "title": "Dockerfile explicitly runs as root",
        "file": "Dockerfile",
        "line": 5
      }
    ]
  }
}
```

US mapping:

```json
{
  "tool": "attestlens_map",
  "arguments": {
    "jurisdiction": "us-ccpa",
    "findings": [
      {
        "source": "demo",
        "sourceRule": "VS-SAST-019",
        "severity": "medium",
        "category": "SAST Lite",
        "title": "Personal data collected without visible consent check",
        "description": "Email is collected without a visible notice or purpose signal.",
        "file": "server.js",
        "line": 7
      }
    ]
  }
}
```

EU mapping:

```json
{
  "tool": "attestlens_map",
  "arguments": {
    "jurisdiction": "eu-gdpr",
    "findings": [
      {
        "source": "demo",
        "sourceRule": "VS-SAST-019",
        "severity": "medium",
        "category": "SAST Lite",
        "title": "Personal data collected without visible consent check",
        "description": "Email is collected without a visible lawful-basis signal.",
        "file": "server.js",
        "line": 7
      },
      {
        "source": "demo",
        "sourceRule": "GDPR-TRANSFER-001",
        "severity": "high",
        "category": "gdpr-transfer",
        "title": "International transfer without safeguards",
        "description": "Transfer outside the EEA is configured without documented safeguards.",
        "file": "config.json",
        "line": 3
      }
    ]
  }
}
```

## Demo Close

The YC-facing point is not that one codebase is "globally compliant" or
"globally non-compliant". The point is narrower and stronger: the same software
has different compliance realities under different legal regimes, and agents
need the runtime to select and enforce the right jurisdiction before they ship.
