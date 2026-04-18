# Phase 2 Plan — AttestLens

## Objective

Transform AttestLens from a scanner into a complete compliance assessment tool by adding:
1. **Interactive attestation questionnaire** — the hard moat
2. **Web dashboard** — professional UX
3. **PDF generation** — consultant deliverable
4. **Live GuardVibe integration** — richer scanning

---

## 2.1 Interactive Attestation Questionnaire

This is the **core differentiator**. Questions map directly to APP/NDB statutory requirements — not generic checkboxes.

### Architecture

```
src/questionnaire/
├── questions.ts       # Question bank (per APP principle)
├── flow.ts            # Question flow engine (branching logic)
├── evaluator.ts       # Answer → PASS/FAIL/UNKNOWN evaluation
├── session.ts         # Session management (save/resume)
└── index.ts           # Public API
```

### Question Design Principles

- Each question traces to a specific APP sub-obligation
- Questions use real statutory language (e.g., "Does the entity have a documented data breach response plan?" → NDB s26WE)
- Answers have confidence-weighted mappings (self-reported = 0.80, evidence-backed = 0.95)
- Questionnaire can convert UNKNOWN controls to PASS/FAIL after completion

### Question Types

| Type | Example | Maps To |
|------|---------|---------|
| `yes_no` | "Do you have a documented privacy policy?" | APP_1.1 |
| `yes_no_evidence` | "Do you have evidence of regular privacy impact assessments?" | APP_1.5 |
| `multi_choice` | "How do you handle cross-border data transfers?" | APP_8.1 |
| `checklist` | "Which security measures are in place?" (multi-select) | APP_11.1 |
| `scale` | "How frequently do you review data retention schedules?" | APP_11.3 |

### MVP Question Count

- ~3-5 questions per APP principle (14 principles)
- ~5 questions for NDB
- **Target: 50-70 questions total**

### CLI Flow

```bash
attestlens attest ./my-project

? APP_1 — Open & Transparent Management
? Does the entity have a documented privacy policy? (Yes/No/Evidence)
> Yes

? Is the policy publicly available? (Yes/No/Evidence)
> Evidence [attach URL]

? How often is the policy reviewed?
> Annually

✅ APP_1: PASS (confidence: 0.82)
```

### Web Dashboard Flow

- Left sidebar: APP principles with status indicators
- Center: Current question with progress bar
- Right: Context panel showing relevant findings
- Bottom: Skip/Back/NEXT buttons

### Data Model

```typescript
interface QuestionnaireSession {
  id: string;
  targetName: string;
  targetPath: string;
  startedAt: string;
  completedAt?: string;
  answers: Answer[];
  results: APPControl[];  // Updated with questionnaire-driven status
}

interface Answer {
  questionId: string;
  response: string | string[];
  evidence?: string;
  confidence: number;
  timestamp: string;
}
```

---

## 2.2 Web Dashboard

### Tech Stack

- **React 19** + TypeScript
- **Vite** for dev/build
- **Tailwind CSS** for styling (matches our dark navy/teal report theme)
- **WebSocket** for real-time scan progress
- Served from `attestlens dashboard` command

### Pages

| Route | Purpose |
|-------|---------|
| `/` | Dashboard — recent scans, quick actions |
| `/scan` | New scan — upload or point to directory |
| `/scan/:id` | Scan results — findings, APP map, report |
| `/attest/:id` | Interactive questionnaire |
| `/report/:id` | Report view — HTML/PDF export |
| `/settings` | Configuration, scanner toggles |

### Key Features

- Real-time scan progress (WebSocket push)
- Interactive APP compliance heatmap (14 principles × color)
- Drag-and-drop evidence upload
- One-click PDF/HTML export
- Historical comparison (diff between scans)

### MVP Scope

- `/` dashboard with scan results list
- `/scan/:id` results page with findings + APP map
- `/attest/:id` questionnaire flow
- `/report/:id` HTML report with PDF download button

---

## 2.3 PDF Generation

### Approach

Use `@react-pdf/renderer` for React-based PDF templates — same data model as HTML reports, different renderer.

```typescript
// src/report/pdf.tsx
export function generatePDFReport(report: ComplianceReport): Promise<Buffer> {
  return renderToBuffer(<ComplianceReportPDF report={report} />);
}
```

### PDF Structure

1. Cover page (logo, project name, date, CONFIDENTIAL)
2. Executive summary (grade, risk, key stats)
3. APP control status table
4. Detailed findings (with code snippets)
5. Remediation playbook (prioritized)
6. Questionnaire results (if completed)
7. Disclaimer + methodology note

---

## 2.4 Live GuardVibe Integration

### Current State

- GuardVibe adapter tries `npx @guardvibe/cli full_audit` first
- Falls back to static regex scanning if unavailable

### Target State

- Support MCP protocol connection to GuardVibe server
- Use `@modelcontextprotocol/sdk` client to call GuardVibe tools
- Configuration in `attestlens.config.json`:

```json
{
  "scanners": {
    "guardvibe": {
      "mcpEndpoint": "http://localhost:3000",
      "enabled": true
    },
    "mcpScan": {
      "enabled": true
    }
  }
}
```

- Fallback to static regex remains if MCP connection fails

---

## Timeline

| Week | Focus | Deliverable |
|------|-------|-------------|
| 1 | Questionnaire engine + question bank | Working CLI `attestlens attest` |
| 2 | Web dashboard scaffold + scan results page | Working `/scan/:id` page |
| 3 | Questionnaire UI + PDF generation | Working `/attest/:id` + PDF export |
| 4 | GuardVibe MCP integration + polish | Live scanning, config file |

---

## Validation Milestone

Before building Phase 2 features, we need:

1. ✅ 5-10 AU consultants/MSPs review the mock report
2. ✅ Confirm the questionnaire design reflects real statutory requirements
3. ✅ Validate that the grading/scoring matches their professional judgment

This is the "validate before code" gate we agreed on.