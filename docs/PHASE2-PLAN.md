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

---

## Phase 3 — AI Integration Roadmap

These are planned but not yet built. Documented here so they're not forgotten.

### 3.1 AI-Guided Attestation (Questionnaire Engine Enhancement)

The questionnaire engine currently has a static question bank. AI integration turns it into an intelligent compliance assistant.

**Features:**

- **Dynamic branching** — AI skips follow-up questions based on previous answers. E.g., if no overseas disclosure, skip APP 8 cross-border questions entirely.
- **AI-suggested answers** — Scan findings pre-populate likely answers. E.g., "I detected SQL injection — your APP 11 Security score should likely be FAIL."
- **Statutory language translation** — AI translates NDB s26WE, APP sub-obligations into plain English for non-lawyer users.
- **Confidence-weighted scoring** — Self-reported answers get 0.80 confidence, evidence-backed get 0.95, AI-suggested get 0.70 (flagged for review).
- **Evidence extraction** — AI reads source code to find evidence supporting or contradicting questionnaire answers.

**Example flow:**
```
? APP 11 — Security: Do you have input validation for all user-facing endpoints?
  → AI suggestion: FAIL (3 SQL injection findings detected in src/api/)
  → Confidence: 0.70 (AI-suggested, flagged for review)
  [Accept] [Override] [Attach Evidence]
```

**Implementation:** LLM calls via the existing MCP server infrastructure. Could use OpenAI, Claude, or local models. Requires `attestlens.config.json` for model selection.

**Dependencies:** Phase 2 questionnaire engine must be complete first.

### 3.2 AI Fix Prompts

Each finding gets an AI-generated remediation suggestion, mapped to APP obligations.

**Current state:** Findings include static `fix` strings (e.g., "Add input validation to all SQL queries.")

**Target state:** AI generates contextual fix prompts with code examples:
```
Finding: VS-SQLI — Potential SQL injection vector
Location: src/api/users.ts:42

AI Fix: Use parameterized queries instead of string concatenation:
  // Before (vulnerable)
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  // After (safe)
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await pool.query(query, [req.params.id]);

APP Obligation: APP 11.1 — Security measures must protect personal information from misuse, interference, and loss.
```

**Implementation:** LLM receives finding + surrounding code context, generates targeted fix. Requires model config.

### 3.3 AI Report Narrative

AI-written executive summaries and compliance narratives replace raw metric dumps.

**Current state:** Reports show "3 FAIL, 9 UNKNOWN" with static descriptions.

**Target state:** AI generates:
- **Executive summary** — Natural language assessment of compliance posture
- **Risk narrative** — "Your organization lacks documented cross-border disclosure procedures (APP 8) and has critical SQL injection vulnerabilities exposing personal information (APP 11)..."
- **Remediation playbook** — Prioritized, plain-English action items with effort estimates
- **Consultant-ready language** — Written in professional compliance tone, suitable for client deliverables

**Implementation:** Report generator calls LLM with structured report data, receives narrative sections. Falls back to static text if LLM unavailable.

### 3.4 AI Model Configuration

All AI features require a model configuration layer:

```typescript
interface AIConfig {
  provider: 'openai' | 'anthropic' | 'local' | 'none';
  model: string;              // e.g., 'gpt-4o', 'claude-3.5-sonnet'
  apiKey?: string;            // From env var or config
  baseUrl?: string;          // For local/self-hosted models
  maxTokens: number;
  temperature: number;
  costBudget: number;        // Max cost per session in USD
}
```

```json
// attestlens.config.json
{
  "ai": {
    "provider": "openai",
    "model": "gpt-4o-mini",
    "costBudget": 0.50,
    "temperature": 0.3
  }
}
```

When `provider: 'none'`, all AI features degrade gracefully to static defaults.

### 3.5 Priority Order

1. **AI-Guided Attestation** — highest value, transforms questionnaire from static to interactive
2. **AI Fix Prompts** — high value, immediate usability for developers
3. **AI Report Narrative** — medium value, improves consultant deliverables
4. **AI Model Config** — foundational, must be built first (or alongside 3.1)

### 3.6 What's NOT AI

These parts are and should remain **deterministic** (no AI):

- Scanner rules (regex, supply chain detection, mapping engine)
- APP/NDB obligation mapping (legal requirements are statutory, not probabilistic)
- Scoring algorithm (must be reproducible and auditable)
- Grade calculation (deterministic formula)
- Path validation and security controls

AI is used for **interpretation, suggestion, and translation** — never for compliance determination itself.