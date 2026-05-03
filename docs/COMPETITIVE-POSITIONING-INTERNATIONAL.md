# Competitive Positioning — International Agent Privacy Gate

**Purpose:** Help the YC application avoid sounding like a clone of privacy scanners, GRC platforms, or frontier-model security agents.

---

## The one-line competitive position

> HoundDog and Privado discover privacy/data-flow issues. Vanta and Drata manage compliance programs. Snyk/Semgrep/CodeQL find security bugs. Clearway sits earlier in the agent workflow: before an AI-generated change merges, it returns a deterministic privacy deploy decision with jurisdiction-specific evidence.

---

## Competitor categories

### 1. Privacy-code scanners

Examples:

- HoundDog.ai
- Privado.ai
- open-source privacy scanners

They are closest on surface area because they scan code for data/privacy risk.

Clearway must not compete by saying “we are the best scanner.” That is dangerous because some competitors have stronger data-flow tracing, IDE integrations, governance integrations, and funding.

Clearway’s wedge:

- deterministic deploy decisions,
- agent/MCP-native workflow,
- jurisdiction pack coverage boundaries,
- pack validation status,
- CI blocking policy,
- rule provenance,
- PR-diff/agent-change focus.

### 2. AppSec / SAST / supply-chain scanners

Examples:

- Semgrep
- Snyk
- CodeQL
- Trivy
- Checkov
- OWASP ZAP

They own CI security scanning mindshare. Clearway should integrate with this workflow, not fight it.

Positioning:

> Snyk catches vulnerable packages. Semgrep catches dangerous code patterns. Clearway catches privacy-policy violations introduced by software changes and routes contextual legal issues to review.

### 3. GRC and compliance platforms

Examples:

- Vanta
- Drata
- Secureframe
- OneTrust
- TrustArc

They own post-hoc compliance records, evidence collection, control management, and audit workflows.

Clearway’s wedge:

> GRC systems manage the compliance program. Clearway is a pre-merge enforcement gate for agent-created code.

Potential future integration:

- Send Clearway evidence to Vanta/Drata/OneTrust rather than replace them.

### 4. Frontier-model security agents

Examples:

- GPT/Claude/Codex security and cyber models
- code-review agents
- autonomous remediation agents

These are a threat to generic scanning and generic “AI finds bugs” tools.

Clearway’s positioning:

> Frontier models generate and review code. Clearway is the deterministic policy boundary they must pass before acting.

Do not compete with model intelligence. Use models as upstream actors that need gates.

### 5. Internal privacy/security teams

Internal teams may have manual review processes.

Positioning:

> Clearway does not replace privacy teams. It makes their policy executable in CI and routes ambiguous issues to them with evidence.

---

## What not to say

Avoid:

- “We automate global privacy compliance.”
- “We replace privacy counsel.”
- “We are better than HoundDog at PII tracing.”
- “We are Vanta for AI agents.”
- “We use AI to decide if you are compliant.”
- “No competitors.”

These create credibility problems.

---

## What to say

Use:

- “Deterministic deploy gate.”
- “Coverage-bounded jurisdiction packs.”
- “Agent-created PRs.”
- “High-confidence blocking, otherwise advisory/needs review.”
- “No LLM at scan runtime.”
- “AI drafts rules; humans validate; runtime stays deterministic.”
- “Pre-merge enforcement, not post-hoc GRC.”

---

## Differentiation matrix

| Dimension | Privacy scanners | SAST tools | GRC platforms | Frontier models | Clearway |
| --- | --- | --- | --- | --- | --- |
| Code scanning | Yes | Yes | Usually no | Yes | Yes |
| Privacy-law mapping | Yes/some | No | Yes/post-hoc | Prompt-dependent | Yes/pack-based |
| CI deploy gate | Sometimes | Yes | No | No/dynamic | Core workflow |
| MCP-native | Rare | Rare | Rare | N/A | Core workflow |
| Deterministic runtime | Usually | Yes | N/A | No | Yes |
| Jurisdiction coverage boundaries | Sometimes | No | Yes | No | First-class target |
| Agent-created PR focus | No/early | No | No | Creates PRs | Core wedge |
| Human-validated rule promotion | Varies | Varies | Yes | No | Core target |

---

## Moat strategy by competitor pressure

### If HoundDog/Privado add MCP

Response:

- They may expose scanner tools to agents.
- Clearway must own deploy-gate policy, pack validation, and PR decision workflow.
- Build false-positive and blocking-rule data from real pilots.

### If Semgrep/Snyk add privacy packs

Response:

- They can add checks, but privacy-law conclusions require coverage boundaries, validation status, and evidence routing.
- Clearway can also use Semgrep-like patterns under the hood if needed.

### If Vanta/Drata add code scanning

Response:

- They are audit systems, not developer/agent-native gates.
- Integrate with them as evidence destinations.

### If frontier models become excellent at privacy review

Response:

- Model review is probabilistic and varies by prompt/context.
- Clearway is deterministic, versioned, and auditable.
- Frontier models can call Clearway as a tool.

---

## YC answer: “Why won’t incumbents win?”

Suggested answer:

> Incumbents are either scanners, GRC systems, or AI assistants. The new problem is different: agents are taking software actions at CI speed, and companies need a deterministic policy decision before those actions ship. That requires a runtime gate, not a dashboard or a chatbot. Our moat compounds through validated jurisdiction packs, real false-positive data, and integration into agent workflows.

---

## YC answer: “Isn’t this just compliance scanning?”

Suggested answer:

> Compliance scanning is the input. The product is the deploy decision. A scanner says “possible issue.” Clearway says “this agent-created change is blocked, warned, or needs review under this jurisdiction pack, with evidence and citations.” That distinction matters because agents need machine-readable gates, not PDFs.

---

## What to build to strengthen differentiation

Highest priority:

1. PR-diff mode.
2. Pack validation status and coverage boundaries.
3. Operational deploy verdicts.
4. Real GitHub Action/demo PR.
5. Evidence chains.
6. Taint-lite source-to-sink detection after pilots.

Do not build a generic dashboard before these.
