# Jurisdiction Research: CCPA/CPRA & GDPR Subset

> Research base for implementing US California and EU GDPR jurisdiction packs in Clearway.

## 1. CCPA/CPRA — California Consumer Privacy Act

### Statute Structure (Cal. Civ. Code §1798.100–199.100)

**Core Consumer Rights (agent-actionable principles):**

| Section | Right | Clearway Principle ID | Agent-Relevant Check |
|---|---|---|---|
| §1798.100 | General duties — collection notice, purpose limitation, retention limits, service provider agreements, security | `CCPA_100` | Does the app collect PI without notice at point of collection? Retention longer than necessary? No service provider agreement? No reasonable security? |
| §1798.105 | Right to delete | `CCPA_105` | Can consumers delete their data? Is deletion endpoint functional? |
| §1798.106 | Right to correct | `CCPA_106` | Can consumers correct inaccurate PI? |
| §1798.110 | Right to know/access | `CCPA_110` | Does the app disclose what PI is collected? Can consumers access their data? |
| §1798.115 | Right to know sale/sharing | `CCPA_115` | Does the app disclose what PI is sold/shared and to whom? |
| §1798.120 | Right to opt-out of sale/sharing | `CCPA_120` | Is there a "Do Not Sell or Share My Personal Information" link? Is opt-out mechanism functional? |
| §1798.121 | Right to limit sensitive PI use | `CCPA_121` | Is there a "Limit the Use of My Sensitive Personal Information" link? |
| §1798.125 | Right of no retaliation | `CCPA_125` | Does the app discriminate against consumers who exercise CCPA rights? |
| §1798.130 | Notice/disclosure/correction/deletion requirements | `CCPA_130` | Are required notices present (at collection, privacy policy, right to opt-out)? 12-month lookback for access requests? |
| §1798.135 | Methods for limiting sale/sharing | `CCPA_135` | Is a Global Privacy Control (GPC) signal honored? Is opt-out via website/form/phone? |
| §1798.140 | Definitions | — | Key defs: "personal information", "sensitive personal information", "sale", "sharing", "business purpose", "service provider", "contractor", "third party" |
| §1798.145 | Exemptions | `CCPA_145` | Is the business exempt? (<$25M revenue, <100K consumers, <50% revenue from sale) |
| §1798.150 | Security breaches (private right of action) | `CCPA_150` | Are security vulnerabilities exposing PI? (This is where scanner overlaps with existing security rules) |
| §1798.185 | Regulations (CPPA rulemaking authority) | — | CPPA can adopt, amend, repeal regulations |
| §1798.199.10–100 | CPRA enforcement provisions (CPPA) | — | Administrative enforcement, audits, penalties |

### CPRA Regulations (effective 1/2/2024, updated 1/1/2026)

**Key regulatory articles relevant to scanning:**

| Reg § | Topic | Agent-Relevant Check |
|---|---|---|
| §7002 | Restrictions on collection and use | Purpose limitation check — is PI used beyond disclosed purpose? |
| §7011 | Privacy policy requirements | Is privacy policy complete? Does it include all 11 required disclosures? |
| §7012 | Notice at collection | Is there a notice at or before point of collection? |
| §7013 | Opt-out of sale/sharing notice | "Do Not Sell or Share" link present and functional? |
| §7014 | Limit sensitive PI use notice | "Limit the Use" link present? |
| §7025 | Opt-out preference signals (GPC) | Is GPC signal honored? |
| §7070–72 | Minors (under 16) | Is there parental consent for under-13? Opt-in for 13-16? |
| §7100 | Training | Are personnel handling PI trained? |
| §7101 | Record-keeping | Are CCPA request records kept for 24 months? |
| §7102 | Large data collector requirements | Risk assessment, cybersecurity audit, annual review for businesses collecting 10M+ consumers |

### CCPA Key Definitions (for rule mapping)

- **Personal Information**: Information that identifies, relates to, describes, or can be linked to a particular consumer or household
- **Sensitive Personal Information**: SSN, driver's license, passport, financial account, precise geolocation, racial/ethnic origin, religious beliefs, private communications, genetic data, biometrics, health data, sex life, orientation
- **Sale**: Making PI available to a third party for monetary or other valuable consideration
- **Sharing**: Making PI available to a third party for cross-context behavioral advertising
- **Business Purpose**: Audits, security, debugging, short-term transient uses, internal research, one-to-one advertising, etc.

### Applicability Thresholds

- Revenue > $25M/year, OR
- Buys/sells/shares PI of ≥100K consumers/households annually, OR
- Derives ≥50% of revenue from selling/sharing consumer PI

### Enforcement

- CPPA (California Privacy Protection Agency) — administrative enforcement, $2,500/violation (unintentional), $7,500/violation (intentional)
- AG — civil actions
- Private right of action for data breaches (§1798.150) — $100–$750/consumer/incident

---

## 2. GDPR Subset — Agent-Relevant Articles

### Scoped Coverage (not full GDPR)

We explicitly cover 14 principle IDs. They represent selected articles/article ranges only:

| Article | Title | Clearway Principle ID | Agent-Relevant Check |
|---|---|---|---|
| Art. 3 | Territorial scope | `GDPR_Art3` | Is the controller/processor established in the EU, or offering goods/services to, or monitoring the behaviour of, data subjects in the Union? |
| Art. 5 | Principles of processing | `GDPR_Art5` | Lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity/confidentiality, accountability |
| Art. 6 | Lawful basis for processing | `GDPR_Art6` | Is there a valid legal basis (consent/contract/legal obligation/vital interests/public interest/legitimate interest) for each processing activity? |
| Art. 9 | Special categories of data | `GDPR_Art9` | Is special category data (racial/ethnic origin, political opinions, philosophical beliefs, religious beliefs, trade union membership, genetic data, biometric identification data, health data, sex life, or sexual orientation) being processed? If so, is explicit consent or exemption documented? |
| Art. 13–14 | Information to data subjects | `GDPR_Art13` (covers Art. 13-14 in this subset model) | Is there a privacy notice that includes "meaningful information about the logic involved" in automated processing? |
| Art. 15 | Right of access | `GDPR_Art15` | Can data subjects access their data + info about automated decision-making logic? |
| Art. 17 | Right to erasure | `GDPR_Art17` | Can data subjects request deletion? Is there a mechanism? |
| Art. 22 | Automated individual decision-making | `GDPR_Art22` | Are there solely automated decisions with legal/significant effects? If so, is there human oversight, right to contest? |
| Art. 25 | Data protection by design and by default | `GDPR_Art25` | Is privacy-by-design implemented? Is data minimization by default? |
| Art. 32 | Security of processing | `GDPR_Art32` | Are appropriate technical and organizational measures in place? (overlaps with existing security scanner rules) |
| Art. 33 | Breach notification to supervisory authority | `GDPR_Art33` | Is there a breach notification process (72-hour window)? |
| Art. 34 | Breach notification to data subjects | `GDPR_Art34` | When is data subject notification required? |
| Art. 35 | Data protection impact assessment | `GDPR_Art35` | Is a DPIA required for this processing? (high-risk AI, profiling, large-scale sensitive data, systematic monitoring) |
| Art. 44–49 | International transfers | `GDPR_Art44` | Is personal data transferred outside EEA? If so, is there an adequacy decision, SCCs, BCRs, or derogation? |

### Explicit Coverage Boundaries

**NOT covered in this pack (stated as boundaries):**
- Art. 7–8 (Conditions for consent — deferred to consent-specific update)
- Art. 12 (Form requirements for information — deferred)
- Art. 16 (Right to rectification — deferred)
- Art. 18 (Right to restriction — deferred)
- Art. 19 (Notification obligation for rectification/erasure — deferred)
- Art. 20 (Right to data portability — deferred)
- Art. 21 (Right to object — deferred)
- Art. 23–24 (Restrictions / data protection officer — deferred)
- Art. 26–39 (Controller/processor obligations, DPOs, joint controllers, records of processing — deferred)
- Art. 36 (Prior consultation — deferred)
- Art. 37–39 (DPO requirements — deferred)
- Art. 40–43 (Codes of conduct, certifications — deferred)
- Art. 50–76 (Cooperation, consistency, enforcement — deferred)
- Art. 82–84 (Compensation, liability, penalty — deferred)
- Art. 85–91 (Specific processing situations — deferred)
- Art. 92–99 (Delegated acts, committee procedure — deferred)
- National implementations (GDPR allows member state derogations)

### Key GDPR Concepts for Rule Mapping

- **Lawful basis**: Each processing activity must have one of 6 bases (Art. 6(1)(a)–(f))
- **Purpose limitation**: Data collected for one purpose cannot be repurposed without compatibility assessment
- **Data minimization**: Only process what's necessary for the stated purpose
- **Storage limitation**: Don't keep data longer than necessary
- **Automated decision-making**: Art. 22 is the most AI-relevant article — prohibits solely automated decisions with legal/significant effects without safeguards
- **DPIA**: Required for high-risk processing (profiling, large-scale sensitive data, systematic monitoring)
- **International transfers**: Data can't leave EEA unless adequacy decision, appropriate safeguards (SCCs, BCRs), or derogation

### Enforcement

- Fines: up to €20M or 4% global annual turnover (whichever is higher)
- 30+ Data Protection Authorities across EU member states
- EDPB (European Data Protection Board) for consistency guidance

---

## 3. Cross-Jurisdiction Comparison (Agent-Relevant)

| Principle | AU APP | US CCPA/CPRA | EU GDPR | Key Differences |
|---|---|---|---|---|
| **Collection notice** | APP 5 | §1798.100, §7012 | Art. 13–14 | AU: notify OAIC; CCPA: at or before collection; GDPR: "meaningful info about logic" |
| **Purpose limitation** | APP 6 | §1798.100(c) | Art. 5(1)(b) | GDPR strictest; CCPA "compatible purpose"; APP "primary/secondary" |
| **Data minimization** | APP 3 (necessary) | §1798.100(c) "proportionate" | Art. 5(1)(c) | GDPR explicit principle; CCPA proportionate; AU "necessary" |
| **Sensitive data** | Not separate category in APP | §1798.140(ae) sensitive PI | Art. 9 special categories | GDPR most prescriptive (explicit consent); CCPA has opt-out limit; AU treats under APP 6 |
| **Cross-border transfer** | APP 8 (reasonable steps) | Not explicit (US focus) | Art. 44–49 (adequacy/SCCs/BCRs) | GDPR most complex; APP 8 requires "reasonable steps"; CCPA doesn't restrict |
| **Security** | APP 11 | §1798.100(e) | Art. 32 | All require "reasonable/appropriate" measures; thresholds differ |
| **Breach notification** | NDB (72hr to OAIC) | §1798.150 (private action) | Art. 33 (72hr to DPA), Art. 34 (to data subject) | All have 72hr but recipients differ; CCPA adds private right of action for breaches |
| **Automated decisions** | Not explicit in APP | Not explicit in CCPA | Art. 22 (right not to be subject to) | GDPR is the only one with explicit automated decision-making rights |
| **Access rights** | APP 12 | §1798.110 | Art. 15 | GDPR includes "logic involved" in automated decisions; CCPA 12-month lookback |
| **Deletion rights** | APP 13 (correction, not deletion) | §1798.105 | Art. 17 | CCPA and GDPR have right to delete/erase; APP only correction |
| **Opt-out** | APP 7 (direct marketing) | §1798.120 (sale/sharing) | Art. 21 (right to object) | CCPA opt-out of sale is unique; GDPR right to object is broader |

---

## 4. Implementation Priority for Rule Packs

### CCPA/CPRA Pack (Phase 7)

**Scanner-detectable rules (high confidence, deterministic):**

1. **CCPA_100_DUTIES** — Collection notice at point of collection (check for notice/consent UI patterns)
2. **CCPA_100_RETENTION** — Retention period disclosure (check privacy policy for retention statements)
3. **CCPA_100_SECURITY** — Reasonable security (reuse existing APP_11 security rules, map to §1798.100(e))
4. **CCPA_100_SERVICE_PROVIDER** — Service provider agreement required (check for third-party data sharing without agreement)
5. **CCPA_120_OPT_OUT** — "Do Not Sell or Share" link presence (scan for link text)
6. **CCPA_121_LIMIT_SENSITIVE** — "Limit the Use of Sensitive PI" link presence (scan for link text)
7. **CCPA_130_PRIVACY_POLICY** — Privacy policy completeness (check for required disclosures)
8. **CCPA_150_BREACH** — Security vulnerabilities exposing PI (reuse existing security rules + private right of action context)

**Questionnaire-triggered rules (SMB compliance check):**

1. Do you sell or share consumer PI with third parties?
2. Do you collect sensitive PI (SSN, precise geolocation, health, biometrics)?
3. Do you honor Global Privacy Control (GPC) signals?
4. Do you have a process for consumer deletion requests?
5. Do you have a process for consumer access requests?
6. Do you retain PI longer than reasonably necessary?
7. Do you have service provider agreements for all data sharing?

### GDPR Subset Pack (Phase 8)

**Scanner-detectable rules (high confidence, deterministic):**

1. **GDPR_Art5_LAWFULNESS** — Lawful basis documented for each processing activity
2. **GDPR_Art5_PURPOSE** — Purpose limitation (check for data use beyond declared purposes)
3. **GDPR_Art5_MINIMIZATION** — Data minimization (check for excessive data collection patterns)
4. **GDPR_Art6_BASIS** — Legal basis for processing (consent/contract/legitimate interest)
5. **GDPR_Art9_SENSITIVE** — Special category data processing without explicit consent
6. **GDPR_Art13_NOTICE** — Privacy notice includes meaningful info about automated logic
7. **GDPR_Art22_AUTOMATED** — Automated decisions with legal/significant effects require safeguards
8. **GDPR_Art25_PRIVACY_BY_DESIGN** — Privacy by design implementation
9. **GDPR_Art32_SECURITY** — Security of processing (reuse APP_11 rules, map to Art. 32)
10. **GDPR_Art33_BREACH_NOTIFY** — Breach notification process to DPA (72hr)
11. **GDPR_Art35_DPIA** — DPIA required for high-risk processing
12. **GDPR_Art44_TRANSFER** — International data transfer without adequacy/safeguards

**Questionnaire-triggered rules (SMB compliance check):**

1. Do you process personal data of EU/EEA residents?
2. What is your legal basis for each processing activity?
3. Do you process special category data (health, biometric, racial, religious, sexual)?
4. Do you make automated decisions with legal or similarly significant effects?
5. Do you transfer personal data outside the EEA?
6. Have you conducted a DPIA for high-risk processing?
7. Do you have a 72-hour breach notification process?
8. Do you have a process for data subject access requests?
9. Do you have a process for data subject erasure requests?

---

## 5. Cross-Border Transfer Mapping

This is the most complex multi-jurisdiction interaction and must be first-class:

| Transfer Direction | Source Rule | Requirement | Clearway Check |
|---|---|---|---|
| AU → US | APP 8 | Reasonable steps to ensure overseas recipient complies with APPs | Binding agreement? APEC CBPR? Contractual obligations? |
| AU → EU | APP 8 | Same as above | EU adequacy from AU perspective? Binding agreement? |
| EU → AU | GDPR Art. 44–49 | Adequacy decision, SCCs, BCRs, or derogation | AU has partial adequacy (not full)? SCCs required? |
| EU → US | GDPR Art. 44–49 | EU-US Data Privacy Framework (DPF) adequacy (for certified orgs) or SCCs/BCRs | Is recipient DPF-certified? SCCs in place? |
| US → EU | CCPA doesn't restrict | No restriction under CCPA | N/A (no check needed) |
| US → AU | CCPA doesn't restrict | No restriction under CCPA | N/A (no check needed) |

### Transfer Rule Schema

```typescript
export const TransferRule = z.object({
  id: z.string(),
  sourceJurisdiction: z.string(),    // 'au-privacy-act', 'us-ccpa', 'eu-gdpr'
  destinationJurisdiction: z.string(),
  mechanism: z.enum(['adequacy', 'scc', 'bcr', 'consent', 'derogation', 'apec-cbpr', 'contractual', 'not_required']),
  adequacyStatus: z.enum(['full', 'partial', 'none', 'conditional']).optional(),
  conditions: z.array(z.string()).default([]),
  citation: z.string(),
});
```

---

## Sources

- CCPA Statute (eff. 01/01/2025): https://cppa.ca.gov/regulations/pdf/ccpa_statute.pdf
- CCPA 2026 Updates: https://cppa.ca.gov/pdf/things_to_know_before_2026_updates.pdf
- CPRA Regulations (eff. 1/2/2024): https://california-ccpa.org/cpra-regulations/
- CCPA Section Guide: https://california-ccpa.org/
- GDPR Full Text: https://eur-lex.europa.eu/eli/reg/2016/679/oj
- GDPR & AI Guide: https://aigovref.com/eu-gdpr-ai
- GDPR Key Requirements: https://www.itgovernance.eu/blog/en/summary-of-the-gdprs-10-key-requirements
- AU Privacy Act: https://www.legislation.gov.au/Details/C2024C00119
