# Vulnerability Remediation Platform

**Product Specification**

> **De-identified.** This specification is derived from a real engagement with a
> financial market infrastructure operator. The client is not named, the backlog
> figure is illustrative rather than actual, and commercial terms have been removed.
> Everything that shapes the *engineering* — the flow, the data model, the governance
> rules, the failure modes, the KPIs — is unchanged, because that is the part the
> product is built against.
>
> This is the **input document**. Every requirement below is traced in
> [`TRACEABILITY.md`](TRACEABILITY.md), and every quotation there is verified against
> this file by `python tools/check_quotes.py`.

---

## Overview

### The Problem

the client runs a huge number of computer systems. Security scanners (including some AI-powered ones)
looked at all that code and found **several thousand high-severity vulnerabilities**: things like passwords
accidentally left in the code, or spots where a bad actor could trick the system into running
commands it shouldn't. That's way too many bugs for people to fix by hand one at a time in a
reasonable amount of time.

### The Requirements

Whoever fixes this has to follow some strict rules, because the client is part of how the world's stock
trades get settled; mistakes here are a big deal:

- Fix the most dangerous bugs first.
- Never let a fix accidentally break something else.
- Keep a "receipt" proving every single bug was actually fixed, not just marked as fixed.
- A human, not a robot, always makes the final call before anything changes production.
- Learn from every fix, so the next 100 similar bugs get fixed faster than the first one.

### The Solution

This product is like a very organized assistant with a filing system:

- It collects every bug report from all of the client's different scanning tools into one list.
- It sorts the list, grouping bugs that are really "the same problem" showing up in different
  places, and puts the scariest ones on top.
- For each bug, it looks up how the client fixed this exact type of problem before, and suggests a fix
  using that same trusted method.
- A person checks the suggested fix before it goes anywhere near real systems.
- Once approved, it tests the fix automatically and re-checks that the bug is actually gone (not
  just that someone said "done").
- It saves a receipt for every fix (what the bug was, how it was fixed, who approved it, and proof
  it worked) so auditors can check later.
- It remembers every approved fix so the next similar bug gets solved even faster.

---

## Product Purpose

Build a governed AI-assisted platform that converts the client security findings into prioritized,
reusable, and validated remediation actions. The product reduces manual triage and remediation
effort, accelerates closure of the high-priority backlog, and creates reusable remediation knowledge
across portfolios, while keeping the client in control of every risk, release, and closure decision.

## Product Goals

- Create one normalized view of findings from existing the client security tools.
- Reduce manual triage using AI classification, root cause analysis, and prioritization.
- Identify repeated issues using deterministic matching and clustering.
- Convert common root cause patterns into approved, reusable remediation patterns.
- Generate portfolio/repository-specific remediation recommendations.
- Validate remediations through existing CI/CD and security testing before closure.
- Automatically create audit-ready evidence with complete traceability.

---

## Personas / Who Uses This Product

| Persona | Role in the product |
|---|---|
| **Security Reviewer / Owner** | Reviews AI-proposed fixes for their finding category, approves or rejects, can override AI classification and confidence scoring. Only role that can move a finding from "proposed" to "approved for validation." |
| **Application / Portfolio Owner** | Provides application context, reviews fixes affecting their repository, retains final say on whether a validated fix is scheduled for release in their app. |
| **Program Governance Lead** | Manages wave sequencing, exception queue prioritization, dashboard/KPI oversight, escalations. |
| **Executive / Audit Viewer** | Read-only access to dashboards, burn-down, KPIs, and evidence packages. No approval rights. |

---

## Product Flow

1. **Ingest** findings from the client scanners and ticketing/security systems.
2. **Normalize** findings into a structured vulnerability record.
3. **Deduplicate** exact matches and **cluster** similar findings.
4. Run an **AI triage assistant** to classify, infer root cause, and recommend a remediation cluster.
5. **Retrieve** approved remediation patterns and the client guidance through RAG.
6. Run a **remediation agent** to propose repository-specific code, config, or dependency changes.
7. **Route the proposal through a security owner for approval.**
8. **Execute build and vulnerability-specific tests through CI/CD**, and re-run the scanners after changes.
9. **Generate evidence** and update the source of record only after validation and approval.
10. **Feed accepted fixes back** into the remediation knowledge base.

---

## Core Product Components

### Ingestion and Normalization

- Connect to scanner/ticketing APIs where available; otherwise support controlled CSV/JSON ingestion.
- Map source fields into a structured schema (finding ID, scanner information, repository, etc.).
- Preserve the original payload and `finding_ID` for traceability.

### Remediation Clustering

- Use **deterministic fingerprints** (scanner, repository, rule ID, file path) for exact/high-confidence duplicates.
- Use **embeddings + clustering** to group near-duplicate findings that aren't exact matches (same root cause, different wording or location) into a shared remediation family.
- **Persist cluster membership** so a fix applied to one member can be propagated as a suggestion to the rest of its cluster.

### AI Triage Assistant

- Classifies each finding into a vulnerability category (secrets, injection, access control, etc.).
- Infers likely root cause using finding metadata and repository context.
- **Assigns a confidence score to its own classification.**
- **Below a defined confidence threshold, routes the finding to manual triage** instead of auto-classifying.

### Remediation Pattern Library & RAG Retrieval

- Version-controlled library of approved fix patterns, one or more per vulnerability category.
- Each pattern includes: description, code/config example, required tests, and closure evidence template.
- **Retrieval-Augmented Generation (RAG)** grounds the remediation agent's suggestions in this library and the client's written standards, rather than general model knowledge, so suggestions reflect what the client has already approved, not generic advice.
- New patterns can only enter the library through **Security Engineering review**; existing patterns can be versioned or deprecated as standards change.

### Remediation Agent

- Given a triaged finding and its matched pattern, generates a repository-specific proposal: code diff, config change, or dependency bump.
- **Never writes directly to a protected branch**: output is always a proposal attached to a pull/merge request.
- Attaches the finding ID, matched pattern ID, and confidence score to every proposal for traceability.

### Human Approval & Review Workflow

- Every AI-generated proposal requires sign-off from a **role-appropriate Security Reviewer** before it proceeds to validation.
- Approval, rejection, and any manual edits are logged against the finding record (who, when, what changed).
- **Escalation rule:** findings with low AI confidence, no matching pattern, or reviewer rejection route to a **manual exception queue** rather than blocking the pipeline.

### CI/CD Validation & Re-scan

- Runs build, regression, and vulnerability-specific security tests on every proposed fix through existing the client CI/CD.
- **Re-runs the original scanner(s)** against the changed code to confirm the finding is no longer detected, not just that a diff was merged.
- A fix is not eligible for closure until **both** test validation and re-scan confirmation pass.

### Evidence & Audit Trail Generator

- Automatically compiles, per closed finding: original finding, root cause, matched pattern, proposed change, reviewer approval record, test results, and re-scan confirmation.
- **Evidence packages are immutable once generated** and linked to the finding's permanent record.
- Supports the client's risk exception/waiver process by attaching the same evidence structure to accepted-risk findings.

### Governance Dashboard & Reporting

- Live view of findings by status, category, portfolio, cycle time, and closure volume.
- Tracks the program KPIs (see below) and exception queue size/age.
- Read access by persona; **no dashboard action can change a finding's status**: status changes only happen through the approval/validation workflow.

### Knowledge Base Feedback Loop

- Every approved, validated fix is fed back into the Remediation Pattern Library as a reusable example.
- **Rejected or reworked proposals are also captured**, so the triage/remediation models improve on real reviewer feedback over time rather than only on successes.

---

## Data Model

**Structured Vulnerability Record:**

| Field | Purpose |
|---|---|
| `finding_id` | Unique ID, traceable to original scanner output |
| `source_scanner` | Which tool detected it (incl. AI-based scanners) |
| `repository` / `portfolio` | Where the finding lives, which division owns it |
| `category` | Vulnerability type (secrets, injection, access control, etc.) |
| `severity` | High / Medium / Low |
| `root_cause` | AI-inferred or human-confirmed root cause |
| `cluster_id` | Deduplication/near-duplicate grouping |
| `confidence_score` | AI triage confidence |
| `matched_pattern_id` | Remediation pattern applied, if any |
| `status` | New → Triaged → Proposed → Approved → Validated → Closed → Exception |
| `approver` | Security Reviewer who signed off |
| `evidence_link` | Pointer to the immutable evidence package |
| `timestamps` | Created, triaged, proposed, approved, validated, closed |

---

## AI Component Specification

- **Model hosting / data residency:** AI components (triage, RAG retrieval, remediation agent) run within a the client-approved environment; no source code, findings, or embeddings leave the client-controlled infrastructure. This must clear the client's data, privacy, security, and TPRM review before use, per the engagement's requirements.
- **Secrets handling in the pipeline itself:** findings that contain live credentials or secrets are **redacted/tokenized before embedding or indexing**, so the tool built to fix secret leaks does not itself become a new secret-exposure vector.
- **Confidence thresholds:** calibrated **per vulnerability category and portfolio, not globally**; a threshold tuned on simple quick-win findings is not assumed to generalize to more complex categories or codebases. Findings below threshold go to manual triage rather than being auto-classified.
- **Hallucination / false-fix mitigation:** no proposal is trusted on the model's word, as every fix must pass CI/CD tests and a post-fix re-scan before it can close a finding.
- **Pattern library governance:** patterns are versioned; changes require Security Engineering approval; deprecated patterns are flagged so the remediation agent stops recommending them.
- **Model evaluation:** triage and remediation agent performance (**classification accuracy, pattern-match precision, reviewer override rate**) is tracked over time as a first-class metric, not just assumed to work because it worked in the pilot phase.

---

## Non-Functional Requirements

- **Security & Access Control:** role-based access control (RBAC) aligned to the personas above; approval actions restricted to authorized Security Reviewers; full action-level audit logging.
- **Scalability:** designed for a **backlog in the low thousands of High-priority findings**, with headroom to extend to the much larger Medium/Low population (an order of magnitude larger) in a later continuation phase **without redesign**.
- **Availability:** ingestion and dashboard components available during the client business hours at minimum; CI/CD validation dependent on existing the client pipeline availability.
- **Auditability:** every state change on a finding is logged with **actor, timestamp, and reason**; evidence packages are immutable and retained per the client audit retention policy.
- **Compliance/TPRM:** all AI tooling and any third-party model dependency is subject to the client data, privacy, security, and Third-Party Risk Management review before production use.

---

## Failure Modes & Exception Handling

- Scanner/ticketing API unavailable: ingestion falls back to controlled CSV/JSON import; no findings are silently dropped.
- AI service unavailable: findings queue for triage rather than blocking ingestion; no default/fallback auto-classification is applied.
- No matching pattern / low confidence / reviewer rejection: finding routes to the manual exception queue, owned by the Program Governance Lead, with age/size tracked on the dashboard so it doesn't silently grow unnoticed near milestone deadlines.
- Batch-applied fix causes a regression: any category-wide automated action (e.g., dependency upgrade) is validated in CI before merge; a failed build blocks that specific change without affecting others in the batch.
- Finding reopens after closure (recurrence): reopened findings re-enter the pipeline at triage with a link to the original evidence package, and the originating pattern is flagged for review.

---

## Out of Scope

- The product does **not** have production deployment authority; the client retains all release timing and deployment decisions.
- The product does **not** replace the client's existing scanners, source control, CI/CD, or ticketing systems: it integrates with and normalizes on top of them.
- **No fix is ever auto-approved or auto-closed** without human sign-off from an authorized Security Reviewer.
- **Medium and Low-priority findings are out of scope for the initial build**; the product is designed to extend to them in a later phase, not to process them at launch.

---

## Success Metrics / KPIs

Tied directly to the engagement's outcome KPIs, **measured natively by the product**:

1. Average remediation **cycle time** per finding, by category.
2. Count of high findings **closed per wave** and cumulative **burn-down**.
3. Remediation **quality score / rework rate** from Security review.
4. **Repeatability:** share of closures using an approved reusable pattern.
5. **Recurrence:** reopened or repeat findings after closure.
6. **Evidence completeness:** percent of closed findings with a full audit package.
7. **Exception queue size and average age** (leading indicator for wave-deadline risk).

---

## Open Questions / Risks

- **Reviewer capacity vs. throughput pressure:** throughput targets create sustained pressure on closure volume; the review workflow needs enough reviewer capacity (or clear escalation tiers) that approval doesn't become a rubber stamp under deadline pressure.
- **Exception queue long-tail risk:** pattern-matchable findings close fast; what's left tends to be the hardest cases, concentrating right before the release freeze. Needs an explicit staffing/ownership plan, not just a queue.
- **TPRM clearance timeline:** getting the AI tooling itself through the client's data/privacy/security/TPRM review is a real schedule dependency and should be tracked as a milestone, not assumed to happen in parallel for free.
