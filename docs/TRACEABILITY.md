# Requirements traceability

Every requirement in `PRODUCT_SPEC.md`, mapped to the code that satisfies it —
or marked **not built**, with a reason.

**Quotes are verbatim from the spec.** If a line is in quotation marks here, it
appears character-for-character in the source document. Where this document
paraphrases, it does not use quotation marks. That distinction is the point of the
file: a traceability matrix that misquotes its own source is worse than none.

| | Meaning |
|---|---|
| ✅ | built, and a test pins it |
| ◐ | partly built; the gap is stated |
| ✗ | **not built.** The reason is stated. Not a plan, a fact. |

---

## A. Product Goals

| # | Requirement | Where | |
|---|---|---|---|
| A1 | "Create one normalized view of findings from existing the client security tools." | `stages/s1_ingest.py` — SARIF 2.1.0, Semgrep JSON, CSV, JSON list → one record shape. Format detected by document shape, never filename. | ✅ |
| A2 | "Reduce manual triage using AI classification, root cause analysis, and prioritization." | `stages/s3_triage.py` — category, CWE, root cause, and a self-reported confidence. Prioritization is severity ordering plus cluster size. | ✅ |
| A3 | "Identify repeated issues using deterministic matching and clustering." | `stages/s2_cluster.py` — sha256 fingerprint for exact, trigram Jaccard for near. | ✅ |
| A4 | "Convert common root cause patterns into approved, reusable remediation patterns." | `stages/s9_learn.py` `record_candidate` → `harness library --promote`. A candidate is never retrievable until a human promotes it. | ✅ |
| A5 | "Generate portfolio/repository-specific remediation recommendations." | `stages/s5_propose.py` — the prompt carries the actual file. **Repository**-specific: yes. **Portfolio**-wide roll-up across many repos: the dashboard shows one run at a time. | ◐ |
| A6 | "Validate remediations through existing CI/CD and security testing before closure." | `stages/s7_validate.py` — runs the project's own commands from `targets.yaml`. Running inside the client's CI *runners* rather than locally: ✗, see F3. | ◐ |
| A7 | "Automatically create audit-ready evidence with complete traceability." | `runstore.seal` / `verify_evidence` — write-once, mode 444, sha256 manifest. | ✅ |

## B. Product Flow — the ten steps

| Step | Where | |
|---|---|---|
| 1 Ingest | `s1_ingest.py` | ✅ |
| 2 Normalize | `s1_ingest.py` + `record.new_record` | ✅ |
| 3 "Deduplicate exact matches and cluster similar findings." | `s2_cluster.py` | ✅ |
| 4 AI triage: "classify, infer root cause, and recommend a remediation cluster." | `s3_triage.py` | ✅ |
| 5 "Retrieve approved remediation patterns and the client guidance through RAG." | `s4_retrieve.py` | ◐ — retrieval is lexical scoring over the pattern library, not embeddings. See C4. |
| 6 Remediation agent | `s5_propose.py` | ✅ |
| 7 "Route the proposal through a security owner for approval." | `s6_approve.py` + `roles.py` | ✅ |
| 8 CI/CD tests + re-scan | `s7_validate.py`, `tools/rescan.py` | ✅ |
| 9 Evidence, "only after validation and approval" | `s8_close.py` — close re-verifies hashes first | ✅ |
| 10 "Feed accepted fixes back into the remediation knowledge base." | `s9_learn.py` | ✅ |

## C. Core Product Components

| # | Requirement | Where | |
|---|---|---|---|
| C1 | "Connect to scanner/ticketing APIs where available; otherwise support controlled CSV/JSON ingestion." | CSV/JSON/SARIF file ingestion is built. **API connectors are ✗** — every scanner and ticketing system has its own auth and pagination, and there is no client endpoint to build against. `s1_ingest.run` takes a path; a connector is a function that produces one. | ◐ |
| C2 | "Preserve the original payload and finding_ID for traceability." | `raw/` holds the file byte-for-byte; `raw_ref` points at the row. Ids are assigned by the harness and never carried from the scanner. | ✅ |
| C3 | "Use deterministic fingerprints (scanner, repository, rule ID, file path) for exact/high-confidence duplicates." | `s2_cluster.fingerprint` — those four fields, in that order. | ✅ |
| C4 | "Use embeddings + clustering to group near-duplicate findings" | **Deliberately not embeddings.** Character-trigram Jaccard instead. The same spec requires that no "embeddings leave the client-controlled infrastructure", and a lexical measure needs no model, no vector store, and no network — and can be *explained*: `s2_cluster.explain()` prints the shared trigrams that merged two findings. The cost: trigrams miss semantic similarity with no shared text. `similarity()` is the one-function seam. | ◐ |
| C5 | "Persist cluster membership so a fix applied to one member can be propagated as a suggestion to the rest of its cluster." | `cluster_id` on every record; `s9_learn.propagate` writes a `suggestions` entry on each open sibling. A suggestion, never an application. | ✅ |
| C6 | "Assigns a confidence score to its own classification." | `TRIAGE_SCHEMA` requires `confidence_score` in [0,1]; a response without it fails. | ✅ |
| C7 | "Below a defined confidence threshold, routes the finding to manual triage instead of auto-classifying." | `s3_triage.run` → `exception: low-confidence`. Never a default classification. | ✅ |
| C8 | "Version-controlled library of approved fix patterns" | `library/` is git-tracked; `index.json` + one markdown file per pattern. | ✅ |
| C9 | "Each pattern includes: description, code/config example, required tests, and closure evidence template." | All four sections are present in both seeded patterns and in the generated candidate template. | ✅ |
| C10 | "New patterns can only enter the library through Security Engineering review" | `record_candidate` writes `status: candidate`; `s4_retrieve.load_library` returns only `status: approved`. A candidate is recorded and unreachable. | ✅ |
| C11 | "deprecated patterns are flagged so the remediation agent stops recommending them" | `flag_pattern()` records a flag on recurrence. **Automatic exclusion of a flagged pattern from retrieval is ✗** — a flag today is advisory to the human who reads it. | ◐ |
| C12 | "Never writes directly to a protected branch: output is always a proposal" | The harness writes a `.diff` into the run directory. It has no git write path at all — not to a branch, protected or otherwise. | ✅ |
| C13 | "Attaches the finding ID, matched pattern ID, and confidence score to every proposal" | All three live on the record and in the sealed manifest. | ✅ |
| C14 | "Every AI-generated proposal requires sign-off from a role-appropriate Security Reviewer before it proceeds to validation." | `roles.PERMITTED[("proposed","approved")] == ("security_reviewer",)`. `--actor` has no default. | ✅ |
| C15 | "Approval, rejection, and any manual edits are logged against the finding record (who, when, what changed)." | `audit.jsonl` — actor, persona, timestamp, from, to, reason, round. | ✅ |
| C16 | "findings with low AI confidence, no matching pattern, or reviewer rejection route to a manual exception queue rather than blocking the pipeline." | All three routes exist. Note: no matching pattern does **not** send a finding to the queue — it generates fresh, which is the case the library learns from. Only a *failed* generation does. | ◐ |
| C17 | "Re-runs the original scanner(s) against the changed code to confirm the finding is no longer detected, not just that a diff was merged." | `tools/rescan.py` — two scans, before and after, checking this finding's rule at this finding's line, plus that no new finding kind appeared. | ✅ |
| C18 | "A fix is not eligible for closure until both test validation and re-scan confirmation pass." | `overall == "passed"` requires all three gates; anything else routes to exception. | ✅ |
| C19 | "Evidence packages are immutable once generated" | Write-once, mode 444, sha256 manifest, re-sealing refused. **Not a WORM store** — a local root user can chmod a file back. Any such change is *detectable*, which is what auditability requires. True immutability needs object-lock storage: ✗. | ◐ |
| C20 | "Supports the client's risk exception/waiver process by attaching the same evidence structure to accepted-risk findings." | `s8_close.accept_risk` — refuses an empty justification. | ✅ |
| C21 | "Live view of findings by status, category, portfolio, cycle time, and closure volume." | `harness serve` — all except portfolio breakdown, which needs multiple runs. | ◐ |
| C22 | "no dashboard action can change a finding's status" | `dashboard/serve.py` defines `do_GET` and nothing else. A test asserts no `do_POST`/`do_PUT`/`do_DELETE`/`do_PATCH` exists in the source. | ✅ |
| C23 | "Rejected or reworked proposals are also captured, so the triage/remediation models improve on real reviewer feedback" | `s9_learn.record_rejection` → `index.json.rejections`, with the objections. | ✅ |

## D. Data Model

Every field in the spec's table exists on the record, spelled as the spec spells it —
see `record.new_record`. `repository` and `portfolio` are separate fields.

The status values are the spec's, in the spec's order:
`new → triaged → proposed → approved → validated → closed`, plus `exception`. ✅

**One deliberate note on order.** The spec approves *before* validating. This harness
implements that, by default. It also costs the scarcest thing in the programme —
reviewer attention — on patches CI may reject anyway, which is the spec's own Open
Question #1. `config.yaml: gate_order` makes the order a policy, defaulting to the
spec's. Documented in `ARCHITECTURE.md`. **The `validate-first` mode is declared but
not yet implemented: ✗.**

## E. AI Component Specification

| # | Requirement | Where | |
|---|---|---|---|
| E1 | "no source code, findings, or embeddings leave the client-controlled infrastructure" | The harness itself makes no network call. Clustering uses no embedding service. **But model inference goes wherever the provider is configured to send it** — that is a property of the deployment, not of this code. `mock` and `claude-code` providers make no outbound call from this process. | ◐ |
| E2 | "findings that contain live credentials or secrets are redacted/tokenized before embedding or indexing" | `redact.py`, run at ingest and again on every prompt before it reaches a provider. Shape detectors plus Shannon entropy; the same secret always produces the same token. | ✅ |
| E3 | "calibrated per vulnerability category and portfolio, not globally" | `thresholds.yaml` — portfolio+category, then portfolio, then category, then global. Tested. | ✅ |
| E4 | "no proposal is trusted on the model's word" | Every model response is schema-validated before use; every patch passes three gates; a human signs. | ✅ |
| E5 | "patterns are versioned; changes require Security Engineering approval" | `library/` is git-tracked, so version history is git's. `status: candidate` gates entry. **A formal version field and a deprecation lifecycle are ✗** — today a pattern is approved or candidate. | ◐ |
| E6 | "triage and remediation agent performance (classification accuracy, pattern-match precision, reviewer override rate) is tracked over time as a first-class metric" | `metrics.json.model_evaluation` — mean confidence, count sent to manual triage, pattern-match precision, reviewer override rate. **"Classification accuracy" proper is ✗**: it needs a labelled ground-truth set, which does not exist yet. Reviewer override rate is the available proxy and is labelled as such. | ◐ |

## F. Non-Functional Requirements

| # | Requirement | Where | |
|---|---|---|---|
| F1 | "role-based access control (RBAC) aligned to the personas above; approval actions restricted to authorized Security Reviewers" | `roles.py` — the authorization *model*, enforced at the one place status changes happen. **Authentication is ✗.** `roles.yaml` maps a string to a persona; nothing proves the caller is that string. Wiring to SSO changes `personas_of` and nothing else. | ◐ |
| F2 | "full action-level audit logging" | `audit.jsonl`, append-only, `verify_audit()` replays it against the state machine. | ✅ |
| F3 | "designed for a backlog in the low thousands of High-priority findings" | Records are independent; each stage is resumable; the run directory is the state. Clustering is the O(n²) step — fine at 4,000, and `_groups_similar` is where a blocking strategy would go. **Not load-tested above the sample corpus: ✗.** The sample corpus is 6 findings. | ◐ |
| F4 | "ingestion and dashboard components available during the client business hours at minimum" | A local CLI and a local server. **Availability as an operated service is ✗** — there is nothing to operate; this is not deployed anywhere. | ✗ |
| F5 | "every state change on a finding is logged with actor, timestamp, and reason" | `record.transition` refuses an empty reason. Tested. | ✅ |
| F6 | "evidence packages are immutable and retained per the client audit retention policy" | Immutable-and-detectable, per C19. **Retention policy is ✗** — nothing expires or archives anything. | ◐ |
| F7 | "all AI tooling and any third-party model dependency is subject to the client data, privacy, security, and Third-Party Risk Management review before production use" | Not a software requirement. Relevant property: the harness runs offline with `--provider mock`, so it can be reviewed before any model is approved. | n/a |

## G. Failure Modes

| Requirement | Behaviour | |
|---|---|---|
| "Scanner/ticketing API unavailable: ingestion falls back to controlled CSV/JSON import; no findings are silently dropped." | Every input row becomes a record or a `skipped` entry with a reason. Tested. | ✅ |
| "AI service unavailable: findings queue for triage rather than blocking ingestion; no default/fallback auto-classification is applied." | A `ProviderError` leaves the record at `new` and reports it. There is no fallback classification path in the code. | ✅ |
| "finding routes to the manual exception queue, owned by the Program Governance Lead, with age/size tracked on the dashboard" | `metrics.json.kpi.exception_queue` carries size, mean age, oldest, and a breakdown by reason; the dashboard shows all four. | ✅ |
| "a failed build blocks that specific change without affecting others in the batch" | Each finding validates in its own scratch copy. One failure affects one finding. | ✅ |
| "Reopened findings re-enter the pipeline at triage with a link to the original evidence package, and the originating pattern is flagged for review." | `record.reopen` + `flag_pattern`. **The recurrence *detector* — noticing that an incoming finding matches a closed one — is ✗.** The mechanism exists; nothing calls it automatically yet. | ◐ |

## H. Out of Scope — verified absent

These are requirements to **not** do things.

| Requirement | How it is guaranteed |
|---|---|
| "does not have production deployment authority" | No deploy, no push, no merge, no branch write anywhere in the codebase. |
| "does not replace the client's existing scanners, source control, CI/CD" | Gate commands come from `targets.yaml` and are the project's own. |
| "No fix is ever auto-approved or auto-closed without human sign-off" | `--actor` is required and resolved through `roles.yaml`. The one exception is `--auto-review`, which is off by default, must be enabled in `config.yaml`, exists for unattended demos, and logs `actor=demo:auto-review` — never a person's name. |
| "Medium and Low-priority findings are out of scope for the initial build" | Not enforced — the harness will process any severity. Prioritization is by severity order. Treated as a scoping statement, not a constraint to implement. |

## I. KPIs

All seven are computed in `stages/s10_report.py`, derived from `audit.jsonl`
timestamps rather than estimated.

| KPI | Field |
|---|---|
| "Average remediation cycle time per finding, by category" | `kpi.cycle_time.by_category_hours` |
| "Count of high findings closed per wave and cumulative burn-down" | `kpi.burn_down` — **per *wave* is ✗**; there is no wave concept yet. Per run, and cumulative within a run. |
| "Remediation quality score / rework rate from Security review" | `kpi.rework_rate` |
| "Repeatability: share of closures using an approved reusable pattern" | `kpi.repeatability` |
| "Recurrence: reopened or repeat findings after closure" | `kpi.recurrence` — counts `closed → triaged` transitions |
| "Evidence completeness: percent of closed findings with a full audit package" | `kpi.evidence_completeness` — re-verifies the hashes, so a tampered package does not count as complete |
| "Exception queue size and average age" | `kpi.exception_queue` |

---

## The ✗ list, in one place

Nothing below is built. Each is a real gap, not a phase-2 euphemism.

1. **Scanner and ticketing API connectors.** File ingestion only.
2. **Authentication.** The authorization model is enforced; identity is asserted, not proven.
3. **Embedding-based clustering.** Lexical similarity instead, for the reason in C4.
4. **`gate_order: validate-first`.** Declared in config, not implemented.
5. **Automatic exclusion of flagged/deprecated patterns from retrieval.** Flags are advisory.
6. **A recurrence detector.** `reopen()` and `flag_pattern()` exist; nothing calls them on ingest.
7. **True WORM evidence storage.** Tamper-evident, not tamper-proof.
8. **Evidence retention/archival policy.**
9. **Classification accuracy against labelled ground truth.** No labelled set exists.
10. **Load testing at realistic backlog size.** The sample corpus is 6.
11. **Per-wave and per-portfolio roll-up.** One run at a time.
12. **Running gates inside the client's own CI runners.** Gates run locally, using the project's commands.
13. **Deployment of any kind.** This is a CLI and a local server.
