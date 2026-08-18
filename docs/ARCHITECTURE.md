# Architecture

How the harness is built, and why. Read `PRODUCT_SPEC.md` first — that is the
requirement. This is the answer to it.

---

## The one idea

A **harness** is not the model. It is the machinery around the model that makes the
model's output trustworthy: what context goes in, what shape comes back, what gates
it must pass, what gets written down, and who is allowed to say yes.

So the model is the smallest part of this repository. Three calls, in three places,
each with a prompt file you can read and a JSON schema it must satisfy. Everything
else is ordinary Python you can step through.

---

## The pipeline

Ten stages. Each is one file. Each reads JSON, writes JSON, and does one thing.

```
scanner file
     │
     ▼
 s1_ingest ──────► findings.jsonl          status: new
     │
     ▼
 s2_cluster ─────► clusters.json           cluster_id set on every record
     │
     ▼
 s3_triage ──────► category, root_cause,   status: triaged
     │             confidence_score          (or exception: low-confidence)
     ▼
 s4_retrieve ────► ranked patterns from library/
     │
     ▼
 s5_propose ─────► patches/<id>.diff       status: proposed
     │
     ▼
 s6_approve ─────► human signs             status: approved
     │                                       (or exception: rejected)
     ▼
 s7_validate ────► build · test · rescan   status: validated
     │             → evidence/<id>/          (or exception: gate-failed)
     ▼
 s8_close ───────► evidence sealed         status: closed
     │
     ▼
 s9_learn ───────► library write-back (successes AND rejections)
     │
     ▼
 s10_report ─────► metrics.json (the 7 KPIs) ──► dashboard
```

Every stage is idempotent and resumable. You can run one stage, inspect the run
directory, and run the next. Nothing is held in memory between stages — the run
directory *is* the state.

---

## The run directory

One invocation of the harness produces one run directory. It is the whole state.

```
runs/<run-id>/
  raw/                 original scanner payloads, byte-for-byte, never edited
  findings.jsonl       one vulnerability record per line
  clusters.json        cluster_id → member finding_ids, and the fingerprint basis
  audit.jsonl          append-only. one line per status change
  llm/                 every model request and response, as sent and as received
  patches/<id>.diff    proposed changes, never applied to the target repo
  evidence/<id>/       sealed after validation: artifacts + sha256 manifest
  metrics.json         the seven KPIs, derived from audit.jsonl
```

Two properties matter and both are mechanical:

- **`raw/` is never edited.** Traceability back to what the scanner actually said.
- **`evidence/` is sealed once** — files written, `chmod 444`, sha256 recorded. A
  later revision writes `round-2/`; it never rewrites `round-1/`.

---

## The record

Fields are the spec's Data Model table, unchanged. Nothing renamed to sound better.

| Field | Set by |
|---|---|
| `finding_id` | `s1_ingest` |
| `source_scanner`, `source_rule_id` | `s1_ingest` |
| `repository`, `portfolio` | `s1_ingest`, from `targets.yaml` |
| `category`, `cwe`, `severity` | `s1_ingest`, refined by `s3_triage` |
| `root_cause` | `s3_triage` (model) |
| `cluster_id` | `s2_cluster` |
| `confidence_score` | `s3_triage` (model, self-reported) |
| `matched_pattern_id` | `s4_retrieve` / `s5_propose` |
| `status` | only ever by `record.transition()` |
| `approver` | `s6_approve`, a human identity |
| `evidence_link` | `s7_validate` |
| `timestamps` | each stage stamps its own |

---

## The status machine

The spec's order, verbatim:

```
new ──► triaged ──► proposed ──► approved ──► validated ──► closed
 │         │            │            │            │
 └─────────┴────────────┴────────────┴────────────┴──────► exception
                                                              │
                                            (governance lead) │
                        triaged ◄─────────────────────────────┘
```

`closed → triaged` also exists, and is how **recurrence** works: a finding that
reopens re-enters at triage carrying a link to its original evidence package.

### A deliberate divergence, stated

The spec approves **before** validating: a Security Reviewer signs off on a
proposal, then CI proves it. That is what this harness implements, by default.

It has a cost, and the spec names it in its own Open Questions: *"the review
workflow needs enough reviewer capacity… that approval doesn't become a rubber
stamp under deadline pressure."* Approving unvalidated patches spends the scarcest
resource in the program on proposals that CI may reject anyway.

So gate order is a policy, not a hardcode. `config.yaml`:

```yaml
gate_order: spec        # approve → validate   (default, matches the spec)
# gate_order: validate-first   approve only what already passed its gates
```

We follow the client's workflow and we say what it costs. We do not silently
invert it.

---

## Where the AI is

Three calls. That is the complete list.

| Stage | Prompt | Schema | The model decides |
|---|---|---|---|
| `s3_triage` | `prompts/triage.md` | `TRIAGE_SCHEMA` | category, root cause, its own confidence |
| `s5_propose` | `prompts/propose.md` | `PROPOSE_SCHEMA` | the diff, and the regression test |
| `s6_approve` | `prompts/review.md` | `REVIEW_SCHEMA` | an **advisory** verdict — a human still signs |

Every call goes through `harness/provider.py`, which:

1. redacts the prompt (`redact.py`) before it leaves the process,
2. writes the request to `runs/<id>/llm/<n>-request.json`,
3. calls the provider,
4. validates the response against its schema — a response that does not fit is a
   failure, not something to be coerced,
5. writes the response to `runs/<id>/llm/<n>-response.json`.

So "what did the AI actually see, and what did it actually say" is a file, per call,
every time.

### Providers

| Provider | What it does | Use |
|---|---|---|
| `mock` | replays recorded JSON from `fixtures/llm/` | tests, and the offline demo |
| `claude-code` | writes the request to disk for the surrounding Claude Code session to answer | live judgement without an API key |
| `anthropic` | direct API call | when a key exists |

The mock provider is not a toy. It is how the test suite pins behaviour, and it is
why the demo runs in four seconds with no network.

---

## Clustering, and why there is no embedding model

The spec asks for deterministic fingerprints for exact duplicates and *"embeddings +
clustering"* for near-duplicates. It also requires that **no embeddings leave
client-controlled infrastructure**.

`s2_cluster.py` does both halves without an embedding model:

- **Exact:** `sha256(source_scanner, repository, source_rule_id, normalized_path)`.
  Same rule, same file, same repo — one cluster, no judgement needed.
- **Near:** character-trigram Jaccard similarity over the normalized code snippet,
  single-link agglomeration above a threshold. Same root cause, different location
  or wording.

Trigram Jaccard is a lexical similarity measure: it needs no model, no GPU, no
network, and no vector store, it is ~40 lines, and its output is explainable — you
can print the shared trigrams that caused two findings to merge. A cosine distance
from an embedding cannot be audited; a shared-trigram list can.

This is a real trade-off, not a free win. Trigrams miss semantic similarity that
embeddings would catch — two findings with the same root cause and no shared text
land in different clusters. The seam for upgrading is `s2_cluster.similarity()`,
one function, one signature.

**Why clustering carries the whole economic case:** Thousands of findings that collapse
into a few hundred remediation families is the difference between a program that
finishes and one that does not. A fix validated on one member is proposed to the
rest of its family — reviewed individually, never auto-applied.

---

## Confidence, and the threshold that is not global

`s3_triage` asks the model for a `confidence_score` in `[0,1]` alongside its
classification. `thresholds.yaml` sets the floor **per category × per portfolio**,
because the spec is explicit that a global threshold is wrong: *"a threshold tuned
on simple quick-win findings is not assumed to generalize."*

Below the floor, the finding becomes `exception: low-confidence` and goes to the
manual queue. It is never auto-classified with a default. When the model is
unavailable, findings **queue at `new`** — they do not receive a fallback
classification. Both behaviours are spec requirements, and both are tested.

---

## Roles

`roles.yaml` maps an identity to a persona. `roles.py` declares which persona may
perform which transition.

| Transition | Who |
|---|---|
| `new → triaged`, `triaged → proposed`, `approved → validated` | `harness` (the machine) |
| `proposed → approved` | **`security_reviewer` only** |
| `validated → closed` | `portfolio_owner` |
| `exception → triaged` | `governance_lead` |
| anything | never `audit_viewer` |

This is not SSO and does not pretend to be. It is the authorization *model* — the
list of who may do what — implemented and enforced at the one place status changes
happen. Wiring it to a real identity provider is a connector, not a redesign.

---

## Secrets

The product exists partly to fix leaked credentials. Its own pipeline must not
become the next place they leak.

`redact.py` runs over every finding's free-text fields at ingest, and over every
prompt before it reaches a provider. Two detectors: known-shape patterns (AWS keys,
private key headers, JWTs, connection strings) and Shannon entropy over
`[A-Za-z0-9+/=_-]{20,}` tokens. Matches become `<REDACTED:sha256[:8]>` — the same
secret redacts to the same token, so clustering still works on the shape of a
finding without storing its content.

---

## The three gates

`s7_validate` runs them in order and stops at the first failure. Commands come from
`targets.yaml` — the harness runs the project's own build, it does not invent one.

| Gate | Passes when |
|---|---|
| **build** | exit 0 |
| **test** | suite green **and** the new regression test both ran and passed |
| **rescan** | the originating rule no longer fires **and** no new finding appeared |

Three verdicts: `pass`, `fail`, `unavailable`.

**`unavailable` is not `pass`.** A gate whose toolchain is missing records what it
could not run and blocks closure. This is the single rule the whole evidence
contract rests on: a receipt that overstates what ran is worse than no receipt.

---

## The dashboard

`harness serve` starts a `http.server` that implements **GET and nothing else**.
There is no POST handler, no PUT, no DELETE — not disabled, absent.

The spec requires it: *"no dashboard action can change a finding's status: status
changes only happen through the approval/validation workflow."* The way to be sure
of that is to not write the code.

It reads `metrics.json` and renders the seven KPIs, the burn-down, and the exception
queue with its age.

---

## What this is not

- Not a scanner. It consumes findings; it does not find them.
- Not a sandbox. It runs on repositories you already trust with your session.
- Not a deployment tool. It produces a proposal and a receipt. A human merges.
- Not SSO, not pgvector, not a ticketing integration. See `TRACEABILITY.md`, which
  marks each of those ✗ with a reason rather than implying coverage.

---

## Prior art

Built after reading three references, and it borrows from each on purpose:

- **`anthropics/defending-code-reference-harness`** — the flow shape, and the rule
  that a finding is data, never instructions.
- **Visa's vulnerability agentic harness** — the separation that matters most: the
  thing that proposes a fix and the thing that judges it are different components
  with different permissions.
- **DeepSeek Harness (`dsh`)** — that a harness should be a runnable thing with a
  visible loop, not a description of one. Also a cautionary note: its web control
  plane shipped with no authentication (repo Discussion #853), which is why this
  dashboard is GET-only by construction.

An earlier iteration of this work exists at `rachitt/vulnerability-remediation`,
built as a Claude Code plugin. This is a rebuild, not a fork: the pipeline is
deterministic Python so that every step can be read, run, and explained.
