"""Stage 9 — learn.

  in:  a closed finding, or a rejected one
  out: a library write, and the cluster-propagation suggestions

Three things happen here, and the second is the one the earlier iteration of this
project missed.

  1. **A closed finding that reused a pattern** increments that pattern's
     `reuse_count` and appends provenance. That is the flywheel: reuse feeds
     retrieval ranking (`s4_retrieve`), so a pattern that keeps working keeps being
     reached for first.

  2. **A closed finding that generated fresh** becomes a `candidate` pattern.
     Candidates are recorded but never retrieved — the spec requires that new
     patterns "only enter the library through Security Engineering review", so a
     human promotes them with `harness library promote`.

  3. **A rejection is recorded too.** The spec asks for this explicitly: "Rejected or
     reworked proposals are also captured, so the triage/remediation models improve
     on real reviewer feedback over time rather than only on successes." A library
     that only remembers what worked cannot tell you what to stop doing.

Nothing here writes to a protected branch. `library/` is version-controlled; the
change lands in the working tree and a human commits it.
"""

from __future__ import annotations

import json
import os

from ..record import now


def _load(library_dir: str) -> dict:
    p = os.path.join(library_dir, "index.json")
    if not os.path.exists(p):
        return {"patterns": [], "rejections": []}
    doc = json.load(open(p, encoding="utf-8"))
    doc.setdefault("rejections", [])
    return doc


def _save(library_dir: str, doc: dict) -> None:
    os.makedirs(library_dir, exist_ok=True)
    with open(os.path.join(library_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)


def record_reuse(rec: dict, *, library_dir: str = "library") -> dict:
    doc = _load(library_dir)
    for p in doc["patterns"]:
        if p["id"] == rec["matched_pattern_id"]:
            p["reuse_count"] = p.get("reuse_count", 0) + 1
            p["last_validated"] = now()
            p.setdefault("provenance", []).append(
                {"finding_id": rec["finding_id"], "repository": rec["repository"],
                 "evidence": rec["evidence_link"], "at": now()})
            _save(library_dir, doc)
            return {"action": "reuse", "pattern_id": p["id"], "reuse_count": p["reuse_count"]}
    return {"action": "none", "reason": f"pattern {rec['matched_pattern_id']} not in the library"}


def record_candidate(rec: dict, *, store, library_dir: str = "library") -> dict:
    """A fresh fix that survived every gate and a human close. It is written as a
    candidate — recorded, not yet retrievable."""
    doc = _load(library_dir)
    pid = f"cand-{rec['category'] or 'other'}-{rec['finding_id'].lower()}"
    if any(p["id"] == pid for p in doc["patterns"]):
        return {"action": "none", "reason": f"{pid} already exists"}

    rel = os.path.join("patterns", f"{pid}.md")
    diff = open(os.path.join(store.root, rec["proposal"]["patch"]), encoding="utf-8").read()
    os.makedirs(os.path.join(library_dir, "patterns"), exist_ok=True)
    with open(os.path.join(library_dir, rel), "w", encoding="utf-8") as fh:
        fh.write(_candidate_markdown(rec, diff))

    doc["patterns"].append({
        "id": pid, "status": "candidate", "title": rec["title"][:120],
        "cwe": rec["cwe"], "category": rec["category"],
        "extensions": [(rec["location"].get("file") or "").rsplit(".", 1)[-1].lower()],
        "frameworks": [], "sink_apis": [], "tags": [],
        "path": rel.replace("\\", "/"), "reuse_count": 0, "created": now(),
        "provenance": [{"finding_id": rec["finding_id"], "repository": rec["repository"],
                        "evidence": rec["evidence_link"], "at": now()}],
    })
    _save(library_dir, doc)
    return {"action": "candidate", "pattern_id": pid,
            "note": "recorded but NOT retrievable until Security Engineering promotes it"}


def record_rejection(rec: dict, objections: list[str], *, library_dir: str = "library") -> dict:
    """What a reviewer refused, and why. Feeds the model-evaluation KPI (reviewer
    override rate) and gives the next prompt real negative examples."""
    doc = _load(library_dir)
    doc["rejections"].append({
        "finding_id": rec["finding_id"], "cwe": rec["cwe"], "category": rec["category"],
        "pattern_id": rec.get("matched_pattern_id"), "round": rec["rounds"],
        "objections": objections, "at": now(),
    })
    _save(library_dir, doc)
    return {"action": "rejection", "count": len(doc["rejections"])}


def flag_pattern(pattern_id: str, reason: str, *, library_dir: str = "library") -> dict:
    """Recurrence handling. When a closed finding reopens, the pattern that produced
    its fix is flagged for review — the fix looked right, passed its gates, and the
    vulnerability came back, so the pattern is the thing to doubt."""
    doc = _load(library_dir)
    for p in doc["patterns"]:
        if p["id"] == pattern_id:
            p.setdefault("flags", []).append({"reason": reason, "at": now()})
            _save(library_dir, doc)
            return {"action": "flagged", "pattern_id": pattern_id}
    return {"action": "none", "reason": f"{pattern_id} not in the library"}


def propagate(rec: dict, *, store) -> dict:
    """The cluster payoff. A fix validated on one member is offered to the rest of its
    family — as a **suggestion**, carrying the pattern and the evidence. Each one is
    still triaged, proposed, approved and validated on its own. Nothing is applied in
    bulk, because a cluster is a similarity claim, not a proof."""
    if not os.path.exists(store.clusters) or not rec.get("cluster_id"):
        return {"suggested": []}
    clusters = json.load(open(store.clusters, encoding="utf-8"))["clusters"]
    siblings = [f for f in clusters.get(rec["cluster_id"], {}).get("members", [])
                if f != rec["finding_id"]]
    by_id = {r["finding_id"]: r for r in store.read_all()}
    open_siblings = [f for f in siblings if by_id.get(f, {}).get("status") not in ("closed",)]
    for f in open_siblings:
        r = by_id[f]
        r.setdefault("suggestions", []).append(
            {"from": rec["finding_id"], "pattern_id": rec.get("matched_pattern_id"),
             "evidence": rec["evidence_link"], "at": now()})
        store.put(r)
    return {"cluster_id": rec["cluster_id"], "suggested": open_siblings}


def run(rec: dict, *, store, library_dir: str = "library") -> dict:
    out = (record_reuse(rec, library_dir=library_dir) if rec.get("matched_pattern_id")
           else record_candidate(rec, store=store, library_dir=library_dir))
    out["propagation"] = propagate(rec, store=store)
    return out


def _candidate_markdown(rec: dict, diff: str) -> str:
    return f"""# {rec['title'][:120]}

- **status**: candidate — not retrievable until promoted
- **cwe**: {rec['cwe']}
- **category**: {rec['category']}
- **origin**: {rec['finding_id']} in `{rec['repository']}`
- **evidence**: `{rec['evidence_link']}`

## Root cause

{rec.get('root_cause') or '(not recorded)'}

## The transform

{(rec.get('proposal') or {}).get('explanation', '(not recorded)')}

```diff
{diff}
```

## Required test

`{(rec.get('proposal') or {}).get('test_name', '')}` — must fail against the
unpatched code for the right reason, and pass against the patched code.

## Before promoting

- [ ] Generalize the diff: strip anything specific to this repository.
- [ ] Fill `frameworks`, `sink_apis` and `tags` in `index.json` so retrieval can score it.
- [ ] Confirm Security Engineering has reviewed the transform, not just this instance.
"""
