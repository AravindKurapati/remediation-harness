"""Stage 4 — retrieve.

  in:  one triaged record
  out: a ranked list of approved patterns from library/, each with a `why`

This is the RAG step, and it runs **before** the model is asked to write anything.
That ordering is the whole reuse claim: the remediation agent starts from a transform
the client has already approved, rather than from the model's general knowledge.

**This function's signature is the retrieval seam.** Callers depend on
`retrieve(record) -> matches`, and on nothing about how patterns are stored. Swapping
the file-backed library for Postgres + pgvector is a change inside this file.

Scoring is deterministic and every point is explained. A pattern that surfaces
carries the list of reasons it surfaced, and those reasons go in the audit trail. A
cosine distance is not reviewable; "matched CWE-89 (+5), same framework (+2), reused
7 times (+0.7)" is.
"""

from __future__ import annotations

import json
import os

FLOOR = 5.0        # below this, a pattern is not offered at all — generate fresh instead

WEIGHTS = {
    "cwe":       5.0,   # the weakness class must match; nothing else compensates
    "category":  2.0,
    "ecosystem": 2.0,
    "framework": 2.0,
    "sink_api":  1.5,
    "tag":       0.5,   # per shared tag, capped
}


def load_library(library_dir: str = "library") -> list[dict]:
    """Approved patterns only. `candidate` patterns are recorded but never retrieved —
    a fix that has not passed Security Engineering review must not be reachable by an
    agent that would then apply it."""
    index_path = os.path.join(library_dir, "index.json")
    if not os.path.exists(index_path):
        return []
    index = json.load(open(index_path, encoding="utf-8"))
    return [p for p in index.get("patterns", []) if p.get("status") == "approved"]


def score(pattern: dict, rec: dict) -> tuple[float, list[str]]:
    points, why = 0.0, []

    if pattern.get("cwe") and pattern["cwe"] == rec.get("cwe"):
        points += WEIGHTS["cwe"]
        why.append(f"matched {rec['cwe']} (+{WEIGHTS['cwe']})")
    elif pattern.get("cwe") and rec.get("cwe"):
        return 0.0, [f"different weakness class: pattern is {pattern['cwe']}, "
                     f"finding is {rec['cwe']}"]

    if pattern.get("category") and pattern["category"] == rec.get("category"):
        points += WEIGHTS["category"]
        why.append(f"same category {rec['category']} (+{WEIGHTS['category']})")

    eco = (rec.get("location") or {}).get("file", "").rsplit(".", 1)[-1].lower()
    if eco and eco in (pattern.get("extensions") or []):
        points += WEIGHTS["ecosystem"]
        why.append(f"applies to .{eco} files (+{WEIGHTS['ecosystem']})")

    blob = f"{rec.get('snippet', '')} {rec.get('title', '')} {rec.get('root_cause') or ''}".lower()

    for fw in pattern.get("frameworks", []):
        if fw.lower() in blob:
            points += WEIGHTS["framework"]
            why.append(f"framework {fw} appears in the finding (+{WEIGHTS['framework']})")
            break

    for api in pattern.get("sink_apis", []):
        if api.lower() in blob:
            points += WEIGHTS["sink_api"]
            why.append(f"sink API {api} appears in the finding (+{WEIGHTS['sink_api']})")
            break

    shared = [t for t in pattern.get("tags", []) if t.lower() in blob][:4]
    if shared:
        points += WEIGHTS["tag"] * len(shared)
        why.append(f"tags {', '.join(shared)} (+{WEIGHTS['tag'] * len(shared)})")

    # A pattern that keeps working keeps getting reached for first. This is the
    # flywheel: reuse feeds ranking, capped so an old pattern cannot outrank a
    # better-matching new one on history alone.
    reuse = min(pattern.get("reuse_count", 0), 10) * 0.1
    if reuse:
        points += reuse
        why.append(f"reused {pattern['reuse_count']} times (+{reuse:.1f})")

    return round(points, 2), why


def retrieve(rec: dict, *, library_dir: str = "library", top: int = 3) -> dict:
    """The seam. Returns the document every downstream component reads."""
    scored = []
    set_aside = []
    for p in load_library(library_dir):
        pts, why = score(p, rec)
        entry = {"pattern_id": p["id"], "title": p.get("title", ""), "score": pts, "why": why,
                 "path": p.get("path"), "reuse_count": p.get("reuse_count", 0)}
        (scored if pts >= FLOOR else set_aside).append(entry)

    scored.sort(key=lambda e: (-e["score"], e["pattern_id"]))
    set_aside.sort(key=lambda e: (-e["score"], e["pattern_id"]))

    return {
        "finding_id": rec["finding_id"],
        "floor": FLOOR,
        "matches": scored[:top],
        "set_aside": set_aside[:top],
        "generate_fresh": not scored,
    }


def body(pattern_id: str, library_dir: str = "library") -> str:
    """The pattern's markdown, for the prompt. Read at retrieval time so the prompt
    carries the transform itself, not a pointer to it."""
    for p in load_library(library_dir):
        if p["id"] == pattern_id:
            path = os.path.join(library_dir, p["path"])
            if os.path.exists(path):
                return open(path, encoding="utf-8").read()
    return ""


def run(rec: dict, *, library_dir: str = "library") -> dict:
    result = retrieve(rec, library_dir=library_dir)
    rec["matched_pattern_id"] = result["matches"][0]["pattern_id"] if result["matches"] else None
    return result
