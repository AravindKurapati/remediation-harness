"""Stage 2 — cluster.

  in:  runs/<id>/findings.jsonl
  out: runs/<id>/clusters.json, and `cluster_id` set on every record

This stage carries the economic case for the whole product. A backlog in the
thousands that collapses into a few hundred remediation families is the difference
between a programme that finishes before the release freeze and one that does not. A fix
validated on one member becomes a *suggestion* to the rest of its family — reviewed
individually, never auto-applied.

Two passes, as the spec asks for:

  exact  sha256(scanner, repository, rule_id, normalized path)
         Same rule, same file, same repo. No judgement needed, so none is used.

  near   character-trigram Jaccard similarity over the normalized snippet, merged by
         single-link agglomeration above a threshold. Same root cause, different
         location or wording.

**Why trigrams and not embeddings.** The spec asks for "embeddings + clustering" and
in the same document forbids embeddings leaving client infrastructure. Trigram Jaccard
needs no model, no GPU, no network and no vector store; it is forty lines; and its
output is auditable — `explain()` prints the shared trigrams that merged two
findings. A cosine distance cannot be defended to an auditor; a shared-substring
list can.

The cost is real: trigrams are lexical, so two findings with the same root cause and
no shared text land in different clusters. `similarity()` is the seam — one function,
one signature — if that trade stops being worth it.
"""

from __future__ import annotations

import hashlib
import json
import re

#: Tuned against the sample corpus, where two instances of one bug score 0.42-0.63
#: and unrelated findings score 0.00-0.25. Overridable per run; it is a tuning
#: decision, not a constant of nature, and it should be re-tuned per client corpus.
NEAR_THRESHOLD = 0.35

#: Normalization removes what VARIES between two instances of the same bug and keeps
#: what does not.
#:
#: An earlier version of this file blanked whole string literals, and that was wrong:
#: the SQL text inside the literal is exactly the structure two instances share.
#: Blanking it reduced
#:     query = "SELECT id FROM accounts WHERE name = '" + name + "'"
#: to  query = 'S' + name + 'S'
#: which carries almost no signal, and near-duplicate detection stopped working while
#: still appearing to (the exact-fingerprint pass was doing all the merging).
#: Quote style and digit values are incidental; SQL keywords are not.
_NUMBER = re.compile(r"\b\d+\b")
_SPACE = re.compile(r"\s+")
_QUOTE = re.compile(r"""['"`]""")


def normalize(snippet: str) -> str:
    s = _QUOTE.sub('"', snippet)      # ' " ` are interchangeable across languages
    s = _NUMBER.sub("N", s)           # a literal 42 and a literal 7 are the same shape
    return _SPACE.sub(" ", s).strip().lower()


def trigrams(s: str) -> set[str]:
    s = normalize(s)
    return {s[i:i + 3] for i in range(len(s) - 2)} if len(s) >= 3 else set()


def similarity(a: str, b: str) -> float:
    """Jaccard overlap of character trigrams: |shared| / |combined|, in [0,1].

    This is the seam. Replacing it with a vector similarity is a change to this
    function and nothing else in the file."""
    ta, tb = trigrams(a), trigrams(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def explain(a: str, b: str, limit: int = 12) -> list[str]:
    """The shared trigrams that merged two findings. This is what makes the cluster
    checkable by a human instead of taken on faith."""
    return sorted(trigrams(a) & trigrams(b))[:limit]


def fingerprint(rec: dict) -> str:
    basis = "|".join([
        rec.get("source_scanner") or "",
        rec.get("repository") or "",
        rec.get("source_rule_id") or "",
        (rec.get("location") or {}).get("file") or "",
    ])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def run(store, threshold: float = NEAR_THRESHOLD) -> dict:
    records = store.read_all()
    if not records:
        return {"clusters": 0, "findings": 0}

    # ── pass 1: exact duplicates share a fingerprint ────────────────────────────
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(fingerprint(r), []).append(r)
    members = list(groups.values())

    # ── pass 2: merge near-duplicates, single link ──────────────────────────────
    # Two groups merge if ANY member of one is similar enough to any member of the
    # other. Single-link keeps a chain of related findings together, which is what a
    # remediation family is: one root cause, many appearances.
    merged = True
    while merged:
        merged = False
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                if _groups_similar(members[i], members[j], threshold):
                    members[i] += members[j]
                    del members[j]
                    merged = True
                    break
            if merged:
                break

    # ── label, biggest family first, and write the basis back ───────────────────
    members.sort(key=len, reverse=True)
    clusters = {}
    for n, group in enumerate(members, start=1):
        cid = f"CL-{n:04d}"
        lead = max(group, key=lambda r: ({"high": 3, "medium": 2, "low": 1}
                                         .get(r["severity"], 0), r["finding_id"]))
        for r in group:
            r["cluster_id"] = cid
        clusters[cid] = {
            "size": len(group),
            "lead_finding": lead["finding_id"],   # the one to fix first; the rest inherit
            "members": sorted(r["finding_id"] for r in group),
            "fingerprints": sorted({fingerprint(r) for r in group}),
            "cwe": sorted({r["cwe"] for r in group if r["cwe"]}),
            "severity": lead["severity"],
        }

    store.write_all(records)
    with open(store.clusters, "w", encoding="utf-8") as fh:
        json.dump({"threshold": threshold, "method": "sha256 fingerprint + trigram jaccard",
                   "clusters": clusters}, fh, indent=2, sort_keys=True)

    return {"findings": len(records), "clusters": len(clusters),
            "collapsed": len(records) - len(clusters)}


def _extension(rec: dict) -> str:
    return ((rec.get("location") or {}).get("file") or "").rsplit(".", 1)[-1].lower()


def _groups_similar(a: list[dict], b: list[dict], threshold: float = NEAR_THRESHOLD) -> bool:
    """Single link: two families merge if ANY member of one is close enough to any
    member of the other.

    Two hard guards run before similarity is even measured, because no amount of
    textual resemblance should overcome them:

      * **different CWE** - one fix cannot close two weakness classes.
      * **different ecosystem** - the same SQL injection in Java and in Python scores
        0.40 on text, and a Java patch is useless to a Python file. A remediation
        family has to be a set of findings ONE fix could serve.
    """
    for x in a:
        for y in b:
            if x.get("cwe") and y.get("cwe") and x["cwe"] != y["cwe"]:
                continue
            if _extension(x) and _extension(y) and _extension(x) != _extension(y):
                continue
            if similarity(x.get("snippet", ""), y.get("snippet", "")) >= threshold:
                return True
    return False
