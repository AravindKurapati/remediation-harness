"""Stage 5 — propose.

  in:  a triaged record, the retrieval result, the target repository
  out: runs/<id>/patches/<finding_id>.diff and a regression test; status `proposed`

The model writes the fix here. Three constraints on what it produces, all checked:

  * **A unified diff, not a rewritten file.** A diff is reviewable; a replacement file
    is not. The schema rejects anything that does not start as a diff.
  * **A regression test comes with it.** A patch without a test proves nothing at
    stage 7 — the suite would go green whether or not the vulnerability was fixed.
  * **Nothing is applied.** The diff is written to the run directory. The target
    repository is not touched here or anywhere else in the pipeline; a human applies
    it by merging a pull request.

If retrieval found a pattern, the prompt carries that pattern's body and the model
adapts it. If not, the model generates fresh and `pattern_id` comes back null — which
is not a failure, it is the case stage 9 learns from.
"""

from __future__ import annotations

import os

from .. import provider as prov
from . import s4_retrieve


def _file_at(repo_root: str, rel: str) -> str:
    p = os.path.join(repo_root, rel)
    if not os.path.isfile(p):
        return ""
    return open(p, encoding="utf-8", errors="replace").read()


def run(rec: dict, retrieval: dict, *, store, provider, repo_root: str,
        library_dir: str = "library", feedback: list[str] | None = None) -> tuple[dict, str, str]:
    """Returns (record, next_status, reason)."""
    rel = (rec.get("location") or {}).get("file") or ""
    source = _file_at(repo_root, rel)
    if not source:
        return rec, "exception", (
            f"stale-finding: {rel} is not present in the repository at this revision")

    top = retrieval["matches"][0] if retrieval["matches"] else None
    pattern_body = s4_retrieve.body(top["pattern_id"], library_dir) if top else ""

    key = rec["finding_id"] if not feedback else f"{rec['finding_id']}-r{rec['rounds'] + 1}"
    try:
        answer = prov.ask(
            provider,
            prompt_name="propose",
            key=key,
            variables={
                "finding": {k: rec[k] for k in ("finding_id", "cwe", "category", "severity",
                                                "title", "root_cause", "location", "snippet")},
                "file_path": rel,
                "file_source": source,
                "pattern": pattern_body or "(no approved pattern cleared the retrieval floor — "
                                           "generate a fix and report pattern_id as null)",
                "retrieval": {"matches": retrieval["matches"], "floor": retrieval["floor"]},
                "feedback": "\n".join(f"- {f}" for f in (feedback or [])) or "(first round)",
            },
            schema=prov.PROPOSE_SCHEMA,
            llm_dir=os.path.join(store.root, "llm"),
        )
    except prov.ProviderError as e:
        return rec, "exception", f"proposal-failed: {e}"

    patch_path = store.path("patches", f"{rec['finding_id']}.diff")
    with open(patch_path, "w", encoding="utf-8") as fh:
        fh.write(answer["diff"])

    test_path = store.path("patches", f"{rec['finding_id']}.test")
    with open(test_path, "w", encoding="utf-8") as fh:
        fh.write(answer["test_source"])

    rec.pop("needs_revision", None)
    rec["matched_pattern_id"] = answer["pattern_id"]
    rec["proposal"] = {
        "patch": os.path.relpath(patch_path, store.root).replace("\\", "/"),
        "test_file": os.path.relpath(test_path, store.root).replace("\\", "/"),
        "test_name": answer["test_name"],
        "explanation": answer["explanation"],
        "left_alone": answer["left_alone"],
    }

    how = (f"adapted pattern {answer['pattern_id']}" if answer["pattern_id"]
           else "generated fresh — no approved pattern cleared the floor")
    return rec, "proposed", f"{how}; regression test {answer['test_name']}"
