"""Stage 3 — triage.

  in:  one record at status `new`, plus the file it points at
  out: category, cwe, root_cause, confidence_score set; status `triaged`
       or status `exception` with a reason

The model is asked for three things and, importantly, for a fourth: **how sure it
is**. That self-reported confidence is checked against a floor from
`thresholds.yaml` before the finding is allowed to continue.

Three spec rules live here, and each has a test:

  * **The floor is per category AND per portfolio, never global.** "A threshold tuned
    on simple quick-win findings is not assumed to generalize to more complex
    categories or codebases."
  * **Below the floor, the finding goes to manual triage.** It is not auto-classified
    at lower confidence, and it does not receive a default category.
  * **If the model is unavailable, the finding stays at `new`.** It queues. It does
    not get a fallback classification, because a guessed category that looks like a
    real one is worse than an obvious gap.
"""

from __future__ import annotations

import os
import yaml

from .. import provider as prov

DEFAULT_FLOOR = 0.75


def floor_for(thresholds: dict, category: str | None, portfolio: str | None) -> float:
    """Most specific wins: portfolio+category, then category, then the default."""
    by_cat = (thresholds or {}).get("categories", {}) or {}
    by_port = (thresholds or {}).get("portfolios", {}) or {}
    if portfolio and category:
        specific = ((by_port.get(portfolio) or {}).get("categories") or {}).get(category)
        if specific is not None:
            return float(specific)
    if portfolio and (by_port.get(portfolio) or {}).get("default") is not None:
        return float(by_port[portfolio]["default"])
    if category and by_cat.get(category) is not None:
        return float(by_cat[category])
    return float((thresholds or {}).get("default", DEFAULT_FLOOR))


def load_thresholds(path: str = "thresholds.yaml") -> dict:
    if not os.path.exists(path):
        return {"default": DEFAULT_FLOOR}
    return yaml.safe_load(open(path, encoding="utf-8")) or {"default": DEFAULT_FLOOR}


def _context(repo_root: str, rec: dict, radius: int = 12) -> str:
    """The lines around the flagged one. Bounded on purpose: the model gets the code
    it needs to judge this finding, not the repository."""
    p = os.path.join(repo_root, (rec.get("location") or {}).get("file") or "")
    if not os.path.isfile(p):
        return "(file not present at this revision)"
    lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
    line = (rec.get("location") or {}).get("line") or 1
    lo, hi = max(0, line - 1 - radius), min(len(lines), line + radius)
    return "\n".join(f"{i + 1:5d} | {lines[i]}" for i in range(lo, hi))


def run(rec: dict, *, store, provider, repo_root: str, thresholds: dict) -> tuple[dict, str, str]:
    """Returns (record, next_status, reason). The caller writes the transition, so
    this stage cannot change a status without the log being written too."""
    try:
        answer = prov.ask(
            provider,
            prompt_name="triage",
            key=rec["finding_id"],
            variables={"finding": {k: rec[k] for k in
                                   ("finding_id", "source_scanner", "source_rule_id", "cwe",
                                    "severity", "title", "snippet", "location", "repository",
                                    "portfolio")},
                       "code": _context(repo_root, rec)},
            schema=prov.TRIAGE_SCHEMA,
            llm_dir=os.path.join(store.root, "llm"),
        )
    except prov.ProviderError as e:
        # Queue, do not guess. The record stays at `new` and this run reports it.
        return rec, "new", f"triage unavailable: {e}"

    floor = floor_for(thresholds, answer["category"], rec.get("portfolio"))
    rec["category"] = answer["category"]
    rec["cwe"] = answer["cwe"] or rec["cwe"]
    rec["root_cause"] = answer["root_cause"]
    rec["confidence_score"] = answer["confidence_score"]

    if answer["confidence_score"] < floor:
        return rec, "exception", (
            f"low-confidence: triage returned {answer['confidence_score']:.2f}, "
            f"below the {floor:.2f} floor for {answer['category']}"
            f"{' in ' + rec['portfolio'] if rec.get('portfolio') else ''}")

    return rec, "triaged", (
        f"classified {answer['category']} / {answer['cwe']} at "
        f"{answer['confidence_score']:.2f} confidence (floor {floor:.2f})")
