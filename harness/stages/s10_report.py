"""Stage 10 — report.

  in:  runs/<id>/findings.jsonl and audit.jsonl
  out: runs/<id>/metrics.json — the seven KPIs the spec names

Every number here is **derived from the audit log**, not estimated and not
self-reported. Cycle time is a subtraction between two logged timestamps. Rework rate
is a count of logged rejections. If the log is wrong, the KPIs are wrong, and
`harness verify` will say so — which is the property that makes them worth reporting
to an auditor.

The seven, in the spec's order:

  1. cycle_time      average remediation cycle time per finding, by category
  2. burn_down       high findings closed per wave, and cumulative
  3. rework_rate     remediation quality — rejections per proposal
  4. repeatability   share of closures that used an approved reusable pattern
  5. recurrence      findings reopened after closure
  6. evidence_completeness  percent of closed findings with a full audit package
  7. exception_queue size and average age

Plus the spec's model-evaluation metrics, which are the same kind of thing:
classification accuracy proxy, pattern-match precision, and reviewer override rate.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict


def _parse(ts: str | None) -> dt.datetime | None:
    return dt.datetime.fromisoformat(ts) if ts else None


def _hours(a: str | None, b: str | None) -> float | None:
    ta, tb = _parse(a), _parse(b)
    return round((tb - ta).total_seconds() / 3600, 2) if ta and tb else None


def _mean(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 2) if xs else None


def run(store, *, now: dt.datetime | None = None) -> dict:
    records = store.read_all()
    entries = list(store.audit_entries())
    now = now or dt.datetime.now(dt.timezone.utc)

    closed = [r for r in records if r["status"] == "closed"]
    exceptions = [r for r in records if r["status"] == "exception"]

    # 1 — cycle time, by category
    by_cat: dict[str, list[float]] = defaultdict(list)
    for r in closed:
        h = _hours(r["timestamps"]["created"], r["timestamps"]["closed"])
        if h is not None:
            by_cat[r["category"] or "unclassified"].append(h)
    cycle_time = {"overall_hours": _mean([h for v in by_cat.values() for h in v]),
                  "by_category_hours": {k: _mean(v) for k, v in sorted(by_cat.items())}}

    # 2 — burn-down of high findings
    high = [r for r in records if r["severity"] == "high"]
    burn_down = {"high_total": len(high),
                 "high_closed": sum(1 for r in high if r["status"] == "closed"),
                 "high_open": sum(1 for r in high if r["status"] not in ("closed", "exception")),
                 "high_exception": sum(1 for r in high if r["status"] == "exception"),
                 "percent_closed": round(100 * sum(1 for r in high if r["status"] == "closed")
                                         / len(high), 1) if high else None}

    # 3 — rework: how often a reviewer sent a proposal back
    proposals = sum(1 for e in entries if e["to"] == "proposed")
    rejections = sum(1 for e in entries if e["from"] == "proposed"
                     and "rejected by" in e.get("reason", ""))
    rework_rate = {"proposals": proposals, "rejections": rejections,
                   "rate": round(rejections / proposals, 3) if proposals else None}

    # 4 — repeatability: closures that reused an approved pattern
    reused = sum(1 for r in closed
                 if r.get("matched_pattern_id") and not str(r["matched_pattern_id"]).startswith("cand-"))
    repeatability = {"closed": len(closed), "with_pattern": reused,
                     "share": round(reused / len(closed), 3) if closed else None}

    # 5 — recurrence: a closed finding that came back
    reopened = sum(1 for e in entries if e["from"] == "closed" and e["to"] == "triaged")
    recurrence = {"reopened": reopened,
                  "rate": round(reopened / len(closed), 3) if closed else None}

    # 6 — evidence completeness
    complete = sum(1 for r in closed
                   if r.get("evidence_link")
                   and not store.verify_evidence(r["finding_id"], r["rounds"] + 1))
    evidence_completeness = {"closed": len(closed), "with_verified_package": complete,
                             "percent": round(100 * complete / len(closed), 1) if closed else None}

    # 7 — the exception queue: size, and age, which is the leading indicator
    ages = []
    for r in exceptions:
        last = max((e["ts"] for e in entries if e["finding_id"] == r["finding_id"]), default=None)
        if last:
            ages.append(round((now - _parse(last)).total_seconds() / 86400, 2))
    queue = {"size": len(exceptions), "mean_age_days": _mean(ages),
             "oldest_days": max(ages) if ages else None,
             "by_reason": _reasons(entries, exceptions)}

    # model evaluation — the spec asks for these as first-class, not assumed
    triaged = [r for r in records if r.get("confidence_score") is not None]
    low_conf = sum(1 for e in entries if "low-confidence" in e.get("reason", ""))
    model = {
        "triaged": len(triaged),
        "mean_confidence": _mean([r["confidence_score"] for r in triaged]),
        "sent_to_manual_triage": low_conf,
        "reviewer_override_rate": rework_rate["rate"],
        "pattern_match_precision": (
            round(reused / sum(1 for r in records if r.get("matched_pattern_id")), 3)
            if any(r.get("matched_pattern_id") for r in records) else None),
    }

    metrics = {
        "generated_at": now.isoformat(timespec="seconds"),
        "run": store.root.replace("\\", "/").rsplit("/", 1)[-1],
        "totals": {"findings": len(records),
                   "by_status": _count(records, "status"),
                   "by_severity": _count(records, "severity"),
                   "by_category": _count(records, "category"),
                   "clusters": _clusters(store)},
        "kpi": {"cycle_time": cycle_time, "burn_down": burn_down, "rework_rate": rework_rate,
                "repeatability": repeatability, "recurrence": recurrence,
                "evidence_completeness": evidence_completeness, "exception_queue": queue},
        "model_evaluation": model,
        "audit_problems": store.verify_audit(),
    }
    with open(store.metrics, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2, sort_keys=True)
    return metrics


def _count(records: list[dict], field: str) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for r in records:
        out[str(r.get(field) or "unset")] += 1
    return dict(sorted(out.items()))


def _reasons(entries: list[dict], exceptions: list[dict]) -> dict[str, int]:
    """Group the queue by the kind of reason, which is what tells a governance lead
    whether the queue is a staffing problem or a tooling problem."""
    ids = {r["finding_id"] for r in exceptions}
    out: dict[str, int] = defaultdict(int)
    for e in entries:
        if e["to"] == "exception" and e["finding_id"] in ids:
            out[e.get("reason", "").split(":")[0].strip() or "unspecified"] += 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _clusters(store) -> dict:
    import os
    if not os.path.exists(store.clusters):
        return {"count": None}
    doc = json.load(open(store.clusters, encoding="utf-8"))["clusters"]
    sizes = [c["size"] for c in doc.values()]
    return {"count": len(doc), "largest": max(sizes) if sizes else 0,
            "collapsed": sum(sizes) - len(doc)}
