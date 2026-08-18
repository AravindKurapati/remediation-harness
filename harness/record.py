"""The vulnerability record and its status machine.

One record per finding. The fields are the spec's Data Model table, unchanged.
`transition()` is the ONLY way a status ever changes, so every change is checked
against the machine below and against the actor's persona.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

FINDING_ID = re.compile(r"^[A-Z]{2,8}-[0-9]{6}$")

# The spec's status values, in the spec's order.
STATUSES = ("new", "triaged", "proposed", "approved", "validated", "closed", "exception")

# from -> allowed next. Every edge in the machine, and nothing else is legal.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "new":       ("triaged", "exception"),
    "triaged":   ("proposed", "exception"),
    "proposed":  ("approved", "proposed", "exception"),   # proposed->proposed = a revision round
    "approved":  ("validated", "exception"),
    "validated": ("closed", "exception"),
    "closed":    ("triaged",),                            # recurrence: a finding reopened
    "exception": ("triaged",),                            # governance lead returns it to the queue
}

# Which stage stamps which timestamp.
STAMP = {
    "triaged": "triaged", "proposed": "proposed", "approved": "approved",
    "validated": "validated", "closed": "closed",
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def new_record(**fields: Any) -> dict:
    """A record at status `new`. Every spec field is present, most of them empty."""
    r = {
        "finding_id":       fields["finding_id"],
        "source_scanner":   fields["source_scanner"],
        "source_rule_id":   fields.get("source_rule_id"),
        "repository":       fields["repository"],
        "portfolio":        fields.get("portfolio"),
        "category":         fields.get("category"),
        "cwe":              fields.get("cwe"),
        "severity":         fields.get("severity", "medium"),
        "title":            fields.get("title", ""),
        "location":         fields.get("location", {}),
        "snippet":          fields.get("snippet", ""),
        "root_cause":       None,
        "cluster_id":       None,
        "confidence_score": None,
        "matched_pattern_id": None,
        "status":           "new",
        "approver":         None,
        "evidence_link":    None,
        "rounds":           0,
        "prior_evidence":   None,     # set on recurrence: the evidence of the earlier close
        "raw_ref":          fields.get("raw_ref"),
        "timestamps":       {"created": now(), "triaged": None, "proposed": None,
                             "approved": None, "validated": None, "closed": None},
    }
    if not FINDING_ID.match(r["finding_id"]):
        raise ValueError(f"finding_id {r['finding_id']!r} is not <PREFIX>-<6 digits>")
    return r


class TransitionError(Exception):
    """A status change the machine does not allow, or the actor may not perform."""


def transition(rec: dict, to: str, *, actor: str, reason: str,
               persona: "str | set[str]" = "harness") -> dict:
    """Move a record to `to`. Raises rather than writing an illegal or unexplained change.

    Returns the audit entry to append. The caller writes it; `runstore.advance()`
    does both together so the log and the records cannot drift apart.
    """
    frm = rec["status"]
    if to not in STATUSES:
        raise TransitionError(f"{to!r} is not a status")
    if to not in TRANSITIONS[frm]:
        raise TransitionError(f"{frm} -> {to} is not a legal transition")
    if not reason or not reason.strip():
        raise TransitionError(f"{frm} -> {to} needs a reason; an unexplained change is not auditable")

    from .roles import check          # imported here to keep the import graph one-way
    authorized_as = check(persona, frm, to)   # raises if this actor may not do it

    rec["status"] = to
    rec["rounds"] += 1 if (frm, to) == ("proposed", "proposed") else 0
    if to in STAMP:
        rec["timestamps"][STAMP[to]] = now()
    if to == "approved":
        rec["approver"] = actor

    return {"ts": now(), "finding_id": rec["finding_id"], "from": frm, "to": to,
            "actor": actor, "persona": authorized_as, "reason": reason.strip(),
            "round": rec["rounds"]}


def reopen(rec: dict, *, evidence_link: str | None = None) -> dict:
    """Recurrence. A closed finding seen again re-enters at triage, carrying a link
    to the evidence package that closed it last time, so the human picking it up can
    see what was tried. The pattern that produced that fix is flagged by `s9_learn`."""
    rec["prior_evidence"] = evidence_link or rec.get("evidence_link")
    rec["confidence_score"] = None
    rec["matched_pattern_id"] = None
    rec["evidence_link"] = None
    return rec
