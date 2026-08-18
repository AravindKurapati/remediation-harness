"""Stage 6 — approve.

  in:  a record at status `proposed`, plus a human identity
  out: status `approved` (with `approver` set), or `exception` with the objection

**This is the gate the whole product exists to protect.** The spec gives the Security
Reviewer one exclusive power: the "only role that can move a finding from 'proposed'
to 'approved'". So this stage does two separable things, and the separation is the
point:

  * `advise()` asks the model for a verdict. It is **advisory**. It cannot approve
    anything. It exists to give the reviewer objections to check, not to replace them.
  * `approve()` requires a real identity, resolves it to a persona through
    `roles.yaml`, and refuses anyone who is not a Security Reviewer.

A machine verdict and a human signature are different things and this file never
lets one stand in for the other. `--actor` has no default: there is no way to approve
without naming who approved.
"""

from __future__ import annotations

import os

from .. import provider as prov
from ..roles import personas_of

MAX_ROUNDS = 2


def advise(rec: dict, *, store, provider, patch: str) -> dict:
    """The advisory verdict. Returns {verdict, objections, reasoning} — never a status."""
    try:
        return prov.ask(
            provider,
            prompt_name="review",
            key=f"{rec['finding_id']}-r{rec['rounds'] + 1}" if rec["rounds"] else rec["finding_id"],
            variables={
                "finding": {k: rec[k] for k in ("finding_id", "cwe", "category", "severity",
                                                "title", "root_cause", "location")},
                "diff": patch,
                "explanation": (rec.get("proposal") or {}).get("explanation", ""),
                "test_name": (rec.get("proposal") or {}).get("test_name", ""),
                "left_alone": (rec.get("proposal") or {}).get("left_alone", []),
                "pattern_id": rec.get("matched_pattern_id") or "(generated fresh)",
            },
            schema=prov.REVIEW_SCHEMA,
            llm_dir=os.path.join(store.root, "llm"),
        )
    except prov.ProviderError as e:
        # No advisory verdict is not a blocker — a human can still review. It is
        # recorded so the reviewer knows they are working without one.
        return {"verdict": "reject", "objections": [f"advisory review unavailable: {e}"],
                "reasoning": "no machine review was obtained; reviewer is on their own here"}


def approve(rec: dict, *, store, actor: str, roles_file: str, note: str = "") -> dict:
    """A human approves. Refuses any identity that is not a Security Reviewer."""
    personas = personas_of(actor, roles_file)          # raises NotPermitted if unlisted
    reason = f"approved by {actor}" + (f": {note}" if note else "")
    return store.advance(rec, "approved", actor=actor, reason=reason, persona=personas)


def reject(rec: dict, *, store, actor: str, roles_file: str, objections: list[str]) -> tuple[dict, bool]:
    """A human rejects. Returns (record, may_revise).

    Under the revision cap the record goes back to `proposed` for another round.
    At the cap it becomes an exception — the rounds are all in the audit log for the
    person who picks it up.
    """
    personas = personas_of(actor, roles_file)
    detail = "; ".join(objections) or "no reason given"
    if rec["rounds"] < MAX_ROUNDS:
        # The objections travel with the record so the next round's prompt carries
        # them verbatim. `s5_propose` clears the flag once it has used them.
        rec["needs_revision"] = objections
        store.advance(rec, "proposed", actor=actor, persona=personas,
                      reason=f"rejected by {actor}: {detail}")
        return rec, True
    rec.pop("needs_revision", None)
    store.advance(rec, "exception", actor=actor, persona=personas,
                  reason=f"revision-cap: rejected {rec['rounds'] + 1} times. Last: {detail}")
    return rec, False
