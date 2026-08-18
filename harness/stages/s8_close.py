"""Stage 8 — close.

  in:  a record at status `validated`
  out: status `closed`, with the evidence re-verified first

Closing is a **human** act, by the Portfolio Owner — the spec gives them "final say
on whether a validated fix is scheduled for release in their app". The harness has no
`--auto-close`, and there is no code path that reaches `closed` without an `--actor`.

Before closing, the sealed evidence is re-hashed. The closure record cites those
hashes, so it must cite intact ones. A mismatch stops the close and is reported as an
integrity problem with the evidence, not a problem with the fix.
"""

from __future__ import annotations

from ..roles import personas_of


def close(rec: dict, *, store, actor: str, roles_file: str, note: str = "") -> dict:
    personas = personas_of(actor, roles_file)

    problems = store.verify_evidence(rec["finding_id"], rec["rounds"] + 1)
    if problems:
        raise ValueError(
            f"cannot close {rec['finding_id']}: its evidence does not verify — "
            + "; ".join(problems))

    reason = (f"closed by {actor}; evidence {rec['evidence_link']} verified"
              + (f": {note}" if note else ""))
    return store.advance(rec, "closed", actor=actor, reason=reason, persona=personas)


def accept_risk(rec: dict, *, store, actor: str, roles_file: str, justification: str) -> dict:
    """The waiver path. The spec asks that accepted-risk findings carry the same
    evidence structure as closures, so they leave the pipeline as a recorded decision
    with a named owner — not as a finding that quietly stopped moving."""
    if not justification.strip():
        raise ValueError("an accepted risk needs a justification; that is the whole artifact")
    personas = personas_of(actor, roles_file)
    return store.advance(rec, "exception", actor=actor, persona=personas,
                         reason=f"risk-accepted by {actor}: {justification.strip()}")
