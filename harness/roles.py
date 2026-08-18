"""Who is allowed to change what.

The spec names four personas and gives one of them an exclusive power: the Security
Reviewer is the "only role that can move a finding from 'proposed' to 'approved'".
This file is that rule, enforced at the one place status changes happen.

An identity may hold **more than one persona** — a small team often has the same
person reviewing security and owning a portfolio — so `personas_of` returns a set and
a transition is permitted if any held persona permits it. What is never allowed is a
persona standing in for one it does not hold.

This is the authorization *model*, not an identity provider. It answers "may this
persona perform this transition"; it does not authenticate anyone. Wiring it to SSO
is a connector: `personas_of` gets a different lookup and nothing else changes.
"""

from __future__ import annotations

import os
import yaml

PERSONAS = ("harness", "security_reviewer", "portfolio_owner", "governance_lead", "audit_viewer")

# (from, to) -> the personas permitted to make that move.
PERMITTED: dict[tuple[str, str], tuple[str, ...]] = {
    ("new", "triaged"):        ("harness",),
    ("new", "exception"):      ("harness", "governance_lead"),
    ("triaged", "proposed"):   ("harness",),
    ("triaged", "exception"):  ("harness", "security_reviewer", "governance_lead"),

    # The spec's exclusive: only a Security Reviewer approves a proposal.
    ("proposed", "approved"):  ("security_reviewer",),
    ("proposed", "proposed"):  ("security_reviewer", "harness"),   # a rejection sends it back
    ("proposed", "exception"): ("security_reviewer", "governance_lead"),

    ("approved", "validated"): ("harness",),
    ("approved", "exception"): ("harness",),                       # a gate failed or could not run

    # The Portfolio Owner "retains final say on whether a validated fix is scheduled
    # for release in their app" - so closing is theirs, not the machine's.
    ("validated", "closed"):   ("portfolio_owner",),
    ("validated", "exception"): ("portfolio_owner", "governance_lead"),

    ("closed", "triaged"):     ("harness",),                       # recurrence
    ("exception", "triaged"):  ("governance_lead",),               # the queue owner returns it
}


class NotPermitted(Exception):
    """The persona may not make this transition."""


def check(held: str | set[str], frm: str, to: str) -> str:
    """Returns the persona that authorized the move, or raises. `held` is one persona
    or the set an identity holds."""
    held = {held} if isinstance(held, str) else set(held)
    unknown = held - set(PERSONAS)
    if unknown:
        raise NotPermitted(f"not a persona: {', '.join(sorted(unknown))}")

    allowed = PERMITTED.get((frm, to))
    if allowed is None:
        raise NotPermitted(f"no persona may perform {frm} -> {to}")

    for persona in allowed:            # in declaration order, so the message is stable
        if persona in held:
            return persona
    raise NotPermitted(
        f"{', '.join(sorted(held))} may not perform {frm} -> {to}; "
        f"that is reserved for {', '.join(allowed)}")


def personas_of(identity: str, roles_file: str = "roles.yaml") -> set[str]:
    """Every persona an identity holds. An identity that is not listed holds none and
    is refused — roles are never defaulted, because defaulting a role is how an
    approval gate quietly stops being one."""
    if not os.path.exists(roles_file):
        raise NotPermitted(f"{roles_file} not found; no identity can be resolved without it")
    roles = yaml.safe_load(open(roles_file, encoding="utf-8")) or {}
    held = {persona for persona, identities in (roles.get("personas") or {}).items()
            if identity in (identities or [])}
    if not held:
        raise NotPermitted(f"{identity!r} has no persona in {roles_file}")
    return held
