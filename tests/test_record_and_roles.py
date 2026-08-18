"""The status machine and the authorization model.

These are the tests that protect the client's governance requirement. If any of them
stops passing, the harness can move a finding somewhere nobody authorized.
"""

import pytest

from harness.record import TransitionError, transition
from harness.roles import NotPermitted, check, personas_of


# ── the machine ─────────────────────────────────────────────────────────────────

def test_legal_transition_advances_and_stamps(finding):
    entry = transition(finding, "triaged", actor="harness:triage", reason="classified")
    assert finding["status"] == "triaged"
    assert finding["timestamps"]["triaged"] is not None
    assert entry["from"] == "new" and entry["to"] == "triaged"


def test_illegal_transition_is_refused(finding):
    # new -> approved would skip triage, proposal, and the reviewer entirely
    with pytest.raises(TransitionError, match="not a legal transition"):
        transition(finding, "approved", actor="someone", reason="skip ahead")
    assert finding["status"] == "new"


def test_a_status_change_needs_a_reason(finding):
    with pytest.raises(TransitionError, match="needs a reason"):
        transition(finding, "triaged", actor="harness", reason="   ")


def test_the_harness_can_never_close_a_finding(finding):
    """Closing is a human act by the portfolio owner. The machine has no path to it."""
    finding["status"] = "validated"
    with pytest.raises(NotPermitted, match="reserved for portfolio_owner"):
        transition(finding, "closed", actor="harness", reason="all gates passed",
                   persona="harness")


def test_a_revision_round_increments_rounds(finding):
    finding["status"] = "proposed"
    transition(finding, "proposed", actor="priya", reason="rejected: wrong shape",
               persona="security_reviewer")
    assert finding["rounds"] == 1


def test_a_closed_finding_can_reopen_at_triage(finding):
    """Recurrence. The spec requires a reopened finding to re-enter at triage."""
    finding["status"] = "closed"
    transition(finding, "triaged", actor="harness:ingest", reason="recurrence: seen again")
    assert finding["status"] == "triaged"


# ── the authorization model ─────────────────────────────────────────────────────

def test_only_a_security_reviewer_approves():
    """The spec's exclusive: the Security Reviewer is the 'only role that can move a
    finding from proposed to approved'."""
    assert check("security_reviewer", "proposed", "approved") == "security_reviewer"
    for persona in ("harness", "portfolio_owner", "governance_lead", "audit_viewer"):
        with pytest.raises(NotPermitted, match="reserved for security_reviewer"):
            check(persona, "proposed", "approved")


def test_an_audit_viewer_can_do_nothing():
    """Read-only access, no approval rights."""
    for frm, to in (("new", "triaged"), ("proposed", "approved"), ("validated", "closed")):
        with pytest.raises(NotPermitted):
            check("audit_viewer", frm, to)


def test_an_identity_may_hold_two_personas(roles_file):
    held = personas_of("both@example.com", roles_file)
    assert held == {"security_reviewer", "portfolio_owner"}
    assert check(held, "proposed", "approved") == "security_reviewer"
    assert check(held, "validated", "closed") == "portfolio_owner"


def test_an_unlisted_identity_is_refused_not_defaulted(roles_file):
    """A role is never defaulted. Defaulting one is how an approval gate quietly
    stops being a gate."""
    with pytest.raises(NotPermitted, match="has no persona"):
        personas_of("stranger@example.com", roles_file)


def test_a_missing_roles_file_refuses_everyone(tmp_path):
    with pytest.raises(NotPermitted, match="not found"):
        personas_of("priya@example.com", str(tmp_path / "absent.yaml"))
