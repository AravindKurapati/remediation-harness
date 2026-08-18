"""The whole pipeline, against the real sample app, with the real gates.

This is the test that would have caught what the demo could not show: it runs every
stage in order, applies real patches to a real copy of a real project, runs that
project's real build and test commands, and checks the audit trail at the end.

It uses the mock provider, so the model's *judgement* is a recording. Everything
around the judgement - the machinery that is the harness - is really executed.
"""

import os

import pytest

from harness.cli import ROOT, main
from harness.runstore import RunStore


def discard(run_id):
    """Sealed evidence is mode 444, so a plain rmtree fails on Windows. `discard()`
    is the deliberate way to destroy a run - see RunStore.discard."""
    store = RunStore(os.path.join(ROOT, "runs", run_id))
    if os.path.exists(store.root):
        store.discard()

FINDINGS = os.path.join(ROOT, "fixtures", "findings", "py-ledger-semgrep.json")


@pytest.fixture(scope="module")
def completed():
    """One pipeline run for the whole module. Every assertion below reads the same
    run directory, which is also how you would inspect it by hand."""
    rid = "R-pytest"
    discard(rid)
    main(["run", "--findings", FINDINGS, "--target", "py-ledger",
          "--run", rid, "--auto-review"])
    yield RunStore(os.path.join(ROOT, "runs", rid))
    discard(rid)


def test_every_finding_reaches_a_terminal_state(completed):
    statuses = {r["finding_id"]: r["status"] for r in completed.read_all()}
    assert set(statuses.values()) <= {"closed", "exception"}, \
        f"a finding stalled mid-pipeline: {statuses}"


def test_the_backlog_collapses_into_families(completed):
    """6 findings, 3 remediation families. At that scale this is the difference
    between finishing before the freeze and not."""
    import json
    clusters = json.load(open(completed.clusters, encoding="utf-8"))["clusters"]
    assert len(clusters) == 3
    assert max(c["size"] for c in clusters.values()) == 3


def test_the_low_confidence_finding_went_to_manual_triage(completed):
    """The MD5 finding comes back at 0.58 because the model cannot see any caller.
    Below the floor it is never auto-classified - it goes to a human."""
    md5 = completed.get("FND-000006")
    assert md5["status"] == "exception"
    reason = [e["reason"] for e in completed.audit_entries()
              if e["finding_id"] == "FND-000006" and e["to"] == "exception"][0]
    assert "low-confidence" in reason


def test_the_wrong_fix_was_rejected_and_the_revision_was_right(completed):
    """The identifier-injection finding first gets `ORDER BY ?`, which cannot work.
    The reviewer catches it, the revision uses the allowlist pattern instead."""
    trail = [e for e in completed.audit_entries() if e["finding_id"] == "FND-000003"]
    rejection = [e for e in trail if e["from"] == "proposed" and e["to"] == "proposed"]
    assert len(rejection) == 1, "the reviewer should have sent this one back once"
    assert "placeholder binds a VALUE" in rejection[0]["reason"]

    final = completed.get("FND-000003")
    assert final["matched_pattern_id"] == "sqli-python-identifier-allowlist"
    assert final["status"] == "closed"


def test_closures_carry_evidence_that_still_verifies(completed):
    for rec in completed.read_all():
        if rec["status"] == "closed":
            assert rec["evidence_link"]
            assert completed.verify_evidence(rec["finding_id"], rec["rounds"] + 1) == []


def test_every_gate_really_ran(completed):
    """Not simulated. `build` is compileall, `test` is pytest against a patched copy
    of the sample app, `rescan` re-runs the originating rule."""
    import json
    rec = completed.get("FND-000001")
    manifest = json.load(open(os.path.join(completed.root, rec["evidence_link"]),
                              encoding="utf-8"))
    assert manifest["gates"] == {"build": "pass", "test": "pass", "rescan": "pass"}
    assert manifest["gates_run"] == ["build", "test", "rescan"]


def test_the_audit_chain_is_sound(completed):
    assert completed.verify_audit() == []


def test_a_reused_pattern_and_a_fresh_fix_are_both_recorded(completed):
    reused = [r for r in completed.read_all()
              if r["status"] == "closed" and r.get("matched_pattern_id")]
    fresh = [r for r in completed.read_all()
             if r["status"] == "closed" and not r.get("matched_pattern_id")]
    assert reused, "the SQLi findings should reuse approved patterns"
    assert fresh, "the secrets findings have no pattern and are generated fresh"


def test_a_fix_is_suggested_to_the_rest_of_its_family(completed):
    """The cluster payoff: a validated fix reaches its siblings as a suggestion,
    never as an automatic application."""
    suggested = [r for r in completed.read_all() if r.get("suggestions")]
    assert suggested, "a closed finding should have proposed itself to its family"


def test_the_sample_repository_was_never_modified():
    """Patches are built in scratch copies. The target is read-only to the harness."""
    db = os.path.join(ROOT, "samples", "py-ledger", "ledger", "db.py")
    source = open(db, encoding="utf-8").read()
    assert '+ name + "\'"' in source, "the vulnerable sample must still be vulnerable"


def test_an_unavailable_gate_blocks_closure():
    """The rule the whole evidence contract rests on. Same findings, same patches -
    but the re-scan tool is not installed, so nothing closes even though build and
    test genuinely passed."""
    strict = "R-pytest-strict"
    discard(strict)
    try:
        main(["run", "--findings", FINDINGS, "--target", "py-ledger-strict",
              "--run", strict, "--auto-review"])
        store = RunStore(os.path.join(ROOT, "runs", strict))
        assert not [r for r in store.read_all() if r["status"] == "closed"]

        reasons = [e["reason"] for e in store.audit_entries() if e["to"] == "exception"]
        assert any("gate-unavailable" in r and "semgrep is not on PATH" in r for r in reasons)
        assert any("build: pass, test: pass" in r for r in reasons), \
            "two gates really passed; the finding still did not close"
    finally:
        discard(strict)
