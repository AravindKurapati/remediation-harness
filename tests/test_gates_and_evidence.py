"""The gates, the evidence bundle, and the audit chain.

This file holds the tests for the one rule the whole product rests on: a receipt must
never claim more than actually happened. If `unavailable` can become `pass`, or if a
sealed bundle can be edited undetected, then the audit trail is decoration and the
client has bought nothing.
"""

import json
import os

import pytest

from harness.record import TransitionError
from harness.stages import s7_validate


# ── gates ───────────────────────────────────────────────────────────────────────

def test_a_missing_tool_is_unavailable_not_pass(tmp_path):
    gate = s7_validate.run_gate("rescan", "definitely-not-a-real-tool --x", str(tmp_path))
    assert gate["verdict"] == "unavailable"
    assert "not on PATH" in gate["reason"]


def test_an_undeclared_gate_is_unavailable_not_skipped(tmp_path):
    gate = s7_validate.run_gate("rescan", None, str(tmp_path))
    assert gate["verdict"] == "unavailable"


def test_a_nonzero_exit_is_a_failure(tmp_path):
    gate = s7_validate.run_gate("build", "python -c \"import sys; sys.exit(3)\"", str(tmp_path))
    assert gate["verdict"] == "fail" and gate["exit_code"] == 3


def test_a_zero_exit_passes(tmp_path):
    gate = s7_validate.run_gate("build", "python -c \"pass\"", str(tmp_path))
    assert gate["verdict"] == "pass"


def test_a_green_suite_without_the_new_test_is_a_failure():
    """The most important gate check. If the regression test did not run, the suite
    was green with or without the fix, so it proves nothing about the finding."""
    gate = {"gate": "test", "verdict": "pass", "output": "4 passed in 0.4s"}
    checked = s7_validate.check_test_ran(gate, "test_quote_in_name_is_data")
    assert checked["verdict"] == "fail"
    assert "did not appear in the output" in checked["reason"]


def test_a_green_suite_with_the_new_test_passes():
    gate = {"gate": "test", "verdict": "pass",
            "output": "tests/test_regression.py::test_quote_in_name_is_data PASSED"}
    assert s7_validate.check_test_ran(gate, "test_quote_in_name_is_data")["verdict"] == "pass"


def test_placeholders_are_substituted_per_finding():
    filled = s7_validate.fill("scan --file {file} --rule {rule}",
                              {"file": "ledger/db.py", "rule": "py.sqli.concat"})
    assert filled == "scan --file ledger/db.py --rule py.sqli.concat"


def test_scanner_text_never_reaches_the_command_line():
    """`<REDACTED:...>` in a snippet is a redirection operator to cmd.exe. Scanner
    text goes in the environment; only paths and ids are substituted into commands."""
    template = "scan --file {file} --rule {rule}"
    assert "{snippet}" not in template
    filled = s7_validate.fill(template, {"file": "a.py", "rule": "r"})
    assert "<" not in filled and ">" not in filled


# ── evidence ────────────────────────────────────────────────────────────────────

def seal_one(store, fid="FND-000001", rnd=1):
    return store.seal(fid, rnd, {"build.log": "exit 0\n", "patch.diff": "--- a\n+++ b\n"},
                      {"overall": "passed", "gates": {"build": "pass"}})


def test_sealing_records_a_hash_for_every_artifact(store):
    link = seal_one(store)
    manifest = json.load(open(os.path.join(store.root, link), encoding="utf-8"))
    assert set(manifest["sha256"]) == {"build.log", "patch.diff"}
    assert manifest["overall"] == "passed"


def test_a_sealed_round_cannot_be_sealed_again(store):
    seal_one(store)
    with pytest.raises(FileExistsError, match="already sealed"):
        seal_one(store)


def test_a_revision_writes_a_sibling_round_and_never_amends(store):
    first = seal_one(store, rnd=1)
    second = seal_one(store, rnd=2)
    assert first != second
    assert store.verify_evidence("FND-000001", 1) == [], "round 1 is untouched"


def test_editing_sealed_evidence_is_detected(store):
    """Not a WORM store - a local user can chmod a file back. But any such change is
    *detectable*, which is what auditability actually requires."""
    seal_one(store)
    p = os.path.join(store.root, "evidence", "FND-000001", "round-1", "build.log")
    os.chmod(p, 0o644)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("(and everything was fine)\n")
    problems = store.verify_evidence("FND-000001", 1)
    assert any("sha256 mismatch" in p for p in problems)


def test_unsealed_evidence_verifies_as_missing(store):
    assert store.verify_evidence("FND-000001", 1) == ["FND-000001 round 1: not sealed"]


# ── the audit chain ─────────────────────────────────────────────────────────────

def test_advancing_writes_the_record_and_the_log_together(store, finding):
    store.put(finding)
    store.advance(finding, "triaged", actor="harness:triage", reason="classified")
    assert store.get("FND-000001")["status"] == "triaged"
    assert [e["to"] for e in store.audit_entries()] == ["triaged"]


def test_an_illegal_transition_writes_nothing(store, finding):
    store.put(finding)
    with pytest.raises(TransitionError):
        store.advance(finding, "closed", actor="x", reason="skip")
    assert store.get("FND-000001")["status"] == "new"
    assert list(store.audit_entries()) == []


def test_verify_is_clean_on_a_well_formed_chain(store, finding):
    store.put(finding)
    store.advance(finding, "triaged", actor="h", reason="classified")
    store.advance(finding, "proposed", actor="h", reason="patch written")
    assert store.verify_audit() == []


def test_a_status_changed_behind_the_log_is_caught(store, finding):
    """A component that edits findings.jsonl directly instead of going through
    advance() is a defect in the harness, and this is how it surfaces."""
    store.put(finding)
    store.advance(finding, "triaged", actor="h", reason="classified")
    smuggled = store.get("FND-000001")
    smuggled["status"] = "closed"
    store.put(smuggled)
    problems = store.verify_audit()
    assert any("but the log ends at" in p for p in problems)
