"""Clustering collapses the backlog; retrieval grounds the fix in an approved pattern.

Clustering is where the economic case lives: Thousands of findings that fold into a few
hundred families is the difference between a programme that finishes and one that
does not. Retrieval is where "reusable" stops being a slogan.
"""

import json

from harness.record import new_record
from harness.stages import s2_cluster, s3_triage, s4_retrieve


def rec(fid, snippet, cwe="CWE-89", rule="py.sqli.concat", path="ledger/db.py", sev="high"):
    return new_record(finding_id=fid, source_scanner="semgrep", source_rule_id=rule,
                      repository="py-ledger", cwe=cwe, category="injection", severity=sev,
                      title="t", snippet=snippet, location={"file": path, "line": 1})


# ── clustering ──────────────────────────────────────────────────────────────────

def test_identical_findings_share_a_fingerprint():
    a = rec("FND-000001", "x")
    b = rec("FND-000002", "y")
    assert s2_cluster.fingerprint(a) == s2_cluster.fingerprint(b)


def test_a_different_file_is_a_different_fingerprint():
    a = rec("FND-000001", "x", path="ledger/db.py")
    b = rec("FND-000002", "x", path="ledger/other.py")
    assert s2_cluster.fingerprint(a) != s2_cluster.fingerprint(b)


def test_near_duplicates_merge_into_one_family(store):
    """The same mistake in two functions: different table, same shape."""
    store.write_all([
        rec("FND-000001", 'query = "SELECT id FROM accounts WHERE name = \'" + name + "\'"'),
        rec("FND-000002", 'query = "SELECT id FROM trades WHERE account = \'" + acct + "\'"',
            rule="py.sqli.concat2"),
    ])
    out = s2_cluster.run(store)
    assert out["clusters"] == 1, "the same defect twice is one remediation family"


def test_unrelated_findings_stay_apart(store):
    store.write_all([
        rec("FND-000001", 'query = "SELECT id FROM accounts WHERE name = \'" + name + "\'"'),
        rec("FND-000002", 'return hashlib.md5(pw.encode()).hexdigest()',
            cwe="CWE-327", rule="py.crypto.weak"),
    ])
    assert s2_cluster.run(store)["clusters"] == 2


def test_different_weakness_classes_never_merge(store):
    """Even with near-identical text. Two CWEs are never one remediation family,
    because one fix cannot close both."""
    same = 'value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
    store.write_all([rec("FND-000001", same, cwe="CWE-89", rule="a"),
                     rec("FND-000002", same, cwe="CWE-798", rule="b")])
    assert s2_cluster.run(store)["clusters"] == 2


def test_normalization_ignores_literals_and_numbers():
    """Two instances of one bug differ in their literals; the shape is what matches."""
    a = 'query = "SELECT id FROM accounts WHERE id = " + str(42)'
    b = 'query = "SELECT id FROM accounts WHERE id = " + str(7)'
    assert s2_cluster.similarity(a, b) > s2_cluster.NEAR_THRESHOLD


def test_a_merge_can_be_explained(store):
    """A cluster a human cannot check is a cluster a human cannot sign off on."""
    a = 'query = "SELECT id FROM accounts WHERE name = \'" + name + "\'"'
    b = 'query = "SELECT id FROM trades WHERE account = \'" + acct + "\'"'
    shared = s2_cluster.explain(a, b)
    assert shared, "explain() must name the shared trigrams that merged two findings"


def test_the_family_lead_is_the_most_severe(store):
    store.write_all([rec("FND-000001", "same snippet here", sev="low"),
                     rec("FND-000002", "same snippet here", sev="high")])
    s2_cluster.run(store)
    clusters = json.load(open(store.clusters, encoding="utf-8"))["clusters"]
    assert clusters["CL-0001"]["lead_finding"] == "FND-000002"


# ── confidence thresholds ───────────────────────────────────────────────────────

THRESHOLDS = {
    "default": 0.75,
    "categories": {"secrets": 0.60, "access-control": 0.85},
    "portfolios": {"clearing": {"default": 0.85, "categories": {"access-control": 0.90}},
                   "reporting": {"default": 0.70}},
}


def test_the_floor_is_per_category_and_per_portfolio():
    """The spec: 'calibrated per vulnerability category and portfolio, not globally'."""
    f = s3_triage.floor_for
    assert f(THRESHOLDS, "access-control", "clearing") == 0.90   # most specific wins
    assert f(THRESHOLDS, "injection", "clearing") == 0.85        # portfolio default
    assert f(THRESHOLDS, "injection", "reporting") == 0.70       # a different portfolio
    assert f(THRESHOLDS, "secrets", None) == 0.60               # category only
    assert f(THRESHOLDS, "crypto", None) == 0.75                # global default


def test_the_same_finding_can_pass_in_one_portfolio_and_not_another():
    """This is the whole point of a non-global threshold."""
    f = s3_triage.floor_for
    assert 0.80 > f(THRESHOLDS, "injection", "reporting")
    assert 0.80 < f(THRESHOLDS, "injection", "clearing")


# ── retrieval ───────────────────────────────────────────────────────────────────

def library(tmp_path, patterns):
    d = tmp_path / "library"
    d.mkdir(exist_ok=True)
    (d / "index.json").write_text(json.dumps({"patterns": patterns}), encoding="utf-8")
    return str(d)


PARAM = {"id": "sqli-param", "status": "approved", "cwe": "CWE-89", "category": "injection",
         "extensions": ["py"], "frameworks": ["sqlite3"], "sink_apis": ["execute"],
         "tags": ["sql", "where"], "path": "p.md", "reuse_count": 0}


def test_a_matching_pattern_clears_the_floor_with_reasons(tmp_path):
    r = rec("FND-000001", 'conn.execute(query) # sqlite3 where')
    out = s4_retrieve.retrieve(r, library_dir=library(tmp_path, [PARAM]))
    assert out["matches"] and out["matches"][0]["pattern_id"] == "sqli-param"
    assert out["matches"][0]["why"], "every match carries the reasons it scored"


def test_a_different_cwe_scores_zero(tmp_path):
    r = rec("FND-000001", "anything", cwe="CWE-79")
    out = s4_retrieve.retrieve(r, library_dir=library(tmp_path, [PARAM]))
    assert out["generate_fresh"] is True
    assert "different weakness class" in out["set_aside"][0]["why"][0]


def test_candidate_patterns_are_never_retrieved(tmp_path):
    """A pattern Security Engineering has not reviewed must not be reachable by an
    agent that would then apply it."""
    candidate = dict(PARAM, id="cand-x", status="candidate")
    out = s4_retrieve.retrieve(rec("FND-000001", "conn.execute(q) sqlite3"),
                               library_dir=library(tmp_path, [candidate]))
    assert out["matches"] == [] and out["generate_fresh"] is True


def test_reuse_raises_a_pattern_score(tmp_path):
    """The flywheel: a pattern that keeps working keeps getting reached for first."""
    r = rec("FND-000001", "conn.execute(query) sqlite3 where")
    cold = s4_retrieve.retrieve(r, library_dir=library(tmp_path, [PARAM]))
    warm = s4_retrieve.retrieve(r, library_dir=library(tmp_path, [dict(PARAM, reuse_count=7)]))
    assert warm["matches"][0]["score"] > cold["matches"][0]["score"]


def test_an_empty_library_asks_for_a_fresh_fix(tmp_path):
    out = s4_retrieve.retrieve(rec("FND-000001", "x"), library_dir=library(tmp_path, []))
    assert out["generate_fresh"] is True
