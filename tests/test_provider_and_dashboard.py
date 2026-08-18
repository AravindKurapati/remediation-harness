"""The model boundary, and the dashboard's read-only guarantee.

An unvalidated model response is how a harness quietly starts trusting prose, so the
schema check is not a formality. And the dashboard's promise - "no dashboard action
can change a finding's status" - is only worth anything if it is structural.
"""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from harness import provider as prov
from harness.dashboard.serve import serve


# ── the schema boundary ─────────────────────────────────────────────────────────

GOOD_TRIAGE = {"category": "injection", "cwe": "CWE-89", "root_cause": "concatenated input",
               "confidence_score": 0.9, "reasoning": "clear"}


def test_a_well_formed_response_passes():
    assert prov.validate(dict(GOOD_TRIAGE), prov.TRIAGE_SCHEMA)["confidence_score"] == 0.9


def test_a_missing_field_is_a_failure_not_a_default():
    bad = {k: v for k, v in GOOD_TRIAGE.items() if k != "confidence_score"}
    with pytest.raises(prov.ProviderError, match="missing required field"):
        prov.validate(bad, prov.TRIAGE_SCHEMA)


def test_a_confidence_outside_zero_to_one_is_refused():
    with pytest.raises(prov.ProviderError, match="outside what the schema allows"):
        prov.validate(dict(GOOD_TRIAGE, confidence_score=1.7), prov.TRIAGE_SCHEMA)


def test_an_invented_category_is_refused():
    with pytest.raises(prov.ProviderError, match="outside what the schema allows"):
        prov.validate(dict(GOOD_TRIAGE, category="probably-bad"), prov.TRIAGE_SCHEMA)


def test_an_integer_confidence_is_accepted_as_a_float():
    assert prov.validate(dict(GOOD_TRIAGE, confidence_score=1), prov.TRIAGE_SCHEMA
                         )["confidence_score"] == 1.0


def test_prose_instead_of_an_object_is_refused():
    with pytest.raises(prov.ProviderError, match="expected an object"):
        prov.validate("Sure! Here is the triage:", prov.TRIAGE_SCHEMA)


def test_a_null_pattern_id_is_allowed_but_a_number_is_not():
    body = {"diff": "--- a\n", "pattern_id": None, "test_name": "t", "test_source": "s",
            "explanation": "e", "left_alone": []}
    assert prov.validate(dict(body), prov.PROPOSE_SCHEMA)["pattern_id"] is None
    with pytest.raises(prov.ProviderError, match="string or null"):
        prov.validate(dict(body, pattern_id=7), prov.PROPOSE_SCHEMA)


def test_a_rewritten_file_instead_of_a_diff_is_refused():
    """A diff is reviewable; a replacement file is not."""
    body = {"diff": "def f():\n    pass\n", "pattern_id": None, "test_name": "t",
            "test_source": "s", "explanation": "e", "left_alone": []}
    with pytest.raises(prov.ProviderError, match="diff"):
        prov.validate(body, prov.PROPOSE_SCHEMA)


def test_a_review_verdict_is_only_approve_or_reject():
    with pytest.raises(prov.ProviderError):
        prov.validate({"verdict": "looks fine to me", "objections": [], "reasoning": "r"},
                      prov.REVIEW_SCHEMA)


def test_a_missing_recording_says_how_to_proceed(tmp_path):
    p = prov.MockProvider(str(tmp_path))
    with pytest.raises(prov.ProviderError, match="--provider claude-code"):
        p.complete("triage", "FND-999999", "prompt")


def test_the_claude_code_provider_writes_the_prompt_and_waits(tmp_path):
    """No API key: the request lands on disk for the surrounding session to answer."""
    p = prov.ClaudeCodeProvider(str(tmp_path))
    with pytest.raises(prov.ProviderError, match="awaiting judgement"):
        p.complete("triage", "FND-000001", "the prompt text")
    assert (tmp_path / "triage-FND-000001.prompt.md").read_text(
        encoding="utf-8") == "the prompt text"


def test_an_unknown_provider_is_refused():
    with pytest.raises(prov.ProviderError, match="unknown provider"):
        prov.build("gpt-please", fixtures="f", llm_dir="l")


# ── the dashboard ───────────────────────────────────────────────────────────────

@pytest.fixture
def dashboard(store, finding):
    store.put(finding)
    with open(store.metrics, "w", encoding="utf-8") as fh:
        json.dump({"kpi": {}, "totals": {"findings": 1}}, fh)
    port = 8765
    threading.Thread(target=serve, args=(store, port, False), daemon=True).start()
    time.sleep(0.6)
    return f"http://127.0.0.1:{port}"


def test_the_page_and_its_data_are_served(dashboard):
    assert "<title>" in urllib.request.urlopen(dashboard + "/").read().decode()
    data = json.loads(urllib.request.urlopen(dashboard + "/data.json").read())
    assert data["findings"][0]["finding_id"] == "FND-000001"


@pytest.mark.parametrize("verb", ["POST", "PUT", "DELETE", "PATCH"])
def test_the_dashboard_implements_no_write_verb(dashboard, verb):
    """The spec: 'no dashboard action can change a finding's status'. The way to be
    sure is not to disable the verbs - it is never to write them. There is no
    do_POST in serve.py, so the standard library answers 501."""
    req = urllib.request.Request(dashboard + "/", data=b"{}", method=verb)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 501


def test_the_dashboard_has_no_write_handler_in_its_source():
    """A structural assertion, so adding one is a deliberate act that fails a test."""
    import inspect

    from harness.dashboard import serve as mod
    source = inspect.getsource(mod)
    for verb in ("POST", "PUT", "DELETE", "PATCH"):
        assert f"def do_{verb}" not in source, f"do_{verb} was defined in the dashboard server"
    assert "def do_GET" in source, "GET is the only verb, and it must be there"
