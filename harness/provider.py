"""The one place a model is called.

Three stages need judgement: triage, propose, review. All three come through here,
so "what did the AI see and what did it say" is one file to read and one directory
to look in.

Every call does the same five things:

  1. redact the prompt, so no secret leaves the process
  2. write the request to runs/<id>/llm/<n>-request.json
  3. call the provider
  4. validate the response against the stage's schema — a response that does not fit
     is a failure, not something to coerce into shape
  5. write the response to runs/<id>/llm/<n>-response.json

Step 4 is the one that matters. An unvalidated model response is how a harness
quietly starts trusting prose.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .redact import redact

PROMPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")


class ProviderError(Exception):
    """The model was unreachable, or answered something the schema rejects."""


# ── schemas ─────────────────────────────────────────────────────────────────────
# Deliberately tiny: field -> (type, validator). Enough to reject a malformed answer,
# small enough to read. A real deployment can swap in jsonschema; the check is
# `validate()` and nothing else changes.

TRIAGE_SCHEMA = {
    "category":         (str,   lambda v: v in ("injection", "secrets", "access-control",
                                                "crypto", "dependency", "other")),
    "cwe":              (str,   lambda v: v.startswith("CWE-")),
    "root_cause":       (str,   lambda v: 10 <= len(v) <= 400),
    "confidence_score": (float, lambda v: 0.0 <= v <= 1.0),
    "reasoning":        (str,   lambda v: len(v) > 0),
}

PROPOSE_SCHEMA = {
    "diff":        (str,  lambda v: v.startswith("---") or v.startswith("diff ")),
    "pattern_id":  (str,  lambda v: True),   # nullable — validate() special-cases it
    "test_name":   (str,  lambda v: len(v) > 0),
    "test_source": (str,  lambda v: len(v) > 0),
    "explanation": (str,  lambda v: len(v) > 0),
    "left_alone":  (list, lambda v: all(isinstance(x, str) for x in v)),
}

REVIEW_SCHEMA = {
    "verdict":    (str,  lambda v: v in ("approve", "reject")),
    "objections": (list, lambda v: all(isinstance(x, str) for x in v)),
    "reasoning":  (str,  lambda v: len(v) > 0),
}


def validate(payload: Any, schema: dict) -> dict:
    if not isinstance(payload, dict):
        raise ProviderError(f"model returned {type(payload).__name__}, expected an object")
    missing = [k for k in schema if k not in payload]
    if missing:
        raise ProviderError(f"model response missing required field(s): {', '.join(missing)}")
    for key, (typ, ok) in schema.items():
        v = payload[key]
        if key == "pattern_id":                      # the one nullable field
            if v is not None and not isinstance(v, str):
                raise ProviderError("pattern_id must be a string or null")
            continue
        if typ is float and isinstance(v, int):
            v = payload[key] = float(v)
        if not isinstance(v, typ):
            raise ProviderError(f"{key}: expected {typ.__name__}, got {type(v).__name__}")
        if not ok(v):
            raise ProviderError(f"{key}: value {v!r} is outside what the schema allows")
    return payload


# ── providers ───────────────────────────────────────────────────────────────────

class MockProvider:
    """Replays recorded responses from fixtures/llm/<prompt>/<key>.json.

    Not a toy. It is how the tests pin behaviour, and it is why the whole pipeline
    runs offline in seconds with no key and no network. A recorded response is a real
    response someone read and checked in — which makes the demo reproducible instead
    of merely impressive.
    """

    name = "mock"

    def __init__(self, fixtures: str):
        self.fixtures = fixtures

    def complete(self, prompt_name: str, key: str, _prompt: str) -> Any:
        p = os.path.join(self.fixtures, prompt_name, f"{key}.json")
        if not os.path.exists(p):
            raise ProviderError(
                f"no recorded response at {p}. Record one, or run with --provider claude-code.")
        return json.load(open(p, encoding="utf-8"))


class ClaudeCodeProvider:
    """Hands the request to the surrounding Claude Code session.

    Writes the prompt to the run's llm/ directory and stops, telling the caller which
    file to answer. The session reads it, thinks, and writes the response beside it.
    Slower than an API call and needs no API key — which is the point when the model
    is only approved to run inside a session.
    """

    name = "claude-code"

    def __init__(self, llm_dir: str):
        self.llm_dir = llm_dir

    def complete(self, prompt_name: str, key: str, prompt: str) -> Any:
        req = os.path.join(self.llm_dir, f"{prompt_name}-{key}.prompt.md")
        res = os.path.join(self.llm_dir, f"{prompt_name}-{key}.response.json")
        if os.path.exists(res):
            return json.load(open(res, encoding="utf-8"))
        os.makedirs(self.llm_dir, exist_ok=True)
        with open(req, "w", encoding="utf-8") as fh:
            fh.write(prompt)
        raise ProviderError(
            f"awaiting judgement. Read {req}, write the JSON answer to {res}, and re-run this stage.")


class AnthropicProvider:
    """Direct API call. Present so the seam is real, not so it is used today."""

    name = "anthropic"

    def __init__(self, model: str = "claude-opus-5"):
        self.model = model

    def complete(self, prompt_name: str, key: str, prompt: str) -> Any:
        try:
            import anthropic                                    # noqa: PLC0415
        except ImportError as e:
            raise ProviderError("the anthropic package is not installed") from e
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model=self.model, max_tokens=4096,
            messages=[{"role": "user", "content": prompt}])
        text = msg.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ProviderError(f"model did not return JSON: {text[:200]}") from e


def build(kind: str, *, fixtures: str, llm_dir: str, model: str = "claude-opus-5"):
    if kind == "mock":
        return MockProvider(fixtures)
    if kind == "claude-code":
        return ClaudeCodeProvider(llm_dir)
    if kind == "anthropic":
        return AnthropicProvider(model)
    raise ProviderError(f"unknown provider {kind!r}; expected mock, claude-code, or anthropic")


# ── the call ────────────────────────────────────────────────────────────────────

def ask(provider, *, prompt_name: str, key: str, variables: dict, schema: dict,
        llm_dir: str) -> dict:
    """Render a prompt, call the model, validate what comes back, record both sides."""
    template = open(os.path.join(PROMPTS, f"{prompt_name}.md"), encoding="utf-8").read()
    prompt = template
    for name, value in variables.items():
        text = value if isinstance(value, str) else json.dumps(value, indent=2, sort_keys=True)
        prompt = prompt.replace("{{" + name + "}}", text)

    prompt, redacted = redact(prompt)

    os.makedirs(llm_dir, exist_ok=True)
    n = len([f for f in os.listdir(llm_dir) if f.endswith("-request.json")]) + 1
    with open(os.path.join(llm_dir, f"{n:03d}-request.json"), "w", encoding="utf-8") as fh:
        json.dump({"prompt_name": prompt_name, "key": key, "provider": provider.name,
                   "redacted": redacted, "prompt": prompt}, fh, indent=2)

    raw = provider.complete(prompt_name, key, prompt)
    result = validate(raw, schema)

    with open(os.path.join(llm_dir, f"{n:03d}-response.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    return result
