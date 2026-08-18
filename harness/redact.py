"""Strip secrets before anything is stored, indexed, or sent to a model.

The product's job includes fixing leaked credentials. A finding about a hardcoded
password contains that password in its snippet. If the harness writes that snippet
to disk and mails it to a model, the tool built to fix secret leaks has become the
next place they leak. The spec calls this out directly.

Two detectors:
  * shapes  — things whose format identifies them (AWS keys, PEM headers, JWTs, URIs
              with inline credentials)
  * entropy — long opaque tokens with no structure, caught by Shannon entropy

A match becomes `<REDACTED:xxxxxxxx>`, where the tag is the first 8 hex of the
secret's sha256. Two properties fall out of that:
  * the same secret always redacts to the same tag, so clustering still sees that
    two findings share a value without ever storing the value
  * a human can confirm a suspected secret matches a tag without the tag revealing it
"""

from __future__ import annotations

import hashlib
import math
import re

SHAPES: list[tuple[str, re.Pattern]] = [
    ("aws-access-key",  re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key",     re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")),
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("github-token",    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token",     re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("uri-credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s/@]{4,})@")),
    # `(?<![A-Za-z])` rather than `\b`: the name is usually prefixed, and `\b` does
    # NOT match between `_` and `P` in `DB_PASSWORD` because both are word characters.
    # That one detail is the difference between catching a hardcoded credential and
    # writing it to disk.
    ("assigned-secret", re.compile(
        r"(?i)(?<![A-Za-z])(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)"
        r"\s*[:=]\s*[\"']?([^\s\"',;)]{6,})")),
]

#: Opaque tokens long enough that guessing is implausible.
CANDIDATE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
ENTROPY_FLOOR = 4.0

#: Words that are long and mixed-case but are not secrets. Without this, class names
#: and file paths get redacted and every finding turns to noise.
ALLOW = re.compile(r"(?i)^(?:[a-z]+(?:[A-Z][a-z]+)+|[A-Za-z]+(?:[._-][A-Za-z]+)+|"
                   r"[0-9a-f]{7,40}|CWE-[0-9]+|https?)$")


def _tag(secret: str) -> str:
    return f"<REDACTED:{hashlib.sha256(secret.encode()).hexdigest()[:8]}>"


def entropy(s: str) -> float:
    """Shannon entropy in bits per character. Random-looking strings score high
    (a base64 key is ~5.0); English words and identifiers score low (~3.0)."""
    if not s:
        return 0.0
    total = 0.0
    for ch in set(s):
        p = s.count(ch) / len(s)
        total -= p * math.log2(p)
    return total


def redact(text: str) -> tuple[str, list[str]]:
    """Return the text with secrets replaced, and the list of detector names that fired."""
    if not text:
        return text, []
    hits: list[str] = []

    for name, pattern in SHAPES:
        def sub(m: re.Match) -> str:
            # If the pattern captured just the secret, keep the surrounding context.
            secret = m.group(1) if m.groups() else m.group(0)
            hits.append(name)
            return m.group(0).replace(secret, _tag(secret))
        text = pattern.sub(sub, text)

    def sub_entropy(m: re.Match) -> str:
        tok = m.group(0)
        if tok.startswith("<REDACTED:") or ALLOW.match(tok) or entropy(tok) < ENTROPY_FLOOR:
            return tok
        hits.append("high-entropy")
        return _tag(tok)

    text = CANDIDATE.sub(sub_entropy, text)
    return text, sorted(set(hits))


def redact_record(rec: dict) -> dict:
    """Redact a finding's free-text fields in place, and record which detectors fired
    so an auditor can see that redaction happened and on what basis."""
    fired: list[str] = []
    for field in ("title", "snippet"):
        if rec.get(field):
            rec[field], hits = redact(rec[field])
            fired += hits
    if fired:
        rec["redacted"] = sorted(set(fired))
    return rec
