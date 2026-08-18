#!/usr/bin/env python3
"""Verify that every quotation in TRACEABILITY.md really appears in the spec.

    python tools/check_quotes.py

A traceability matrix that misquotes its own source is worse than not having one: it
looks like diligence and is the opposite. An earlier iteration of this project
shipped a matrix whose "quotes" were paraphrases, which is the kind of thing that
ends a review in the first two minutes.

So the claim is checkable, and this is the check. Every `"..."` span in
TRACEABILITY.md must appear in PRODUCT_SPEC.md, after normalizing whitespace and
the markdown emphasis the spec transcription adds. Exit 1 if any does not.
"""

from __future__ import annotations

import os
import re
import sys

# A cp1252 console cannot print an em dash, and a checker that crashes on its own
# output is not a checker.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(HERE, "docs", "PRODUCT_SPEC.md")
DOC = os.path.join(HERE, "docs", "TRACEABILITY.md")

#: Quoted spans of at least four words. Shorter ones are terms, not quotations.
QUOTED = re.compile(r'"([^"\n]{16,})"')

#: Spans this file deliberately does not check: they are labelled in the document as
#: paraphrase or as this project's own words, not as quotations from the spec.
EXEMPT = (
    "actor=demo:auto-review",
)


def normalize(text: str) -> str:
    """Strip what the transcription adds and the source did not have: markdown
    emphasis, backticks, and line-wrapping. Compare on words, not on layout."""
    text = re.sub(r"[*`_]", "", text)
    text = text.replace("’", "'").replace("‘", "'")
    text = text.replace("“", '"').replace("”", '"')
    text = text.replace("—", "-").replace("–", "-")
    text = text.replace("…", "...")
    return re.sub(r"\s+", " ", text).strip().lower()


def main() -> int:
    spec = normalize(open(SPEC, encoding="utf-8").read())
    doc = open(DOC, encoding="utf-8").read()

    checked = missing = 0
    for line_no, line in enumerate(doc.splitlines(), start=1):
        # Strip `code spans` first: an identifier in backticks is not a quotation.
        for quote in QUOTED.findall(re.sub(r"`[^`]*`", "", line)):
            if any(e in quote for e in EXEMPT):
                continue
            checked += 1
            if normalize(quote) not in spec:
                missing += 1
                print(f"NOT IN SPEC  {DOC}:{line_no}\n             \"{quote}\"\n")

    print(f"{checked} quotation(s) checked against {os.path.basename(SPEC)}; "
          f"{missing} not found.")
    if missing:
        print("\nFix the quote or stop presenting it as one. A paraphrase is fine — "
              "without quotation marks.")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
