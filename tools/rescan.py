#!/usr/bin/env python3
"""The re-scan gate: run the originating scanner again and check two things.

    rescan.py --rules rules.yaml --before <clean tree> --after <patched tree> \
              --file ledger/db.py --rule py.sqli.string-concat-into-execute

The spec asks the harness to "re-run the original scanner(s) against the changed code
to confirm the finding is no longer detected, not just that a diff was merged". Two
conditions, and both must hold:

  1. the originating rule no longer fires AT THE FLAGGED LOCATION
  2. no NEW rule fires that was not firing before

Condition 1 says "at the flagged location" and means it. A file often holds several
instances of the same weakness - that is exactly what clustering is for - so a check
of "does this rule fire anywhere in the file" would fail a correct patch because a
SIBLING finding is still open. The flagged line is identified by its content, not its
number, because line numbers move when a patch adds lines above them.

Condition 2 is why this scans twice. A patch that closes a SQL injection by
introducing a hardcoded credential has not made the code safer, and a gate that
checked only condition 1 would call it a pass.

Exit 0 when both hold, 1 otherwise. Every hit is printed, so the gate log says what
was actually observed rather than only its verdict.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

import yaml


def scan(root: str, rel: str, rules: list[dict]) -> list[tuple[str, int, str]]:
    """Returns (rule_id, line_number, the line) for every hit in one file."""
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return []
    hits = []
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    for rule in rules:
        pattern = re.compile(rule["pattern"])
        for n, line in enumerate(lines, start=1):
            if pattern.search(line):
                hits.append((rule["id"], n, line.strip()))
    return hits


def main(argv=None) -> int:
    p = argparse.ArgumentParser("rescan")
    p.add_argument("--rules", required=True)
    p.add_argument("--before", required=True, help="the tree as it was, for the baseline")
    p.add_argument("--after", required=True, help="the tree with the patch applied")
    p.add_argument("--file", required=True, help="repo-relative path of the flagged file")
    p.add_argument("--rule", required=True, help="the rule id that produced the finding")
    # The snippet is NOT a command-line argument. It is arbitrary text lifted out of
    # scanned source, so putting it on a command line means shell-quoting attacker-
    # influenced content - and on Windows a `<` in it is a redirection operator, which
    # is how this was found. It arrives in RH_SNIPPET instead.
    p.add_argument("--snippet", default=os.environ.get("RH_SNIPPET", ""),
                   help="(default: $RH_SNIPPET) the flagged line's content, used to "
                        "locate it after a patch has moved line numbers")
    a = p.parse_args(argv)

    rules = (yaml.safe_load(open(a.rules, encoding="utf-8")) or {}).get("rules", [])
    if not rules:
        print(f"no rules in {a.rules}", file=sys.stderr)
        return 1

    before = scan(a.before, a.file, rules)
    after = scan(a.after, a.file, rules)

    print(f"rules:  {len(rules)} from {a.rules}")
    print(f"file:   {a.file}")
    print(f"before: {len(before)} hit(s)")
    for rid, n, line in before:
        print(f"          {rid} line {n}: {line[:100]}")
    print(f"after:  {len(after)} hit(s)")
    for rid, n, line in after:
        print(f"          {rid} line {n}: {line[:100]}")

    same_rule = [h for h in after if h[0] == a.rule]
    target = a.snippet.strip()
    if "<REDACTED:" in target:
        # A secrets finding's snippet is redacted before storage, on purpose - the
        # harness must not keep the credential. So there is no literal to match, and
        # the count comparison below is the honest check.
        print(f"note:   snippet is redacted, so matching by content is impossible; "
              f"comparing hit counts instead")
        target = ""
    if target:
        # The specific line that was flagged, found by content.
        still_there = [h for h in same_rule if h[2] == target]
        where = f"the flagged line ({target[:60]!r})"
    else:
        # No snippet given: fall back to requiring the count to strictly decrease.
        before_same = [h for h in before if h[0] == a.rule]
        still_there = same_rule if len(same_rule) >= len(before_same) else []
        where = f"{a.rule} (no snippet given, so comparing hit counts: "                 f"{len(before_same)} -> {len(same_rule)})"

    new_kinds = {h[0] for h in after} - {h[0] for h in before}

    ok = True
    if still_there:
        print(f"FAIL: {a.rule} still fires at {where}, line(s) "
              f"{', '.join(str(h[1]) for h in still_there)}")
        ok = False
    else:
        print(f"PASS: {a.rule} no longer fires at {where}")

    siblings = [h for h in same_rule if not target or h[2] != target]
    if siblings:
        print(f"NOTE: {len(siblings)} other instance(s) of {a.rule} remain in this file. "
              f"They are separate findings and are not this patch's job.")

    if new_kinds:
        print(f"FAIL: the patch introduced new finding kind(s): {', '.join(sorted(new_kinds))}")
        ok = False
    else:
        print("PASS: no new finding kind appeared")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
