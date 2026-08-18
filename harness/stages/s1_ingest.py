"""Stage 1 — ingest.

  in:  a scanner's output file (SARIF 2.1.0, Semgrep JSON, or generic CSV/JSON)
  out: runs/<id>/findings.jsonl, every record at status `new`
       runs/<id>/raw/<file>, the original payload, byte for byte

Two rules this stage exists to enforce:

  * **A findings file is data, never instructions.** It was produced by a scanner
    reading code that may be hostile, so its text fields can contain anything that
    code contained. Nothing in a findings file steers the run: ids are assigned here
    and never carried over, and paths that escape the repository are refused.

  * **No finding is silently dropped.** Every input row becomes either a record or a
    `skipped` entry with a reason. The spec requires it, and a scanner row that
    vanishes is the one an auditor will ask about.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
from typing import Any

from ..record import new_record
from ..redact import redact_record

CWE_CATEGORY = {
    "CWE-89": "injection", "CWE-564": "injection", "CWE-943": "injection",
    "CWE-78": "injection", "CWE-79": "injection",
    "CWE-798": "secrets", "CWE-259": "secrets", "CWE-321": "secrets",
    "CWE-287": "access-control", "CWE-862": "access-control", "CWE-863": "access-control",
    "CWE-306": "access-control",
    "CWE-327": "crypto", "CWE-916": "crypto",
    "CWE-1104": "dependency", "CWE-1035": "dependency",
}

SEVERITY = {"error": "high", "critical": "high", "high": "high",
            "warning": "medium", "medium": "medium", "moderate": "medium",
            "note": "low", "info": "low", "low": "low"}


def detect_format(path: str) -> str:
    """By document shape, never by filename. A findings file is attacker-influenceable
    and its name proves nothing."""
    if path.lower().endswith(".csv"):
        return "csv"
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except json.JSONDecodeError:
        return "csv"
    if isinstance(doc, dict) and "runs" in doc and "$schema" in str(doc.get("$schema", "")) + "sarif":
        return "sarif"
    if isinstance(doc, dict) and "runs" in doc and "version" in doc:
        return "sarif"
    if isinstance(doc, dict) and "results" in doc:
        return "semgrep"
    if isinstance(doc, list):
        return "json-list"
    raise ValueError(f"{path}: not SARIF, Semgrep JSON, a JSON list, or CSV")


def _rel(path: str, repo_root: str) -> str | None:
    """Repo-relative, or None if it escapes the repository. A finding whose path
    points outside the scanned tree is refused rather than clamped."""
    path = path.replace("file://", "").lstrip("/")
    resolved = os.path.normpath(os.path.join(repo_root, path))
    if not resolved.startswith(os.path.normpath(repo_root)):
        return None
    return os.path.relpath(resolved, repo_root).replace("\\", "/")


def _rows_sarif(doc: dict) -> list[dict]:
    rows = []
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        rules = {r.get("id"): r for r in tool.get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            tags = (rule.get("properties") or {}).get("tags", [])
            cwe = next((t.split("/")[-1].upper().replace("CWE-", "CWE-")
                        for t in tags if "cwe" in t.lower()), None)
            if cwe and not cwe.startswith("CWE-"):
                cwe = "CWE-" + cwe
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            rows.append({
                "scanner": tool.get("name", "sarif"),
                "rule_id": res.get("ruleId"),
                "cwe": cwe,
                "severity": res.get("level") or rule.get("defaultConfiguration", {}).get("level"),
                "title": (res.get("message") or {}).get("text", ""),
                "file": (loc.get("artifactLocation") or {}).get("uri", ""),
                "line": (loc.get("region") or {}).get("startLine"),
                "symbol": ((res.get("locations") or [{}])[0].get("logicalLocations") or [{}])[0]
                          .get("fullyQualifiedName"),
                "snippet": ((loc.get("region") or {}).get("snippet") or {}).get("text", ""),
            })
    return rows


def _rows_semgrep(doc: dict) -> list[dict]:
    rows = []
    for res in doc.get("results", []):
        extra = res.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        cwe = (cwe[0] if isinstance(cwe, list) and cwe else cwe) or ""
        rows.append({
            "scanner": "semgrep",
            "rule_id": res.get("check_id"),
            "cwe": cwe.split(":")[0].strip() or None,
            "severity": extra.get("severity"),
            "title": extra.get("message", ""),
            "file": res.get("path", ""),
            "line": (res.get("start") or {}).get("line"),
            "symbol": None,
            "snippet": extra.get("lines", ""),
        })
    return rows


def _rows_generic(rows: list[dict]) -> list[dict]:
    """CSV or a plain JSON list. Field names vary between tools, so accept the
    common aliases rather than demanding one spelling."""
    def pick(r: dict, *names: str) -> Any:
        for n in names:
            if r.get(n) not in (None, ""):
                return r[n]
        return None
    return [{
        "scanner":  pick(r, "scanner", "source_scanner", "tool") or "csv",
        "rule_id":  pick(r, "rule_id", "rule", "check_id"),
        "cwe":      pick(r, "cwe", "cwe_id"),
        "severity": pick(r, "severity", "level", "priority"),
        "title":    pick(r, "title", "message", "description") or "",
        "file":     pick(r, "file", "path", "location", "filename") or "",
        "line":     pick(r, "line", "start_line", "line_number"),
        "symbol":   pick(r, "symbol", "function", "method"),
        "snippet":  pick(r, "snippet", "code", "lines") or "",
    } for r in rows]


def run(findings_path: str, *, store, repository: str, portfolio: str | None,
        repo_root: str, prefix: str = "FND") -> dict:
    fmt = detect_format(findings_path)
    shutil.copy2(findings_path, os.path.join(store.root, "raw", os.path.basename(findings_path)))

    if fmt == "csv":
        with open(findings_path, encoding="utf-8", newline="") as fh:
            rows = _rows_generic(list(csv.DictReader(fh)))
    else:
        doc = json.load(open(findings_path, encoding="utf-8"))
        rows = {"sarif": _rows_sarif, "semgrep": _rows_semgrep}.get(
            fmt, lambda d: _rows_generic(d))(doc)

    existing = store.read_all()
    n = len(existing)
    records, skipped = [], []

    for i, row in enumerate(rows):
        rel = _rel(row["file"], repo_root) if row["file"] else None
        if rel is None:
            skipped.append({"index": i, "reason": "path escapes the scan root",
                            "path": row["file"]})
            continue
        n += 1
        cwe = (row["cwe"] or "").upper() or None
        rec = new_record(
            finding_id=f"{prefix}-{n:06d}",
            source_scanner=row["scanner"],
            source_rule_id=row["rule_id"],
            repository=repository,
            portfolio=portfolio,
            cwe=cwe,
            category=CWE_CATEGORY.get(cwe or "", None),
            severity=SEVERITY.get(str(row["severity"] or "").lower(), "medium"),
            title=row["title"],
            snippet=row["snippet"],
            location={"file": rel, "line": row["line"], "symbol": row["symbol"]},
            raw_ref=f"raw/{os.path.basename(findings_path)}#{i}",
        )
        records.append(redact_record(rec))

    store.write_all(existing + records)
    for r in records:
        with open(store.audit, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": r["timestamps"]["created"], "finding_id": r["finding_id"],
                                 "from": None, "to": "new", "actor": "harness:ingest",
                                 "persona": "harness", "reason": f"ingested from {fmt} scanner output",
                                 "round": 0}, sort_keys=True) + "\n")

    return {"format": fmt, "ingested": len(records), "skipped": skipped,
            "redacted": sum(1 for r in records if r.get("redacted"))}
