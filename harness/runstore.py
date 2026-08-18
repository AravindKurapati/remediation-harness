"""The run directory: read it, append to it, seal it.

One invocation produces one run directory, and that directory is the entire state of
the system. No stage holds anything in memory between calls, so you can run a stage,
open the files, and run the next one — which is also how you debug it.

Two rules are enforced here rather than trusted to each stage:

  * `advance()` writes the audit entry and the record's new status together. A
    component cannot change a status without logging it, or log without changing it.
  * `seal()` makes evidence read-only and records a sha256 for every file. Sealing
    twice is refused; that is what makes "immutable once generated" checkable.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from typing import Any, Iterator

from . import record as rec_mod


class RunStore:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)

    # ── layout ──────────────────────────────────────────────────────────────────

    @property
    def findings(self) -> str: return os.path.join(self.root, "findings.jsonl")
    @property
    def audit(self) -> str: return os.path.join(self.root, "audit.jsonl")
    @property
    def clusters(self) -> str: return os.path.join(self.root, "clusters.json")
    @property
    def metrics(self) -> str: return os.path.join(self.root, "metrics.json")

    def path(self, *parts: str) -> str:
        p = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    @classmethod
    def create(cls, runs_dir: str, run_id: str) -> "RunStore":
        store = cls(os.path.join(runs_dir, run_id))
        for sub in ("raw", "llm", "patches", "evidence"):
            os.makedirs(os.path.join(store.root, sub), exist_ok=True)
        return store

    def discard(self) -> None:
        """Delete this run, sealed evidence and all.

        An ordinary `rm -rf` does NOT work here, and that is the design working:
        sealed artifacts are mode 444, and Windows refuses to unlink a read-only file.
        So destroying evidence has to be a deliberate call that says it is destroying
        evidence, rather than something a cleanup script does by accident.
        """
        def force(func, path, _exc):
            os.chmod(path, stat.S_IWRITE)
            func(path)

        shutil.rmtree(self.root, onerror=force)

    # ── records ─────────────────────────────────────────────────────────────────

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.findings):
            return []
        with open(self.findings, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def write_all(self, records: list[dict]) -> None:
        """Rewrite findings.jsonl. Whole-file, because a record is small and a
        partial write that leaves the file half-old is worse than a slow one."""
        tmp = self.findings + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        os.replace(tmp, self.findings)

    def get(self, finding_id: str) -> dict:
        for r in self.read_all():
            if r["finding_id"] == finding_id:
                return r
        raise KeyError(f"no finding {finding_id} in {self.findings}")

    def put(self, updated: dict) -> None:
        records = self.read_all()
        for i, r in enumerate(records):
            if r["finding_id"] == updated["finding_id"]:
                records[i] = updated
                break
        else:
            records.append(updated)
        self.write_all(records)

    def by_status(self, *statuses: str) -> list[dict]:
        return [r for r in self.read_all() if r["status"] in statuses]

    def ids_by_status(self, *statuses: str) -> list[str]:
        """Ids, not records — so a loop re-reads each one just before acting on it.

        This matters more than it looks. A stage that iterates over record *objects*
        is holding a snapshot from before the loop started, and any write another
        iteration made to a sibling (cluster propagation does exactly that) is then
        overwritten by the stale copy on the next `put`. Iterating ids and calling
        `get` fresh is the fix, and it is why the run directory is the state rather
        than a cache of it.
        """
        return [r["finding_id"] for r in self.read_all() if r["status"] in statuses]

    # ── the audit log ───────────────────────────────────────────────────────────

    def advance(self, r: dict, to: str, *, actor: str, reason: str,
                persona: str = "harness") -> dict:
        """Change a status and log it, as one operation. The only way either happens."""
        entry = rec_mod.transition(r, to, actor=actor, reason=reason, persona=persona)
        self.put(r)
        with open(self.audit, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return r

    def audit_entries(self) -> Iterator[dict]:
        if not os.path.exists(self.audit):
            return iter(())
        with open(self.audit, encoding="utf-8") as fh:
            return iter([json.loads(line) for line in fh if line.strip()])

    def verify_audit(self) -> list[str]:
        """Replay the log against the machine. Returns the problems found — an empty
        list means every status in findings.jsonl is reachable by a logged path."""
        problems: list[str] = []
        seen: dict[str, str] = {}
        for e in self.audit_entries():
            fid, frm = e["finding_id"], e["from"]
            if frm is None:                       # the creation entry: nothing -> new
                seen[fid] = e["to"]
                continue
            if fid in seen and seen[fid] != frm:
                problems.append(f"{fid}: log jumps {seen[fid]} -> {frm} with no entry between")
            if e["to"] not in rec_mod.TRANSITIONS.get(frm, ()):
                problems.append(f"{fid}: illegal transition {frm} -> {e['to']}")
            if not e.get("reason", "").strip():
                problems.append(f"{fid}: {frm} -> {e['to']} logged with no reason")
            seen[fid] = e["to"]
        for r in self.read_all():
            if r["status"] != seen.get(r["finding_id"], "new"):
                problems.append(f"{r['finding_id']}: status is {r['status']} but the log ends at "
                                f"{seen.get(r['finding_id'], 'new')}")
        return problems

    # ── evidence ────────────────────────────────────────────────────────────────

    def seal(self, finding_id: str, round_no: int, artifacts: dict[str, str],
             summary: dict[str, Any]) -> str:
        """Write a round's artifacts once, hash them, make them read-only.

        `artifacts` is name -> content. Returns the manifest path, which becomes the
        record's `evidence_link`. A sealed round is never rewritten; a revision writes
        `round-2/` beside `round-1/`.
        """
        d = os.path.join(self.root, "evidence", finding_id, f"round-{round_no}")
        if os.path.exists(os.path.join(d, "manifest.json")):
            raise FileExistsError(f"{d} is already sealed; a revision writes round-{round_no + 1}")
        os.makedirs(d, exist_ok=True)

        digests = {}
        for name, content in artifacts.items():
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
            digests[name] = hashlib.sha256(content.encode()).hexdigest()
            os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)   # 444

        manifest = {"finding_id": finding_id, "round": round_no,
                    "sealed_at": rec_mod.now(), "sha256": digests, **summary}
        mp = os.path.join(d, "manifest.json")
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        os.chmod(mp, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return os.path.relpath(mp, self.root)

    def verify_evidence(self, finding_id: str, round_no: int) -> list[str]:
        """Re-hash a sealed round. Any mismatch means the evidence was edited after
        the fact, which is the thing an audit trail exists to make visible."""
        d = os.path.join(self.root, "evidence", finding_id, f"round-{round_no}")
        mp = os.path.join(d, "manifest.json")
        if not os.path.exists(mp):
            return [f"{finding_id} round {round_no}: not sealed"]
        manifest = json.load(open(mp, encoding="utf-8"))
        problems = []
        for name, expected in manifest["sha256"].items():
            p = os.path.join(d, name)
            if not os.path.exists(p):
                problems.append(f"{name}: missing")
                continue
            actual = hashlib.sha256(open(p, encoding="utf-8").read().encode()).hexdigest()
            if actual != expected:
                problems.append(f"{name}: sha256 mismatch — sealed {expected[:12]}, now {actual[:12]}")
            if os.access(p, os.W_OK) and os.name != "nt":   # Windows ignores chmod 444 for owners
                problems.append(f"{name}: writable after sealing")
        return problems
