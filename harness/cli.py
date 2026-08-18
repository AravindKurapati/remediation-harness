"""The command line. One subcommand per stage, plus `run` which chains them.

    harness ingest    --findings scan.sarif --target py-ledger
    harness triage    --run R-...   [--provider mock|claude-code|anthropic]
    harness propose   --run R-...
    harness approve   --run R-... --finding FND-000001 --actor priya@example.com
    harness validate  --run R-...
    harness close     --run R-... --finding FND-000001 --actor sam@example.com
    harness report    --run R-...
    harness verify    --run R-...
    harness serve     --run R-...

    harness run --findings scan.sarif --target py-ledger --auto-review
        the whole pipeline end to end. --auto-review makes the *advisory* verdict
        stand in for a human so a demo can run unattended; it is refused unless
        config.yaml sets `allow_auto_review: true`, and every such approval is
        logged as `actor=demo:auto-review` so it is obvious in the audit trail.

Every subcommand takes and returns files. Nothing is held between calls.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

import yaml

from . import provider as prov
from .roles import NotPermitted
from .runstore import RunStore
from .stages import (s1_ingest, s2_cluster, s3_triage, s4_retrieve, s5_propose,
                     s6_approve, s7_validate, s8_close, s9_learn, s10_report)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def library_dir() -> str:
    """Where the approved patterns live.

    `$RH_LIBRARY` overrides the default. Two reasons it is not simply a constant:
    the test suite must not mutate the repository's tracked library (a suite that
    dirties `git status` is a suite people stop trusting), and three client accounts
    on one accelerator will each want their own approved corpus.
    """
    return os.environ.get("RH_LIBRARY") or os.path.join(ROOT, "library")


def load(name: str, default=None):
    p = os.path.join(ROOT, name)
    if not os.path.exists(p):
        return default
    return yaml.safe_load(open(p, encoding="utf-8")) or default


def target_of(name: str) -> dict:
    targets = load("targets.yaml", {}).get("targets", {})
    if name not in targets:
        raise SystemExit(f"no target {name!r} in targets.yaml. Known: {', '.join(targets) or 'none'}")
    t = dict(targets[name])
    t["root"] = os.path.join(ROOT, t["root"]) if not os.path.isabs(t["root"]) else t["root"]
    return t


def open_run(run_id: str) -> RunStore:
    store = RunStore(os.path.join(ROOT, "runs", run_id))
    if not os.path.exists(store.findings):
        raise SystemExit(f"no run {run_id} (looked in {store.root})")
    return store


def make_provider(kind: str, store: RunStore):
    return prov.build(kind, fixtures=os.path.join(ROOT, "fixtures", "llm"),
                      llm_dir=os.path.join(store.root, "llm"),
                      model=load("config.yaml", {}).get("model", "claude-opus-5"))


#: Windows terminals default to a codepage that cannot print these, and a demo that
#: shows mojibake reads as a broken tool. Transliterating in one place keeps the
#: source prose readable and the output portable.
_ASCII = str.maketrans({"—": "-", "–": "-", "'": "'", "'": "'", '"': '"', '"': '"',
                        "→": "->", "•": "*", "…": "..."})


def say(*parts) -> None:
    print(*(str(p).translate(_ASCII) for p in parts), flush=True)


# ── stages ──────────────────────────────────────────────────────────────────────

def cmd_ingest(a) -> RunStore:
    t = target_of(a.target)
    run_id = a.run or f"R-{dt.datetime.now(dt.timezone.utc):%Y%m%d-%H%M%S}"
    store = RunStore.create(os.path.join(ROOT, "runs"), run_id)
    out = s1_ingest.run(a.findings, store=store, repository=a.target,
                        portfolio=t.get("portfolio"), repo_root=t["root"],
                        prefix=load("config.yaml", {}).get("id_prefix", "FND"))
    say(f"[1/10] ingest     {out['ingested']} findings from {out['format']}"
        + (f", {len(out['skipped'])} refused" if out["skipped"] else "")
        + (f", {out['redacted']} redacted" if out["redacted"] else ""))
    for s in out["skipped"]:
        say(f"        refused row {s['index']}: {s['reason']} ({s['path']})")
    say(f"        run: {run_id}")
    return store


def cmd_cluster(a) -> None:
    store = open_run(a.run)
    out = s2_cluster.run(store)
    say(f"[2/10] cluster    {out['findings']} findings -> {out['clusters']} clusters "
        f"({out['collapsed']} folded in)")


def cmd_triage(a) -> None:
    store, t = open_run(a.run), target_of(a.target) if a.target else None
    provider = make_provider(a.provider, store)
    thresholds = load("thresholds.yaml", {"default": 0.75})
    root = t["root"] if t else _repo_root_of(store)
    ok = queued = manual = 0
    for fid in store.ids_by_status("new"):
        rec = store.get(fid)
        rec, nxt, reason = s3_triage.run(rec, store=store, provider=provider,
                                         repo_root=root, thresholds=thresholds)
        if nxt == "new":
            store.put(rec); queued += 1; say(f"        {rec['finding_id']} queued: {reason}")
            continue
        store.advance(rec, nxt, actor="harness:triage", reason=reason)
        ok += nxt == "triaged"
        manual += nxt == "exception"
    say(f"[3/10] triage     {ok} triaged, {manual} to manual queue"
        + (f", {queued} queued (model unavailable)" if queued else ""))


def cmd_propose(a) -> None:
    """First proposals, and revisions.

    A record at `triaged` gets its first patch. A record at `proposed` carrying
    `needs_revision` was sent back by a reviewer — it gets another round with those
    objections in the prompt. That is flow step 10, and it is the same function
    because a revision is a proposal that has read the feedback.
    """
    store, t = open_run(a.run), target_of(a.target) if a.target else None
    provider = make_provider(a.provider, store)
    root = t["root"] if t else _repo_root_of(store)
    made = revised = failed = 0

    work = store.ids_by_status("triaged") + [r["finding_id"] for r in store.by_status("proposed")
                                             if r.get("needs_revision")]
    for fid in work:
        rec = store.get(fid)           # re-read: an earlier iteration may have written here
        feedback = rec.get("needs_revision")
        retrieval = s4_retrieve.run(rec, library_dir=library_dir())
        top = retrieval["matches"][0] if retrieval["matches"] else None
        say(f"[4/10] retrieve   {rec['finding_id']}: "
            + (f"{top['pattern_id']} ({top['score']}) - {'; '.join(top['why'][:2])}"
               if top else "nothing cleared the floor; will generate fresh"))
        rec, nxt, reason = s5_propose.run(rec, retrieval, store=store, provider=provider,
                                          repo_root=root, feedback=feedback,
                                          library_dir=library_dir())
        if feedback and nxt == "proposed":
            store.put(rec)            # already at `proposed`; the round was logged on rejection
            revised += 1
            say(f"        {rec['finding_id']} revised (round {rec['rounds'] + 1}): {reason}")
            continue
        store.advance(rec, nxt, actor="harness:propose", reason=reason)
        made += nxt == "proposed"; failed += nxt == "exception"
    say(f"[5/10] propose    {made} proposed"
        + (f", {revised} revised" if revised else "")
        + (f", {failed} to exception queue" if failed else ""))


def cmd_approve(a) -> None:
    store = open_run(a.run)
    roles = os.path.join(ROOT, "roles.yaml")
    rec = store.get(a.finding)
    if rec["status"] != "proposed":
        raise SystemExit(f"{a.finding} is {rec['status']}, not proposed — nothing to approve")

    if a.show:
        patch = open(os.path.join(store.root, rec["proposal"]["patch"]), encoding="utf-8").read()
        say(patch)
    try:
        if a.reject:
            _, again = s6_approve.reject(rec, store=store, actor=a.actor, roles_file=roles,
                                         objections=a.reject)
            s9_learn.record_rejection(rec, a.reject, library_dir=library_dir())
            say(f"[6/10] rejected   {a.finding} by {a.actor} — "
                + ("back for another round" if again else "revision cap reached, to exception queue"))
        else:
            s6_approve.approve(rec, store=store, actor=a.actor, roles_file=roles, note=a.note or "")
            say(f"[6/10] approved   {a.finding} by {a.actor}")
    except NotPermitted as e:
        raise SystemExit(f"refused: {e}")


def cmd_validate(a) -> None:
    store, t = open_run(a.run), target_of(a.target) if a.target else None
    t = t or target_of(store.read_all()[0]["repository"])
    passed = blocked = 0
    for fid in store.ids_by_status("approved"):
        rec = store.get(fid)
        rec, nxt, reason = s7_validate.run(rec, store=store, repo_root=t["root"],
                                           target=t, round_no=rec["rounds"] + 1)
        store.advance(rec, nxt, actor="harness:validate", reason=reason)
        passed += nxt == "validated"; blocked += nxt == "exception"
        say(f"        {rec['finding_id']}: {reason}")
    say(f"[7/10] validate   {passed} validated" + (f", {blocked} blocked" if blocked else ""))


def cmd_close(a) -> None:
    store = open_run(a.run)
    roles = os.path.join(ROOT, "roles.yaml")
    rec = store.get(a.finding)
    try:
        if a.accept_risk:
            s8_close.accept_risk(rec, store=store, actor=a.actor, roles_file=roles,
                                 justification=a.accept_risk)
            say(f"[8/10] risk accepted  {a.finding} by {a.actor}")
            return
        s8_close.close(rec, store=store, actor=a.actor, roles_file=roles, note=a.note or "")
    except (NotPermitted, ValueError) as e:
        raise SystemExit(f"refused: {e}")
    out = s9_learn.run(rec, store=store, library_dir=library_dir())
    say(f"[8/10] closed     {a.finding} by {a.actor}")
    say(f"[9/10] learn      {out['action']}"
        + (f" {out.get('pattern_id', '')}" if out.get("pattern_id") else "")
        + (f"; suggested to {len(out['propagation']['suggested'])} cluster siblings"
           if out["propagation"]["suggested"] else ""))


def cmd_report(a) -> None:
    store = open_run(a.run)
    m = s10_report.run(store)
    k = m["kpi"]
    say(f"[10/10] report    {store.metrics}")
    say("")
    say(f"  findings {m['totals']['findings']}  ->  clusters {m['totals']['clusters']['count']}"
        f"  (folded {m['totals']['clusters']['collapsed']})")
    say(f"  cycle time      {k['cycle_time']['overall_hours']} h avg")
    say(f"  burn-down       {k['burn_down']['high_closed']}/{k['burn_down']['high_total']} high closed"
        f"  ({k['burn_down']['percent_closed']}%)")
    say(f"  rework rate     {k['rework_rate']['rate']}  ({k['rework_rate']['rejections']}"
        f"/{k['rework_rate']['proposals']} proposals sent back)")
    say(f"  repeatability   {k['repeatability']['share']}  "
        f"({k['repeatability']['with_pattern']}/{k['repeatability']['closed']} closures reused a pattern)")
    say(f"  recurrence      {k['recurrence']['reopened']} reopened")
    say(f"  evidence        {k['evidence_completeness']['percent']}% of closures verified complete")
    say(f"  exception queue {k['exception_queue']['size']} items, "
        f"mean age {k['exception_queue']['mean_age_days']} d")
    for reason, n in k["exception_queue"]["by_reason"].items():
        say(f"      {n:3d}  {reason}")
    if m["audit_problems"]:
        say("")
        say("  AUDIT PROBLEMS:")
        for p in m["audit_problems"]:
            say(f"      {p}")


def cmd_verify(a) -> None:
    store = open_run(a.run)
    problems = store.verify_audit()
    for rec in store.read_all():
        if rec.get("evidence_link"):
            problems += [f"{rec['finding_id']}: {p}"
                         for p in store.verify_evidence(rec["finding_id"], rec["rounds"] + 1)]
    if problems:
        say(f"verify: {len(problems)} problem(s)")
        for p in problems:
            say(f"  {p}")
        raise SystemExit(1)
    say(f"verify: audit chain sound, all sealed evidence hashes intact")


def cmd_serve(a) -> None:
    from .dashboard.serve import serve
    serve(open_run(a.run), port=a.port)


def cmd_library(a) -> None:
    lib = library_dir()
    doc = json.load(open(os.path.join(lib, "index.json"), encoding="utf-8"))
    if a.promote:
        for p in doc["patterns"]:
            if p["id"] == a.promote:
                if p["status"] != "candidate":
                    raise SystemExit(f"{a.promote} is {p['status']}, not a candidate")
                p["status"] = "approved"
                json.dump(doc, open(os.path.join(lib, "index.json"), "w", encoding="utf-8"),
                          indent=2, sort_keys=True)
                say(f"promoted {a.promote} — it is now retrievable")
                return
        raise SystemExit(f"no pattern {a.promote}")
    for p in doc["patterns"]:
        say(f"  {p['status']:9s} {p['id']:52s} {p.get('cwe') or '':8s} reused {p.get('reuse_count', 0)}")
    if doc.get("rejections"):
        say(f"  {len(doc['rejections'])} recorded rejection(s)")


# ── the whole pipeline ──────────────────────────────────────────────────────────

def cmd_run(a) -> None:
    store = cmd_ingest(a)
    a.run = os.path.basename(store.root)
    cmd_cluster(a)
    cmd_triage(a)
    cmd_propose(a)

    cfg = load("config.yaml", {})
    if a.auto_review:
        if not cfg.get("allow_auto_review"):
            raise SystemExit("--auto-review needs `allow_auto_review: true` in config.yaml. "
                             "It exists for unattended demos; a real approval names a human.")
        # review, then re-propose anything sent back, until nothing is pending revision
        for _ in range(s6_approve.MAX_ROUNDS + 1):
            _auto_review(store, a)
            if not [r for r in store.by_status("proposed") if r.get("needs_revision")]:
                break
            say("[10/10] revise    reviewer objections returned to the proposal stage")
            cmd_propose(a)
    else:
        pending = store.by_status("proposed")
        say("")
        say(f"  {len(pending)} proposal(s) awaiting a Security Reviewer:")
        for r in pending:
            say(f"      harness approve --run {a.run} --finding {r['finding_id']} "
                f"--actor <you> --show")
        return

    cmd_validate(a)
    _auto_close(store, a)
    cmd_report(a)
    _library_note()


def _library_note() -> None:
    """Say what landed in the library and that nobody has reviewed it yet.

    Stage 9 writes candidate patterns into the working tree on purpose - the spec
    requires that new patterns "only enter the library through Security Engineering
    review", so an uncommitted change awaiting a human IS the review gate. Without
    this line the run looks like it dirtied your checkout for no reason.
    """
    import json
    index = os.path.join(library_dir(), "index.json")
    if not os.path.exists(index):
        return
    doc = json.load(open(index, encoding="utf-8"))
    cands = [p["id"] for p in doc.get("patterns", []) if p.get("status") == "candidate"]
    rejects = len(doc.get("rejections", []))
    if not cands and not rejects:
        return
    say("")
    if cands:
        say(f"  library: {len(cands)} candidate pattern(s) written to your working tree, "
            f"unreviewed and NOT retrievable:")
        for c in cands:
            say(f"      {c}")
        say(f"      review, then `harness library --promote <id>` and commit.")
    if rejects:
        say(f"  library: {rejects} recorded rejection(s) - what a reviewer refused, and why.")


def _auto_review(store: RunStore, a) -> None:
    """Demo path. The advisory verdict stands in for a human, and the audit trail says
    so — actor `demo:auto-review`, never a person's name."""
    provider = make_provider(a.provider, store)
    roles = os.path.join(ROOT, "roles.yaml")
    ok = no = 0
    for fid in store.ids_by_status("proposed"):
        rec = store.get(fid)
        patch = open(os.path.join(store.root, rec["proposal"]["patch"]), encoding="utf-8").read()
        verdict = s6_approve.advise(rec, store=store, provider=provider, patch=patch)
        if verdict["verdict"] == "approve":
            s6_approve.approve(rec, store=store, actor="demo:auto-review", roles_file=roles,
                               note=verdict["reasoning"][:160])
            ok += 1
        else:
            s6_approve.reject(rec, store=store, actor="demo:auto-review", roles_file=roles,
                              objections=verdict["objections"])
            s9_learn.record_rejection(rec, verdict["objections"],
                                      library_dir=library_dir())
            no += 1
        say(f"        {rec['finding_id']}: {verdict['verdict']} — {verdict['reasoning'][:90]}")
    say(f"[6/10] review     {ok} approved, {no} rejected  (advisory verdict, demo mode)")


def _auto_close(store: RunStore, a) -> None:
    roles = os.path.join(ROOT, "roles.yaml")
    for fid in store.ids_by_status("validated"):
        rec = store.get(fid)           # re-read: cluster propagation writes to siblings
        try:
            s8_close.close(rec, store=store, actor="demo:auto-review", roles_file=roles,
                           note="demo mode")
        except (NotPermitted, ValueError) as e:
            say(f"        {rec['finding_id']} not closed: {e}")
            continue
        out = s9_learn.run(rec, store=store, library_dir=library_dir())
        say(f"[9/10] learn      {rec['finding_id']}: {out['action']}"
            + (f", suggested to {len(out['propagation']['suggested'])} sibling(s)"
               if out["propagation"]["suggested"] else ""))


def _repo_root_of(store: RunStore) -> str:
    return target_of(store.read_all()[0]["repository"])["root"]


# ── argument parsing ────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser("harness", description="governed vulnerability remediation")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, *, run=True, target=False, provider=False):
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        if run:
            s.add_argument("--run", required=True)
        if target:
            s.add_argument("--target")
        if provider:
            s.add_argument("--provider", default="mock",
                           choices=["mock", "claude-code", "anthropic"])
        return s

    i = sub.add_parser("ingest"); i.set_defaults(fn=cmd_ingest)
    i.add_argument("--findings", required=True); i.add_argument("--target", required=True)
    i.add_argument("--run")

    add("cluster", cmd_cluster)
    add("triage", cmd_triage, target=True, provider=True)
    add("propose", cmd_propose, target=True, provider=True)

    ap = add("approve", cmd_approve)
    ap.add_argument("--finding", required=True); ap.add_argument("--actor", required=True)
    ap.add_argument("--reject", nargs="*"); ap.add_argument("--note"); ap.add_argument("--show",
                                                                                      action="store_true")

    add("validate", cmd_validate, target=True)

    cl = add("close", cmd_close)
    cl.add_argument("--finding", required=True); cl.add_argument("--actor", required=True)
    cl.add_argument("--note"); cl.add_argument("--accept-risk")

    add("report", cmd_report)
    add("verify", cmd_verify)
    add("serve", cmd_serve).add_argument("--port", type=int, default=8711)

    lb = sub.add_parser("library"); lb.set_defaults(fn=cmd_library, run=None)
    lb.add_argument("--promote")

    r = sub.add_parser("run"); r.set_defaults(fn=cmd_run)
    r.add_argument("--findings", required=True); r.add_argument("--target", required=True)
    r.add_argument("--run"); r.add_argument("--auto-review", action="store_true")
    r.add_argument("--provider", default="mock", choices=["mock", "claude-code", "anthropic"])

    a = p.parse_args(argv)
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
