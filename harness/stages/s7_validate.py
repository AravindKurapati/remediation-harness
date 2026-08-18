"""Stage 7 — validate.

  in:  an approved record, its patch, and the target's commands from targets.yaml
  out: a sealed evidence bundle; status `validated` or `exception`

Three gates, in order, stopping at the first failure:

  build    the project compiles with the patch applied
  test     the suite is green AND the new regression test both ran and passed
  rescan   the originating rule no longer fires AND no new finding appeared

Three verdicts: `pass`, `fail`, `unavailable`.

**`unavailable` is not `pass`.** A gate whose toolchain is missing records what it
could not run, and blocks closure. This is the single rule the evidence contract
rests on. A receipt that overstates what ran is worse than no receipt — it launders
an unvalidated change into an audit trail, which is exactly the failure the client
is buying protection against.

The harness runs the project's own commands from `targets.yaml`. It does not invent
a build, install a toolchain, or rewrite a build file. If the project cannot build
itself, that is the project's answer and the harness records it.

Everything happens in a scratch copy. The target repository is never modified.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

GATES = ("build", "test", "rescan")


def apply_patch(workspace: str, diff_text: str) -> tuple[bool, str]:
    """Apply the diff to the scratch copy. Returns (ok, output).

    `git apply` first because it refuses an inexact match; `patch -p1` second because
    it is more widely present. Note that `patch` will apply with *fuzz* where `git
    apply` refuses — so the order matters: we want the strict tool's answer when it
    is available.

    Everything is bytes, encoded UTF-8 explicitly. `text=True` would encode using the
    platform's preferred encoding, which on Windows is cp1252 — and a single non-ASCII
    character in a context line then fails to round-trip and the patch silently stops
    matching. That is a genuinely nasty bug: the diff looks correct in every editor
    and the tool reports a mismatch on a line that appears identical.
    """
    attempts = []
    for cmd in (["git", "apply", "--verbose", "-"], ["patch", "-p1"]):
        try:
            p = subprocess.run(cmd, cwd=workspace, input=diff_text.encode("utf-8"),
                               capture_output=True, timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            attempts.append(f"{cmd[0]}: not available")
            continue
        out = (p.stdout + p.stderr).decode("utf-8", errors="replace").strip()
        if p.returncode == 0:
            return True, out
        attempts.append(f"{cmd[0]}: exit {p.returncode}: {out[:400]}")
    return False, "the diff did not apply. " + " | ".join(attempts)


def fill(command: str | None, subs: dict[str, str]) -> str | None:
    """Substitute the per-finding placeholders a gate command may carry.

    `{harness} {repo} {workspace} {file} {rule}`. The re-scan gate needs them because
    it checks *this* finding's rule at *this* finding's location — a scan that only
    reported "the tree is clean overall" would pass a patch that moved the bug.
    """
    if not command:
        return command
    for key, value in subs.items():
        command = command.replace("{" + key + "}", value)
    return command


def run_gate(name: str, command: str | None, workspace: str, timeout: int = 600,
             env_extra: dict[str, str] | None = None) -> dict:
    """One gate. Never returns `pass` for something it did not observe succeed."""
    if not command:
        return {"gate": name, "verdict": "unavailable", "command": None,
                "reason": f"no {name} command declared for this target in targets.yaml"}

    tool = command.split()[0]
    if shutil.which(tool) is None:
        return {"gate": name, "verdict": "unavailable", "command": command,
                "reason": f"{tool} is not on PATH"}

    started = time.time()
    try:
        # utf-8 with errors="replace": a build log can contain anything, and a gate
        # must never fail because its own output would not decode.
        p = subprocess.run(command, cwd=workspace, shell=True, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           env={**os.environ, **(env_extra or {})})
    except subprocess.TimeoutExpired:
        return {"gate": name, "verdict": "fail", "command": command,
                "reason": f"timed out after {timeout}s", "duration": timeout}

    return {"gate": name, "verdict": "pass" if p.returncode == 0 else "fail",
            "command": command, "exit_code": p.returncode,
            "duration": round(time.time() - started, 1),
            "output": (p.stdout + p.stderr)[-8000:]}


def check_test_ran(gate: dict, test_name: str) -> dict:
    """A green suite is not proof. If the new regression test did not appear in the
    output, the suite was green with or without the fix and the gate proves nothing."""
    if gate["verdict"] != "pass" or not test_name:
        return gate
    if test_name.split(".")[-1] not in gate.get("output", ""):
        gate["verdict"] = "fail"
        gate["reason"] = (f"the suite passed but {test_name} did not appear in the output; the "
                          f"regression test did not run, so the suite proves nothing here")
    return gate


def run(rec: dict, *, store, repo_root: str, target: dict, round_no: int) -> tuple[dict, str, str]:
    """Returns (record, next_status, reason). Seals evidence either way."""
    workspace = tempfile.mkdtemp(prefix=f"rh-{rec['finding_id']}-")
    results: list[dict] = []
    try:
        shutil.copytree(repo_root, workspace, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(".git", "runs", "__pycache__",
                                                      "target", "build", ".gradle"))

        diff_text = open(os.path.join(store.root, rec["proposal"]["patch"]),
                         encoding="utf-8").read()
        applied, apply_out = apply_patch(workspace, diff_text)
        if not applied:
            results = [{"gate": "build", "verdict": "fail", "command": "apply patch",
                        "reason": apply_out}]
        else:
            test_src = open(os.path.join(store.root, rec["proposal"]["test_file"]),
                            encoding="utf-8").read()
            if target.get("test_path"):
                dest = os.path.join(workspace, target["test_path"])
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(test_src)

            subs = {
                "harness":   os.path.dirname(os.path.dirname(os.path.dirname(
                                 os.path.abspath(__file__)))),
                "repo":      os.path.abspath(repo_root),
                "workspace": workspace,
                "file":      (rec.get("location") or {}).get("file") or "",
                "rule":      rec.get("source_rule_id") or "",
            }
            # Scanner text goes in the environment, never on the command line: it is
            # attacker-influenceable, and shell-quoting it correctly on every platform
            # is not a thing to rely on.
            env_extra = {"RH_SNIPPET": (rec.get("snippet") or "").strip(),
                         "RH_FINDING": rec["finding_id"]}
            for name in GATES:
                gate = run_gate(name, fill(target.get(name), subs), workspace,
                                env_extra=env_extra)
                if name == "test":
                    gate = check_test_ran(gate, rec["proposal"]["test_name"])
                results.append(gate)
                if gate["verdict"] != "pass":
                    break                    # stop at the first gate that did not pass
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    verdicts = {g["gate"]: g["verdict"] for g in results}
    ran = [g["gate"] for g in results]
    overall = ("passed" if all(verdicts.get(g) == "pass" for g in GATES)
               else "blocked" if "unavailable" in verdicts.values()
               else "failed")

    artifacts = {f"{g['gate']}.log": _render(g) for g in results}
    artifacts["patch.diff"] = open(os.path.join(store.root, rec["proposal"]["patch"]),
                                   encoding="utf-8").read()
    link = store.seal(rec["finding_id"], round_no, artifacts,
                      {"overall": overall, "gates": verdicts, "gates_run": ran,
                       "test_name": rec["proposal"]["test_name"],
                       "pattern_id": rec.get("matched_pattern_id")})
    rec["evidence_link"] = link

    summary = ", ".join(f"{g}: {verdicts.get(g, 'not reached')}" for g in GATES)
    if overall == "passed":
        return rec, "validated", f"all three gates passed ({summary})"

    blocker = next(g for g in results if g["verdict"] != "pass")
    detail = blocker.get("reason") or f"exit {blocker.get('exit_code')}"
    kind = "gate-unavailable" if blocker["verdict"] == "unavailable" else "gate-failed"
    return rec, "exception", f"{kind}: {blocker['gate']} — {detail} ({summary})"


def _render(gate: dict) -> str:
    head = [f"gate:    {gate['gate']}",
            f"verdict: {gate['verdict']}",
            f"command: {gate.get('command')}"]
    if "exit_code" in gate:
        head.append(f"exit:    {gate['exit_code']}")
    if "duration" in gate:
        head.append(f"took:    {gate['duration']}s")
    if gate.get("reason"):
        head.append(f"reason:  {gate['reason']}")
    return "\n".join(head) + "\n\n" + ("-" * 60) + "\n" + gate.get("output", "(no output)")
