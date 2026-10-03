#!/usr/bin/env python3
"""The command a recursive-grep refusal names runs, and does what it says.

The hook refuses `grep -rn PAT .` and hands the model a rewrite: the same
command with `set -o pipefail;` ahead of it and `<this binary> filter` as its
last stage. The Go tests check the rewrite's text and that the hook allows it.
Neither runs it, and running it is the half that can fail on a platform: the
binary's own path is spliced into a shell command, and on Windows that is a
drive-letter path handed to Git Bash, which is what the Bash tool runs there.

So this builds the binary, drives the hook over three trees, and executes each
rewrite in bash:

  * a clean match crosses, exit 0, the matched line on stdout;
  * a planted key is withheld, exit 3, nothing on stdout;
  * no match keeps grep's own exit 1, which is what the pipefail is for;

and feeds each rewrite back to the hook, which has to let it through -- a
rewrite the hook refused in turn would hand the model a fix that loops.

Bash is found the way Claude Code finds it on Windows, at Git for Windows'
install path, because subprocess resolves a bare `bash` through System32 first
and that is WSL's. SPILL_GUARD_BASH overrides it.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANTED = ROOT / "testdata" / "corpus" / "planted" / "aws-access-key-id.env"
EXE = ".exe" if os.name == "nt" else ""


def find_bash():
    override = os.environ.get("SPILL_GUARD_BASH")
    if override:
        return override
    if os.name == "nt":
        git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
        if git_bash.exists():
            return str(git_bash)
        sys.exit("check-filter-rewrite: no Git Bash at " + str(git_bash) +
                 "; set SPILL_GUARD_BASH to the bash the Bash tool runs")
    found = shutil.which("bash")
    if not found:
        sys.exit("check-filter-rewrite: no bash on PATH")
    return found


def hook(binary, command, cwd):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": command}, "cwd": str(cwd),
               "session_id": "check-filter-rewrite"}
    r = subprocess.run([str(binary), "hook"], input=json.dumps(payload).encode(),
                       capture_output=True)
    if r.returncode != 0:
        sys.exit(f"check-filter-rewrite: the hook exited {r.returncode} on "
                 f"{command!r}: {r.stderr.decode(errors='replace')}")
    if not r.stdout.strip():
        return None, ""
    out = json.loads(r.stdout)["hookSpecificOutput"]
    return out["permissionDecision"], out["permissionDecisionReason"]


def rewrite_of(reason):
    _, sep, after = reason.partition("run it as `")
    if not sep:
        return ""
    return after.partition("` instead")[0]


def main():
    bash = find_bash()
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        binary = tmp / "bin" / ("spill-guard" + EXE)
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/spill-guard"],
                       cwd=ROOT, check=True)
        tree = tmp / "tree"
        (tree / "sub").mkdir(parents=True)
        (tree / "a.go").write_bytes(b"func foo() {}\n")
        shutil.copyfile(PLANTED, tree / "sub" / "k.env")

        # pattern, wanted exit, whether stdout must carry output
        cases = [
            ("foo", 0, True),
            ("AKIA", 3, False),
            ("no-such-text-anywhere", 1, False),
        ]
        for pattern, want_rc, want_out in cases:
            command = f"grep -rn {pattern} ."
            decision, reason = hook(binary, command, tree)
            if decision != "deny":
                failures.append(f"{command!r}: decision {decision!r}, want deny")
                continue
            rewrite = rewrite_of(reason)
            if not rewrite:
                failures.append(f"{command!r}: the reason names no rewrite: {reason}")
                continue
            again, _ = hook(binary, rewrite, tree)
            if again is not None:
                failures.append(f"{rewrite!r}: the hook answered {again!r} to its "
                                f"own rewrite, want no verdict")
            r = subprocess.run([bash, "-c", rewrite], cwd=tree, capture_output=True)
            stdout = r.stdout.decode(errors="replace")
            stderr = r.stderr.decode(errors="replace")
            print(f"{pattern!r}: exit {r.returncode}, {len(r.stdout)} bytes out")
            if r.returncode != want_rc:
                failures.append(f"{rewrite!r}: exit {r.returncode}, want {want_rc} "
                                f"(stderr: {stderr.strip()})")
            if want_out and "a.go" not in stdout:
                failures.append(f"{rewrite!r}: stdout {stdout!r}, want the match")
            # A byte count and not the bytes: on the planted arm they are
            # the key, and this message reaches whoever is reading the log.
            if not want_out and stdout:
                failures.append(f"{rewrite!r}: {len(r.stdout)} bytes on stdout, "
                                f"want nothing")
            if want_rc == 3 and "aws-access-key-id" not in stderr:
                failures.append(f"{rewrite!r}: stderr does not name the rule: "
                                f"{stderr.strip()}")

    if failures:
        for f in failures:
            print("check-filter-rewrite: " + f, file=sys.stderr)
        return 1
    print(f"check-filter-rewrite: {len(cases)} rewrites ran under {bash} and "
          f"did what their reasons say")
    return 0


if __name__ == "__main__":
    sys.exit(main())
