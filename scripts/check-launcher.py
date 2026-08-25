#!/usr/bin/env python3
"""Check that the launcher runs, resolves, and denies when it cannot.

`hooks.json` cannot invoke the binary directly. An absent one exits 127 and a
non-executable one exits 126, and only exit 2 blocks a tool call -- so the hook
would be installed, silent, and enforcing nothing, with nothing in the
transcript. The launcher exists to turn that into a deny, and every property
that makes it work is one nothing else here holds:

  * `hooks-check` does not reach it. That script scopes to `.githooks` and asks
    whether git will run a hook; this file is invoked by Claude Code, not git,
    and lives somewhere else. A launcher at mode 644 would pass every gate in
    this repo and never fire once -- which is exit-status-guard's 1.0.0 bug,
    not a hypothetical.
  * A suite that invokes the binary directly never executes the launcher at
    all, and a launcher that stopped working produces exactly the empty stdout
    a clean call produces.

So this drives the file. Each platform drives the path that platform will
actually take: cmd.exe runs the batch half and everything else runs the POSIX
half, and neither half is exercised by the other. The stub is a real executable
built from a temporary single-file Go program, so `spill-guard.exe` on Windows
is an executable Windows will run rather than a script standing in for one.

The deny cases assert their own precondition. A launcher that denied because
the test forgot to hide something proves nothing, so before believing a deny
this asks the child environment whether it can resolve `spill-guard` at all --
naming the tool rather than a directory it might live in.

Exits 1 and lists every finding, so one run reports all of them.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "hooks" / "run-spill-guard.cmd"
TRACKED = "hooks/run-spill-guard.cmd"
EXECUTABLE = "100755"
WINDOWS = os.name == "nt"

# A stub that reports everything the launcher is supposed to hand it. Built
# rather than scripted: on Windows the default install location names
# spill-guard.exe, and a batch file with that name is not something cmd.exe
# will run.
STUB = """package main

import (
\t"fmt"
\t"io"
\t"os"
)

func main() {
\tfmt.Printf("argv:%q\\n", os.Args[1:])
\tin, _ := io.ReadAll(os.Stdin)
\tfmt.Printf("stdin:%q\\n", in)
}
"""

STUB_NAME = "spill-guard.exe" if WINDOWS else "spill-guard"


def build_stub(into):
    """Build the stub executable into `into` and return its path."""
    src = into / "stub.go"
    src.write_text(STUB, encoding="utf-8")
    out = into / STUB_NAME
    result = subprocess.run(("go", "build", "-o", str(out), str(src)),
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        sys.exit(f"launcher: could not build the stub binary, so nothing below "
                 f"could have been driven:\n{result.stderr.strip()}")
    return out


def evidence(rc, out, err):
    """What a reader of a CI log needs to act on a finding.

    The launcher writes its reasoning to stderr and its verdict to stdout, so a
    finding that quotes only stdout throws away the half that says why. Every
    finding below carries this; the cost of not carrying it is a CI round trip
    per hypothesis, on the one platform this gate exists to reach and nobody
    can drive locally.
    """
    return f"exit {rc}, stdout {out!r}, stderr {err.strip()!r}"


def run(env, args=(), stdin=""):
    """Invoke the launcher the way Claude Code does -- through a shell, by
    path -- and return (rc, stdout, stderr).

    Going through a shell is the point on POSIX: the file carries no shebang,
    so it is the shell's ENOEXEC fallback that runs it under /bin/sh, and that
    fallback needs the execute bit the index check asserts separately.
    """
    if WINDOWS:
        argv = ("cmd", "/c", str(LAUNCHER)) + tuple(args)
    else:
        quoted = " ".join(f'"{a}"' for a in (str(LAUNCHER),) + tuple(args))
        argv = ("/bin/sh", "-c", quoted)
    p = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                       check=False, cwd=ROOT, env=env)
    return p.returncode, p.stdout, p.stderr


def path_without_spill_guard():
    """The real PATH with every directory holding a spill-guard removed.

    Naming directories to keep would be guesswork about where the tool lives,
    and this repo has already paid for that once: `PATH=/usr/bin:/bin` was used
    to hide Go from a gate and hid nothing, because CI had linked Go into
    /usr/bin. So this names the tool and drops whatever holds it -- which also
    means the gate keeps working on a machine where spill-guard is installed,
    rather than reporting a finding about the developer's laptop.
    """
    keep = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        here = Path(entry)
        if any((here / name).exists()
               for name in ("spill-guard", "spill-guard.exe")):
            continue
        keep.append(entry)
    return os.pathsep.join(keep)


def base_env(tmp):
    """An environment with no spill-guard reachable by any of the three routes.

    HOME and LOCALAPPDATA are redirected so the default install location is a
    directory that exists and is empty, which is the state a machine is in
    before the install script has run.
    """
    env = dict(os.environ)
    env.pop("SPILL_GUARD_BIN", None)
    env["PATH"] = path_without_spill_guard()
    env["HOME"] = str(tmp)
    env["LOCALAPPDATA"] = str(tmp)
    (tmp / ".local" / "bin").mkdir(parents=True, exist_ok=True)
    (tmp / "spill-guard" / "bin").mkdir(parents=True, exist_ok=True)
    return env


def resolvable(env):
    """Whether the child environment can find a spill-guard at all.

    This is the precondition on every deny case below. `PATH=/usr/bin:/bin` was
    once used elsewhere in this repo to hide a tool and hid nothing, because
    the CI setup had linked it into /usr/bin -- so ask about the tool rather
    than about a directory.
    """
    probe = "where spill-guard" if WINDOWS else "command -v spill-guard"
    argv = ("cmd", "/c", probe) if WINDOWS else ("/bin/sh", "-c", probe)
    p = subprocess.run(argv, capture_output=True, text=True, check=False,
                       env=env)
    return p.returncode == 0 and p.stdout.strip() != ""


def deny_reason(out):
    """The permissionDecisionReason in `out`, or None if it is not a deny.

    Parsed rather than grepped: the property is that Claude Code can read this
    as a decision object, and a string that merely contains the word deny is
    the failure mode -- the launcher's own stdout is the only thing standing
    between a missing binary and a tool call nobody scanned.
    """
    try:
        decoded = json.loads(out)
    except (ValueError, TypeError):
        return None
    block = decoded.get("hookSpecificOutput")
    if not isinstance(block, dict):
        return None
    if block.get("hookEventName") != "PreToolUse":
        return None
    if block.get("permissionDecision") != "deny":
        return None
    reason = block.get("permissionDecisionReason")
    return reason if isinstance(reason, str) and reason else None


def index_mode(findings):
    out = subprocess.run(("git", "ls-files", "-s", "--", TRACKED), cwd=ROOT,
                         check=True, capture_output=True, text=True).stdout
    if not out.strip():
        findings.append(f"{TRACKED} is not tracked, so there is no launcher "
                        f"for hooks.json to invoke")
        return
    mode = out.split()[0]
    if mode != EXECUTABLE:
        findings.append(f"{TRACKED} is mode {mode} in the index, so a fresh "
                        f"clone gets a launcher the shell refuses with 126 and "
                        f"the tool call runs unscanned -- "
                        f"`git update-index --chmod=+x {TRACKED}`")


def denies_with_nothing_installed(findings, tmp):
    env = base_env(tmp)
    if resolvable(env):
        findings.append("the environment for the deny cases can still resolve "
                        "a spill-guard, so a deny below would prove nothing "
                        "and a run would prove nothing either")
        return
    rc, out, err = run(env, ("hook",))
    reason = deny_reason(out)
    if reason is None:
        findings.append(f"with no binary anywhere the launcher did not write "
                        f"anything Claude Code reads as a deny, so the tool "
                        f"call would run unscanned -- {evidence(rc, out, err)}")
        return
    if "install" not in reason.lower():
        findings.append(f"the deny for a missing binary names no way to "
                        f"install one: {reason!r}")


def denies_on_an_unusable_explicit_path(findings, tmp, stub):
    """SPILL_GUARD_BIN naming nothing must deny rather than fall back.

    The control is the second half: a resolvable binary sits on PATH, so a
    launcher that quietly fell back would run and this would go green.
    """
    env = base_env(tmp)
    env["SPILL_GUARD_BIN"] = str(tmp / "not-a-file")
    env["PATH"] = os.pathsep.join([str(stub.parent), env["PATH"]])
    if not resolvable(env):
        findings.append("the fallback control cannot resolve a spill-guard on "
                        "PATH, so this case cannot tell a deny from a launcher "
                        "that fell back and found nothing")
        return
    rc, out, err = run(env, ("hook",))
    if deny_reason(out) is None:
        findings.append(f"SPILL_GUARD_BIN naming a path that is not executable "
                        f"did not deny -- an explicit path that does not work "
                        f"is a configuration error, not a reason to run some "
                        f"other binary -- {evidence(rc, out, err)}")


def resolves(findings, tmp, stub, route):
    """Each resolution route runs the binary, with argv and stdin intact."""
    env = base_env(tmp)
    if route == "SPILL_GUARD_BIN":
        env["SPILL_GUARD_BIN"] = str(stub)
    elif route == "PATH":
        env["PATH"] = os.pathsep.join([str(stub.parent), env["PATH"]])
    elif route == "the default install location":
        target = tmp / ("spill-guard/bin" if WINDOWS else ".local/bin")
        shutil.copy2(stub, target / STUB_NAME)
    rc, out, err = run(env, ("hook", "--flag"), stdin="payload-on-stdin")
    if rc != 0:
        findings.append(f"{route}: the launcher exited non-zero instead of "
                        f"running the binary -- {evidence(rc, out, err)}")
        return
    if 'argv:["hook" "--flag"]' not in out:
        findings.append(f"{route}: the binary did not receive the arguments "
                        f"verbatim -- {evidence(rc, out, err)}")
    if 'stdin:"payload-on-stdin"' not in out:
        findings.append(f"{route}: the binary did not receive stdin, which is "
                        f"where the hook payload arrives -- {evidence(rc, out, err)}")


def main():
    if shutil.which("go") is None:
        sys.exit("launcher: no go on PATH, and the stub this drives the "
                 "launcher with is built rather than scripted")

    findings = []
    index_mode(findings)

    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        stub_dir = work / "bin"
        stub_dir.mkdir(parents=True)
        stub = build_stub(stub_dir)

        denies_with_nothing_installed(findings, work / "case-missing")
        denies_on_an_unusable_explicit_path(findings, work / "case-explicit",
                                            stub)
        for route in ("SPILL_GUARD_BIN", "PATH", "the default install location"):
            resolves(findings, work / f"case-{route.split()[0]}", stub, route)

    for entry in findings:
        print(f"launcher: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} launcher problem(s). A launcher that cannot "
              f"deny leaves the hook installed and enforcing nothing.",
              file=sys.stderr)
        return 1
    half = "batch" if WINDOWS else "POSIX"
    print(f"launcher: executable in the index, denies with nothing installed "
          f"and on an unusable SPILL_GUARD_BIN, and resolves by all three "
          f"routes -- driven through the {half} half on {sys.platform}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
