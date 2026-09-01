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
    """(whether the child environment can find a spill-guard, what it found).

    This is the precondition on every deny case below. `PATH=/usr/bin:/bin` was
    once used elsewhere in this repo to hide a tool and hid nothing, because
    the CI setup had linked it into /usr/bin -- so ask about the tool rather
    than about a directory.

    It returns what it found as well as whether, because a precondition that
    fires and cannot say which entry produced the hit costs the same CI round
    trip evidence() exists to prevent -- on the same platform, for the same
    reason.
    """
    probe = "where spill-guard" if WINDOWS else "command -v spill-guard"
    argv = ("cmd", "/c", probe) if WINDOWS else ("/bin/sh", "-c", probe)
    p = subprocess.run(argv, capture_output=True, text=True, check=False,
                       env=env)
    found = p.stdout.strip()
    return (p.returncode == 0 and found != ""), found


def exits_zero(findings, what, rc, out, err):
    """A deny has to arrive on exit 0, and the code is half the spelling.

    A deny object on stdout blocks whatever the process exits with, so a
    launcher denying on exit 2 still stops the call -- and the model is told
    the hook errored and never sees the reason, because exit 2 discards stdout.
    The other codes are worse in a different way: 1, 9 and 127 are what a
    launcher that FAILED produces, which is the state this deny exists to be
    distinguishable from. So 0 is the only code that carries no second meaning,
    and pinning the object without pinning the code pins half the spelling.
    """
    if rc != 0:
        findings.append(f"{what} arrived on exit {rc} rather than 0. The object "
                        f"blocks either way; on 2 stdout is discarded and the "
                        f"reason never reaches the model, and 1, 9 and 127 are "
                        f"the codes a launcher that failed produces -- "
                        f"{evidence(rc, out, err)}")


def deny_reason(out):
    """The block reason in `out`, or None if it is not a block Claude Code reads.

    Parsed rather than grepped: the property is that Claude Code can read this
    as a decision object, and a string that merely contains the word deny is
    the failure mode -- the launcher's own stdout is the only thing standing
    between a missing binary and a tool call nobody scanned.

    The shape is `{"decision":"block","reason":...}` and the PreToolUse
    `permissionDecision` object is refused by name, which is the half of this
    function that is a gate rather than a parser.

    The launcher never learns which event it was invoked for. hooks.json points
    it at `PreToolUse` and at `UserPromptSubmit`, and the payload naming the
    event goes past on stdin. internal/hook/verdict.go measures both encodings
    against 2.1.238: the PreToolUse deny object is accepted and **ignored** on
    UserPromptSubmit, so a launcher writing it denies `Read` and `Bash` loudly
    while every prompt goes to the model with whatever is in it. That shipped
    -- the launcher carried it from the day it was written until the day
    hooks.json first pointed at a prompt -- and it was invisible here because
    this function asserted the broken shape.
    """
    try:
        decoded = json.loads(out)
    except (ValueError, TypeError):
        return None
    if isinstance(decoded.get("hookSpecificOutput"), dict):
        # Named rather than falling through to None: this is the regression,
        # and "did not write anything Claude Code reads as a deny" would send
        # a reader looking for a launcher that wrote nothing.
        return _PRE_TOOL_USE_SHAPE
    if decoded.get("decision") != "block":
        return None
    reason = decoded.get("reason")
    return reason if isinstance(reason, str) and reason else None


# What deny_reason hands back for the one wrong shape it can name. A sentinel
# rather than None so a caller can say which of the two failures it got.
_PRE_TOOL_USE_SHAPE = object()


def blocks_both_events(findings, what, out):
    """The block has to be the event-agnostic shape, and say so when it is not."""
    reason = deny_reason(out)
    if reason is _PRE_TOOL_USE_SHAPE:
        findings.append(
            f"{what} is the PreToolUse `hookSpecificOutput` object. Claude Code "
            f"accepts and IGNORES that on UserPromptSubmit -- measured in "
            f"internal/hook/verdict.go -- and this launcher cannot see which "
            f"event it was invoked for, so every prompt would reach the model "
            f"unscanned while Read and Bash denied loudly. Write "
            f'{{"decision":"block","reason":...}}, which blocks both.')
        return None
    return reason


def both_halves_block_the_same(findings):
    """Every block literal in the file, in both halves, is the flat shape.

    The dynamic arms above drive one half: the POSIX one everywhere but
    Windows, the batch one only on a Windows runner. So each half's payload is
    unasserted on the other platform, and the two can drift apart silently --
    a Windows user then gets the fail-open this file's `deny_reason` exists to
    prevent, with nothing red anywhere.

    Found by a reviewer transplanting the broken object into the batch half on
    darwin: the mutation landed, `git diff --quiet` returned 1, and the gate
    stayed green at exit 0. The precondition was satisfied and the mutation did
    not bite, which is the shape CLAUDE.md warns about.

    This reads the literals rather than driving them, so it holds for both
    halves from either platform, and it is a complement to the drives rather
    than a replacement: a literal that parses correctly and never reaches
    stdout is still a launcher that does not deny.
    """
    raw = LAUNCHER.read_bytes()
    lines = raw.split(b"\n")
    cut = next((i for i, line in enumerate(lines)
                if line.rstrip(b"\r") == TERMINATOR), None)
    if cut is None:
        # line_endings has already said so, and with no split there is no way
        # to attribute a literal to a half.
        return
    halves = (("batch", lines[:cut + 1]), ("POSIX", lines[cut + 1:]))

    seen = 0
    for name, body in halves:
        for line in body:
            literal = block_literal(line)
            if literal is None:
                continue
            seen += 1
            try:
                decoded = json.loads(literal)
            except ValueError as err:
                findings.append(f"a block literal in the {name} half is not "
                                f"JSON ({err}), so Claude Code reads nothing "
                                f"and the call runs unscanned: {literal!r}")
                continue
            if sorted(decoded) != ["decision", "reason"]:
                findings.append(
                    f"a block literal in the {name} half carries "
                    f"{sorted(decoded)!r} rather than the flat "
                    f"{{'decision', 'reason'}}. The PreToolUse object is "
                    f"accepted and IGNORED on UserPromptSubmit and this file "
                    f"cannot see which event it was invoked for, so that half "
                    f"would let every prompt through: {literal!r}")
            elif decoded.get("decision") != "block":
                findings.append(f"a block literal in the {name} half decides "
                                f"{decoded.get('decision')!r}, not 'block': "
                                f"{literal!r}")

    # Two per half: DENY_EXPLICIT and DENY_MISSING. A split that found none in
    # one half is a rename this check would otherwise pass silently, which is
    # the same vacuous-instrument failure it exists to catch.
    if seen != 4:
        findings.append(f"found {seen} block literal(s) across the two halves, "
                        f"want 4 -- either a deny path has gone or this check "
                        f"has stopped recognising one, and both read as green")


def block_literal(line):
    """The JSON object on a launcher line that writes a block, or None.

    Two spellings, one per half: the batch half echoes it and the POSIX half
    assigns it to a shell variable in single quotes.
    """
    text = line.rstrip(b"\r").decode("utf-8", "replace").strip()
    if text.startswith("echo {"):
        return text[len("echo "):]
    if text.startswith("DENY_") and "='{" in text:
        return text.split("=", 1)[1].strip().strip("'")
    return None


# The line the batch half ends on. cmd.exe never reads past it and sh treats
# everything above it as heredoc content, which is what lets one file carry two
# sets of line endings without either half noticing the other's.
TERMINATOR = b"CMDBLOCK"


def line_endings(findings):
    """The batch half must be CRLF and the POSIX tail must be LF.

    Not a style rule. Measured 2026-08-25 on GitHub runners, driving the
    launcher end to end in four arms:

      * LF throughout -- cmd.exe loses its file position across a parenthesized
        block, the `goto` after it dies with `The system cannot find the batch
        label specified`, and the launcher exits 1 with empty stdout. That is
        not a deny, so the tool call runs unscanned. The tree carried exactly
        this and a whole platform's deny path was inert.
      * CRLF throughout -- the POSIX half dies on `set: Illegal option -`
        before it resolves anything.
      * CRLF to the terminator and LF after -- passes every case on every
        platform, with and without the block.

    So both halves are checked, and so is the `-text` attribute that stops git
    normalising the split away. A rule this easy to undo with one editor's
    default cannot live in a comment.

    The terminator is checked separately, because its CR answers to sh rather
    than to cmd.exe and the consequence of losing it is a different defect.
    Line 1 opens the heredoc as `: << \'CMDBLOCK\'` and keeps its own CR, so
    sh\'s delimiter is `CMDBLOCK\r` and the terminator has to carry a CR to
    match it. Drop that one byte and the delimiter never matches, sh swallows
    the whole POSIX half as heredoc content, and the launcher exits **0** with
    nothing on either stream -- silent, which is worse than the cmd.exe defect
    above, where it at least exited 1.

    cmd.exe is unaffected by that byte, and the correction is worth stating
    because the first version of this comment claimed otherwise. Every batch
    path leaves at an `exit /b` well above the terminator, so cmd never reads
    that line; the four-arm probe agrees from the other side, since Windows
    passed the arm whose terminator carried no CR. So this one silences macOS
    and Linux and leaves Windows working -- two of three shipped targets, not
    three. Measured 2026-08-25 on darwin and read off the control flow for the
    rest, which is the split this repo asks of every other claim.
    """
    # Split on LF and find the terminator by its text rather than by its
    # ending. The whole-file regression flattens everything to LF, which takes
    # the terminator's CRLF with it -- so a reader that located the halves by
    # matching CRLF would lose its bearings on exactly the defect that shipped,
    # and report that it cannot tell the halves apart instead of naming which
    # one is wrong.
    lines = LAUNCHER.read_bytes().split(b"\n")
    cut = next((i for i, line in enumerate(lines)
                if line.rstrip(b"\r") == TERMINATOR), None)
    if cut is None:
        findings.append(f"{TRACKED} has no {TERMINATOR.decode()} line, so the "
                        f"batch half and the POSIX half cannot be told apart -- "
                        f"and one of them is running with the other's endings")
        return

    batch, terminator, tail = lines[:cut], lines[cut], lines[cut + 1:]
    # Each entry was terminated by the LF we split on, so it was CRLF exactly
    # when it still ends with CR. The final entry is whatever followed the last
    # newline, and an empty one falls out of both counts on its own.
    #
    # Three findings rather than two, because the terminator's CR answers to a
    # different reader than the lines above it and losing it is a different
    # defect. Folding it into the batch count would name cmd.exe for something
    # only sh sees.
    stray_lf = sum(1 for line in batch if not line.endswith(b"\r"))
    stray_crlf = sum(1 for line in tail if line.endswith(b"\r"))
    if stray_lf:
        findings.append(f"{TRACKED} carries {stray_lf} bare LF in the batch "
                        f"half, where cmd.exe needs CRLF -- a `goto` past a "
                        f"parenthesized block then fails to find its label and "
                        f"the launcher exits without denying")
    if not terminator.endswith(b"\r"):
        findings.append(f"{TRACKED}'s {TERMINATOR.decode()} line carries no CR, "
                        f"so it no longer matches the heredoc delimiter on line "
                        f"1 -- sh swallows the whole POSIX half and the launcher "
                        f"exits 0 saying nothing on macOS and Linux. cmd.exe "
                        f"never reads this line, so Windows is unaffected")
    if stray_crlf:
        findings.append(f"{TRACKED} carries {stray_crlf} CRLF after the "
                        f"terminator, where /bin/sh needs LF -- the POSIX half "
                        f"dies on its own prologue before resolving anything")

    attr = subprocess.run(("git", "check-attr", "text", "--", TRACKED),
                          cwd=ROOT, check=True, capture_output=True,
                          text=True).stdout.strip()
    if not attr.endswith("unset"):
        findings.append(f"git reports `{attr}` for {TRACKED}, so git is free to "
                        f"normalise its line endings -- and a checkout that "
                        f"normalises them is a checkout where one half of this "
                        f"file does not run")


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
    ok, found = resolvable(env)
    if ok:
        findings.append(f"the environment for the deny cases can still resolve "
                        f"a spill-guard at {found!r}, so a deny below would "
                        f"prove nothing and a run would prove nothing either")
        return
    # A prompt payload, not a tool one. The launcher passes stdin through
    # rather than reading it, so this cannot change what it writes -- which is
    # the property being asserted. The event that reaches a real hook is the
    # one this file's deny has to block, and the launcher has no way to know
    # which it was, so the arm below pins that the two agree byte for byte.
    prompt_payload = ('{"hook_event_name":"UserPromptSubmit",'
                      '"prompt":"whatever this session typed"}')
    rc, out, err = run(env, ("hook",), stdin=prompt_payload)
    reason = blocks_both_events(findings, "the deny for a missing binary", out)
    if reason is None:
        if deny_reason(out) is None:
            findings.append(f"with no binary anywhere the launcher did not write "
                            f"anything Claude Code reads as a block, so the tool "
                            f"call would run unscanned -- {evidence(rc, out, err)}")
        return
    exits_zero(findings, "the deny for a missing binary", rc, out, err)
    if "install" not in reason.lower():
        findings.append(f"the deny for a missing binary names no way to "
                        f"install one: {reason!r}")

    # Byte-identical on a tool payload. The launcher is event-blind by
    # construction and this is what says so out loud: if a later change ever
    # made the output depend on the event, one shape would be right and the
    # other would be the fail-open above.
    tool_payload = ('{"hook_event_name":"PreToolUse","tool_name":"Bash",'
                    '"tool_input":{"command":"echo hi"}}')
    _, tool_out, _ = run(env, ("hook",), stdin=tool_payload)
    if tool_out != out:
        findings.append(f"the launcher's block differs between a "
                        f"UserPromptSubmit payload and a PreToolUse one, so it "
                        f"is reading stdin rather than passing it through -- "
                        f"prompt {out!r} against tool {tool_out!r}")


def denies_on_an_unusable_explicit_path(findings, tmp, stub):
    """SPILL_GUARD_BIN naming nothing must deny rather than fall back.

    The control is the second half: a resolvable binary sits on PATH, so a
    launcher that quietly fell back would run and this would go green.
    """
    env = base_env(tmp)
    env["SPILL_GUARD_BIN"] = str(tmp / "not-a-file")
    env["PATH"] = os.pathsep.join([str(stub.parent), env["PATH"]])
    ok, _ = resolvable(env)
    if not ok:
        findings.append(f"the fallback control cannot resolve a spill-guard on "
                        f"PATH -- `{'where' if WINDOWS else 'command -v'} "
                        f"spill-guard` came back empty with {stub} on it -- so "
                        f"this case cannot tell a deny from a launcher that "
                        f"fell back and found nothing")
        return
    rc, out, err = run(env, ("hook",))
    if blocks_both_events(findings, "the deny for an unusable SPILL_GUARD_BIN",
                          out) is None:
        if deny_reason(out) is None:
            findings.append(f"SPILL_GUARD_BIN naming a path that is not "
                            f"executable did not deny -- an explicit path that "
                            f"does not work is a configuration error, not a "
                            f"reason to run some other binary -- "
                            f"{evidence(rc, out, err)}")
        return
    exits_zero(findings, "the deny for an unusable SPILL_GUARD_BIN", rc, out, err)


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
    line_endings(findings)
    both_halves_block_the_same(findings)

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
    print(f"launcher: executable in the index, split line endings intact, "
          f"4 block literals flat in both halves, denies with nothing "
          f"installed and on an unusable SPILL_GUARD_BIN, and resolves by all "
          f"three routes -- driven through the {half} half on {sys.platform}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
