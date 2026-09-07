#!/usr/bin/env python3
"""Every tracked file through the hook, and the class allowed to match.

A session working in this repository reads this repository, so the scanner runs
over its own tree, and a good many tracked files trip it. Most are supposed to:
a corpus of fabricated credentials is what proves the rules can fire at all. So
the property worth gating is not *no tracked file matches* -- that one fails on
the corpus by design, and a gate whose first run had to be suppressed for the
whole planted corpus would teach everyone to suppress it. It is that **nothing
enters the class without somebody deciding it should**.

No counts are written down here, on purpose. Every figure this gate could quote
moves: the corpus grows by specification, so a new rule brings a planted
fixture, and the tracked total drops each time a merged pull request deletes a
backlog row. Both moved while this file was being written, in opposite
directions. The gate prints the live numbers on every run, which is where to
read them -- pinning them in a comment nothing re-reads is the shape Q98 is
about.

Two ways a file is allowed to match, and they are different kinds of claim:

  * a **region** -- a directory that holds credential-shaped values by
    specification, where a new file is the ordinary way of working. Adding a
    planted fixture is how a new rule is proved to fire, so enumerating those
    would redden the pull request that does the right thing.
  * an **allowlist entry** -- one path, with the decision behind it written
    down. Everywhere else, a file that starts matching is either a secret or a
    literal somebody should have put in `testdata/corpus/vectors/`, and both
    are worth stopping the pull request for.

The allowlist is asserted in both directions. An entry that no longer matches
is a failure and not a quiet success: a list that keeps entries after their
reason is gone stops describing the tree, and the next reader has no way to
tell a live exemption from a dead one. `internal/hook/manifest_test.go` makes
the same argument about the event matcher, for the same reason.

**The zero this reports is the easy kind to fake.** A binary whose ruleset did
not compile matches nothing, and every file then reads as clean -- which is the
same output as a tree with nothing wrong in it. So the planted corpus is the
positive control: every file under it has to be refused before any zero below
means anything. That is not a second `precision` gate. `precision` asserts one
finding per planted file through `internal/scan`; this drives the built binary
through `hook.Run`, which is the entry point a session actually reaches, and it
is here to prove this gate can come back non-empty.

The other way to a vacuous pass is the harness. A payload shape this binary
does not decode, a build that did not happen, a `git ls-files` that came back
empty -- each is an exit rather than a shorter list.

**A block is a `deny` object on stdout at exit 0**, not a non-zero status. A
census keyed on the exit code reports every file allowed, which is a clean
sweep of the whole tree and completely wrong.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY_SRC = "./cmd/spill-guard"

# Directories whose contents are credential-shaped because that is what they
# are for. `.github/secret_scanning.yml` already tells GitHub push protection
# the same thing about `testdata/corpus/**`, with the measurement behind it;
# this is the narrower pair, because `clean/` must stay quiet and a file there
# that starts matching is a precision regression this gate should catch.
REGIONS = {
    "testdata/corpus/planted/":
        "one fabricated credential per shipped rule -- matching is what the "
        "fixture is for, and `precision` fails if one stops",
    "testdata/corpus/vectors/":
        "the values the unit tests assert on, kept in one place so a string "
        "that could pass for an issued credential stays out of source",
}

# Every other tracked file that matches, and why it is allowed to. A reason
# here is a decision somebody took, not a note that the file was already like
# this when the list was written.
ALLOWED = {
    "README.md":
        "the published canary the install check tells a reader to paste. It "
        "has to match: the whole check is that the prompt gets blocked",
    "testdata/corpus/README.md":
        "prose about the canary values, which quotes them to explain what "
        "makes each one inert",
    "internal/selftest/selftest.go":
        "the canary is compiled in rather than read from a file, because a "
        "canary a broken install fails to find is one whose absence looks "
        "like a pass. Shipped source, so it cannot read testdata either way",
    # The next three describe the literal rather than deciding it -- none of
    # them says why the value could not come from testvec. Q152 is the row that
    # answers that per file, and whatever moves takes its line out of here.
    "cmd/spill-guard/main_test.go":
        "the literal sits inside a JSON payload driven through the binary end "
        "to end. Q152 asks whether it could be built with the vector instead",
    "internal/hook/hook_test.go":
        "the value the block assertions are written against. Q152 asks whether "
        "the const could be a testvec lookup",
    "internal/scan/decode_test.go":
        "the key a UTF-16 fixture is built around, in the test that builds it. "
        "Q152 asks whether the bytes here are the assertion or just the input",
    "internal/validate/jwt_test.go":
        "a table of JWT shapes where each case is a specific malformation, so "
        "the bytes are the assertion",
    "internal/rules/capture_test.go":
        "the one entry here that is not a decision. Q121 moves this literal "
        "into testdata/corpus/vectors/, and the stale-entry check below is "
        "what makes that pull request delete this line rather than leave it",
}


def run(*argv, **kw):
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                          check=False, **kw)


def tracked():
    """Every tracked path. Empty is an exit: a sweep with nothing to sweep
    reports the same clean result as a sweep that found nothing wrong."""
    done = run("git", "ls-files")
    if done.returncode != 0:
        sys.exit(f"self-scan: `git ls-files` failed: {done.stderr.strip()}")
    found = [line for line in done.stdout.splitlines() if line]
    if not found:
        sys.exit("self-scan: `git ls-files` named no files, so nothing below "
                 "could have matched")
    return found


def build(into):
    done = run("go", "build", "-o", str(into), BINARY_SRC)
    if done.returncode != 0:
        sys.exit(f"self-scan: building {BINARY_SRC} failed:\n{done.stderr}")
    return into


def verdict(binary, path):
    """("deny"|"clear", reason). Anything else exits: a payload this binary
    cannot answer is a broken harness, and it would otherwise be counted as a
    file that did not match."""
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(ROOT / path)},
    })
    done = run(str(binary), "hook", input=payload)
    if done.returncode not in (0, 1):
        sys.exit(f"self-scan: the hook exited {done.returncode} on {path}, "
                 f"which is the code for a payload it could not decode:\n"
                 f"{done.stderr.strip()}")
    out = done.stdout.strip()
    if not out:
        return "clear", ""
    try:
        decoded = json.loads(out)
    except json.JSONDecodeError:
        sys.exit(f"self-scan: the hook wrote something that is not JSON on "
                 f"{path}, so no verdict here can be read:\n{out[:400]}")
    decision = (decoded.get("hookSpecificOutput") or {}).get("permissionDecision")
    if decision == "deny":
        return "deny", decoded["hookSpecificOutput"]["permissionDecisionReason"]
    if decision == "allow":
        return "clear", ""
    if decoded.get("decision") == "block":
        return "deny", decoded.get("reason", "")
    # `ask` is the override downgrade and reaches no Read call, and a shape
    # this does not name is one whose verdict nobody here has decided how to
    # count. Both are exits rather than a default.
    sys.exit(f"self-scan: the hook wrote a verdict on {path} that this does "
             f"not know how to read:\n{out[:400]}")


def region_of(path):
    for prefix in REGIONS:
        if path.startswith(prefix):
            return prefix
    return None


def reason_line(reason):
    """The rule and offset out of a block reason, which is one long sentence."""
    marker = "in what this call would have sent: "
    at = reason.find(marker)
    return reason[at + len(marker):].split(". Nothing was sent")[0] if at >= 0 else reason


def main():
    files = tracked()
    matched = {}
    with tempfile.TemporaryDirectory() as tmp:
        binary = build(Path(tmp) / "spill-guard")
        for path in files:
            kind, reason = verdict(binary, path)
            if kind == "deny":
                matched[path] = reason

    failures = []

    # The control. Every planted fixture has to be refused before the absences
    # below are worth reading.
    planted = [p for p in files if p.startswith("testdata/corpus/planted/")]
    if not planted:
        failures.append("no planted fixtures are tracked, so nothing here "
                        "proves the ruleset fires at all")
    for path in planted:
        if path not in matched:
            failures.append(f"{path} was not refused. Either the shipped "
                            f"ruleset has stopped firing -- in which case "
                            f"every clean result below means nothing -- or a "
                            f"fixture was added for a rule that ships disabled")

    # A file entering the class. This is the property the gate is for.
    for path in sorted(matched):
        if region_of(path) or path in ALLOWED:
            continue
        failures.append(
            f"{path} matches the shipped ruleset and nothing says it should. "
            f"If it is a secret, remove it. If it is a test literal, move it "
            f"to testdata/corpus/vectors/ and read it through internal/testvec. "
            f"If it has to stay, add it to ALLOWED in this file with the "
            f"reason. The hook refused it saying: {reason_line(matched[path])}")

    # The other direction. An entry whose reason has expired stops describing
    # the tree, and nothing else would say so.
    for path in sorted(ALLOWED):
        if path not in files:
            failures.append(f"{path} is on the allowlist and is not tracked, "
                            f"so the entry describes a file that is gone")
        elif path not in matched:
            failures.append(f"{path} is on the allowlist and no longer "
                            f"matches, so the exemption is dead -- delete the "
                            f"entry rather than leaving it to read as live")

    for failure in failures:
        print(f"self-scan: {failure}", file=sys.stderr)
    if failures:
        print(f"\n{len(failures)} problem(s). This gate is what stops a "
              f"credential-shaped literal reaching a file a session then "
              f"cannot read.", file=sys.stderr)
        return 1

    print(f"self-scan: {len(files)} tracked files through the hook, "
          f"{len(matched)} refused, all of them accounted for")
    for prefix, why in REGIONS.items():
        count = sum(1 for p in matched if p.startswith(prefix))
        print(f"self-scan:   {count:>2} in {prefix} -- {why}")
    print(f"self-scan:   {len(ALLOWED)} named, each with a reason:")
    for path, why in ALLOWED.items():
        print(f"self-scan:      {path} -- {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
