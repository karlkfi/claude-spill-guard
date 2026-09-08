#!/usr/bin/env python3
"""Re-take the harness census in internal/hook/testdata/prompt-oracle.json.

The fixture is Claude Code's own answer to the `@`-token grammar: for each
probe prompt, the set of files the harness resolved and spliced into the
model's context. A Go test compares the resolver against it on every run, so
the resolver cannot drift from the fixture. Nothing re-takes the fixture, so it
drifts silently from the harness -- a grammar this project does not own, pinned
by a recording nobody re-derives.

This replays each case against a real `claude` binary and compares what the
harness spliced with what the fixture says it spliced. The only thing it can
report is the fixture having gone stale, which is the whole reason to run it.

**It needs no credential.** `claude -p` resolves `@` tokens and writes each
resolved file to the session transcript as an attachment whose
`attachment.type` is `file` before it makes an API call, so under a clean
`HOME` it reports `Not logged in`, bills nothing, and has already produced the
observation. That is why this can run on a fork's pull request, and why it
covers the prompt surface only: a `Read` path or a `Bash` operand reaches a
hook only once the model has chosen a tool call, which is an API call.

**Observing and comparing are separate**, which is what lets a mutation control
cost nothing. `--record` drives the harness once and writes what it saw;
`--compare` reads that recording back and holds it against the fixture. The
control then mutates the fixture and compares against the same recording,
rather than paying another 90 seconds to re-drive a harness whose answer it
already has.

**Re-taking the census** is `--record` against the new binary, then
`--compare --allow-version-drift` to read what moved, then the new version in
`harness.version` and in the workflow's pin in one commit. Without that last
step a green run says nothing about which version it confirmed, which is why
`--compare` asserts the two agree by default.

**The floor is the reason this is trustworthy at all.** A replay that drove
nothing -- a binary that failed to install, a `HOME` the harness would not
write under -- agrees with all ten of the cases that expect an empty splice and
reports green. So a recording that observed fewer than the fixture's own
non-empty cases, or fewer than its files, is a failure rather than a pass. The
Go test carries the same floor for the same reason.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "internal" / "hook" / "testdata" / "prompt-oracle.json"

# The harness writes its transcript under $HOME, so a run gets a clean one and
# nothing reads the credential on the machine driving it.
TRANSCRIPT_GLOB = ".claude/projects/*/*.jsonl"


def load(path):
    """The fixture envelope. Every way it can come back thin is an exit."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as err:
        sys.exit(f"prompt-oracle: the census at {path} is not readable as "
                 f"JSON, so nothing here compares against it: {err}")
    for key in ("harness", "tree", "cases"):
        if not data.get(key):
            sys.exit(f"prompt-oracle: the census has no {key!r}, so nothing "
                     f"below could have failed")
    if not data["harness"].get("version"):
        sys.exit("prompt-oracle: the census names no harness version, so a "
                 "disagreement could not say which two versions it is between")
    return data


def build_tree(base, tree):
    """Rebuild the directory the probes ran in, and the home the one
    home-relative case resolves against. Both sides read the same spec: a tree
    written twice drifts, and a drifted tree reads as a drifted grammar."""
    root = base / "probe"
    home = base / "home"
    root.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    for path, body in tree.items():
        target = home / path[2:] if path.startswith("~/") else root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return root, home


def spelling(path, root, home):
    """Map an absolute path the harness reported back into the spelling the
    fixture records, so a disagreement names `nested/inner.txt` rather than a
    temp path."""
    path = Path(path)
    for base, prefix in ((root, ""), (home, "~/")):
        try:
            return prefix + Path(path).resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            continue
    return str(path)


def spliced(home, root, probe_home):
    """The files one run spliced, read out of its transcript.

    The subject is `attachment.type == "file"`. A raw count of attachments
    looks like it would do and does not: it carries skill listings, token
    reminders and deferred-tool deltas too, so it answers a different question
    from whether a file crossed."""
    found = []
    for transcript in sorted(Path(home).glob(TRANSCRIPT_GLOB)):
        for line in transcript.read_text(errors="replace").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            attachment = entry.get("attachment")
            if isinstance(attachment, dict) and attachment.get("type") == "file":
                name = attachment.get("filename")
                if name:
                    found.append(spelling(name, root, probe_home))
    return sorted(set(found))


def version_of(binary):
    """`claude --version` reduced to the version itself, or an exit."""
    result = subprocess.run((binary, "--version"), capture_output=True,
                            text=True, check=False)
    if result.returncode != 0:
        sys.exit(f"prompt-oracle: `{binary} --version` exited "
                 f"{result.returncode}, so the binary under test cannot be "
                 f"named:\n{result.stderr.strip()}")
    reported = result.stdout.split()
    if not reported:
        sys.exit(f"prompt-oracle: `{binary} --version` wrote nothing, so a "
                 f"disagreement could not name the harness it is against")
    return reported[0]


def record(fixture, binary, out):
    """Drive every case once and write what the harness spliced."""
    binary = shutil.which(binary) or binary
    if not os.access(binary, os.X_OK):
        sys.exit(f"prompt-oracle: no executable claude at {binary}")
    observed = {"harness": {"version": version_of(binary)}, "cases": {}}
    with tempfile.TemporaryDirectory() as base:
        base = Path(base)
        root, probe_home = build_tree(base, fixture["tree"])
        for case in fixture["cases"]:
            run_home = base / "runs" / case["name"]
            run_home.mkdir(parents=True)
            # The harness resolves `~` through $HOME, and the probe tree's home
            # is where the recorded `~/` case has to land -- so the run's own
            # HOME is that directory, with the transcript written beside it.
            shutil.copytree(probe_home, run_home, dirs_exist_ok=True)
            prompt = case["prompt"].replace("{{root}}", str(root))
            subprocess.run((binary, "-p", prompt), cwd=root, check=False,
                           capture_output=True, text=True,
                           env={"PATH": os.environ.get("PATH", ""),
                                "HOME": str(run_home), "TERM": "dumb"})
            observed["cases"][case["name"]] = spliced(run_home, root, run_home)
    Path(out).write_text(json.dumps(observed, indent=2) + "\n")
    print(f"prompt-oracle: drove {len(observed['cases'])} cases against "
          f"{observed['harness']['version']} into {out}")


def compare(fixture, recording, expect_version):
    """Hold a recording against the census. Returns the failures."""
    try:
        observed = json.loads(Path(recording).read_text())
    except (OSError, json.JSONDecodeError) as err:
        sys.exit(f"prompt-oracle: the recording at {recording} is not "
                 f"readable: {err}")

    recorded = fixture["harness"]["version"]
    ran = observed.get("harness", {}).get("version", "unknown")
    failures = []
    if expect_version and ran != recorded:
        failures.append(
            f"the census was confirmed against {recorded} and this ran "
            f"{ran}. Bump `harness.version` in the census in the same commit "
            f"that moves the pin, or a green run says nothing about which "
            f"version it confirmed.")

    # The floor, on what was observed rather than on what the fixture holds. A
    # replay that drove nothing agrees with every case expecting an empty
    # splice, and there are ten of those.
    want_cases = sum(1 for c in fixture["cases"] if c["harness_files"])
    want_files = sum(len(set(c["harness_files"])) for c in fixture["cases"])
    got_cases = sum(1 for files in observed.get("cases", {}).values() if files)
    got_files = sum(len(set(files)) for files in observed.get("cases", {}).values())
    if got_cases < want_cases or got_files < want_files:
        failures.append(
            f"the replay saw {got_cases} cases splice something and "
            f"{got_files} files cross, where the census holds {want_cases} and "
            f"{want_files}. A run that drove nothing agrees with every case "
            f"that expects an empty splice, so a shortfall is a failure rather "
            f"than a pass.")

    for case in fixture["cases"]:
        want = sorted(set(case["harness_files"]))
        got = observed.get("cases", {}).get(case["name"])
        if got is None:
            failures.append(f"{case['name']}: the replay recorded nothing for "
                            f"this case, so it went undriven")
            continue
        got = sorted(set(got))
        if got != want:
            failures.append(
                f"{case['name']}: the census records {want} and {ran} "
                f"spliced {got}. The `@` grammar moved under the census; "
                f"re-take it and re-read what internal/hook resolves.")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default=str(FIXTURE))
    parser.add_argument("--claude", default="claude",
                        help="the binary to drive; pin it, never @latest")
    parser.add_argument("--record", metavar="PATH",
                        help="drive the harness and write what it spliced")
    parser.add_argument("--compare", metavar="PATH",
                        help="hold a recording against the census")
    parser.add_argument("--allow-version-drift", action="store_true",
                        help="do not require the driven version to be the one "
                             "the census names")
    args = parser.parse_args()

    fixture = load(args.fixture)
    if not args.record and not args.compare:
        parser.error("one of --record or --compare is required")
    if args.record:
        record(fixture, args.claude, args.record)
    if args.compare:
        failures = compare(fixture, args.compare, not args.allow_version_drift)
        if failures:
            print("prompt-oracle: the census no longer matches the harness")
            for line in failures:
                print(f"  - {line}")
            sys.exit(1)
        print(f"prompt-oracle: {len(fixture['cases'])} cases agree with "
              f"{fixture['harness']['version']}")


if __name__ == "__main__":
    main()
