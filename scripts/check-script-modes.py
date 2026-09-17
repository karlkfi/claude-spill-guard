#!/usr/bin/env python3
"""A file advertises exactly the way it can be run, and now something checks.

`scripts/README.md` has stated the rule since Q56: a shebang and mode `755`
travel together, because a shebang on a file at `644` names an interpreter the
mode refuses, and the bit on a file nothing executes invites a reading that does
not hold. The same page said no gate asserted it, on purpose, and the argument
was that nothing here is invoked by path -- the Makefile runs `$(PYTHON)
scripts/x.py` and the workflow runs `python3 scripts/x.py` -- so a mode that
disagrees breaks nothing.

That argument is about consequence and it still holds. What it did not have is
the rate. Of the 14 `scripts/*.py` entry points added since Q56 straightened the
set on 2026-08-26, 11 arrived at `755` and **3 arrived at `644`**, and not one
of the three was ever noticed afterwards -- the oldest stood fourteen days. None
of them drifted: each was born wrong and stayed. A rule nothing reads is applied
by whoever happens to have read the page, which is a 21% miss rate at the only
moment it can be got right.

So this is the smallest claim that closes it: for every tracked file, carrying a
shebang and being executable in the **index** are the same thing. The index
rather than the working tree, because the index mode is what ships and what
`git update-index --chmod=+x` sets; a working-tree bit that disagrees is a local
artifact of however the file was checked out.

Two exemptions, and both are asserted rather than skipped.

`testdata/corpus/` is a region. A fixture's shebang is part of the
credential-shaped text the corpus exists to hold, not a declaration about how to
run it -- `precision` and `self-scan` read these files as bytes and nothing
executes one. Adding another is the ordinary way of working there, which is why
it is a region and not a path, on the same reading `self-scan` already takes of
`planted/` and `vectors/`.

`hooks/run-spill-guard.cmd` is a named path. It is executable and carries no
shebang, because cmd.exe runs its batch half and `sh` reads the rest; the
`launcher` gate asserts that mode directly, since a launcher at `644` never
fires once. A named path has to still disagree, or the exemption has outlived
its reason and this fails on it.

`scripts/vendor/` is deliberately **not** exempt. Its two files agree today, and
`scripts/README.md` says a vendored copy keeps whatever mode upstream shipped --
so a future one could disagree. That is a decision for whoever takes the update,
not something to skip silently: `make vendor` pins content and a mode is not
content, so `git update-index --chmod` is available without breaking a digest.

Exits 1 and lists every finding, so one run reports all of them.
"""

import subprocess
import sys

EXECUTABLE = "100755"
SYMLINK = "120000"

# Regions where a shebang is text rather than a declaration. A new file here is
# ordinary, so this is a prefix and not a list of paths.
EXEMPT_REGIONS = {
    "testdata/corpus/":
        "corpus fixtures: a shebang is part of the credential-shaped text, and "
        "nothing executes one",
}

# Single files whose disagreement is deliberate. Asserted both ways below.
EXEMPT_PATHS = {
    "hooks/run-spill-guard.cmd":
        "executable with no shebang: cmd.exe runs the batch half and `sh` reads "
        "the rest, and the `launcher` gate asserts this mode because a launcher "
        "at 644 never fires once",
}


def tracked():
    """Every tracked path with its index mode and whether it opens with `#!`."""
    out = subprocess.run(
        ["git", "ls-files", "-s"],
        capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        mode, blob, _stage = meta.split()
        if mode == SYMLINK:
            # A symlink's own bytes are its target, and the mode is the link's.
            continue
        head = subprocess.run(
            ["git", "cat-file", "-p", blob],
            capture_output=True, check=True).stdout[:2]
        yield mode, path, head == b"#!"


def region_of(path):
    for prefix in EXEMPT_REGIONS:
        if path.startswith(prefix):
            return prefix
    return None


def main():
    findings = []
    checked = 0
    exempted_regions = 0
    seen_paths = {}

    for mode, path, shebang in tracked():
        executable = mode == EXECUTABLE
        if path in EXEMPT_PATHS:
            seen_paths[path] = (shebang, executable)
            continue
        region = region_of(path)
        if region is not None:
            exempted_regions += 1
            continue
        checked += 1
        if shebang and not executable:
            findings.append(
                f"{path} is {mode} and opens with a shebang, so the line names "
                f"an interpreter the mode refuses and `./{path}` exits 126. "
                f"Either `git update-index --chmod=+x {path}`, or drop the "
                f"shebang if nothing is meant to run it")
        elif executable and not shebang:
            findings.append(
                f"{path} is {mode} and carries no shebang, so the bit says it "
                f"can be run and nothing says with what. Either add a shebang, "
                f"or `git update-index --chmod=-x {path}` -- or add it to "
                f"EXEMPT_PATHS in scripts/check-script-modes.py with the reason, "
                f"the way the launcher is")

    # The other direction on the named exemptions: one that no longer disagrees
    # is an exemption outliving its reason, and an unchecked path either way.
    for path, reason in sorted(EXEMPT_PATHS.items()):
        if path not in seen_paths:
            findings.append(
                f"{path} is exempt in scripts/check-script-modes.py and is not "
                f"tracked any more, so the exemption covers nothing. Delete it, "
                f"along with the reason it carries: {reason}")
            continue
        shebang, executable = seen_paths[path]
        if shebang == executable:
            findings.append(
                f"{path} is exempt in scripts/check-script-modes.py and no "
                f"longer needs to be -- its shebang and its mode now agree. "
                f"Delete the exemption so the file is checked like every other, "
                f"rather than leaving a reason that has stopped being true: "
                f"{reason}")

    for prefix, reason in sorted(EXEMPT_REGIONS.items()):
        if not any(p.startswith(prefix) for _m, p, _s in tracked()):
            findings.append(
                f"{prefix} is an exempt region in "
                f"scripts/check-script-modes.py and holds no tracked file, so "
                f"nothing is being excused. Delete it: {reason}")

    if not checked:
        print("script-modes: nothing was checked at all, so nothing above "
              "could have failed", file=sys.stderr)
        return 1

    for entry in findings:
        print(f"script-modes: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} file(s) whose shebang and index mode "
              f"disagree, or exemption(s) that have outlived their reason.",
              file=sys.stderr)
        return 1

    print(f"script-modes: {checked} tracked file(s), every shebang matched by "
          f"an executable bit and the reverse; {len(EXEMPT_PATHS)} named "
          f"exemption(s) still needed, {exempted_regions} file(s) in "
          f"{len(EXEMPT_REGIONS)} exempt region(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
