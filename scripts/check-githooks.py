#!/usr/bin/env python3
"""Check that every tracked git hook would actually run.

git skips a hook file that is not executable, silently and at exit 0, so a
hook that lost its mode bit is indistinguishable from a repo with no hook --
and the whole point of `make hooks` is that the store gates run before a commit
rather than at review. That is this project's worst failure shape wearing
different clothes: a check that reports a safety it is not providing.

The mode that matters is the one in the git index, not the one on disk. A
`chmod +x` in a working tree is not what a fresh clone gets; `git update-index
--chmod=+x` is.

Two other things a hook needs to run at all: a shebang, since git executes the
file rather than sourcing it, and a hook name git recognises -- a file called
`pre-comit` sits there executable and is never invoked.

Exits 1 and lists every hook that would not run, so one run reports all of them.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / ".githooks"

# git's own hook names, from `githooks(5)`. A file here under any other name is
# a typo or a helper, and either way git will not call it.
KNOWN = frozenset("""
applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit
prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge
pre-push pre-receive update proc-receive post-receive post-update
reference-transaction push-to-checkout pre-auto-gc post-rewrite sendemail-validate
fsmonitor-watchman p4-changelist p4-prepare-changelist p4-post-changelist
p4-pre-submit post-index-change
""".split())

EXECUTABLE = "100755"
SHEBANG = re.compile(rb"^#!\S")


def tracked_modes():
    """{repo-relative path: index mode} for everything under .githooks."""
    out = subprocess.run(("git", "ls-files", "-s", "-z", "--", ".githooks"),
                         cwd=ROOT, check=True, capture_output=True,
                         text=True).stdout
    modes = {}
    for entry in out.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        modes[path] = meta.split()[0]
    return modes


def main():
    modes = tracked_modes()
    if not modes:
        print("githooks: .githooks holds no tracked file, so every assertion "
              "below passed over nothing. `make hooks` points core.hooksPath "
              "at a directory with no hook in it.", file=sys.stderr)
        return 1

    findings = []
    for path in sorted(modes):
        name = Path(path).name
        if modes[path] != EXECUTABLE:
            findings.append(f"{path} is mode {modes[path]} in the index, so a "
                            f"fresh clone gets a hook git will not run -- "
                            f"`git update-index --chmod=+x {path}`")
        if name not in KNOWN:
            findings.append(f"{path} is not a hook name git recognises, so it "
                            f"sits there and is never invoked")
        head = (ROOT / path).read_bytes()[:64]
        if not SHEBANG.match(head):
            findings.append(f"{path} opens with no shebang, so git runs it "
                            f"under whatever /bin/sh happens to be")

    for entry in findings:
        print(f"githooks: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} tracked hook problem(s). A hook that does not "
              f"run reports a safety it is not providing.", file=sys.stderr)
        return 1
    print(f"githooks: {len(modes)} tracked hook(s), all executable and named "
          f"for a hook git calls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
