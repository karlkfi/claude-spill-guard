#!/usr/bin/env python3
"""The Go toolchain gates: gofmt, go vet, go test.

`gofmt -l` is the reason this is a script rather than three lines of YAML. It
lists every unformatted file and exits **0**, so the obvious spelling of the
gate passes while printing exactly the output that says it should not. Measured
on Go 1.26.5: one unformatted file listed, exit 0.

Two modules, because `./...` stops at a module boundary. The root module is the
shipped binary; tools/ pins the tools the gates run and now carries one of its
own, and its tests are the only thing asserting that the workflow parser reads
what a regex could not. A suite nothing runs is not a suite. `gofmt -l .` walks
the whole tree and already covers both, so only vet and test are per module.

Every step runs even when an earlier one fails, so one run reports everything.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def gofmt():
    """Non-empty output means unformatted files, whatever the exit status."""
    result = subprocess.run(
        ("gofmt", "-l", "."), cwd=ROOT, capture_output=True, text=True, check=False
    )
    unformatted = result.stdout.strip()
    if unformatted:
        print(f"gofmt would rewrite:\n{unformatted}", file=sys.stderr)
        return False
    if result.returncode != 0:
        print(f"gofmt exited {result.returncode}:\n{result.stderr.strip()}", file=sys.stderr)
        return False
    print("gofmt: every file is formatted", flush=True)
    return True


# Every Go module in the tree, as (label, directory). Named rather than
# discovered: a walk that found no go.mod would report success over nothing.
MODULES = (("", ROOT), (" (tools)", ROOT / "tools"))


def run(where, *args):
    """Run a go command with its output inherited, so CI logs carry it."""
    sys.stdout.flush()
    return subprocess.run(("go",) + args, cwd=where, check=False).returncode == 0


def main():
    steps = [("gofmt", gofmt())]
    for label, where in MODULES:
        steps.append((f"go vet{label}", run(where, "vet", "./...")))
        steps.append((f"go test{label}", run(where, "test", "./...")))
    failed = [name for name, ok in steps if not ok]
    if failed:
        print(f"\nfailed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
