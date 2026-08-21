#!/usr/bin/env python3
"""The Go toolchain gates: gofmt, go vet, go test.

`gofmt -l` is the reason this is a script rather than three lines of YAML. It
lists every unformatted file and exits **0**, so the obvious spelling of the
gate passes while printing exactly the output that says it should not. Measured
on Go 1.26.5: one unformatted file listed, exit 0.

All three run even when an earlier one fails, so one run reports everything.
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


def run(*args):
    """Run a go command with its output inherited, so CI logs carry it."""
    sys.stdout.flush()
    return subprocess.run(("go",) + args, cwd=ROOT, check=False).returncode == 0


def main():
    failed = [
        name
        for name, ok in (
            ("gofmt", gofmt()),
            ("go vet", run("vet", "./...")),
            ("go test", run("test", "./...")),
        )
        if not ok
    ]
    if failed:
        print(f"\nfailed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
