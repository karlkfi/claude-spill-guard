#!/usr/bin/env python3
"""Build every target the project ships, from one runner.

The point is the whole set. A loop that stops at the first failure, or that
takes its exit status from the last target, reports green while a target
nobody builds locally has been broken for weeks -- and the targets most likely
to break are the ones no contributor is sitting in front of.

CGO_ENABLED=0 is part of the assertion, not a convenience: cgo is how a "static
binary, empty supply chain" turns into one linked against whatever the build
host had installed.

Exits 1 and lists every target that failed, so one run reports all of them.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "bin"

TARGETS = (
    ("darwin", "arm64"),
    ("darwin", "amd64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
)


def build(goos, goarch):
    """Build one target, returning stderr on failure and None on success."""
    name = "spill-guard.exe" if goos == "windows" else "spill-guard"
    result = subprocess.run(
        ("go", "build", "-o", str(OUT / f"{goos}-{goarch}" / name), "./cmd/..."),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"},
    )
    return None if result.returncode == 0 else (result.stderr.strip() or f"exited {result.returncode}")


def main():
    failures = []
    for goos, goarch in TARGETS:
        error = build(goos, goarch)
        print(f"{goos}/{goarch}: {'ok' if error is None else 'FAILED'}")
        if error is not None:
            failures.append((f"{goos}/{goarch}", error))

    for target, error in failures:
        print(f"cross-compile: {target} failed to build:\n{error}", file=sys.stderr)
    if failures:
        print(f"\n{len(failures)} of {len(TARGETS)} target(s) failed", file=sys.stderr)
        return 1
    print(f"all {len(TARGETS)} targets build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
