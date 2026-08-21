#!/usr/bin/env python3
"""Check the shipped binary's import graph against what this project promises.

Two checks, selected by argument:

  no-deps      go.mod carries no `require` block, and every package in the
               build graph is either stdlib or this module's own.
  no-network   the build graph contains none of net, net/http, os/exec.

Both read the graph through `go list`, which is the toolchain's own answer to
what gets linked -- not a grep over import lines, which misses a transitive
pull and trips over one inside a string.

Test-only imports are deliberately out of scope. `go list -deps ./...` reports
what the binary links; a test that imports net/http ships in no artifact.

Exits 1 and lists every violation, so one run reports all of them.
"""

import json
import subprocess
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Anything with network capability, and anything that can start a process that
# has it, reaches one of these three in the transitive graph -- so matching them
# exactly over the closure is enough, and net/netip stays available for the
# reserved-range validator, which parses addresses and opens nothing.
FORBIDDEN = ("net", "net/http", "os/exec")

CHECKS = ("no-deps", "no-network")


def go(*args):
    """Run a go command in the repo root, returning stdout. Any failure is a
    check failure: a graph that cannot be read is not a graph that is clean."""
    result = subprocess.run(
        ("go",) + args, cwd=ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"`go {' '.join(args)}` exited {result.returncode}:\n{result.stderr.strip()}")
    return result.stdout


def packages():
    """Every package the build graph reaches, as {import path: package}."""
    decoder = json.JSONDecoder()
    text = go("list", "-deps", "-json", "./...")
    found, at = {}, 0
    while at < len(text):
        obj, end = decoder.raw_decode(text, at)
        found[obj["ImportPath"]] = obj
        at = end
        while at < len(text) and text[at].isspace():
            at += 1
    return found


def chain_to(pkgs, module, target):
    """The shortest import chain from one of this module's packages to target,
    so the failure names who pulled it in rather than only that it is there."""
    queue = deque(
        [[path] for path in sorted(pkgs) if path == module or path.startswith(module + "/")]
    )
    seen = set()
    while queue:
        path = queue.popleft()
        if path[-1] == target:
            return " -> ".join(path)
        for dep in pkgs.get(path[-1], {}).get("Imports", ()):
            if dep not in seen:
                seen.add(dep)
                queue.append(path + [dep])
    return target


def check_no_deps(module, pkgs):
    failures = []
    for require in json.loads(go("mod", "edit", "-json")).get("Require") or ():
        failures.append(f"go.mod requires {require['Path']} {require['Version']}")
    for path, pkg in sorted(pkgs.items()):
        if pkg.get("Standard") or path == module or path.startswith(module + "/"):
            continue
        failures.append(f"non-stdlib package in the build graph: {chain_to(pkgs, module, path)}")
    return failures


def check_no_network(module, pkgs):
    return [
        f"{name} in the build graph: {chain_to(pkgs, module, name)}"
        for name in FORBIDDEN
        if name in pkgs
    ]


def main(argv):
    if len(argv) != 1 or argv[0] not in CHECKS:
        print(f"usage: check-supply-chain.py {{{'|'.join(CHECKS)}}}", file=sys.stderr)
        return 2

    check = argv[0]
    try:
        module = json.loads(go("mod", "edit", "-json"))["Module"]["Path"]
        pkgs = packages()
    except RuntimeError as err:
        print(f"{check}: {err}", file=sys.stderr)
        return 1

    failures = check_no_deps(module, pkgs) if check == "no-deps" else check_no_network(module, pkgs)
    for failure in failures:
        print(f"{check}: {failure}", file=sys.stderr)
    if failures:
        print(f"\n{len(failures)} violation(s)", file=sys.stderr)
        return 1
    print(f"{check}: {len(pkgs)} packages in the build graph, all clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
