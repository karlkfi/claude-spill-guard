#!/usr/bin/env python3
"""Check that every relative link in the repo's markdown resolves.

Repo-relative and file-relative links only. Absolute URLs, mailto:, and bare
anchors are out of scope -- a link checker that reaches the network is a
different tool with different failure modes, and this one runs on every PR.

Exits 1 and lists every broken link, so one run reports all of them.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# [text](target) -- not preceded by `!` so images are included the same way,
# and not inside a fenced code block, which is stripped first.
LINK = re.compile(r"(?<!\\)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")

SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def links_in(text):
    """Yield (line_number, target) for every markdown link outside a fence."""
    in_fence = False
    for n, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK.finditer(line):
            yield n, match.group(1)


def main():
    broken = []
    for md in sorted(ROOT.rglob("*.md")):
        if ".git" in md.parts:
            continue
        for line, target in links_in(md.read_text(encoding="utf-8")):
            if target.startswith(SKIP_PREFIXES):
                continue
            path = target.split("#", 1)[0]
            if not path:
                continue
            resolved = (ROOT / path[1:]) if path.startswith("/") else (md.parent / path)
            if not resolved.exists():
                broken.append(f"{md.relative_to(ROOT)}:{line}: {target}")

    for entry in broken:
        print(f"broken link: {entry}", file=sys.stderr)
    if broken:
        print(f"\n{len(broken)} broken link(s)", file=sys.stderr)
        return 1
    print("all relative links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
