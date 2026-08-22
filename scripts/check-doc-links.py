#!/usr/bin/env python3
"""Check that every relative link in the repo's markdown resolves.

Repo-relative and file-relative links only, path half and fragment both.
Absolute URLs and mailto: are out of scope -- a link checker that reaches the
network is a different tool with different failure modes, and this one runs on
every PR. A fragment is not: the headings are on disk, so resolving one is a
second read of a file already open. Anchors into non-markdown targets are still
out of scope, since nothing here knows what a heading is in those. Headings are
ATX (`## Like this`) -- a setext heading is invisible here, and reading one is
not free, because every row in `docs/queue` closes its frontmatter with the
`---` that would make the line above it a heading.

Exits 1 and lists every broken link, so one run reports all of them.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# [text](target) -- not preceded by `!` so images are included the same way,
# and not inside a fenced code block or an inline span, both stripped first.
LINK = re.compile(r"(?<!\\)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")
# A run of backticks, its content, and a run of the same length. A row quoting
# a broken link as an exhibit is the case this exists for.
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
INLINE_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")

SKIP_PREFIXES = ("http://", "https://", "mailto:")


def prose_lines(text):
    """Yield (line_number, line) for every line outside a fenced code block."""
    in_fence = False
    for n, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield n, line


def links_in(text):
    """Yield (line_number, target) for every markdown link in prose."""
    for n, line in prose_lines(text):
        for match in LINK.finditer(CODE_SPAN.sub("", line)):
            yield n, match.group(1)


def slug(heading):
    """GitHub's anchor for a heading: link text only, lowercase, everything that
    is not a word character or a hyphen dropped, then spaces to hyphens."""
    text = INLINE_LINK.sub(r"\1", heading).lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def slugs_in(text):
    """The anchors a file offers. GitHub disambiguates a repeated heading by
    appending -1, -2 in document order, so a duplicate is not ambiguous."""
    anchors, seen = set(), {}
    for _, line in prose_lines(text):
        match = HEADING.match(line)
        if not match:
            continue
        base = slug(match.group(1))
        count = seen.get(base, 0)
        seen[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def main():
    broken = []
    anchors = {}

    def anchors_of(md):
        if md not in anchors:
            anchors[md] = slugs_in(md.read_text(encoding="utf-8"))
        return anchors[md]

    for md in sorted(ROOT.rglob("*.md")):
        if ".git" in md.parts:
            continue
        for line, target in links_in(md.read_text(encoding="utf-8")):
            if target.startswith(SKIP_PREFIXES):
                continue
            where = f"{md.relative_to(ROOT)}:{line}: {target}"
            path, _, fragment = target.partition("#")
            if path:
                resolved = (ROOT / path[1:]) if path.startswith("/") else (md.parent / path)
                if not resolved.exists():
                    broken.append(f"broken link: {where}")
                    continue
            else:
                resolved = md
            if not fragment or resolved.suffix != ".md" or not resolved.is_file():
                continue
            if fragment not in anchors_of(resolved.resolve()):
                broken.append(f'broken anchor: {where} -- no heading slugs to "{fragment}"')

    for entry in broken:
        print(entry, file=sys.stderr)
    if broken:
        print(f"\n{len(broken)} broken link(s)", file=sys.stderr)
        return 1
    print("all relative links resolve, fragments included")
    return 0


if __name__ == "__main__":
    sys.exit(main())
