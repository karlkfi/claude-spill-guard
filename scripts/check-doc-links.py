#!/usr/bin/env python3
"""Check that every relative link in the repo's markdown resolves.

Repo-relative and file-relative links only, path half and fragment both.
Absolute URLs and mailto: are out of scope -- a link checker that reaches the
network is a different tool with different failure modes, and this one runs on
every PR. A fragment is not: the headings are on disk, so resolving one is a
second read of a file already open. Anchors into non-markdown targets are still
out of scope, since nothing here knows what a heading is in those. Headings are
ATX (`## Like this`) and setext (underlined with `=` or `-`), which is why the
walk drops frontmatter before it reads either: every row in `docs/queue` closes
its own with the `---` that would otherwise underline `size: S` into a heading.

Exits 1 and lists every broken link, so one run reports all of them.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# [text](target) -- not preceded by `!` so images are included the same way,
# and not inside a fenced code block or an inline span, both stripped first.
LINK = re.compile(r"(?<!\\)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
# A fence marker: its indent, the run, and whatever follows. A block closes only
# on a run of its own character, at least as long, with nothing after it, which
# is how a doc shows one fence inside another.
FENCE = re.compile(r"^( *)(`{3,}|~{3,})(.*)$")
# A run of backticks, its content, and a run of the same length. A row quoting
# a broken link as an exhibit is the case this exists for.
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
INLINE_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
DELIMITER = re.compile(r"^---[ \t]*$")
SETEXT = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# A list marker and the run of whitespace to its content. Where that content
# starts is what an indented code block is measured against: four spaces opens
# one at the outermost level and is ordinary item content inside a list, so a
# walk that reads the indent alone drops the links in every nested item.
LIST_ITEM = re.compile(r"^ *(?:[-*+]|\d{1,9}[.)]) +")

SKIP_PREFIXES = ("http://", "https://", "mailto:")


def frontmatter_end(lines):
    """The index of the first line below a YAML frontmatter block, or 0.

    An opener with no close is not frontmatter, so the file is read whole.
    """
    if not lines or not DELIMITER.match(lines[0]):
        return 0
    for i in range(1, len(lines)):
        if DELIMITER.match(lines[i]):
            return i + 1
    return 0


def prose_lines(text):
    """Yield (line_number, line, underlines) for every line rendering as prose.

    `underlines` is the heading text a setext underline sits under, and None on
    every other line. Frontmatter, fenced code and indented code are all out.
    """
    lines = text.splitlines()
    start = frontmatter_end(lines)

    fence = None          # marker, run length, container's content column
    items = []            # where the content of each open list item starts
    para, para_col = [], 0

    for n, line in enumerate(lines[start:], start + 1):
        expanded = line.expandtabs(4)
        indent = len(expanded) - len(expanded.lstrip(" "))

        if fence:
            marker, width, column = fence
            close = FENCE.match(expanded)
            if (close and indent < column + 4
                    and close.group(2)[0] == marker
                    and len(close.group(2)) >= width
                    and not close.group(3).strip()):
                fence = None
            continue
        if not line.strip():
            para = []
            yield n, line, None
            continue

        item = LIST_ITEM.match(expanded)

        # A line that has dedented out of the open items closes them, and so
        # does a marker opening a sibling of one.
        if item or not para:
            while items and indent < items[-1]:
                items.pop()
        content = items[-1] if items else 0

        # A fence opens within three spaces of its container's content column.
        # Four past it is the indented code block the marker is being shown
        # inside, and reading it as an opener skips every link to the next one.
        opener = FENCE.match(expanded)
        if opener and indent < content + 4:
            fence = (opener.group(2)[0], len(opener.group(2)), content)
            para = []
            continue

        if para:
            # An underline belongs to its paragraph only from inside the same
            # container, which is what keeps a `---` at column 0 under a list
            # item a thematic break rather than a heading over the item.
            if SETEXT.match(expanded) and para_col <= indent < para_col + 4:
                yield n, line, " ".join(s.strip() for s in para)
                para = []
                continue
            # Indented code cannot interrupt a paragraph, so an indented line
            # under an open one is a continuation whatever its column.
        elif indent >= content + 4:
            continue

        if item and indent < content + 4:
            items.append(item.end())
            para, para_col = [expanded[item.end():]], item.end()
        elif HEADING.match(line) or SETEXT.match(expanded):
            para = []
        else:
            if not para:
                para_col = content
            para.append(line)

        yield n, line, None


def links_in(text):
    """Yield (line_number, target) for every markdown link in prose."""
    for n, line, _ in prose_lines(text):
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
    for _, line, underlines in prose_lines(text):
        match = HEADING.match(line)
        heading = match.group(1) if match else underlines
        if heading is None:
            continue
        base = slug(heading)
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
