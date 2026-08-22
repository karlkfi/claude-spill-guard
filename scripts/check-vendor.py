#!/usr/bin/env python3
"""Check that every vendored file still hashes to the digest declared for it.

Two files here are verbatim copies of tooling that lives in another repo. A fix
written into the copy reaches no other repo running the same tooling, and the
next re-vendor overwrites it silently, because a re-vendor is a copy rather than
a merge. This is what makes that visible: the copy drifts, the gate goes red,
and the diff says which file.

It cannot tell you whether upstream has moved -- that repo is private, so an
oracle for it needs a token this one does not carry. scripts/README.md argues
that. What is local, and is all this asserts, is that the bytes here still match
what somebody wrote down when they took them.

**The input set comes from the tree, not from the table.** Everything git tracks
under scripts/vendor/ is vendored by construction, so a third copy added without
a row fails here rather than passing unnoticed -- which is the failure a manifest
cannot have, since a manifest can only check what it already lists. The table
supplies the expected digest for each file the tree names, and a file it does not
name is a finding.

The digests are 16 hex characters, which is the record's existing shape and
enough for what this catches: an honest edit, not a forged one. Nothing here is
an anti-tamper control -- anyone who can write the file can write the row above
it, which is the point. A deliberate fork stays possible and stops being silent,
because declaring one moves the digest in the same diff a reviewer reads.

Exits 1 and lists every disagreement, so one run reports all of them.
"""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
VENDOR = SCRIPTS / "vendor"
README = SCRIPTS / "README.md"

# The table's header row, matched exactly. Anchoring on it rather than on any
# pipe-delimited line keeps prose that happens to hold a table out of the parse,
# and turns a reformat into one clear failure instead of a silently short list.
HEADER = "| Here | Upstream path | Taken from | sha256 |"

DIGEST_LEN = 16
DIGEST_RE = re.compile(rf"^[0-9a-f]{{{DIGEST_LEN}}}$")

# The first column is a link, so the record reads as a page and the `docs` gate
# resolves it. Its href is README-relative.
LINK_RE = re.compile(r"\]\(([^)]+)\)")


def tracked():
    """Every tracked path under scripts/vendor/, repo-relative."""
    out = subprocess.run(("git", "ls-files", "-z", "--", "scripts/vendor"),
                         cwd=ROOT, check=True, capture_output=True,
                         text=True).stdout
    return sorted(p for p in out.split("\0") if p)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()[:DIGEST_LEN]


def row(rel, actual):
    """The table row to paste for a file, with the columns only a human knows
    left as placeholders."""
    href = Path(rel).relative_to("scripts")
    return (f"| [`{Path(rel).name}`]({href}) | `<upstream path>` | "
            f"`<commit>`, <date> | `{actual}` |")


def declared():
    """{repo-relative path: digest} from the table, and any complaint about a
    row that did not parse. Exits if the table itself is not there: a parse that
    found nothing passes every assertion below."""
    lines = README.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines)
                     if line.strip() == HEADER)
    except StopIteration:
        sys.exit(f"vendor: no `{HEADER}` header in "
                 f"{README.relative_to(ROOT)}, so no digest is declared "
                 f"anywhere and nothing below could have failed")

    found, findings = {}, []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            findings.append(f"a row in {README.relative_to(ROOT)} has "
                            f"{len(cells)} columns, not 4: {line.strip()!r}")
            continue
        link = LINK_RE.search(cells[0])
        value = cells[3].strip("`")
        if link is None:
            findings.append(f"a row in {README.relative_to(ROOT)} names no "
                            f"linked file in its first column: {cells[0]!r}")
            continue
        if not DIGEST_RE.match(value):
            findings.append(f"the row for {cells[0]} declares {value!r}, which "
                            f"is not {DIGEST_LEN} hex characters")
            continue
        rel = str((SCRIPTS / link.group(1)).resolve().relative_to(ROOT))
        if rel in found:
            findings.append(f"{rel} has two rows in "
                            f"{README.relative_to(ROOT)}, so which digest "
                            f"binds is whichever one a reader stops at")
        found[rel] = value

    if not found and not findings:
        sys.exit(f"vendor: the table in {README.relative_to(ROOT)} holds no "
                 f"rows, so nothing below could have failed")
    return found, findings


def main():
    files = tracked()
    if not files:
        print("vendor: git tracks nothing under scripts/vendor/, so every "
              "assertion below passed over nothing -- has the tree moved?",
              file=sys.stderr)
        return 1

    expected, findings = declared()

    for rel in files:
        actual = digest(ROOT / rel)
        if rel not in expected:
            findings.append(f"{rel} is vendored and nothing declares a digest "
                            f"for it. Add its row to "
                            f"{README.relative_to(ROOT)}:\n    {row(rel, actual)}")
        elif expected[rel] != actual:
            findings.append(f"{rel} hashes to {actual}, and "
                            f"{README.relative_to(ROOT)} declares "
                            f"{expected[rel]}. Send the change upstream and "
                            f"re-vendor, or declare the fork by moving the "
                            f"row:\n    {row(rel, actual)}")

    for rel in sorted(set(expected) - set(files)):
        findings.append(f"{README.relative_to(ROOT)} declares a digest for "
                        f"{rel}, which git does not track -- the row outlived "
                        f"the file")

    for entry in findings:
        print(f"vendor: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} vendored-copy disagreement(s). A fix written "
              f"into a copy reaches no other repo running the same tooling, and "
              f"the next re-vendor discards it.", file=sys.stderr)
        return 1
    print(f"vendor: {len(files)} vendored file(s), each hashing to the digest "
          f"{README.relative_to(ROOT)} declares")
    return 0


if __name__ == "__main__":
    sys.exit(main())
