#!/usr/bin/env python3
"""Check that no rendered backlog index is committed.

The store keeps one file per item so that two sessions completing different
items never touch the same path. An index undoes that in a single file: every
completing session has to delete its own row from it, and git needs one
unchanged line between two changes, so rows that sit next to each other cannot
both merge. Render on demand instead -- `queue.py render`.

Tracked files only. An index rendered into the working tree is the sanctioned
workflow and must not fail the gate; what this asserts is that none of them was
committed.

Two signals, because either alone is evadable. The first matches what
`queue.py render` emits, which is how an index gets committed in practice --
someone renders one and saves it. The second counts how many of the store's
items a file names, which catches an index nobody rendered.

Exits 1 and lists every file that looks like one, so one run reports all of them.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "docs" / "queue"

# `render --format table` opens with this line, and `render` (text) emits rows
# of status, id, size, title. Three consecutive rows rather than one: a single
# line of that shape is reachable in prose quoting the output.
TABLE_HEADER = "| ID | Item | Labels | St | Sz | Notes |"
TEXT_ROW = re.compile(r"^(?:ready|blocked|deferred)\s+Q\d+\s+\S+\s+\S")
TEXT_ROW_RUN = 3

# Either shape counts as naming an item: a link at its file, or the bare id. An
# index built by hand may use only the second.
ITEM_LINK = re.compile(r"\[[^\]]*\]\((?:\./)?(Q\d+)\.md(?:#[^)]*)?\)")
ITEM_ID = re.compile(r"\bQ\d+\b")

# Half the store, with a floor. Measured 2026-08-21 over the 48 tracked files
# of a 23-item store: the most any real page names is 6 distinct ids, in
# docs/queue/README.md, and an index names all 23. Half is 12, so the floor
# governs only below 20 items -- where it trades a missed hand-rolled index for
# keeping that margin off prose. Nothing is given up on the shape that actually
# gets committed: the render signature above has no threshold and fires
# whatever the store's size.
ID_FLOOR = 10


def tracked():
    """Every tracked path, as a list of repo-relative strings."""
    out = subprocess.run(("git", "ls-files", "-z"), cwd=ROOT, check=True,
                         capture_output=True, text=True).stdout
    return [p for p in out.split("\0") if p]


def store_size():
    return len([p for p in STORE.glob("Q*.md") if re.fullmatch(r"Q\d+", p.stem)])


def looks_rendered(text):
    """The reason `queue.py render` output is in here, or None."""
    lines = text.splitlines()
    if any(line.strip() == TABLE_HEADER for line in lines):
        return "carries the header `queue.py render --format table` emits"
    run = 0
    for line in lines:
        run = run + 1 if TEXT_ROW.match(line) else 0
        if run >= TEXT_ROW_RUN:
            return f"carries {TEXT_ROW_RUN} consecutive `queue.py render` rows"
    return None


def main():
    limit = max(ID_FLOOR, (store_size() + 1) // 2)
    findings = []
    for rel in tracked():
        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        reason = looks_rendered(text)
        if reason is None:
            named = set(ITEM_LINK.findall(text)) | set(ITEM_ID.findall(text))
            if len(named) >= limit:
                reason = (f"names {len(named)} of the store's items, at or over "
                          f"the {limit} that reads as an enumeration")
        if reason is not None:
            findings.append(f"{rel}: {reason}")

    for entry in findings:
        print(f"committed index: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} committed backlog index(es). The store has no "
              f"index by design -- render one with `python3 scripts/queue.py "
              f"render` and leave it untracked.", file=sys.stderr)
        return 1
    print(f"no committed backlog index (limit: {limit} items named in one file)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
