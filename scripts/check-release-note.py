#!/usr/bin/env python3
"""Check that a pull request body carries a `release-note` block.

docs/releases/README.md says a release's change list is collected from the
blocks `.github/pull_request_template.md` asks for, and nothing made a body
carry one. Measured 2026-11-02 while cutting v0.6.1: 1 of the 17 pull requests
merged since v0.6.0 carried the block, and that one said `NONE`; v0.6.0 had
recorded 7 of 22. The other sixteen, every product fix among them, were
reconstructed from their bodies and re-driven on built binaries at tag time --
which is the expensive half of a release, and the half the block exists to
remove. `gh pr create --body-file` never shows the template, so a session
opening a pull request that way skips the field without seeing it.

`NONE` is an answer, and so is any sentence. What fails is a body with no
block, a block that is empty, and a block that never closes. A block inside an
HTML comment does not count: GitHub renders the comment as nothing, so whoever
collects the notes from the rendered body would not see it.

It is a workflow job and not a `make` gate, because the body exists only in the
event payload. Locally, feed it one:

  gh pr view N --json body -q .body > body.md
  python3 scripts/check-release-note.py --body-file body.md
"""

import argparse
import json
import re
import sys
from pathlib import Path

COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
# CommonMark: up to three spaces of indent, three or more backticks or tildes,
# and the info string's first word is the language.
OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*release-note[ \t]*$")


def blocks(body):
    """Each `release-note` block's text, or None for one that never closes."""
    lines = COMMENT.sub("", body.replace("\r\n", "\n")).split("\n")
    found = []
    i = 0
    while i < len(lines):
        m = OPEN.match(lines[i])
        i += 1
        if not m:
            continue
        fence = m.group(1)
        close = re.compile(r"^ {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*$")
        content = []
        while i < len(lines) and not close.match(lines[i]):
            content.append(lines[i])
            i += 1
        if i == len(lines):
            found.append(None)
        else:
            found.append("\n".join(content).strip())
            i += 1
    return found


def check(body):
    """The reasons this body fails, empty when it passes."""
    found = blocks(body or "")
    if not found:
        return ["the body has no ```release-note block. Copy the one from "
                ".github/pull_request_template.md into the body and fill it "
                "in: one sentence for the next release's notes, or `NONE` for "
                "a change that ships in no artifact"]
    reasons = []
    for n, text in enumerate(found, 1):
        if text is None:
            reasons.append(f"release-note block {n} never closes, so nothing "
                           f"after its opening fence reads as the note")
        elif not text:
            reasons.append(f"release-note block {n} is empty. Write the "
                           f"sentence, or `NONE` -- an empty block is the "
                           f"skipped field this check exists to refuse")
    return reasons


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--event", type=Path,
                        help="a pull_request event payload, as $GITHUB_EVENT_PATH names")
    source.add_argument("--body-file", type=Path, help="a pull request body")
    args = parser.parse_args()

    if args.event:
        # A body nobody wrote arrives as null, not as an empty string.
        body = json.loads(args.event.read_text())["pull_request"]["body"]
    else:
        body = args.body_file.read_text()

    reasons = check(body)
    for reason in reasons:
        print(f"release-note: {reason}", file=sys.stderr)
    if reasons:
        return 1
    print(f"release-note: {len(blocks(body))} block(s), none empty")
    return 0


if __name__ == "__main__":
    sys.exit(main())
