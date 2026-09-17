#!/usr/bin/env python3
"""Check that the plugin manifests agree -- with each other, and with the tag.

`.claude-plugin/plugin.json` carries a `version`, and
`.claude-plugin/marketplace.json` repeats it in the entry that points at this
repository. A marketplace entry compares that string and nothing else, so a
release whose manifests still say the old number cannot be delivered by `claude
plugin update` at all: the tag publishes archives that no plugin install ever
reaches. The failure is silent on both sides -- the release is complete and
correct, and every existing install stays where it is.

`docs/development/release-process.md` has said "nothing checks this at tag time"
since the process was written, and made it step 1 of the pre-tag list with a
read-back a person runs by hand. This is that check, and the reason it exists
rather than the sentence continuing to exist is v0.1.0: the release job asserted
eight things, every one of them about assets, and published a draft with an
empty body. An invariant stated in prose and enforced by a human reading it back
is the same shape, one file over.

Two claims, and they are separable on purpose:

  --version X.Y.Z   both manifests carry exactly X.Y.Z. Only a tag knows the
                    number, so the release job is the only caller that can pass
                    it.

  (no argument)     the manifests agree with each other. That is checkable on
                    every pull request, with no tag, and it is the half that
                    catches the common defect -- editing one file and not the
                    other.

Exits 1 and reports every disagreement, so one run says all of them.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / ".claude-plugin" / "plugin.json"
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"

# The repository the marketplace entry has to point at for its version to be
# this plugin's. An entry for something else carrying its own version is not a
# disagreement with anything here.
SOURCE = "karlkfi/claude-spill-guard"


def load(path):
    """The decoded file, or exit saying which one could not be read.

    A manifest this cannot parse is not "no version found": every assertion
    below would then pass over nothing, which is the reading this whole script
    exists to refuse.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        sys.exit(f"plugin-version: {path.relative_to(ROOT)} could not be read "
                 f"({err}), so what the manifests declare is unknown and every "
                 f"check below would pass over nothing.")


def repo_of(entry):
    """The repository a marketplace entry installs from, as a string.

    `source` is written as an object here -- `{"source": "github", "repo":
    "owner/name"}` -- and Claude Code also accepts a bare string. Both shapes
    are read, because matching only the one this file happens to use today
    would make the check silently stop finding the entry the day it changed,
    and a check that finds no entry has to be loud rather than empty.
    """
    source = entry.get("source")
    if isinstance(source, str):
        return source
    if isinstance(source, dict):
        return " ".join(v for v in source.values() if isinstance(v, str))
    return ""


def declared():
    """Every (where, version) the manifests carry, for this plugin.

    A marketplace with no entry for this repository is a finding rather than an
    empty list -- that is a manifest which cannot deliver this plugin at all,
    and returning nothing would read as agreement.
    """
    found = []

    plugin = load(PLUGIN)
    version = plugin.get("version")
    if not isinstance(version, str) or not version:
        sys.exit(f"plugin-version: {PLUGIN.relative_to(ROOT)} carries no "
                 f"`version` string, so there is nothing here to compare.")
    found.append((PLUGIN.relative_to(ROOT), version))

    market = load(MARKETPLACE)
    entries = market.get("plugins")
    if not isinstance(entries, list) or not entries:
        sys.exit(f"plugin-version: {MARKETPLACE.relative_to(ROOT)} lists no "
                 f"plugins, so no marketplace entry can deliver this one.")

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", f"plugins[{i}]")
        if SOURCE in repo_of(entry):
            v = entry.get("version")
            if not isinstance(v, str) or not v:
                sys.exit(f"plugin-version: the {name} entry in "
                         f"{MARKETPLACE.relative_to(ROOT)} carries no "
                         f"`version` string.")
            found.append((f"{MARKETPLACE.relative_to(ROOT)} ({name})", v))

    if len(found) == 1:
        sys.exit(f"plugin-version: no entry in "
                 f"{MARKETPLACE.relative_to(ROOT)} names {SOURCE}, so nothing "
                 f"there can deliver this plugin.")
    return found


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--version",
        help="the version both manifests must carry, without a leading `v`. "
             "Only a tag knows this, so the release job is its only caller; "
             "without it this checks the manifests against each other.")
    args = parser.parse_args(argv[1:])

    found = declared()
    findings = []

    if args.version:
        want = args.version.lstrip("v")
        if not want:
            sys.exit("plugin-version: --version was empty after stripping a "
                     "leading `v`, and comparing against an empty string would "
                     "pass over nothing.")
        for where, version in found:
            if version != want:
                findings.append(f"{where} says {version}, and the tag says "
                                f"{want}")
        target = f"the tag's {want}"
    else:
        versions = {version for _, version in found}
        if len(versions) > 1:
            listed = ", ".join(f"{where} says {version}"
                               for where, version in found)
            findings.append(f"the manifests disagree: {listed}")
        target = f"each other at {found[0][1]}"

    if findings:
        for line in findings:
            print(f"plugin-version: {line}", file=sys.stderr)
        print(f"\nA marketplace entry compares this string and nothing else, "
              f"so `claude plugin update` cannot deliver a release whose "
              f"manifests disagree with it.", file=sys.stderr)
        return 1

    print(f"plugin-version: {len(found)} manifest version(s) agree with "
          f"{target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
