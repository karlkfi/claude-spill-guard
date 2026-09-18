#!/usr/bin/env python3
"""Keep every published release body equal to the notes file it came from.

[`docs/releases/README.md`](../docs/releases/README.md) states it in one line:
"The invariant is that this file matches the published body -- so an edit to
the notes lands as a PR and is then republished, never typed into the Release."
That is what makes each fix a diff and each published body reproducible from a
commit, and it is the whole reason the notes are authored in the tree rather
than in the web form.

One thing checked it, and it ran only on a tag: `release.yml`'s *The published
body is the notes file, byte for byte* step, which compares the two after
GoReleaser publishes the draft. After that tag nothing read the pair again. A
notes file edited and merged sat diverged from the published body for as long
as nobody ran `gh release edit`, and no gate, no job and no lint had an opinion.

**The comparison is the release job's, not a second one.** Two normalisations,
both measured there rather than anticipated: `\\r` is dropped, because a body
GitHub stores with CRLF would differ from the tree's LF and say nothing about
the text, and trailing newlines are stripped from both sides, because GitHub
returns the body with one more than the file carries. Measured here 2026-09-07
across all three published releases: v0.1.0 16,009 bytes published against
16,008 in the tree, v0.2.0 17,708 against 17,706, v0.3.0 29,180 against 29,179,
and every pair equal once those two are applied. A byte-exact compare fails on
every release that is right.

**The walk is over releases, not over files.** A tag with notes and no release
is legitimate -- `v0.1.0-rc.1.md` and `v0.2.0-rc.1.md` are both in the tree and
both rehearsal drafts that were deleted -- so a notes file nothing published is
not a finding. A release with no notes file is the same defect from the other
side, and walking the releases sees it for free.

It reads the working tree rather than the tag's tree, which the README settles:
digests land as an amendment after the publish goes green, so the tagged copy
of a notes file stays one section behind the published body by design. The
invariant is stated against the published body, not against the tag.

**Where it binds, which is the decision this was written to take.** The
invariant is false only from the moment a notes edit *merges*: while that pull
request is open the divergence is the proposal, and the branch cannot repair it
either way, because republishing is `gh release edit` and no pull request runs
it. So a per-branch failure would redden the one party who cannot act, during
the one window in which the tree is right. `--merged` is what promotes a
finding to a failure, the way `queue`'s `dangling-link` is promoted on a push
to `main`, and it fires at the same merge that creates the divergence rather
than one merge later.

Without it the findings are still printed -- a contributor editing a notes file
should be told what will be owed -- and exit is 0. That includes a read this
could not take: `gh` is not in the required tool tier and there is no second
reader for a release *body*, so a machine without it must not fail `make check`.
In the merged tier it is a runner with `GH_TOKEN`, and there a read that failed
is this check failing rather than an answer about the tree.
"""

import argparse
import difflib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTES = ROOT / "docs" / "releases"

# How much of a divergence to show. The release job prints 40; a finding needs
# enough to say which paragraph moved and no more, since a whole release body
# in a job log buries the other findings under it.
DIFF_LINES = 20


def normalise(text):
    """The release job's two normalisations, and no others."""
    return text.replace("\r", "").rstrip("\n")


def gh(*args):
    """(stdout, None) or (None, why not)."""
    if not shutil.which("gh"):
        return None, "`gh` is not on PATH, and a release body has no second reader"
    done = subprocess.run(("gh",) + args, cwd=ROOT, capture_output=True,
                          text=True, check=False)
    if done.returncode != 0:
        return None, (f"`gh {' '.join(args)}` exited {done.returncode}: "
                      f"{done.stderr.strip()}")
    return done.stdout, None


def published():
    """(the tags a release exists for, None), or (None, why not).

    Drafts included, because `gh release list` reports them and the release job
    asserts a draft's body against the same file -- a draft that published two
    newlines instead of the notes is the defect that produced that step.
    """
    out, why = gh("release", "list", "--limit", "1000",
                  "--json", "tagName", "--jq", ".[].tagName")
    if out is None:
        return None, why
    return sorted(out.split()), None


def findings(tags):
    """Every release whose body is not its notes file, in tag order."""
    out = []
    for tag in tags:
        notes = NOTES / f"{tag}.md"
        if not notes.is_file():
            out.append(f"missing: {notes.relative_to(ROOT)}: {tag} is published "
                       f"and its notes are not in the tree")
            continue

        body, why = gh("release", "view", tag, "--json", "body", "--jq", ".body")
        if body is None:
            out.append(f"unreadable: {tag}: {why}")
            continue

        authored = notes.read_text(encoding="utf-8")
        if normalise(body) == normalise(authored):
            continue

        out.append(
            f"diverged: {notes.relative_to(ROOT)}: the published {tag} body is "
            f"not this file ({len(body.encode())} bytes published against "
            f"{len(authored.encode())} in the tree). Republish it: "
            f"`gh release edit {tag} --notes-file docs/releases/{tag}.md`")
        shown = list(difflib.unified_diff(
            normalise(body).splitlines(), normalise(authored).splitlines(),
            fromfile=f"published {tag}", tofile=str(notes.relative_to(ROOT)),
            lineterm=""))
        out.extend(f"  {line}" for line in shown[:DIFF_LINES])
        if len(shown) > DIFF_LINES:
            out.append(f"  ... {len(shown) - DIFF_LINES} more diff line(s)")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--merged", action="store_true",
        help="promote every finding to a failure. The invariant is only false "
             "once a notes edit has merged, so this binds on `main` and reports "
             "without failing anywhere else.")
    args = parser.parse_args()

    tags, why = published()
    if tags is None:
        print(f"release-notes: the release list could not be read -- {why}. "
              f"That is this check failing, not an answer about the tree.",
              file=sys.stderr if args.merged else sys.stdout)
        return 1 if args.merged else 0

    if not tags:
        print("release-notes: no release is published, so there is no body to "
              "compare a notes file against")
        return 0

    print(f"release-notes: {len(tags)} published release(s): "
          f"{', '.join(tags)}", flush=True)

    hits = findings(tags)
    if not hits:
        print(f"release-notes: every published body is the notes file it came "
              f"from, under the release job's two normalisations")
        return 0

    stream = sys.stderr if args.merged else sys.stdout
    for hit in hits:
        print(hit, file=stream)
    named = sum(1 for hit in hits if not hit.startswith("  "))
    if args.merged:
        print(f"\nrelease-notes: {named} published release(s) no longer match "
              f"their notes file. docs/releases/README.md: the invariant is "
              f"that the file matches the published body, so republish rather "
              f"than editing the Release.", file=stream)
        return 1
    print(f"\nrelease-notes: {named} finding(s), reported and not failing. The "
          f"invariant is false only once an edit has merged, and no pull "
          f"request can republish -- `make release-notes MERGED=true` is what "
          f"the push to main runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
