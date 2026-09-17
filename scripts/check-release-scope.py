#!/usr/bin/env python3
"""Keep a release-scope record from outliving the tag it was written for.

`docs/plan/<tag>.md` says what a release is for, and it is written to be read
before the tag. After the tag it is a document naming a version that exists
while asserting that version is still ahead -- the one failure mode the
arrangement was shaped to avoid. A `vX.Y.Z` label on a row is the same record
in the store: it is what makes `render --label vX.Y.Z` show the release's
scope, and once that release exists it shows a scope nobody is still deciding.

`docs/development/release-process.md` carries the deletion under *Publishing
the draft*, and until this existed that was the whole of the enforcement: a
step somebody performs by reading it back. This repository has priced that
construction twice already -- the plugin manifests carried *Nothing checks this
at tag time* until #87 gated them, and the release job's asset assertions sat
on top of a draft with an empty body until #85. Both were invariants stated in
prose beside the person expected to honour them.

**The asymmetry is what makes it worth a gate rather than a reminder.**
Forgetting the deletion leaves a record that reads as current and nothing
reports it, so the failure is silent and permanent. Performing it when there is
nothing to delete costs a `git rm` that fails loudly. Only one direction has a
symptom.

**Where it runs, and the window it opens.** On the pull request, which is where
`release-claims` already reads real release state and where the previous tag's
record is the thing under review. The release job is the wrong place: a tag
that has just published *has* a plan doc, legitimately, because the deletion is
a step after publishing -- so a check there fails every correct release. What
this does instead is redden every branch between the publish and the PR that
takes the deletion. That is the pressure rather than a defect, and the repair
is the `git rm` the runbook already names.

**The passing answer is an empty one**, which is the shape that reports green
while reading nothing: a run that found no `docs/plan/` at all prints exactly
what a correctly retired one prints. Nothing in this file can stand in for
that, so the assertion that it can fire at all lives in the mutation control,
which plants a record for a released version and requires the finding by name.

**The release state is read the way `release-claims` reads it**, deliberately
the same ladder rather than a second answer: the fact lives off this machine,
`gh` is not in the required tool tier, and a read that could not be taken has
to report itself failing rather than as a verdict about the tree. `gh release
list` first -- it is the only reader that sees a draft, and a draft means the
tag is cut, which is the event a scope record retires against. `git ls-remote
--tags` is the fallback for a machine with no `gh`; it reads tags rather than
releases, so where the two disagree it fires earlier than the primary reader
and never later.

The store is read through the vendored `queue.py`, not by a second frontmatter
parser. Two readers of one format is how the format's meaning drifts, and the
one that ships with the store is the one `make queue` already enforces against.
"""

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAN = "docs/plan"
STORE = ROOT / "docs" / "queue"
QUEUE_PY = ROOT / "scripts" / "vendor" / "claude-skills" / "queue.py"

# What a release-scope record names. Anchored, because a plan doc is named for
# a tag and a label is written as one; anything else under docs/plan/ is some
# other document and not this gate's business.
VERSION_TAG = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def released_tags():
    """(the tags a release exists for, what answered), or (None, why not)."""
    if shutil.which("gh"):
        done = subprocess.run(
            ("gh", "release", "list", "--limit", "1000",
             "--json", "tagName", "--jq", ".[].tagName"),
            cwd=ROOT, capture_output=True, text=True, check=False)
        if done.returncode == 0:
            return set(done.stdout.split()), "`gh release list`"

    done = subprocess.run(("git", "ls-remote", "--tags", "origin", "v*"),
                          cwd=ROOT, capture_output=True, text=True, check=False)
    if done.returncode == 0:
        tags = set()
        for line in done.stdout.splitlines():
            ref = line.partition("\t")[2]
            # An annotated tag also prints `refs/tags/v0.1.0^{}` for the commit
            # it points at, which names the tag on the line above and nothing
            # new.
            if ref.startswith("refs/tags/") and not ref.endswith("^{}"):
                tags.add(ref[len("refs/tags/"):])
        return tags, "`git ls-remote --tags origin 'v*'`"

    return None, done.stderr.strip() or "both reads failed"


def plan_records():
    """Tracked docs/plan/<tag>.md, as (path, tag).

    Tracked rather than globbed: the record this is about is the one the
    repository carries. A plan doc being drafted in a working tree names a
    version nobody has tagged, so neither reading finds it anyway.
    """
    listed = subprocess.run(("git", "ls-files", PLAN), cwd=ROOT,
                            capture_output=True, text=True, check=False)
    if listed.returncode != 0:
        sys.exit(f"release-scope: `git ls-files {PLAN}` exited "
                 f"{listed.returncode}, so nothing below could have been "
                 f"read.\n{listed.stderr.strip()}")
    return [(path, Path(path).stem) for path in listed.stdout.split()
            if VERSION_TAG.match(Path(path).stem)]


def scope_labels():
    """Every version-shaped label in the store, as (path, label).

    Empty is an exit rather than a shorter list, and only here: docs/plan/ is
    legitimately empty for most of a release cycle, while a store that loaded
    nothing is a store this did not find. `make queue` promotes the same case
    under `empty-store` for the same reason.

    Read through queue.py's own loader, which walks the working tree where the
    plan half reads the index. Second-guessing it with `git ls-files` would be
    the second reader this avoids, and the difference cannot reach a record the
    repository carries -- an untracked row is nobody's release scope.
    """
    spec = importlib.util.spec_from_file_location("spillguard_queue", QUEUE_PY)
    queue = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(queue)

    items, _ = queue.load(STORE)
    if not items:
        sys.exit(f"release-scope: {STORE.relative_to(ROOT)} loaded no items, "
                 f"so half of this read nothing and a pass would mean nothing")
    return [(str(item.path.relative_to(ROOT)), label)
            for item in items for label in item.labels
            if VERSION_TAG.match(label)]


def findings(released):
    out = []
    for path, tag in plan_records():
        if tag in released:
            out.append(f"stale plan: {path}: {tag} is released, so this record "
                       f"outlived the tag it was written for")
    for path, label in scope_labels():
        if label in released:
            out.append(f"stale label: {path}: `{label}` is released, so this "
                       f"row is labelled for a scope nobody is still deciding")
    return out


def main():
    released, instrument = released_tags()
    if released is None:
        print(f"release-scope: the release state could not be read -- "
              f"{instrument}. That is this check failing, not an answer about "
              f"the tree, so it reports nothing about the records in it. Like "
              f"`release-claims`, its oracle is off this machine.",
              file=sys.stderr)
        return 1

    state = ", ".join(sorted(released)) if released else "none"
    print(f"release-scope: released: {state}, per {instrument}", flush=True)

    hits = findings(released)
    if not hits:
        print("release-scope: no plan doc and no row label names a release "
              "that exists")
        return 0

    for hit in hits:
        print(hit, file=sys.stderr)
    print(f"\nrelease-scope: {len(hits)} record(s) survive the release they "
          f"were written for. Retire them the way "
          f"docs/development/release-process.md says, under *Publishing the "
          f"draft*: `git rm` the plan doc, and drop the label from every row "
          f"still carrying it.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
