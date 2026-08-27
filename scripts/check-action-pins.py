#!/usr/bin/env python3
"""Every `uses:` in every workflow names an immutable revision.

A tag is mutable by whoever owns the action, and an action runs inside a job
holding the repository token, so a tag-pinned step is third-party code that can
change under this repository between one run and the next. This is a different
surface from `no-deps` and `no-network`, which check what the shipped binary
links; this checks what runs in CI.

actionlint does not close it. It reads the ref and asserts only that one is
present and well formed, so `@v4` and `@main` both pass. Dependabot bumps pins
and cannot stop one being written as a tag. A gate is the only thing that
catches the reference typed by hand next year.

The reading comes from a real YAML parser, not a regex over the lines: `uses:`
appears in this repository's own workflow inside a comment and inside a `run:`
block, and neither is a mapping key. scripts/workflow_model.py is the seam.

Three shapes are exempt or judged differently, and each for its own reason:

  * a local action (`./.github/actions/x`) is this repository's own code, and
    the commit that changes it is the commit under review;
  * a reusable workflow is `owner/repo/.github/workflows/x.yml@ref` and takes
    the same SHA rule as an action -- it is somebody else's code either way;
  * a `docker://` image has no git ref, so what it needs is a digest.

Exits 1 and lists every unpinned reference, so one run reports all of them --
and exits 1 on finding no reference at all, because a gate that swept nothing
prints the same success line as one that swept everything.
"""

import re
import sys

import workflow_model

# A commit SHA as GitHub writes one. Full length only: an abbreviated SHA is
# ambiguous by construction, and the whole property here is that the reference
# names exactly one object.
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# An image digest. sha256 is what a registry emits and what `docker://` takes.
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DOCKER_PREFIX = "docker://"


def verdict(value):
    """None when the reference is pinned, or why it is not."""
    if value.startswith("./"):
        return None
    if value.startswith(DOCKER_PREFIX):
        image = value[len(DOCKER_PREFIX):]
        _, sep, digest = image.rpartition("@")
        if not sep:
            return ("names a docker image with no digest. A tag is mutable by "
                    "whoever owns the registry entry")
        if not DIGEST_RE.match(digest):
            return (f"pins a docker image to {digest!r}, which is not "
                    f"`sha256:` and 64 hex characters")
        return None
    action, sep, ref = value.rpartition("@")
    if not sep or not action:
        return ("names no revision at all, so the ref GitHub resolves is "
                "whatever the default branch holds at the time")
    if not SHA_RE.match(ref):
        return (f"is pinned to {ref!r}, which is a tag or branch rather than a "
                f"40-character commit SHA. Whoever owns that action can move "
                f"it between one run and the next")
    return None


def main():
    files = workflow_model.load()
    findings, checked = [], 0
    for path, entry in sorted(files.items()):
        # A workflow with no steps that use anything is legitimate; a model
        # that lost the list is not, and the parser exits rather than
        # returning one, so reaching here with an empty list is a real zero.
        for item in entry["uses"]:
            checked += 1
            why = verdict(item["value"])
            if why is not None:
                findings.append(f"{path}:{item['line']}: {item['path']} "
                                f"{why}:\n    uses: {item['value']}")

    # The seam guarantees every workflow file was modelled. It does not
    # guarantee the `uses:` extraction produced anything, and the parser's own
    # floor is on `jobs:` rather than on this -- so a total extraction failure
    # that still found jobs arrives here as a clean sweep of nothing, and the
    # success line below would call it "every one pinned". A workflow of `run:`
    # steps alone is a legitimate zero and this refuses that too, deliberately:
    # the two are indistinguishable from here, and this repository's rule is to
    # block on what it cannot settle rather than pass.
    if not checked:
        print(f"action-pins: {len(files)} workflow(s) modelled and not one "
              f"`uses:` among them, so nothing below could have failed. That is "
              f"a workflow with no actions in it, or an extractor that stopped "
              f"finding them; from here they read the same.", file=sys.stderr)
        return 1

    for entry in findings:
        print(f"action-pins: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} unpinned reference(s) of {checked} checked. "
              f"An action runs in a job holding the repository token, so a "
              f"mutable ref is third-party code that can change under this "
              f"repository without a commit here.", file=sys.stderr)
        return 1
    print(f"action-pins: {checked} `uses:` reference(s) across "
          f"{len(files)} workflow(s), every one pinned to an immutable revision")
    return 0


if __name__ == "__main__":
    sys.exit(main())
