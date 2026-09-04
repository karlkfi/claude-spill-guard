# Merge posture

What a merge to `main` costs here, declared rather than derived. A dispatching
session reads it to route each pull request to a reviewer; nothing else consumes
it. Three keys:

    reaches:   opt-in-channel
    gate:      tag
    reviewers: solo

## reaches — opt-in-channel

`.claude-plugin/marketplace.json` names a GitHub source with no ref pin, so an
install resolves whatever `main` holds at that moment: a merge propagates
without a tag, and CI cannot see that it does. Two things bound how far. Adding
the marketplace is an explicit step, so nobody receives this by default; and
plugin auto-update does not work at all — `autoUpdate: true` is persisted and
nothing consumes it (`anthropics/claude-code#73673`) — so an existing install
stays where it was installed. A fresh install is the whole of the channel.

The signed binaries are a separate path and are tag-only: `install/install.sh`
and `install.ps1` fetch release assets, and `.goreleaser.yaml` runs on a tag.

## gate — tag

The expensive human read belongs at the release, where the notes get written and
the artifacts get verified. `docs/development/release-process.md` owns that step.
Agents review at merge; a pull request carrying a feature, an interface change,
an architectural choice or a change of scope still surfaces to the maintainer,
because that is context a person needs in their head rather than a defect an
agent might catch.

## reviewers — solo

One maintainer. `main` is unprotected and there is no CODEOWNERS file, so no
mechanism holds a merge open for a second reader. Read the corroborating author
count carefully: every agent session on this machine authenticates as `karlkfi`,
so "one distinct author" over a fortnight is one *account*, and it is the absence
of protection and of CODEOWNERS that carries the key.

`solo` is not permission for an agent to merge. It records that no colleague's
review is being spent when one does not happen — the merge decision itself stays
with the maintainer.

## Re-taking the readings

    python3 ~/.claude/skills/session-orchestrator/scripts/merge-posture.py \
      karlkfi/claude-spill-guard

It reports branch protection, CODEOWNERS, distinct authors, merge velocity, and
which workflows publish on a merge as against on a tag, then checks them against
this file. Exit 1 is a disagreement or a missing declaration. It sees CI and
nothing else, so its silence about what a merge reaches is not agreement — that
key is the one this file exists to supply.
