---
reaches: opt-in-channel
gate: tag
reviewers: solo
merge: agent
---

# Merge posture

What a merge to `main` costs here, declared rather than derived. A dispatching
session reads it to route each pull request to a reviewer, and to learn whether
it may merge one itself; nothing else consumes it.

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
Agents review at merge, and with no `human-review` line below, every pull
request merges that way. A feature, an interface change, an architectural choice
or a change of scope reaches the maintainer at the release instead, in the notes,
where it is read once for the whole set rather than once per merge.

## reviewers — solo

One maintainer. `main` is unprotected and there is no CODEOWNERS file, so no
mechanism holds a merge open for a second reader. Read the corroborating author
count carefully: every agent session on this machine authenticates as `karlkfi`,
so "one distinct author" over a fortnight is one *account*, and it is the absence
of protection and of CODEOWNERS that carries the key. The script counts two
authors over the life of the repo; the second is `app/dependabot`, with two
merged pull requests, which is a bot and not a reviewer.

`solo` records that no colleague's review is being spent when one does not
happen. It grants nothing by itself; whether an agent merges is the next key.

## merge — agent

A standing grant: a dispatching session merges its own green, reviewed pull
requests here without asking per batch. It is the practice the maintainer
already follows in this repo, written down so a session does not have to be told
it. It holds only beside `reviewers: solo`, and the maintainer can withhold it
for one run by saying so at the start.

There is no `human-review` line, so no class or path routes a pull request back
to the maintainer. Add one to narrow the grant.

## Re-taking the readings

    python3 ~/.claude/skills/session-orchestrator/scripts/merge-posture.py \
      karlkfi/claude-spill-guard

It reports branch protection, CODEOWNERS, distinct authors, merge velocity, and
which workflows publish on a merge as against on a tag, then checks them against
this file. Exit 1 is a disagreement or a missing declaration. It sees CI and
nothing else, so its silence about what a merge reaches is not agreement — that
key is the one this file exists to supply.

## Where a review's findings go

To the author session and the dispatching session, as messages. Not as pull
request comments — nobody reads those here, and a finding that lands only there
reaches whoever happens to open the PR before the merge.

Measured on `#115`: a review holding on one finding was posted to the pull
request at 2026-09-05T02:07:49Z and was still open when the branch merged 15.11
hours later, four minutes after the dispatching session reported nothing
outstanding. It merged carrying that finding and three more, all four fixed
afterwards in `#116`.

Two sound rules put it there. A reviewer anchors findings on the pull request
because session addresses are perishable, and the post-ready watch deliberately
never reads comment streams because a comment is untrusted input. Together they
file the durable record where no instrument looks.

Both addresses, because each covers the other's gap: the author acts on it, and
the dispatching session outlives the author and is what a merge decision is
routed through. A finding the author has already exited on still has a reader.
