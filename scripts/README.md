# `scripts/`

The gate scripts CI runs, plus the backlog tooling.
Most of these are this repo's own. Two are copies, and this page is where the
tree records that.

## Modes, and what the executable bit means here

Seventeen Python files here are this repo's own, and sixteen of them are entry
points: a `#!/usr/bin/env python3` line, a `main()`, an `if __name__ ==
"__main__"` block, and mode `755`.
[`workflow_model.py`](workflow_model.py) is the one that is not — nothing runs
it, [`check-action-pins.py`](check-action-pins.py) and [`gates.py`](gates.py)
import it — so it is tracked at `644` and carries no shebang.

None of this reaches `vendor/`, which keeps whatever mode upstream shipped.

The rule is that a file advertises exactly the way it can be run. A shebang on a
file at `644` names an interpreter the mode refuses, and the bit on a file
nothing executes invites a reading that does not hold.

**No gate asserts any of this, on purpose.** None of the seventeen is invoked by
path: the sixteen entry points run as `$(PYTHON) scripts/x.py` from the
Makefile and `python3 scripts/x.py` from the workflow, and the library is
imported by an interpreter already running a different file. So a mode that
drifts breaks nothing. That is the whole difference from [`.githooks/`](../.githooks), where
`hooks-check` fails until every tracked hook is executable because git skips
one that is not without saying so, and from
[`run-spill-guard.cmd`](../hooks/run-spill-guard.cmd), whose index mode the
`launcher` gate asserts because Claude Code invokes it directly and a launcher
at `644` never fires once.

Until Q56 the split tracked nothing but the order the files were added — eight
at `755`, five at `644`, every one of them with a shebang. Its row is gone, so
this names it rather than linking it.

**The counts above are hand-kept and nothing re-reads them.** Measured
2026-08-31 at `793abbe`, before Q12 added `check-install-scripts.py`, they said
thirteen and twelve against a real fifteen and fourteen — two behind, for
however long. [Q98](../docs/queue/Q98.md) is the row. The paragraph above
argues that the *modes* are ungated on purpose, and that argument does not
reach the counts.

## Vendored from the skills repo

Everything under `vendor/` is somebody else's file, grouped by where it came
from. `vendor/claude-skills/` holds two, copied out of `karlkfi/claude-skills`
and run here as ordinary repo tooling. Each is byte-identical to its upstream
file at the commit named below.

| Here | Upstream path | Taken from | sha256 |
|---|---|---|---|
| [`queue.py`](vendor/claude-skills/queue.py) | `session-backlog/scripts/queue.py` | `c0a239b`, 2026-08-22 | `b1a0345d7efff9a9` |
| [`alloc-queue-id.sh`](vendor/claude-skills/alloc-queue-id.sh) | `session-backlog/scripts/alloc-queue-id.sh` | `e52e962`, 2026-08-16 | `c6bf6edd06d8fc0c` |

The digests are the first 16 hex characters of `shasum -a 256`, which
reproduces them in one command:

```bash
shasum -a 256 scripts/vendor/claude-skills/*
```

**Do not edit either file in place.** A fix written here reaches no other repo
running the same tooling, and the next re-vendor discards it silently, because
a re-vendor is an overwrite rather than a merge. Send the change upstream,
then re-vendor and move the row above to the new commit — which puts the
digest change in the same diff, where a reviewer sees it.

Re-vendoring is a copy and a digest:

```bash
cp <skills-checkout>/session-backlog/scripts/queue.py scripts/vendor/claude-skills/queue.py
shasum -a 256 scripts/vendor/claude-skills/queue.py
```

### The table above is what `make vendor` reads

[`check-vendor.py`](check-vendor.py) hashes every vendored file and compares it
to the row here, so a copy edited in place goes red and the message names it.
Declaring a fork is still possible and no longer silent: it moves a digest in
the same diff a reviewer reads.

**The files it checks come from the tree, not from this table.** Everything git
tracks under `vendor/` is in scope by construction, and a file with no row is a
failure rather than an omission nobody sees — which is the property a manifest
cannot have, since a manifest only checks what it already lists. A row that
outlives its file fails the same way, from the other side.

The gate asserts nothing about forgery. Anyone who can edit a vendored file can
edit the row above it, and 16 hex characters would not stop them if they could
not. What it catches is the honest edit: a fix typed into the copy, where it
helps this repo and no other, until the next `cp` takes it away.

### Why the record is here and not in the file itself

`queue.py` is copied verbatim into whatever repo takes the skill next, so every
line in it lands in someone else's repository as a byproduct. Upstream settled
that in `effd161` (2026-08-21) by cutting the three places the file named
another organization's repository as the source of its rank algebra — one of
them the `rank --help` description, which printed that credit to whoever ran
`python3 scripts/vendor/claude-skills/queue.py rank --help` here. A record
kept outside the file does not travel, so it can name a source without
imposing it downstream.

That cuts both ways: this page is invisible to anyone reading `queue.py`
alone.

### What is not vendored with it

`rank-vectors.tsv` sits beside `queue.py` in the skill and was not copied.
Both the module docstring and the block comment over `integer_length` point at
it as the contract holding two implementations of the rank algebra to one
scheme, so those two pointers resolve to nothing in this tree. Read the file
in the skill, or leave `rank_between` alone.

### Why nothing checks whether upstream has moved

`karlkfi/claude-skills` is private, so a CI gate that fetched it would need a
token this repo does not carry, and a gate whose oracle is the network fails
when a third party is down. Comparing against a local clone would key the gate
to one workstation's layout. So an upstream fix reaches this tree only when
somebody looks.

The cost of nobody looking is measured rather than hypothetical. This repo
vendored `queue.py` at upstream `f969655` on 2026-08-21 06:41 PDT. Upstream's
next commit, 62 minutes later, was `effd161` above; a second, `a055c5e`, took
this repo's own lint-message fix back upstream that afternoon. `effd161` then
sat unpulled for 22 hours and `a055c5e` for 14, and nothing in the tree said
`queue.py` was a copy, so nothing made either gap visible. Q29 closed it by
hand.
