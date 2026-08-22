# `scripts/`

The gate scripts `.github/workflows/tests.yml` runs, plus the backlog tooling.
Most of these are this repo's own. Two are copies, and this page is the only
thing in the tree that says so.

## Vendored from the skills repo

[`queue.py`](queue.py) and [`alloc-queue-id.sh`](alloc-queue-id.sh) are copied
out of `karlkfi/claude-skills` and run here as ordinary repo tooling. Both are
byte-identical to the commit they name below.

| Here | Upstream path | Taken from | sha256 |
|---|---|---|---|
| [`queue.py`](queue.py) | `session-backlog/scripts/queue.py` | `a055c5e`, 2026-08-21 | `c514771d81bba5ba` |
| [`alloc-queue-id.sh`](alloc-queue-id.sh) | `session-backlog/scripts/alloc-queue-id.sh` | `e52e962`, 2026-08-16 | `c6bf6edd06d8fc0c` |

The digests are the first 16 hex characters of `shasum -a 256`, which
reproduces them in one command:

```bash
shasum -a 256 scripts/queue.py scripts/alloc-queue-id.sh
```

**Do not edit either file in place.** A fix written here reaches no other repo
running the same tooling, and the next re-vendor discards it silently, because
a re-vendor is an overwrite rather than a merge. Send the change upstream,
then re-vendor and move the row above to the new commit — which puts the
digest change in the same diff, where a reviewer sees it.

Re-vendoring is a copy and a digest:

```bash
cp ~/workspace/claude-skills/session-backlog/scripts/queue.py scripts/queue.py
shasum -a 256 scripts/queue.py
```

### Why the record is here and not in the file itself

`queue.py` is copied verbatim into whatever repo takes the skill next, so every
line in it lands in someone else's repository as a byproduct. Upstream settled
that in `effd161` (2026-08-21) by cutting the three places the file named
another organization's repository as the source of its rank algebra — one of
them the `rank --help` description, which printed that credit to whoever ran
`python3 scripts/queue.py rank --help` here. A record kept outside the file
does not travel, so it can name a source without imposing it downstream.

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
