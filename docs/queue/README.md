# The backlog

One file per item, `QN.md`, each carrying its own priority in a `rank` key.
There is no table and no counter: an item owns a file, so two sessions working
different items never touch the same path.

**A directory listing is not the backlog.** It sorts `Q1, Q10, Q11, Q2`, which
is neither priority nor number. Render the real order:

```bash
python3 scripts/queue.py render
```

`--all` includes deferred items, `--format table` emits Markdown, and
`--label open-question` lists the items that end in a decision rather than a
next step.

**The rendered index is never committed.** A tracked index would be the one
file every completing session has to edit, which is the contention this layout
exists to remove.

## Filing an item

**Check the item against current `origin/main` first.** A branch cut before a
fix merged still shows the defect, and `gh pr list` sees only the fix that is
still open:

```bash
git fetch origin main
git log --oneline HEAD..origin/main    # any output: re-read the code on main
```

```bash
./scripts/alloc-queue-id.sh 'The item title'      # claims the id on the remote
python3 scripts/queue.py rank --head              # or --tail, --after, --before
```

Then write `docs/queue/QN.md` with the frontmatter below and run
`python3 scripts/queue.py lint`. Never hand-type a rank.

```yaml
---
id: Q42
rank: a0
labels:
    - tests
status: ready          # ready | blocked | deferred
size: S                # S = one session/PR · M = 2–3 sessions · L = a big one
---

# The title, 72 characters at most

The body, as prose. No length cap — the index summarises it and this page
carries the whole thing.
```

Labels in use: `security` `tests` `docs` `infra` `bug` `hook` `rules`
`release`. Add `open-question` to an item that ends in a decision rather than a
next step, and drop it in the same edit that writes the answer in.

A blocked item's body opens with what it waits on — `Blocked by [Q3](Q3.md)`
where the blocker is an item, prose where it is not. A deferred item opens with
its revive trigger: `**Demand:**`, `**Event:**` or `**Decision:**`.

## Where this backlog came from

Every item traces to [`../design/`](../design/), which is the whole project so
far — there is no code yet. `Q1` and `Q2` are measurements the design depends on
and nobody has taken; take those before planning against anything downstream of
them.

## The rest of the process

Picking, completing, deferring and grooming live in the `session-backlog` skill.
Completing an item is `git rm docs/queue/QN.md` in its own commit — git history
is the archive.
