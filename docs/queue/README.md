# The backlog

One file per item, `QN.md`, each carrying its own priority in a `rank` key.
There is no table and no counter: an item owns a file, so two sessions working
different items never touch the same path.

**A directory listing is not the backlog.** It sorts `Q1, Q10, Q11, Q2`, which
is neither priority nor number. Render the real order:

```bash
python3 scripts/vendor/claude-skills/queue.py render
```

`--all` includes deferred items, `--format table` emits Markdown, and
`--label open-question` lists the items that end in a decision rather than a
next step.

**The rendered index is never committed.** A tracked index would be the one
file every completing session has to edit, which is the contention this layout
exists to remove. `scripts/check-queue-index.py` holds that in CI: it fails a
tracked file carrying `render` output, or naming half the store's items in any
form. An index names every item and a page of prose names a handful, so the two
never meet — the script's header has the measurement. One in your working tree
is the sanctioned workflow and does not fail; the check reads what is tracked.

## Filing an item

**Check the item against current `origin/main` first.** A branch cut before a
fix merged still shows the defect, and `gh pr list` sees only the fix that is
still open:

```bash
git fetch origin main
git log --oneline HEAD..origin/main    # any output: re-read the code on main
```

```bash
./scripts/vendor/claude-skills/alloc-queue-id.sh 'The item title'  # claims the id
python3 scripts/vendor/claude-skills/queue.py rank --head          # or --tail/--after/--before
```

Then write `docs/queue/QN.md` with the frontmatter below and run
`python3 scripts/vendor/claude-skills/queue.py lint`. Never hand-type a rank.

`lint` reports at exit 0 what the files alone cannot settle, so a clean local
run is not the whole gate. CI promotes five of those notes with `--strict`.
`blocked-opener`, `deferred-trigger`, `empty-store` and `stale-citation` bind
on every event. `dangling-link` is a note on a pull request and a failure on
`main`, because a row may link an item a sibling PR is still filing — correct
in the merged set, red on the branch that carries the link — and only the
merged tree can tell that from a typo. `make queue MERGED=true` runs the
trunk's set locally.

`stale-citation` binds on a branch, and what it catches there is a citation
your own diff invalidated — correct when you wrote it, moved by an edit in the
same PR. A citation a *sibling* moves is a different matter: your branch stays
green, because the pointer is still correct against the tree in front of you,
and `main` reddens on the merge. No event split reaches that, which is what
`MERGED=true` on the trunk is for.

One case costs you something, and it is wider than a missing file. Any pointer
that describes the merged tree rather than the branch in front of you reddens
here — a file another branch is adding, a fragment it adds, or a line number
that is only right once it lands — with no repair available until it does.
Mark such a pointer `exhibit:`, or write it afterwards. `make queue` is also
the pre-commit hook, so it blocks the commit rather than only a CI run.

All four of the class's checks behave that way, because `lint` sees one tree,
so promoting some and not others would not help. [Q67](Q67.md) is the open
question about a marker that expires once the sibling lands.

How near a fragment must be is a separate setting again — `--citation-window`,
ten lines by default — which promotion does not reach, so a clean run means no
citation has drifted more than the window rather than that citations are exact.

CI also runs `queue.py claims --strict`, which fails an id holding no
reservation on the remote at the commit that files the row, rather than at the
rebase that collides with it.

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

A blocked item's body opens with what it waits on — a link to the blocking item
where the blocker is one, prose where it is not:

```markdown
Blocked by [Q7](Q7.md). The rules have to exist before a corpus gate means
anything.
```

That example is fenced because the link checker skips fenced blocks and inline
code spans alike. As a live link it would dangle the day Q7 is completed.

**When the blocker ships, the PR that completes it flips `status` to `ready`
here and drops the line.** Doing the prose half and leaving `status: blocked`
puts a row in the store waiting on nothing, and it was invisible to every gate
until `blocked-opener` and `dangling-link` started binding.

A deferred item opens with its revive trigger: `**Demand:**`, `**Event:**` or
`**Decision:**`.

## Where this backlog came from

Every item traces to [`../design/`](../design/), which is where the project was
argued out before any of it was written. `Q1` and `Q2` are measurements the
design depends on and nobody has taken; take those before planning against
anything downstream of them.

## The rest of the process

Picking, completing, deferring and grooming live in the `session-backlog` skill.
Completing an item is `git rm docs/queue/QN.md` in its own commit — git history
is the archive, with one exception worth knowing before relying on it.

**Filing and completing a row in the same pull request is allowed, and under a
squash it forfeits that archive.** It is the right shape when the item did not
exist when the work started: a row live for the length of one pull request is a
row nobody would ever pick up. What it costs depends on how the pull request
lands, and nothing here fixes that — `allow_merge_commit` is `false`, but
`allow_squash_merge` and `allow_rebase_merge` are both `true`, there are no
rulesets, and `main` is unprotected. The practice has already changed once: #1
to #6 landed as merge commits, and the 47 that have merged since, #7 through
#54, each landed as one single-parent commit on `main`.

Under that squash an add in one commit and a delete in another cancel, and the
row reaches `main` in no form. Measured on #50, which filed and completed Q82
while filing Q83:

```
git log origin/main -- docs/queue/Q82.md   # nothing
git log origin/main -- docs/queue/Q83.md   # 7ed48cb ... (#50)
```

A rebase merge would keep both commits and the row's prose with them, so the
loss is a property of the strategy rather than of the shape — and since nothing
guarantees the strategy, write as though the squash applies. Put anything a
later reader needs — the measurement, the reason, the caveat — in the tree or
in a row that outlives the merge, not in the body. [Q93](Q93.md) is the item
covering that boundary generally.
