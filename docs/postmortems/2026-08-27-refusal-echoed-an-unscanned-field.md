# A refusal echoed an unscanned field, and the fix was orphaned by a squash

**2026-08-27.** A refusal path in `internal/hook` quoted a caller-supplied
string back into a reason that reaches the API, and the one-line fix for it
missed the merge it was written against by a single commit. The defect was
live on `main` for about seventeen minutes.

Nothing shipped: this repository has no release, and
[`docs/releases/README.md`](../releases/README.md) says the first one waits on
a binary and a hook that fires. The postmortem is here for the two mechanisms,
which will recur.

## What the defect was

The `Read` arm refuses a `file_path` it cannot resolve to a file, which is
correct and is the fail-closed rule working. The refusal named the offending
path in its reason:

```go
return nil, fmt.Errorf("the Read call names a relative file_path, "+
    "which this cannot resolve to the file the tool would open: %q",
    *in.FilePath)
```

`file_path` is a caller-supplied string. When it cannot be resolved, **nothing
has been opened and nothing has been scanned**, so the value being quoted is
arbitrary unexamined input — and stderr reaches the API. A `file_path` whose
text happens to carry credential-shaped bytes was echoed back verbatim.

The repository's own rule is to emit a rule ID, a path, and an offset, and no
fragment. The trap is that `file_path` reads as *the path* in that sentence,
so quoting it looks like the sanctioned case. It is not, and the distinction is
temporal rather than typed: the rule permits naming a path this binary resolved
and attempted to open. An unresolved one has had nothing happen to it.

The `Bash` arm had already reached the opposite answer for the same reason, and
stopped naming an operand it could not resolve. **One binary, one class of
unresolved token, two answers.** That asymmetry is what made it findable.

The fix removes the interpolation:

```go
return nil, errors.New("the Read call names a relative file_path, " +
    "which this cannot resolve to the file the tool would open")
```

## Timeline

| Time (UTC) | Event |
|---|---|
| — | A reviewer sweeping a package's refusal paths finds the `Read` arm quoting where the `Bash` arm does not. Raised as a note on the pull request under review. |
| — | The author of the sibling pull request reproduces it, fixes it, adds a case, and drives the inversion. |
| 14:52:12 | That sibling's parent merges as a squash. The fix is one commit past what merged, and is orphaned. |
| — | The coordinating session, reasoning that the parent had merged, directs the fix to be filed as a backlog row instead. |
| — | The author refuses, on the measurement, and pushes the fix into its own open pull request. |
| 15:09:00 | That pull request merges. The defect leaves `main`. |

## Contributing factors

**The squash boundary is invisible from a pull request view.** The fix was
written and driven inside a review window and orphaned by a merge that landed
between the drive and the push. Nothing in the interface says *your commit is
one past what merged*; the branch still shows it, and the trunk no longer
reaches it.

**A finding was routed by branch state where the question was trunk state.**
The instruction to file a row rested on "the pull request that would have
carried this has merged" — true, and not the question. Whether the defect was
live on `main` was a separate fact, answerable by building the trunk, and it
was not asked. The two look identical right up until a squash separates them.

**A note carries no re-check.** The finding was correctly identified and then
downgraded, and nothing in the process re-examined a downgrade. It survived
because its author declined the instruction and re-measured, which is a good
outcome reached by an unreliable route.

**The negatives were vacuous, and nothing said so.** With the fix in place,
every refusal in the package returns nothing of the payload — so the assertions
proving that are all negatives, and a later narrowing elsewhere could hollow
them out silently. The suite had one positive case holding them up and no
statement of the dependency.

## What changed

**Mitigative.** The interpolation is gone, with a regression case planting
credential-shaped text inside a `file_path` and asserting the refusal does not
echo it.

**Preventative.** The blinding control: the positive case that proves the
inspection can see a value at all is named, and cross-referenced in both
directions with the negatives that depend on it. Blinding the reason-reader
turns the positive red while the negatives stay green — which is the signal
that the negatives alone prove nothing.

## What we would tell the next reader

**A refusal is an emission.** Every path that declines to do work still writes
a string that leaves the machine, and the fail-closed rule guarantees those
paths are the ones that run when something is unusual. They deserve the same
scrutiny as the success path, and they tend to get less, because refusing feels
like not acting.

**Verify a defect against the trunk, not against the branch it was found in.**
A merge answers where a *change* went and says nothing about where a *defect*
is. Building the trunk answers it directly and costs a minute.

**A row is the wrong home for a fix that is already written and driven.** The
argument for filing — keep the diff scoped — is real, and it is outweighed when
the alternative leaves a live defect on the trunk while the fix sits in a queue.

## Notes on this document

The regression fixture uses synthetic credential-shaped strings generated for
the test corpus. No real credential was involved at any point, and none appears
here or in the repository.
