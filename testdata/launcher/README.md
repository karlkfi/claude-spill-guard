# Launcher fixtures

One file, and it is a launcher that **fails**. Nothing here is ever copied back
into `hooks/`.

## `lf-uniform-failing.cmd`

`hooks/run-spill-guard.cmd` as it stood at `793abbe`, flattened to uniform LF
and with a parenthesized block spliced into the `PATH` route. 7,214 bytes,
sha256 `d28a64b3b35a5f42fd60f6e2da74517114ffc267f83b0b93357fecfe32b93729`.

It is the exact artifact the four-arm measurement of 2026-08-25 drove on a
`windows-latest` runner, where cmd.exe lost its file position across the block,
the `goto` after it died with `The system cannot find the batch label
specified`, and the launcher exited 1 with empty stdout — not a deny, so the
tool call would have run unscanned.

`launcher-mutation-control`'s LF step copies it over the launcher and requires
`scripts/check-launcher.py` to catch it. That is the whole of what the control
asserts: **the gate catches a launcher known to fail on Windows.** It has never
asserted that the launcher currently in `hooks/` is one byte-layout away from
failing — that is `line_endings`' job, and it does not need a runtime symptom.

## Why a fixture and not a mutation

The step used to reconstruct this file by patching whichever launcher was in
the tree. That worked while the launcher was the one it had been measured
against, and stopped the moment anything else changed the file. Measured
2026-08-31 across three heads: shortening four deny strings moved the
reconstruction 610 bytes off, the byte-position mechanism stopped landing
mid-label, and cmd.exe went on denying correctly — so `line_endings` reddened,
the behavioural grep found nothing, and the step failed reporting *the gate
failed for the wrong reason*.

Padding the block to raise the per-line drift made it worse rather than better,
because it moved the file further from 7,214 bytes rather than nearer.

The file is checked in so the control stops depending on the launcher's bytes
at all, and the step asserts the sha256 above before driving it — a fixture
whose hash is unchecked can drift silently in exactly the way this one did.

`-text` in [`.gitattributes`](../../.gitattributes) keeps git from normalising
the line endings, since uniform LF is the property under test.

Regenerating it, should the measurement ever be re-taken: read the launcher
through universal newlines, apply the `straight` → `block` substitution the
step carries, and write the bytes. Anything that changes the hash needs a new
measurement on a Windows runner, not a new hash.
