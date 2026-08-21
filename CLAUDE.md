# Working in this repo

spill-guard is a Claude Code hook that stops secrets and PII from reaching the
API through a session. It is a static Go binary with an empty supply chain.

The design is in [`docs/design/`](docs/design/) and it is not built yet. Read
`docs/design/README.md` before writing code; read
`docs/design/language-choice.md` before re-opening any decision it already
measured.

## Layout

| Path | What it is |
|---|---|
| `docs/design/README.md` | The proposed design. Threat model through CI. |
| `docs/design/language-choice.md` | Why Go, with the measurements. Do not re-litigate. |
| `docs/design/brief.md` | The origin brief, as written. |

Everything under `cmd/`, `internal/`, `rules/`, and `hooks/` is proposed in the
design doc and does not exist.

## Rules that are not negotiable

**Zero third-party runtime dependencies.** `regexp` and `encoding/json` are
stdlib. Test-only dependencies are fine. This is a stated product property, not
a preference: the entire premise is that nothing leaves the machine, and an
empty supply chain is a claim a user can verify in an afternoon. CI enforces it
on the import graph.

**No network capability whatsoever.** No `net`, no `net/http`, no `os/exec`.
Enforced by a job over `go list -deps`, not by review. A telemetry field added
in good faith is the failure mode here, and review does not reliably catch it.

**Fail closed.** The sibling guards fail silent so that a hook on every call
never breaks ordinary work. This one inverts that, because a secret scanner that
fails quietly reports a safety it is not providing. Every internal error blocks
with a reason. `spill-guard selftest` proves the hook is live rather than
installed and inert.

**Never put a raw secret in a struct that outlives the match.** The
predecessor's `Finding` carried `secretValue` beside `matchRedacted`; it was
used only as a dedup key and never printed, and the field's existence was still
a standing hazard. Carry a truncated hash instead. Emit rule ID, path, and
offset — no fragment, not even a redacted one, because stderr reaches the API.

**No in-band bypass tag.** A magic string that disables the scanner is a
prompt-injection surface: any content the model reads can contain it, including
the buffer being scanned. Config and `SPILL_GUARD_OVERRIDE=` in command position
only — places the model cannot write to from inside a scanned file.

**Escape control characters in every emitted string.** C0, DEL, and the bidi
overrides. Paths and rule descriptions both reach a terminal.

**Precision is the product.** The inherited ruleset flagged 27.6% of real files
with zero true positives. Recall regressions get reported; precision
regressions are invisible until the noise has trained everyone to ignore the
tool. Every new rule needs a corpus case proving it stays quiet on clean input,
and the `precision` job pins the false-positive count.

**Do not hand-roll shell parsing.** The Bash operand resolution is a port of
`claude-workspace-guard`'s segmentation layer, kept structurally identical so a
fix there transfers by inspection. Writing quote-state tracking from scratch is
the documented failure mode for this class of tool, and it fails silently in
both directions.

## Measured facts, so nobody re-derives them

From [`docs/design/language-choice.md`](docs/design/language-choice.md):

- **Do not fold rules into one alternation.** 0.5x in Go, 0.7x with Rust's
  `RegexSet`. The DFA state space explodes and the lazy cache thrashes on
  heterogeneous input. Run patterns separately.
- **The prefilter needs word boundaries.** `strings.Contains` finds `sk-` inside
  `disk-containerd-…`, and one bad keyword (`AC`) took the file hit rate from
  1.2% to 18.9%.
- **RE2 has no lookaround and caps bounded repetition at 1000.** Nine inherited
  rules need rewriting; `{1,1024}` becomes `{1,1000}`.
- **Skip binaries.** NUL in the first 8 KiB. One PNG was 55% of the benchmark
  corpus.
- **Never benchmark on a repeated chunk.** It overstated one engine by ~10x.
  Use real heterogeneous files, verify match counts agree before comparing
  times, and measure fixed cost separately — below ~8 KB it dominates.

## Open questions

Four, in `docs/design/README.md` under **Open questions**. Two of them
(`PostToolUse` withholding, and which exit codes Claude Code treats as blocking)
are measurements nobody has taken. Take them; do not read them out of the docs.
The predecessor failed open on Node 18 for exactly that reason.

## Prose

Docs here are read by people deciding whether to trust the tool. Draft with the
`deslop` writing system and `karl-writing-style`, not as a cleanup pass
afterwards. Exact numbers over adjectives — they are the cheapest credibility
signal available and this repo has plenty of them.
