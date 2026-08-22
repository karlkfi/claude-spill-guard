# Working in this repo

spill-guard is a Claude Code hook that stops secrets and PII from reaching the
API through a session. It is a static Go binary with an empty supply chain.

The design is in [`docs/design/`](docs/design/) and the scanner is not built
yet. Read `docs/design/README.md` before writing code; read
`docs/design/language-choice.md` before re-opening any decision it already
measured.

## Layout

| Path | What it is |
|---|---|
| `docs/design/README.md` | The proposed design. Threat model through CI. |
| `docs/design/distribution.md` | The launcher, signed release assets, install channels. |
| `docs/design/language-choice.md` | Why Go, with the measurements. Do not re-litigate. |
| `docs/design/brief.md` | The origin brief, as written. |
| `cmd/spill-guard/` | The entry point. `version` and nothing else so far. |
| `internal/validate/` | The six validators. Precision lives here, not in the regex. |
| `internal/rules/` | The loader. Decode, merge the project's overrides, compile, and fail closed on anything it cannot settle. |
| `scripts/` | The gate scripts CI runs, plus the backlog tooling. |

The rest of `internal/`, plus `rules/` and `hooks/`, is proposed in the design
doc and does not exist — including `rules/spill-guard.json` itself, which the
loader reads and the v1 ruleset ships. `cmd/spill-guard/` is a skeleton: the
subcommands the design names land with the pipeline that implements them.

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

**The launcher denies when the binary is missing.** `hooks.json` never invokes
`spill-guard` directly: an absent binary exits 127, and only exit 2 blocks, so
the call goes through with nothing in the transcript. Empty stdout is not what
makes it pass — a hook exiting 2 with empty stdout still blocks — the exit code
is. The launcher denies with a `deny` object on stdout, which blocks whatever it
exits with. Anything `hooks.json` invokes ships executable, with the mode set in
the git index via `git update-index --chmod=+x`. Both of those are shipped bugs
from sibling repos, not hypotheticals. The measured table is in
[`docs/design/README.md`](docs/design/README.md#the-exit-code-contract-measured).

## Running the gates

There is no `make check` yet. Until there is, the gates are the scripts
`.github/workflows/tests.yml` runs — read the job list rather than keeping a
copy of it here, which is the drift this repo has an item open about.

## The backlog

`docs/queue/`, one file per item with priority in each item's `rank` key. There
is no committed index — a directory listing sorts `Q1, Q10, Q11, Q2`, so render
the real order:

```bash
python3 scripts/queue.py render
```

Pick the top ready item, after `gh pr list` — an open PR is the in-flight
signal. File one with `./scripts/alloc-queue-id.sh 'title'` for the ID and
`python3 scripts/queue.py rank` for the key; never hand-type a rank. Lint with
`python3 scripts/queue.py lint`, and commit backlog edits in isolation from
code. A clean local lint is not the CI verdict — `lint` reports several classes
as notes at exit 0 and the `queue` job promotes five of them with `--strict`.
Completing an item is `git rm docs/queue/QN.md` **and flipping any row that
waited on it to `status: ready`**, since git history is the archive and a row
left blocked waits on nothing.
[`docs/queue/README.md`](docs/queue/README.md) has the frontmatter, the
conventions, and which classes bind on which event.

Everything in there traces to `docs/design/`.

## Open questions

One left in `docs/design/README.md` under **Open questions** — what counts as
human-typed — plus two smaller ones at the end of `distribution.md`.

The two the design turned on are measured: only exit 2 blocks, and
`PostToolUse` cannot withhold a result, so nothing is catchable after the fact.
Both were taken by driving a real hook. Any re-measurement is taken the same
way: reading Claude Code's own docs or source is second-best, and the
predecessor failed open on Node 18 for exactly that reason.

## Prose

Docs here are read by people deciding whether to trust the tool. Draft with the
`deslop` writing system and `karl-writing-style`, not as a cleanup pass
afterwards. Exact numbers over adjectives — they are the cheapest credibility
signal available and this repo has plenty of them.
