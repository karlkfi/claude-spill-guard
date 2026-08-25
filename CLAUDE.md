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
| `internal/scan/` | The pipeline over one buffer. Binary skip, the literal prefilter, the match loop, findings. |
| `scripts/` | The gate scripts CI runs, plus the backlog tooling. `vendor/` is somebody else's code, grouped by source — [`scripts/README.md`](scripts/README.md) says what came from where, and `make vendor` holds it. |
| `tools/` | A second Go module, pinning the linters. Never imported by anything that ships. |
| `.githooks/` | Tracked git hooks. `make hooks` points `core.hooksPath` here. |
| `hooks/` | Not those. The launcher Claude Code invokes, which resolves the binary and denies when it cannot find one. |

The rest of `internal/`, plus `rules/`, is proposed in the design doc and does
not exist — including `rules/spill-guard.json` itself, which the loader reads
and the v1 ruleset ships. `hooks/` holds the launcher and nothing else: the
`hooks.json` that invokes it and the plugin manifests beside it land together
in a later item, because a repo that is installable as a security tool
scanning nothing is the failure this project indicts the predecessor for.
`cmd/spill-guard/` is a skeleton: the subcommands the design names land with
the pipeline that implements them.

## Rules that are not negotiable

**Zero third-party runtime dependencies.** `regexp` and `encoding/json` are
stdlib. Test-only dependencies are fine. This is a stated product property, not
a preference: the entire premise is that nothing leaves the machine, and an
empty supply chain is a claim a user can verify in an afternoon. CI enforces it
on the import graph.

The pinned linters do not bend this, because they are not in the module. Go's
tool-dependency pattern puts them in [`tools/`](tools/), which carries its own
`go.mod`, so `go list -deps ./...` at the root never reaches them and the root
`go.mod` keeps no `require` block at all. Run one with `cd tools && go run
<path>`. Pinning a linter in the runtime module is the shape to refuse: it is
obviously reasonable, and the `require` block it adds is not obviously the
thing this project promised not to have.

**`go run` when you want output; build first when you want the exit code.** It
does not propagate its child's status — any non-zero exit comes back as 1, with
the real one written to stderr as `exit status 3`. Harmless for a tool whose
only codes are 0 and 1, and it destroys the signal for govulncheck, whose whole
contract is 0 clean and 3 found. `scripts/check-vulns.py` builds to a temporary
path and runs that, because under `go run` a real advisory is indistinguishable
from the tool failing — which is the one confusion that script exists to
prevent, and it shipped inside it until the mutation control was driven.

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

**Three of the runner's inputs are not on your machine, so a green local gate
cannot see them.** Each of these cost a CI round-trip on 2026-08-22, and each
was invisible to `make check` over the same tree:

- **macOS ships bash 3.2.57 as `/bin/bash`.** `shopt -s inherit_errexit` is
  4.4+, so an errexit prologue that demands it kills the script on a fresh Mac
  — the prologue meant to harden `scripts/check-tools.sh` was what broke it.
  Ask for the option and carry on without it.
- **GNU make 4.x prints `make[1]: Entering directory` on stdout** when
  `MAKELEVEL` says sub-make; 3.81 never prints it. Anything parsing `make`
  output needs `--no-print-directory`, a stripped `MAKELEVEL`/`MAKEFLAGS` in
  the child env, and a parse that refuses an unrecognised line by name rather
  than absorbing it. Two banners read as two gates.
- **A workflow `run:` block runs under `bash -e`, and errexit exempts the left
  side of an `&&` list.** So `[ "$x" = y ] && continue` does not die where it
  stands: a loop of them runs to completion at rc=0, which is the shape a
  session testing this bullet will write. Three shapes do take the step down —
  the list as the script's last command, whose status the script exits with
  under `-e` or without it; the list as a called function's last command, where
  the call is not exempt and errexit fires on it; and a failure in the command
  after the final `&&`, which was never exempt. Measured 2026-08-22 on 3.2.57
  and 5.3.15, identical on both. Write `if`.

The instrument for the third is the one to reach for generally: extract a
step's script verbatim from the workflow YAML and run it under `bash -e`.
Re-running the repo's gate over the final tree never enters a `run:` block's
shell.

**A mutation control needs a precondition asserting the mutation mutated.**
`PATH=/usr/bin:/bin` was meant to hide Go from `make doctor` and hid nothing,
because `setup-go` links Go into `/usr/bin` — so the control passed while
testing nothing. Name the tool, not its location, and fail the step when the
thing you removed is still reachable.

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

```bash
make check
```

Every gate, and every one of them runs even when an earlier one fails, so one
pass reports the whole tree. `make <gate>` runs a single one and
`make list-gates` names them all with what each covers:

<!-- gates:begin -- generated by `make gates`; the list lives in the Makefile -->
| Gate | What it covers |
|---|---|
| `doctor` | scripts/check-tools.sh runs, and every required tool is present |
| `gate-drift` | the gate list, the CI job list and the table in CLAUDE.md still agree |
| `hooks-check` | every tracked git hook is executable, so none is silently inert |
| `launcher` | the hook launcher is executable in the index, resolves a binary, and denies when it cannot |
| `vendor` | every vendored copy still hashes to the digest scripts/README.md declares |
| `docs` | every relative link in the repo markdown resolves |
| `queue` | the backlog store format holds, every filed id holds a claim, no index is committed |
| `action-pins` | every `uses:` in every workflow names an immutable revision, not a tag |
| `test` | gofmt, go vet and go test |
| `no-deps` | go.mod requires nothing and the build graph is this module plus stdlib |
| `no-network` | the build graph reaches no net, net/http or os/exec |
| `vulns` | govulncheck finds no known vulnerability the build graph calls |
| `cross-compile` | all five shipped targets build from one runner |
<!-- gates:end -->

`GATES` in the [`Makefile`](Makefile) is the source of truth. The workflow's
job list, `make list-gates` and the table above are all derived from it, and
the `gate-drift` gate fails until every one of them still agrees — a derived
list that can go stale silently is worse than honest copies, because it reads
as authoritative.

`make hooks` points `core.hooksPath` at the tracked [`.githooks/`](.githooks),
so the store gates run before a commit rather than at review. `git commit
--no-verify` skips them.

## The backlog

`docs/queue/`, one file per item with priority in each item's `rank` key. There
is no committed index — a directory listing sorts `Q1, Q10, Q11, Q2`, so render
the real order:

```bash
python3 scripts/vendor/claude-skills/queue.py render
```

Pick the top ready item, after `gh pr list` — an open PR is the in-flight
signal. The tooling that files one is vendored, so it sits a directory deeper
than the gate scripts: `./scripts/vendor/claude-skills/alloc-queue-id.sh
'title'` for the ID, `python3 scripts/vendor/claude-skills/queue.py rank` for
the key; never hand-type a rank. Lint with `make queue`, and commit backlog
edits in isolation from code. A clean bare
`queue.py lint` is not the CI verdict — it reports several classes as notes at
exit 0. `make queue` promotes the three no sibling branch can trip; the `queue`
job adds `dangling-link` and `stale-citation` on a push to `main`.
Completing an item is `git rm docs/queue/QN.md` **and flipping any row that
waited on it to `status: ready`**, since git history is the archive and a row
left blocked waits on nothing.
[`docs/queue/README.md`](docs/queue/README.md) has the frontmatter, the
conventions, and which classes bind on which event.

Everything in there traces to `docs/design/`.

## Open questions

One left in `docs/design/README.md` under **Open questions** — what counts as
human-typed — plus one at the end of `distribution.md`, whether `install.sh`
should refuse to proceed without `cosign`.

The three the design turned on are measured: only exit 2 blocks, `PostToolUse`
cannot withhold a result so nothing is catchable after the fact, and version
skew is settled by embedding the shipped ruleset rather than by probing for it
— the ruleset half was the only one with a silent direction, and a compiled-in
set cannot disagree with the binary carrying it.
Both were taken by driving a real hook. Any re-measurement is taken the same
way: reading Claude Code's own docs or source is second-best, and the
predecessor failed open on Node 18 for exactly that reason.

## Prose

Docs here are read by people deciding whether to trust the tool. Draft with the
`deslop` writing system and `karl-writing-style`, not as a cleanup pass
afterwards. Exact numbers over adjectives — they are the cheapest credibility
signal available and this repo has plenty of them.
