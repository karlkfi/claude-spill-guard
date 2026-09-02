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
| `docs/development/release-process.md` | Cutting a release: what a person does, and what the tag does. |
| `cmd/spill-guard/` | The entry point. `hook`, `selftest` and `version`; the rest land with the rows that specify them. |
| `internal/validate/` | The eight validators. Precision lives here, not in the regex. |
| `internal/rules/` | The loader. Decode, merge the project's overrides, compile, and fail closed on anything it cannot settle. |
| `internal/hook/` | The entry Claude Code invokes. Decode a payload, choose what of the call is scannable — including the `@` tokens a prompt carries — encode a verdict. Where fail-closed holds or does not. |
| `internal/scan/` | The pipeline over one buffer. The BOM decode, the binary skip, the literal prefilter, the match loop, findings — and the reason, when it read nothing. |
| `internal/bash/` | Shell segmentation, ported from `claude-workspace-guard` rather than written. Splits a command string into the simple commands it runs, so a reader's file operands can be found. |
| `internal/readers/` | Which token of a segment is a path. The per-command table, ported from the same upstream; the read/write split is this repo's and is written at each site. |
| `internal/selftest/` | The `selftest` subcommand. Canary payloads through `hook.Run` in-process, an allowing arm per surface, and a report that says what it cannot establish. |
| `internal/testvec/` | The loader for `testdata/corpus/vectors/`. Test-only, linked into no binary, and it takes a `TB` rather than `*testing.T` so nothing outside a test imports `testing`. |
| `rules/` | The shipped ruleset, and [`rules/README.md`](rules/README.md) for what each rule turns on. The JSON is data; `embed.go` beside it is the `go:embed` that compiles it in, which has to live here because the directive reaches only its own directory. |
| `testdata/corpus/` | The precision corpus. `clean/` must produce nothing; `planted/` must produce exactly one finding each. `vectors/` is neither: it is the credential-shaped strings the unit tests read, kept where secret scanning is told not to look. |
| `scripts/` | The gate scripts CI runs, `check-install-scripts.py` which only the release workflow can run, and the backlog tooling. `vendor/` is somebody else's code, grouped by source — [`scripts/README.md`](scripts/README.md) says what came from where, and `make vendor` holds it. |
| `tools/` | A second Go module, pinning the linters. Never imported by anything that ships. |
| `.githooks/` | Tracked git hooks. `make hooks` points `core.hooksPath` here. |
| `hooks/` | Not those. `hooks.json`, the wiring Claude Code reads, and the launcher it names — which resolves the binary and denies when it cannot find one. |
| `.claude-plugin/` | `plugin.json` and `marketplace.json`. The only place a version is written, and the two have to carry the same one. |
| `install/` | `install.sh` and `install.ps1`, the fallback channel. Here so they are reviewable at a versioned URL, and uploaded as release assets so the documented two-step form has something to fetch. |
| `.goreleaser.yaml` | What a tag publishes. Release-time only, and never in the shipped module. |

`internal/hook/` now exists and the binary reaches the pipeline through it, so
`spill-guard hook` scans a payload and blocks. The ruleset it uses is the one
`rules/embed.go` compiles in, which is how the design settles version skew: a
binary and a ruleset that cannot be separated cannot disagree. One of the two
escape hatches the design names is wired — `SPILL_GUARD_OVERRIDE=` on a `Bash`
command, read from an inline assignment prefix and never from the environment,
and it downgrades a block to a confirmation rather than to an allow. The
project ruleset at `.claude/spill-guard.json` is still read by nobody, and Q73
is narrowed to why: it is a file the model can write, so honouring a
disablement in it is a question about a bypass rather than a loader change.

A buffer the pipeline declined to read is now a verdict rather than a field
nobody consumes, and the axis is declaration rather than content: a buffer that
declared an encoding blocks, and one that declared nothing does not, because
that second case the design chose against a measurement. So a UTF-32 mark
blocks, a UTF-16 mark whose *decoded* text holds a NUL blocks, and a NUL in a
buffer nothing declared — an image, an executable, UTF-16 written with no
mark — is allowed.

Allowed is not silent. It writes a `systemMessage` naming the buffer and the
reason, and the call goes through carrying it. That field is the one measured
to reach the *person* rather than the model — a hook's stderr on exit 0 reaches
neither, and plain stdout and `additionalContext` reach only the model. Driven
on both events, and unlike the block encodings it is **not** per event: one
field serves `UserPromptSubmit` and `PreToolUse` alike, arriving as a
`hook_system_message` attachment and a `level: notice` stream event, with the
call still running on both. `verdict.go` has the tables and Q111 has the branch
this does not cover.

**That law has one measured exception and it is a gap rather than a decision.**
`decode` reads two of the three byte-order marks. UTF-8's, `EF BB BF`, is a
declaration it has no arm for, so such a buffer falls through undecoded, its NUL
is read raw, and it is allowed exactly as an image is — driven end to end, a
UTF-8 mark plus a NUL plus an AWS-shaped key exits 0 while the same file
without the NUL denies. It now says so rather than saying nothing, which is a
notice about an unread buffer and not a block on a secret. Do not repair the law by redefining the axis
as whichever declaration this build routes on: that is true by construction,
cannot be falsified by a fourth encoding, and is how this one got through. `blocks` in
[`internal/hook/hook.go`](internal/hook/hook.go) carries the argument, and a
skip reason it has not been taught blocks, which is how the middle case gets
its verdict without a case of its own.

**Two things about that middle case are settled and should not be re-derived.**
It does not turn on frequency: over `~/go/pkg/mod` and this tree, 43 files in
245,397 carry a UTF-16 mark and none decodes to binary — 21 of them organic,
across seven unrelated Go modules, so a mark is not itself a Windows artifact.
But the decode exists for Windows PowerShell 5.1 and nothing here runs `pwsh`,
so that zero measures the platform rather than the population. What the 43 do
settle is the cost: every one is `Scanned`, so none changes verdict, and the
flip is free on the only population this machine can show. What
settles it is that `FF FE 00 00` is both the UTF-32LE mark and a UTF-16LE mark
followed by `U+0000`, so before the split the same UTF-16 buffer blocked or was
allowed depending on where its NUL sat. And the surface a call arrived on is
*not* a second axis — measured and rejected, in `docs/design/README.md` under
"The verdict is per reason and not per surface".

The plugin is real now: `hooks/hooks.json` wires the two events
[`internal/hook`](internal/hook/hook.go) answers to, and `.claude-plugin/`
carries the manifests that make the repo installable. That order was deliberate
— a repo installable as a security tool scanning nothing is the failure this
project indicts the predecessor for, so the wiring waited for something to
fire.

**The matcher is held to the Go constants, not kept in step by hand.**
`internal/hook/manifest_test.go` reads `hooks/hooks.json` and asserts set
equality both ways against `PreToolUse`/`UserPromptSubmit` and
`ToolRead`/`ToolBash`. Containment would only catch the loud direction. A
matcher wider than the scanner delivers calls the hook returns clean on, and
the hook still runs; an event the scanner handles and the manifest omits fires
nothing at all — no payload, no verdict, no line in the transcript — so the
surface is absent and reads exactly like a call that carried no secret.

**Neither direction is readable from the source**, which is why the wiring was
driven rather than reviewed. `claude plugin details spill-guard` reports the
events it registered, and the first run of it reported `Hooks (0)` — the
marketplace entry names a GitHub source, so the install cloned `main`, which
had no manifests. That failing arm is what makes the `Hooks (2) PreToolUse,
UserPromptSubmit` beside it worth anything.

The timeout is 60 seconds, matching branch-guard. What Claude Code does with a
hook that exceeds it is unmeasured, so the value is picked in the direction
that cannot fail open: if expiry allows the call, a longer timeout is safer,
and if it blocks, a longer timeout only ever costs a stall.

`install/` is the fallback channel, and both scripts are driven rather than
reviewed. `scripts/check-install-scripts.py` serves a GoReleaser dist directory
over a loopback port and makes each script install from it, run the binary it
installed, and refuse four things: a corrupted archive, a `checksums.txt` that
does not list it, a machine with neither `cosign` nor `gh`, and a `--rehearse`
aimed at github.com. The release workflow runs it on all three operating
systems on every pull request. It cannot be a gate: it installs out of a
directory only GoReleaser produces, and `make doctor` calls GoReleaser a
release-tier tool, so a gate over it would fail on a fresh clone.

What it cannot reach is the verification itself. `--rehearse` skips the
signature, because artifacts served from a loopback port carry no release
provenance to check, so the `cosign verify-blob` and `gh attestation verify`
calls are driven by nothing here and cannot be until a signed release exists —
and the first one is a permanent version number. What is driven is the step
before them: which verifier the script picks, and that it refuses when there is
none. [`docs/development/release-process.md`](docs/development/release-process.md)
carries the manual check that closes the rest, after a draft is published.

The `Bash` surface is now whole: the command string is scanned and so are the
files its readers are pointed at, `internal/readers` being what decides which
token is a path. An operand of a known reader that cannot be resolved — a
`$VAR`, a glob, a relative path after a `cd` — blocks, because a scanner that
skips one reports a clean result for a file nothing opened. An operand that
resolves to something other than a regular file blocks as well, and so does a
`Read` call's `file_path`: opening a fifo waits for a writer that never comes,
which hangs the call instead of deciding it, and neither answer this project
chooses between is reached. A device is refused with it rather than skipped,
because the class is not safe — `/dev/zero` returns bytes for as long as
anything reads them — and because the traffic it costs was measured at 12 of
129,000 `Bash` calls. The reading is `os.Stat`, which follows a symlink the way
the tools do; `os.Lstat` cannot tell a link to a fifo from a link to a file. A
command with no row contributes no operands, which is the design's stated
limitation rather than a gap.

The prompt surface is read the same way and by the same shape, and what it does
not cover is named below rather than counted — a count here has already gone
stale twice in a day, because every drive of a new token shape can add one. A
prompt
is scanned as text *and* read as a carrier of `@` file operands, because typing
`@deploy.env` splices the file into the model's context with no hook of any
kind running for it — `UserPromptSubmit` is where that crossing is stopped or
nowhere. The token grammar in `internal/hook/prompt.go` is driven rather than
reasoned about, and the harness publishes its own answer: a splice arrives in
the transcript as an attachment whose `attachment.type` is `file` and whose
`filename` is the path it resolved. That census is
`internal/hook/testdata/prompt-oracle.json`, compared against on every run
rather than read once and agreed with. The rest of the class the design names —
an MCP file reader, a search tool that returns lines, a skill load — is out of
v1 and stated in *What it is not*, because the tool set is not a list anyone
can enumerate once.

**Do not write that the token grammar matches the harness.** Six boundary
codepoints and the ASCII punctuation set have been driven, and that is the
whole of what is known; the class is open and the next codepoint is a drive
away. Three fail-opens came out of assuming otherwise, and the third is the one
to remember: `unicode.IsSpace` is wrong here because Unicode removed U+FEFF
from `White_Space` in 4.0.1 and the harness did not follow. A hand-written
table invites the question *where did these characters come from*; the standard
library forecloses it, which makes the idiomatic call the more dangerous of the
two. Any assumption that Go's notion of a character class matches somebody
else's parser is settled by driving it and by nothing else.

**The hole is a binary `@` target, and it is the scan pipeline's rather than the
resolver's.** Read which arm is which before reasoning about it, because the
harmless one is the one that comes to mind. Measured 2026-08-28: `@logo.png`
arrives as a `file` attachment whose `content.type` is `image`, carrying no
text — nothing crosses that a rule could match. `@heap.dump`, a NUL in its
first bytes, arrives as `content.type` `text` carrying **the whole file**, NUL
included, with a marker placed after that NUL intact. That second arm is the
one with a consequence: the resolver opens it and hands it on, `internal/scan`
skips a buffer with a NUL in the first 8 KiB, and a skipped buffer contributes
no findings, so a credential inside one is allowed. Driven on a built binary,
with the control beside it: the same key without the NUL blocks and names the
rule, and with it the hook exits 0. It is not a regression — nothing scanned an
`@` target before this — and it is the reason-versus-surface question the
`Read` and `Bash` surfaces already carry.

**Q84 closed half of that and not the half that matters.** The allow now
carries a notice naming the buffer, so the transcript is no longer empty and
the user can act; the credential is still unscanned and still allowed. Do not
read the notice as coverage. It reports that nothing looked.

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
with a reason.

`spill-guard selftest` is the check a user runs, and what it can answer is
narrower than "is the hook live". It drives canary payloads through `hook.Run`
in-process -- prompt, `Read`, `Bash` command, `Bash` operand -- and asserts a
block naming the rule, with an allowing arm on every surface. One arm carries
no canary and names no rule: a `Read` of a file behind a UTF-32 mark, whose
block names the skip reason instead, because it is the one payload here that
reaches a verdict with no finding behind it. It is a blocking arm, so it makes
that branch cheaply reachable and adds nothing an allowing arm can see.

**The allowing arms are what can see an over-block, and they only can because
`drive` has a third outcome.** With two, an arm was `blocks` or `allows`, and
the three situations that are neither -- refused, a verdict that is not a
block, blocked by a rule that is not the canary's -- collapsed onto `allows`.
A blocking arm caught them by disagreeing; an allowing arm agreed and printed
`ok`. Measured on the seven arms of the time: one over-matching rule added to
the shipped set turned all three allowing arms into blocks, and the report read
`7 of 7 arms as expected. This binary scans and blocks.` at exit 0. That is a
precision regression -- the thing this repo calls the product -- invisible to
the check a user runs. `anomalous` is a want no arm may hold, so it disagrees
with every arm, and the same mutation on today's eight reads `3 of 8 arms did
not do what they must` at exit 1. It cannot spawn the launcher: `os/exec` is
forbidden across the build graph, so the launcher is covered by *how* it is
invoked, and running `run-spill-guard.cmd selftest` puts the resolution order
in the path and
reports the binary it found. Whether Claude Code is invoking the hook at all is
not reachable from outside a session, and the report says so rather than
letting a green run imply it.

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

**A mutation control needs a precondition asserting the mutation had its
effect, not that it happened.** The two come apart. `PATH=/usr/bin:/bin` was
meant to hide Go from `make doctor` and hid nothing, because `setup-go` links
Go into `/usr/bin` — the control passed while testing nothing. That is the
instance; the rule recurs. On 2026-08-25 a Windows control asserted "uniform
LF, block present", both true, while the launcher went on denying: the mutation
landed and did not bite. Five such controls in one batch, three carrying an
explicit precondition that passed.

The checkable form is comparison against a case already measured, and **the
case is a file, not a recipe for producing one.** That control copies
`testdata/launcher/lf-uniform-failing.cmd` over the launcher and asserts its
sha256, byte count and uniform LF before driving it — 7,214 bytes,
`d28a64b3…`, checked in because it is the exact artifact a `windows-latest`
runner was measured failing on. The hash assertion is the load-bearing half: a
fixture nobody checks drifts silently, which is what happened to the thing it
replaced.

What it replaced *read* as that and was not. It rebuilt the failing arm by
patching whichever launcher was in the tree, so it landed on the measured file
only while the launcher was the one it had been measured against — and the
sentence describing it, "transplants the failing arm byte for byte, 7,214 bytes
verified identical", was true of the *substitution text* and false of the
resulting file, which is what made it read as rigorous. Shortening four deny
strings moved the reconstruction 610 bytes, cmd.exe went on denying correctly,
and the step failed three heads running saying the gate had failed for the
wrong reason. Padding the mutation to raise the drift made it worse, because it
moved the file further from 7,214 rather than nearer.

**A mutation is only valid against the artifact it was measured on**, and
nothing anywhere said the reconstruction was a reconstruction. Q103 carries the
byte table and the class. Where no such case exists, build one,
and give any probe whose answer matters when it is *empty* a positive control
proving it can come back non-empty.

**The launcher's line endings are load-bearing, and split.** CRLF down to the
`CMDBLOCK` terminator, LF after it, `-text` in `.gitattributes` so git cannot
normalise the split away. Measured 2026-08-25 in four arms on GitHub runners:
LF throughout makes cmd.exe lose its file position across a parenthesized
block, so the `goto` after it dies with `The system cannot find the batch label
specified`, the launcher exits 1 with empty stdout, and the call runs
unscanned; CRLF throughout kills the POSIX half on `set: Illegal option -`.
`make launcher` asserts both halves and a `windows-latest` control reproduces
the failure.

**The launcher denies when the binary is missing.** `hooks.json` never invokes
`spill-guard` directly: an absent binary exits 127, and only exit 2 blocks, so
the call goes through with nothing in the transcript. Empty stdout is not what
makes it pass — a hook exiting 2 with empty stdout still blocks — the exit code
is. The launcher blocks with `{"decision":"block","reason":…}` on stdout, which
blocks whatever it exits with — and that shape rather than the `PreToolUse`
deny object, because the launcher never learns which event it was invoked for
and the deny object is accepted and ignored on `UserPromptSubmit`. Anything `hooks.json` invokes ships executable, with the mode set in
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
| `status-drift` | the README's status table still says what the tree can actually do |
| `hooks-check` | every tracked git hook is executable, so none is silently inert |
| `launcher` | the hook launcher is executable in the index, resolves a binary, and denies when it cannot |
| `vendor` | every vendored copy still hashes to the digest scripts/README.md declares |
| `docs` | every relative link in the repo markdown resolves |
| `queue` | the backlog store format holds, every filed id holds a claim, no index is committed |
| `action-pins` | every `uses:` in every workflow names an immutable revision, not a tag |
| `test` | gofmt, go vet and go test |
| `precision` | the shipped ruleset stays quiet on the clean corpus and finds every planted secret |
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

One gate is weaker on a branch than on the trunk, and only on purpose. `queue`
holds `dangling-link` back on a pull request, because a row may link an item a
sibling PR is still filing. `make queue MERGED=true` runs the trunk's set, and
it is the only local command that sees what the push to `main` will see.

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
exit 0. `make queue` promotes four of them; the `queue` job adds
`dangling-link` on a push to `main`, and `make queue MERGED=true` is the only
local command that runs that stronger set. `stale-citation` catches a citation
your own diff moved; one a sibling moves leaves your branch green and reddens
`main`, so the trunk's run is still what closes it. It is promoted whole, so a
row whose pointer describes the merged tree rather than your branch — a file, a
fragment, or a line number a sibling PR is still adding — is red on your branch
until that PR lands. Mark it `exhibit:`, or write it afterwards.
Completing an item is `git rm docs/queue/QN.md` **and flipping any row that
waited on it to `status: ready`**, since a row left blocked waits on nothing
and git history is the archive — except for a row filed and completed in the
same pull request, which a squash erases.
[`docs/queue/README.md`](docs/queue/README.md) has that case, the frontmatter,
the conventions, and which classes bind on which event.

Everything in there traces to `docs/design/`.

## Open questions

None left. The last one — whether `install.sh` should refuse without `cosign` —
is settled under **Settled** at the end of `distribution.md`, and `install/`
now implements it: verify with whichever of `cosign` or `gh` is present, refuse
only when neither is. The framing was the defect rather than the answer, since
`cosign` was never the only verifier for what it checks. `docs/design/README.md` has none either — what
counts as human-typed is settled there under
[**What gets scanned is the crossing, not the hop**](docs/design/README.md#what-gets-scanned-is-the-crossing-not-the-hop),
which answers it by dropping authorship for whether a payload field's bytes have
crossed the filesystem-to-context boundary yet.

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
