# Design

spill-guard stops secrets and PII from reaching the Anthropic API through a
Claude Code session. Detection is local heuristics only — a static Go binary,
stdlib `regexp`, no network calls for any reason.

This directory holds the design and the reasoning behind it:

| Doc | What it is |
|---|---|
| This file | The proposed design: threat model, hook surface, pipeline, rule schema, failure policy, CI. |
| [`distribution.md`](distribution.md) | How the binary reaches a machine — the launcher, signed release assets, and the install channels evaluated against each other. |
| [`language-choice.md`](language-choice.md) | Why Go, with the measurements. Verbatim from the analysis that started the project. |
| [`brief.md`](brief.md) | The origin brief, kept as written. |

**Status: nothing scans anything yet.** The module, the entry point's skeleton
and four of the [CI gates](#ci) exist; `internal/` does not. The
[open questions](#open-questions) are the parts that need a decision or a
measurement before implementation goes further.

## The problem

Claude Code sends what it reads to the API. `cat .env`, a `grep -r password`
across a repo, a pasted stack trace carrying a bearer token — the content lands
in the conversation and the conversation goes over the wire. There is no undo,
and no moment where anything says a credential just left the machine.

Git secret scanners do not cover this. `gitleaks` and its relatives watch the
commit boundary; a file read into a session is never committed and never
scanned. The boundary that matters here is the one between the local filesystem
and the model's context.

## What it is not

- **Not a git scanner.** The commit boundary already has good tools.
- **Not a defense against a user who means it.** The escape hatch is one env
  var. This is a net for the accident, not a wall against intent.
- **Not remote anything.** No telemetry, no update check, no shared rule
  source, no daemon.
- **Not a recall play.** Ten precise rules beat seventy noisy ones. The
  inherited ruleset's defect was precision, not coverage — 27.6% of real files
  flagged, 5,679 matches, zero of them credentials
  ([`language-choice.md` §3](language-choice.md)).

## The hook surface

A hook can only stop content it sees before the model does. Three events see
text, and they do not have the same power.

| Event | What it sees | Can it withhold? |
|---|---|---|
| `UserPromptSubmit` | Text the human typed | Yes — the prompt never reaches the model |
| `PreToolUse` | The tool call's arguments: a command string, a file path, a `Write` body | Yes — `deny` stops the call |
| `PostToolUse` | The tool's result | **No.** The result is already sent — [measured below](#posttooluse-cannot-withhold-a-result) |

`PreToolUse` on `Read` is stronger than it first looks. The hook gets the path
before the tool runs, so it can open the file and scan it locally, then deny.
The content never enters the transcript, and the design does not have to depend
on what `PostToolUse` can withhold.

`Bash` is the hard case. The hook sees the command, not its output, and the
output of an arbitrary command cannot be predicted. Two partial answers, both
worth having and neither complete:

1. Scan the command string itself. `curl -H "Authorization: Bearer sk-..."`
   carries the secret in the argument, where the hook can see it.
2. Resolve the file operands of the common readers (`cat`, `head`, `tail`,
   `grep`) and scan those files, the same way `Read` is handled. Sibling
   guards already parse Bash to this depth; workspace-guard's segmentation
   layer is the thing to port rather than to rewrite.

Neither catches a command that synthesizes a secret at runtime. That is a
stated limitation, not a gap to close later, and `PostToolUse` does not close it
either: the measurement below rules out catching `Bash` after the fact. These
two are the whole answer for `Bash`, not a fast path in front of one.

### `PostToolUse` cannot withhold a result

Measured 2026-08-21 against Claude Code 2.1.220 on darwin/arm64. A `PostToolUse`
hook on `Bash` denied a call whose output carried a marker string. The check is
whether that marker reaches the session transcript under `~/.claude/projects/`,
because the transcript is what went to the API — the hook's own return value
proves nothing either way, which is the trap this measurement exists to avoid.

Three ways of denying, one result:

| How the hook denied | Marker in the `tool_result` | `is_error` |
|---|---|---|
| exit 2, reason on stderr | present | false |
| exit 0, `{"decision":"block","reason":...}` | present | false |
| exit 0, a `deny` decision object | present | false |

A hook that exits 0 and does nothing produces a transcript identical in that
respect. In all three deny runs the verdict arrives *after* the result, as a
separate `attachment` entry, so the model reads the output and then reads the
complaint about it. Its own recorded reasoning in the `decision: block` run:

> I did run the echo command successfully - it output "SPILL_Q2_MARKER_9K"

By the time a `PostToolUse` hook runs, the output has been sent. The hook can
append a warning about content the model already has. It cannot unsend it.

**So the `PostToolUse` surface is worth having only as an after-the-fact
warning**, which is close to worthless for this tool's purpose and must not be
counted as a control. Everything spill-guard actually prevents has to be
prevented at `UserPromptSubmit` or `PreToolUse`. For `Bash` that means the
command string and its resolved file operands are the entire surface, so the
segmentation layer this design ports from workspace-guard is load-bearing rather
than an optimisation.

## Pipeline

Per buffer, in order. Each stage exists to keep the next one off work it does
not need to do.

1. **Skip binaries.** A NUL byte in the first 8 KiB means skip. In the
   benchmark corpus one PNG was 55% of all bytes, and the three language
   prototypes disagreed on it because Go keeps raw bytes where Rust and Python
   substitute U+FFFD.

2. **Literal prefilter.** Word-boundary search for each credential rule's
   keywords, 255–307 MiB/s against 1.0 MiB/s for the regex pass — roughly 280x.
   Use word boundaries, not `strings.Contains`: naive matching finds `sk-`
   inside `disk-containerd-…`, and one broad keyword (`AC`) took the file hit
   rate from 1.2% to 18.9% on real files. The prefilter gates the credential
   family only. Numeric PII rules have no literal to anchor on, which is one
   reason they ship disabled.

3. **Match, one rule at a time.** Never fold the patterns into a single
   alternation. Measured at 0.5x in Go and 0.7x in Rust: the DFA state space
   explodes and the lazy-DFA cache thrashes on heterogeneous input. Two engines,
   same result.

4. **Validate.** This is where precision comes from, and regex is not where it
   lives:

   | Validator | Applies to |
   |---|---|
   | Luhn | Payment cards |
   | mod-11 | National ID numbers |
   | Shannon entropy floor | High-entropy credential candidates |
   | Reserved-range exclusion | IP rules — RFC1918, loopback, link-local, documentation ranges, `0.0.0.0` |
   | Context label proximity | Bare numeric runs, which count only near a label like `phone:` or `ssn=` |

5. **Report.** Rule ID, path, byte offset. Nothing else.

## Rule schema

Rules are data. The shipped set lives in `rules/spill-guard.json`; a project
extends it from `.claude/spill-guard.json`, matching the sibling guards.

```json
{
  "id": "aws-access-key-id",
  "family": "credential",
  "description": "AWS access key ID",
  "regex": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\\b",
  "group": 1,
  "keywords": ["AKIA", "ASIA", "ABIA", "ACCA", "A3T"],
  "entropy": 3.0,
  "validators": [],
  "enabled": true
}
```

| Field | What it does |
|---|---|
| `id` | Stable identifier. Appears in findings and in the friction report. |
| `family` | `credential` or `pii`. The `pii` family defaults to disabled. |
| `regex` | RE2. Compiled at startup; a rule that does not compile is a startup failure, not a skipped rule. |
| `group` | Which capture group holds the candidate. Lets a rule capture a wider window than it reports. |
| `keywords` | Word-boundary literals for the prefilter. Empty means ungated, which is expensive — say so deliberately. |
| `entropy` | Minimum Shannon bits per character over the captured group. Omitted means no floor. |
| `validators` | Named checks from the table above, all of which must pass. |
| `enabled` | Ships `false` for every `pii` rule. |

`gitleaks` is a safe ruleset to borrow from. Its `go.mod` carries no PCRE or
`regexp2` dependency and it uses stdlib `regexp`, so a non-RE2 rule would panic
at its startup rather than ship.

RE2 has no lookaround and no backreferences. Nine of the inherited rules use
them and need rewriting; most are `(?<![A-Za-z0-9])X(?![A-Za-z0-9])` boundary
guards, which the `group` field handles — capture a wider window, post-filter in
code. RE2 also caps bounded repetition at 1000, so `{1,1024}` becomes `{1,1000}`.
[`language-choice.md` §4](language-choice.md) names all nine.

## Fail closed, and prove it

The sibling guards fail **silent**: an unparseable input or a missing registry
means no opinion, because a hook that runs on every Bash call must never be the
reason ordinary work fails. spill-guard inverts that. A secret scanner that
fails quietly reports a safety it is not providing, which is worse than not
being installed.

So every internal error blocks, with a reason naming the error.

The predecessor shows why this needs more than a policy statement.
`coo-quack/sensitive-canary` exits 2 to block on internal error — correct — but
it needs Node ≥22.6 for `--experimental-strip-types`, and on Node 18 it exits
**9**. Claude Code does not treat 9 as blocking, so the plugin sat installed,
checking nothing, reporting nothing. A single static binary removes that whole
class. It does not remove the obligation to measure the harness's exit-code
contract instead of reading it in the docs, which
[the section below](#the-exit-code-contract-measured) now does.

Two mechanisms carry this:

- **`spill-guard selftest`** feeds a canary secret through the full hook path
  and asserts a block. If the hook is not live, this is how you find out.
- **The contract is measured, not read.** Only exit 2 blocks, a `deny` object on
  stdout blocks whatever the exit code, and a hook that cannot run at all does
  neither ([below](#the-exit-code-contract-measured)). That is a property of
  the harness rather than of spill-guard, so it can move under a Claude Code
  upgrade: re-run the probe against a new version instead of trusting the
  table.

## The exit-code contract, measured

Measured 2026-08-21 against Claude Code 2.1.220 on darwin/arm64. A throwaway
project ran a `PreToolUse` hook on `Bash` that appended to a log, wrote a chosen
shape to stdout or stderr, and exited a chosen code. The tool call under test
was `echo PROBE_RAN_MARKER_7X`, and the observable is whether that marker came
back in a `tool_result` in the `--output-format stream-json` transcript. The
hook's own log separates *the hook never ran* from *the hook ran and was
ignored*.

The call is blocked if **either** signal says so, and they are independent:

| Signal | Blocks | What the model receives |
|---|---|---|
| A `deny` decision object on stdout | whatever the exit code | the `permissionDecisionReason`, verbatim |
| Exit code 2 | whatever is on stdout | `PreToolUse:Bash hook error: [<path>]: <the hook's stderr>` |

Anything else runs. The cells driven, all of them with an empty stderr unless
noted:

| Hook exit | Hook stdout | The tool call |
|---|---|---|
| 0 | empty | runs |
| 1 | empty, plain text, or text on stderr | runs |
| 9 | empty | runs |
| 126 | empty | runs |
| 127 | empty | runs |
| 0 | text that is not a decision object | runs |
| 2 | empty, plain text, or text on stderr | **blocked** |
| 0, 1, 9, 127 | a `deny` decision object | **blocked** |

**Only exit 2 blocks, and the documentation was right about it.** 1, 9, 126 and
127 all let the call through. The predecessor's Node-18 exit 9 is a measurement
now instead of an inference.

**The exit code is not what makes a missing binary harmless.** A hook exiting 2
with nothing on either stream still blocks, and the model is told `No stderr
output`. Empty stdout is not the operative part of the failure the launcher
exists to prevent; the non-2 exit code is.

**A deny on stdout outranks the exit code.** The same `deny` object blocked the
call on exits 0, 1, 9 and 127, and the reason reached the model byte-identical
in all four. So a launcher that writes its deny and then dies still blocks — the
one shape here that fails closed on its own. Prefer it.

**On exit 2 the reason travels on stderr, and stdout is discarded.** A hook that
writes `spill-guard: blocked ...` to stdout and exits 2 stops the call and tells
the model nothing about why. The `deny` object has no such trap, and no
`PreToolUse:Bash hook error: [<path>]:` prefix wrapped around its reason.

### The two shapes that fail open

Both were driven end to end, not reasoned about. Neither hook can write stdout
at all, so neither has the `deny` escape above:

| Configuration | What happens |
|---|---|
| `hooks.json` names a path that does not exist | the shell exits 127, the tool runs, `is_error` is false |
| `hooks.json` names a file at mode 644 | the shell exits 126, the tool runs, `is_error` is false |

Neither produces a warning anywhere in the transcript, and neither reaches the
model. This is the case [`distribution.md`](distribution.md) argues the launcher
exists to prevent, measured on both of the exit codes that get there.

Two conditions that do **not** change any of the above, each measured on exits
0, 2 and 127: running under `--permission-mode bypassPermissions`, and running
in a workspace whose trust dialog has never been accepted. The untrusted
workspace has its `permissions.allow` entries ignored with a warning on stderr,
and its hooks run anyway.

## Output discipline

**The raw secret never enters a struct that outlives the match.** The
predecessor's `Finding` carried `secretValue` beside `matchRedacted`; tracing
showed it was used only as a dedup key and never printed, but the field's
existence is a standing hazard. Findings here carry a truncated
`sha256(rule_id || value)` for dedup and nothing else.

**Findings emit rule ID, path, and byte offset — no fragment, not even a
redacted one.** Everything a hook writes to stderr reaches the API, so an
8-character redacted window is 8 characters of the secret sent to the place the
scanner exists to keep it away from.

**Control characters are escaped in every emitted string.** Paths and rule
descriptions both reach a terminal; C0, DEL, and the bidi overrides get escaped
before anything is written.

**There is no in-band bypass tag.** A magic string that turns the scanner off is
a prompt-injection surface, because any content the model reads can contain it —
including the file being scanned. The escape hatch is `SPILL_GUARD_OVERRIDE=`
in command position, matching `WORKSPACE_GUARD_OVERRIDE` and
`PROD_GUARD_OVERRIDE`, plus per-rule disablement in config. Both are places the
model cannot write to from inside a scanned buffer.

## Repo layout

```
cmd/spill-guard/          Entry point. Subcommands: hook, scan, selftest, rules, version.
internal/hook/            Claude Code payload decode, verdict encode, exit-code contract.
internal/rules/           Schema, registry load and merge, compile.
internal/scan/            Binary skip, prefilter, match loop, findings.
internal/validate/        Luhn, mod-11, entropy, reserved ranges, context labels.
internal/bash/            Segment parsing, ported from workspace-guard.
rules/spill-guard.json    The shipped ruleset. Data, not code.
hooks/hooks.json          Hook wiring.
hooks/run-spill-guard.cmd Launcher. Resolves the binary, denies when it cannot.
scripts/install.sh        Install script, POSIX.
scripts/install.ps1       Install script, Windows.
testdata/corpus/          Precision fixtures — clean files that must not flag.
docs/design/              This directory.
```

The launcher is load-bearing, not glue: `hooks.json` invoking the binary
directly would fail open when the binary is absent. See
[`distribution.md`](distribution.md).

## CI

Every property this project claims is enforced by a job, because a property
stated in a README and checked by nobody is a property that decays.

| Job | What it enforces |
|---|---|
| `test` | `go test ./...`, `go vet`, `gofmt -l` |
| `no-deps` | `go.mod` has no `require` block, and `go list -deps ./...` resolves to stdlib only |
| `no-network` | `go list -deps` contains no `net`, `net/http`, or `os/exec` |
| `cross-compile` | All five targets build from one runner: darwin/arm64, darwin/amd64, linux/amd64, linux/arm64, windows/amd64 |
| `precision` | The ruleset runs over `testdata/corpus/` and the false-positive count must not exceed a pinned number |
| `mutation-control` | Disable one rule; the suite must go red |

The precision job is the one that matters most. Recall regressions are visible —
somebody reports a missed secret. Precision regressions are invisible until the
noise has trained everyone to ignore the tool, which is how the inherited
ruleset arrived at 5,679 matches and zero true positives.

The mutation-control job follows the sibling repos: a suite that has never
failed is a suite with no evidence behind it.

## Benchmarking, if you benchmark at all

Four rules, each of which was learned by getting it wrong
([`language-choice.md` §2](language-choice.md)):

- **Never benchmark on a repeated chunk.** A 176-byte block repeated 47,662
  times overstated Rust by roughly 10x — it keeps the DFA cache warm and lets
  literal prefilters skip everything.
- **Use real heterogeneous files.**
- **Verify match counts are identical before comparing any two timings.** An
  early run compared 75 Python patterns against 66 Go ones.
- **Measure fixed startup cost separately from throughput.** Below about 8 KB of
  input it dominates completely, and a per-invocation hook lives there.

## Open questions

One left, and it needs an answer before or during implementation because it
changes the shape of the thing. The other two were measurements rather than
decisions, and both are taken: see
[the hook surface](#posttooluse-cannot-withhold-a-result) and
[the exit-code contract](#the-exit-code-contract-measured).

### 1. What counts as human-typed

The audit's carried-over requirement is to distinguish human-typed text from
runtime-written text when deciding what to scan. `UserPromptSubmit` is clearly
the first and a tool result is clearly the second, but a `Write` body composed
by the model from a file it read is neither. The rule that decides this has not
been written.
