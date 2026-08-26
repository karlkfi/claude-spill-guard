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

**Status: nothing scans anything yet.** The module, the entry point's
skeleton, the [CI gates](#ci), `internal/validate`, `internal/rules`,
`internal/scan` and the shipped ruleset exist, and the binary reaches none of
them — there is no `hook` subcommand to call them from. The validators came
first because they are pure functions over a candidate and needed nothing to
call them. The [open questions](#open-questions) are the parts that need a
decision or a measurement before implementation goes further.

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

   | Name in `validators` | Check | Applies to |
   |---|---|---|
   | `luhn` | Luhn checksum | Payment cards |
   | `card-placeholder` | Denylist of the published test numbers and repeated-digit runs Luhn accepts | Payment cards, beside `luhn` |
   | `mod-11` | ISO 7064 MOD 11-2 | National ID numbers |
   | `entropy` | Shannon floor, read from the rule's `entropy` | High-entropy credential candidates |
   | `reserved-range` | Reserved-range exclusion | IP rules — RFC1918, loopback, link-local, documentation ranges, `0.0.0.0` |
   | `context-label` | Proximity to one of the rule's `labels` | Bare numeric runs, which count only near a label like `phone:` or `ssn=` |

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
  "validators": ["entropy"],
  "enabled": true
}
```

A numeric PII rule is the other shape. It has no literal to prefilter on, so
`keywords` is empty and `labels` carries the words the value has to sit near:

```json
{
  "id": "us-ssn",
  "family": "pii",
  "description": "US Social Security number",
  "regex": "\\b(\\d{3}-?\\d{2}-?\\d{4})\\b",
  "group": 1,
  "keywords": [],
  "labels": ["ssn", "social security"],
  "validators": ["context-label"],
  "enabled": false
}
```

| Field | What it does |
|---|---|
| `id` | Stable identifier. Appears in findings and in the friction report. |
| `family` | `credential` or `pii`. The `pii` family defaults to disabled. |
| `description` | What the rule matches, in a few words. It reaches a terminal, so it is escaped like a path. |
| `regex` | RE2. Compiled at startup; a rule that does not compile is a startup failure, not a skipped rule. |
| `group` | Which capture group holds the candidate. Lets a rule capture a wider window than it reports. |
| `keywords` | Word-boundary literals for the prefilter. Empty means ungated, which is expensive — say so deliberately. |
| `labels` | Word-boundary literals the candidate has to sit near, for the context-proximity check. Read after the match, so unlike `keywords` it gates nothing. |
| `entropy` | Minimum Shannon bits per character over the captured group. Omitted means no floor. A floor above what the group can reach is a startup failure, not a quiet rule. |
| `validators` | Names from the validator table above, all of which must pass. |
| `enabled` | Ships `false` for every `pii` rule. |

`labels` and `keywords` are both word-boundary literal lists and they are not
interchangeable. `keywords` runs before the regex and gates the credential
family; `labels` is read by the context-proximity check after a match, and
gates nothing. Spending `keywords` on a numeric rule's labels would hand that
rule the prefilter [the pipeline](#pipeline) says it does not have, and that
absence is one of the reasons the family ships disabled.

**The proximity window is not per-rule.** `NearLabel` takes one and the loader
always passes `internal/validate`'s `DefaultLabelWindow`, measured at 64 bytes.
A per-rule override is defensible in the abstract — a postal code sits closer to
its label than a free-text address does — but there is nothing to set one from.
The measurement behind 64 found no knee to sit in, and its own doc comment says
the corpus was the wrong shape and the number has to be re-taken against
`testdata/corpus`. A per-rule window would freeze that provisional number into
every rule that overrode it, where the re-measurement cannot reach it. So a
rule carrying `window` is rejected at startup rather than ignored. Adding the
field later breaks no rule file written before it; taking it away once rules
have set it does.

A rule names every check that has to pass, including the two that read a field
of its own — `entropy` reads the rule's floor and `context-label` reads its
labels. Presence and configuration are separate on purpose. A numeric rule
whose author wrote the labels and left the validator off is an ungated numeric
regex, which is the shape that produced 5,679 matches and no credentials, so
naming the check is what turns that omission into a startup error. The loader
rejects a rule carrying configuration no check reads.

**It rejects the mirror image too: a check named with configuration that can
never let it pass.** `context-label` with no labels — absent, empty, or nothing
but empty strings — searches for nothing and so reports nothing. An entropy
floor above what the captured group can reach does the same: Shannon's ceiling
is log2 of the distinct byte count, so an eight-byte capture cannot exceed 3
bits however random it is, and a floor of 3.5 on one disables the rule outright.
Either way the rule loads, compiles, runs on every file and reports nothing,
which is exactly what a clean scan looks like from outside. That is the argument
that already fails a rule whose regex does not compile, so it gets the same
answer.

The entropy bound comes off the rule's own regex, at the **longest** string the
group can capture rather than the shortest. A group matching 8 to 64 bytes
reaches 3 bits at its shortest and 6 at its longest, so measuring the shortest
would refuse a working rule at startup — the failure this check exists to
prevent, pointed the other way.

The walk over-estimates rather than under-estimates, because the two errors are
not symmetric: missing a dead rule leaves this check half-done, while refusing a
live one takes the scanner down. One of those over-estimates is systematic and
worth knowing about. The ceiling counts distinct *byte values* at 256 rather
than at what the group can actually produce, so `[a-f0-9]{32}` is capped at
log2(32) = 5 bits where sixteen hex symbols cap it at 4 — a 32-character hex key
rule with a floor of 4.5 is dead and still loads. Every restricted-charset rule
carries that slack, exact length or not.

`(?:ab){1,3}` looks like a second, length-shaped kind of looseness and is not.
Its six-byte bound is exact — `ababab` is six bytes and the group matches it —
and every one of its 1.585 bits of slack is the two symbols it draws on. There
is one mechanism here, not two.

## Loading the ruleset

Both files are one JSON object with a `rules` array, so the config keys
`.claude/spill-guard.json` grows later need no format change. `id`, `family`,
`description`, `regex` and `enabled` are required of a rule; the rest default
to absent, and `enabled` has no default because a rule that does not say is a
rule somebody has not decided about.

A project entry whose `id` is already shipped overrides the fields it mentions
and leaves the others, which makes

```json
{"rules": [{"id": "aws-access-key-id", "enabled": false}]}
```

the way to turn a shipped rule off. An entry with a new `id` is appended and
has to be a whole rule.

**A field the schema has no room for is a load failure.** Go's `encoding/json`
drops an unknown field in silence unless the decoder is told not to — measured,
not read — and every field here only ever makes a rule stricter, so a
misspelled one leaves a rule that loads, compiles, runs, and reports either
nothing or everything. `window` is the field this catches by design.

Every problem is reported in one run. A rule author who has to fix them one at
a time is a rule author who stops running the loader.

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
internal/validate/        Luhn, card placeholders, mod-11, entropy, reserved ranges, context labels.
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

What runs today is not enumerated here, because a second copy of a list is a
copy that drifts. `GATES` in the `Makefile` is the source of truth; `make
list-gates` names every gate with what it covers, the workflow's job list is
asserted against it by the `gate-drift` gate, and
[`CLAUDE.md`](../../CLAUDE.md#running-the-gates) carries the table generated
from it. `make check` runs the lot.

The `precision` job is the one that matters most. Recall regressions are
visible — somebody reports a missed secret. Precision regressions are invisible
until the noise has trained everyone to ignore the tool, which is how the
inherited ruleset arrived at 5,679 matches and zero true positives. It runs the
shipped ruleset over `testdata/corpus/`, pins the false-positive count on the
clean half at zero, and requires each planted file to produce exactly one
finding.

**A second job disabling one rule is not separate from it.** The design asked
for one, and every gate here is already paired with a mutation control that
breaks its property and requires it to go red — so turning a rule off is a step
of `precision-mutation-control` rather than a job of its own, which is also the
only shape `gate-drift` accepts: a job in no gate's name is one `make check`
does not cover. The other three steps break the corpus rather than the ruleset,
because a zero over an empty corpus, a zero over a corpus nothing adversarial
is left in, and a zero from a test that quietly stopped running are all the same
zero from outside.

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
