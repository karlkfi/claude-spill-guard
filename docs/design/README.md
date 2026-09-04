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

**Status: it scans, and it is wired.** `spill-guard hook` reads a payload,
scans what the call would have sent, and blocks — driven end to end against a
live Claude Code on 2026-08-27, where a `Read` of a file carrying a Slack
webhook came back denied with the rule, the path and the byte offset and no
fragment of the value. `hooks/hooks.json` and the plugin manifests now point
Claude Code at that binary, at `PreToolUse` on `Read` and `Bash` and at
`UserPromptSubmit`; they were held back until there was a hook to fire, because
a repo installable as a security tool scanning nothing is the failure this
document indicts the predecessor for. `Bash` is scanned as a command string
**and** as the files its readers are pointed at, `internal/readers` being the
per-command table of which argument is a path. Nothing under
[open questions](#open-questions) blocks that any more; the last of them is
settled under
[what gets scanned](#what-gets-scanned-is-the-crossing-not-the-hop).

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
- **Not every reader in the class it defends.** v1 covers the three that are
  measured — a `Read` path, a `Bash` reader's resolved operands, and an
  `@path` in a prompt. The class is
  [wider than those](#what-gets-scanned-is-the-crossing-not-the-hop), and
  [driving the rest of it](#the-rest-of-the-class-driven) leaves two members
  out for two different reasons. A search tool returns lines from files it
  chooses, so nothing a `PreToolUse` hook opens can bound it. A skill load
  carries a name rather than a path, so nothing here can resolve what it would
  read. An MCP server's file reader is the shape most likely to be a third and
  has not been driven.

  **A subagent load is not one of them.** It was named here as an uncovered
  member and it is covered: a subagent's own tool calls fire the same hooks
  the parent's do, measured.

  **Do not close what is left with a list of tool names, and do not close it
  with a payload shape either.** The tool set is not fixed — nineteen deferred
  tools announced in one `deferred_tools_delta` on 2026-08-28, fifteen on
  2026-09-04 — and a `PreToolUse` matcher of `*` does see every tool including
  ones installed later. What fails is the field test that matcher was to
  carry: it misses the one member the drive found, because `Skill` names no
  path at all. Membership is an argument about what the call returns, and that
  argument is per tool.

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
   layer is the thing to port rather than to rewrite, and so is the
   per-command table above it that says which of a segment's tokens is a path.
   That table is `internal/readers`, and its read/write split is this repo's
   own: workspace-guard asks which files a command touches, writes included,
   and this asks what is about to leave the machine, which is the reads.

Neither catches a command that synthesizes a secret at runtime. That is a
stated limitation of content matching rather than a gap to close later, and
`PostToolUse` does not close it either: the measurement below rules out catching
`Bash` after the fact. What closes part of it is a third answer that matches
nothing at all — [refusing the call on its shape](#a-shape-refused-where-there-is-nothing-to-match),
for the case where the bytes exist only in the tool process and there is no
buffer anywhere to open. The three are the whole answer for `Bash`, and none of
them is a fast path in front of another.

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
command string, its resolved file operands and the shapes refused below are the
entire surface, so the segmentation layer this design ports from workspace-guard
is load-bearing rather than an optimisation — all three answers are read off it.

### A shape refused, where there is nothing to match

Both answers above look for a secret's bytes. `env` has none to look at. The
values live in the tool process's own environment, so at `PreToolUse` there is
no buffer on disk for a rule to open, and `PostToolUse` cannot withhold the
result once the command has run. A scanner that only matches values is
structurally blind to it, and no rule added to `rules/spill-guard.json` changes
that.

So the third answer refuses the call on what it would do. `env` blocks, and the
reason carries the filtered form — `printenv PATH HOME` for the variables you
want, `${FOO:+set}` to check one is set without printing it, `env | cut -d= -f1`
for the names alone. A deny rather than an ask, because the model applies what
the reason names and a human is not interrupted.

**The threat model is accident, not an adversary.** Say it in the reason and
say it here, because it is what makes the deny proportionate rather than
theatre. A session that wants a value writes `printenv AWS_SECRET_ACCESS_KEY`
and gets it; nothing here stops that, and this repo has already settled that a
control the scanned content can talk its way past is worthless — the
[no-in-band-bypass rule](#output-discipline) is the same argument one level
down. What a shape deny stops is the ordinary case: a session reaching for
`env` while debugging a `PATH` problem, and writing every variable into a
transcript that keeps them. Measured 2026-08-31 on one machine, a `Bash` tool
process carries 58 environment variables, and `CLAUDE_CODE_MESSAGING_TOKEN` is
one of them — put there by the harness rather than by any config, so nothing a
user edits removes it.

**It may not fire on the careful form, and that is the bar it had to clear.**
The careful form is what sessions already write, so a rule keyed on the command
name would deny the very thing its own reason recommends and teach the session
to stop filtering. Measured over 21,252 `Bash` calls in 303 transcript files on
this machine, the seven days to 2026-09-04, driven through the shipped
`envDumped` rather than through a probe written to describe it:

| | |
|---|---|
| Calls swept | 21,252, of which 2 could not be segmented |
| Segments whose command this rule knows | 5,380 — `python3` 5,266, `export` 40, `env` 35, `set` 17, `python` 17, `node` 2, `printenv` 1, `declare` 1, `typeset` 1 |
| Refused | **0** |
| The same sweep with 15 synthetic dumps appended | 15 |

The last row is the control. A zero over a sweep that has never been seen to
fire says nothing, and this one fires on every planted case while declining
5,380 real ones.

**What decides it is position in the pipeline, not the command name.** `env |
cut -d= -f1` segments into a bare `env` and a `cut`, so nothing in the `env`
segment's own tokens tells it apart from a dump. What does is whether anything
consumes its output: a stage after it is being written to, and nothing after it
means the tool result is. That is what `Segment.Pipe` is read for. Redirects are
not consulted, because `Segment.Redirects` records the target and not the
descriptor — reading any redirect as a filter would wave through `env
2>/dev/null`, and `env > vars.txt` is refused instead.

**Only the bare form of each command**: `env`, `printenv`, `set`, `export`,
`export -p`, `declare -p`, `typeset -p`, and an inline `python`/`node` script
naming `os.environ` or `process.env` without subscripting it. `env -0` still
dumps and is not refused, and neither is `os.environ.items()`. Widening to
catch them costs the precision above — every option this learns to see is
another way to be wrong about a form somebody wrote deliberately — and
`.keys()` sits on the other side of that line and is genuinely careful. The
accident is the bare one. Under-firing on a deliberate spelling is a stated
limitation; firing on `env | cut -d= -f1` would be a defect.

**Not `updatedInput`.** `PreToolUse` accepts it alongside the decision, so the
hook could rewrite `env` into `env | cut -d= -f1` and allow it silently. Refuse
that. Every measurement in this document was taken by driving a real hook and
reading what reached a transcript, so the record saying what ran is what the
whole verification posture rests on. A deny that names the fix costs one turn
and leaves it honest.

**The override reaches it like any other block.** `SPILL_GUARD_OVERRIDE=<why>
env` is a confirmation rather than an allow, which is the right shape for a
control whose threat model is accident: the session that means it says why, and
a person is told before the environment leaves the machine.

**What this does not do is guard a path.** The row that filed it carried a
second half — refusing a read of `~/.claude/settings.json`, `.env`,
`~/.aws/credentials` and the rest of that class — and that half is not here. It
is reachable by content matching where this one is not, it is capped by
`internal/readers` so an interpreter read of the same path is invisible to it,
and its own negative corpus is unmeasured: 15 guarded-reader calls at
`~/.claude/settings.json` in the week the row measured, and nothing saying
whether the rule would have denied all 15. It has its own row.

### What gets scanned is the crossing, not the hop

Scanning every field of every hook payload is the safe-looking default and it is
how a scanner becomes noise: one secret reported at the `Read`, again at the
`Write` that copies it, again at the heredoc that echoes it. Scanning only what
a human typed is the opposite error — it catches the pasted credential and
nothing the model moves.

Authorship is the wrong axis for both. The boundary this tool defends is the
local filesystem to the model's context, and the question a hook input answers
is whether its bytes have crossed it yet. A `Write` body composed out of a file
the model read is neither human-typed nor runtime-written, and deciding which it
is has no answer because the question does not apply to it.

**Whatever the model composed has already crossed.** The model emits the
`tool_use` block, so every byte of it is API output before the `PreToolUse` hook
is called. Denying that call stops a file being written; it unsends nothing. So
`Write.content`, `Edit.old_string` and `new_string`, a heredoc body inside a
`Bash` command, and the `description` beside it are re-emissions, and a finding
on one of them names a crossing that happened at an earlier hop.

**What a hook opens for itself has not crossed.** `PreToolUse` on `Read` carries
the path and no content, so the hook reads the file, and those bytes are still
on the local side until it allows the call. Same for the file operands the
`Bash` reader spec resolves, and for an `@path` in a prompt, which is the same
shape arriving through `UserPromptSubmit` — [below](#path-is-an-operand-not-a-hop).

Those three are the readers v1 covers, and they are instances rather than the
class. The class is *any hook input naming a filesystem path whose result comes
back as content*, and an installed MCP file or transcript reader is a member of
it that no rule here mentions. Under the old axis those were runtime output and
excluded with `PostToolUse`; under this one they are uncrossed hops where a deny
works, so the axis opens that obligation rather than discharging it. Enumerating
the readers is backlog work, not something this section settles.

Measured 2026-08-27 against Claude Code 2.1.238 on darwin/arm64, by logging the
raw stdin of a hook wired to all three events in a throwaway project and driving
a session that read a file, wrote its contents to a second file, and ran `cat`
on the first:

| Payload field | Where the bytes come from | Crossed already | Scan |
|---|---|---|---|
| `UserPromptSubmit.prompt` | the keyboard or the clipboard | No | **Yes** |
| `PreToolUse` `Read.file_path` → the file the hook opens | the filesystem | No | **Yes** |
| `PreToolUse` `Bash.command` → resolved read operands, opened by the hook | the filesystem | No | **Yes** |
| `PreToolUse` `Bash.command`, the string itself | the model — see below | Yes | **Yes** |
| `PreToolUse` `Bash.description` | the model | Yes | No |
| `PreToolUse` `Write.content` | the model | Yes | No |
| `PreToolUse` `Edit.old_string`, `Edit.new_string` | the model | Yes | No |
| `PostToolUse.tool_response` | the tool, and [already sent](#posttooluse-cannot-withhold-a-result) | Yes | No |

`Read`'s `tool_input` was `{"file_path": …}` and nothing else, which is what
makes the hook's own open the only way to see the content. `Write`'s carried the
full 55-byte body the model had assembled from the `Read` that preceded it,
and the `Bash` heredoc arrived intact inside `command`. Every payload also
carried `session_id`, `prompt_id`, `cwd`, `transcript_path` and, for a tool, a
`tool_use_id` beginning `toolu_`.

**The `Bash` command string is scanned, and the reason is authorship rather than
crossing.** By the rule above a model-composed command has already crossed and a
finding on it would be a warning, which
[the `PostToolUse` verdict](#posttooluse-cannot-withhold-a-result) says not to
count as a control. It is scanned anyway because it is the one payload field
whose authorship the measurement above did not settle: every `PreToolUse` seen
there carried a `toolu_` id, so every one was model-issued, and no probe has yet
established what a command the human runs directly looks like from inside a
hook. Failing closed on an unmeasured case is this project's rule, and the cost
is one short string per `Bash` call with no file to open. The backlog holds the
measurement that would retire the exception.

**Dedup on the content hash is not the mechanism, and would cost more than the
repetition it removes.** The repetition it targets is real — the same secret at
four hops — but the rule above deletes three of those hops structurally, without
keeping anything. Making the scanner quiet by remembering what it has already
reported would instead need the `Finding` digest to survive between hook
invocations, and each of those is a fresh process — five invocations in one
session came back with five distinct PIDs under one parent, measured the same
day — so the set becomes a file on disk keyed by `session_id`. Three things
follow, and each of them is a rule this project already made:

- **The file inverts.** `Digest` is the first eight bytes of
  `sha256(rule id, NUL, value)`, and the rule id is public in
  `rules/spill-guard.json`. Sixty-four bits pins a guess uniquely, so for any
  low-entropy value the file is the plaintext with a short walk in front of
  it. The `pii` family is all such values: a US SSN is 10⁹ candidates, which
  is 7 minutes of single-core Python, measured 2026-08-27 as the best of three
  runs of 1,000,000 digests, scaled. "Never put a raw secret in a struct that
  outlives the match" is not satisfied by writing a recoverable derivation of
  one to disk instead.
- **A cache silences the scanner, which is the fail-open direction.** A stale,
  corrupt, or planted entry means a real secret goes unreported and the run
  looks clean, and there is no in-band signal that anything was suppressed. This
  project blocks on every internal error for that reason.
- **It is state, and state has to be reaped.** A per-session file outlives the
  session that made it. The brief rules out a daemon and a persistent process;
  a directory of digest sets nobody deletes is the same obligation arriving
  through a side door.

### `@path` is an operand, not a hop

Typing `@secret.txt` in a prompt puts the file's contents in front of the model,
and **no hook of any kind runs for it**. Measured 2026-08-27 on 2.1.238, in a
project wiring all three events to a stdin logger. The marker column is read
from the session transcript named by the hook payload's own `transcript_path`,
not from what the run printed — a hook's stdout proves nothing here for the same
reason it proves nothing [for `PostToolUse`](#posttooluse-cannot-withhold-a-result),
and a blocked turn prints nothing whatever the splice did:

| Prompt | Hook records | `tool_use_id` in transcript | Marker in transcript |
|---|---|---|---|
| `… @secret.txt … Do not use any tool.` | 1 — `UserPromptSubmit` | 0 | 2, in 21,722 bytes |
| `Use the Read tool on secret.txt …` — control, same directory and config | 4, including `PreToolUse` `Read` | present | present |
| `… @secret … Do not use any tool.` — near-miss token, file untouched | 1 — `UserPromptSubmit` | 0 | 0, in 21,384 bytes |
| `… @secret.txt …` again, `UserPromptSubmit` exiting 2 | 1 — `UserPromptSubmit` | 0 | 0, in 1,404 bytes |

Three things that table has to do at once. The `Read` control makes row one an
absence rather than a dead hook. The **zero `tool_use_id`** makes it a splice
rather than a hop the design already covers — content arriving is not evidence
of a splice, because a model free to call `Read` produces the same content by a
route `PreToolUse` does see. And the near-miss row shows the splice is keyed to
an exact token: `@secret` next to a file named `secret.txt` moves nothing.

**That is not a limitation to declare, because the operand is visible.**
`UserPromptSubmit.prompt` carries `@secret.txt` as literal text, unexpanded, and
denying there suppressed the crossing rather than merely the echo: the deny
arm's whole transcript is 1,404 bytes against 21,722, with the marker absent
from it. So the prompt is two things at once: content to scan,
and a carrier of file operands, in the same way a `Bash` command string is. The
resolution rule is the `Bash` reader spec's problem restated with a simpler
grammar, and it belongs in the scan set rather than in
[what this is not](#what-it-is-not).

Getting it wrong is the failure this project indicts its predecessor for. A user
who types `@.env` is doing the most obvious dangerous thing available, and a
scanner that reports clean on it is reporting a safety it is not providing.

#### The token grammar, and the harness as its own oracle

A spliced file arrives in the transcript as an attachment whose
`attachment.type` is `file` and whose `filename` is the absolute path the
harness itself resolved the token to. So the resolver does not have to be
validated by reading that field and agreeing with it: the census is kept in
`internal/hook/testdata/prompt-oracle.json` and a test compares against it on
every run.

**Take the census on `attachment.type == "file"`, never on a raw count of
`"type":"attachment"`.** Skill listings, token reminders, deferred-tool deltas
and hook records all carry that key, so the raw count is non-zero whether or
not a file crossed: over the twenty-three transcripts the table below is drawn
from it ranges 5 to 14, and the ten arms where nothing was spliced at all still
returned 5 or 6. It read 5 to 9 over the first eighteen, which is the argument
against calibrating on it made by the census itself. What makes it survive a spot-check is that it is not
uninformative: it goes to 0 on a turn the hook blocked, so a driver who checks
a deny arm first sees it working and stops filtering. Separating a blocked turn
from an allowed one is a different question from whether a file crossed, which
is the only one this section needs.

Driven 2026-08-28 against 2.1.238 under `-p`, in the same throwaway project:

| Shape | What the harness does |
|---|---|
| `@` at the start of the input, or after a space, tab or newline | Splices |
| `@` after anything else | Nothing. Thirty characters driven — the ASCII punctuation set and a letter — including a backslash, so an escape is not a case of its own |
| Inside a fenced code block | Splices. There is no markdown awareness; a token after a backtick is suppressed by the whitespace rule, not by the fence |
| Token end and boundary | Whitespace, but the harness's notion of it. U+00A0, U+3000 and **U+FEFF** split; U+200B, U+00AD and **U+0085** do not. Go's `unicode.IsSpace` disagrees on two of those, one each way |
| `@.`, `@..` | Nothing — no attachment of any type, not even a directory one |
| Trailing punctuation | Trimmed, and repeats with it. Driven: `.` `,` `;` `:` `)` `-` `&` `=` `+` `#` `\` `%`. The trim is a punctuation set rather than a longest-existing-prefix search — `@u1.txtZZZ` beside an existing `u1.txt` spliced nothing |
| `@nosuchfile` | Nothing, so nothing crossed |
| `@a/dir` | An attachment of type `directory` carrying the entry names one level down, not file content |
| `@*.txt` | Nothing. Globs are not expanded |
| `@~/.zshrc` | Expands, and reaches outside the project |
| `@~user/.zshrc` | Nothing, on a run whose `@~/.zshrc` reached that same file. One record came back, and the harness does not dedup — `@x` and `@./x` give two records for one path — so one record there is one splice rather than two collapsed |
| A 5,001-line file | 2,000 lines. The splice is bounded, and the marker on the last line did not cross |
| `@logo.png` | A `file` attachment whose `content.type` is `image`, carrying no text |
| `@heap.dump`, a NUL in its first bytes | A `file` attachment whose `content.type` is `text`, carrying the whole file — NUL included, and a marker placed after it crossed |

That last row is the one with a consequence, and it is closed. The resolver
opens such a file and hands it on; [the pipeline](#pipeline) skipped a buffer
with a NUL in the first 8 KiB, so a credential inside one was allowed — first
in silence, then with a notice reporting that nothing had looked. On this
surface the pipeline now matches those bytes rather than declining them, which
is [a buffer whose bytes cross anyway](#a-buffer-whose-bytes-cross-anyway-measured)
below. Driven 2026-09-03 on a built binary: a NUL, then an AWS-shaped key,
under `@` — exit 0 with a notice before, and after it a block naming
`aws-access-key-id` at the offset the key sits at in the file.

The `Read` and `Bash` surfaces still decline it, and that is a cost measurement
rather than a second verdict axis. The section below has the table.

Two of those set the resolver's shape where the measurement runs out, and they
go opposite ways.

The **leading-boundary** rule is matched rather than widened, because thirty
characters of the set that could have shown a looser harness came back the
other way, and a resolver treating `foo@x.env` as a token would block every
prompt that writes an address beside a real filename.

The **trailing trim** and the **whitespace class** are widened past what is
driven, and the resolver got both wrong before it got them right. Three
fail-opens, in the order they were found:

1. **The trim set was five characters somebody typed.** One prompt naming nine
   spliced files put eight through unscanned while a plain `@ok.txt` in it
   blocked. The set is now the ASCII punctuation set bar `/`; every ASCII
   punctuation character driven is trimmed except `_`.
2. **The space test was ASCII-only.** U+00A0 splits, so `@a<NBSP>@b` was one
   token naming nothing and both files were invisible rather than skipped.
3. **`unicode.IsSpace` was still wrong**, and this is the one worth
   generalising. The argument for it was that it is a strict superset of the
   six ASCII characters, so widening could not lose a boundary — true, and
   beside the point. The exposure is a boundary the *harness* has and Go does
   not, and there is one: Unicode removed U+FEFF from `White_Space` in 4.0.1.
   Go implements the current standard and the harness splits on U+FEFF anyway,
   so a BOM-led paste went unscanned.

A hand-written table invites the question *where did these characters come
from*. `unicode.IsSpace` forecloses it, which is what makes the stdlib idiom
the more dangerous of the two: the standard moved in 2003 and the harness did
not follow.

The asymmetry is why all three repairs widen rather than match: under-trimming
leaves a file unscanned and spliced anyway, while over-trimming names a path
that does not exist and costs one `os.Stat`. Only one direction is a
fail-open. The resolver over-scans on U+0085 for exactly that reason — Go calls
it a space, the harness does not, and the oracle declares the divergence rather
than hiding it.

**None of this is a claim that the boundary class is settled.** Six codepoints
have been driven. The rest of the class is not, and the way to extend it is to
drive more rather than to reason from whichever standard looks authoritative.

### The rest of the class, driven

The three surfaces above are instances. The class is *any hook input naming a
filesystem path whose result comes back as content*, and closing it with a list
of tool names goes stale in silence: a tool installed after the list was
written is waved through, and nothing reports that a call went unscanned. The
tool set moves. One bare `claude -p` session announced nineteen deferred tools
in a single `deferred_tools_delta` on 2026-08-28 and another announced fifteen
on 2026-09-04.

The replacement this repo proposed was a payload test — a `tool_input` field
whose value is a filesystem path, under a `PreToolUse` matcher of `*`. Driving
it says the test is wrong in both directions, and the expensive error is not
the one the proposal expected.

Measured 2026-09-04 against Claude Code 2.1.251 on darwin/arm64. A hook logging
raw stdin was wired to `PreToolUse` with a matcher of `*` and to
`UserPromptSubmit`, in a throwaway project holding one skill and two files, and
every verdict below is read from the session transcript the payload's own
`transcript_path` names rather than from what the run printed. Ten arms were
driven and seven tools reached the hook:

| Tool | `tool_input` keys | In the class |
|---|---|---|
| `Read` | `file_path` | **Yes**, and covered |
| `Bash` | `command`, `description` | **Yes**, and covered |
| `Skill` | `skill` | **Yes**, and the payload names no path |
| `Agent` | `subagent_type`, `description`, `prompt`, `run_in_background` | No — the hook fires on the subagent's own calls |
| `ToolSearch` | `query`, `max_results` | No — it searches tool schemas |
| `WebFetch` | `url`, `prompt` | No — not the filesystem |
| `Write` | `file_path`, `content` | No — model-composed, and [already crossed](#what-gets-scanned-is-the-crossing-not-the-hop) |

**A skill load is a member, and it names no path.** `Skill`'s whole
`tool_input` is `{"skill": "probe-skill"}`. The file's text then arrives as an
injected `user` turn opening `Base directory for this skill:`, and no
`UserPromptSubmit` fires for that turn — the arm logged two records, the
prompt and the `Skill` call, and nothing else. So that call is the only hop
where anything can decide, and it is an uncrossed one: with the same prompt in
the same directory and only the hook's verdict differing, a marker planted in
the skill body crossed once where the hook allowed and zero times where it
denied.

The payload test cannot see any of that. What the payload carries is a name
the harness resolves, and resolving it back is not a field-level operation:
`probe-skill` resolved under the project's own `.claude/skills/`, and `brevity`
in the same session resolved to `/Users/karl/.claude/skills/brevity`, outside
the project root. A resolver here would have to reproduce a search order this
repo has not driven — and getting it wrong reports clean on a file nothing
opened, which is the failure this project indicts its predecessor for, while
failing closed on it blocks every skill invocation in every session. **So the
member stays out, and the reason is resolution rather than bounding.**

**A subagent load is not a member and needs nothing.** `Agent` carries a prompt
the model composed, so its own payload has already crossed. What the subagent
reads afterwards is covered, because its tool calls fire the same hooks: one
`Explore` agent issued five `Bash` calls and all five reached the hook, under
the parent's `session_id` and carrying an `agent_id` the parent's own calls do
not have. [What this is not](#what-it-is-not) named a skill or subagent load as
one uncovered member. It is two, and only one of them was ever uncovered.

**The search tool is the member that cannot be bounded, and this machine has
none.** A search takes a pattern and a root and returns matching lines from
files it chooses, so bounding it means scanning the tree, which is not
something a `PreToolUse` hook can do per call. The drive does not touch that
argument. What it adds is that neither `Grep` nor `Glob` was in the tool set at
all: a session asked to search file contents reached `ToolSearch` for
`select:Grep,Glob`, got nothing back, and reported it had neither. The search
affordance that is present is the `Explore` subagent, which is the paragraph
above.

**What a fourth member has to establish.** An MCP server's file reader is
undriven and is the shape most likely to be one. Three readings settle a
candidate, in this order, because each is cheap only where the one before it
came back yes:

1. **Does the hook see the call at all?** A matcher of `*` and a stdin log.
2. **Has the content crossed already?** Only what the hook can open for itself
   is stoppable, and a deny that leaves the marker in the transcript says it
   was not.
3. **Can the hook bound what the call would return?** One file is bounded. A
   tree walk is not, and neither is a name the harness resolves by a rule
   nobody here has driven.

## Pipeline

Per buffer, in order. Each stage exists to keep the next one off work it does
not need to do.

1. **Decode what declares itself.** A UTF-16 byte-order mark — `FF FE` or
   `FE FF` — is decoded to UTF-8 and the rest of the pipeline reads that. A
   mark is a declaration the file makes about itself, not an inference drawn
   from its bytes, so this settles nothing the NUL check below stays out of.
   Windows PowerShell 5.1 is the file class it is for: `>`, `>>` and
   `Out-File` write UTF-16LE, and every Unicode encoding but UTF-7 writes a
   mark, so the encoding a Windows script leaves behind always says what it
   is — [`about_Character_Encoding`][psenc], read 2026-08-27, and the citation
   is here rather than in a commit message because it is the only evidence
   this repository has for the claim: there is no `pwsh` on the runners or on
   a maintainer's Mac, so nothing can drive it. PowerShell 6 and later default
   to `utf8NoBOM`, which has no NUL and always scanned. `Start-Transcript` is
   the near miss worth naming: it writes UTF-8 with a mark, not UTF-16, so a
   transcript is only in this class when a program's output was redirected
   into it. `FF FE 00 00` is UTF-32LE and opens with the whole UTF-16LE mark,
   so the longer mark is tested first and named rather than decoded.

[psenc]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding

   A finding reports a byte offset, so a decoded match is mapped back to the
   offset in the file. The decode and the map are one walk over the code
   units, which is what stops them disagreeing.

2. **Skip binaries.** A NUL byte in the first 8 KiB of what step 1 produced
   means skip. In the benchmark corpus one PNG was 55% of all bytes, and the
   three language prototypes disagreed on it because Go keeps raw bytes where
   Rust and Python substitute U+FFFD.

   This stage is cheap and it has to stay ahead of the expensive ones, which
   is a constraint on step 1 rather than on this one: a decode that runs to
   the end of the buffer before anything decides to skip it inverts the whole
   reason for the order. So the decode produces the sniff window first, this
   check reads it, and the rest of the buffer is decoded only if it passes.
   The window is a decision identical to the whole buffer's, not an
   approximation of it, because this check never reads past 8 KiB. Measured
   2026-08-27 on a 64 MiB UTF-16 buffer whose fourth character is a NUL:
   189 ms and 32 MiB allocated and discarded, against a bound of 1 MiB the
   test now holds it to.

   UTF-16 written with no mark still lands here and is still skipped. Nothing
   in such a buffer declares its encoding, and the alternative — reading
   alternating NULs across the sniff window as UTF-16 rather than as binary —
   is exactly the heuristic the NUL check was chosen instead of. It is a
   stated gap rather than a silent one, which is what step 6 is for.

   A caller whose buffer crosses whatever this returns takes a second entry
   point, which runs the match loop over the raw bytes and reports the skip
   beside the findings rather than instead of them. The trade above is about
   work, and there is none to save once the bytes are on their way. Only a
   prompt does that today — [a buffer whose bytes cross
   anyway](#a-buffer-whose-bytes-cross-anyway-measured) has the cost table that
   keeps the other two surfaces on the skip.

   The check gives two reasons, not one, and which it gives is decided by
   whether step 1 decoded. A buffer whose UTF-16 mark this stage read, and
   whose *decoded* window then holds a NUL, is still skipped and by this same
   check — but its text was read before the NUL was found, where the other
   class's was not. Step 6 keys on that, so the two cannot share a reason
   without the verdict losing the thing it routes on.

   **Declaration is the axis, and step 1 reads two of the three marks — UTF-8's
   is a declaration it does not read.** That is a gap rather than a decision,
   and it is a measured fail-open rather than a nicety.
   `EF BB BF` is a byte-order mark by the same registry as `FF FE`, declares
   UTF-8, and is what PowerShell 7's `Out-File -Encoding utf8BOM`, Notepad and
   Visual Studio emit. Step 1 has no arm for it, so such a buffer reaches this
   check undecoded, its NUL is read raw, and it is skipped and allowed exactly
   as an image is. Driven end to end on a built binary: a UTF-8 mark, a NUL and
   an AWS-shaped key exits 0 on empty stdout, while the same file without the
   NUL denies and names the rule — at byte 29 against 26, the three bytes of the
   mark, which is its own evidence that nothing decoded it.

   Whether step 1 should grow that arm is a separate question, and `Q102`
   carries it rather than this section. The mark alone cannot be the trigger:
   63 files in this machine's Go module cache carry `EF BB BF` and 61 are
   ordinary text — `.html`, `.yaml`, `.md`, `.json`, `.env` and a
   Windows-authored `.wxs` among them. Of the 2 that also carry a NUL, both are
   `.wasm`.

   **That is a cost reading and it does not bound the benefit.** It says what an
   arm on mark-plus-NUL would cost here; it says nothing about how often a
   Windows-authored file carries the mark, a NUL and a credential, because that
   population is exactly as unobservable on these machines as the UTF-16 one.

3. **Literal prefilter.** Word-boundary search for each credential rule's
   keywords, 255–307 MiB/s against 1.0 MiB/s for the regex pass — roughly 280x.
   Use word boundaries, not `strings.Contains`: naive matching finds `sk-`
   inside `disk-containerd-…`, and one broad keyword (`AC`) took the file hit
   rate from 1.2% to 18.9% on real files. The prefilter gates the credential
   family only. Numeric PII rules have no literal to anchor on, which is one
   reason they ship disabled.

4. **Match, one rule at a time.** Never fold the patterns into a single
   alternation. Measured at 0.5x in Go and 0.7x in Rust: the DFA state space
   explodes and the lazy-DFA cache thrashes on heterogeneous input. Two engines,
   same result.

   **Where every match a rule can produce begins at one of its keywords, it
   runs at the positions step 3 found rather than over the buffer.** Eight of
   the ten enabled rules open on `\b`, which is an empty-width op at the head
   of the compiled program: `regexp` derives no literal prefix from it, so it
   has nothing to skip towards and runs the NFA over every byte to arrive back
   at positions the prefilter had already found and thrown away. Deleting the
   `\b` is not the repair — it is what keeps `ghp_` from matching inside
   `xghp_`, and precision is the product. Keeping the positions is.

   Measured 2026-09-04 over this repository's own text, 1,355,099 bytes in 172
   files, which names every keyword the ruleset gates on and so clears every
   prefilter: the shipped set goes from 7.12 MB/s to 32.09 MB/s, and per rule
   from 49.8–62.7 MB/s to 181–4,790 MB/s. Both arms are in
   `internal/scan/bench_test.go`, one binary over one buffer, and it refuses to
   time them until they report the same findings.

   Five conditions decide it and none is about speed. Four belong to the loader
   (`internal/rules/anchor.go`): the pattern opens on `\b`, nothing in it asks
   where the text begins, every string it can match begins with one of the
   keywords, and its longest match is bounded. The fifth is
   `internal/scan/prefilter.go`'s, because it is about the boundary that file
   checks — every keyword opens on a word byte, without which a hit and the
   pattern's own `\b` are different predicates in both directions.

   The bound is what excludes `jwt`, and it is a cost condition rather than a
   correctness one. `eyJ[A-Za-z0-9_-]{8,}` keeps the engine's threads alive for
   as long as the class matches, so one attempt reads to the end of the buffer:
   on 64 KiB of `-eyJ` repeated — a hit every four bytes, and every byte in the
   class — running it at each hit took 29.8 s against 12.2 ms for one
   whole-buffer pass.

   A bounded rule can still be handed more hits than they are worth, so the
   loop counts them first. One attempt reads at most the rule's reach and the
   pass reads the buffer once, so past `len(buf) / (reach + 8)` hits the pass is
   the cheaper arm and it runs. That charges every attempt its worst case, which
   most do not spend, and the direction is deliberate: over-charging costs
   throughput on a buffer nobody has, and under-charging costs it on every
   buffer, in the arm nothing measures.

5. **Validate.** This is where precision comes from, and regex is not where it
   lives:

   | Name in `validators` | Check | Applies to |
   |---|---|---|
   | `luhn` | Luhn checksum | Payment cards |
   | `card-placeholder` | Denylist of the published test numbers and repeated-digit runs Luhn accepts | Payment cards, beside `luhn` |
   | `aws-placeholder` | Rejects a key ID ending in `EXAMPLE`, the mark AWS puts on the credentials in its own documentation | `aws-access-key-id`, beside `entropy` |
   | `jwt-sample-key` | Recomputes the HMAC and rejects a token that verifies under a published sample signing key | `jwt`, beside `entropy` |
   | `mod-11` | ISO 7064 MOD 11-2 | National ID numbers |
   | `entropy` | Shannon floor, read from the rule's `entropy` | High-entropy credential candidates |
   | `reserved-range` | Reserved-range exclusion | IP rules — RFC1918, loopback, link-local, documentation ranges, `0.0.0.0` |
   | `context-label` | Proximity to one of the rule's `labels` | Bare numeric runs, which count only near a label like `phone:` or `ssn=` |

6. **Report.** Rule ID, path, byte offset. Nothing else — and, beside the
   findings, whether the buffer was read at all. A scanner that reports an
   unread file the way it reports a file it read and found nothing in reports
   a safety it is not providing, so every path that declines to read names its
   reason and the caller carries that as far as the user.

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
| `keywords` | Word-boundary literals for the prefilter. Empty means ungated, which is expensive — say so deliberately. A keyword at the head of every match the rule can produce is what lets [the pipeline](#pipeline) run the rule at those positions instead of over the buffer; one further in still gates, and pays a full pass. |
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

The bound has two terms and takes the smaller. Both come off the rule's own
regex.

The length term is the **longest** string the group can capture rather than the
shortest. A group matching 8 to 64 bytes allows 3 bits at its shortest and 6 at
its longest, so measuring the shortest would refuse a working rule at startup —
the failure this check exists to prevent, pointed the other way.

The alphabet term is how many distinct byte values the group can draw on, since
a capture holds at most that many however long it runs. `[a-f0-9]{32}` is capped
at log2(16) = 4 bits rather than the log2(32) = 5 its length allows, so a floor
of 4.5 on a hex key rule is refused rather than loaded dead. That floor is the
base64 threshold carried over onto a hex charset, which is the ordinary way to
write the mistake rather than a constructed one.

Both terms over-estimate rather than under-estimate, because the two errors are
not symmetric: missing a dead rule leaves this check half-done, while refusing a
live one takes the scanner down. An operator neither walk names widens — to 256
bytes on the length, to every byte value on the alphabet.

The slack left over is a union that knows which symbols the group can emit and
not which of them co-occur in one match. `(a{6}|b{6})` unions to two symbols and
caps at 1 bit, where every string it matches is one repeated symbol at Shannon
0. `(?:ab){1,3}` is not that case: six bytes over two symbols caps it at 1 bit,
which `ababab` reaches exactly.

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

### An unread buffer is not a clean one, and the two reasons are not alike

Step 6 has every path that declines to read name its reason. What the hook does
with that reason is a second decision, and it comes out differently for the two
the pipeline can give. The axis is the one step 1 already runs on: a byte-order
mark is a declaration the buffer makes about itself, and a NUL in the sniff
window is an inference drawn from its bytes. What blocks is a buffer that
declared itself text and could not be read.

**A declared encoding this build cannot decode blocks.** A UTF-32 mark says the
file is text, so the class is text by declaration and credential-shaped bytes
can be in it. The skip is a decoder this build does not have rather than a trade
it made — step 1 names the encoding because no measurement said the class was
worth carrying. Blocking costs close to nothing, because close to nothing is
written in UTF-32, and the reason names a remedy: convert the file, or override.

**The binary skip does not block.** That one *is* the trade, and step 2 took it
against a measurement — one PNG was 55% of the benchmark corpus. Denying every
image read is not a convenience cost: a hook that does it gets uninstalled, and
an uninstalled scanner enforces nothing, which lands on the same side of the
ledger as failing open.

#### An allowed skip says so, and the channel for saying it is measured

Not blocking is not the same as not saying. Step 6 asks every path that
declines to read to name its reason and have the caller carry that as far as
the user, and an allow meant exit 0 on an empty stdout — the one silence the
hook produces that is not a scan which ran. It now writes a `systemMessage`
naming the buffer and the reason, and the call goes through carrying it.

Which field does that is a measurement rather than a reading of the docs.
Driven 2026-09-01 against Claude Code 2.1.251 on darwin/arm64: seven arms of a
real `UserPromptSubmit` hook in a throwaway project, each emitting one marker
one way, read back out of the `--output-format stream-json` stream and the
session transcript both.

| The hook writes (exit 0 unless noted) | The stream | The transcript |
|---|---|---|
| nothing — the control | — | — |
| the marker on stderr | — | — |
| the marker on stderr, exit 1 | — | `hook_non_blocking_error` |
| the marker on stdout, as plain text | — | `hook_success`, injected as context |
| `{"systemMessage": marker}` | `system`/`informational`, `level` `notice` | `hook_system_message` |
| `{"…additionalContext": marker}` | — | `hook_additional_context` |

**Of the six driven, `systemMessage` is the only one that reaches the
person.** The two that carry
text to the model — `additionalContext` and a hook's plain stdout — reach it
while telling nobody, and a hook's stderr on exit 0 reaches neither: absent from
the stream, absent from the transcript, absent from the session. The
`systemMessage` rows are the control for the blanks, since the same instrument
found the marker there. None of the seven withheld anything; the `systemMessage`
arm's transcript carries the user message and reaches the same next step the
control does.

**Routing it to the person rather than the model is the decision, not a
detail.** The remedies are a human's to take — convert the file, arm an
override — and the model can take neither. The same text sent to the model
would be spent on every image read: 59 of the 1,878 distinct `Read` targets in
this machine's transcripts that still exist on disk are binary, 58 of them PNGs
and one a PDF. Targets that did not survive are outside that denominator, so it
is a rate over durable files rather than over all reads.

**The notice names the two text populations, because the reason cannot.**
`SkippedBinary` is one reason over a NUL in the sniff window, so UTF-16 written
with no byte-order mark and a UTF-8 mark ahead of a NUL both arrive wearing a
screenshot's label. Naming them is what lets a reader who knows their file is
text act on a notice that says *binary* — and it is why this closes both
members without deciding anything about the UTF-8 decode arm, which is `Q102`.
A prompt now matches the raw bytes as well, which reaches the UTF-8 member's
credential without a decode arm and does nothing for the UTF-16 one, whose key
is a NUL to the byte. The notice is what both still get.

**`PreToolUse` takes the same field, and it is driven rather than inferred.**
An earlier revision of this section reasoned that it was safe to emit there
without a measurement, because `claude -p` could not authenticate on the machine
at the time and the exit-code table already rules out the direction that
matters. The measurement was taken once the CLI could log in again, on a `Bash`
call, and it agrees:

| the hook writes on `PreToolUse` | the stream | the transcript | the call |
|---|---|---|---|
| nothing — the control | — | — | runs |
| `{"systemMessage": marker}` | `PreToolUse:Bash says: <marker>`, `level` `notice` | `hook_system_message`, `hookEvent` `PreToolUse` | runs |

Both arms' `tool_result` carries the command's own marker, so the field informs
without withholding on this event too. The control shows no marker of ours and
does show an unrelated `UserPromptSubmit` notice, which is what says the reader
was working on the run that found nothing.

So `systemMessage` is **not** per event the way the block encodings are, and one
field serves both. That is worth stating explicitly, because everything else
about hook output in this document is per event, and the reasonable prior — the
one this section held for a day — was that this would be too.

It also explains the corpus zero rather than leaving it hanging: across 1,654
session transcripts here, all 407 `hook_system_message` attachments carried
`UserPromptSubmit` or `Stop`, and none carried `PreToolUse` because no installed
hook had ever emitted one there. The population was empty, not the capability.

#### A blocking verdict carries the notice too, on a channel that is per event

The notice above fires on the one branch that neither blocked nor scanned. A
call that *also* blocks — findings in one buffer, an allowed skip in another —
said so to the model and nothing to the person, and `found()`'s own sentence,
*N rule match(es) in what this call would have sent*, is a claim about coverage
that only a call every buffer of which was read can make. Any multi-buffer call
reaches it: a `Bash` segment naming a `.env` and a `.png`, or a prompt carrying
`@deploy.env` and `@logo.png`, blocks on the first and was silent about the
second.

Putting a `systemMessage` beside a decision object changes an encoding this
document measured rather than reasoned about, so it was driven before it was
written. Driven 2026-09-03 against Claude Code 2.1.251 on darwin/arm64, nine
arms of a real hook in a throwaway project, read back out of
`--output-format stream-json`. The four arms that emitted the field were read
in the session transcript as well, where each arrives as the
`hook_system_message` attachment Q84 measured, or does not:

| The hook writes on `PreToolUse` (Bash) | The person is shown | The call |
|---|---|---|
| nothing — the control | — | runs |
| a deny object alone | — | blocked |
| a deny object + `systemMessage` | the notice, `level` `notice` | blocked |
| an ask object + `systemMessage` | the notice, `level` `notice` | withheld |
| `systemMessage` alone — the control | the notice, `level` `notice` | runs |

| The hook writes on `UserPromptSubmit` | The person is shown | The prompt |
|---|---|---|
| nothing — the control | — | runs |
| `{"decision":"block","reason":…}` | the reason, `level` `warning` | blocked |
| the same, plus `systemMessage` | the reason. **Nothing of the field** | blocked |
| `systemMessage` alone — the control | the notice, `level` `notice` | runs |

**So the field is per event once a decision object is beside it, and the
section above is not wrong about the case it measured.** `systemMessage` alone
serves both events; beside a block on `UserPromptSubmit` it is dropped without
a word. The two `systemMessage`-alone rows are the control for that blank, and
each event's block-alone row is the control that says the arm blocked at all.

**That event needs no field, which is why this is a routing choice rather than
a gap.** Its block reason is itself shown to the person, as `UserPromptSubmit
operation blocked by hook: …` at `level` `warning` — something the `PreToolUse`
deny reason does not do, where the reason reaches the model and the person sees
it only if the model repeats it. So the notice joins the reason there and rides
its own field here, and on both events it lands in front of the person who can
act on it. `carry` in `internal/hook/verdict.go` is that one decision, and the
verdicts on either side of it do not re-derive it.

**The notice still reports that nothing looked.** It says what went unread and
refuses to say anything about what did not: *no verdict on this call is a
report on its text — a buffer nothing decoded is never reported as a clean
one*. Reading it as coverage is the failure this whole section exists against,
and a block beside it makes that reading easier rather than harder, because the
block sounds like a verdict on the call.

**The claim is about the buffer's text, not about whether anything looked at
its bytes**, and the two come apart the moment a buffer can be matched without
being decoded. Q118 drove the merge of that capability against the earlier
wording and read back a block reason that named a finding *in* a file and then
said no verdict covered it — one paragraph, both halves true of a different
verb, and a green suite behind them. So the sentence is written against the
distinction that survives, which is *decoded*.

The confirmation takes it for a sharper reason than the block does. An override
downgrades a block to an ask, and approving is the whole of what that prompt is
for: a human told what they are about to send and not told what nothing opened
is approving a coverage nobody has.

The residue was two populations rather than one, and one of them is now closed.
UTF-16 written with no mark lands in the binary skip and is allowed with it —
step 2's own stated gap, where nothing declares anything and separating it is
the heuristic the NUL check was chosen instead of. That one stands. The second
*did* declare itself: a UTF-16 mark whose decoded sniff window holds a `U+0000`
is classified as binary deliberately, after the decode, on the rule that a NUL
in decoded text describes the text rather than the encoding. It satisfied the
description of what blocks and was allowed anyway, because step 2 routed on
decoded content where this routes on declaration and one skip reason stood for
both.

#### A declared encoding whose decoded text is binary blocks

Step 2 gives that case its own reason now, so it arrives here as a reason
nothing was taught and blocks on the fail-closed default. The classification is
untouched — the buffer is still binary, and still binary because of its decoded
content, which is step 2's rule read on its own terms and was never the thing in
dispute. What a separate reason adds is the declaration, which is what this
verdict has always routed on.

**The argument is not how often the class turns up, and this repository cannot
find out.** Measured 2026-08-31, twice. Over the same session corpus as the
section below: 2 of 40,416 `Bash` operands carry a UTF-16 mark, neither of them
decoding to binary, and the `Read` and prompt surfaces have none at all. Over
`~/go/pkg/mod` and this repository's own tree — 245,397 files, every marked one
listed rather than sampled — 43 carry a UTF-16 mark, **none** decodes to binary,
and nothing carries a UTF-32 mark. Widened to `~/workspace`, `~/.claude`, `~/go`
and the Go toolchain, 6,589,166 files, the shape is the same: 45 marked, none
decoding to binary, no UTF-32 mark, and every organic one still in the module
cache.

**21 of those 43 are organic**, in seven unrelated modules: `subosito/gotenv`,
`docker/cli`, `golang.org/x/net`'s `html/charset`, `gopkg.in/ini.v1`,
`aws/smithy-go`, `BurntSushi/toml` and `Azure/go-autorest`. So a byte-order mark
is not itself a Windows artifact, on a machine with no `pwsh` at all. The other
22 are copies of this repository's planted fixture across worktrees, and that
count moves as worktrees come and go.

An earlier draft of this paragraph said every marked file was one of ours. That
was read off the first 25 of a listing the walk had ordered by root, so the
module cache never entered the sample — the fixtures were simply first. The
correction is why the sentence now names a fully enumerated population.

Both are close to worthless as a measure of how often the class turns up, and
step 1 says why: the file class the decode exists for is Windows PowerShell 5.1,
and there is no `pwsh` on the runners or on a maintainer's Mac. A near-zero
drawn from machines that cannot produce the population is not evidence the
population is rare — it is a measurement of the platform. So the case for the
split had to be made on something other than frequency.

What the 43 do establish is the **cost**, which is a different question and one
this machine can answer. Every one of them is `Scanned` — they decode as UTF-16
and their sniff windows hold no NUL — so not one changes verdict under this
change. The flip costs nothing on the only marked-file population observable
here. Note what that is not: it is not evidence about the newly-blocked class,
which has zero organic observations, and the two must not be run together.

**What settles it is `FF FE 00 00`.** Those bytes are the UTF-32LE mark and
equally a UTF-16LE mark followed by `U+0000`, and step 1 resolves them
longer-mark-first because that is what the Unicode standard says to do. Before
the split, that resolution decided *block against allow*: a UTF-16LE buffer
whose first character was a `U+0000` took the UTF-32 arm and blocked, while the
same buffer with the `U+0000` one character later took the binary skip and was
allowed. Two neighbours, the same encoding, the same credential, opposite
verdicts, and the only difference between them an ambiguity nobody here chose.
Now both block, and the two readings differ only over which encoding to name —
the most such an ambiguity should ever cost.
`TestAUTF16NULIsNamedAsDeclaredWhereverItSits` is that pair. Undo the split and
it fails on the `NUL second` arm alone: `NUL first` stays green, because it
never went through the UTF-16 branch.

#### The verdict is per reason and not per surface, measured

The binary allow is argued from `Read`, where an image is opened on purpose.
The reason is what the hook is handed; the surface is not, so the allow reaches
`Bash` operands and prompt `@` targets on an argument that was never about
them. The case for a second axis is that those populations look different —
nobody `cat`s a PNG by accident, and what a reader is pointed at when the
operand *is* binary might be a heap dump with a token in it.

Measured 2026-08-31 over the 1,580 session transcripts under
`~/.claude/projects/` (898,099 records, 128,963 `Bash` calls, 12,271 typed
prompts) by running this repository's own `bashTargets`, `promptTargets` and
`scan.Buffer` over every call in them and classifying each buffer the way the
pipeline would:

| Surface | Buffers reaching the pipeline | Skipped binary | Rate |
|---|---|---|---|
| `Bash` operands | 40,416 | 21 | 0.052% |
| prompt `@` targets | 130 | 4 — *all of them fixtures this repo wrote* | 3.1%, and none of it organic |
| `Read` `file_path` | 3,026 | 96 | 3.2% |

Read the prompt row with its caveat attached. At 3.1% beside `Read`'s 3.2% it
invites the reading that the two surfaces behave alike, and they are as unlike
as the corpus can make them: strike the fixtures and the row is 0 of 126.

The rates are not what settles it. What those 21 and 4 buffers *are*, is:

- All 21 `Bash` buffers are an executable or an image somebody opened on
  purpose: the Claude Code binary itself 13 times, `powermetrics` 4, two
  favicons, and one `.dylib` a sibling repository built for a trace probe.
- All 4 prompt buffers are this repository's own fixtures — two `logo.png` and
  two `heap.dump`, written into worktree scratchpads by the sessions that drove
  the `@` measurement above. Nothing organic was observed in 881 `@` tokens.

  That denominator needs the same name sweep the `Bash` bullet below describes,
  and for a sharper reason. `promptTargets` skips a token whose file is gone, so
  the content sweep classified 130 buffers out of 881 tokens — 14.8% of its own
  denominator, worse attrition than the `Bash` arm's. Sweeping all 881 by name
  instead, deleted targets included, returns four binary-shaped names and they
  are the same four fixtures: `heap.dump` twice and `logo.png` twice.

  The remainder is `.txt`, `.head`, `.md`, `.zshrc` and extensionless paths —
  and five `.env` tokens, which are two names in two prompts rather than five
  occasions. Four of them are `deploy.env`, `deploy.env-`, `deploy.env#` and
  `deploy.env%%`, typed in one prompt to the millisecond to drive the
  punctuation trim; the fifth is `secret.env`. Both are fixtures, and by where
  they came from rather than by what they are called: every prompt in the corpus
  naming an `@…env` token sits in a `claude-spill-guard` worktree or its
  scratchpad. So are the `.txtzzz` and zero-width-suffixed tokens the grammar
  drives left behind.

  **None observed is not a rate of zero.** Nought events in 881 puts the 95%
  upper bound near 0.34%, so what the corpus supports is that nothing organic
  turned up, not that nothing organic exists. It changes no decision here — the
  residue routes to Q84 regardless of surface — and it is the sentence most
  likely to be quoted later as though it were a measured rate.

  The self-reference cuts three ways and the third is the one worth writing
  down. It does not make the defect unreal: the crossing happens and step 2
  still skips those bytes. It does make frequency the wrong axis, which is what
  the row said. And it leaves the prompt arm with no organic data in *either*
  direction — an absence of events rather than a low rate, which is normally a
  weak thing to decide on. Here it is the criterion the row itself set.

  It is also wider than the binary targets. Once the `.env` tokens are counted,
  **every security-shaped token in these 881 is one this project wrote**, and
  the organic remainder is `.txt`, `.head`, `.md`, `.zshrc` and paths with no
  extension. That is the honest statement of what this corpus can support: not
  that credential-shaped prompt traffic is rare, but that there is none of it
  here to measure, because the only sessions that produced any were the ones
  driving this scanner.

  **Reviewing this section demonstrated it.** The counts above were taken at 881
  `@` tokens and 5 `.env` names. Re-running the same census while the change was
  under review returned 883 and 7, and the entire delta is one prompt — a
  message between two sessions arguing about this paragraph, in which the phrase
  `@…env` is itself taken as a file token. Two more security-shaped tokens
  entered the corpus while the pull request adding this sentence was open, and
  both came from the sessions reviewing it. That is not a caveat about the
  numbers going stale. It is the finding, and it is about the numerator rather
  than the denominator: **the security-shaped count moves whenever this
  repository is worked on and does not otherwise.**

  The token total is not that count and does not behave that way. Of the 883,
  365 come from `claude-spill-guard` sessions and 518 from everything else,
  `github-actions-gateway` alone contributing 356 — so ordinary work on other
  projects moves the denominator, as it should. What it has never once moved is
  the numerator: every `.env` name and every binary `@` target traces to a
  `claude-spill-guard` worktree or its scratchpad. A corpus with organic `@`
  traffic and no organic *credential-shaped* `@` traffic is exactly the shape
  that makes a frequency argument unavailable here.
- The population the split exists to catch is absent. The table classifies
  files as they stand today, and 37,710 of the 83,141 resolvable operands point
  at something since deleted — which is exactly what a heap dump does, so the
  content sweep alone would not settle this. A second sweep over the operand
  *names* covers the deleted ones, because a name survives its file: of 103,330
  file operands named across those `Bash` calls, resolvable or not and present
  or not, **none** is a `.dump`, a `.pack`, an SQLite file or a core file.
  Fourteen carry a binary-shaped name at all, and eight of those are images.

So a surface split would fire 25 times in that corpus, block the wrong thing 23
of them, and catch two files this project wrote to demonstrate the defect. That
is not a second policy this repository can keep true. The verdict stays keyed on
the reason alone.

**Read the whole of it as a dated reading rather than a property of the tree.**
It is one maintainer's agent sessions on one machine, no gate re-runs it, and
nothing in CI can: the transcripts are not in the repository. "The population is
absent" means absent from this corpus, whose composition shows what it is — the
commonest `Bash` operand extensions are `.log`, `.md`, `.go`, `.sh` and `.py`.
A forensics or data-science user reads differently and this cannot speak for
them. That bounds the claim rather than undermining it, because the tool is a
net for the accident rather than a wall against intent, and accidental frequency
is what an ordinary-session corpus measures well.

What the measurement does not retire is the crossing. A binary buffer carrying
a credential is still allowed on every surface, and the remedy the corpus
supports is telling the user the buffer went unread — which needs no ruling on
which surface it happened on, and is Q84 rather than this. It is no longer
allowed in silence, and on a prompt it is no longer unread: the section below
is the third answer this one did not weigh.

A reason the hook has not been taught blocks. `internal/scan` can grow one
without `internal/hook` being told, and of the two directions that mismatch can
fail in, only one of them ships a scanner that waves a buffer through.

#### A buffer whose bytes cross anyway, measured

The section above settles the verdict and leaves the crossing open. It weighed
two answers, block and allow, and there is a third: a scanner can **match**
such a buffer, which costs no verdict at all — a raw pass over an image finds
nothing and the call goes through.

That option stayed out of view because the binary skip reads as a judgement
about what the bytes are when it is a trade about work. One PNG was 55% of the
benchmark corpus in [`language-choice.md`](language-choice.md) against a regex
pass at 1.0 MiB/s, so the pipeline declines the buffer rather than spend the
loop on it. Where the bytes are already on their way there is nothing to trade.
A prompt `@` token is that case: the harness splices the file into the context
whole, NUL included, so it has been read off disk and the crossing happens
whatever the hook returns.

**The trade is still real on the other two surfaces, which is why this is a
second entry point rather than a change to the skip.** Measured 2026-09-03 on
darwin/arm64 over 4,000 binary files under `/usr/bin`, `/usr/lib`,
`~/go/pkg/mod` and `/System/Applications` — 1,414.7 MiB, matched raw against the
shipped ruleset:

| | |
|---|---|
| aggregate throughput | 17.4 MiB/s |
| files where any rule passed the prefilter | 249 of 4,000 |
| findings | 0 |
| slowest file | a 75.3 MiB git pack, 8.2s, 4 rules ran |
| the Claude Code binary, 2.1.238 | 306.4 MiB, **36.5s**, 9 rules ran |
| the Claude Code binary, 2.1.251 | 188.0 MiB, 24.8s, 9 rules ran |

The last two rows decide it. That binary is the commonest binary `Bash` operand
in the corpus above — 13 of the 21 — and 36.5s of match loop against a
60-second hook timeout is not a cost to take where the population is real. On
the prompt surface the population is empty: of 881 `@` tokens, the only
binary-shaped names are four fixtures this repository wrote.

The 0 is a measurement rather than a silence. The same probe over a 54-byte
binary fixture holding an AWS-shaped key returns one finding, so it can come
back non-empty.

**The crossing does not separate the surfaces, and the argument that said it
did was wrong.** Q118 proposed that the harness had decided such a file is text
on this surface and not elsewhere. Driven 2026-09-03 against Claude Code
2.1.251, a `Read` of the same NUL-bearing file returned its content whole with
a marker past the NUL intact — so `Read` crosses exactly as a splice does, and
what separates the two is the cost table above and nothing else.

**It is coverage and not a second verdict axis.** `blocks()` still takes a
reason and never an event, `scan.ScannedRaw` allows for `scan.SkippedBinary`'s
reason, and the notice still goes out. What moved is which entry point
`scanCall` picks, chosen by whether the trade has anything left to trade rather
than by what a call is allowed to do.

**The notice survives the scan, because a raw pass is not a decode.** The sniff
cannot tell an image from text this build does not read — UTF-16 with no
byte-order mark, a UTF-8 mark ahead of a NUL — and a raw pass over the second
finds nothing whatever is written in it. So a matched buffer is still reported
as one nothing decoded, and the sentence moved from *nothing scanned this* to
*nothing decoded this*: the property both populations share, and the one a
reader has a remedy for.

**It over-reads, on the precedent this document already set.** A text splice is
bounded at 2,000 lines and a directory listing at 1,000 entries, and the
resolver reads the whole file and the whole directory anyway: where the harness
sends a subset, reading all of it reports bytes the harness did not send, and
only the other direction can report a clean result for something that crossed.
The binary row is where the bound is unmeasured — `heap.dump` crossed whole,
and a file with few newlines has few lines to be capped at — so the resolver
reads what is there.

**The match is bounded even though the read is not, and that bound is what
keeps this from being a regression.** Measured 2026-09-03 on a buffer carrying
every keyword the shipped ruleset gates on, so nothing prefilters away: the raw
pass ran at 6.8 MiB/s and crossed the 60-second hook timeout at about 410 MiB.
[Pipeline step 4](#pipeline) has since moved that rate by 5.8x, which moves the
crossing with it and leaves every figure below a larger margin than the one it
was chosen against.
Past that timeout the hook is killed and writes nothing at all, so an unbounded
raw pass would take a buffer the skip reports in 44 ms and make it one nobody
hears about — trading the notice for silence, which is the direction this
design does not go. `scan.rawLimit` is 32 MiB, which the rate puts at 4.7 s of
match loop and a driven hook puts at 4.3 s of wall clock — a buffer of exactly
that size carrying every keyword, with the key in its last bytes so the loop
cannot stop early. Fourteen times inside the timeout. Above it the answer is
`SkippedBinary` and the notice goes out exactly as it does without this entry
point, so coverage is added below the limit and nothing is taken away above it.

A size limit rather than a deadline, and the two turned out not to be
alternatives. Nothing inside the pipeline can be interrupted — the match loop
and `os.ReadFile` both take no context — so a deadline written here could only
be a check between rules, and one pass over a 306 MiB buffer is the granularity
that defeats that.
[The budget](#the-scanners-own-budget-and-overrunning-it-blocks) sits a layer up
and works by outrunning the scan rather than by stopping it. It does not retire
this limit, because the two answer differently above their thresholds: past the
budget the verdict is a block, and past this limit it is the allow the skip
already gives, with the notice out in 39ms. For a 306 MiB executable that is the
right answer and a block is not.

What this closes is one surface. A credential in a binary-looking `@` target
blocks, and so does one behind a UTF-8 byte-order mark ahead of a NUL, which is
[Q102](../queue/Q102.md)'s member reached without a decode arm — on a prompt
only. On `Read` and `Bash` both are still allowed with a notice, and
`docs/releases/` says so.

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

**A deny on stdout outranks the exit code — on `PreToolUse`.** The same `deny`
object blocked the call on exits 0, 1, 9 and 127, and the reason reached the
model byte-identical in all four. So a launcher that writes its deny and then
dies still blocks, which is the one shape here that fails closed on its own.
Prefer it *for the event it was measured on*, and read the next paragraph before
writing it anywhere else.

**The encoding is per event, and generalising this row fails open on the one a
human types into.** On `UserPromptSubmit` a `permissionDecision` of `deny` is
accepted and ignored, and **naming the event correctly does not rescue it** — an
object stamped `"hookEventName": "UserPromptSubmit"` is ignored exactly as one
stamped `PreToolUse` is, both around 22 KB with the marker twice in each. Read
the marker count rather than the byte total: transcript size varies by kilobytes
across runs of the same arm, so a pair of exact sizes reads as a signature and is
not one. `permissionDecision` has no meaning on that event whatever it is labelled,
so the shape that blocks there is `decision: block`. That clause is here because
the obvious repair for the sentence before it is to fix the event name, and that
repair does nothing. The encoder and the full table belong with the `hook`
subcommand that writes them; what matters here is that the sentence above stops
at `PreToolUse`.

The reading this section needs is the one about `@path`, because
[the operand](#path-is-an-operand-not-a-hop) rides in on that event. Driven
2026-08-27 on 2.1.238 with a prompt naming `@secret.txt`, reading the session
transcript rather than stdout: with a `deny` object the transcript is 22,086
bytes and the file's marker appears twice; with `{"decision":"block"}` it is
1,214 bytes with the marker absent; with exit 2, 1,404 bytes, absent. So both
working encodings suppress the splice and not merely the prompt, and the
recommended one suppresses neither.

**On exit 2 the reason travels on stderr, and stdout is discarded.** A hook that
writes `spill-guard: blocked ...` to stdout and exits 2 stops the call and tells
the model nothing about why. The `deny` object has no such trap, and no
`PreToolUse:Bash hook error: [<path>]:` prefix wrapped around its reason.

### The block encoding is per event, and the wrong one fails open

Measured 2026-08-27 against Claude Code 2.1.238 on darwin/arm64, the same way:
a real hook in a throwaway project, `--output-format stream-json` read for
whether the content reached the model. The `PreToolUse` column re-drives the
table above on the newer version and agrees with it.

| Hook writes | `PreToolUse` on `Bash` | `UserPromptSubmit` |
|---|---|---|
| a `deny` decision object | **blocked**, reason verbatim | **runs** |
| `{"decision":"block","reason":…}` | **blocked**, reason verbatim | **blocked**, reason verbatim |
| nothing, exit 2, reason on stderr | **blocked**, reason wrapped | **blocked**, reason wrapped |

**The deny object is accepted and ignored on `UserPromptSubmit`.** The prompt
goes to the model and answers normally, with no warning in the transcript and
nothing on either stream — the same silence a hook that found nothing produces.
So a hook entry that writes one encoding for both events reports a safety it is
not providing on half of what it is wired to, which is this project's own
failure mode arriving in the verdict writer.

`internal/hook` therefore encodes per event: the deny object at `PreToolUse`,
matching this table, and `decision`/`reason` at `UserPromptSubmit`. Nothing
derives one from the other.

**The launcher cannot do that, and for a while it did not have to.** It never
learns which event it was invoked for — `hooks.json` points it at both, and the
payload naming the event goes past on stdin, which it passes through rather
than reads. So it wrote the deny object, matching the `PreToolUse` row and
nothing else, and until `hooks.json` existed nothing invoked it at all. The
moment the prompt entry was wired, a fresh install with no binary yet denied
`Read` and `Bash` loudly and let every prompt through — half loud, which is
worse than silent, because the visible denials are evidence the guard is live.
Driven end to end on 2.1.251 in both directions: with the deny object the
prompt reached the model, and with `{"decision":"block","reason":…}` it came
back `UserPromptSubmit operation blocked by hook` with the reason verbatim.

A component blind to the event has to write the row that holds for every event,
which is the second one. `scripts/check-launcher.py` refuses the `PreToolUse`
shape by name rather than merely accepting the right one, because the wrong
shape is valid JSON and a valid verdict and fails only on the surface nothing
was testing.

**Exit 2 is what is left when the event is unreadable.** A payload that is not
JSON, or that names no event, gives nothing to write a decision object in — the
shape depends on the event. Exit 2 blocks both events without one, so that is
where a payload nobody can act on lands, with the reason on stderr.

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

### The third shape is a timeout, and it is the one this repo configures

`hooks/hooks.json` sets `"timeout": 60` on both entries. Driven 2026-09-03
against Claude Code 2.1.251 on darwin/arm64: **a hook that runs past its
timeout is killed, whatever it was going to say is discarded, and the call
proceeds.** On both events.

The hook logged its entry, slept, wrote a reason to stderr and exited a chosen
code. `UserPromptSubmit` ran under a `HOME` of its own holding no credential,
the route [Q94](../queue/Q94.md) established. `PreToolUse` needs one, a hook
there firing only once the model has chosen a tool call, so it ran under
`--settings` with `--setting-sources project` to keep this machine's own guards
out of the arm.

| Event | Timeout | The hook | The call |
|---|---|---|---|
| `UserPromptSubmit` | 30s | exits 2 after 1s | **blocked**, reason verbatim |
| `UserPromptSubmit` | 2s | exits 2 after 10s | runs |
| `UserPromptSubmit` | 60s | exits 2 after 70s | runs |
| `PreToolUse` on `Bash` | 30s | exits 2 after 1s | **blocked**, reason reaches the model |
| `PreToolUse` on `Bash` | 2s | exits 2 after 10s | runs |

Every timed-out arm lands where the same hook lands when it exits 0 on purpose,
and each event has its own tell. On `UserPromptSubmit` the prompt reaches a
turn — `num_turns` 1, against 0 for the block control, whose transcript instead
holds `UserPromptSubmit operation blocked by hook` with the reason. On
`PreToolUse` the command runs and its marker comes back in the result, with
`permission_denials` empty where the block control lists the call. So the exit
code stops mattering, and a hook that would have blocked allows.

The process was killed rather than ignored. Its log carries a line on entry and
one after the sleep, and the timed-out arms hold only the first; wall clock
tracked the timeout and not the sleep, 2.36s at `timeout: 2` and 60.38s at
`timeout: 60`.

**Unlike the other two, this one is written down.** The transcript of the
60-second arm carries this, with the path elided:

```json
{"type":"hook_cancelled","hookName":"UserPromptSubmit","hookEvent":"UserPromptSubmit",
 "toolUseID":"eb9d4d8c-…","command":"…","durationMs":60021,"timedOut":true,"timeoutMs":60000}
```

The `PreToolUse` record is the same shape, `hookName` reading `PreToolUse:Bash`
and the pair reading 2020 against 2000. Who reads either is not established. It reached neither the `--output-format json`
result nor stderr, and the model's own answer named no hook, so nothing here
shows it arriving at either audience while the call is happening. Whether an
interactive client renders it was not driven.

**60 was a hedge and the hedge resolved the wrong way.** The argument was that a
longer timeout cannot make an unmeasured behaviour worse — safer if expiry
allows, a stall if it blocks. Expiry allows. The direction was right, and the
value is load-bearing now rather than cautious: every second under the ceiling
is a second in which a scan that did not finish is a scan that never happened.

**No encoding in the tables above reaches this.** Both blocking shapes need the
hook to write something or exit 2, and a killed process does neither. Nothing
this repo ships can turn an expiry into a block.

**So the budget has to be the scanner's own**, which is the section below.

### The scanner's own budget, and overrunning it blocks

`internal/hook` gives the scan **45 seconds** and keeps 15 of the 60 for
itself. A scan still running at the end of the 45 stops and writes the verdict
this design gives a buffer it could not read: a block, on the same branch, with
a reason naming the budget, and downgraded to a confirmation by an override
exactly as every other block here is.

There is no third answer to weigh. Fifteen seconds later the process is killed
and the call proceeds, so the choice at the deadline is between blocking and
allowing silently, and the allow is what this whole file is about.

**A size cap is the cheaper half and is not the fix.** A cap answers before
reading and a deadline answers during, and three things walk past the first.
Cost is not a function of size: [Q122](../queue/Q122.md) measured the same 64
MiB at 9,746 MiB/s as binary, 1,055 MiB/s as text no rule gates on, and 6.5
MiB/s as text carrying every keyword — the third now 32.84, which narrows the
spread from 1,500x to 300x and leaves the argument where it was — so a cap
tight enough to bound the third refuses the other two for nothing. A call adds
up rather than arriving one file
at a time — the same row has `cat` over four 128 MiB files at 78.1 seconds,
with no file in it near any plausible cap. And a directory operand has no size
to cap at all, which is what made this the section the directory-operand
question was waiting on — [answered below](#a-directory-operand-is-refused-rather-than-walked-and-that-is-a-decision-now).

**A deadline is available even though nothing here takes a `context`.**
`os.ReadFile` takes none and neither does the match loop, which is why a fifo
had to be refused up front rather than read with a limit — `fifo_unix_test.go`
says so, against that question. That argument is about *interrupting* the work,
and a deadline does not have to: the scan runs on its own goroutine, the verdict
is written by the one waiting on it, and the process exit collects whatever was
still running. Go preempts a goroutine in a tight match loop asynchronously, so
the timer is scheduled without the scan yielding. That is the load-bearing
mechanism claim and it is driven rather than read —
`TestTheDeadlineFiresWhileTheMatchLoopIsRunning` blocks on the clock over a
buffer whose next arm, given time, blocks on a key planted in it.

#### Driven end to end, on built binaries

The fixture is ordinary text carrying one occurrence of each keyword the shipped
ruleset gates on, with the planted key from
[`testdata/corpus/planted/aws-access-key-id.env`](../../testdata/corpus/planted/aws-access-key-id.env)
in its last bytes — so a run that reaches the end has to emit a real deny, and a
scan that never started is not mistaken for one that finished. `Read` surface,
warm page cache, Apple M5 Max, Go 1.26.5, 2026-09-04. Wall clock is the whole
process, which is the quantity the harness's 60 is charged against.

| Fixture | `v0.1.0`..`main` | with the budget |
|---|---|---|
| 128 MiB | 18.051s, denies `aws-access-key-id` | 17.716s, denies `aws-access-key-id` |
| 400 MiB | 54.448s, denies | **45.010s, blocks on the budget** |
| 500 MiB | **68.130s**, denies — 8s past the ceiling | **45.011s, blocks on the budget** |

The 128 MiB row is the control, and it is the one that says the deadline has not
replaced the scanner: same verdict, same rule, either side. The 500 MiB row is
the case the row was filed for.

**Those sizes moved when the match loop stopped scanning the whole buffer for a
rule whose keywords say where to look** ([step 4](#pipeline)). The same 500 MiB
fixture, built the same way and driven on a built binary, now denies
`aws-access-key-id` in 14.9–17.7s over four consecutive runs rather than
blocking on the budget, and the in-process pair behind that is 32.84 MiB/s
against 5.68 for the arm with no rule anchored, min of three in one process.
The rows above are not re-taken here and cannot honestly be: they were taken on
a quiet machine, and this one carried a load average of 72 while these runs
were made — one such run did block at 45.046s on the same fixture, which is the
measurement failing rather than a second answer.

What the change moves is which fixture reaches the budget, not whether the
budget fires. That half is driven by `TestAScanThatOverrunsItsBudgetBlocks`
against a budget already spent, on all three surfaces, and is untouched here.
A fixture that does reach the budget, and the table re-taken beside it, is
[Q132](../queue/Q132.md).

**What happens to that 68.130s under Claude Code is composed rather than
observed, and the composition is the same one Q122 declined to make.** These are
hook-process wall times; that the harness kills a hook at its timeout and lets
the call through is the measurement above, taken separately. Nothing here has
driven a real session at the crossing — [Q122](../queue/Q122.md) carries that as
owed work, and it is owed after this change as much as before it.

Two numbers fall out of the pair. The deadline lands within **11ms** of the
budget measured from process spawn, so the launcher, this binary's startup, the
timer's lateness and the write together are 11ms of the 15,000 the margin holds.
And this fixture runs at 7.34 MiB/s where [Q122](../queue/Q122.md) measured 6.5
and [#92](https://github.com/karlkfi/claude-spill-guard/pull/92)'s session
measured 6.8 — three fixtures, three rates, a 60-second crossing anywhere from
390 to 440 MiB. That spread is not noise to average away. It is the reason the
bound is a clock and not a byte count.

#### What 45 costs, and why it is not smaller

The margin was measured twice more, from inside. A hook invocation over a
payload naming no file, driven through the shell and the launcher: 7.02ms at
best over 30 runs, 7.49ms median, one 350ms outlier on a machine already
carrying other work. The verdict written after the deadline fires, timed over a
64 MiB buffer at four budgets: under 10ms idle and under 37ms with twice as many
CPU-bound goroutines running as the machine has cores. Fifteen seconds is nearly
forty times the worst two of those added together, and it is not sized to them —
it is sized so that being wrong about scheduling on somebody else's machine
costs nothing.

What the budget costs is the calls that would have finished between 45 and 60
seconds, which at the worst measured rate is a call adding up to between 293 and
390 MiB. Nothing in the two populations this repo has counted comes near either
end: nothing outside `.git` in this worktree exceeds 5 MiB, and the largest
session transcript on the author's machine is 35.4 MiB, which is 5.4 seconds.

A smaller budget is the change to argue for rather than against, and the
argument that stops it is the slower machine. 45 seconds is a wall clock, so it
needs no per-machine tuning to stay under the ceiling — but the *population* it
blocks does scale with single-core speed. A 35.4 MiB transcript is 5.4s here and
would be 16s on a machine three times slower, which a 10-second budget refuses
and this one does not. The stall is the objection on the other side, and it is
weaker than it looks: the alternative to waiting 45 seconds was never a quick
answer, it was waiting 60 and getting no answer at all.

### A directory operand is refused rather than walked, and that is a decision now

`grep -rn pat docs/` and `rg pat docs/` name a directory. `internal/readers`
returns it as a read operand because it is one, and `bashTargets` refuses the
call, because a directory is not a regular file; a `Read` whose `file_path` is
one takes the same branch. It costs **7.1%** of the `Bash` calls that carry a
reader operand — 5,036 of 70,480, measured over this machine's transcripts by
driving the real segmenter, and a floor rather than a rate, since `grep -rn pat
docs` with no trailing separator is a directory operand too and is not in the
count.

Three answers were open. Scanning the directory listing is a fail-open over
every file in the tree and was never in contention. What decides between the
other two is below, and neither argument is the one the question started with:
that one was *an unbounded walk that overruns allows the call*, and
[the budget](#the-scanners-own-budget-and-overrunning-it-blocks) has taken it
away — an overrunning walk blocks now, like anything else.

**Nothing in the operand says what a walk would cost.** Measured 2026-09-04 by
walking each root with `filepath.WalkDir` and putting every regular file through
`scan.Buffer` with the shipped ruleset, symlinks not followed, on an M5 Max
already carrying other work:

| Root | Files | Read | Walk and scan |
|---|---|---|---|
| `docs/` in this repo | 76 | 0.4 MiB | 13 ms |
| this worktree | 227 | 1.6 MiB | 40 ms |
| the `claude-spill-guard` checkout, its worktrees included | 11,815 | 970.5 MiB | 3.119 s |
| `~/go/pkg/mod` | 239,648 | 5,167.5 MiB | 94.245 s |
| a `github-actions-gateway` checkout | 568,883+ | 10,342.9+ MiB | **unfinished at 120 s** |

Four orders of magnitude, and the operand is one token either way. Two of the
five are past the 45-second budget, so on those a walk buys a stall and then the
same block a refusal gives in microseconds. The three that fit are the honest
cost of refusing, and the top row is the one the row was filed about.

**A walk reads a different file set from the one the command would send, and by
how much depends on which reader named the directory.** `grep -r` reads
everything under the root; ripgrep honours `.gitignore` and `.ignore` and skips
hidden files unless told otherwise. Driven on ripgrep 14.1.1 over a five-file
fixture — `.env`, `.ignore`, the `ignored.txt` that `.ignore` names,
`visible.txt`, and `sub/deep.txt`:

| | Files it would read |
|---|---|
| a plain walk, and `grep -rl '' .` | 5 |
| `rg --files`, defaults | **2** — `visible.txt`, `sub/deep.txt` |
| `rg --files --hidden --no-ignore` | 5 |

The `.env` is in the first set and not the second. At repository scale the gap
is wider: in the `claude-spill-guard` checkout `rg --files` reports **211** files
where the walk above found 11,815 and 1,132 findings in them, because
`.gitignore` excludes `.claude/worktrees/`. So a walk under an `rg` operand
would block that call on content ripgrep was never going to open, which is a
false positive by this design's own definition — and **precision is the
product**. The inherited ruleset flagged 27.6% of real files with zero true
positives, and this is the same failure arriving through the operand resolver
instead of through a regex.

**Closing that gap means re-implementing the readers' traversal, one reader at a
time.** `--glob`, `--type`, `--max-depth`, `--max-filesize`, `--hidden`,
`--no-ignore` and the ignore-file stack all change ripgrep's set; `--include`,
`--exclude`, `--exclude-dir` and `-r` against `-R` change `grep`'s. That is the
class of work this repo refuses by name for shell parsing — it fails silently in
both directions — and there is no shortcut past it, because the only way to
learn which files a command reads is to run it, and `os/exec` is forbidden
across this build graph.

**The narrower version does not survive either**, and it is named here because
it is the obvious next proposal: walk only for `grep`, whose plain `-r` really
does read everything under the root, and keep refusing `rg`. That is correct for
a `grep -r` carrying no filter flags and silently wrong for one that does, so
what it buys is the flagless form and what it costs is a traversal rule that is
right or wrong depending on a flag nobody looked at. It also does nothing about
the bottom of the table: `grep -r pat ~/go/pkg/mod` is 94 seconds, so the
carve-out converts an instant refusal into a 45-second one.

**So the refusal stands, and it is a decision rather than a side effect.** The
reason names the case and the remedy — *name the files instead* — rather than
reporting the mode class, and
`TestADirectoryOperandSaysSoAndSaysWhatToDoInstead` pins that wording. What it
costs is the top rows of the table: a `grep -rn pat docs/` that a walk would
have covered in 13 ms is refused, and the user retypes it against files. The
alternative on the bottom rows is a scanner reporting on a file set the command
would not have sent.

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
`PROD_GUARD_OVERRIDE`. `internal/hook/override.go` reads it from an inline
assignment prefix on a `Bash` command and from nowhere else — not from
`os.Getenv`, because an exported variable and a `settings.json` `env` block are
both durable, both silent, and both writable by the model, one of them at
`.claude/settings.local.json`.

**It downgrades a block to a confirmation, never to an allow.** That is the
half of "matching those two" that decides what the hatch is worth: both of them
downgrade to a prompt as well. The argument is this document's own opening —
what is missing today is any moment where somebody is told a credential is
about to leave the machine, and an override that allowed silently would delete
that moment in exactly the calls that have one to lose. So the scan runs on an
overridden call, and the findings are what the confirmation carries. A call
that scans clean is silent with a prefix exactly as it is without one — except
where the prefix carries no reason, which is refused before the scan runs and
so blocks a call that would otherwise have been allowed. That is deliberate:
articulating why is the whole of what this hatch controls for, and an empty
value skips exactly that.

The encoding is `permissionDecision: "ask"`, and it needed measuring for the
reason the block encodings did — a shape that is accepted and ignored runs the
call. Measured 2026-08-28 against Claude Code 2.1.238 on darwin/arm64, driving
a real hook under `-p --output-format stream-json`, with the observable the
marker a `Bash` call echoes coming back in a `tool_result`:

| Hook stdout | Permission mode | The marker | What the model receives |
|---|---|---|---|
| empty — control | default | present | the command's output |
| a `deny` object — control | default | **absent** | the reason, verbatim |
| an `ask` object | default | **absent** | the reason, verbatim |

So an ask nobody can answer withholds the result exactly as a deny does. Both
controls fired, which is what separates that from a probe reporting every arm
blocked.

**What this table cannot show, and a fourth row that pretended otherwise.** An
earlier version carried an `ask` arm under `bypassPermissions`, returning the
same result. It was not evidence: `-p` has no permission UI for the mode to act
on, so the two arms differ by a flag that does nothing there, and a control
whose result does not move when you vary its input is a reading about the
instrument. It is dropped rather than kept with a caveat.

So an ask reaching a person is **undriven here** and rests on prod-guard 2.5.2
shipping this encoding for its own override downgrade. The arm that matters —
an interactive session under `bypassPermissions`, where an ask might be
approved with nobody reading it — cannot be driven from a harness with no human
in it, and is not driven.

**Which is why the downgrade does not fire in that mode at all.** For a
fail-closed tool the undriven arm must not be the permissive one, so
`permission_mode` of `bypassPermissions` keeps the block and says so in the
reason. That costs the user nothing they had — an ask nobody answers stops the
call too — and it sends the reason to the model instead of stalling the session
on an unanswerable prompt. prod-guard takes the same branch at
`scripts/bash-prod-guard.py:2547`, for both halves of that argument.

The mode is read from the payload, driven 2026-08-28: every PreToolUse payload
from 2.1.238 carried `permission_mode`, reading `default` and
`bypassPermissions` to match the flag the session started with.

**That reading is the whole of the evidence that this branch is live rather than
dead code, and no test can add to it.** A unit test hands the decoder a payload
carrying the field, so it exercises the branch whether or not Claude Code ever
sends one — the fixture supplies the value the mechanism depends on. The tests
below pin what the branch *does*; only the raw payload says it will ever be
reached. Re-take it by logging a real payload, not by reading the suite.

Only `bypassPermissions` suppresses the downgrade; absent, empty and unknown all
still downgrade. An allowlist of interactive modes would turn every mode Claude
Code adds into a hatch that silently stops working, and branch-guard's #33 is
the measurement against it: an ask in `auto` reaches a prompt somebody answers,
so treating it as human-free was the defect there.

**The residual, stated rather than implied.** The two choices fail in opposite
directions and neither is free. A denylist means a future human-free mode under
a new name still downgrades to an ask nobody reads. An allowlist means every
interactive mode Claude Code adds is a hatch that stops working until this
binary is updated, which is #33's failure re-opened. The denylist is what both
sibling guards chose, and it is the one whose failure needs Claude Code to add a
*new* unattended mode rather than merely to add a mode.

**Per-rule disablement in `.claude/spill-guard.json` is not wired, and it is
not the same kind of thing.** `internal/rules` merges a project ruleset over
the shipped one and `Load` takes the bytes, so the loader call is one argument.
What that argument would admit is a two-step bypass: write the file with
`{"id": "…", "enabled": false}`, then read the secret. Neither step is caught.
`Write` and `Edit` are not in the scanned set, and a `cat > .claude/spill-guard.json`
heredoc that *is* scanned carries no secret, so a scanner looking for
credentials passes it either way.

Saying the model can author both hatches is true and settles nothing, because
the design does not defend against a user who means it. What separates them is
scope and legibility. The prefix excuses one call and sits in the command the
human is being asked to approve; a config entry disables a rule for every later
call in every later session, and the write that made it is one line of
scrollback. One is a decision somebody takes; the other is a decision somebody
took once and nobody re-reads.

The three guards that suggest themselves each fail on their own terms:

- **Scan `Write` and `Edit`.** Does not close it. The bypass is the
  disablement, and the disablement carries no secret to find.
- **Let a project entry make a rule stricter and never weaker.** Not decidable
  from the schema, because every field an override can set has a weakening
  direction — `enabled: false`, a regex that matches nothing, keywords the
  prefilter will never find in the buffer, a raised entropy floor under the
  ceiling `compile` already enforces. The one mechanically clean version is *a
  project entry may add a rule and may not touch a shipped one*, which
  `apply` is already shaped to express and which removes the reason the file
  exists: turning a noisy rule off is the precision case the whole ruleset is
  tuned for.
- **Require a signature from outside the workspace.** Needs a key, a verifier
  and somebody to hold both, in a binary whose stated property is an empty
  supply chain.

So this half stays a decision rather than a loader change, and [Q73](../queue/Q73.md)
is narrowed to it. The environment prefix had no such question, which is why it
landed first.

## Repo layout

```
cmd/spill-guard/          Entry point. Subcommands: hook, scan, selftest, rules, version.
internal/hook/            Claude Code payload decode, verdict encode, exit-code contract.
internal/rules/           Schema, registry load and merge, compile.
internal/scan/            Binary skip, prefilter, match loop, findings.
internal/validate/        Luhn, card placeholders, mod-11, entropy, reserved ranges, context labels.
internal/bash/            Segment parsing, ported from workspace-guard.
rules/spill-guard.json    The shipped ruleset. Authored and reviewed as JSON.
rules/embed.go            The go:embed that compiles it in. Reaches only its own directory.
hooks/hooks.json          Hook wiring. The events and the matcher.
hooks/run-spill-guard.cmd Launcher. Resolves the binary, denies when it cannot.
.claude-plugin/           plugin.json and marketplace.json. The only version.
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

None left in this file. The three it opened with are all settled, two by
measurement and one by argument off them:

- **`PostToolUse` cannot withhold a result**, so nothing is catchable after the
  fact — [measured](#posttooluse-cannot-withhold-a-result).
- **Only exit 2 blocks, and a `deny` object on stdout outranks the exit code** —
  [measured](#the-exit-code-contract-measured).
- **What counts as human-typed** was the wrong axis, and the requirement it came
  from is met by asking whether a payload field's bytes have crossed the
  filesystem-to-context boundary yet —
  [above](#what-gets-scanned-is-the-crossing-not-the-hop).

One remains outside it, at the end of [`distribution.md`](distribution.md):
whether `install.sh` should refuse to proceed without `cosign`.
