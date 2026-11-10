# The shipped ruleset

`spill-guard.json` is the v1 ruleset: twelve credential rules, `us-ssn`, and three
more numeric PII rules that ship off. It is the only ruleset. `rules/embed.go` compiles it
into the binary and `internal/rules` loads nothing else — there is no project
file layered over it, and a rule that is too noisy is turned off here, in a
change somebody reviews. The schema and what the loader refuses are in
[`docs/design/README.md`](../docs/design/README.md#rule-schema).

**There used to be a project ruleset in the design, and retiring it was the
decision rather than wiring it up.** `.claude/spill-guard.json` is a file the
model can write, so honouring `{"id": "jwt", "enabled": false}` from it is a
two-step bypass that no scan of the write can catch, because the disablement
carries no secret. `docs/design/README.md` under *Output discipline* has the
argument, and the loader no longer has the merge, so bringing it back is a
reviewed diff rather than a flag.

JSON has no comments, so the reasoning is here.

## Twelve credential rules, not seventy

The predecessor's ruleset flagged 27.6% of 257 real files and produced more
than 5,600 matches with zero credentials in them. That is a precision failure, not a
coverage one, so v1 does not aim at gitleaks-level breadth. Every rule below
anchors on a literal a scanner can prefilter on, and every one of them is
carried by a planted fixture in
[`testdata/corpus/`](../testdata/corpus/README.md).

| Rule | Anchor | What keeps it quiet |
|---|---|---|
| `aws-access-key-id` | `AKIA` `ASIA` `ABIA` `ACCA` | 20 fixed characters, Shannon floor 3.0, and no `EXAMPLE` suffix |
| `github-token` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | 36 fixed characters, floor 3.0 |
| `github-fine-grained-pat` | `github_pat_` | 70–90 characters, floor 3.0 |
| `slack-token` | `xoxa-` `xoxb-` `xoxe-` `xoxp-` `xoxr-` `xoxs-` | floor 3.0 |
| `slack-webhook-url` | `hooks.slack.com` | the host and both path segments are literal; the floor reads the last segment only |
| `stripe-live-secret-key` | `sk_live_` `rk_live_` | live keys only — see below |
| `openai-api-key` | `sk-` | the embedded `T3BlbkFJ`, floor 3.0 |
| `anthropic-api-key` | `sk-ant-api03-` `sk-ant-admin01-` | 108 or 110 fixed characters closing `AA`, floor 3.0 — see below |
| `anthropic-token` | `sk-ant-oat` `sk-ant-ort` `sk-ant-sid` `sk-ant-ccsr-` | 20 to 1000 body bytes, floor 3.0 — see below |
| `google-api-key` | `AIza` | 39 fixed characters, floor 3.0 |
| `private-key-block` | `PRIVATE KEY` | a base64 body line has to follow the header, across RFC 1421's headers if the key has them, indented or not, behind a unified diff's `+` or `-`, and behind grep's `path:N:` or `path-N-` |
| `jwt` | `eyJ` | three segments, the first two both opening `eyJ`, measured by an extent rather than capped, floor 3.5, and no published sample signature |

**The entropy floors are what make a *padded* placeholder quiet.** A repository
holds far more `AKIAXXXXXXXXXXXXXXXX` than it holds keys, and the two are the
same shape to a regex; the padded one carries 1.0219 bits per byte against a
floor of 3.0, so it goes. What a floor cannot reach is a published example
written to look like a key. AWS's own measures 3.6842 and clears the floor by
design, and the jwt.io sample token measures 5.4441 against 3.5 — the two
rules below carry a second check for exactly that. Six of the twelve rules match
[`testdata/corpus/clean/env.example`](../testdata/corpus/clean/env.example) and
none of the six survives its own validator.

**`sk_test_` is not a credential and is not matched.** A Stripe test key is
published by the integrator in their own README, works against nothing, and
appears beside the test card numbers. Matching `sk_live_` and `rk_live_` costs
no recall that matters and removes a whole class of file from the output.
[`testdata/corpus/clean/payments.md`](../testdata/corpus/clean/payments.md) is
that file.

**`anthropic-api-key`'s length is another detector's reading, because Anthropic
publishes no format.** Read 2026-11-03:
[gitleaks](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
and [TruffleHog](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/anthropic/anthropic.go)
both match the two prefixes here, 93 bytes of `[A-Za-z0-9_-]` and a closing `AA`,
and TruffleHog verifies a hit against the live API.
[OpenRouter's guardrail docs](https://openrouter.ai/docs/guides/features/guardrails/secret-formats.md)
name the same prefixes and tail with no length.
[keyhog](https://github.com/santhreal/keyhog/pull/7) moved from a different fixed
layout, with a hyphen before its last six bytes, to 80–120 bytes, which contains
this one, so it is no evidence against it. A key of another length goes unreported
here, which is the rule's stated limit rather than a judgement that it is
harmless. The other `sk-ant-` prefixes are `anthropic-token`'s, below.

**`anthropic-token` has a floor rather than a length, and the floor is Claude
Code's.** Claude Code 2.1.290 reads four more `sk-ant-` prefixes: an OAuth access
token (`sk-ant-oat01-`), its refresh token (`sk-ant-ort01-`), a claude.ai session
key sent as a cookie (`sk-ant-sid01-`), and a git password for a remote session
(`sk-ant-ccsr-`). This repo has found no published length for any of them, and
none near key length exists on this machine to measure. The one bound on record
is the secret scanner bundled in that binary, whose `anthropic-oauth-token` rule
is `sk-ant-(?:oat|ort)\d{2}-[\w-]{20,}`. This rule takes that floor and caps the
run at RE2's 1000, so it keeps the anchored path. It has no closing `\b`, unlike
the rules above it: past the cap a run of word bytes has no boundary to stop at,
so with one a hyphen-free token longer than 1000 bytes went unreported, and
without it that token is reported on its first 1000.

A bare prefix would be the precision risk, because sessions quote these
prefixes. Read 2026-11-09 over 2,997 transcripts under `~/.claude/projects`,
5.47 GB: 118 `sk-ant-oat01-`, 74 `sk-ant-ort01-`, 62 `sk-ant-sid01-` and 35
`sk-ant-ccsr-`, and the longest body behind any of them was 3 bytes. The same
read finds the planted `sk-ant-api03-` fixture at its 95 bytes, so it is not
blind to a long one. A floor of 20 therefore costs nothing on what sessions here
write, and a padded placeholder in
[`testdata/corpus/clean/env.example`](../testdata/corpus/clean/env.example)
falls to the entropy floor. A placeholder written in words does not: the
prefix followed by `your-oauth-token-goes-here` clears 3.0 and blocks, as do
most stand-ins spelled in words; one padded out with a repeated letter can
still fall under the floor. The census found no body that
long behind these prefixes, placeholder or otherwise, so that is a stated
limit rather than a measured cost. Nor does the census say how long a real token
is, so a real one shorter than 20 bytes would go unreported.

`sk-ant-si-` and `sk-ant-cc-` are not here because they are already caught:
Claude Code strips either one to reach a JWT, and `jwt` reports the token
behind the prefix.

**`slack-webhook-url` reports the last path segment rather than the URL.** The
entropy check reads the captured group, and a webhook URL is mostly a literal
host, so capturing the whole thing would put a floor over text that is the same
in every match. Capturing the secret tail lets the floor drop
`.../B00000000/XXXXXXXXXXXXXXXXXXXXXXXX` without dropping a real one.

**Eleven of the twelve carry an entropy floor. The twelfth is structural instead.**
`private-key-block` matches a PEM header, which is a fixed string, and a floor
over a constant is not a check — so the rule requires one base64 body line
after the header, stepping over `Proc-Type:` and `DEK-Info:` if the key is an
RFC 1421 encrypted one, and over leading whitespace in front of either. Prose
quoting `-----BEGIN RSA PRIVATE KEY-----` to explain what one looks like carries
no such line and is not reported. That was
not hypothetical: the paragraph you are reading, and the row that filed the
problem, were both findings until the clause landed. Scanned over every tracked
file, the rule went from 3 hits to 1, the one being its own planted fixture.

Do not quote that pair, and do not trust the number in this paragraph either.
With the clause removed the same scan read 8 on 2026-08-27 and reads 27 at the
commit you are looking at — eighteen of those twenty-seven are
`pemblock_test.go`, which exists to exercise this rule. The clause-free count
measures how much prose about PEM headers the repository holds, not how noisy
the rule is, and it climbs every time somebody documents it: 19 while that
branch was being reviewed, 21 after review asked for two more cases, 27 once
the indentation arms below brought six more and a third fixture. The shipped
count stays at its planted fixtures, 4 of them. The reading that holds is the
gated one below.

[`testdata/corpus/clean/tls-runbook.md`](../testdata/corpus/clean/tls-runbook.md)
is what holds that down. It quotes four private-key headers inline and displays
a fifth in an indented block — that fifth is what holds the clause's *shape*
down — so removing the clause takes the clean corpus from 0 findings to 5 and
reddens the gate. Six armour lines sit in the file; the `CERTIFICATE` one is
public and outside the rule's alternation. Before
that file existed the clause could be reverted with every test still passing,
which is the shape this whole item is about.

**The step over RFC 1421's headers is exactly two field names, and that is the
precision decision.** An encrypted PKCS#1 key — what `openssl rsa -aes128 -p`
and `ssh-keygen -m PEM -N` write — puts `Proc-Type:` and `DEK-Info:` where the
body would be, so the clause missed it. The obvious widening is a bounded lazy
window between header and body, and the corpus refuses it: at 200 bytes it
fires on the runbook above, which lays out a header, explains the format in
prose, and shows a body line. Naming the two fields admits every encrypted key
those two toolchains emit and readmits no prose, because a prose line is not
`Proc-Type:` or `DEK-Info:` and the body still has to be the first thing on its
line.

Widening to any `Name: value` line was measured too and is quiet over the whole
corpus, which is why this originally shipped as a judgement call. It is not one.
Three shapes separate them — a header followed by an undefined field, by
`Comment: exported by ssh-keygen`, or by a prose line ending in a colon, each
with a body under it. `TestTheGenericStepReportsWhatTheNamedPairDoesNot` holds
both halves: the alternative reports all three and the shipped rule reports
none. It compiles a regex that ships nowhere, which
[`corpus_test.go`](../internal/scan/corpus_test.go)'s inherited controls
already do for the same reason — a claim with nothing that can fail is the
shape this repository refuses. A toolchain that writes a third RFC 1421 field
would go unreported and would be the thing that reverses this.

**Two arms of the alternation are dead.** `SSH2 ENCRYPTED ` cannot reach RFC
4716 armor, which is four dashes with inner spaces — `ssh-keygen -e -m
RFC4716` emits `---- BEGIN SSH2 PUBLIC KEY ----`, byte-checked — where the
rule requires five and none. `PGP ` cannot reach
`-----BEGIN PGP PRIVATE KEY BLOCK-----`, because real armor carries ` BLOCK`
before the dashes; that one is derived from the spec rather than measured,
`gpg` being absent on the machine it was taken on. They stay because deleting
them is a judgement about what no toolchain
writes rather than a proof, and with the body-line clause in force all an arm
can add is a header followed by base64 — a key block, or a document displaying
one, which is a class every other arm already carries.

What the widening costs is a document that displays the encrypted layout
verbatim — header, `Proc-Type:`, `DEK-Info:`, blank line, base64 — which is now
reported. That is the same class as any document displaying a key block, which
every arm already carries, and it is the one user-visible cost of the change.

The clause's other cost is not live: a key whose header and body reach the
scanner in different buffers reports nothing, and nothing chunks a file today —
`scan.Buffer` takes the whole thing — so it is a constraint on whatever calls
it rather than a gap.

**Leading whitespace is allowed in front of the body and in front of those two
fields, which is a second widening with the same cost.** A key pasted into a
YAML block scalar or an indented Markdown fence carries whitespace on every
line, and `kubectl create secret tls` writes exactly that — so the commonest
way a key reaches a file somebody then `cat`s was the one shape the clause
missed. It is the *body's* indentation that decides it and never the header's:
the header may already sit anywhere on a line, so an indented header over an
un-indented body was reported before this and an un-indented header over an
indented body was not.

Both places need it, not one. Putting `[ \t]*` only in front of the body leaves
an indented encrypted key missed, because that key's `Proc-Type:` and
`DEK-Info:` lines are indented too and the step over them never engages. Driven
against the shipped tree: the half-fix leaves
[`private-key-block-indented.yaml`](../testdata/corpus/planted/private-key-block-indented.yaml)
reporting nothing, which is why that fixture is the encrypted layout rather
than the plain one.

What holds the widening down is the same runbook and the same reason. Its "What
the parts look like" section displays an indented header and an indented body
line with prose between them, and prose is not whitespace — so `[ \t]*` cannot
cross it where a bounded window over printable bytes would. The narrow form and
the 200-byte window agree on every key and disagree there, which is the whole
of why one shipped.

**The clean corpus is 13 kB, so it cannot settle whether precision moved. The
differential can.** Compiling both clauses and counting the files the new one
matches and the old one does not, over `~/go/pkg/mod` — 239,671 files, 5.05
GiB — the widening adds **3 matches in 1 file**, and all three are indented
`client-key: |` block scalars in
`gitlab.com/gitlab-org/api/client-go@v1.46.0/config/config_test.go`, at header
indents of 8, 10 and 10 columns. Three true positives of exactly the shape this
section is about, and no new false positive anywhere in the population.

Two things make that zero a measurement rather than a silent filter. 738 of
those files carry `PRIVATE KEY`, so the sweep reaches the rule it is about; and
files are read whole and matched in every encoding the keyword appears in — none
of them a UTF-16 one here, checked rather than assumed. Both arms read the same
buffer either way, so any narrowing hides a match from both and cannot
manufacture a difference between them. Found by the review of the pull request
that landed the widening and re-taken here; it is a reading over one machine's
module cache, not a gate, so nothing re-runs it.

`TestTheCorpusHoldsTheIndentedShape` in
[`pemblock_test.go`](../internal/scan/pemblock_test.go) is the guard on the
*corpus* rather than on the rule. It compiles the clause with the whitespace
made mandatory, so it matches only what this widening newly admits, and demands
a planted file it can find and no clean one. When Q76 was filed that reading
was 0 and 0 — three deliberately varied candidates agreeing because the corpus
held no instance of the shape at all, which is a finding about the corpus and
not about the candidates.

**A separator line carrying whitespace was not crossed, and a unified diff
writes one.** The step from the header to the body ran over `[\r\n]+` —
newlines and nothing else — so a key whose separator line held a space or a tab
went unreported. Q143 filed that with no observed traffic behind it, which is
why it was a row and not an edit: widening a shipped rule on nothing is how
precision goes.

The traffic is `git diff`. Unified format prefixes every context line with a
space, so a blank line inside a quoted file arrives as a line carrying exactly
one — driven on git 2.55.0, 2026-09-07, in a scratch repository rather than
argued from the format. An encrypted key is what pays for it: `openssl rsa
-aes128 -p` and `ssh-keygen -m PEM -N` both write a bare empty line between
`DEK-Info:` and the body, so a patch quoting that file turns the one separator
the rule depends on into a whitespace-only line.
[`private-key-block-in-diff.patch`](../testdata/corpus/planted/private-key-block-in-diff.patch)
is `git diff` output rather than a hand-written patch, because the producer is
the evidence.

**Both steps need it, and the row that filed this named one.** Widening only
the header's separator leaves the diff shape missed, because in an encrypted key
the whitespace-only line falls after `DEK-Info:` rather than after the header —
the same half-fix the indentation widening above ran into, arriving at the other
step. Driven against the shipped clause: of the five cases this section adds,
the header-only form reports three — the ones separated after the header — and
misses both the one whose whitespace line follows `DEK-Info:` and the planted
patch, which is that shape.

**The separator still has to reach a line ending, so it is `(?:[ \t]*[\r\n])+`
and not `[ \t\r\n]+`.** The one-character form the row proposed also admits a
body on the header's own line, which no toolchain writes and which nothing here
asked for. Over 5.05 GiB the two forms are indistinguishable — neither admits a
file the other does not — so no measurement separates them and the narrower one
is preferred on the rule this section states by name. `the body on the header's
own line` is a `false` row in `TestPrivateKeyBlockAcrossThePEMLayouts`, which is
the only thing holding the choice down.

**The differential says what the widening costs, which is nothing here.** Both
clauses compiled and counted over `~/go/pkg/mod` — 244,160 files on 2026-09-07,
753 of them carrying `PRIVATE KEY`, a larger cache than the 239,671 the
indentation reading above walked — the shipped clause, `[ \t\r\n]+` and
`(?:[ \t]*[\r\n])+` all report **642 matches in 466 files**, and the set each
widening newly admits is **empty**. So this widening is not paid for by a
population reading, and does not pretend to be: it is paid for by the producer
above.

**The clean corpus was re-taken rather than reasoned about**, which the row
asked for by name. `tls-runbook.md`'s "What the parts look like" section
separates a displayed header from an indented body line with prose, and prose is
neither whitespace nor a line ending, so the prediction was that it stays quiet.
It does: 13 files, 13,360 bytes, 0 findings, unchanged either side.

`TestTheCorpusHoldsTheWhitespaceSeparatorShape` in
[`pemblock_test.go`](../internal/scan/pemblock_test.go) is the guard on the
corpus, and it computes what the widening newly admits instead of approximating
it — walking each half of the corpus with the shipped rule and with the
pre-widening clause and taking the difference. 4 newly admitted planted files, 0
clean. A hand-written approximation can drift from the two patterns it stands
between; a subtraction cannot.

That figure was 1 until the sections below landed, and the extra 3 are not this
widening's. A patch's added and removed lines separate a key's header from its
body with a whitespace-only line *and* put a marker in front of every line, so
the two fixtures that section plants need both steps and the pre-widening
clause misses them for either reason. The grep-output fixture is the third, for
the same reason with grep's prefix in place of the marker. A subtraction says what one pattern
admits over another, never which of two changes is responsible, which is why
the section below takes its own.

**A diff's `+` and `-` are not whitespace, and the clause could not cross
either.** The widening above taught the step to cross a patch's *context*
lines, which take a space. An added line takes `+` and a removed one takes `-`,
so a key arriving in a commit went unreported — and that is the direction with
the traffic behind it. A key shows up in a patch's context only when something
near it changed; a key being committed shows up as added every time.

**One shape was reported before this, and by accident.** `+` is in the base64
alphabet, so a plain key's body line beginning `+MII…` reads as base64 that
starts one byte early, and the clause matched without ever crossing anything.
Nothing chose that, and it does not survive an encrypted key, whose
`Proc-Type:` and `DEK-Info:` lines the step has to cross first. Driven
2026-09-19 on `git diff --cached` output, git 2.55.0, in a scratch repository:

| Where the key sits in the patch | Before | After |
|---|---|---|
| context lines, prefix `` (one space) | yes | yes |
| added lines, plain layout | yes, by the alphabet | yes |
| **added lines, encrypted layout** | **no** | yes |
| **removed lines, either layout** | **no** | yes |
| quoted-reply lines, prefix `> ` | no | no |

**A removed key is a decision and not a consequence of admitting `+`.** A patch
that deletes a key carries the whole key in its text, so the bytes cross
exactly as an added one's do —
[`docs/design/README.md`](../docs/design/README.md#what-gets-scanned-is-the-crossing-not-the-hop)
is what settles that — and a modification hunk emits both markers from one `git
diff`. There is no reader that produces one and not the other, so the
asymmetry between the table's second row and its third and fourth was never
chosen: it is the base64 alphabet happening to contain one of the two bytes.

**One marker, not a run of them.** The byte after it has to be horizontal
whitespace, a line ending, or the body itself, which is what keeps `-` off
prose: a Markdown rule between a displayed header and a body line is not
crossed, because the second dash is neither, and neither is a prose bullet
whose text carries no 32-byte base64 run. Both are `false` rows in
`TestPrivateKeyBlockAcrossThePEMLayouts`, and what they hold down is the shape
of the arm rather than a law about prose — a bullet whose text *is* a body
line is a document displaying a key block, which every arm already carries.

**The marker sits in front of the indentation, and the refused alternative is
the one that allows whitespace on both sides of it.** Three spellings, driven
2026-09-21 against constructed layouts:

| | a diff of an unindented key | a diff of an indented key | `  - <body>` | `- <body>` |
|---|---|---|---|---|
| `[-+]?[ \t]*`, shipped | yes | yes | no | yes |
| `[ \t]*[-+]?` | yes | no | no | no |
| `[ \t]*[-+]?[ \t]*` | yes | yes | yes | yes |

**The first column is what stops the middle row being a non-starter, and an
earlier version of this table left it out.** Without it the middle spelling
read as refusing the producer altogether. It does not: every unindented diff
shape crosses it, both markers and both layouts, and what it loses is the one
row where the two widenings meet — a key indented *inside* a diff. Driven
2026-09-21 by the independent review of the pull request that made this change
and re-driven here, by putting the middle spelling into all four sites of the
shipped ruleset: all three planted patch fixtures still report, both corpus
subtractions come back byte-identical to shipped, and exactly one of the 34
rows in `TestPrivateKeyBlockAcrossThePEMLayouts` goes red.

So the first row against the second is a trade with a named case on each side,
not a dismissal. The middle spelling refuses all three bullet shapes, so it is
the only one of the three that adds no false-positive surface at all; shipped
buys back the indented-in-a-diff case — a committed Kubernetes secret is the
producer, and plausibly the highest-traffic real spill this rule sees — and
pays the unindented `- <body>` bullet beside it. The third spelling is the
widening to refuse: it readmits every indented Markdown bullet whose first
token is 32 base64 characters, and it buys nothing over shipped on any column
here, because no producer writes whitespace in front of the marker. The corpus
and the differential are empty on this axis and separate none of the three, so
what prices them is this table and the producer argument above it. `an indented list item, which is the
marker and the indentation the other way round` in
`TestPrivateKeyBlockAcrossThePEMLayouts` is the row that holds it, and it is
red under the third spelling and green under the other two.

The first row's third column is not a typo. An **un**indented `- ` bullet whose
text opens with 32 base64 characters is crossed, and always was going to be:
that is a document displaying a key body, which every arm of this rule already
carries. 0 instances in the 263,734-file sweep.

**`>` was priced and refused.** A quoted-reply email is the other concrete
prefix, and no population reading separates it from the shipped pair — so the
narrower one is preferred, on the rule this section states by name. What
separates them is the producer: `git diff`, `git show` and `git format-patch`
write `+` and `-` from one command, and nothing here reaches an `.eml`.
`TestTheQuotedReplyStepReportsWhatTheShippedMarkersDoNot` compiles the arm that
ships nowhere and holds both halves, which is why the refusal is a measurement
rather than an omission: that arm reports two email shapes and the shipped rule
reports neither. A nested `>>` reply is refused with it, driven.

**The differential says what the markers cost, and the population cannot say
what they buy.** All four clauses compiled and counted over `~/go/pkg/mod` —
263,734 files on 2026-09-19, 828 of them carrying `PRIVATE KEY` — the
pre-change clause, the `+`-only arm, the pair that now ships and the `>` arm
all report **721 matches in 526 files**, and the set each marker newly admits
is **empty**. Read the second half of that before drawing recall from it: 303
files in the population are patches or hold one, and **none** of those 303
carries `PRIVATE KEY`. So the zero bounds the false positives over published
Go source and says nothing about recall in either direction, which is why the
arms are paid for by the producer above rather than by the sweep. The clean
corpus is unchanged either side, for all four: 13 files, 13,360 bytes, 0
findings.

**A second population reaches the shape that one could not, and it was taken by
the independent review of this change rather than here.** Same four arms over
`~/workspace` on 2026-09-21: 8,514,452 files, 13,737 carrying `PRIVATE KEY`,
and 876 patch-shaped files of which **24 do carry a key** — where the module
cache had 302 patches and none. The arms report 718, 719, 720 and 720 matches,
and the entire newly-admitted set across all three widenings is **this change's
own two planted fixtures**, sitting in the branch's worktree. So the
false-positive bound now holds over a population that contains key-bearing
patches, which is what the paragraph above has to concede it does not, and the
`>` refusal survives 17x the keyword traffic unchanged.

It is recorded rather than re-taken, and deliberately. `~/workspace` holds live
worktrees that move between runs, so a second pass would produce a third set of
numbers and settle nothing; the reading above is one run of one binary over
both populations, which is what makes the two comparable. Attributed because it
is not this branch's measurement.

`TestTheCorpusHoldsBothDiffMarkerShapes` is the guard on the corpus, and it
takes **two** subtractions rather than one. Against a markerless clause it says
the corpus holds the shape at all; against a `+`-only clause it says the corpus
holds the *removed* half, which a single subtraction cannot — either fixture
alone satisfies that one, so the `-` arm could be dropped with the count still
moving. 3 newly admitted planted files, 2 of them by `-`, and 0 clean either
way. Each count is one higher than the markers explain: the grep-output fixture
below is missed by both older clauses, for its prefix rather than a marker.

**What no marker reaches is a key a hunk header splits.** Under `git diff`'s
default three lines of context, a change close enough to a key puts `@@ -n,m
+n,m @@` between its header and its body, and no marker crosses a whole line
the key's own file does not contain. Driven: missed on context lines and on
added lines alike, before this change and after it. Admitting it is the
bounded-window shape this section already refuses by name, so it is a row
rather than an edit, and whether it has traffic is unmeasured.

**grep's per-line prefix is crossed too, because `spill-guard filter` reads
nothing else.** The filter is the last stage of a recursive grep, and grep
opens every line it prints with `path:N:`, or `path-N-` on a context line,
`path:` and `path-` without `-n`, and `N:` and `N-` with `-h`. None of that is
a marker or whitespace, so a key printed by `grep -rn -A30 'PRIVATE KEY' .`
crossed the filter whole. Driven 2026-10-25 against `main` at `9f0fbdc`: under
`-rn -A30`, `-r -A30`, `-rnh -A30`, `-rn -C2` and `-rn -A30 --null` with the
system grep, and the first three again with the one a session's `grep` resolves
to, the planted keys exited 0 every time. Only `-rh`, which prints no prefix,
exited 3.

The arm is an optional path that opens on neither a marker nor whitespace,
then `-` or `:`, digits, and `-` or `:` again; or the same path ending `-` with
no digits. Two things hold it down:

- **`path:` without a line number is not admitted.** Admitting it admits any
  first word ending in a colon, which is the `base64:` row the named-pair step
  above was chosen to refuse. So a body on a *matched* line under `grep -r`
  without `-n` is a stated under-fire. A pattern has to match the body itself
  to produce it.
- **A body behind a grep prefix has to reach the end of its line.** The prefix
  can stop at any hyphen inside the path, and `/` is in the base64 alphabet, so
  a Go pseudo-version reads as a key body: `-3a47de7e79bd/googleapis/appengine/v1/certificate`
  is 48 bytes of it. The first draft of this arm reported genproto's
  `certificate.pb.go`, a doc comment displaying a header, in four module
  versions. A body line ends where the line does and a path does not.

**The arm runs on every buffer and not only on grep output, so on a raw file it
can only add false positives.** A PEM body line never holds a `-`. Under a
header, the line `https://example.com/some-` followed by 36 base64 characters
to the end of the line exits 3 here and 0 on `main`. That is the class it
belongs to, not the whole of it: any first word ending in `-` and followed by
a base64 run to the line's end. The differential below finds no instance of
it in real files, and the independent review of this change re-took it over
985 files and found none either. It is a constructed cost and not a measured
one.

**A key under a path with a space crosses the filter.** The prefix arm admits no
whitespace, because a path that may contain spaces is a prose line, and prose
under a header is the thing this rule refuses. So `grep -rn -A3` over
`my keys/k.pem` passes the key, where the same file read raw, or grepped with
`-h`, is blocked. Found by the same review and driven here.

**The differential is the files a key-bearing grep would print.** Over the 974
files under `~/go/pkg/mod` carrying `PRIVATE KEY` on 2026-10-25, each read raw
and as `grep -A30 'PRIVATE KEY'` output under `-n -H`, `-H` and `-n -h`: raw,
both clauses report 834 matches in 587 files and the set the arm newly admits
is **empty**. As grep output `main` reports **0**, and this clause reports 827
matches in the same 587 files under all three prefixes, with no file reported
that is not reported raw. The 7 matches short of raw are all in one go-jose
test file, and are other rules' findings past the 30-line window, four of them
named `jwt` and three not named. It is a reading over one
machine's module cache and nothing re-runs it.

`TestTheCorpusAsGrepOutput` is the gate that does re-run. It reads every clean
file as grep output under all four prefixes and demands silence, and reads the
planted PEM files the same way and demands a finding, so the zero cannot come
from a transform that broke the rule. Only `tls-runbook.md` of the 13 clean
files carries the keyword, so that zero is a floor. Grep output of this
repository was read the same way:
`grep -rn -A5 KEY`, `-rn -A30 PRIVATE.KEY`, `-r -A30 PRIVATE.KEY`,
`-rn -C10 BEGIN` and `-rn -A3 -i token`, outside `planted/`, `vectors/` and
`.git`, 3,026 lines at the largest. Every one exits 0 on both builds, and the
same `-rn -A30` with `planted/` put back blocks on 7 matches on this one and
on none on `main`.
[`private-key-block-in-grep-output.txt`](../testdata/corpus/planted/private-key-block-in-grep-output.txt)
is real `grep -rn -A30` output of an encrypted key, so the prefix falls on the
RFC 1421 fields and the separator line as well as the body.

**Two rules carry a second check, because their vendor publishes a realistic
example.** An entropy floor drops a padded placeholder and admits a plausible
one, which is the shape a documentation page carries. Both checks are in
[`internal/validate`](../internal/validate/) with the arithmetic; what follows
is why each one has a boundary, since a suppression list that does not is the
argument [Q33](../docs/queue/Q33.md) makes against extending
`card-placeholder`'s table.

`aws-access-key-id` names `aws-placeholder`, which drops a key ID ending in
`EXAMPLE`. That is AWS's own mark — `AKIAIOSFODNN7EXAMPLE` on the IAM pages,
`ASIAIOSFODNN7EXAMPLE` on the STS ones, and
`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` for the secret printed beside
them. A suffix rather than a table, so there is no
vendor list to bound: the boundary is one vendor's convention over its own key
IDs, which is the entire namespace this rule matches. Over the 145 tracked files
of this repository on 2026-08-27 the rule went from 13 matches to 2, and every
one of the 11 it dropped was that pair. A twelfth was the planted fixture, which
carried the same key and was rewritten rather than dropped. What it costs is a
real key whose last seven characters are `EXAMPLE`, which is one in 3.4e10 at
the smallest alphabet that tail can be drawn from.

**Four prefixes ship, and each one is reachable by a test.** The ruleset was
inherited carrying five, and three of them — `A3T`, `ABIA` and `ACCA` — traced
to nothing AWS publishes. Reading [AWS's IAM identifiers reference][iam-ids] on
2026-09-07 settled all three at once. Its *Understanding unique ID prefixes*
table names twelve: `ABIA` (AWS STS service bearer token), `ACCA`
(context-specific credential), `AGPA`, `AIDA`, `AIPA`, `AKIA` (access key),
`ANPA`, `ANVA`, `APKA`, `AROA`, `ASCA` and `ASIA` (temporary STS access key).
`ABIA` and `ACCA` are on it and stay. `A3T` is not on it, and is cut.

The reading is dated because the table carries its own caveat — "Prefixes may
vary based on when they were created" — so a prefix retired before AWS kept a
public list would be missing from it for a reason that has nothing to do with
whether keys on it exist.

The other two were already sourced twice over: `aws-placeholder` below,
`internal/validate/aws.go` and `testdata/corpus/README.md` all cite
`AKIAIOSFODNN7EXAMPLE` on the IAM pages and `ASIAIOSFODNN7EXAMPLE` on the STS
ones, which is AWS printing a key on each of those prefixes.

What the arms cost on real source is a separate reading, taken before that one
and unaffected by it. Each arm compiled alone over `~/go/pkg/mod`, 239,671 files
and 5.05 GiB of third-party Go source, with every arm first driven against a
value built for it so a zero below is a property of the population rather than
of the pattern.

| Arm | regex matches | surviving entropy 3.0 and `aws-placeholder` |
|---|---|---|
| `A3T`, since cut | 0 | 0 |
| `AKIA` | 56 | **0** |
| `ASIA` | 5 | 2 |
| `ABIA` | 0 | 0 |
| `ACCA` | 0 | 0 |

**Read the `AKIA` row before drawing anything from the zeros.** It is the arm
nobody disputes, and on this population it too survives nothing: 56 matches, all
of them dropped. So *zero surviving matches is not evidence an arm is dead* —
it is what the arm everybody keeps also does here. What separates the rows is
the raw count, and even that measures the wrong thing for the question: a module
cache is published source, so it holds placeholders and test fixtures rather
than issued credentials. It says which prefixes people *write down*, never which
AWS hands out.

**The cut is AWS's list, and not the zeros.** `A3T` reports 0 and 0 in the
table, and so does `AKIA` on the surviving column — the paragraph above forbids
reading a zero as evidence an arm is dead, and it forbids it in this direction
too. What the zero does add is a bound on what cutting `A3T` costs here: over
5.05 GiB of published Go source, nothing writes an `A3T` key ID down at all, so
no observable match is lost. What no reading here bounds is a prefix AWS issues
and has not listed, which is what the table's own caveat leaves open.

`ABIA` and `ACCA` report the same 0 and 0 and stay, because they are on the
list. That is the whole of the rule: an arm is kept or cut on what AWS
documents, and the population reading says only what it costs either way.

`private-key-block` keeps its `SSH2 ENCRYPTED ` and `PGP ` arms on the
keep-anyway half of the argument one section up: deleting an arm is a judgement
about what nothing writes rather than a proof, so the cheaper error is to keep
it. Only that half carries. Those two arms are shown dead *structurally*, by
reading the armor real toolchains emit. The AWS arms have their own version of
that reading now — AWS's published prefix table — and it is what cut one and
kept four. Until it was read, the zeros could not make the move and every arm
stayed.

What the arms did lack was evidence they could fire.
`TestEveryAWSPrefixArmIsReachable` in
[`internal/scan`](../internal/scan/awsprefix_test.go) drives one value per arm
through the shipped rule, and
[`testdata/corpus/planted/aws-access-key-id-asia.env`](../testdata/corpus/planted/aws-access-key-id-asia.env)
plants the `ASIA` one end to end. Before both, deleting `ASIA` — or all four
non-`AKIA` arms together — left `go test ./...` green; each of the five
deletions is red now, driven one at a time. An arm no test can distinguish from
absent is surface with no evidence behind it, and that was the defect rather
than the arms.

What would reverse this is the reading nobody here has taken: AWS's own list of
the prefixes it issues. A prefix absent from it is an arm to cut. What gets
deleted then is the paragraph above opening **All five prefixes stay** and this
one; the table and the paragraph between them survive either way, because they
are about what the arms cost and what tests them rather than about why they are
kept.

`jwt` names `jwt-sample-key`, which recomputes the HMAC and drops a token that
verifies under a published sample secret. A debugger that wants its own example
reproducible has to publish the key, so what separates that sample from a live
token is visible after all. One secret is listed, `your-256-bit-secret`, and it
is measured: HMAC-SHA256 over the first two segments of the token on jwt.io's
front page reproduces that token's signature exactly. Keys are the better half
of the pair to enumerate, because the list then also covers a payload somebody
edited in the debugger before pasting the result — which a token list cannot
reach. What it costs is a real token whose owner signed it with a copied sample
secret. That is a false negative on a dangerous file, and not one this tool can
help with: a token anyone can forge is not protected by stopping the paste.

**It is coupled to where the token ends, and that is no longer a bound.** The
check recomputes over the capture it is handed, so a capture ending one byte
early makes the comparison fail and a published sample gets reported as a
credential. Between Q133 and Q164 the capture's end came from the pattern's
third repeat — the bound that reads free, because nothing follows the signature,
so a short one truncated the capture rather than refusing the token. HS512 is
the longest HMAC signature at 86 bytes; the bound was 1,000, and read off the
two corpus tokens, both HS256, a bound would have landed on 43.

`jwt` is the one rule that names an **extent**, and that is what replaced the
bound.

## `extent`: where the thing ends, when the pattern cannot say

A validator answers yes or no about the bytes it was handed. It cannot ask for
more of them, and for one rule that is the wrong shape: RE2 caps a bounded
repeat at 1000 — driven, `{8,1000}` compiles and `{8,1001}` returns `invalid
repeat count` — so a pattern that has to cross one segment of a JWT to reach the
next cannot cross more than 1,003 bytes of it. That is Go's ceiling and not the
format's, and a production access token with many claims is past it. It went
unmatched, in silence.

So the rule detects with a pattern and measures with an extent:

| | |
|---|---|
| `regex` | `\b(eyJ[A-Za-z0-9_-]{8})` — a base64url-encoded JSON object starts here |
| `extent` | `jwt-token` — three segments, two dots, no ceiling |

The pipeline runs the extent between the match and the checks and widens the
capture to what it returned, at one call site, so every check sees the whole
token rather than a prefix of it. An extent may refuse, and does for about 95%
of what the pattern matches: `eyJ` heads any encoded JSON object, and the walk
is the whole of what separates one from a token.

Two things follow that are worth stating rather than rediscovering. The
truncation above is now unreachable through a bound, because no repeat in the
pattern reaches the capture — the failure mode is a walk that stops in the wrong
place, which
[`internal/validate/extent_test.go`](../internal/validate/extent_test.go) drives
against every byte class that can follow a token. And the rule's entropy floor
of 3.5 is only meetable because of the extent: the pattern captures eleven
bytes, which cannot carry more than log2(11) = 3.459 bits, so the loader reads
the extent's alphabet rather than the pattern's capture when it checks that a
floor is reachable at all.

[`internal/scan/jwt_extent_test.go`](../internal/scan/jwt_extent_test.go)
carries the end-to-end arms, against the ruleset as Q133 shipped it.

## Numeric PII: `us-ssn` ships on, the other three stay off

Every one of the inherited false positives came from numeric PII rules, so
the family shipped off from the start. All four are written as they would have to
be if anyone turned them on:

| Rule | Validators | Ships |
|---|---|---|
| `us-ssn` | `context-label` | **on** |
| `payment-card` | `luhn`, `card-placeholder`, `context-label` | off, measured below |
| `cn-resident-id` | `mod-11`, `context-label` | off |
| `ipv4-public` | `reserved-range` | off |

**What `us-ssn` finds is narrow, and that is the sentence to repeat.** A value
written `###-##-####`, area below 900, with `ssn` or `social security` in the 64
bytes before it, in any case and spelled with a space, a hyphen, an underscore or
nothing. A bare nine digits is not read, because `\b\d{3}-?\d{2}-?\d{4}\b` is an order number, a
phone number and a serial. Neither is a label after the value, or a column header
further back than the window, so most rows of a CSV go unreported.
`TestUSSSNShapes` holds each of those.

The snake_case and camelCase field names are in the list because a value under
`social_security_number` or `socialSecurityNumber` went unreported, the second past
the label's own word boundary. Over the populations below, each of the two labels
newly fires on nothing but the control written to test it.

**Karl chose `us-ssn` alone on 2026-11-03, on this reading.** Nothing re-runs it, and
it is a reading of how often each rule fires on clean text rather than a precision
ratio: no population was expected to hold a real value and no hit was identified as
one, so every hit counts as a false positive by construction. Files deduplicated by
content within each population, binaries skipped, `.git` and worktrees not walked,
files over 64 MiB skipped.

| Population | Files | `us-ssn` files | `payment-card` files |
|---|---|---|---|
| `~/go/pkg/mod` | 136,126 | 10 | 2 |
| `~/workspace`, this machine | 64,538 | 1 | 0 |
| `/opt/homebrew` | 25,235 | 0 | 0 |
| `~/Library/Logs`, `/var/log` | 117 | 0 | 0 |
| public payment projects, 9 | 49,611 | 1 | 318 |
| public infrastructure, 4 | 33,248 | 1 | 0 |
| public data sets, 3 | 912 | 0 | 1 |
| public applications, 3 | 85,729 | 0 | 11 |
| **Those eight** | **395,516** | **13, 0.003%** | **332, 0.08%** |
| public PII tooling, 4 | 5,724 | 17 | 16 |
| public projects where an SSN field belongs, 17 | 60,637 | 81, 0.13% | 1 |

The public projects were shallow clones picked to be adversarial, so their rates do
not generalise. The last reading is the traffic: 5.00 GB of this machine's Claude
Code transcripts, 521,519 distinct prompts, commands and tool results, where neither
rule fires on anything the hook scans. `payment-card` fires 6 times there, on what
reads as Stripe's page of test numbers, from a tool whose results no hook reads.

**`payment-card` fires where a payment integration lives.** 308 of the 864 files in
`active_merchant`, 35.6%, are gateway test numbers the 34-entry denylist does not
hold, and the label gate cannot help, because a fixture is labelled exactly as a real
card would be: `credit_card('…')` holds `card`. Each of those files would be a denied
`Read`, and `Read` has no override. The clean corpus reads 0 on this rule throughout,
which is why that zero carries no weight. [Q33](../docs/queue/Q33.md) has the rest.

**`us-ssn` fires where an SSN field lives, at a rate the 0.003% does not show.** No
population behind that figure holds such a project, so the table's last row was
swept after Karl's choice: HR, health records, tax, government identity and
validators. `18F/identity-idp` reads 39 of 4,814 files, 0.81%,
`codeforamerica/vita-min` 20 of 4,359, 0.46%, and 8 of the 17 read none. The mechanism
is `payment-card`'s: a fixture is labelled as a real record is, and 72 of the 81 have
a test-, example- or docs-shaped path. Each is a denied `Read`, with no override, for
a session working there. The peak is 44x below `active_merchant`. By the harness's
flags, not driven through a validator, 45 of the 81 hold nothing but placeholder
values no check drops, and so do all 10 in `~/go/pkg/mod`;
[Q242](../docs/queue/Q242.md) has that. Shown this row, Karl kept the rule as it is and
left Q242 for later.

What this leaves out: `~/Documents`, `~/Downloads` and mail, deliberately, so recall
on real values is unmeasured; non-English text; exports beyond those data sets; and
four more projects of that last kind, `vets-api`, `vets-website`, `mymove` and
`moov-node`, whose clones returned `Repository not found`.

**The other half of the decision is cost, because no prefilter gates this family.**
One thread, 20,000 real text files, 312 MB, minimum of three, on `efac304`, on a
machine other sessions were using: 97.75 MB/s for the shipped set, 38.40 with
`us-ssn`, 2.55x. Process start did not move with both PII rules on, at 4.5ms. The
worst case tried is 32 MiB of synthetic grouped digits, 23ms to 1.357s.

## Adding a rule

Four things, and the `precision` gate fails without the last two.

1. For a `credential` rule, a literal anchor in `keywords`, with a word boundary
   the regex agrees with. The prefilter requires a boundary in front of the
   keyword, so a regex that does not open on `\b` matches text the gate will
   never hand it. A `pii` rule takes none: the prefilter gates the credential
   family and nothing else, so keywords there are a startup failure rather than
   a field that does nothing.
2. RE2 only: no lookaround, no backreferences, bounded repetition capped at
   1000. The loader refuses anything else at startup.
3. A planted fixture under `testdata/corpus/planted/`, named for the rule,
   carrying exactly one match. A rule with no fixture fails
   `TestEveryEnabledRuleHasAPlantedFile`, because a rule that matches nothing
   reports the same clean result as a rule that checked.
4. The clean corpus still at zero. A rule that needs an exception to stay quiet
   is a rule to drop.

[iam-ids]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
