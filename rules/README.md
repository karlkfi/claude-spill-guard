# The shipped ruleset

`spill-guard.json` is the v1 ruleset: ten credential rules, and four numeric
PII rules that ship off. `internal/rules` can layer `.claude/spill-guard.json`
over it — an entry whose `id` is already here overrides the fields it names, so

```json
{"rules": [{"id": "jwt", "enabled": false}]}
```

is the shape that turns one off. The schema, the merge, and what the loader
refuses are in
[`docs/design/README.md`](../docs/design/README.md#rule-schema).

**Nothing reads that file yet.** `spill-guard hook` loads the compiled-in set
and passes no override, so the paragraph above describes the loader rather than
the shipped tool. Honouring a disablement written by whatever can write files
in the project is a decision about a bypass, and it is
[Q73](../docs/queue/Q73.md).

JSON has no comments, so the reasoning is here.

## Ten credential rules, not seventy

The predecessor's ruleset flagged 27.6% of 257 real files and produced 5,679
matches with zero credentials in them. That is a precision failure, not a
coverage one, so v1 does not aim at gitleaks-level breadth. Every rule below
anchors on a literal a scanner can prefilter on, and every one of them is
carried by a planted fixture in
[`testdata/corpus/`](../testdata/corpus/README.md).

| Rule | Anchor | What keeps it quiet |
|---|---|---|
| `aws-access-key-id` | `AKIA` `ASIA` `ABIA` `ACCA` `A3T` | 20 fixed characters, Shannon floor 3.0, and no `EXAMPLE` suffix |
| `github-token` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | 36 fixed characters, floor 3.0 |
| `github-fine-grained-pat` | `github_pat_` | 70–90 characters, floor 3.0 |
| `slack-token` | `xoxa-` `xoxb-` `xoxe-` `xoxp-` `xoxr-` `xoxs-` | floor 3.0 |
| `slack-webhook-url` | `hooks.slack.com` | the host and both path segments are literal; the floor reads the last segment only |
| `stripe-live-secret-key` | `sk_live_` `rk_live_` | live keys only — see below |
| `openai-api-key` | `sk-` | the embedded `T3BlbkFJ`, floor 3.0 |
| `google-api-key` | `AIza` | 39 fixed characters, floor 3.0 |
| `private-key-block` | `PRIVATE KEY` | a base64 body line has to follow the header, across RFC 1421's headers if the key has them, indented or not |
| `jwt` | `eyJ` | three segments, the first two both opening `eyJ`, floor 3.5, and no published sample signature |

**The entropy floors are what make a *padded* placeholder quiet.** A repository
holds far more `AKIAXXXXXXXXXXXXXXXX` than it holds keys, and the two are the
same shape to a regex; the padded one carries 1.0219 bits per byte against a
floor of 3.0, so it goes. What a floor cannot reach is a published example
written to look like a key. AWS's own measures 3.6842 and clears the floor by
design, and the jwt.io sample token measures 5.4441 against 3.5 — the two
rules below carry a second check for exactly that. Four of the ten rules match
[`testdata/corpus/clean/env.example`](../testdata/corpus/clean/env.example) and
none of the four survives its own validator.

**`sk_test_` is not a credential and is not matched.** A Stripe test key is
published by the integrator in their own README, works against nothing, and
appears beside the test card numbers. Matching `sk_live_` and `rk_live_` costs
no recall that matters and removes a whole class of file from the output.
[`testdata/corpus/clean/payments.md`](../testdata/corpus/clean/payments.md) is
that file.

**`slack-webhook-url` reports the last path segment rather than the URL.** The
entropy check reads the captured group, and a webhook URL is mostly a literal
host, so capturing the whole thing would put a floor over text that is the same
in every match. Capturing the secret tail lets the floor drop
`.../B00000000/XXXXXXXXXXXXXXXXXXXXXXXX` without dropping a real one.

**Nine of the ten carry an entropy floor. The tenth is structural instead.**
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
count stays at its planted fixtures, 3 of them. The reading that holds is the
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

**All five prefixes stay, and each one is now reachable by a test.** The
ruleset was inherited, and for three of the five — `A3T`, `ABIA` and `ACCA` —
nothing here traces the prefix to anything AWS publishes. The other two are
sourced: `aws-placeholder` below, `internal/validate/aws.go` and
`testdata/corpus/README.md` all cite `AKIAIOSFODNN7EXAMPLE` on the IAM pages and
`ASIAIOSFODNN7EXAMPLE` on the STS ones, which is AWS printing a key on each of
those prefixes. Settling the unsourced three means reading AWS's IAM identifiers
reference, which this build graph is forbidden to fetch.

What can be measured is the cost of being wrong in each direction, and it is
lopsided. Each arm compiled alone over `~/go/pkg/mod`, 239,671 files and 5.05
GiB of third-party Go source, with every arm first driven against a value built
for it so a zero below is a property of the population rather than of the
pattern.

| Arm | regex matches | surviving entropy 3.0 and `aws-placeholder` |
|---|---|---|
| `A3T` | 0 | 0 |
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

What it does settle is the cost. The three unsourced arms are `A3T`, `ABIA` and
`ACCA`, and each adds no match at all to a 5 GiB population — not a surviving
one, not a dropped one — so keeping them costs nothing this reading can find.
Cutting one AWS does issue costs a missed credential, which is the failure the
tool exists to prevent. That asymmetry decides it on its own, without needing
the zeros to mean more than they do.

`private-key-block` keeps its `SSH2 ENCRYPTED ` and `PGP ` arms on the
keep-anyway half of the argument one section up: deleting an arm is a judgement
about what nothing writes rather than a proof, so the cheaper error is to keep
it. Only that half carries. Those two arms are shown dead *structurally*, by
reading the armor real toolchains emit, and no equivalent reading exists for a
prefix AWS may or may not issue — which is exactly the move the paragraph above
says these zeros cannot make.

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

## The numeric PII family ships disabled

Every one of the 5,679 inherited false positives came from numeric PII rules.
Shipping the family off is the finding rather than a deferral, and the four
rules here are written as they would have to be if anyone turned them on:

| Rule | Validators |
|---|---|
| `payment-card` | `luhn`, `card-placeholder`, `context-label` |
| `us-ssn` | `context-label` |
| `cn-resident-id` | `mod-11`, `context-label` |
| `ipv4-public` | `reserved-range` |

Forced on, they report nothing over the clean corpus — the checksums, the
reserved ranges and the label proximity are exactly what the inherited family
had none of. That is one small corpus and not a case for enabling them: the
family also has no prefilter, so every one of these rules costs a full regex
pass over every buffer, which is the second reason
[the design](../docs/design/README.md#pipeline) gives for the default.

`us-ssn` requires the hyphens. `\b\d{3}-?\d{2}-?\d{4}\b` is a nine-digit run
with optional punctuation, which is an order number, a phone number and a
serial; the hyphenated form is what people actually write an SSN as.

## Adding a rule

Four things, and the `precision` gate fails without the last two.

1. A literal anchor in `keywords`, with a word boundary the regex agrees with.
   The prefilter requires a boundary in front of the keyword, so a regex that
   does not open on `\b` matches text the gate will never hand it.
2. RE2 only: no lookaround, no backreferences, bounded repetition capped at
   1000. The loader refuses anything else at startup.
3. A planted fixture under `testdata/corpus/planted/`, named for the rule,
   carrying exactly one match. A rule with no fixture fails
   `TestEveryEnabledRuleHasAPlantedFile`, because a rule that matches nothing
   reports the same clean result as a rule that checked.
4. The clean corpus still at zero. A rule that needs an exception to stay quiet
   is a rule to drop.
