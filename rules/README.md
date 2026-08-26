# The shipped ruleset

`spill-guard.json` is the v1 ruleset: ten credential rules, and four numeric
PII rules that ship off. A project layers `.claude/spill-guard.json` over it —
an entry whose `id` is already here overrides the fields it names, so

```json
{"rules": [{"id": "jwt", "enabled": false}]}
```

is how a project turns one off. The schema, the merge, and what the loader
refuses are in
[`docs/design/README.md`](../docs/design/README.md#rule-schema).

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
| `aws-access-key-id` | `AKIA` `ASIA` `ABIA` `ACCA` `A3T` | 20 fixed characters, Shannon floor 3.0 |
| `github-token` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | 36 fixed characters, floor 3.0 |
| `github-fine-grained-pat` | `github_pat_` | 70–90 characters, floor 3.0 |
| `slack-token` | `xoxa-` `xoxb-` `xoxe-` `xoxp-` `xoxr-` `xoxs-` | floor 3.0 |
| `slack-webhook-url` | `hooks.slack.com` | the host and both path segments are literal; the floor reads the last segment only |
| `stripe-live-secret-key` | `sk_live_` `rk_live_` | live keys only — see below |
| `openai-api-key` | `sk-` | the embedded `T3BlbkFJ`, floor 3.0 |
| `google-api-key` | `AIza` | 39 fixed characters, floor 3.0 |
| `private-key-block` | `PRIVATE KEY` | a base64 body line has to follow the header |
| `jwt` | `eyJ` | three segments, the first two both opening `eyJ`, floor 3.5 |

**The entropy floors are what make a placeholder quiet.** A repository holds
far more `AKIAXXXXXXXXXXXXXXXX` than it holds keys, and the two are the same
shape to a regex. It carries 1.0219 bits per byte against 3.6842 for AWS's own
documented example, so the floor separates them and no denylist has to. Four of
the ten rules match
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
after the header. Prose quoting `-----BEGIN RSA PRIVATE KEY-----` to explain
what one looks like carries no such line and is not reported. That was not
hypothetical: the paragraph you are reading, and the row that filed the
problem, were both findings until the clause landed. Scanned over every tracked
file, the rule went from 3 hits to 1, the one being its own planted fixture.

The cost is a header truncated at a buffer boundary, which is a real recall gap
and a deliberate one: a key without its body is not a key.

**Two rules still have no answer for their own documentation**, and Q60 carries
both. `jwt`'s 3.5 bits are real and the jwt.io sample token clears them at
5.4441, because a sample JWT and a live one differ only in a signing key the
scanner cannot see. `aws-access-key-id` is the same shape from the other
direction: AWS's own published example reaches 3.6842 and passes the floor by
design, which is what makes the floor work on placeholders and useless here.

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
