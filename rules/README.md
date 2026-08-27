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
| `aws-access-key-id` | `AKIA` `ASIA` `ABIA` `ACCA` `A3T` | 20 fixed characters, Shannon floor 3.0, and no `EXAMPLE` suffix |
| `github-token` | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | 36 fixed characters, floor 3.0 |
| `github-fine-grained-pat` | `github_pat_` | 70–90 characters, floor 3.0 |
| `slack-token` | `xoxa-` `xoxb-` `xoxe-` `xoxp-` `xoxr-` `xoxs-` | floor 3.0 |
| `slack-webhook-url` | `hooks.slack.com` | the host and both path segments are literal; the floor reads the last segment only |
| `stripe-live-secret-key` | `sk_live_` `rk_live_` | live keys only — see below |
| `openai-api-key` | `sk-` | the embedded `T3BlbkFJ`, floor 3.0 |
| `google-api-key` | `AIza` | 39 fixed characters, floor 3.0 |
| `private-key-block` | `PRIVATE KEY` | a base64 body line has to follow the header |
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
after the header. Prose quoting `-----BEGIN RSA PRIVATE KEY-----` to explain
what one looks like carries no such line and is not reported. That was not
hypothetical: the paragraph you are reading, and the row that filed the
problem, were both findings until the clause landed. Scanned over every tracked
file, the rule went from 3 hits to 1, the one being its own planted fixture.
Re-taken 2026-08-27 over 145 tracked files: still 1, and 8 with the clause
removed. That second number grows as prose about the rule accumulates — four
of the eight are the runbook below — so the reading that holds is the gated
one in the next paragraph rather than this one.

[`testdata/corpus/clean/tls-runbook.md`](../testdata/corpus/clean/tls-runbook.md)
is what holds that down. It quotes four PEM headers in prose, so removing the
clause takes the clean corpus from 0 findings to 4 and reddens the gate. Before
that file existed the clause could be reverted with every test still passing,
which is the shape this whole item is about.

The cost is a header truncated at a buffer boundary, and an RFC 1421 encrypted
key, whose `Proc-Type:` line sits where the body would be. A PKCS#8 encrypted
key has base64 straight after the header and does match. Two arms of the
alternation, `SSH2 ENCRYPTED ` and `PGP `, reach nothing their toolchains
actually emit and have been dead since the rule was written. Q69 has all three
with the measurements, and reading it before trusting this rule's coverage is
the point of it.

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
