# The precision corpus

Two halves, and the gate over them is
[`scripts/check-precision.py`](../../scripts/check-precision.py) by way of
`internal/scan/corpus_test.go`. Run it with `make precision`.

| Half | What it asserts |
|---|---|
| `clean/` | The shipped ruleset reports **zero** findings. That number is pinned. |
| `planted/` | Each file produces **exactly one** finding, of the rule its filename names. |

## Nothing in `planted/` is a real credential

Every value is fabricated to the shape its rule matches and works against
nothing, and every one of them was written for this directory.

Most of them carry the stem `ZmT4bXn9Ld6VcP1`, matched case-insensitively —
`aws-access-key-id.env` holds it uppercase, that rule being `[A-Z0-9]{16}`.
That is deliberate: it makes "fabricated" something a reader can grep for
rather than something this file asserts. The exceptions are
`github-fine-grained-pat.txt`, which carries the stem with an underscore
through the middle because its rule admits one; the PEM blocks, whose bodies
are base64 of ordinary ASCII; and `slack-webhook-url.yaml`, which predates the
convention.

`aws-access-key-id.env` is the newest of them. It used to carry
`AKIAIOSFODNN7EXAMPLE`, the key AWS publishes in its own documentation, and the
rule now drops that key on the `EXAMPLE` suffix. A fixture proving a rule can
fire cannot be a value the rule is supposed to stay quiet on.

They are here as literals rather than assembled at scan time because the thing
under test is a buffer, and a fixture that only exists inside a test is a
fixture nobody can read.

## `clean/` has to stay adversarial

A corpus gate pinned at zero is worth exactly what its clean half is worth, and
a bland clean half reports zero for a reason that has nothing to do with the
ruleset. So the clean files are checked against two of the rules that produced
the inherited 5,679 —
[`docs/design/language-choice.md`](../../docs/design/language-choice.md) §3 has
them — and both still have to fire:

| Inherited rule | Matches on `clean/`, 2026-08-27 | Floor |
|---|---|---|
| `pii-postal-code` `\b\d{5}(?:-\d{4})?\b` | 31 | 20 |
| `pii-phone-cn` | 8 | 6 |

The three worked examples the design names are all in here deliberately:
`65536` in `buffers.go` and `nginx.conf`, the NodePort `30443` in
`k8s-service.yaml` and `main.tf`, and the amdgpu DKMS string
`1:6.16.13.30300400-2341068` in `dkms-status.txt`, whose `0400-2341068` slice
was reported 268 times as a Chinese phone number.

`env.example` and `payments.md` are the other half of the same idea:
placeholder credentials and published test card numbers, which are what a real
repository is full of and what a scanner has to be silent about.

`tls-runbook.md` is there for one rule. `private-key-block` requires a base64
body line after the PEM header, and nothing else in the corpus reaches that
rule at all — so the clause could be deleted with every test still green. The
runbook quotes four headers in prose, which turns a deletion into 4 findings
and a red gate. A rule with no clean file touching it has a guard that cannot
fire.

`iam-policy-notes.md` and `jwt-debugging.md` are two more of the same, for the
two rules whose vendor publishes an example realistic enough to clear an
entropy floor. The first quotes AWS's documented access key ID and its STS
counterpart; the second quotes the sample token on jwt.io's front page. Each
holds down one validator: removing `aws-placeholder` takes the clean half to 2
findings and removing `jwt-sample-key` takes it to 1, both measured by driving
the deletion rather than by reading the rule.

## Adding to it

**A clean file** goes in as it was written, not tidied. Anything it forces you
to except is a rule to drop rather than a file to edit — that is the whole
argument for pinning the count at zero.

**A planted file** is named for its rule, carries one match, and is listed in
the `planted` map in `internal/scan/corpus_test.go`. The map is what carries
the count, which the filename cannot; a file in one and not the other fails the
gate from either side.
