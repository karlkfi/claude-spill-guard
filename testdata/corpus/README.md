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
nothing. `aws-access-key-id.env` carries `AKIAIOSFODNN7EXAMPLE`, which is the
key AWS publishes in its own documentation. The rest were written for this
directory.

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

| Inherited rule | Matches on `clean/`, 2026-08-25 | Floor |
|---|---|---|
| `pii-postal-code` `\b\d{5}(?:-\d{4})?\b` | 30 | 20 |
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

## Adding to it

**A clean file** goes in as it was written, not tidied. Anything it forces you
to except is a rule to drop rather than a file to edit — that is the whole
argument for pinning the count at zero.

**A planted file** is named for its rule, carries one match, and is listed in
the `planted` map in `internal/scan/corpus_test.go`. The map is what carries
the count, which the filename cannot; a file in one and not the other fails the
gate from either side.

`aws-access-key-id-utf16le.env` is the one file here that is not testing a
rule. It tests an encoding: UTF-16LE with a byte-order mark, which is what
Windows PowerShell 5.1 writes through `>`. It sits in the corpus rather than in
a unit fixture so that the shipped ruleset and the gate's own walk are what read
it — a decode asserted only against a buffer assembled in a test proves nothing
about a file on disk, and this repository normalises line endings on everything
it does not exempt. `.gitattributes` marks it `-text` for that reason.

Its key is its own, and that is the rule rather than an accident: two fixtures
sharing one literal makes every edit to one a silent break in the other. The
in-memory pair in `internal/scan/decode_test.go` is where identical text is
scanned in both encodings, which is the comparison that needs identity.

**Put something in the value that a reader can check.** This directory is
public and it ships inside a security tool, so someone who finds a
credential-shaped string here has only the sentence above to tell them it is
inert — and in `aws-access-key-id-utf16le.env` they cannot read it at all
without decoding the file first. `AKIA0SPILLGUARD98107` carries this project's
name, which anyone can grep for and no issued credential would contain. That
costs nothing and needs no argument.

The digits in it are a second, weaker signal, and the difference is worth
stating rather than blurring. A widely used technique recovers an AWS account
ID by base32-decoding a key ID's 16-character body, which would mean a real one
draws from A-Z and 2-7 and can never contain `0`, `1`, `8` or `9`. **Nobody
here has verified that against an authoritative source.** AWS's [IAM
identifiers reference][iam-ids] documents the prefixes and says nothing about
the alphabet, and its own examples are hand-written non-keys that prove nothing
either way — `AROA1234567890EXAMPLE` on that page contains every digit, and
AWS's two published access key IDs disagree with each other, `AKIAI44QH8DHBEXAMPLE`
carrying an `8` where `AKIAIOSFODNN7EXAMPLE` draws only from A-Z and 2-7.

So treat the digits as a hedge, not a proof, and let the greppable name carry
the claim. `internal/rules/capture_test.go` reached the same shape first, with
`AKIA0123456789ABCDEF`.

[iam-ids]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
