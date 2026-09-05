# The precision corpus

Two halves, and the gate over them is
[`scripts/check-precision.py`](../../scripts/check-precision.py) by way of
`internal/scan/corpus_test.go`. Run it with `make precision`.

| Half | What it asserts |
|---|---|
| `clean/` | The shipped ruleset reports **zero** findings. That number is pinned. |
| `planted/` | Each file produces **exactly one** finding, of the rule its filename names. |

`vectors/` sits beside them and is neither: nothing walks it, no rule runs over
it, and it contributes to neither count. It holds the strings the unit tests
elsewhere read, and the section below says why they are kept here.

## Nothing in `planted/` is a real credential

Every value is fabricated to the shape its rule matches and works against
nothing, and every one of them was written for this directory.

Most of them carry the stem `ZmT4bXn9Ld6VcP1`, matched case-insensitively —
`aws-access-key-id.env` holds it uppercase, that rule being `[A-Z0-9]{16}`.
That is deliberate: it makes "fabricated" something a reader can grep for
rather than something this file asserts. The exceptions are
`github-fine-grained-pat.txt`, which carries the stem with an underscore
through the middle because its rule admits one; the PEM blocks, whose bodies
are base64 of ordinary ASCII; `slack-webhook-url.yaml`, which predates the
convention; and the two AWS files that carry `0SPILLGUARD` instead —
`aws-access-key-id-utf16le.env` and `aws-access-key-id-asia.env` — for the
reason **Adding to it** gives below, which is the mark to reach for now.

`aws-access-key-id.env` used to carry `AKIAIOSFODNN7EXAMPLE`, the key AWS
publishes in its own documentation, and the rule now drops that key on the
`EXAMPLE` suffix. A fixture proving a rule can fire cannot be a value the rule
is supposed to stay quiet on.

Three files carry `aws-access-key-id`, and the third is about the rule rather
than the encoding. The rule matches five prefixes — `A3T[A-Z0-9]`, `AKIA`,
`ASIA`, `ABIA` and `ACCA` — and the two files above are both `AKIA`, so a walk
over this corpus could not tell `ASIA` from absent. `aws-access-key-id-asia.env`
is the STS session key that closes it. The other three arms are covered by
`TestEveryAWSPrefixArmIsReachable` in `internal/scan` off the vectors below,
rather than by a file each: what a corpus file buys over a vector is the walk
and the validators, and `ASIA` is the arm where that matters, because
`iam-policy-notes.md` already holds an `ASIA` the rule has to **drop** and
nothing held one it has to find.

They are here as literals rather than assembled at scan time because the thing
under test is a buffer, and a fixture that only exists inside a test is a
fixture nobody can read.

Three files carry `private-key-block`, because the rule has three layouts to
reach. `private-key-block.pem` is a body on the line after the header;
`private-key-block-rfc1421.pem` is the encrypted PKCS#1 form, with `Proc-Type:`
and `DEK-Info:` in between, which is what `openssl rsa -aes128 -p` and
`ssh-keygen -m PEM -N` write; and `private-key-block-indented.yaml` is that same
encrypted key inside a Kubernetes secret's block scalar, indented by four.

The third is the encrypted layout deliberately. Indentation and encryption are
one fixture rather than two because a widening that admits an indented body and
not indented `Proc-Type:` and `DEK-Info:` lines leaves this file reporting
nothing — driven, and the reason it is not a plain indented key. Its body is
`private-key-block-rfc1421.pem`'s, which is the one place two fixtures here
share a literal on purpose: what varies between them is the layout around the
body, so a body that varied too would be noise.

Two further layouts cannot be files at all — a CRLF fixture depends on what git
does to it on checkout — so `TestPrivateKeyBlockAcrossThePEMLayouts` in
`internal/scan` carries those as literals.

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
runbook quotes four private-key headers inline and displays a fifth in an
indented block, which turns a deletion into 5 findings and a red gate. That
fifth carries a second job now that the clause admits leading whitespace: it is
a displayed header and an indented body line with prose between them, so it is
what separates stepping over whitespace from stepping over a window of anything
printable. The sixth armour line is a `CERTIFICATE`, which is public and which the rule's
alternation does not reach. A rule with no clean
file touching it has a guard that cannot fire.

It holds the *shape* of that clause down as well as its presence. The clause
steps over `Proc-Type:` and `DEK-Info:` so an RFC 1421 encrypted key is
reported, and the obvious way to write that step is a bounded window of any
printable bytes. The runbook's "What the parts look like" section is a header,
then prose, then a body line inside 200 bytes: at a 200-byte window it is a
finding, and with the two field names it is not. That section is the whole
reason the narrower form shipped.

`iam-policy-notes.md` and `jwt-debugging.md` are two more of the same, for the
two rules whose vendor publishes an example realistic enough to clear an
entropy floor. The first quotes AWS's documented access key ID and its STS
counterpart; the second quotes the sample token on jwt.io's front page. Each
holds down one validator: removing `aws-placeholder` takes the clean half to 2
findings and removing `jwt-sample-key` takes it to 1, both measured by driving
the deletion rather than by reading the rule.

## `vectors/` holds values, not files

`vectors/credentials.json` is keyed by id, and each entry is a value and a note.
The unit tests elsewhere in the repository name a value rather than writing
one, so no `_test.go` file has to carry a string shaped like a credential.

They are kept in this tree because of
[`.github/secret_scanning.yml`](../../.github/secret_scanning.yml), which is
the one place GitHub is told not to read. A value that could pass for an issued
credential is a value some detector eventually flags, and the answer to that is
a place to keep them rather than an exemption for whichever source file gets
found. GitHub's detector for the `ASIA` prefix opened an alert on
`internal/validate/aws_test.go` on 2026-08-27, and two days earlier it had
opened one on `ASIAIOSFODNN7EXAMPLE`, which is the value AWS publishes with the
word EXAMPLE inside it. No property of the string escapes that.

**What stays inline is what no detector can mistake for a credential.** A body
one character too long for the rule's `\b`, a lowercase suffix, a padded
placeholder: those are a validator's edge cases, the exact bytes are what each
case is about, and they belong beside the assertion. The test is whether the
string could pass for an issued credential -- a question about the string, not
about which detectors exist this year.

Nothing reads the `note`. The loader in
[`../../internal/testvec/`](../../internal/testvec/) takes the value alone, and
the note is there for the reason the marks in `planted/` are: someone who finds
a credential-shaped string in a public repository has only what is written
beside it to tell them it is inert.

## Adding to it

**A clean file** goes in as it was written, not tidied. Anything it forces you
to except is a rule to drop rather than a file to edit — that is the whole
argument for pinning the count at zero.

**A planted file** is named for its rule, carries one match, and is listed in
the `planted` map in `internal/scan/corpus_test.go`. The map is what carries
the count, which the filename cannot; a file in one and not the other fails the
gate from either side.

**A vector** is a `value` and a `note` under a new id in
`vectors/credentials.json`, added when a test needs a string that could pass
for an issued credential. `minVectors` in `internal/testvec` is a floor at the
file's current size, so removing an entry means lowering it in the same edit.

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

**A planted value cannot rely on a marker the ruleset rejects, and this is the
one rule here that is `planted/`-only.** Everything else in this file is about
what a rule may match; this is about what a fixture is allowed to be, and it
binds nowhere else in the repository — a unit test elsewhere needs its value to
match a regex, not to survive every validator.

`aws-access-key-id.env` is the worked example. It carries
`AKIAIOSFODNN7EXAMPLE`, which is fabricated in the most authoritative way
available: AWS publishes it, so a reader who greps it lands in AWS's own
documentation. That makes it an excellent value for a unit test and a
disqualified one here, because `aws-placeholder` drops exactly that suffix.
A planted fixture has to be **found**, so it cannot be marked by the string the
scanner is being taught to reject.

Which leaves a fixture needing some other mark, and this is where a reader
matters as well as the rule. This directory is public and it ships inside a
security tool, so someone finding a credential-shaped string here has only the
sentence above to tell them it is inert — and in `aws-access-key-id-utf16le.env`
they cannot read it at all without decoding the file first.
`AKIA0SPILLGUARD98107` carries this project's name, which anyone can grep for
and no issued credential would contain. That costs nothing and needs no
argument about AWS.

The digits in it are a second and weaker signal. A widely used technique
recovers an AWS account ID by base32-decoding a key ID's body, which would rule
`0`, `1`, `8` and `9` out of a real one — and nobody in this repository has
verified that against an authoritative source. AWS's [IAM identifiers reference][iam-ids]
documents the unique-ID prefixes and says nothing about the alphabet. So the
digits in `AKIA0SPILLGUARD98107` are a hedge rather than a proof, and the
greppable name is what carries the claim. `internal/rules/capture_test.go`
reached the same shape first, with `AKIA0123456789ABCDEF`.

[iam-ids]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
