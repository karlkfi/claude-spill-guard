# spill-guard

**A Claude Code hook that refuses a call when it would send a credential to the
API.**

[![tests](https://img.shields.io/github/actions/workflow/status/karlkfi/claude-spill-guard/tests.yml?branch=main&label=tests)](https://github.com/karlkfi/claude-spill-guard/actions/workflows/tests.yml) [![License: MIT](https://img.shields.io/github/license/karlkfi/claude-spill-guard.svg)](LICENSE) [![Claude Code plugin](https://img.shields.io/badge/Claude_Code-plugin-7e57c2)](#install)

> `cat .env` is one keystroke, and the file is in the transcript before anyone
> reads a line of it.

Claude Code sends what it reads to the API, and there is no undo. Git secret
scanners do not help, because a file read into a session is never committed.
spill-guard runs before the call and stops it there. It is a net for the
accident rather than a wall, and [what it does not catch](#what-it-does-not-catch)
is a short list worth reading before you rely on it.

## What it blocks

| The call | What happens |
|---|---|
| `cat deploy.log`, a `Read` of it, or `@deploy.log` in a prompt, with a key in the file | Blocked, naming the rule and byte offset and never the value |
| A prompt with a key pasted into it | Blocked the same way |
| `cat .env`, or a `Read` of `.env` | Blocked on the path alone, whatever the file holds |
| `cat ~/.aws/credentials`, or four other credential files | Blocked on the path alone |
| `env`, `printenv` | Blocked, offering `env \| cut -d= -f1` for the names |
| `grep -r password .` | Blocked, offering the same command with the output scanned |
| `cat go.mod` | Allowed, and nothing is said |

The other four are `~/.netrc`, `~/.git-credentials`, `~/.docker/config.json` and
`~/.kube/config`. The path refusals exist because most of what those files hold
matches no rule.
No rule in v0.6.1 recognises an AWS secret access key, a netrc password or a
base64 registry auth, so a clean scan of one of those files would report a safety
the scan is not providing.

This is what comes back, from v0.6.1. The line breaks are added and the path is
shortened. The rest is verbatim.

```text
> cat deploy.log

spill-guard: blocked. 1 rule match(es) in what this call would have sent:
"aws-access-key-id" at byte 15 of "/home/you/app/deploy.log". Nothing was sent.
The values are not repeated here, because this text reaches the API as well.
Remove or rotate what the rules name, then try again.

> cat .env

spill-guard: blocked. "/home/you/app/.env" is a dotenv file, and this refused
to read it on that alone. Nothing here opened the file, so nothing here has an
opinion about what is in it -- the class is refused because most of what these
files hold matches no rule in this set, and a clean scan of one would report a
safety it is not providing. Nothing was sent. If you want the shape of the file
rather than its values, a filter with a stage after it -- `cat FILE | cut -d=
-f1` -- is not refused and is still scanned. This reaches the readers it knows
and no others: an interpreter told to open the same path goes straight past it,
so read this as a net for the accident rather than as a claim that the path is
guarded.
```

On a tool call Claude gets the refusal in place of the result, so the way
forward lands where the command gets rewritten.

**[PENDING, rules stream: the final rule list and the PII claim.]** The draft
sentence, true of v0.6.1: it matches ten credential shapes (AWS key IDs, GitHub
tokens of both kinds, Slack tokens and webhooks, Stripe live keys, OpenAI and
Google API keys, PEM private keys and JWTs), and the four numeric PII rules ship
disabled. [`rules/README.md`](rules/README.md) has what keeps each one quiet.

## Install

Two halves. The binary does the reading, and the plugin tells Claude Code which
calls to hand it. A plugin with no binary blocks every call it sees and names
the install command in the refusal, so a half-finished install is loud.

**The binary**, on macOS and Linux:

```bash
curl -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/install.sh
sh install.sh
```

On Windows, as of v0.6.1, spill-guard needs Git for Windows. Without it Claude
Code runs hooks under PowerShell, the hook command does not parse, and nothing is
scanned or refused, so run the live check below.

```powershell
curl.exe -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/install.ps1
powershell -ExecutionPolicy Bypass -File install.ps1
```

Two steps rather than one. Piping the script into a shell works, and it is a
strange way to open for a tool whose whole pitch is that nothing leaves your
machine. Download it, read it, run it. It checks the download's signature with
`cosign` or `gh`, and it refuses if you have neither.
[`docs/installing.md`](docs/installing.md) has what it verifies, the `go install`
route for a machine with neither, and what `spill-guard selftest` reports.

**The plugin**, once the binary is there:

```bash
claude plugin marketplace add karlkfi/claude-spill-guard
claude plugin install spill-guard@spill-guard
```

Hooks are read when a session starts, so start a new one.

### Check that the hook is live

A scanner that enforces nothing and a session with no secrets in it produce the
same silence, so check. This needs no secret:

```bash
mkdir spill-guard-check && cd spill-guard-check && touch .env && claude
```

Ask Claude to run `cat .env` and then to read `.env` with its `Read` tool. Both
should come back blocked by spill-guard. If either one does not, the hook is not
live, and nothing leaked, because the file is empty.

The file has to exist, since a missing `.env` is allowed. This check also says
nothing about prompts: `@.env` is allowed, because the path refusal does not
reach that surface. `spill-guard selftest` drives a prompt through the scanner,
in-process rather than through Claude Code.

**A key you plant yourself will probably come back allowed**, with nothing said.
AWS's documented example key and anything else ending in `EXAMPLE` are refused
as placeholders, and `AKIA` plus sixteen `X`s falls below the entropy floor.
`AKIA` plus sixteen random characters is blocked. The values you reach for when
testing are the ones the precision work exists to ignore, so that silence is the
scanner working rather than failing open. `spill-guard selftest` is the check to
reach for.

## What it does not catch

The threat model is the accident. These go straight through, each driven through
the v0.6.1 binary unless it says otherwise:

- **An interpreter.** `python3 -c 'print(open(".env").read())'` and the `node`
  equivalent pass, because the hook knows which argument of `cat` is a file and
  has no way to know what a script opens.
- **What a command prints.** `gh auth token`, `kubectl get secret db -o yaml` and
  `aws configure get aws_secret_access_key` all pass. The hook decides before
  the call runs, so it never sees the output.
- **An MCP file reader.** By the manifest rather than a drive: `hooks/hooks.json`
  matches `Read`, `Bash` and `Grep`, so an `mcp__…` tool never reaches the hook.
- **A value no rule knows.** A password in `deploy.env` passes `cat`, because the
  path refusal covers `.env` and the credential files above rather than every
  name with `env` in it. A `@.env` in a prompt gets the content scan and not the
  path refusal, so a password in it passes too.
- **`!` bash mode and skill loads**, by the measurements in
  [`docs/design/`](docs/design/README.md) rather than by this drive. `!cat` is not
  a tool call, and a skill load names no file.
- **Someone who means it.** A `SPILL_GUARD_OVERRIDE=<reason>` prefix on a `Bash`
  command turns a block into a confirmation prompt.

## A finding blocks, a gap does not

A rule match blocks, and so does a refused shape. A call the scanner could not
read does not: an operand it cannot resolve (`cat "$X"`), a directory it will
not walk (`rg password .`), a buffer it cannot decode, or a scan past its
45-second budget. The hook writes no verdict, so your normal permission rules
run unchanged, and the gap is recorded. `spill-guard coverage` counts those
records, grouped by reason.

That was a block until 2026-09-05, and the measurement is what changed it. Over
one week and 100 sessions on one machine, 509 of 540 blocks were gaps rather
than findings, and after 505 of those 509 the session got a clean call through
within four attempts by reading the same tree another way. The refusal was not
withholding the bytes. It charged a turn.

A broken install still blocks, with the Windows exception under
[Install](#install). A missing binary is refused by the launcher, and a payload
the binary cannot decode exits 2.

## What it costs

About 10 ms per hook call. Medians ranged from 8.9 ms to 10.8 ms across two runs
of 40 calls each, for a `Bash` `ls`, a `Read` of a 1.2 KB file and a short prompt.
That is v0.6.1 through the plugin's launcher, on one Apple M5 Max on 2026-11-03,
with small inputs. About 2 ms of it is the cost of spawning any process from the
measuring script. A larger file costs more: the binary alone, without the
launcher, took 4.2 to 4.6 ms on those inputs and 5.0 to 5.4 ms on a 68 KB file.
Your machine will differ.

## How it is built

- A static Go binary with no third-party runtime dependencies. `go.mod` requires
  nothing, and `make no-deps` fails if that changes.
- No `net`, `net/http` or `os/exec` anywhere in the build graph, enforced by
  `make no-network` rather than by review. See [`PRIVACY.md`](PRIVACY.md) for
  what it reads and the one file it writes.
- A refusal names a rule, a path and a byte offset, and no fragment of the value,
  because the refusal reaches the API too.
- One ruleset, compiled into the binary. There is no project override, because a
  file the model can write is a two-step bypass: disable the rule, then read the
  secret.

## Why there are so few rules

This replaces `coo-quack/sensitive-canary`, a Node plugin that audits clean and
is safe to install. Its ruleset, run over 257 real text files from an infrastructure repo,
produced **5,679 matches across 9 rules, all of them PII noise and not one
credential**. 71 of the 257 files flagged, which is 27.6%.

```
pii-phone-cn      2533     pii-postal-cn       8
pii-ipv4-public   1522     pii-phone-de        4
pii-phone-kr      1441     pii-steuer-id-de    3
pii-postal-code    169     pii-brn-kr          3
                           pii-phone-it        1
```

`0400-2341068` was flagged 268 times as a Chinese phone number. It is a slice of
the amdgpu DKMS version string `1:6.16.13.30300400-2341068`.

Numeric PII patterns cannot be made precise by regex alone, so precision here
comes from checksum validators, entropy floors and placeholder checks, with the
numeric family shipping off. `make precision` holds that: the shipped rules must
report zero findings on [`testdata/corpus/clean/`](testdata/corpus/) and exactly
one on each planted fixture. The clean corpus is adversarial, since on 2026-11-03
the old `pii-postal-code` pattern reported 31 matches on it and `pii-phone-cn`
reported 8.

[`docs/design/language-choice.md`](docs/design/language-choice.md) has the full
analysis, the benchmarks, and a list of confident claims that measurement killed.

## Status

Generated from the tree by `make status`, and CI fails when it stops being true.
[Releases](https://github.com/karlkfi/claude-spill-guard/releases) has the
current version.

<!-- status:begin -- generated by `make status`; derived from the tree, not hand-kept -->
Every capability below is in place.

| Capability | Today |
|---|---|
| Scan a file or a buffer | yes |
| Run as a Claude Code hook | yes |
| Ship a ruleset | yes |

`spill-guard` builds and answers `coverage`, `filter`, `hook`, `selftest`,
`version`.
<!-- status:end -->

## Design docs

- [`docs/design/`](docs/design/): the threat model, hook surface, scan pipeline,
  rule schema, failure policy and CI.
- [`docs/design/distribution.md`](docs/design/distribution.md): how the binary
  gets onto a machine, and the launcher that denies when it is missing.
- [`docs/installing.md`](docs/installing.md): what the install scripts verify,
  and how to read `selftest`.

## Other guards

These watch different boundaries. The first five install from one marketplace,
[`karlkfi/claude-bouncer`](https://github.com/karlkfi/claude-bouncer), as
`<name>@claude-bouncer`.

- [**workspace-guard**](https://github.com/karlkfi/claude-bouncer/tree/main/plugins/workspace-guard):
  prompts before guarded file commands read or write outside the project root.
- [**branch-guard**](https://github.com/karlkfi/claude-bouncer/tree/main/plugins/branch-guard):
  auto-approves safe git, and pauses commits and pushes to a protected branch.
- [**prod-guard**](https://github.com/karlkfi/claude-bouncer/tree/main/plugins/prod-guard):
  blocks mutating commands aimed at production.
- [**exit-status-guard**](https://github.com/karlkfi/claude-bouncer/tree/main/plugins/exit-status-guard):
  denies commands whose exit status is the answer and gets discarded.
- [**foreground-guard**](https://github.com/karlkfi/claude-bouncer/tree/main/plugins/foreground-guard):
  keeps blocking commands from stalling a session.
- [**pr-sentinel**](https://github.com/karlkfi/claude-pr-sentinel): watches a PR
  to green without merging it.

## Contributing

Bugs, ideas and questions go in
[GitHub Issues](https://github.com/karlkfi/claude-spill-guard/issues). A rule that
flags ordinary work is a bug worth reporting, so include the exact text and the
rule ID. For development conventions, see [`CLAUDE.md`](CLAUDE.md).

## License

MIT, see [LICENSE](LICENSE).
