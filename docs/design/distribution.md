# Getting the binary onto the machine

Go was chosen partly because it cross-compiles to every target from any machine
([`language-choice.md`](language-choice.md)). That solves building the five
binaries and says nothing about how one arrives on a user's laptop, which is the
harder half.

The constraint that shapes everything: **Claude Code plugins have no
install-time hook.** Every `plugin.json` across the five plugins installed on
this machine carries the same eight keys — `name`, `version`, `description`,
`author`, `homepage`, `repository`, `license`, `keywords` — and nothing that
runs a command. A plugin install is a git clone and nothing else.

## The launcher is not optional

`hooks.json` cannot invoke `spill-guard` directly.

If the binary is absent, the shell exits 127, and Claude Code lets the tool call
through — measured, along with every other code, in
[`README.md`](README.md#the-exit-code-contract-measured). The empty stdout is not
the operative part: a hook that exits 2 with nothing on either stream still
blocks. It is the non-2 exit code that decides. The hook is then installed,
silent, and enforcing nothing — the predecessor's Node-18 failure with a
different exit code on it. exit-status-guard shipped the same class of bug in
1.0.0: the launcher went out at mode 644, the shell refused it, exit 126, and the
guard never fired once. Both 126 and 127 were driven end to end here, and neither
puts anything in the transcript.

So `hooks.json` invokes a launcher, and the launcher's job when it cannot find a
binary is to **deny** — naming the install command for the platform it is on.
Missing binary is a blocking condition, not a quiet one. Spell it as a `deny`
decision object on **stdout**. That blocks whatever the launcher then exits with
— measured on 0, 1, 9 and 127 — so a launcher that writes its deny and then dies
still blocks, which no other spelling gives you. The alternative, exit 2 with the
reason on **stderr**, works but reaches the model wrapped in
`PreToolUse:<tool> hook error: [<path>]:`. Writing the reason to stdout and
exiting 2 is the one combination that blocks and explains nothing: stdout is
discarded on exit 2.

Resolution order:

1. `SPILL_GUARD_BIN`, an explicit path.
2. `spill-guard` on `PATH` — covers Homebrew, Scoop, and `go install`.
3. The default install-script location: `~/.local/bin/spill-guard`, or
   `%LOCALAPPDATA%\spill-guard\bin\spill-guard.exe` — covers a fresh install
   whose `PATH` the running session has not picked up yet.
4. Nothing found: deny, with the install command.

The launcher ships executable, set in the git index with
`git update-index --chmod=+x` rather than `chmod` alone, and CI drives the hook
through it on all three operating systems. Both halves of that are 1.0.0 bugs
from a sibling repo, not hypotheticals.

## The base layer: signed release assets

Every channel below is a front-end onto the same artifacts, so this is what has
to be right.

Each release publishes five archives, a `checksums.txt` over them, a Sigstore
signature of that file, and a GitHub build provenance attestation.

| Artifact | Verifies |
|---|---|
| `checksums.txt` | The archive is the one the release published |
| cosign keyless signature | `checksums.txt` came from this repo's release workflow |
| `actions/attest-build-provenance` | Which workflow, commit, and runner built the archive — `gh attestation verify` checks it |

Keyless signing is the choice worth defending: it uses the workflow's OIDC
identity, so there is no signing key to store, rotate, or lose. A GPG key held
by one person is a key that expires unnoticed on a project maintained in spare
hours.

The predecessor had verified SLSA provenance and SHA-pinned CI actions. Both are
worth keeping.

**GoReleaser is a release-time tool, not a runtime dependency.** The
zero-dependency property is about the shipped binary's import graph and an empty
`require` block in `go.mod`; a build tool that never enters the binary does not
touch it. The alternative is a hand-rolled `go build` matrix with
`gh release upload`, which has fewer moving parts and then leaves the tap and
bucket updates to be hand-rolled too. GoReleaser, pinned by commit SHA.

## Channels

### macOS and Linux: a Homebrew tap

```
brew install karlkfi/tap/spill-guard
```

A personal tap is a repo of formulae, self-hosted, with no third-party review.
`homebrew-core` is the one that costs review and a notability bar; a tap costs a
repo. The formula pins the archive's sha256, so Homebrew verifies integrity at
install without any extra step from the user, and Homebrew on Linux means one
channel covers both platforms.

Maintenance is a release-workflow step that opens a PR on the tap with the new
version and checksums.

### Windows: a Scoop bucket

```
scoop bucket add karlkfi https://github.com/karlkfi/scoop-bucket
scoop install spill-guard
```

Same shape as the tap and the same reason: a bucket is self-hosted with no
review gate, and the manifest pins the sha256.

**winget and Chocolatey are deliberately not in v1.** winget needs a pull
request into `microsoft/winget-pkgs` and Chocolatey needs moderation review.
That is the same third-party approval cost that rules out Debian and Fedora
packaging, and it buys reach this project does not need yet. Either can be added
later without changing anything above.

### Everywhere else: an install script

`install.sh` and `install.ps1`, both living in this repo so they are reviewable
at a versioned URL. Each detects OS and architecture, downloads the matching
archive, **verifies the sha256 against `checksums.txt`**, verifies the Sigstore
signature when `cosign` is present, and installs to `~/.local/bin` or
`%LOCALAPPDATA%`.

The documented form is two steps:

```bash
curl -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/install.sh
sh install.sh
```

The one-liner that pipes into a shell will work, and it is not what the README
leads with. For a tool whose entire pitch is that nothing leaves your machine,
opening with "pipe this remote script into your shell" undercuts the claim
before a reader gets to the second paragraph. Download, read, run.

CI runs both scripts on all three operating systems every release. An install
script that broke is indistinguishable from a tool nobody installed.

### For anyone with a Go toolchain

```
go install github.com/karlkfi/claude-spill-guard/cmd/spill-guard@latest
```

Zero maintenance, and the module checksum database verifies the source. It is an
alternative rather than a channel, because most users of a Claude Code plugin do
not have Go.

## Rejected: committing the binaries

Measured on this machine with Go 1.26.5, `-trimpath -ldflags="-s -w"`, over a
probe importing the packages the scanner will actually use (`regexp`,
`encoding/json`, `crypto/sha256`, `bufio`, `strings`, `unicode/utf8`, `fmt`,
`os`):

```
darwin/amd64      2.45 MB
darwin/arm64      2.32 MB
linux/amd64       2.29 MB
linux/arm64       2.19 MB
windows/amd64     2.38 MB
                 --------
total            11.63 MB
```

The real scanner will be larger. A marketplace install is a git clone, so every
release would add that to a history every user downloads, permanently. Twenty
releases is a quarter of a gigabyte to install a 2 MB tool.

It buys a one-step install. The tap and the bucket buy the same thing for the
cost of two small repos.

## Rejected: fetching at first run

The launcher could download the binary the first time it runs. It would make the
plugin install self-contained, and it puts a network call inside the tool whose
stated property is that it has none. Even scoped to the launcher rather than the
scanner, it turns "no network capability, verifiable in an afternoon" into a
claim with an asterisk. Not worth it.

## Version skew: settled by removing it, not by detecting it

A tap that upgrades `spill-guard` while the plugin stays pinned leaves two
pairs able to disagree — launcher against binary, and binary against ruleset.
The question was posed as a choice between checking on every invocation and
checking only in `selftest`. Neither is the answer, because only one of the two
pairs fails silently and it can be made unable to disagree at all.

**Only the ruleset half has a silent direction.** Driven against
`internal/rules` on 2026-08-24, not read off the schema:

| Skew | What happens |
|---|---|
| Older binary, newer ruleset | `0 rule(s), err=the shipped ruleset: json: unknown field "window"` — refused at startup, naming the field |
| Newer binary, older ruleset | `1 rule(s), err=<nil>` — loads clean, and quietly lacks whatever the newer release added |

The first is the fail-closed rule doing its job: the binary stops with a reason.
The second is a scanner that runs, reports nothing, and is indistinguishable
from one that checked everything, which is the failure this whole project is
built around.

**So the shipped ruleset is compiled into the binary.** `rules/spill-guard.json`
stays a JSON file in the repo, authored and reviewed as JSON; `go:embed` puts it
in the artifact, and the pair can no longer disagree because there is no longer
a pair. It costs nothing at run time and nothing in the supply chain: `embed` is
stdlib, and both gates were run against a probe importing it — `no-deps` and
`no-network` each reported 106 packages, all clean.

It costs no capability either. A project entry whose `id` is already shipped
overrides the fields it names, and that includes the pattern: driven on the same
day, an override of `{"id": "aws", "regex": "(ASIA[A-Z0-9]{16})"}` against a
shipped `aws` rule returned one rule whose compiled pattern was the override's.
Turning a shipped rule off, retuning one, and adding new ones all survive.

**The launcher-against-binary half stays, and it fails loud.** The launcher
resolves a path and passes its arguments through; it chooses no subcommand, so
the interface is whatever `hooks.json` names. A binary that does not recognise
it exits 2 with a reason on stderr, and
[`README.md`](README.md#the-exit-code-contract-measured) measures exit 2 as
blocking. Fail-closed and visible, which is where an incompatibility should
land.

**Nothing probes a version on the hook path.** The launcher would have to read a
version out of a manifest in cmd.exe batch as well as POSIX sh — hand-rolled
parsing in the language least able to do it — or spawn the binary a second time
to ask. That second spawn was measured on 2026-08-24, darwin/arm64, over 200
runs of a `-trimpath -ldflags="-s -w"` build of `cmd/spill-guard`: p50 2.20 ms,
p95 2.53 ms, p99 2.62 ms. Small in isolation and roughly a doubling of the
binary-side fixed cost, on a path nobody chose to be on, to detect a
disagreement that no longer exists.

`selftest` asserts the launcher and the binary agree anyway, because there it is
free and a human is asking the question directly.

## Open

- **Whether `install.sh` should refuse to proceed without `cosign`.** Failing
  closed is this project's rule everywhere else, and most machines do not have
  cosign installed.
