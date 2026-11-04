# Installing and checking spill-guard

The [README](../README.md#install) has the install commands and the check that
the hook is live. This page has what the scripts verify, the route without them,
and how to read `spill-guard selftest`.

## What the install scripts verify

Each script works out your OS and architecture, checks the archive's sha256
against `checksums.txt`, and then checks the signature with whichever of
`cosign` or `gh` you have: `cosign` against the keyless Sigstore signature in
`checksums.txt.sigstore.json`, `gh` against the build provenance. With neither
installed it **refuses**.

The sha256 is not the fallback it looks like. `checksums.txt` comes from the same
place the archive did, so it answers corruption and not substitution, and
authenticity needs a verifier. On a machine with neither tool,
[`go install`](#without-the-install-script) needs no verifier. A Homebrew tap and
a Scoop bucket are designed in
[`design/distribution.md`](design/distribution.md), and neither is built.

`sh install.sh --verifier` answers which tool you have without downloading
anything. A successful run names the one it used, and a run that names neither
took a path nobody intended.

Either script installs a single binary, to `~/.local/bin`, or to
`%LOCALAPPDATA%\spill-guard\bin` on Windows, and writes nothing else. Pass `--dir`
(`-Dir` to `install.ps1`) to put it somewhere else.

The install scripts are themselves listed in `checksums.txt`, so the script you
fetched in order to read it can also be checked:

```bash
curl -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

`--ignore-missing` is load-bearing: without it `sha256sum -c` fails on every asset
you did not download, which reads as a verification failure.

CI installs through both scripts on Linux, macOS and Windows on every pull
request, against the archives that same pull request built. What it cannot reach
is the signature check itself, because artifacts served from a loopback port carry
no release provenance. [`development/release-process.md`](development/release-process.md)
has the manual check that closes that, after a draft is published.

## Without the install script

`go install` needs a Go toolchain and no verifier. The module checksum database
checks what it downloads, which is a weaker guarantee than the signature the
script checks:

```bash
go install github.com/karlkfi/claude-spill-guard/cmd/spill-guard@latest
```

It writes to `$(go env GOPATH)/bin`. The launcher looks on `PATH` first, then at
`~/.local/bin/spill-guard`. If that directory is on neither, set `SPILL_GUARD_BIN`
to the binary's path.

## Reading `spill-guard selftest`

`selftest` builds hook payloads and runs the scanner over them in-process,
reporting what happened to each:

```text
spill-guard dev selftest
binary:  /Users/you/go/bin/spill-guard
ruleset: compiled in

  ok    a prompt carrying the canary                 blocked (aws-access-key-id)
  ok    a prompt with nothing in it                  allowed
  ok    a Read of a file holding the canary          blocked (aws-access-key-id)
  ...
  ok    a Read of a file this build cannot decode    deferred (UTF-32: declared by a byte-order mark, and not decoded)
```

It reports `dev` unless it came from a release: `go install` does not stamp a
version, and only the release build passes one in.

**The allowing rows are the half that catches the likely failure.** A scanner that
blocks everything and one that works produce the same report if the report is only
made of blocks, and a rule that matches too much is the ordinary shape of that. An
allowing row goes `FAIL` if its call is blocked at all, by any rule.

**`deferred` is its own row type.** A buffer nothing could read is a coverage
failure, so the call proceeds and the gap is recorded. A deferred call writes no
verdict, so from outside it looks exactly like a clean allow. A report that only
knew *allowed* and *blocked* would print `ok` for a binary whose scanner had quietly
stopped reading anything at all.

**What it does not settle.** `selftest` calls the scanner directly, so it says
nothing about whether Claude Code is invoking the hook. Nothing run outside a
session can. The [live check](../README.md#check-that-the-hook-is-live) answers
that one.

**Which binary a session will find.** Run `selftest` through the launcher and the
`binary:` line reports the one the hook's resolution order picked. A plugin install
puts the launcher at
`~/.claude/plugins/cache/<marketplace>/spill-guard/<version>/hooks/run-spill-guard.cmd`.
If it cannot find a binary it prints its refusal as a JSON block object at exit 0.
That is the hook contract rather than a shell one, so read the message and do not
chain on the status.
