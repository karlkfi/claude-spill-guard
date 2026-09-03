# Cutting a release

A tag is the only thing that publishes. Pushing `vX.Y.Z` runs
[`.github/workflows/release.yml`](../../.github/workflows/release.yml), which
builds the five archives, writes `checksums.txt`, signs it with cosign, mints a
build provenance attestation, and uploads all of it to a **draft** release —
including the attestation itself, as `spill-guard_<version>.intoto.jsonl`, so
the provenance is an asset rather than only an API record. Nothing reaches a
user until a person publishes that draft.

Everything below is the part a person does.

## The tag carries the version, except in the plugin manifests

The binary reports whatever the tag said, with the leading `v` stripped.
`cmd/spill-guard/main.go` carries `dev` as the default and `-ldflags -X
main.version={{ .Version }}` overrides it at build time, so a working tree says
`dev` and the tag `v1.2.3` produces a binary reporting `1.2.3`. GoReleaser's
`.Version` is the tag without the `v`; `.Tag` is the raw tag. The archive name
carries the same stripped form, so the binary and the file it ships in agree —
measured on a real annotated tag, not read off the template docs.

**The plugin manifests are the exception, and they are the whole of it.**
`.claude-plugin/plugin.json` carries its own `version`, and
`.claude-plugin/marketplace.json` repeats it in the entry that points at this
repo. A marketplace entry compares that string and nothing else, so a release
whose manifest still says the old number cannot be delivered by `claude plugin
update` at all — the tag would publish archives nobody's plugin install ever
reaches.

So the bump is a step a person takes, in the pull request that precedes the
tag. Edit both files to the tag without its `v`, then read them back rather
than trusting the edit:

```bash
python3 -c 'import json;print("plugin.json     ", json.load(open(".claude-plugin/plugin.json"))["version"]);print("marketplace.json", [p["version"] for p in json.load(open(".claude-plugin/marketplace.json"))["plugins"]])'
```

Both lines must read the tag you are about to push. This is a commit on a
branch and a pull request like any other — nothing about a two-line version
bump needs a direct-to-`main` exception, which is why this document still
describes none.

## Before the tag

1. **The plugin manifests say the version you are about to tag**, merged. The
   section above has the read-back, and `scripts/check-plugin-version.py`
   is what enforces it — the `plugin-version` gate runs the half that needs no
   tag on every pull request, and the release job runs
   `--version "${GITHUB_REF_NAME#v}"` before it builds anything, so a stale
   number stops the run rather than costing the whole plugin channel.
2. **`main` is green on the exact commit you are about to tag.** Not green this
   morning. Run `make check` over the same tree as well — every gate runs even
   when an earlier one fails, so one pass reports the whole thing.
3. **Read the public surface this tag publishes for the first time.** A
   subcommand name, a flag, a rule ID, an exit code, a finding's JSON shape:
   each costs a rename now and a compatibility shim afterwards. Nothing lints
   this. Deciding to ship a name as it stands is a fine answer; freezing one by
   not looking is not.
4. **Write the notes.** `docs/releases/vX.Y.Z.md`, holding the release body
   verbatim. [`docs/releases/README.md`](../releases/README.md) has the format
   and where the contents come from. The workflow refuses to run without this
   file, so it has to be merged before the tag is pushed.
5. **Sign off on the worktree itself.** `git status` clean, `git log` reading
   the way you want it read, and the diff since the previous tag one you have
   actually looked at. The tag is a permanent version number: a release
   published in error is superseded by a higher patch, never retagged.

## The tag

```bash
git switch main && git pull --ff-only
git tag -a vX.Y.Z -m 'Release vX.Y.Z'
git push origin vX.Y.Z
```

Then watch the run:

```bash
gh run list --workflow=release.yml --limit 1
```

## What the workflow asserts, and what it does not

The `release` job fails closed at five points, and each one leaves the tag
spent rather than the release wrong:

| It stops when | Because |
|---|---|
| `docs/releases/<tag>.md` is not in the tree | The body is authored in the repository. A generated changelog would then have to be corrected on the Release, off the record that invariant exists to keep. |
| The published body is not that file | The row above asserts the file exists, which is not the same claim and was measured coming apart. The first `v0.1.0` tag published ten correct, signed, verifiable assets and a body of two newlines: `changelog.disable: true` makes GoReleaser ignore `--release-notes`, and every other assertion here is about assets, so all of them passed. The tag was deleted unpublished and re-cut. |
| The archives are not one per shipped target, named as the install channels expect | `scripts/check-release-artifacts.py`. Every channel builds an archive name from an OS and an architecture. |
| An archive does not match its `checksums.txt` line | Signing a stale checksums file signs a wrong answer, and the signature over it verifies perfectly. |
| A published asset does not verify as an outside consumer would check it | It re-downloads the release, re-runs `sha256sum -c`, verifies the cosign signature against this workflow **at this tag**, and verifies provenance for all five archives — twice each, once through the attestations API and once against the attached bundle, which is the only copy a consumer without that API has. |

The last row is the one worth reading twice. `--certificate-identity` is pinned
to `.github/workflows/release.yml@refs/tags/<tag>`, so a signature minted from a
branch, from another workflow, or from a fork is a valid Sigstore signature that
this check rejects.

**The tag does not check that the binaries work, and a pull request does.** The
`release` job cross-compiles and never runs what it built. `install-dry-run`
does: on every pull request it installs the snapshot archive on Linux, macOS
and Windows through [`install/install.sh`](../../install/install.sh) and
[`install/install.ps1`](../../install/install.ps1), runs `spill-guard version`
from where it landed, and asserts that the version the binary reports is the
one its archive name carries — two values set by different mechanisms,
`-ldflags -X` and `name_template`.

One step of that install is covered nowhere yet, and deliberately rather than
by oversight. `install-dry-run` fetches from a loopback server through
`--rehearse`, which skips signature verification: artifacts served from a
loopback port carry no release provenance to check. `cosign verify-blob` and
`gh attestation verify` need a signed release, and the first one is a permanent
version number. What CI does drive is the step before them — which verifier the
script picks, and that it refuses when there is none. The manual step under
**Publishing the draft** is what closes the rest.

## Publishing the draft

The workflow prints these two lines at the end of a successful run:

```bash
gh release view vX.Y.Z
gh release edit vX.Y.Z --draft=false
```

The Releases page does the same thing; `gh` is a convenience here and not a
tool the release needs. Either way, read the rendered body before publishing. The notes file targets GitHub's
comment-flavour renderer, where a single newline becomes a `<br>` — a hard-wrapped
paragraph looks fine in the diff and wrong on the page.

**Then install from the published release, once, on one machine.** This is the
only occasion on which the signature verification inside the install scripts
runs at all, for the reason above, so a release nobody installs from ships that
step untested:

```bash
curl -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/install.sh
sh install.sh
```

`--dir` puts the binary somewhere other than `~/.local/bin`, which is how to
run this check without disturbing an install you already have.

The script is itself in `checksums.txt`, so the copy you just fetched can be
checked against the same file everything else is checked against:

```bash
curl -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

`--ignore-missing` is load-bearing: without it `sha256sum -c` fails on the five
archives you did not download, which reads as a verification failure.

The install has to name a verifier and say which — `cosign verified
checksums.txt against karlkfi/claude-spill-guard at vX.Y.Z`, or `gh verified
the build provenance of ...`. A run that installed and said neither took a path nobody
intended, and the sha256 line above it is not a substitute: `checksums.txt`
comes from the same place the archive did. `sh install.sh --verifier` answers
which tool the machine has without downloading anything.

**Then retire the release-scope record, if the tag had one.**
`docs/plan/<tag>.md` says what the release was for, and it is written to be
read before the tag rather than after it — a plan doc naming a version that
exists is the staleness the record is meant to avoid. Delete it, and drop the
matching label from every row still carrying it, in one docs-only commit:

```bash
git rm docs/plan/vX.Y.Z.md
```

Nothing checks this. It is a step somebody performs by reading it back, which
is the construction this repository has already paid for once — see *What the
workflow asserts, and what it does not*.

## Rehearsing without spending a version number

A prerelease tag runs the whole pipeline. `release.prerelease: auto` in
[`.goreleaser.yaml`](../../.goreleaser.yaml) marks anything carrying a hyphen,
so `v1.0.0-rc.1` publishes as a prerelease draft and needs its own
`docs/releases/v1.0.0-rc.1.md`.

Cut one when the publish path has changed, and always before a first release —
signing, the attestation, and the asset upload are the three steps no pull
request can reach, and a rehearsal is the difference between finding that out on
`v1.0.0-rc.1` and finding it out on `v1.0.0`.

Deleting a rehearsal tag and its draft is fine. Deleting a published one is not.

**A rehearsal proves what it checks, and nothing else. Check the draft the way
you would check the real one** — every step under **Publishing the draft**
below, the rendered body included. That instruction is written down there
because that is where a person does it, and reading this section alone is how a
rehearsal turns into an assets-only check.

Measured on v0.1.0: three rehearsals went green and each verified archives,
`checksums.txt`, the cosign bundle, the attestation and the binary. None of them
opened the release body, because nothing here said to and the release job
asserted only about assets. `changelog.disable: true` had been discarding
`--release-notes` the whole time, so all three published a body of two
newlines, and so did the real tag. The gate that now compares the published
body to the notes file closes that instance; this paragraph is here for the
next thing the pipeline does not assert.

## Running the pipeline locally

`make doctor` reports `cosign` and `goreleaser` in its `release` tier: missing is
not a failure, because a contributor fixing a bug has no reason to install a
signing tool. To build what a release builds, without signing or publishing:

```bash
goreleaser release --snapshot --clean --skip=sign
python3 scripts/check-release-artifacts.py
```

Match the version the workflow pins — `VERSION` at the top of
[`install-goreleaser.py`](../../scripts/install-goreleaser.py) — or `goreleaser
check` is validating the config against a schema that is not the one a release
will read. On Linux and on Apple silicon that script installs it, and refuses
any archive that does not hash to the digest pinned beside the version:

```bash
python3 scripts/install-goreleaser.py
```

The same two commands run on every pull request, so a config that stopped
producing five archives is caught there rather than on a tag.

To drive the install scripts against what that produced:

```bash
python3 scripts/check-install-scripts.py
```

It serves `dist/` on a loopback port, installs from it, runs the binary it
installed, and requires a refusal for a corrupted archive, a `checksums.txt`
that does not list the archive, a machine with neither verifier, and a
`--rehearse` aimed at github.com. It is not a gate for the same reason nothing
else on this page is: it needs the `dist/` only GoReleaser produces.
