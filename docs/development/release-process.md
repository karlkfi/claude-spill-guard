# Cutting a release

A tag is the only thing that publishes. Pushing `vX.Y.Z` runs
[`.github/workflows/release.yml`](../../.github/workflows/release.yml), which
builds the five archives, writes `checksums.txt`, signs it with cosign, mints a
build provenance attestation, and uploads all of it to a **draft** release.
Nothing reaches a user until a person publishes that draft.

Everything below is the part a person does.

## No file carries the version

The binary reports whatever the tag said. `-ldflags -X main.version=<tag>` sets
it at build time, and `cmd/spill-guard/main.go` carries `dev` as the default, so
a build from a working tree says `dev` and a release says `v1.2.3`. There is no
version to bump in a manifest and no bump commit, which is why this document
does not describe a direct-to-`main` exception for one — sibling repos need it
and this one has nothing for it to apply to.

That changes when the plugin manifests land (`Q10`): `plugin.json` carries its
own version, a marketplace entry compares that string and nothing else, and a
release whose manifest still says the old number cannot be delivered by `claude
plugin update` at all. Add the bump step here in the same PR that adds the
manifest.

## Before the tag

1. **`main` is green on the exact commit you are about to tag.** Not green this
   morning. Run `make check` over the same tree as well — every gate runs even
   when an earlier one fails, so one pass reports the whole thing.
2. **Read the public surface this tag publishes for the first time.** A
   subcommand name, a flag, a rule ID, an exit code, a finding's JSON shape:
   each costs a rename now and a compatibility shim afterwards. Nothing lints
   this. Deciding to ship a name as it stands is a fine answer; freezing one by
   not looking is not.
3. **Write the notes.** `docs/releases/vX.Y.Z.md`, holding the release body
   verbatim. [`docs/releases/README.md`](../releases/README.md) has the format
   and where the contents come from. The workflow refuses to run without this
   file, so it has to be merged before the tag is pushed.
4. **Sign off on the worktree itself.** `git status` clean, `git log` reading
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

The `release` job fails closed at four points, and each one leaves the tag
spent rather than the release wrong:

| It stops when | Because |
|---|---|
| `docs/releases/<tag>.md` is not in the tree | The body is authored in the repository. A generated changelog would then have to be corrected on the Release, off the record that invariant exists to keep. |
| The archives are not one per shipped target, named as the install channels expect | `scripts/check-release-artifacts.py`. Every channel builds an archive name from an OS and an architecture. |
| An archive does not match its `checksums.txt` line | Signing a stale checksums file signs a wrong answer, and the signature over it verifies perfectly. |
| A published asset does not verify as an outside consumer would check it | It re-downloads the release, re-runs `sha256sum -c`, verifies the cosign signature against this workflow **at this tag**, and verifies provenance for all five archives. |

The last row is the one worth reading twice. `--certificate-identity` is pinned
to `.github/workflows/release.yml@refs/tags/<tag>`, so a signature minted from a
branch, from another workflow, or from a fork is a valid Sigstore signature that
this check rejects.

**Nothing here checks that the binaries work.** They are cross-compiled and not
run; `make check` covers the tests, and the install scripts (`Q12`) are what
will exercise an installed artifact on all three operating systems.

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

## Running the pipeline locally

`make doctor` reports `cosign` and `goreleaser` in its `release` tier: missing is
not a failure, because a contributor fixing a bug has no reason to install a
signing tool. To build what a release builds, without signing or publishing:

```bash
goreleaser release --snapshot --clean --skip=sign
python3 scripts/check-release-artifacts.py
```

Match the version the workflow pins — `GORELEASER_VERSION` in
[`release.yml`](../../.github/workflows/release.yml) — or `goreleaser check` is
validating the config against a schema that is not the one a release will read.

The same two commands run on every pull request, so a config that stopped
producing five archives is caught there rather than on a tag.
