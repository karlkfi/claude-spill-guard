#!/bin/sh
# Install spill-guard from a published release, on macOS and Linux.
#
# The documented form is two steps -- download, read, run:
#
#   curl -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/install.sh
#   sh install.sh
#
# The one-liner that pipes this into a shell works and is not what the README
# leads with. For a tool whose whole pitch is that nothing leaves your machine,
# opening with "pipe this remote script into your shell" undercuts the claim
# before a reader reaches the second paragraph.
#
# WHAT IT VERIFIES, AND WHY IN THAT ORDER
#
#   1. The archive's sha256 against checksums.txt. Always, with no way to turn
#      it off. It answers corruption and a truncated download, and it does not
#      answer substitution, because checksums.txt is fetched from the same
#      place the archive was.
#   2. The signature, with whichever verifier is installed -- `cosign` against
#      the keyless Sigstore signature over checksums.txt, else `gh attestation
#      verify` against the build provenance on the archive itself. This is the
#      step that answers authenticity, and either chain closes it: the sha256
#      above binds the archive to checksums.txt, so a checksums.txt that
#      verifies speaks for the archive.
#
# It refuses when neither is installed. `cosign` and `gh` are two verifiers of
# one property rather than a strict mode and a lax one, so the question was
# never fail-closed against reach. The argument is in
# docs/design/distribution.md under "Settled".
#
# One leg of that argument is not true yet, which is why the refusal below
# names neither channel. It says refusing costs reach almost nothing because
# the Homebrew formula and the Scoop manifest pin the sha256 themselves and ask
# the user for no tool at all -- and neither exists: .goreleaser.yaml carries no
# `brews:` and no `scoops:` block, and Q13 and Q14 are both still open. Until
# they land, a refused user is a user with nowhere else to go, so the message
# names what actually works today. Sending them to `brew install
# karlkfi/tap/spill-guard` would be telling somebody who is already stuck to run
# a command that fails.
#
# POSIX sh, because the documented invocation is `sh install.sh` and that is
# dash on Debian and Ubuntu: no `local`, no arrays, no `pipefail`, no `[[`.
#
# curl and nothing else does the fetching. wget cannot report the URL a
# redirect landed on without parsing headers, and resolving `latest` to a real
# tag is what lets the archive, checksums.txt, the signature and the cosign
# identity all name one release rather than straddle a publish across three
# independent redirects. The two-step form above already spends a curl, so
# requiring it costs nobody anything.

set -eu

REPO='karlkfi/claude-spill-guard'
WORKFLOW='.github/workflows/release.yml'
OIDC_ISSUER='https://token.actions.githubusercontent.com'

version=''
dest=''
rehearse=''
mode='install'

say() { printf 'install.sh: %s\n' "$1"; }
die() { printf 'install.sh: %s\n' "$1" >&2; exit 1; }

usage() {
	cat <<'USAGE'
usage: sh install.sh [options]

  --version TAG    install this release instead of the latest (e.g. v1.2.3)
  --dir DIR        install into DIR instead of ~/.local/bin
  --verifier       print which signature verifier would be used, and exit
                   non-zero when neither cosign nor gh is installed
  --rehearse URL   fetch the archive and checksums.txt from URL instead of the
                   release, and do NOT verify the signature. For exercising
                   this script against artifacts no release has published; it
                   refuses a github.com URL, so it is not an install path.
  -h, --help       this text
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version)
		[ $# -ge 2 ] || die '--version needs a tag, e.g. --version v1.2.3'
		version="$2"
		shift 2
		;;
	--dir)
		[ $# -ge 2 ] || die '--dir needs a directory'
		dest="$2"
		shift 2
		;;
	--verifier)
		mode='verifier'
		shift
		;;
	--rehearse)
		[ $# -ge 2 ] || die '--rehearse needs a URL'
		rehearse="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		printf 'install.sh: unknown argument: %s\n\n' "$1" >&2
		usage >&2
		exit 2
		;;
	esac
done

NO_VERIFIER='neither cosign nor gh is installed, so nothing here could establish that an archive came from this repository. The sha256 check answers corruption and not substitution, so it is not a fallback. Install either one and run this again -- `brew install cosign`, or gh from https://cli.github.com. With a Go toolchain and no wish to install either, `go install github.com/karlkfi/claude-spill-guard/cmd/spill-guard@latest` builds from source and the module checksum database does the verifying instead.'

# Which verifier this machine has, as a name on stdout, or a non-zero exit.
# Resolved without touching the network, which is what lets `--verifier` answer
# the question a refusal raises -- and what gives the refusal path a seam CI
# can drive. No pull request can reach the verification itself: a real
# signature needs a real release, and the first one is a permanent version
# number.
verifier() {
	if command -v cosign >/dev/null 2>&1; then
		echo cosign
		return 0
	fi
	if command -v gh >/dev/null 2>&1; then
		echo gh
		return 0
	fi
	return 1
}

if [ "$mode" = verifier ]; then
	if found="$(verifier)"; then
		say "signatures would be verified with $found"
		exit 0
	fi
	die "$NO_VERIFIER"
fi

command -v curl >/dev/null 2>&1 ||
	die 'curl is not installed, and it is what this script downloads with. Install curl and run this again.'

case "$(uname -s)" in
Darwin) goos=darwin ;;
Linux) goos=linux ;;
MINGW* | MSYS* | CYGWIN*)
	die 'this is the POSIX installer and you are on Windows. Download install.ps1 from the same release and run it with PowerShell.'
	;;
*) die "$(uname -s) is not a platform spill-guard ships a binary for: it ships darwin and linux on amd64 and arm64, and windows on amd64." ;;
esac

case "$(uname -m)" in
x86_64 | amd64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*) die "$(uname -m) is not an architecture spill-guard ships a binary for: it ships amd64 and arm64." ;;
esac

# A rehearsal is not an install path, and this is what stops it becoming one.
# The flag skips signature verification -- artifacts served from an arbitrary
# URL carry no release provenance to check -- so it must not be possible to aim
# it at the place a real install fetches from.
if [ -n "$rehearse" ]; then
	case "$rehearse" in
	*github.com* | *githubusercontent.com*)
		die '--rehearse refuses a github.com URL. It exists to exercise this script against artifacts no release has published, and it does not verify signatures, so pointing it at the real release would install an unverified archive from the one place that can be verified.'
		;;
	esac
	[ -n "$version" ] ||
		die '--rehearse needs --version too: there is no `latest` to resolve at a URL that is not a GitHub release.'
fi

# `latest` is resolved to a real tag before anything is fetched.
if [ -z "$version" ]; then
	landed="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
		die "could not reach https://github.com/$REPO/releases/latest to find out which release is the latest."
	version="${landed##*/}"
	case "$version" in
	v*) ;;
	*) die "https://github.com/$REPO/releases/latest redirected to $landed, whose last path element is not a tag. Pass --version vX.Y.Z." ;;
	esac
	say "latest is $version"
fi

# GoReleaser names an archive with the tag's leading `v` stripped, and the
# binary reports the same stripped form. scripts/check-release-artifacts.py
# pins the shape, because this name is an interface: install.ps1, the Homebrew
# formula and the Scoop manifest all reconstruct it.
number="${version#v}"
archive="spill-guard_${number}_${goos}_${goarch}.tar.gz"

if [ -n "$rehearse" ]; then
	base="${rehearse%/}"
else
	base="https://github.com/$REPO/releases/download/$version"
fi

if [ -z "$dest" ]; then
	[ -n "${HOME:-}" ] ||
		die 'HOME is not set, so there is no ~/.local/bin to install into. Pass --dir.'
	dest="$HOME/.local/bin"
fi

# Resolved before anything is downloaded, so a machine with no sha256 tool
# refuses on an empty directory rather than after a download it cannot check.
if command -v sha256sum >/dev/null 2>&1; then
	sha_cmd='sha256sum'
elif command -v shasum >/dev/null 2>&1; then
	sha_cmd='shasum -a 256'
else
	die 'no sha256sum and no shasum, so the archive could not be verified. Refusing rather than installing something unchecked.'
fi

work="$(mktemp -d)" || die 'could not create a temporary directory'
# shellcheck disable=SC2064 -- $work is expanded now on purpose: the trap must
# name the directory this run made, not whatever the variable holds later.
trap "rm -rf '$work'" EXIT INT TERM

fetch() {
	curl -fsSL -o "$work/$1" "$base/$1" ||
		die "could not download $base/$1"
}

say "downloading $archive"
fetch "$archive"
fetch checksums.txt

# Both sha256sum and shasum write `<digest>  <name>`, so the first field is the
# whole answer on either.
actual="$($sha_cmd "$work/$archive" | cut -d' ' -f1)"
expected="$(awk -v want="$archive" '$2 == want { print $1 }' "$work/checksums.txt")"

# An empty `expected` has to fail loudest, because it is what a checksums.txt
# for some other release looks like and it is the reading a comparison written
# the other way round would pass.
[ -n "$expected" ] ||
	die "checksums.txt does not list $archive, so there is nothing here to check this download against. Nothing was installed."
[ "$actual" = "$expected" ] ||
	die "$archive does not match checksums.txt: it should be $expected and it is $actual. Nothing was installed."
say 'sha256 matches checksums.txt'

if [ -n "$rehearse" ]; then
	printf 'install.sh: REHEARSAL -- the signature was NOT verified. These artifacts\n' >&2
	printf 'install.sh: came from %s, which is not a release, so there is no\n' "$base" >&2
	printf 'install.sh: provenance to check. The sha256 above answers corruption and\n' >&2
	printf 'install.sh: not authenticity. Do not use this to install.\n' >&2
elif found="$(verifier)"; then
	case "$found" in
	cosign)
		fetch checksums.txt.sig
		fetch checksums.txt.pem
		# The identity is pinned to this repository's release workflow at this
		# tag. A signature minted from a branch, from another workflow, or from
		# a fork is a valid Sigstore signature that this has to reject.
		cosign verify-blob \
			--certificate "$work/checksums.txt.pem" \
			--signature "$work/checksums.txt.sig" \
			--certificate-identity "https://github.com/$REPO/$WORKFLOW@refs/tags/$version" \
			--certificate-oidc-issuer "$OIDC_ISSUER" \
			"$work/checksums.txt" ||
			die "cosign could not verify that checksums.txt was signed by $REPO's release workflow at $version. Nothing was installed."
		say "cosign verified checksums.txt against $REPO at $version"
		;;
	gh)
		gh attestation verify "$work/$archive" \
			--repo "$REPO" \
			--signer-workflow "$REPO/$WORKFLOW" ||
			die "gh could not verify that $archive was built by $REPO's release workflow. Nothing was installed."
		say "gh verified the build provenance of $archive"
		;;
	esac
else
	die "$NO_VERIFIER Nothing was installed."
fi

tar -xzf "$work/$archive" -C "$work" spill-guard ||
	die "$archive does not carry a spill-guard binary at its root."

mkdir -p "$dest" || die "could not create $dest"
cp "$work/spill-guard" "$dest/spill-guard" || die "could not write $dest/spill-guard"
chmod 0755 "$dest/spill-guard"

# Running it is the last assertion and the only one about this machine: a
# cross-compiled binary for the wrong architecture verifies perfectly and does
# not execute.
if ! reported="$("$dest/spill-guard" version)"; then
	die "$dest/spill-guard was installed and does not run on this machine."
fi
say "installed spill-guard $reported to $dest/spill-guard"

case ":${PATH}:" in
*":$dest:"*) ;;
*)
	printf '\n'
	printf 'install.sh: %s is not on your PATH. The hook launcher looks there\n' "$dest"
	printf 'install.sh: anyway, so spill-guard will run as a hook; add it to PATH to\n'
	printf 'install.sh: use the command yourself:\n\n'
	printf '  export PATH="%s:$PATH"\n\n' "$dest"
	;;
esac
