#!/usr/bin/env bash
# Report which command-line tools this project needs and whether they are here.
#
# THE ONE PROPERTY THIS HAS TO KEEP: it runs on a fresh clone with none of the
# tools present. That rules out the natural implementation, which reaches for
# the very things it is checking -- `go version` to find Go, `go run` from
# tools/ to find a linter. Both work perfectly on the machine of whoever wrote
# them and neither works on the machine that needs the report. So every probe
# here is `command -v` and nothing else: a PATH lookup, no execution, no
# module download, no network.
#
# `command -v` is a shell builtin, so this holds even when PATH itself is
# nearly empty. The gate that keeps it that way runs this with `go` off PATH
# and with GOPROXY off over an empty module cache; see doctor-mutation-control
# in .github/workflows/tests.yml.
#
# The pinned linters are deliberately NOT in the list. golangci-lint,
# govulncheck and actionlint are versioned in tools/go.mod and run through
# `cd tools && go run ...`, so a contributor never installs them and their
# absence from PATH is correct rather than a finding. Go is what they need.
#
# Two tiers, and the split is the whole design:
#
#   required     nothing in this repo works without it, so a miss exits 1.
#   release      needed only to cut a release. A miss is reported and exits 0,
#                because a contributor fixing a bug has no reason to install
#                a signing tool. Tiers copied from a larger project are how a
#                doctor target starts reporting absences nobody needs to fix.
#
# Usage: check-tools.sh [--tier required|release|all]
set -euo pipefail

# `set -e` does not reach inside a command substitution: `out="$(f)"` runs f
# past its own failure and takes the status of f's last command.
# inherit_errexit is what makes that exit rather than continue with a truncated
# value, and it is bash 4.4+.
#
# ASKED FOR, NOT REQUIRED, AND ONLY IN THIS SCRIPT. macOS still ships bash
# 3.2.57 as /bin/bash -- measured 2026-08-22 on darwin 25.5 -- and this is the
# one script whose whole job is to run on a machine with nothing set up, so
# `#!/usr/bin/env bash` on a fresh Mac finds 3.2 and an unguarded `shopt` kills
# it on line 32 with `invalid shell option name`. That is this target's stated
# property failing, caused by the prologue meant to protect it.
#
# Safe here specifically: nothing below takes a value from a command
# substitution that can fail. The two that exist -- `hint` and `path_hint` --
# are pure `case` statements, and the third is guarded by `|| echo unknown`.
# Every other script in this repo runs under CI's bash or a developer's, so
# they take the option unguarded. Do not copy this line into them.
shopt -s inherit_errexit 2>/dev/null || true

tier=all
while [[ $# -gt 0 ]]; do
	case "$1" in
	--tier)
		tier="${2:?--tier needs a value}"
		shift 2
		;;
	-h | --help)
		awk '/^# Usage:/ { sub(/^#[[:space:]]?/, ""); print }' "$0"
		exit 0
		;;
	*)
		printf 'check-tools: unknown argument: %s\n' "$1" >&2
		exit 2
		;;
	esac
done
case "$tier" in
required | release | all) ;;
*)
	printf 'check-tools: --tier takes required, release or all, not %s\n' "$tier" >&2
	exit 2
	;;
esac

# One row per tool: tier, name, what it is for, and where to get it. The hint
# is per-OS because the answer genuinely differs, and a hint that names the
# wrong package manager is worse than none -- it sends someone to a dead end
# with the confidence of an instruction.
uname_s="$(uname -s 2>/dev/null || echo unknown)"
case "$uname_s" in
Darwin) os=macos ;;
Linux) os=linux ;;
MINGW* | MSYS* | CYGWIN*) os=windows ;;
*) os=unknown ;;
esac

hint() {
	case "$1:$os" in
	go:macos) echo "brew install go" ;;
	go:linux) echo "https://go.dev/dl/ , or your distribution's golang package" ;;
	go:windows) echo "winget install GoLang.Go" ;;
	git:macos) echo "xcode-select --install, or brew install git" ;;
	git:linux) echo "apt install git / dnf install git" ;;
	git:windows) echo "winget install Git.Git" ;;
	make:macos) echo "xcode-select --install" ;;
	make:linux) echo "apt install make / dnf install make" ;;
	make:windows) echo "ships with Git for Windows' SDK, or use WSL" ;;
	python3:macos) echo "brew install python" ;;
	python3:linux) echo "apt install python3 / dnf install python3" ;;
	python3:windows) echo "winget install Python.Python.3.13" ;;
	cosign:macos) echo "brew install cosign" ;;
	cosign:linux) echo "https://docs.sigstore.dev/system_config/installation/" ;;
	cosign:windows) echo "winget install sigstore.cosign" ;;
	goreleaser:macos) echo "brew install goreleaser" ;;
	goreleaser:linux) echo "https://goreleaser.com/install/" ;;
	goreleaser:windows) echo "scoop install goreleaser" ;;
	*) echo "https://github.com/karlkfi/claude-spill-guard" ;;
	esac
}

# Where a tool usually lands when it is installed and still not found. Printed
# only on a miss, because "installed but not on PATH" is the case a bare
# "not found" leaves someone chasing an install they already did.
path_hint() {
	case "$1" in
	go) echo 'Go installs to /usr/local/go/bin on Linux and macOS; add it to PATH.' ;;
	cosign | goreleaser) echo 'go install puts binaries in $(go env GOPATH)/bin; add it to PATH.' ;;
	*) echo '' ;;
	esac
}

required_tools="go git make python3"
release_tools="cosign goreleaser"

missing_required=0
missing_release=0

report() {
	local label="$1" tools="$2" name found
	printf '%s\n' "$label"
	for name in $tools; do
		# The whole probe. A PATH lookup and no execution, so a tool that is
		# present but broken still reads as present -- which is correct here:
		# this answers "is it installed", and a broken install is a different
		# report with a different fix.
		if found="$(command -v "$name" 2>/dev/null)" && [[ -n "$found" ]]; then
			printf '  %-11s %s\n' "$name" "$found"
			continue
		fi
		printf '  %-11s MISSING -- %s\n' "$name" "$(hint "$name")"
		local extra
		extra="$(path_hint "$name")"
		[[ -z "$extra" ]] || printf '  %-11s %s\n' '' "$extra"
		if [[ "$label" == required* ]]; then
			missing_required=$((missing_required + 1))
		else
			missing_release=$((missing_release + 1))
		fi
	done
	printf '\n'
}

printf 'spill-guard tools (%s)\n\n' "$os"

if [[ "$tier" == required || "$tier" == all ]]; then
	report 'required -- nothing here works without these' "$required_tools"
fi
if [[ "$tier" == release || "$tier" == all ]]; then
	report 'release only -- needed to cut a release, not to fix a bug' "$release_tools"
fi

printf 'The pinned linters are not in this list. golangci-lint, govulncheck and\n'
printf 'actionlint are versioned in tools/go.mod and run with `cd tools && go run\n'
printf '<path>`, so Go being present is what they need from you.\n'

if [[ "$missing_release" -gt 0 ]]; then
	printf '\n%d release-only tool(s) missing. That is not a problem unless you are\n' "$missing_release"
	printf 'cutting a release.\n'
fi
if [[ "$missing_required" -gt 0 ]]; then
	printf '\n%d required tool(s) missing.\n' "$missing_required" >&2
	exit 1
fi
