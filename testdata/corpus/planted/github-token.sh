#!/usr/bin/env bash
# Release helper. The token was exported inline rather than read from the
# keychain, which is how it ended up committed.
set -euo pipefail
export GH_TOKEN=ghp_R7wKq2ZmT4bXn9Ld6VcP1YsA3EjH5uGf0iQz
gh release create "v$1" --generate-notes
