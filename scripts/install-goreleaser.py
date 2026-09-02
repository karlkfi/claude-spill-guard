#!/usr/bin/env python3
"""Install the GoReleaser CLI this repository pinned, and refuse any other bytes.

`action-pins` requires a 40-character commit SHA for every `uses:` in every
workflow, on the argument that a tag is mutable by whoever owns it and an action
runs in a job holding this repository's token. The GoReleaser *binary* sat
outside that: `goreleaser/goreleaser-action` was pinned by SHA and the CLI it
downloaded was chosen by a version input, which is a git tag on
`goreleaser/goreleaser` resolved on the day -- on the job that holds
`contents: write` and `id-token: write`.

`action-pins` cannot see that and never will: it reads `uses:` values, and a
tool version passed as an action input is not one. So the pin has to be
something a job fails on rather than something a gate reads. This is it. Fetch
the archive, hash it, compare, and refuse before anything is extracted or run --
the same shape as scripts/check-vendor.py, which is where this repository
already keeps a copy honest against a digest somebody wrote down.

The digests below are upstream's own, published in the `checksums.txt` of the
release VERSION names. Re-pinning is a version, two digests, and a diff a
reviewer can check against that file:

    gh release download v2.19.0 --repo goreleaser/goreleaser -p checksums.txt -O -

This asserts nothing about forgery, for the reason scripts/README.md gives
about its own table: whoever can edit a digest can edit the line above it. What
it stops is the tag moving under a release nobody re-reviewed.
"""

import argparse
import hashlib
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "v2.18.0"

# Keyed by what platform.system() and platform.machine() report, and holding
# the two platforms that run this: CI is ubuntu-latest, and darwin/arm64 is
# where a maintainer drives it before pushing. An unlisted platform is a
# refusal rather than a download -- a pin that falls back to whatever upstream
# serves is not a pin.
ARCHIVES = {
    ("Linux", "x86_64"): (
        "goreleaser_Linux_x86_64.tar.gz",
        "41cdf49b653784b03a08013dd99e382cd5d463049e915c2d818eaed182ae6197",
    ),
    ("Darwin", "arm64"): (
        "goreleaser_Darwin_arm64.tar.gz",
        "1c42b87cbce094a60f1a94dab0c71f640dbe4396fa5dc632b5c25bf14b1e88fc",
    ),
}

URL = "https://github.com/goreleaser/goreleaser/releases/download/{v}/{name}"

# The archive is 26 MB, so it is hashed as it arrives.
CHUNK = 1 << 20


def fetch(url, dest):
    """Download to dest, returning its sha256."""
    digest = hashlib.sha256()
    with urllib.request.urlopen(url) as response, open(dest, "wb") as out:
        while chunk := response.read(CHUNK):
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def extract(archive, dest):
    """Write the `goreleaser` member of archive to dest, executable.

    By name and written here, rather than `extractall`, which would take its
    destinations from paths inside the archive.
    """
    with tarfile.open(archive) as tar:
        member = tar.extractfile("goreleaser")
        if member is None:
            sys.exit(f"install-goreleaser: {archive.name} holds no `goreleaser` "
                     f"file, so the digest matched an archive of something else")
        dest.write_bytes(member.read())
    dest.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, help="directory to install into")
    args = parser.parse_args()

    key = (platform.system(), platform.machine())
    if key not in ARCHIVES:
        sys.exit(f"install-goreleaser: nothing is pinned for {key[0]}/{key[1]}. "
                 f"Pinned: {', '.join(f'{s}/{m}' for s, m in ARCHIVES)}. Add its "
                 f"row from the checksums.txt of {VERSION} rather than letting "
                 f"this fall back to whatever upstream serves.")
    name, expected = ARCHIVES[key]

    dest = args.dest or Path(
        os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / f"goreleaser-{VERSION}"
    dest.mkdir(parents=True, exist_ok=True)

    url = URL.format(v=VERSION, name=name)
    print(f"install-goreleaser: fetching {url}")
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / name
        actual = fetch(url, archive)
        if actual != expected:
            sys.exit(f"install-goreleaser: {name} hashes to {actual}, which does "
                     f"not match the digest this repository pinned, {expected}. "
                     f"Nothing was extracted. Either {VERSION} moved under the "
                     f"pin, or the download did not arrive intact -- re-pin from "
                     f"upstream's checksums.txt only after reading why it moved.")
        print(f"install-goreleaser: {name} matches {expected}")
        extract(archive, dest / "goreleaser")

    binary = dest / "goreleaser"
    # The bytes verified above are only the right tool if they run and say so.
    reported = subprocess.run((binary, "--version"), capture_output=True,
                              text=True, check=True).stdout
    if VERSION.lstrip("v") not in reported:
        sys.exit(f"install-goreleaser: the archive pinned for {VERSION} installed "
                 f"a binary reporting something else:\n{reported}")

    github_path = os.environ.get("GITHUB_PATH")
    if github_path:
        with open(github_path, "a", encoding="utf-8") as fh:
            fh.write(f"{dest}\n")
        print(f"install-goreleaser: {binary} is on PATH for the steps below")
    else:
        print(f"install-goreleaser: installed {binary}; add {dest} to PATH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
