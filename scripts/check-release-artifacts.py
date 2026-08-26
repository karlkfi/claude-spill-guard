#!/usr/bin/env python3
"""What a GoReleaser run produced is what a release is supposed to publish.

The release job runs on a `v*` tag and on nothing else, so no pull request
exercises it and its first execution is a permanent version number. This is
what a pull request runs instead: build a snapshot, then assert the result
against the two things that have to hold.

  * **Coverage.** One archive per target in scripts/cross-compile.py, and no
    others. Two lists of platforms drift, and the direction that fails quietly
    is this one: a release publishing four archives while the gate builds five
    looks green everywhere and strands whoever is on the fifth platform.
  * **Naming.** install.sh, the Homebrew formula and the Scoop manifest each
    build an archive name from an OS and an architecture, so the name is an
    interface. Renaming it breaks every install channel at once, and the
    channels report it, not this repository.

The checksums are recomputed rather than trusted. `checksums.txt` is the file
every channel verifies against and the one cosign signs, so a run that wrote a
stale or partial one signs a wrong answer -- and the release would still carry
a valid signature over it.

Reads dist/artifacts.json for the model rather than globbing the directory: the
glob cannot say which target an archive was built for, and a missing target is
exactly what it would have to notice. Every way this can come back empty is an
exit rather than a shorter list.

Usage: check-release-artifacts.py [--dist DIR] [--signed]

`--signed` additionally requires the cosign signature and certificate beside
the checksums file. The pull-request run passes `--skip=sign` and omits this:
cosign sign-blob writes a public Rekor entry, and minting one per pull request
logs builds nobody published.
"""

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The archive name every install channel reconstructs. The version is whatever
# the tag said, so it is matched loosely; the two fields a channel computes are
# not.
ARCHIVE_RE = re.compile(
    r"^spill-guard_(?P<version>.+)_(?P<goos>[a-z0-9]+)_(?P<goarch>[a-z0-9]+)"
    r"\.(?P<ext>tar\.gz|zip)$")

CHECKSUMS = "checksums.txt"

# tar.gz everywhere but Windows, where every unarchiver handles zip and
# tar.gz needs one installed.
EXT = {"windows": "zip"}
DEFAULT_EXT = "tar.gz"


def targets():
    """The shipped targets, from the gate that builds them. Imported rather
    than copied: a second list is a second answer, and this exists to catch
    exactly that."""
    path = ROOT / "scripts" / "cross-compile.py"
    spec = importlib.util.spec_from_file_location("cross_compile", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    found = tuple(module.TARGETS)
    if not found:
        sys.exit(f"release-artifacts: {path.relative_to(ROOT)} names no "
                 f"targets, so every assertion below would pass over nothing")
    return found


def artifacts(dist):
    """dist/artifacts.json as a list. GoReleaser writes it on every run, so its
    absence means the build did not get that far."""
    path = dist / "artifacts.json"
    if not path.is_file():
        sys.exit(f"release-artifacts: no {path}. GoReleaser writes it on every "
                 f"run, so either the build did not reach the archive stage or "
                 f"--dist names the wrong directory.")
    try:
        model = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        sys.exit(f"release-artifacts: {path} is not JSON ({err})")
    if not model:
        sys.exit(f"release-artifacts: {path} is empty, so nothing below could "
                 f"have failed")
    return model


def digests(text):
    """{name: digest} from a checksums file, or an exit. The format is
    `<digest>  <name>` -- two spaces, as sha256sum writes it."""
    found = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        if not sep or len(digest) != 64:
            sys.exit(f"release-artifacts: {CHECKSUMS} carries a line that is "
                     f"not `<sha256>  <name>`: {line!r}")
        found[name] = digest
    return found


def check(dist, signed, shipped):
    """Every disagreement, as a list of lines."""
    findings = []
    model = artifacts(dist)

    archives = {}
    for entry in model:
        if entry.get("type") != "Archive":
            continue
        archives[entry["name"]] = (entry.get("goos"), entry.get("goarch"))
    if not archives:
        sys.exit(f"release-artifacts: {dist}/artifacts.json names no archive "
                 f"at all, so the coverage assertion below would pass over "
                 f"nothing")

    want = set(shipped)
    built = set(archives.values())
    for goos, goarch in sorted(want - built):
        findings.append(f"nothing was archived for {goos}/{goarch}, which "
                        f"scripts/cross-compile.py builds. A release that "
                        f"publishes fewer archives than the gate builds is "
                        f"green everywhere and unusable on that platform")
    for goos, goarch in sorted(built - want):
        findings.append(f"an archive was built for {goos}/{goarch}, which "
                        f"scripts/cross-compile.py does not build -- so it "
                        f"ships untested by the cross-compile gate")

    for name, (goos, goarch) in sorted(archives.items()):
        match = ARCHIVE_RE.match(name)
        if match is None:
            findings.append(f"{name} is not "
                            f"`spill-guard_<version>_<os>_<arch>.<ext>`. Every "
                            f"install channel builds that name from an OS and "
                            f"an architecture, so this breaks all of them")
            continue
        ext = EXT.get(goos, DEFAULT_EXT)
        if (match["goos"], match["goarch"], match["ext"]) != (goos, goarch, ext):
            findings.append(f"{name} names {match['goos']}/{match['goarch']} "
                            f"as {match['ext']}, and it was built for "
                            f"{goos}/{goarch} as {ext}")

    checksums = [e for e in model if e.get("type") == "Checksum"]
    if len(checksums) != 1 or checksums[0]["name"] != CHECKSUMS:
        findings.append(f"the run produced "
                        f"{[e['name'] for e in checksums] or 'no'} checksum "
                        f"file, and every channel verifies against exactly one "
                        f"named {CHECKSUMS}")
        return findings

    path = dist / CHECKSUMS
    if not path.is_file():
        findings.append(f"artifacts.json names {CHECKSUMS} and {path} is not "
                        f"there")
        return findings

    recorded = digests(path.read_text(encoding="utf-8"))
    for name in sorted(set(archives) - set(recorded)):
        findings.append(f"{name} was archived and is not in {CHECKSUMS}, so "
                        f"nothing a user runs can verify it")
    for name in sorted(set(recorded) - set(archives)):
        findings.append(f"{CHECKSUMS} carries {name}, which this run did not "
                        f"archive -- a stale file signed as though current")
    for name, digest in sorted(recorded.items()):
        blob = dist / name
        if not blob.is_file():
            findings.append(f"{CHECKSUMS} carries {name} and {blob} is not there")
            continue
        actual = hashlib.sha256(blob.read_bytes()).hexdigest()
        if actual != digest:
            findings.append(f"{CHECKSUMS} says {name} is {digest} and it is "
                            f"{actual}. Signing that file signs a wrong answer")

    if signed:
        for suffix, what in ((".sig", "cosign signature"),
                             (".pem", "signing certificate")):
            blob = dist / (CHECKSUMS + suffix)
            if not blob.is_file():
                findings.append(f"no {blob.name}, so the release carries no "
                                f"{what} over {CHECKSUMS}")
    return findings


def main(argv):
    dist, signed = ROOT / "dist", False
    rest = argv[1:]
    while rest:
        if rest[0] == "--signed":
            signed, rest = True, rest[1:]
        elif rest[0] == "--dist" and len(rest) > 1:
            dist, rest = Path(rest[1]), rest[2:]
        else:
            sys.exit(f"release-artifacts: unknown argument {rest[0]!r}; pass "
                     f"--dist DIR, --signed, or nothing")

    shipped = targets()
    findings = check(dist, signed, shipped)
    for entry in findings:
        print(f"release-artifacts: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} disagreement(s) between what this run "
              f"produced and what a release publishes.", file=sys.stderr)
        return 1
    print(f"release-artifacts: {len(shipped)} archives, one per shipped "
          f"target, each named as the install channels expect and each matching "
          f"its {CHECKSUMS} digest"
          f"{', signed' if signed else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
