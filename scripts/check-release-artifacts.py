#!/usr/bin/env python3
"""What a GoReleaser run produced is what a release is supposed to publish.

The release job runs on a `v*` tag and on nothing else, so no pull request
exercises it and its first execution is a permanent version number. This is
what a pull request runs instead: build a snapshot, then assert the result
against the three things that have to hold.

  * **Coverage.** One archive per target in scripts/cross-compile.py, and no
    others. Two lists of platforms drift, and the direction that fails quietly
    is this one: a release publishing four archives while the gate builds five
    looks green everywhere and strands whoever is on the fifth platform.
  * **Naming.** install.sh, the Homebrew formula and the Scoop manifest each
    build an archive name from an OS and an architecture, so the name is an
    interface. Renaming it breaks every install channel at once, and the
    channels report it, not this repository.
  * **Coverage of what is not an archive.** A release also carries the two
    install scripts, which GoReleaser uploads rather than builds. Two separate
    lists in .goreleaser.yaml decide what happens to one -- `release` uploads
    it and `checksum` puts it in checksums.txt -- and a name on the first and
    not the second ships outside the file cosign signs. That was Q97.

The checksums are recomputed rather than trusted. `checksums.txt` is the file
every channel verifies against and the one cosign signs, so a run that wrote a
stale or partial one signs a wrong answer -- and the release would still carry
a valid signature over it.

Reads dist/artifacts.json for the model rather than globbing the directory: the
glob cannot say which target an archive was built for, and a missing target is
exactly what it would have to notice. The extra files are not in there --
GoReleaser records no artifact for one and does not copy it into dist -- so
those come from .goreleaser.yaml, through the parser in tools/cmd/releaseconfig
for the reason scripts/workflow_model.py gives. Every way any of this can come
back empty is an exit rather than a shorter list.

Usage: check-release-artifacts.py [--dist DIR] [--signed]
       check-release-artifacts.py --count-targets

`--count-targets` prints how many targets ship and exits, so a caller that
needs the number reads it from the same import rather than writing it down. The
release workflow's provenance loop is that caller: a literal there would be a
second copy of a list this file exists to keep single, and it would be wrong on
the release that added a target rather than on a pull request.

`--signed` additionally requires the Sigstore bundle beside the checksums file.
One bundle rather than a `.sig` and a `.pem`, because cosign v3 signs into the
new bundle format by default and dropped the flags that wrote the other two.
The name is read from .goreleaser.yaml's `signs` entry rather than written here,
so a change to the signing config cannot leave this asserting the old asset --
which is the defect this line replaces, and it cost a rehearsal to find.

The pull-request run passes `--skip=sign` and omits this: cosign sign-blob
writes a public Rekor entry, and minting one per pull request logs builds
nobody published.
"""

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The archive name every install channel reconstructs. The version is whatever
# the tag said, so it is matched loosely; the two fields a channel computes are
# not.
ARCHIVE_RE = re.compile(
    r"^spill-guard_(?P<version>.+)_(?P<goos>[a-z0-9]+)_(?P<goarch>[a-z0-9]+)"
    r"\.(?P<ext>tar\.gz|zip)$")

CHECKSUMS = "checksums.txt"

CONFIG = ROOT / ".goreleaser.yaml"

# Two {published name: the file on disk it is a copy of} maps, and every glob
# that named nothing -- carried rather than dropped, because such a glob
# contributes no name and the comparison between the two maps passes over it.
Extras = namedtuple("Extras", "uploaded covered unmatched")

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


_DECLARED = None


def declared():
    """.goreleaser.yaml as the parser in tools/cmd/releaseconfig reads it.

    Run once and kept, because two callers need it and `go run` is the slow
    part of this script. A parser that cannot run is fatal rather than an empty
    model: every assertion below would pass over nothing.
    """
    global _DECLARED
    if _DECLARED is not None:
        return _DECLARED
    result = subprocess.run(("go", "run", "./cmd/releaseconfig", str(CONFIG)),
                            cwd=ROOT / "tools", capture_output=True, text=True,
                            check=False)
    if result.returncode != 0:
        sys.exit(f"release-artifacts: the parser in tools/cmd/releaseconfig "
                 f"exited {result.returncode}, so what {CONFIG.name} declares "
                 f"is unknown and every assertion about it would pass over "
                 f"nothing. Go is a required tool -- see `make doctor`.\n"
                 f"{result.stderr.strip()}")
    try:
        _DECLARED = json.loads(result.stdout)
    except json.JSONDecodeError as err:
        sys.exit(f"release-artifacts: the parser wrote something this cannot "
                 f"read ({err}). Anything else on its stdout would be read as "
                 f"the model.\n{result.stdout[:400]}")
    return _DECLARED


def signed_assets():
    """The asset names the signing config produces, beside CHECKSUMS.

    Read from `signs:` rather than written down, because the last copy written
    down here went stale the day cosign v3 replaced a `.sig` and a `.pem` with
    one `.sigstore.json`, and it went stale in the direction that only a real
    tag can show: `--skip=sign` on every pull request means nothing checks it
    until the release is being cut.

    A `signs:` section that declares no name at all is a finding rather than a
    default filled in here. GoReleaser's own default is `${artifact}.sig`, and
    a copy of it in this file is the same drift one level down.
    """
    names, findings = [], []
    signs = declared().get("signs")
    if not signs:
        findings.append(f"{CONFIG.name} declares no `signs:` entry, so nothing "
                        f"signs {CHECKSUMS} and --signed has no asset to "
                        f"require")
        return names, findings
    for i, entry in enumerate(signs):
        for key in ("signature", "certificate"):
            template = entry.get(key) or ""
            if not template:
                continue
            if "${artifact}" not in template:
                findings.append(f"{CONFIG.name} `signs[{i}].{key}` is "
                                f"{template!r}, which names no ${{artifact}} -- "
                                f"this cannot say what asset it becomes")
                continue
            names.append(template.replace("${artifact}", CHECKSUMS))
    if not names:
        findings.append(f"{CONFIG.name} `signs[0]` declares neither a "
                        f"`signature:` nor a `certificate:`, so the asset it "
                        f"writes is GoReleaser's default and not stated here")
    return names, findings


def declared_extras():
    """What a release carries besides the archives, from .goreleaser.yaml.

    Read through the parser in tools/cmd/releaseconfig rather than matched out
    of the file: `yaml` is not importable on a machine that satisfies `make
    doctor`, and a pattern over raw lines reads a glob inside a `before.hooks`
    shell line as a declaration. GoReleaser names each asset after the file's
    basename, which is the name checksums.txt records."""
    model = declared()
    try:
        globs = (model["release_extra_files"], model["checksum_extra_files"])
    except (KeyError, TypeError) as err:
        sys.exit(f"release-artifacts: the parser wrote something this cannot "
                 f"read ({err}). Anything else on its stdout would be read as "
                 f"the model.\n{json.dumps(model)[:400]}")

    resolved, unmatched = [], []
    for section in globs:
        found = {}
        for pattern in section:
            matched = sorted(p for p in ROOT.glob(pattern) if p.is_file())
            if not matched:
                unmatched.append(pattern)
            for path in matched:
                found[path.name] = path
        resolved.append(found)
    return Extras(resolved[0], resolved[1], sorted(set(unmatched)))


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


def check(dist, signed, shipped, extras):
    """Every disagreement, as a list of lines."""
    findings = []
    model = artifacts(dist)

    for pattern in extras.unmatched:
        findings.append(f"{CONFIG.name} declares the extra file {pattern} and "
                        f"nothing in this tree matches it, so the release "
                        f"carries no such asset")
    for name in sorted(set(extras.uploaded) - set(extras.covered)):
        findings.append(f"{name} is uploaded by release.extra_files and is not "
                        f"named by checksum.extra_files, so it is absent from "
                        f"{CHECKSUMS} and the signature over that file does "
                        f"not reach it -- it ships as the one asset a user "
                        f"cannot check")
    for name in sorted(set(extras.covered) - set(extras.uploaded)):
        findings.append(f"{name} is named by checksum.extra_files and is not "
                        f"uploaded by release.extra_files, so {CHECKSUMS} "
                        f"carries a digest for a file the release does not "
                        f"publish -- `sha256sum -c` over it fails for whoever "
                        f"downloaded everything there is")

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
    for name in sorted(set(extras.covered) - set(recorded)):
        findings.append(f"checksum.extra_files names {name} and {CHECKSUMS} "
                        f"does not carry it, so nothing a user runs can verify "
                        f"it")
    for name in sorted(set(recorded) - set(archives) - set(extras.covered)):
        findings.append(f"{CHECKSUMS} carries {name}, which this run did not "
                        f"archive and {CONFIG.name} does not declare -- a "
                        f"stale file signed as though current")
    # An extra file is checksummed where it sits and is not copied into dist,
    # so its digest is recomputed from the source the release uploads.
    for name, digest in sorted(recorded.items()):
        blob = extras.covered.get(name, dist / name)
        if not blob.is_file():
            findings.append(f"{CHECKSUMS} carries {name} and {blob} is not there")
            continue
        actual = hashlib.sha256(blob.read_bytes()).hexdigest()
        if actual != digest:
            findings.append(f"{CHECKSUMS} says {name} is {digest} and it is "
                            f"{actual}. Signing that file signs a wrong answer")

    if signed:
        names, complaints = signed_assets()
        findings.extend(complaints)
        for name in names:
            blob = dist / name
            if not blob.is_file():
                findings.append(f"no {blob.name}, so the release carries "
                                f"nothing to verify {CHECKSUMS} with -- "
                                f"{CONFIG.name} says signing writes it")
    return findings


def main(argv):
    if argv[1:] == ["--count-targets"]:
        print(len(targets()))
        return 0

    dist, signed = ROOT / "dist", False
    rest = argv[1:]
    while rest:
        if rest[0] == "--signed":
            signed, rest = True, rest[1:]
        elif rest[0] == "--dist" and len(rest) > 1:
            dist, rest = Path(rest[1]), rest[2:]
        else:
            sys.exit(f"release-artifacts: unknown argument {rest[0]!r}; pass "
                     f"--dist DIR, --signed, --count-targets, or nothing")

    shipped = targets()
    extras = declared_extras()
    findings = check(dist, signed, shipped, extras)
    for entry in findings:
        print(f"release-artifacts: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} disagreement(s) between what this run "
              f"produced and what a release publishes.", file=sys.stderr)
        return 1
    print(f"release-artifacts: {len(shipped)} archives, one per shipped "
          f"target, each named as the install channels expect, and "
          f"{len(extras.covered)} extra file(s) beside them, each matching its "
          f"{CHECKSUMS} digest{', signed' if signed else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
