#!/usr/bin/env python3
"""Drive install.sh and install.ps1 against artifacts a release run built.

An install script that broke is indistinguishable from a tool nobody
installed: no user reports it, because the people who would report it are the
people who could not install it. Nothing else in this repository reaches these
files -- `make check` never runs them, and the release job would first execute
them on a permanent version number.

So this runs them. Each platform drives the script that platform will actually
take, from a loopback HTTP server rooted at a GoReleaser dist directory, and
asserts the three things a broken installer gets wrong quietly:

  * it installs, and the binary it installed runs *here*. A cross-compiled
    archive for the wrong architecture verifies perfectly and does not execute,
    so the last word belongs to `spill-guard version` rather than to a digest;
  * the version it reports is the one the archive name carries. Those two are
    set by different mechanisms -- `-ldflags -X` and `name_template` -- and a
    release whose binary and filename disagree is one nobody can reason about;
  * it refuses. A corrupted archive, a checksums.txt that does not list it, a
    machine with neither cosign nor gh, and a `--rehearse` aimed at github.com
    all have to stop it, and each refusal has to name the reason it stopped
    for. A script that exits non-zero for the wrong reason passes a test that
    only reads the status.

Every refusal arm asserts its own precondition first, because a break that
silently did not happen leaves the script reading clean input -- and a refusal
that never had anything to refuse is indistinguishable from one that worked.

The server runs in this process on 127.0.0.1 at a port the kernel picks, so
there is no readiness race to lose and no orphan to leave behind.

WHAT THIS CANNOT REACH. `--rehearse` skips signature verification, because
artifacts served from a loopback port carry no release provenance to check. So
the cosign and `gh attestation verify` calls are not driven here and cannot be:
they need a signed release, and the first one is a permanent version number.
What is driven is the step before them -- which verifier the script would pick,
and that it refuses when there is none. docs/development/release-process.md
carries the manual step that closes the rest, after a draft is published.

Usage: check-install-scripts.py [--dist DIR]

Exits 1 and lists every finding, so one run reports all of them.
"""

import functools
import hashlib
import http.server
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WINDOWS = os.name == "nt"

# The two tools install.sh and install.ps1 choose between, and the two names
# `--verifier` may print. Read out of the script's own verdict rather than by
# probing PATH a second way: what the script can resolve is the question, and a
# second probe is a second answer.
VERIFIERS = ("cosign", "gh")

GOARCH = {"x86_64": "amd64", "amd64": "amd64",
          "aarch64": "arm64", "arm64": "arm64"}
GOOS = {"darwin": "darwin", "linux": "linux", "win32": "windows"}


class Quiet(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler logs every request to stderr, which would bury
    a finding in a CI log under one line per download."""

    def log_message(self, *args):
        pass


class Serving:
    """A loopback HTTP server over one directory, as a context manager
    yielding its base URL."""

    def __init__(self, directory):
        self.directory = str(directory)

    def __enter__(self):
        handler = functools.partial(Quiet, directory=self.directory)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        return False


def host():
    """(goos, goarch) for the machine this is running on, or an exit."""
    goos = GOOS.get(sys.platform)
    goarch = GOARCH.get(platform.machine().lower())
    if goos is None or goarch is None:
        sys.exit(f"install-scripts: {sys.platform}/{platform.machine()} is not "
                 f"a target spill-guard ships, so there is no archive here to "
                 f"install and nothing below could have failed")
    return goos, goarch


def snapshot(dist):
    """The version GoReleaser stamped on this run's artifacts, or an exit."""
    path = dist / "metadata.json"
    if not path.is_file():
        sys.exit(f"install-scripts: no {path}. GoReleaser writes it on every "
                 f"run, so either the build did not happen or --dist names the "
                 f"wrong directory.")
    version = json.loads(path.read_text(encoding="utf-8")).get("version", "")
    if not version:
        sys.exit(f"install-scripts: {path} names no version, so the archive "
                 f"name below would be built from an empty string")
    return version


def hosts():
    """[(label, argv prefix)] -- every shell that will run an install script on
    this machine. Windows PowerShell 5.1 is the floor the script is written to
    and PowerShell 7 is what a developer is likelier to have, so both are
    driven where both are present."""
    if not WINDOWS:
        # Absolute, because the no-verifier arm empties PATH and a shell named
        # by a bare word is the first thing that stops resolving.
        return [("sh", [shutil.which("sh") or "/bin/sh",
                        str(ROOT / "install" / "install.sh")])]
    found = []
    for exe, label in (("powershell", "powershell 5.1"), ("pwsh", "pwsh 7")):
        path = shutil.which(exe)
        if path:
            found.append((label, [path, "-NoProfile", "-ExecutionPolicy",
                                  "Bypass", "-File",
                                  str(ROOT / "install" / "install.ps1")]))
    if not found:
        sys.exit("install-scripts: neither powershell nor pwsh is on PATH, so "
                 "install.ps1 could not be driven at all")
    return found


def flag(name, value=None):
    """A flag as the script that runs here spells it. install.sh takes
    --rehearse; install.ps1 takes -Rehearse.

    Keyed on the platform rather than on a host's label: install.sh runs
    nowhere but POSIX and install.ps1 nowhere but Windows, so the platform is
    the fact, and a label is a string somebody may add another of."""
    if WINDOWS:
        spelling = "-" + name[0].upper() + name[1:]
    else:
        spelling = "--" + name.lower()
    return [spelling] if value is None else [spelling, value]


def run(launch, args, env=None):
    """(rc, combined output). Both streams, because a refusal goes to stderr
    and the progress that says how far it got goes to stdout -- a finding that
    quotes one of them throws away the half that says why."""
    done = subprocess.run(launch + args, capture_output=True, text=True,
                          cwd=str(ROOT), env=env, check=False)
    return done.returncode, (done.stdout + done.stderr).strip()


def evidence(rc, out):
    return f"\n    exit {rc}\n" + "\n".join(f"    | {ln}"
                                            for ln in out.splitlines())


def mutate(dist, into, edit):
    """A copy of `dist` with `edit` applied, as a Path. `edit` returns a
    sentence describing what it changed, or None when it changed nothing --
    which is a precondition failure rather than a passing arm."""
    copy = Path(into)
    shutil.copytree(dist, copy)
    return copy, edit(copy)


def corrupt(archive):
    """Append a byte to the archive, and report the digest either side. A
    mutation that left the digest alone would leave the installer reading
    matching input and passing for that reason."""
    def edit(copy):
        target = copy / archive
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        target.write_bytes(target.read_bytes() + b"x")
        after = hashlib.sha256(target.read_bytes()).hexdigest()
        if before == after:
            return None
        return f"{archive} now hashes to {after} and checksums.txt says {before}"
    return edit


def delist(archive):
    """Drop the archive's line from checksums.txt."""
    def edit(copy):
        # Bytes rather than text: on Windows a text write would translate every
        # line ending in the file, which is a second mutation nobody asked for
        # and one that would land in the digests the installer then reads.
        path = copy / "checksums.txt"
        lines = path.read_bytes().splitlines(keepends=True)
        kept = [ln for ln in lines if archive.encode() not in ln]
        if len(kept) == len(lines):
            return None
        path.write_bytes(b"".join(kept))
        return f"checksums.txt no longer lists {archive}"
    return edit


def blind_env(empty):
    """An environment in which neither cosign nor gh resolves.

    PATH is replaced rather than trimmed: which directory a tool lives in is a
    guess, and the guess that misses leaves the tool resolvable and the arm
    testing nothing -- which is how `PATH=/usr/bin:/bin` came to hide a Go
    toolchain that setup-go had linked into /usr/bin.

    What replaces it is a directory holding nothing, except on Windows, where
    the two operating-system directories stay so that PowerShell still starts.
    Those are read from %SystemRoot% rather than written down, and neither
    carries cosign or gh -- and the caller does not take that on trust: the arm
    requires the script to refuse, so a mutation that hid nothing shows up as
    the script resolving a verifier anyway.
    """
    env = dict(os.environ)
    if WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        env["PATH"] = os.pathsep.join((os.path.join(root, "System32"), root))
    else:
        env["PATH"] = str(empty)
    return env


def main(argv):
    dist = ROOT / "dist"
    rest = argv[1:]
    while rest:
        if rest[0] == "--dist" and len(rest) > 1:
            dist, rest = Path(rest[1]), rest[2:]
        else:
            sys.exit(f"install-scripts: unknown argument {rest[0]!r}; pass "
                     f"--dist DIR or nothing")

    goos, goarch = host()
    version = snapshot(dist)
    ext = "zip" if goos == "windows" else "tar.gz"
    archive = f"spill-guard_{version}_{goos}_{goarch}.{ext}"
    if not (dist / archive).is_file():
        sys.exit(f"install-scripts: {dist / archive} is not there, so nothing "
                 f"below could have installed anything. The dist directory "
                 f"holds: {sorted(p.name for p in dist.iterdir())}")

    shells = hosts()
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for label, launch in shells:
            try:
                findings += drive(label, launch, dist, tmp, archive, version)
            except Exception:
                # The contract at the top of this file is that one run reports
                # every finding, and an exception escaping one shell breaks it
                # in the direction that hides work already done: the shells
                # before it accumulated findings that are then never printed.
                # Measured on windows-latest 2026-09-01, where a FileExistsError
                # under the second PowerShell discarded everything the first had
                # found. So a crash becomes a finding and the next shell runs.
                findings.append(
                    f"[{label}] the check itself failed while driving this "
                    f"shell, so this shell asserted nothing:\n"
                    + textwrap.indent(traceback.format_exc().rstrip(), "    "))

    for entry in findings:
        print(f"install-scripts: {entry}", file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} finding(s). The install script is the only "
              f"thing between a release and a machine, and nothing else in "
              f"this repository runs it.", file=sys.stderr)
        return 1
    print(f"install-scripts: {archive} installs and runs, reports {version}, "
          f"and refuses a corrupted archive, a checksums.txt that does not "
          f"list it, a machine with no verifier, and a github.com rehearsal "
          f"-- driven under {', '.join(label for label, _ in shells)}")
    return 0


def drive(label, launch, dist, tmp, archive, version):
    """Every arm, under one shell. Returns findings."""
    findings = []
    binary = "spill-guard.exe" if WINDOWS else "spill-guard"
    n = 0

    # Under its own directory, because Windows drives install.ps1 twice -- once
    # per PowerShell -- and the counter below restarts with each call. Sharing
    # the parent made the second host's first copytree land on a directory the
    # first host had already made, which is a FileExistsError rather than a
    # finding: it aborts the run, so the first host's findings are accumulated
    # and never printed. Measured on windows-latest 2026-09-01, and reproduced
    # here by driving `sh` twice.
    root = tmp / "".join(c if c.isalnum() else "-" for c in label)
    root.mkdir()

    def where(what):
        nonlocal n
        n += 1
        return root / f"{what}-{n}"

    def rehearse(base, dest):
        return (flag("version", version)
                + flag("rehearse", base)
                + flag("dir", str(dest)))

    # The whole point, and the arm every other one is a control on.
    dest = where("installed")
    with Serving(dist) as base:
        rc, out = run(launch, rehearse(base, dest))
    installed = dest / binary
    if rc != 0:
        findings.append(f"[{label}] the install script did not install "
                        f"{archive}{evidence(rc, out)}")
    elif not installed.is_file():
        findings.append(f"[{label}] the install script reported success and "
                        f"{installed} is not there{evidence(rc, out)}")
    else:
        done = subprocess.run((str(installed), "version"), capture_output=True,
                              text=True, check=False)
        reported = done.stdout.strip()
        if done.returncode != 0:
            findings.append(f"[{label}] {installed} was installed and does not "
                            f"run here{evidence(done.returncode, done.stderr)}")
        elif reported != version:
            findings.append(f"[{label}] the installed binary reports "
                            f"{reported!r} and it shipped in an archive named "
                            f"for {version!r}. Those are set by -ldflags and by "
                            f"name_template, and a release whose binary and "
                            f"filename disagree is one nobody can reason about")

    # Which verifier it would use. The verification itself needs a signed
    # release, so this is the furthest a pull request reaches.
    #
    # A machine with neither tool is a legitimate answer rather than a finding,
    # and it is also the answer that leaves the mutation below nothing to hide
    # -- so the same read decides both, and says out loud when the arm did not
    # run.
    verifier_rc, verifier_out = run(launch, flag("verifier"))
    if verifier_rc != 0:
        if "neither cosign nor gh" not in verifier_out:
            findings.append(f"[{label}] --verifier exited {verifier_rc} "
                            f"without saying why"
                            f"{evidence(verifier_rc, verifier_out)}")
        print(f"install-scripts: [{label}] neither cosign nor gh is installed "
              f"here, so --verifier is refusing correctly and the no-verifier "
              f"mutation had nothing to hide -- that arm was not driven",
              file=sys.stderr)
    elif not any(tool in verifier_out for tool in VERIFIERS):
        findings.append(f"[{label}] --verifier exited 0 and named neither "
                        f"cosign nor gh{evidence(verifier_rc, verifier_out)}")

    # The refusals. Each asserts its own precondition first.
    for what, edit, expect in (
            ("a corrupted archive", corrupt(archive),
             "does not match checksums.txt"),
            ("a checksums.txt that does not list the archive", delist(archive),
             "does not list")):
        copy, changed = mutate(dist, where("mutated"), edit)
        if changed is None:
            findings.append(f"[{label}] the mutation for {what} changed "
                            f"nothing, so the install script would have read "
                            f"clean input and the arm below tested nothing")
            continue
        dest = where("refused")
        with Serving(copy) as base:
            rc, out = run(launch, rehearse(base, dest))
        if rc == 0:
            findings.append(f"[{label}] the install script accepted {what} "
                            f"({changed}){evidence(rc, out)}")
        elif expect not in out:
            findings.append(f"[{label}] the install script refused {what} and "
                            f"not for that reason -- it never said "
                            f"{expect!r}{evidence(rc, out)}")
        elif (dest / binary).exists():
            findings.append(f"[{label}] the install script refused {what} and "
                            f"left {dest / binary} behind{evidence(rc, out)}")

    # A machine with neither verifier must refuse rather than fall back to the
    # sha256, which answers corruption and not substitution. Driven only where
    # the read above found a verifier to hide.
    if verifier_rc == 0:
        empty = where("empty")
        empty.mkdir()
        rc, out = run(launch, flag("verifier"), blind_env(empty))
        if rc == 0:
            findings.append(f"[{label}] the no-verifier mutation hid nothing "
                            f"-- the script resolved one anyway, so the arm "
                            f"tested nothing{evidence(rc, out)}")
        elif "neither cosign nor gh" not in out:
            findings.append(f"[{label}] with no verifier the script exited "
                            f"{rc} without saying why{evidence(rc, out)}")

    # --rehearse must not be usable as an install path. It skips the signature,
    # so aiming it at the release would install an unverified archive from the
    # one place that can be verified.
    rc, out = run(launch, flag("version", version)
                  + flag("rehearse",
                         "https://github.com/karlkfi/claude-spill-guard/releases/download/v9.9.9"))
    if rc == 0:
        findings.append(f"[{label}] --rehearse accepted a github.com URL, so "
                        f"the flag that skips signature verification can be "
                        f"aimed at the real release{evidence(rc, out)}")
    elif "refuses a github.com URL" not in out:
        findings.append(f"[{label}] --rehearse refused a github.com URL and "
                        f"not for that reason{evidence(rc, out)}")

    return findings


if __name__ == "__main__":
    sys.exit(main(sys.argv))
