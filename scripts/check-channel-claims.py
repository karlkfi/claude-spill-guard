#!/usr/bin/env python3
"""No message this project prints may name an install channel that does not exist.

Q12's review found both install scripts telling a blocked user to run `brew
install karlkfi/tap/spill-guard`. The tap does not exist, so the command fails,
and the user reading it is by definition already stuck -- the refusal is
designed behaviour on the path the design deliberately chose, not an error. It
was fixed by hand. Two more of the same class survived in the launcher's deny
reasons until Q10 removed them. Nothing stopped any of it coming back:
`check-install-scripts.py` asserts the substring `neither cosign nor gh` and
reads no further, so the whole tail of that refusal is unchecked, and it cannot
be a gate anyway -- it installs out of a GoReleaser dist directory, which a
fresh clone does not have.

**The answer is in the tree, which is what makes this mechanizable.**
`.goreleaser.yaml` is the file that would carry a `brews:` or a `scoops:` block
and carries neither. So the channel set is read rather than hand-kept, the same
shape as `check-release-artifacts.py` importing its target list from
`cross-compile.py`. A list of channels written down here would drift from the
release config, and drift in the direction that passes.

**The hard half is telling a message from a comment.** `install/install.sh`'s
own header names `brew install karlkfi/tap/spill-guard` deliberately, as the
thing not to do, and it has to keep saying so -- that comment is the argument
for the refusal's wording. A pattern over the file flags it. So this reads only
the string literals on lines that are not comments, which is one rule rather
than a parser per emit shape, and it catches strictly more than scoping to
`die` arguments would: an `echo`, a `printf` format, a constant later
interpolated into a refusal are all covered by the same read. A literal that is
never printed -- a `case` pattern, a `[ "$a" = "b" ]` -- is read too and is
harmless, because nothing that is not an install command can match below.

**The command has to name this project, not the channel.** `NO_VERIFIER` sends
a blocked user to `brew install cosign` and `winget install sigstore.cosign`,
which are real channels for a different package and must not fire. So every
pattern binds to `project_name` from `.goreleaser.yaml`, and `brew` alone means
nothing.

**`go install` is a channel with no GoReleaser block, and it is live.** The
refusal names it, and it works today with no release and no tag: measured
2026-09-02, `go list -m github.com/karlkfi/claude-spill-guard@latest` resolves
to `v0.0.0-20260902011456-507599777104`, a pseudo-version of `main`. So its
existence condition is the module path in `go.mod` rather than a key in the
release config, and what is checked is that a `go install` *of this project*
names that path. A `go install` of something else is somebody else's package,
the same reading that lets `brew install cosign` through, so it is bound to the
binary name for the same reason: the last path element, not the host.

**What this deliberately does not cover, so nobody repairs the apparent
inconsistency.** The launcher's deny tells a user to download `install.sh` from
the latest release, and there is no release, so that channel does not exist
either. It is not flagged here. The two cases differ in what the project has
decided: the tap and the bucket are channels it has chosen not to build yet
(Q13 and Q14 are open, and the design says in as many words that the refusal
must not name them), while the release is configured and waits only on a tag.
Q101 is the row for the second and `release-claims` is the gate that reads it.
This one owns package managers.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GORELEASER = ROOT / ".goreleaser.yaml"
GOMOD = ROOT / "go.mod"

# Where a user-facing string can be written, and how a comment starts in each.
# run-spill-guard.cmd is a polyglot, so it has both: `REM`/`::` for the batch
# half and `#` for the POSIX half.
EMITTERS = {
    "install/install.sh": ("#",),
    "install/install.ps1": ("#",),
    "hooks/run-spill-guard.cmd": ("#", "REM ", "REM\t", "::"),
}

# One substring per file that the extraction has to find. Not a completeness
# check -- it is the positive control on the reader. A regex that stopped
# matching would otherwise report every file clean, which is the same output as
# a tree with nothing wrong in it.
MUST_SEE = {
    "install/install.sh": "neither cosign nor gh",
    "install/install.ps1": "neither cosign nor gh",
    "hooks/run-spill-guard.cmd": "spill-guard: blocked",
}

# Each channel, the install commands that only work if it ships, and the
# `.goreleaser.yaml` keys that would make it ship. `{p}` is project_name.
CHANNELS = (
    ("a Homebrew tap", ("brews", "homebrew_casks"),
     (r"brew\s+install\s+\S*{p}\b", r"brew\s+tap\s+[\w.-]+/[\w.-]+")),
    ("a Scoop bucket", ("scoops",),
     (r"scoop\s+install\s+\S*{p}\b", r"scoop\s+bucket\s+add\s+[\w.-]+")),
    ("winget", ("winget",), (r"winget\s+install\s+\S*{p}\b",)),
    ("Chocolatey", ("chocolateys",), (r"choco(?:latey)?\s+install\s+\S*{p}\b",)),
    ("a Linux package", ("nfpms",),
     (r"(?:apt(?:-get)?|dnf|yum|zypper)\s+install\s+\S*{p}\b",)),
    ("Nix", ("nix",), (r"nix(?:-env)?\s+\S*\s+\S*{p}\b",)),
    ("the AUR", ("aurs",), (r"(?:yay|paru|pacman)\s+-S\S*\s+\S*{p}\b",)),
    ("a snap", ("snapcrafts",), (r"snap\s+install\s+\S*{p}\b",)),
    ("krew", ("krews",), (r"kubectl\s+krew\s+install\s+\S*{p}\b",)),
)

GO_INSTALL = re.compile(r"go\s+install\s+(\S+?)(?:@\S+)?(?=[\s`'\"]|$)")

MODULE_LINE = re.compile(r"^module\s+(\S+)", re.M)

# Single- and double-quoted runs. Both shells escape a quote by leaving the
# string and re-entering it, so a run that ends early only ever splits one
# literal into two, which changes no answer below.
LITERAL = re.compile(r"'([^']*)'|\"([^\"]*)\"")

TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):", re.M)


def release_config():
    """The top-level keys of .goreleaser.yaml, and project_name.

    Read as keys at column zero rather than through a YAML parser: the question
    is only which blocks are present, `action-pins` already owns the case where
    a real parse matters, and `yaml` is not importable on a machine that
    satisfies `make doctor`.
    """
    if not GORELEASER.is_file():
        sys.exit(f"channel-claims: {GORELEASER.relative_to(ROOT)} is missing, "
                 f"so there is nothing to read the shipped channels from and a "
                 f"pass would mean nothing")
    text = GORELEASER.read_text(encoding="utf-8")
    keys = set(TOP_LEVEL_KEY.findall(text))
    name = re.search(r"^project_name:\s*(\S+)", text, re.M)
    if name is None:
        sys.exit(f"channel-claims: {GORELEASER.relative_to(ROOT)} names no "
                 f"project_name, so no pattern below could be bound to this "
                 f"project and every one of them would match nothing")
    return keys, name.group(1)


def module_path():
    """The module path, which is what a `go install` has to name to be ours."""
    found = re.search(r"^module\s+(\S+)", GOMOD.read_text(encoding="utf-8"), re.M)
    if found is None:
        sys.exit("channel-claims: go.mod names no module")
    return found.group(1)


def emitted(path, comment_markers):
    """Every string literal on a line that is not a comment, with its line."""
    out = []
    for number, line in enumerate((ROOT / path).read_text(encoding="utf-8")
                                  .splitlines(), 1):
        stripped = line.lstrip()
        if any(stripped.startswith(m) for m in comment_markers):
            continue
        for single, double in LITERAL.findall(line):
            out.append((number, single or double))
    return out


def findings(keys, project, module):
    out = []
    for path, markers in EMITTERS.items():
        literals = emitted(path, markers)
        if not any(MUST_SEE[path] in text for _, text in literals):
            sys.exit(f"channel-claims: nothing read out of {path} contains "
                     f"{MUST_SEE[path]!r}, so the reader is not seeing the "
                     f"strings this checks and a clean result would mean "
                     f"nothing")
        for line, text in literals:
            for channel, required, patterns in CHANNELS:
                if keys.intersection(required):
                    continue
                for pattern in patterns:
                    found = re.search(pattern.format(p=re.escape(project)),
                                      text, re.I)
                    if found:
                        out.append((path, line, found.group(0), channel,
                                    required[0]))
            for found in GO_INSTALL.finditer(text):
                named = found.group(1)
                if (named.rsplit("/", 1)[-1] == project
                        and not named.startswith(module + "/")
                        and named != module):
                    out.append((path, line, found.group(0), named, None))
    return out


def main():
    keys, project = release_config()
    module = module_path()
    shipped = sorted(k for _, required, _ in CHANNELS
                     for k in required if k in keys)
    print(f"channel-claims: .goreleaser.yaml ships "
          f"{', '.join(shipped) if shipped else 'no package channel'}; "
          f"`go install {module}` always works", flush=True)

    hits = findings(keys, project, module)
    if not hits:
        print(f"channel-claims: nothing {len(EMITTERS)} emitting file(s) print "
              f"names a channel that does not exist")
        return 0

    for path, line, command, channel, key in hits:
        detail = (f"{channel} does not exist: .goreleaser.yaml carries no "
                  f"`{key}:` block"
                  if key else
                  f"{channel} is not this project -- go.mod says {module}")
        print(f"absent channel: {path}:{line}: {command!r} -- {detail}",
              file=sys.stderr)
    print(f"\nchannel-claims: {len(hits)} message(s) name a channel that does "
          f"not exist. A person reads these at the moment they are stuck, "
          f"which is the worst moment to be sent somewhere that 404s.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
