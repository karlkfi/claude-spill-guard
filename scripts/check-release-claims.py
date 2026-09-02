#!/usr/bin/env python3
"""Keep the prose agreeing with whether a release exists.

The defect this exists for shipped three times and was caught three times by a
reader. `docs/design/distribution.md` said the cosign signature and the build
provenance attestation "are already published by the release workflow", and
`gh release list` returns nothing: there is no release, so nothing has been
published by anything. Two more of the same shape were written and fixed by
hand during Q12. Every one of the gates was green through all of it, because
none of them reads whether a release exists.

**The instrument is the release state, not the configuration.** `.goreleaser.yaml`
carrying a `signs:` block says a release *would* sign; it says nothing about one
having happened. That is the fault line, and it is sharper than "check the
tense": a claim about a file in the tree is verifiable now, a claim about what a
release published is not. `distribution.md` carries two **This is built.**
blocks and only one was ever wrong -- the clean one names files, the broken one
named outcomes -- so a check keyed on release words alone flags both and is
worth nothing.

**Two directions, because the fact flips.** While no release exists, prose must
not claim in completed aspect that a release produced something. Once one does,
every "there is no release yet" in the tree is stale -- four of them today, in
README.md twice, `distribution.md` and `docs/releases/README.md` -- and that
direction is the one nobody will otherwise notice, since it goes wrong on the
busiest day this repository will have.

**What it does not reach, stated rather than implied.** The first Q12 instance
read "the two-step form above has something to fetch". It names no artifact and
uses no completion marker, so nothing below fires on it; the sentence is a claim
about a release only to a reader who knows what the two-step form fetches. This
catches the decidable core and leaves that one where the row left the
overstated-guarantee family: a reader's job. A floor, not a census.

**The lexicons are hand-written, and that is the right call here.** Q105's
channel list must come from `.goreleaser.yaml`, because the tree holds the
answer and a hand-kept copy would drift from it. This is the other shape: the
tree holds the *state*, which is read, and what is written down is how English
spells a completed claim. That does not drift when the repository changes.
Precision measured 2026-09-01 over every tracked `*.md` outside the exclusions
below: one hit, the defect. The inverse lexicon: four hits, all four real.

Exclusions, each for a different reason. `docs/queue/` quotes defects as
exhibits -- the row this was written for carried the broken sentence verbatim,
and the `docs` gate has the same problem with broken links, which is what
`exhibit:` is for there. `docs/postmortems/` is a dated record of what was true
when it was written, so going stale is what it is for. `testdata/` is scanner
input.

Needs the network, like `vulns` and for the same reason: the answer genuinely
lives off this machine. And like `vulns` it must never report a read it could
not take as an answer about the prose, so an unreadable state exits saying so
rather than assuming either direction.
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_PREFIXES = ("docs/queue/", "docs/postmortems/", "testdata/")

# A completed-aspect claim: a marker of something having happened, then a verb
# of release production within the same clause. The 40-character window is what
# keeps "already" in one sentence from reaching a participle in the next clause
# of a long one.
COMPLETED = re.compile(
    r"\b(?:already|has been|have been|was|were|is now|are now)\b"
    r"[^.]{0,40}?\b"
    r"(?:published|uploaded|signed|released|attached|minted|shipped)\b",
    re.I)

# What the claim has to be about. Without this, "the ruleset is now compiled in"
# is a finding.
RELEASE_REF = re.compile(
    r"\b(?:release|artifact|asset|archive|checksums\.txt|signature"
    r"|attestation|provenance)\b", re.I)

# Anything that makes the sentence conditional, future or negated. "taken once a
# draft is published" is the shape this exists for: three sentences in the tree
# carry a publication verb in a subordinate clause and assert nothing.
HEDGE = re.compile(
    r"\b(?:will|would|once|until|when|after|before|if|unless|should|could"
    r"|may|might|not|no|none|never|yet)\b", re.I)

# Existential claims that no release exists. Spelled tightly on purpose: a
# looser `no release` also matches "artifacts served from a loopback port carry
# no release provenance", which is about a rehearsal and not about the state.
DENIED = re.compile(
    r"(?:there is no release|there are no releases|no release (?:yet|exists|has been)"
    r"|there is none yet|there has never been a release|is a 404 today"
    r"|with the first release and not before)", re.I)

SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z*`\[])")


def prose_files():
    """Tracked markdown, minus the trees that quote or date their claims.

    Empty is an exit rather than a shorter list. A gate whose passing answer is
    already an empty one cannot also treat "nothing to read" as a pass: the two
    print the same line.
    """
    listed = subprocess.run(("git", "ls-files", "*.md"), cwd=ROOT,
                            capture_output=True, text=True, check=False)
    if listed.returncode != 0:
        sys.exit(f"release-claims: `git ls-files` exited {listed.returncode}, "
                 f"so nothing below could have been read.\n"
                 f"{listed.stderr.strip()}")
    found = [p for p in listed.stdout.split() if not p.startswith(SKIP_PREFIXES)]
    if not found:
        sys.exit("release-claims: no tracked markdown outside "
                 f"{', '.join(SKIP_PREFIXES)}, so this read nothing and a pass "
                 f"would mean nothing")
    return found


def sentences(path):
    """Every sentence in a file, with the line its paragraph starts on.

    Paragraphs are flattened first because the prose here hard-wraps at 79
    columns, so a claim is split across lines far more often than not. No fence
    handling: both lexicons need an English aspect marker beside a release
    referent, which no command line in this tree carries.
    """
    text = (ROOT / path).read_text(encoding="utf-8")
    for para in re.finditer(r"[^\n]+(?:\n[^\n]+)*", text):
        # Flatten, keeping each kept character's offset in the file, so a
        # finding names the line the sentence starts on rather than the line
        # its paragraph does. The two are six apart in the instance this was
        # written for.
        flat, offsets = [], []
        for word in re.finditer(r"\S+", para.group(0)):
            if flat:
                flat.append(" ")
                offsets.append(word.start())
            flat.append(word.group(0))
            offsets.extend(range(word.start(), word.end()))
        flat = "".join(flat)

        start = 0
        for sentence in SENTENCE.split(flat):
            at = para.start() + offsets[start]
            yield text.count("\n", 0, at) + 1, sentence
            start = flat.index(sentence, start) + len(sentence)


def release_state(forced):
    """Whether a release exists, and what answered.

    `gh release list` first: it is the only reader that sees a draft, and a
    draft publishes no assets, so a tag alone is the wrong answer for prose
    about what a user can download. `git ls-remote --tags` is the fallback for a
    machine without `gh`, which is not in the required tool tier.
    """
    if forced:
        return forced == "released", f"forced to {forced} by --assume-release"

    if shutil.which("gh"):
        done = subprocess.run(
            ("gh", "release", "list", "--limit", "1"),
            cwd=ROOT, capture_output=True, text=True, check=False)
        if done.returncode == 0:
            return bool(done.stdout.strip()), "`gh release list`"

    done = subprocess.run(("git", "ls-remote", "--tags", "origin", "v*"),
                          cwd=ROOT, capture_output=True, text=True, check=False)
    if done.returncode == 0:
        return bool(done.stdout.strip()), "`git ls-remote --tags origin 'v*'`"

    return None, done.stderr.strip() or "both reads failed"


def findings(released, paths):
    """Every sentence disagreeing with the state, in file order."""
    out = []
    for path in paths:
        for line, sentence in sentences(path):
            if released:
                if DENIED.search(sentence):
                    out.append((path, line, "stale", sentence))
            elif (COMPLETED.search(sentence) and RELEASE_REF.search(sentence)
                    and not HEDGE.search(sentence)):
                out.append((path, line, "unbuilt", sentence))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--assume-release", choices=("none", "released"),
        help="skip the state read and assume this instead. For the mutation "
             "control, which cannot cut a release to drive the other arm.")
    args = parser.parse_args()

    released, instrument = release_state(args.assume_release)
    if released is None:
        print(f"release-claims: the release state could not be read -- "
              f"{instrument}. That is this check failing, not an answer about "
              f"the prose, so it reports neither direction. Like `vulns`, its "
              f"oracle is off this machine.", file=sys.stderr)
        return 1

    state = "a release exists" if released else "no release exists"
    print(f"release-claims: {state}, per {instrument}", flush=True)

    paths = prose_files()
    hits = findings(released, paths)
    if not hits:
        print(f"release-claims: no prose in {len(paths)} tracked files "
              f"disagrees")
        return 0

    for path, line, kind, sentence in hits:
        print(f"{kind} claim: {path}:{line}: {sentence}", file=sys.stderr)
    if released:
        print(f"\nrelease-claims: {len(hits)} sentence(s) say no release "
              f"exists, and one does. They were true when written and are not "
              f"now.", file=sys.stderr)
    else:
        print(f"\nrelease-claims: {len(hits)} sentence(s) claim a release "
              f"produced something, and there is no release. Say what the tree "
              f"holds, or write the claim in the future tense.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
