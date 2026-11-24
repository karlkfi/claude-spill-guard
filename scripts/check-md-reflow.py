#!/usr/bin/env python3
"""Hold the repo's Markdown to one sentence per source line, with mdreflow.

mdreflow is pinned in tools/go.mod and configured by .mdreflow.yaml. With no
argument this reflows every file in scope; `--check` writes nothing and exits 1
naming each file that would change.

Scope is every Markdown file git tracks or would track, less the symlinks and
less what .mdreflow.yaml excludes. The files are named to mdreflow rather than
left to its directory walk, which skips an excluded file without a word: named,
each one is refused aloud, so the pass line can say how many, and a file skipped
for any reason but the config is a failure.

A paragraph mdreflow declines to touch is reported and is not a failure. Its
reason code is mdreflow's own, and breaking that paragraph's lines by hand is
the remedy.
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
CONFIG = ".mdreflow.yaml"
PATTERNS = ("*.md", "*.mdx", "*.markdown")

# mdreflow's own contract: 0 clean, 1 something would change, 3 a named file
# refused. Anything else is the tool failing.
CLEAN, WOULD_CHANGE, REFUSED = 0, 1, 3

EXCLUDED_RE = re.compile(r"^(.+): skipped \(excluded by config\)$", re.M)
REFUSED_RE = re.compile(
    r"^.+: (?:skipped \(excluded by (?!config\)).*|refused: .*)$", re.M)
DECLINED_RE = re.compile(r"^.+:\d+(?:-\d+)?: skipped: .*$", re.M)


def markdown_files():
    listed = subprocess.run(
        ("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
         *PATTERNS), cwd=ROOT, capture_output=True, text=True, check=False)
    if listed.returncode != 0:
        sys.exit(f"md-reflow: `git ls-files` exited {listed.returncode}, so "
                 f"nothing below could have been read.\n{listed.stderr.strip()}")
    paths = sorted(set(filter(None, listed.stdout.split("\0"))))
    return [p for p in paths
            if (ROOT / p).is_file() and not (ROOT / p).is_symlink()]


def tool_failed(result):
    sys.exit(f"{(result.stdout + result.stderr).strip()}\n\nmd-reflow: mdreflow "
             f"exited {result.returncode}, which is neither clean nor a file "
             f"to reflow -- so this is the tool failing, not an answer about "
             f"the prose.")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="report what would change and write nothing")
    args = parser.parse_args()

    paths = markdown_files()
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "mdreflow"
        build = subprocess.run(
            ("go", "build", "-o", str(binary),
             "github.com/jbeda/mdreflow/cmd/mdreflow"),
            cwd=TOOLS, capture_output=True, text=True, check=False)
        if build.returncode != 0:
            sys.exit(f"{build.stderr.strip()}\n\nmd-reflow: mdreflow did not "
                     f"build from tools/, so nothing below could have run. It "
                     f"is pinned in tools/go.mod.")

        def mdreflow(*argv):
            return subprocess.run((str(binary), "--config", CONFIG, *argv),
                                  cwd=ROOT, capture_output=True, text=True,
                                  check=False)

        # A refusal's 3 masks a 1, so the excluded files are found first and
        # left out of the run whose exit code is the answer.
        probe = mdreflow("--check", "--", *paths)
        if probe.returncode not in (CLEAN, WOULD_CHANGE, REFUSED):
            tool_failed(probe)
        refused = REFUSED_RE.findall(probe.stderr)
        if refused:
            print("\n".join(refused), file=sys.stderr)
            print(f"\nmd-reflow: {len(refused)} file(s) skipped by something "
                  f"other than {CONFIG}, so nothing holds them to the "
                  f"convention.", file=sys.stderr)
            return 1
        excluded = set(EXCLUDED_RE.findall(probe.stderr))
        in_scope = [p for p in paths if p not in excluded]
        if not in_scope:
            print(f"md-reflow: no Markdown in scope -- {len(excluded)} file(s) "
                  f"excluded by {CONFIG}, so this read nothing and a pass would "
                  f"mean nothing", file=sys.stderr)
            return 1

        result = mdreflow("--explain", *(("--check",) if args.check else ()),
                          "--", *in_scope)

    if result.returncode == WOULD_CHANGE:
        print(result.stdout.strip(), file=sys.stderr)
        print("\nmd-reflow: the files above are not one sentence per line. "
              "`make md-reflow` rewrites them.", file=sys.stderr)
        return 1
    if result.returncode != CLEAN:
        tool_failed(result)
    declined = DECLINED_RE.findall(result.stderr)
    for entry in declined:
        print(entry)
    print(f"md-reflow: {len(in_scope)} file(s) are one sentence per line, "
          f"{len(declined)} paragraph(s) declined, {len(excluded)} file(s) "
          f"excluded by {CONFIG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
