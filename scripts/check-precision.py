#!/usr/bin/env python3
"""Run the precision corpus and prove it ran.

The corpus gate is the deliverable Q7 said mattered most, and the failure mode
it has to survive is its own: a gate that pins a false-positive count at zero
is worth nothing if it cannot produce anything else. Two ways this one could
report a vacuous zero, and neither shows up in an exit status:

  * `go test -run` exits **0** when the pattern matches no test. Renaming a test
    function, or moving it to another package, retires it in silence -- so the
    names are listed here and every one of them has to report a result.
  * a walk over an empty corpus finds nothing to flag. That half is asserted
    inside the tests, which carry floors on file count and bytes, and it is
    named here so a reader knows where it lives.

`-count=1` because a cached result is a reading of a tree that is no longer the
one on disk, and the corpus is data rather than code: the fixtures can change
under a test binary that did not.

The measured lines each test logs -- corpus size, findings, what the inherited
rules still report on the clean half -- are printed on success as well as on
failure. A gate whose numbers are visible only when it breaks is a gate nobody
watches move.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "./internal/scan"

# Every test the corpus gate is. Listed rather than matched on a prefix,
# because a prefix pattern that stops matching is the silence this exists to
# refuse -- and a name that has gone away has to be a failure here rather than
# one fewer line of output.
TESTS = (
    "TestCorpusIsBigEnoughToMeanSomething",
    "TestShippedRulesetFlagsNothingInTheCleanCorpus",
    "TestCleanCorpusWouldFlagUnderTheInheritedRules",
    "TestEveryPlantedSecretIsFoundExactlyOnce",
    "TestEveryEnabledRuleHasAPlantedFile",
    "TestNumericPIIFamilyShipsDisabled",
)

RESULT = re.compile(r"^\s*--- (PASS|FAIL|SKIP): (\w+)", re.M)
# What the tests log: `    corpus_test.go:152: clean: 10 files, ...`
MEASURED = re.compile(r"^\s+corpus_test\.go:\d+: (.*)$", re.M)


def main():
    pattern = "^(" + "|".join(TESTS) + ")$"
    done = subprocess.run(
        ("go", "test", "-count=1", "-v", "-run", pattern, PACKAGE),
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    log = done.stdout + done.stderr
    print(log, end="" if log.endswith("\n") else "\n")

    reported = {name: verdict for verdict, name in RESULT.findall(log)}
    failures = []
    for name in TESTS:
        verdict = reported.get(name)
        if verdict is None:
            failures.append(f"{name} reported no result -- `go test -run` exits 0 "
                            f"when it matches nothing, so a renamed or moved test "
                            f"retires itself in silence")
        elif verdict != "PASS":
            failures.append(f"{name}: {verdict}")
    if done.returncode != 0 and not failures:
        failures.append(f"`go test` exited {done.returncode} with every named test "
                        f"passing, so something outside them failed -- read the log "
                        f"above")

    for failure in failures:
        print(f"precision: {failure}", file=sys.stderr)
    if failures:
        print(f"\n{len(failures)} precision problem(s). The corpus gate is the "
              f"only thing that sees a precision regression: nobody reports "
              f"noise, they stop reading the output.", file=sys.stderr)
        return 1

    print(f"precision: {len(TESTS)} corpus tests, all reported and all passed")
    for line in MEASURED.findall(log):
        print(f"precision:   {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
