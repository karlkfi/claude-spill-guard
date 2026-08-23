#!/usr/bin/env python3
"""Known vulnerabilities in whatever the binary links, from govulncheck.

With no third-party dependencies this is mostly reporting advisories against
the standard library, which is exactly the class that otherwise goes unnoticed
in a binary nobody rebuilds between releases. `no-deps` proves the graph is
stdlib-only; it says nothing about that stdlib being current.

govulncheck is pinned in tools/go.mod like the other tools the gates run, so
this never installs anything: it is built at the pinned version from a module
the shipped binary's graph does not reach. `-C ..` points it at the root module
from inside tools/, which is the only way to have both the pinned tool and the
module under test.

**It is built and then run, rather than `go run`.** `go run` does not propagate
its child's exit status: it reports 1 for any non-zero exit and writes the real
one to stderr as `exit status 3`. govulncheck's whole contract is in that code,
so under `go run` a found vulnerability is indistinguishable from the tool
failing -- and this script would have called a real advisory a network problem,
which is the one mistake it exists to prevent. Measured 2026-08-23 by driving
the mutation control below: `go run` returned 1 while govulncheck had exited 3.

**This is the one gate here whose oracle is the network.** It reads the
vulnerability database at vuln.go.dev, so it can fail for a reason that has
nothing to do with this tree -- and scripts/README.md argues against exactly
that shape for the vendor-freshness check. It is worth it here because the
answer genuinely lives off the machine and cannot be cached into the
repository. What it must not do is report a third party being down as though
it had found something, so the two exits are told apart and named.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"

# govulncheck's own contract: 0 clean, 3 vulnerabilities found, anything else
# is the tool failing rather than an answer about the code.
CLEAN, FOUND = 0, 3


def main():
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "govulncheck"
        build = subprocess.run(
            ("go", "build", "-o", str(binary), "golang.org/x/vuln/cmd/govulncheck"),
            cwd=TOOLS, capture_output=True, text=True, check=False)
        if build.returncode != 0:
            print(build.stderr.strip(), file=sys.stderr)
            print(f"\nvulns: govulncheck did not build from tools/, so nothing "
                  f"below could have run. It is pinned in tools/go.mod.",
                  file=sys.stderr)
            return 1
        result = subprocess.run((str(binary), "-C", str(ROOT), "./..."),
                                capture_output=True, text=True, check=False)
    output = (result.stdout + result.stderr).strip()

    if result.returncode == CLEAN:
        print("vulns: govulncheck reports no vulnerability the build graph calls")
        return 0
    if result.returncode == FOUND:
        print(output, file=sys.stderr)
        print("\nvulns: govulncheck found a vulnerability this code calls.",
              file=sys.stderr)
        return 1
    print(output, file=sys.stderr)
    print(f"\nvulns: govulncheck exited {result.returncode}, which is neither "
          f"clean ({CLEAN}) nor a finding ({FOUND}) -- so this is the tool "
          f"failing, not an answer about the code. Its database is at "
          f"vuln.go.dev and it is the one gate here that needs the network.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
