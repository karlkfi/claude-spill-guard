// Command spill-guard scans local content for secrets and PII before a Claude
// Code session can send it to the API.
//
// The design is in docs/design/README.md. `hook` and `version` are
// implemented; the scan, selftest and rules subcommands land with the rows
// that specify them.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/karlkfi/claude-spill-guard/internal/hook"
)

// version is overridden at release time with -ldflags -X.
var version = "dev"

const usage = `usage: spill-guard <command>

commands:
  hook      scan a Claude Code hook payload read from stdin
  version   print the version and exit
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run returns the process exit code. Anything it does not recognise exits
// non-zero: a scanner that shrugs at an argument it does not understand is one
// that reports a safety it is not providing.
//
// Exit 2 is what the launcher's own mismatch lands on. hooks.json chooses the
// subcommand and this binary decides whether it knows it, so a launcher paired
// with a binary that does not answer `hook` blocks with a reason on stderr
// rather than passing the call through.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "hook":
		return hook.Run(stdin, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		// %q escapes C0, DEL and the bidi overrides, which is required of every
		// string this binary emits -- stderr reaches both a terminal and the API.
		fmt.Fprintf(stderr, "spill-guard: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
