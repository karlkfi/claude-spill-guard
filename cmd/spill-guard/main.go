// Command spill-guard scans local content for secrets and PII before a Claude
// Code session can send it to the API.
//
// The design is in docs/design/README.md. Only `version` is implemented; the
// hook, scan, selftest and rules subcommands land with the pipeline.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is overridden at release time with -ldflags -X.
var version = "dev"

const usage = `usage: spill-guard <command>

commands:
  version   print the version and exit
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run returns the process exit code. Anything it does not recognise exits
// non-zero: a scanner that shrugs at an argument it does not understand is one
// that reports a safety it is not providing.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
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
