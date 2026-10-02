// Package filter is the `filter` subcommand: the shipped ruleset over a
// command's output, run as the last stage of the pipeline that produces it.
//
// It exists for the one reader whose input cannot be opened ahead of the call.
// A recursive grep over a directory reads a file set only the walk itself
// decides -- .gitignore, --include, --exclude, symlinks -- and the hook refuses
// to re-implement that walk (docs/design/README.md, "A directory operand is
// refused rather than walked"). What crosses is grep's output, and that is a
// buffer: so the hook denies the bare form and names this one, and the scan
// happens where the bytes actually are.
//
// It is the more precise reading as well as the possible one. `grep -rn 'func
// foo' .` sends only the lines matching `func foo`, so a planted key elsewhere
// in the tree does not block it, where a walk would block every recursive grep
// in a repository that carries a fixture.
//
// The verdict is the hook's: a finding blocks. Nothing is written to stdout,
// the rule and the output line go to stderr, and the exit status is blocked,
// which `set -o pipefail` carries out of the pipeline because nothing grep
// returns can collide with it. `--redact` is the exception a session asks for
// by name, for the case where it needs the rest of the output and has no better
// way to get it; it writes the output with each value replaced by the rule
// that matched it, and says so on stderr.
//
// The whole stream is read before a byte is written. A block has to withhold
// everything, so it cannot have started writing, and the ruleset has rules
// that span lines -- a PEM header and the body after it -- which a line-at-a-
// time pass would never see whole. Redaction keeps the same shape rather than
// a second, streaming one, so the two modes cannot disagree about what they
// matched.
package filter

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	"github.com/karlkfi/claude-spill-guard/internal/scan"
	embedded "github.com/karlkfi/claude-spill-guard/rules"
)

// The exit statuses. grep's own are 0, 1 and 2, so under `set -o pipefail` a
// pipeline ending here reports grep's status when this exits 0 and one of
// these otherwise -- and neither of these is a status grep can produce.
const (
	// Blocked is a finding, or output this could not read: either way nothing
	// was written to stdout.
	Blocked = 3
	// Failed is this subcommand unable to run at all -- an unknown flag, a read
	// error, a ruleset that does not load. Nothing was written to stdout.
	Failed = 4
)

const usage = "usage: spill-guard filter [--redact]\n"

// The label a finding is reported against. Output has no path; the line number
// is what a reader can act on, and it is computed here rather than carried.
const label = "<stdin>"

// Run reads stdin whole, scans it, and writes it to stdout when nothing matched.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	redact := false
	for _, arg := range args {
		switch arg {
		case "--redact":
			redact = true
		default:
			// %q for the reason main.go gives: this reaches a terminal and the
			// API, and the argument came from the call.
			fmt.Fprintf(stderr, "spill-guard filter: unknown argument %q\n%s", arg, usage)
			return Failed
		}
	}

	buf, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "spill-guard filter: reading stdin: %v. Nothing was written.\n", err)
		return Failed
	}
	set, err := rules.Load(embedded.Shipped)
	if err != nil {
		fmt.Fprintf(stderr, "spill-guard filter: loading the compiled-in ruleset: %v. "+
			"Nothing was written.\n", err)
		return Failed
	}

	// The raw pass, because `grep -a` writes a file's bytes NUL and all, and
	// those bytes are what crosses -- the same argument that put a prompt's
	// binary `@` target on it in internal/hook.
	got, err := scan.BufferIncludingBinary(label, buf, set)
	if err != nil {
		fmt.Fprintf(stderr, "spill-guard filter: %v. Nothing was written.\n", err)
		return Failed
	}
	if got.Skipped != scan.Scanned && got.Skipped != scan.ScannedRaw {
		// The hook can defer on a buffer it could not read, because the call it
		// lets through is one nothing asked it about. This was asked by name, and
		// the only power it has is to withhold, so passing unread bytes through
		// would be reporting a scan that did not happen.
		fmt.Fprintf(stderr, "spill-guard filter: blocked. This output could not be "+
			"read (%s), so it was not written. Narrow the search, or name the files "+
			"to read instead.\n", got.Skipped)
		return Blocked
	}
	if len(got.Findings) == 0 {
		stdout.Write(buf)
		return 0
	}

	if redact {
		// A redaction marker is ASCII. Written into output this decoded from
		// UTF-16 it would corrupt the stream around it rather than replace one
		// value, so a declared encoding blocks instead.
		if bytes.HasPrefix(buf, []byte{0xFF, 0xFE}) || bytes.HasPrefix(buf, []byte{0xFE, 0xFF}) {
			fmt.Fprintf(stderr, "spill-guard filter: blocked. %s It was not redacted, "+
				"because this output declares a UTF-16 encoding and a marker would "+
				"corrupt it. Nothing was written.\n", listed(buf, got.Findings))
			return Blocked
		}
		stdout.Write(redacted(buf, got.Findings))
		fmt.Fprintf(stderr, "spill-guard filter: redacted. %s Each value was replaced "+
			"by a marker naming its rule; what you read is not the file's content "+
			"there, so do not write it back.\n", listed(buf, got.Findings))
		return 0
	}

	fmt.Fprintf(stderr, "spill-guard filter: blocked. %s Nothing was written, and the "+
		"values are not repeated here, because this text reaches the API as well. "+
		"`grep -rl` lists the files a pattern matches without their content, and "+
		"`--exclude` keeps a file out of the search. If you need the rest of this "+
		"output and there is no better way to get it, `spill-guard filter "+
		"--redact` writes it with each value replaced.\n", listed(buf, got.Findings))
	return Blocked
}

// maxListed caps how many matches a message names, as internal/hook's does.
const maxListed = 5

// listed names each finding by rule and output line. No fragment and no byte
// window, for the reason scan.Finding gives.
func listed(buf []byte, findings []scan.Finding) string {
	items := make([]string, 0, maxListed+1)
	for i, f := range findings {
		if i == maxListed {
			items = append(items, fmt.Sprintf("and %d more", len(findings)-maxListed))
			break
		}
		line := bytes.Count(buf[:f.Offset], []byte{'\n'}) + 1
		// %q for the rule id: it comes out of a JSON file and reaches a terminal.
		items = append(items, fmt.Sprintf("%q on line %d", f.RuleID, line))
	}
	return fmt.Sprintf("%d rule match(es) in this output: %s.", len(findings),
		strings.Join(items, "; "))
}

// redacted returns buf with each finding's span replaced by a marker.
//
// Overlapping spans -- two rules over one value -- are merged and take the
// first rule's name, so no byte of either survives.
func redacted(buf []byte, findings []scan.Finding) []byte {
	spans := append([]scan.Finding(nil), findings...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].Offset < spans[j].Offset })
	var out bytes.Buffer
	at := 0
	for _, f := range spans {
		if f.End <= at {
			continue
		}
		if f.Offset >= at {
			out.Write(buf[at:f.Offset])
			fmt.Fprintf(&out, "[spill-guard redacted: %s]", f.RuleID)
		}
		at = f.End
	}
	out.Write(buf[at:])
	return out.Bytes()
}
