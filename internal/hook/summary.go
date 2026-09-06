package hook

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Summarize reads the coverage log and reports what this scanner could not
// read, commonest first.
//
// The log is written so that somebody can act on it, and a file of one JSON
// record per call is not that -- the reasons repeat with a different path each
// time, so the shape a reader needs is the count per class. That grouping is
// the whole of what this adds.
//
// Exit 0 on an absent log: a machine that has had no coverage failure is the
// good case, not an error.
func Summarize(stdout, stderr io.Writer) int {
	path, err := CoveragePath()
	if err != nil {
		fmt.Fprintf(stderr, "%sthe state directory could not be resolved: %v\n", noticeLead, err)
		return 1
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stdout, "No coverage log at %q.\n\n"+
				"Nothing this scanner could not read has been recorded on this "+
				"machine. That is the good case: every call either scanned or "+
				"found something.\n", path)
			return 0
		}
		fmt.Fprintf(stderr, "%sthe coverage log could not be read: %v\n", noticeLead, err)
		return 1
	}
	defer f.Close() //nolint:errcheck // read-only

	counts := map[string]int{}
	total, unparsed := 0, 0
	var first, last time.Time
	s := bufio.NewScanner(f)
	// A reason can be long; the default 64 KiB token is not guaranteed to hold
	// one with a deep path in it.
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var c coverage
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			// A truncated last line is what a rotation mid-write leaves, so
			// this is counted and reported rather than being fatal.
			unparsed++
			continue
		}
		total++
		counts[class(c.Reason)]++
		if first.IsZero() || c.Time.Before(first) {
			first = c.Time
		}
		if c.Time.After(last) {
			last = c.Time
		}
	}
	if err := s.Err(); err != nil {
		fmt.Fprintf(stderr, "%sthe coverage log could not be read to the end: %v\n", noticeLead, err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\n\n", path)
	if total == 0 {
		fmt.Fprint(stdout, "The log is empty.\n")
		return 0
	}
	fmt.Fprintf(stdout, "%d call(s) this scanner could not read, %s to %s.\n\n",
		total, first.Local().Format(time.DateOnly), last.Local().Format(time.DateOnly))

	type row struct {
		reason string
		n      int
	}
	rows := make([]row, 0, len(counts))
	for r, n := range counts {
		rows = append(rows, row{r, n})
	}
	// Count descending, then the reason, so two runs over one log agree.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].reason < rows[j].reason
	})
	for _, r := range rows {
		fmt.Fprintf(stdout, "  %6d  (%4.1f%%)  %s\n", r.n, 100*float64(r.n)/float64(total), r.reason)
	}
	if unparsed > 0 {
		fmt.Fprintf(stdout, "\n%d line(s) did not parse, which is what a rotation "+
			"mid-write leaves behind.\n", unparsed)
	}
	fmt.Fprint(stdout, "\nEach of these is a call that proceeded with nothing "+
		"scanned. They are not findings: a rule that matched would have stopped "+
		"the call and is not written here.\n")
	return 0
}

// class reduces a reason to the group a reader counts by.
//
// There are two quote levels and only the inner one may be elided. A composed
// reason reads
//
//	... could not be completed: "in the \"cat\" here, a file operand is a glob ...".
//
// The outer span is the specific reason and is the whole of what distinguishes
// one gap from another; the inner span is the command name, which is what
// makes 500 records group into 500 classes. Eliding the outer one was the
// first version of this and it reported every coverage failure on the machine
// as a single class -- caught by driving the subcommand rather than by a test,
// because the grouping was self-consistently wrong.
func class(reason string) string {
	var b strings.Builder
	runes := []rune(reason)
	inner := false
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		// An escaped quote opens or closes the inner span.
		if r == '\\' && i+1 < len(runes) && runes[i+1] == '"' {
			i++
			inner = !inner
			if inner {
				b.WriteString(`"…"`)
			}
			continue
		}
		if inner {
			continue
		}
		// A bare quote is an outer delimiter: drop the mark, keep the content.
		if r == '"' {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(bare.ReplaceAllString(b.String(), `"…"`))
}

// bare matches a path that is not inside quotes, which the elision above
// cannot reach.
//
// Two of the three coverage bodies quote what they name and one does not:
// unread() builds its list through listSkips, which writes the path plain. So
// fourteen records of the same shape over fourteen temp files grouped as
// fourteen classes, which is the grouping bug again in the one body the first
// fix did not cover -- found by running the subcommand over a real log rather
// than by a test, twice now.
//
// Eliding at the reader rather than quoting at the source is deliberate. The
// bodies are user-visible strings with tests pinning their wording, and a
// class function that only works for reasons written a particular way is the
// thing that just failed twice. This copes with a path however it arrives.
var bare = regexp.MustCompile(`(?:[A-Za-z]:\\|/)[^\s,;:()"]*(?:[/\\][^\s,;:()"]*)+`)
