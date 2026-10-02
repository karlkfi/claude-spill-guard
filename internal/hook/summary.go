package hook

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
// The generation appendCoverage rotated out is read as well, oldest first.
// Without it a report taken just after a rotation covers a few records and
// reads as a machine whose gaps went away.
//
// --file narrows the report to one file and --since to the records written at
// or after a moment, so a gap already reported, or closed by a later release,
// stops being counted again.
//
// Exit 0 on an absent log: a machine that has had no coverage failure is the
// good case, not an error. A file named by --file is not that case, since
// somebody asked for it, and its absence exits 1.
func Summarize(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "read only this `log`: a bare name is looked up in the state directory, anything else is a path")
	sinceArg := fs.String("since", "", "count only records written at or after this `time` (2006-01-02, 2006-01-02T15:04, or RFC 3339; local time unless it says otherwise)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%sunexpected argument %q\n", noticeLead, fs.Arg(0))
		return 2
	}
	var since time.Time
	if *sinceArg != "" {
		var ok bool
		if since, ok = parseSince(*sinceArg); !ok {
			fmt.Fprintf(stderr, "%s--since %q is not a time this reads: use 2006-01-02, "+
				"2006-01-02T15:04, or RFC 3339\n", noticeLead, *sinceArg)
			return 2
		}
	}

	path, err := CoveragePath()
	if err != nil {
		fmt.Fprintf(stderr, "%sthe state directory could not be resolved: %v\n", noticeLead, err)
		return 1
	}
	paths := []string{path + ".1", path}
	if *file != "" {
		paths = []string{*file}
		if !strings.ContainsAny(*file, `/\`) {
			paths[0] = filepath.Join(filepath.Dir(path), *file)
		}
	}

	t := tally{counts: map[string]int{}, since: since}
	var read []string
	for _, p := range paths {
		ok, err := t.add(p)
		if err != nil {
			fmt.Fprintf(stderr, "%sthe coverage log could not be read: %v\n", noticeLead, err)
			return 1
		}
		if ok {
			read = append(read, p)
		}
	}
	if len(read) == 0 {
		if *file != "" {
			fmt.Fprintf(stderr, "%sno coverage log at %q\n", noticeLead, paths[0])
			return 1
		}
		fmt.Fprintf(stdout, "No coverage log at %q.\n\n"+
			"Nothing this scanner could not read has been recorded on this "+
			"machine. That is the good case: every call either scanned or "+
			"found something.\n", path)
		return 0
	}

	fmt.Fprintf(stdout, "%s\n\n", strings.Join(read, "\n"))
	if t.earlier > 0 {
		fmt.Fprintf(stdout, "%d record(s) before %s left out.\n\n",
			t.earlier, since.Local().Format(time.DateTime))
	}
	if t.total == 0 {
		if t.earlier > 0 {
			fmt.Fprint(stdout, "Nothing was recorded since then.\n")
			return 0
		}
		fmt.Fprint(stdout, "The log is empty.\n")
		return 0
	}
	fmt.Fprintf(stdout, "%d call(s) this scanner could not read, %s to %s.\n\n",
		t.total, t.first.Local().Format(time.DateOnly), t.last.Local().Format(time.DateOnly))

	type row struct {
		reason string
		n      int
	}
	rows := make([]row, 0, len(t.counts))
	for r, n := range t.counts {
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
		fmt.Fprintf(stdout, "  %6d  (%4.1f%%)  %s\n", r.n, 100*float64(r.n)/float64(t.total), r.reason)
	}
	if t.unparsed > 0 {
		fmt.Fprintf(stdout, "\n%d line(s) did not parse, which is what a rotation "+
			"mid-write leaves behind.\n", t.unparsed)
	}
	fmt.Fprint(stdout, "\nEach of these is a call that proceeded with nothing "+
		"scanned. They are not findings: a rule that matched would have stopped "+
		"the call and is not written here.\n")
	return 0
}

// tally accumulates records across the log's generations.
type tally struct {
	counts                   map[string]int
	total, unparsed, earlier int
	first, last              time.Time
	since                    time.Time // zero counts everything
}

// add counts the records in one generation, reporting false for a file that
// does not exist.
func (t *tally) add(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close() //nolint:errcheck // read-only

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
			t.unparsed++
			continue
		}
		if c.Time.Before(t.since) {
			t.earlier++
			continue
		}
		t.total++
		t.counts[class(c.Reason)]++
		if t.first.IsZero() || c.Time.Before(t.first) {
			t.first = c.Time
		}
		if c.Time.After(t.last) {
			t.last = c.Time
		}
	}
	if err := s.Err(); err != nil {
		return true, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

// parseSince reads --since. A form with no zone is local time, because the
// report prints its dates in local time and a bound should read the same way.
func parseSince(v string) (time.Time, bool) {
	if ts, err := time.Parse(time.RFC3339, v); err == nil {
		return ts, true
	}
	for _, layout := range []string{time.DateOnly, "2006-01-02T15:04", "2006-01-02T15:04:05", time.DateTime} {
		if ts, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
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
