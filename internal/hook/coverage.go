package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// A coverage failure is a call this scanner could not decide: an operand that
// will not resolve before the command runs, a buffer nothing could decode, a
// scan that ran out of budget. It is not a finding and it is not a refusal --
// it is the absence of a reading.
//
// Such a call defers. The hook writes no verdict at all, so the permission
// flow that would have run without this hook installed runs unchanged: an
// explicit allow would suppress the user's own rules, and this has no opinion
// to spend on them.
//
// It used to block, and the measurement is why it stopped. Over the week to
// 2026-09-05, across 100 sessions on one machine, 509 of 540 blocks (94.3%)
// were this class, and 49 of 69 confirmed confirmation prompts (71%) were too
// -- 47 of those 49 on the same reason, an operand carrying a `$`. After a
// coverage block the session got a clean call through within four attempts
// 99.2% of the time (505 of 509), reading the same tree by another route. So
// the block was not withholding the bytes. It was charging a turn, and then a
// person's attention, for a refusal the next call walked around.
//
// What replaces it is a record. A gap nobody can see is a gap nobody fixes,
// and the point of not prompting is that the prompt was never the thing that
// closed one.
type coverage struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	Tool   string    `json:"tool,omitempty"`
	Reason string    `json:"reason"`
}

// record writes one coverage failure to both sinks and reports nothing.
//
// Best-effort is the contract, not a shortcut. This runs on a call that is
// about to proceed, so a sink that is full, read-only or absent must not
// change the verdict -- turning a logging failure into a block would rebuild
// the friction this whole path exists to remove, and would do it on the
// machines least able to diagnose it.
func record(stderr io.Writer, call payload, event Event, reason string) {
	c := coverage{
		Time:   time.Now().UTC(),
		Event:  string(event),
		Reason: reason,
	}
	// ToolName is absent on UserPromptSubmit and optional everywhere, so the
	// field stays empty rather than inventing a name for the record.
	if call.ToolName != nil {
		c.Tool = *call.ToolName
	}
	// The opener is the plugin's own name at position 0, as on every other
	// string this package emits: a session runs several hooks and a line in a
	// transcript is attributable to none of them without it.
	//
	// stderr on exit 0 reaches neither the model nor the person -- which is
	// the property wanted here -- and the harness records it in the
	// hook_success attachment beside the invocation. That capture is Claude
	// Code's behaviour rather than this binary's, and it is thin: over 14 days
	// and 47,494 exit-0 hook runs on this machine, one carried non-empty
	// stderr, and that one was a probe driving this exact question. So it is
	// the free sink, never the only one.
	fmt.Fprintf(stderr, "%s%s\n", noticeLead, reason)
	appendCoverage(c)
}

// coverageCap is where the log rotates, per file. Two files are kept, so the
// store is bounded at twice this and needs no pruning by anything else.
//
// A scanner that fills a disk is a scanner that gets uninstalled, and the
// volume here is not hypothetical: the week measured above would have written
// on the order of 500 records, but the population that produces them is every
// unresolvable operand in every session, which is the busiest path this binary
// has.
const coverageCap = 4 << 20

// appendCoverage adds one line to the coverage log, rotating first if the file
// has reached the cap. Every error is dropped: see record.
func appendCoverage(c coverage) {
	dir, err := coverageDir()
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, "coverage.jsonl")
	// Rotation is a rename over the previous generation rather than a trim of
	// this one: truncating in place loses the oldest records, which are the
	// ones a coverage trend is read from.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= coverageCap {
		_ = os.Rename(path, path+".1")
	}
	// 0600 because the reasons name paths on this machine. They carry no
	// matched value -- a coverage failure is by definition a buffer nothing
	// read -- but a path is still somebody's directory layout.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck // best-effort; see record
	line, err := json.Marshal(c)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
}

// coverageDir resolves the state directory, XDG first and $HOME after it.
//
// os.UserConfigDir is not used: this is state a user may delete without
// changing how the binary behaves, which is the distinction XDG draws between
// state and config, and the log is regenerated on the next coverage failure.
func coverageDir() (string, error) {
	if x := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		return filepath.Join(x, "spill-guard"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "spill-guard"), nil
}

// CoveragePath reports where the log is written, for the `coverage`
// subcommand and for a person who wants to read it with anything else.
func CoveragePath() (string, error) {
	dir, err := coverageDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "coverage.jsonl"), nil
}
