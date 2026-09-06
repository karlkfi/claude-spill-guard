package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readCoverage returns the records written under the isolated state dir.
func readCoverage(t *testing.T) []coverage {
	t.Helper()
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		t.Fatal("the state dir is not isolated, so this would read the real log")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "spill-guard", "coverage.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []coverage
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var c coverage
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("coverage line is not JSON: %q (%v)", line, err)
		}
		out = append(out, c)
	}
	return out
}

// The record is the whole point of deferring rather than allowing. A gap
// nobody can see is a gap nobody fixes, so this pins that the file sink
// receives what the stderr line says -- the two are written together and only
// one of them survives the session.
func TestACoverageFailureIsWrittenToTheLog(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := drive(t, bashCall(t, "cat $SOME_VAR", dir))
	deferred(t, code, stdout, stderr)

	got := readCoverage(t)
	if len(got) != 1 {
		t.Fatalf("wrote %d records, want 1", len(got))
	}
	if got[0].Event != string(PreToolUse) {
		t.Errorf("event = %q, want %q", got[0].Event, PreToolUse)
	}
	if got[0].Tool != "Bash" {
		t.Errorf("tool = %q, want Bash", got[0].Tool)
	}
	if !strings.Contains(got[0].Reason, "expands at run time") {
		t.Errorf("reason = %q, want the unresolvable operand", got[0].Reason)
	}
	if got[0].Time.IsZero() {
		t.Error("the record carries no timestamp, so a trend cannot be read from it")
	}
}

// The control for the test above: a call the scanner could read writes nothing.
//
// Without this, a sink that logged every call would pass -- and a log that
// records everything answers nothing, which is the failure mode a coverage
// log has rather than the one a scanner has.
func TestACleanCallWritesNoCoverageRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(path, []byte("nothing interesting here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, bashCall(t, "cat notes.txt", dir))
	if code != 0 || stdout != "" || strings.TrimSpace(stderr) != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q, want a silent allow", code, stdout, stderr)
	}
	if got := readCoverage(t); len(got) != 0 {
		t.Errorf("a clean call wrote %d coverage record(s): %+v", len(got), got)
	}
}

// A finding is not a coverage failure, and must not be logged as one.
//
// The log is swept to decide what the resolver should learn to read. A rule
// match is the scanner working, so a record for it would inflate the very
// number the log exists to drive down -- and it would put a matched file's
// path in a file the finding path deliberately keeps values out of.
func TestAFindingIsNotLoggedAsACoverageFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.env")
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := drive(t, bashCall(t, "cat deploy.env", dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a deny object", code)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
		t.Fatalf("reason = %q, want the finding -- otherwise this asserts nothing", reason)
	}
	if got := readCoverage(t); len(got) != 0 {
		t.Errorf("a finding wrote %d coverage record(s): %+v", len(got), got)
	}
}

// The record must not carry the value, for the reason no verdict may: this
// file is on disk and a path is not a secret, but the reasons are composed
// from the same strings the API sees.
func TestACoverageRecordCarriesNoScannedValue(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := drive(t, bashCall(t, "cat $HOME/"+secret, dir))
	deferred(t, code, stdout, stderr)
	for _, c := range readCoverage(t) {
		if strings.Contains(c.Reason, secret) {
			t.Errorf("the coverage record carries the value: %q", c.Reason)
		}
	}
}

// The log is bounded, so a busy machine cannot fill a disk with it. The cap is
// enforced by rotation rather than truncation, because the oldest records are
// the ones a trend is read from.
func TestTheCoverageLogRotatesAtTheCap(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := filepath.Join(state, "spill-guard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "coverage.jsonl")
	if err := os.WriteFile(path, make([]byte, coverageCap), 0o600); err != nil {
		t.Fatal(err)
	}

	appendCoverage(coverage{Reason: "the newest record"})

	rotated, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("nothing was rotated aside: %v", err)
	}
	if rotated.Size() != int64(coverageCap) {
		t.Errorf("the rotated file is %d bytes, want the %d that were there",
			rotated.Size(), coverageCap)
	}
	fresh, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fresh), "the newest record") {
		t.Errorf("the new log does not carry the record that triggered the rotation: %q", fresh)
	}
	if len(fresh) >= coverageCap {
		t.Errorf("the new log is %d bytes, so it was appended to rather than started", len(fresh))
	}
}

// The log is 0600. The reasons name paths on this machine, which is somebody's
// directory layout even though no value is in there.
func TestTheCoverageLogIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := drive(t, bashCall(t, "cat $SOME_VAR", dir))
	deferred(t, code, stdout, stderr)

	fi, err := os.Stat(filepath.Join(os.Getenv("XDG_STATE_HOME"), "spill-guard", "coverage.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("mode = %04o, want nothing for group or other", perm)
	}
}

// A sink that cannot be written must not change the verdict.
//
// This is the property that keeps the change safe: the whole point is that a
// call proceeds, so a full disk or a read-only home turning that back into a
// stopped call would rebuild the friction on exactly the machines least able
// to diagnose it. Driven by making the state directory a file, so MkdirAll
// fails for a reason no permission bit can undo.
func TestAnUnwritableLogDoesNotChangeTheVerdict(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	if err := os.WriteFile(filepath.Join(state, "spill-guard"), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	code, stdout, stderr := driveRaw(bashCall(t, "cat $SOME_VAR", dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: a logging failure must not block", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want no verdict", stdout)
	}
	// The stderr half still works, because it does not touch the filesystem.
	if !strings.Contains(stderr, "expands at run time") {
		t.Errorf("stderr = %q, want the record on the sink that still works", stderr)
	}
}
