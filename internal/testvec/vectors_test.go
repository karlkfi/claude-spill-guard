package testvec

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// recorder stands in for *testing.T so a failure is a value this test can
// assert on. Its Fatalf does not abort, so loadFrom runs on past the first
// failure -- harmless here, since every case below asserts that at least one
// was recorded rather than which.
type recorder struct{ failures []string }

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// write puts a vectors file in a temporary directory and returns its path.
func write(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// The shipped file is what every table reads, so this is the case that has to
// pass. It is also the positive control for the four below: they assert a
// failure, and a loader that failed on everything would satisfy all of them.
func TestTheShippedFileLoads(t *testing.T) {
	var rec recorder
	set := loadFrom(&rec, find(&rec))
	if len(rec.failures) != 0 {
		t.Fatalf("loading the shipped file failed: %v", rec.failures)
	}
	if len(set) < minVectors {
		t.Errorf("the shipped file holds %d vector(s), want at least %d", len(set), minVectors)
	}
	for id := range set {
		if got := set.Get(t, id); got == "" {
			t.Errorf("vector %q has no value", id)
		}
	}
}

// Each of these drives one check in loadFrom. An assertion that has never
// failed is not evidence that it can.
func TestLoadRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"a file holding fewer vectors than the floor",
			`{"only-one": {"value": "AKIA0SPILLGUARD11111", "note": "x"}}`},
		{"a field the entry does not carry, which is how a typo arrives",
			`{"id": {"value": "AKIA0SPILLGUARD11111", "values": "x"}}`},
		{"an entry with no value at all",
			`{"id": {"note": "x"}}`},
		{"a file that is not JSON",
			`this is not a vectors file`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec recorder
			loadFrom(&rec, write(t, tc.body))
			if len(rec.failures) == 0 {
				t.Error("loadFrom accepted it, want a failure")
			}
		})
	}
}

// A missing id reaching a table as the empty string is the failure this
// guards: several of the tables that read this file accept "" as a case.
func TestGetRejectsAnUnknownID(t *testing.T) {
	var rec recorder
	if got := (Set{}).Get(&rec, "absent"); got != "" {
		t.Errorf("Get on an absent id returned %q", got)
	}
	if len(rec.failures) == 0 {
		t.Error("Get accepted an absent id, want a failure")
	}
}

// The walk has to find the file from wherever `go test` puts the working
// directory, which is the package directory rather than the repository root.
func TestFindWalksUpToTheRepositoryRoot(t *testing.T) {
	var rec recorder
	path := find(&rec)
	if len(rec.failures) != 0 {
		t.Fatalf("find failed: %v", rec.failures)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("find returned %s: %v", path, err)
	}
}
