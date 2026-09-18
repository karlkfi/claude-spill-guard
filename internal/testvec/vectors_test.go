package testvec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder stands in for *testing.T so a failure is a value this test can
// assert on. Its Fatalf does not abort, so loadFrom runs every check and
// records each failure it finds, which is why the cases below match the
// message rather than counting: a body trips checks it is not named for.
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
// failed is not evidence that it can, and counting failures is not evidence of
// which: every body here holds one vector, so the floor records a failure
// beside whatever the case is about. `want` is what makes each case name true.
//
// Two of the four match encoding/json's own wording, which is the only thing
// DisallowUnknownFields and a syntax error say about themselves. A stdlib
// rewording fails this loudly, which is the direction to fail in.
//
// The values are the padded placeholder rather than anything that could pass
// for a key. These cases are about the file's shape, so the value is not what
// they assert on -- and a matching literal here would put a string the scanner
// refuses in the package that exists to keep such strings out of source.
func TestLoadRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"a file holding fewer vectors than the floor",
			`{"only-one": {"value": "AKIA0000000000000000", "note": "x"}}`,
			"vector(s), want at least"},
		{"a field the entry does not carry, which is how a typo arrives",
			`{"id": {"value": "AKIA0000000000000000", "values": "x"}}`,
			`unknown field "values"`},
		{"an entry with no value at all",
			`{"id": {"note": "x"}}`,
			"has no value"},
		{"a file that is not JSON",
			`this is not a vectors file`,
			"invalid character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec recorder
			loadFrom(&rec, write(t, tc.body))
			for _, f := range rec.failures {
				if strings.Contains(f, tc.want) {
					return
				}
			}
			t.Errorf("no recorded failure holds %q; got %q", tc.want, rec.failures)
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
