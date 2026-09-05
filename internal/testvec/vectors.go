// Package testvec loads the credential-shaped strings the tests assert on.
//
// The values live under testdata/corpus/, which is the one tree
// .github/secret_scanning.yml tells GitHub not to read, so a string that could
// pass for an issued credential stays out of every source file and out of
// every alert. What stays inline is the case no scanner can mistake for one --
// a body a character too long, a lowercase suffix, a padded placeholder --
// because there the bytes are what the assertion is about and belong beside
// it.
//
// Nothing outside a _test.go file imports this, so it is linked into no
// shipped binary. It takes a TB rather than *testing.T for the same reason a
// non-test package does not import testing: that import registers test flags
// on whatever links it.
package testvec

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// TB is the part of *testing.T this package needs.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Vector is one named string and the note saying what it is. Nothing reads the
// note; it is there for whoever finds a credential-shaped value in the tree
// and needs a sentence telling them it is inert.
type Vector struct {
	Value string `json:"value"`
	Note  string `json:"note"`
}

// Set is the file, keyed by id.
type Set map[string]Vector

// relPath is where the file sits relative to the repository root, which is
// found by walking up rather than by counting `..` at each call site.
const relPath = "testdata/corpus/vectors/credentials.json"

// minVectors is a floor. A decode returning an empty map fails no assertion by
// itself: every table reading it reports zero cases, and a table test with no
// cases reports the same green as one with all of them.
const minVectors = 11

// Load reads the vectors file, failing the test rather than returning an
// error, since every caller is a table that has nothing to assert without it.
func Load(tb TB) Set {
	tb.Helper()

	return loadFrom(tb, find(tb))
}

// loadFrom is Load against a named file, so the checks below can be driven
// against a file written to fail them.
func loadFrom(tb TB, path string) Set {
	tb.Helper()

	f, err := os.Open(path)
	if err != nil {
		tb.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	var set Set
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		tb.Fatalf("decoding %s: %v", path, err)
	}
	if len(set) < minVectors {
		tb.Fatalf("%s holds %d vector(s), want at least %d", path, len(set), minVectors)
	}
	for id, v := range set {
		if v.Value == "" {
			tb.Fatalf("%s: vector %q has no value", path, id)
		}
	}
	return set
}

// Get is the id lookup, failing on a name the file does not carry. A missing
// id would otherwise reach an assertion as the empty string, which several of
// these tables accept as a legitimate case.
func (s Set) Get(tb TB, id string) string {
	tb.Helper()

	v, ok := s[id]
	if !ok {
		tb.Fatalf("no vector named %q", id)
	}
	return v.Value
}

// find walks up from the working directory to the file. Walking to the file
// rather than to a go.mod keeps it right in tools/, which carries a second
// module of its own.
func find(tb TB) string {
	tb.Helper()

	dir, err := os.Getwd()
	if err != nil {
		tb.Fatalf("working directory: %v", err)
	}
	for {
		path := filepath.Join(dir, relPath)
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatalf("no %s above the working directory", relPath)
		}
		dir = parent
	}
}
