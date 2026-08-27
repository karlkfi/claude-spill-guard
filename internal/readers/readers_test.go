package readers

import (
	"reflect"
	"testing"
)

// The cases Q62 names, plus the ones the divergence turns on. A spec entry
// naming the wrong argument position produces a scanner that reads the wrong
// file, reports clean, and looks like it ran -- so the table is checked by
// what it answers rather than by reading it.
func TestFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tokens  []string
		want    []string
		unknown bool
	}{
		{"cat takes every positional", []string{"cat", "a", "b"}, []string{"a", "b"}, false},
		{"grep's first positional is the pattern", []string{"grep", "pat", "f"}, []string{"f"}, false},
		{"grep -e moves the pattern off the positionals",
			[]string{"grep", "-e", "pat", "f"}, []string{"f"}, false},
		{"grep -f names a file and suppresses prog",
			[]string{"grep", "-f", "pats", "f"}, []string{"pats", "f"}, false},
		{"an inline long value is still the flag's file",
			[]string{"grep", "--file=pats", "f"}, []string{"pats", "f"}, false},
		{"a flag value is never an operand",
			[]string{"grep", "-m", "3", "pat", "f"}, []string{"f"}, false},
		{"-- ends the flags", []string{"cat", "--", "-weird"}, []string{"-weird"}, false},
		{"a bare - is a positional", []string{"cat", "-"}, []string{"-"}, false},
		{"jq's file is the second token of a two-token flag",
			[]string{"jq", "--rawfile", "v", "data.json", ".x", "in.json"},
			[]string{"data.json", "in.json"}, false},
		{"awk drops variable assignments",
			[]string{"awk", "prog", "v=1", "f"}, []string{"f"}, false},
		{"awk keeps a path whose basename holds an =",
			[]string{"awk", "prog", "dir/a=b"}, []string{"dir/a=b"}, false},
		{"an alias resolves to its row",
			[]string{"egrep", "pat", "f"}, []string{"f"}, false},
		{"a path-qualified command still resolves",
			[]string{"/usr/bin/cat", "f"}, []string{"f"}, false},
		{"an unknown flag is assumed to take no argument",
			[]string{"cat", "--no-such-flag", "f"}, []string{"f"}, false},
		{"sed -i keeps its operand, because we scan reads",
			[]string{"sed", "-i", "s/a/b/", "f"}, []string{"f"}, false},

		// The divergence.
		{"uniq's second positional is written, not read",
			[]string{"uniq", "in", "out"}, []string{"in"}, false},
		{"xxd's second positional is written, not read",
			[]string{"xxd", "in", "out"}, []string{"in"}, false},
		{"sort -o names an output and is not an operand",
			[]string{"sort", "-o", "out", "in"}, []string{"in"}, false},
		{"base64 -i is a read and -o is not",
			[]string{"base64", "-i", "in", "-o", "out"}, []string{"in"}, false},
		{"a list-of-files flag returns the list itself",
			[]string{"wc", "--files0-from", "list"}, []string{"list"}, false},

		// Commands with no row.
		{"cp has no row here", []string{"cp", "a", "b"}, nil, true},
		{"mv has no row here", []string{"mv", "a", "b"}, nil, true},
		{"rm has no row here", []string{"rm", "a"}, nil, true},
		{"tee has no row here", []string{"tee", "a"}, nil, true},
		{"unlink goes with rm", []string{"unlink", "a"}, nil, true},
		{"a command nobody has a table for", []string{"curl", "https://x"}, nil, true},
		{"no tokens at all", nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, known := Files(tc.tokens)
			if known == tc.unknown {
				t.Fatalf("known = %v, want %v", known, !tc.unknown)
			}
			if !known {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Files(%q) = %q, want %q", tc.tokens, got, tc.want)
			}
		})
	}
}

// firstOutput indexes into the positional run, which only lines up when the row
// contributes no flag-named files and takes no leading program token. Upstream
// says so in a comment; this is the assertion, because a later flag added to
// one of these rows would silently shift what gets dropped.
func TestOutputRowsHaveTheShapeFirstOutputAssumes(t *testing.T) {
	found := 0
	for name, s := range specs {
		if s.firstOutput < 0 {
			continue
		}
		found++
		if len(s.fileFlags) != 0 {
			t.Errorf("%q has firstOutput and %d file flag(s); the drop would "+
				"land on the wrong operand", name, len(s.fileFlags))
		}
		if s.prog != 0 {
			t.Errorf("%q has firstOutput and prog %d", name, s.prog)
		}
		if s.skipAssignments {
			t.Errorf("%q has firstOutput and skips assignments", name)
		}
	}
	if found == 0 {
		t.Fatal("no row carries firstOutput, so this test asserts nothing")
	}
}

// The read/write split is this repo's, and a row for a write command is how it
// would be lost -- silently, because a scanner that reports a `cp` destination
// as readable content just over-blocks and never says why.
func TestNoWriteCommandHasARow(t *testing.T) {
	for _, name := range []string{"cp", "mv", "tee", "rm", "unlink"} {
		if _, ok := lookup(name); ok {
			t.Errorf("%q has a row; upstream's write commands are not this "+
				"package's, and the package comment says why", name)
		}
	}
}

// Every alias has to land on a row, or it silently reports the command as one
// nobody has a table for -- which reads exactly like a command nobody ported.
func TestEveryAliasResolves(t *testing.T) {
	if len(aliases) == 0 {
		t.Fatal("no aliases, so this test asserts nothing")
	}
	for from, to := range aliases {
		if _, ok := specs[to]; !ok {
			t.Errorf("alias %q -> %q, which is not a row", from, to)
		}
	}
}
