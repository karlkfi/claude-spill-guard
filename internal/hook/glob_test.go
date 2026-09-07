package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A glob is expanded by bash before the command runs, against the filesystem
// this process reads, so the file set is settled here in a way a directory
// operand's never is: no reader flag alters an argv the shell computed. Q135
// measured 51 of 393 refusals on this arm in two days, every one a plain
// POSIX pattern, and the re-take on 2026-09-06 found 135 glob operands behind
// the reason and every one plain.
func TestAGlobOperandIsExpandedToTheFilesBashWouldSend(t *testing.T) {
	dir, name := planted(t)
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, name), key, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"cat *.env",
		"grep -n AWS *.env",
		"cat sub/*.env",
		"cat */" + name,
		"cat ?eploy.env",
		"cat [d]eploy.env",
		"cat [!x]eploy.env",
		"cd sub && cat *.env",
		"cat " + dir + "/*.env",
		// The prefix takes effect after the operands are expanded, and `-euo
		// pipefail` carries no `f`: neither changes the set, driven.
		"GLOBIGNORE=x cat *.env",
		"set -euo pipefail; cat *.env",
	} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, dir))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			reason := reasonOf(t, stdout)
			if !strings.Contains(reason, "aws-access-key-id") {
				t.Errorf("reason does not name the rule: %q", reason)
			}
			if !strings.Contains(reason, name) {
				t.Errorf("reason does not name the file: %q", reason)
			}
		})
	}
}

// bash's default matches a leading `.` in a filename only against a literal
// `.` at the start of the pattern element -- `*`, `?` and `[.]` do not reach
// it, driven on 5.3.15 -- where filepath.Glob matches all three. So a hidden
// file the command would not receive is filtered out of the set, and a block
// on its content would be a block on bytes that never cross. The literal forms
// reach it, as they do in bash.
func TestAGlobDoesNotReachADotfileBashWouldNotSend(t *testing.T) {
	dir, name := planted(t)
	hidden := "." + name
	if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, hidden)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.env"), []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"cat *.env", "cat ?" + name, "cat [.]" + name} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, dir))
			if code != 0 || stdout != "" || stderr != "" {
				t.Errorf("exit %d, stdout %q, stderr %q, want a silent 0", code, stdout, stderr)
			}
		})
	}
	for _, command := range []string{"cat .*.env", `cat \.` + name, "cat .[d]eploy.env"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, dir))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, hidden) {
				t.Errorf("reason does not name the hidden file: %q", reason)
			}
		})
	}
}

// The expansion assumes bash's default options, and anything in the string
// that could change them puts the pattern back where it was before this:
// recorded, and the call proceeds. Each shape here is one bash expands
// differently from the default, or one filepath.Glob reads differently from
// bash, driven on 5.3.15. None of them appears in the measured population --
// 0 `shopt`, 0 `set -f`, 0 GLOBIGNORE in 95 commands -- so the arm is a
// guard rather than a cost.
func TestAGlobBashWouldExpandDifferentlyIsRecorded(t *testing.T) {
	dir, name := planted(t)
	for _, tc := range []struct{ name, command, says string }{
		{"dotglob set", "shopt -s dotglob; cat *.env", "changes how the shell expands"},
		{"any shopt", "shopt -u dotglob; cat *.env", "changes how the shell expands"},
		{"a shopt beside the reader in a subshell", "(shopt -s dotglob; cat *.env)", "changes how the shell expands"},
		{"noglob by flag", "set -f; cat *.env", "changes how the shell expands"},
		{"noglob by name", "set -o noglob; cat *.env", "changes how the shell expands"},
		{"GLOBIGNORE assigned", "GLOBIGNORE=x; cat *.env", "changes how the shell expands"},
		{"GLOBIGNORE exported", "export GLOBIGNORE=x; cat *.env", "changes how the shell expands"},
		{"after an eval", "eval x=1; cat *.env", "changes how the shell expands"},
		{"after a source", "source rc; cat *.env", "changes how the shell expands"},
		{"in a backtick body after a shopt", "shopt -s dotglob; echo `cat *.env`", "changes how the shell expands"},
		{"a class Go cannot compile", "cat *.[env", "cannot expand"},
		{"a POSIX class", "cat [[:alpha:]]*.env", "cannot expand"},
		{"a step up after a wildcard", "cat */../" + name, "cannot expand"},
		{"a trailing separator", "cat */", "cannot expand"},
		{"a brace beside a wildcard", "cat *.{env,txt}", "brace expansion"},
		{"a brace alone", "cat {deploy,x}.env", "brace expansion"},
		{"a sequence brace", "cat deploy{1..2}.env", "brace expansion"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, dir))
			reason := deferred(t, code, stdout, stderr)
			if !strings.Contains(reason, tc.says) {
				t.Errorf("reason = %q, want it to say %q", reason, tc.says)
			}
		})
	}
}

// The lexer strips quotes and backslashes, so `cat "*.env"` and `cat \*.env`
// reach here as `*.env` and are expanded where bash would open one file named
// `*.env`. Q92's class, and in the precision direction: every file bash would
// send is in the set, and files it would not are too. Pinned so a lexer that
// keeps quote provenance reddens this and decides.
func TestAQuotedGlobExpandsWhereBashWouldNot(t *testing.T) {
	dir, name := planted(t)
	for _, command := range []string{`cat "*.env"`, `cat '*.env'`, `cat \*.env`} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, dir))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
				t.Errorf("reason does not name the file: %q", reason)
			}
		})
	}
}

// globFixture is the tree the bash rows below were taken over: two plain
// files, a hidden one, a directory with a plain and a hidden file, a hidden
// directory, and three names that carry a space, a bracket and a `?`.
func globFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"d/sub", "d/.hid"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"a.txt", "b.txt", ".hidden.txt", "sub/c.md", "sub/.h.md", ".hid/x.md", "sp ace.txt", "x[1].txt", "q?.txt"} {
		if err := os.WriteFile(filepath.Join(root, "d", f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// What `for x in <pattern>; do printf '%s\n' "$x"; done` printed under bash
// 5.3.15 with `--norc --noprofile`, over globFixture, on 2026-09-06. A pattern
// bash passes through unexpanded prints itself, and that literal names no
// file, so those rows are the empty set. `refused` marks the rows this declines
// to expand, and for them the property is that the refusal is reached rather
// than an empty set returned: bash sends files for four of the six.
var bashGlobRows = []struct {
	pattern string
	bash    []string
	refused bool
}{
	{"d/*", []string{"d/a.txt", "d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/sub", "d/x[1].txt"}, false},
	{"d/*.txt", []string{"d/a.txt", "d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/x[1].txt"}, false},
	{"d/.*", []string{"d/.hid", "d/.hidden.txt"}, false},
	{"d/.*.txt", []string{"d/.hidden.txt"}, false},
	{"d/*/*.md", []string{"d/sub/c.md"}, false},
	{"d/*/.*.md", []string{"d/sub/.h.md"}, false},
	{"d/sub/*", []string{"d/sub/c.md"}, false},
	{"d/nomatch*", []string{}, false},
	{"d/[", []string{}, true},
	{"d/x[[]1].txt", []string{"d/x[1].txt"}, false},
	{"d/q?.txt", []string{"d/q?.txt"}, false},
	{"d/*/", []string{"d/sub"}, true},
	{"d/**", []string{"d/a.txt", "d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/sub", "d/x[1].txt"}, false},
	{"d/{a,b}.txt", []string{"d/a.txt", "d/b.txt"}, true},
	{"d/a{1..2}.txt", []string{}, true},
	{"*/a.txt", []string{"d/a.txt"}, false},
	{"./d/*.txt", []string{"./d/a.txt", "./d/b.txt", "./d/q?.txt", "./d/sp ace.txt", "./d/x[1].txt"}, false},
	{"d/./*.txt", []string{"d/./a.txt", "d/./b.txt", "d/./q?.txt", "d/./sp ace.txt", "d/./x[1].txt"}, false},
	{"d/sub/../*.txt", []string{"d/sub/../a.txt", "d/sub/../b.txt", "d/sub/../q?.txt", "d/sub/../sp ace.txt", "d/sub/../x[1].txt"}, false},
	{"d/*.{txt,md}", []string{"d/a.txt", "d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/x[1].txt"}, true},
	{"d/[ab].txt", []string{"d/a.txt", "d/b.txt"}, false},
	{"d/[!a]*.txt", []string{"d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/x[1].txt"}, false},
	{"d/[^a]*.txt", []string{"d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/x[1].txt"}, false},
	{"d/*[.]txt", []string{"d/a.txt", "d/b.txt", "d/q?.txt", "d/sp ace.txt", "d/x[1].txt"}, false},
	{"d/sp*", []string{"d/sp ace.txt"}, false},
	{"d/* ace.txt", []string{"d/sp ace.txt"}, false},
	{"d/*.TXT", []string{}, false},
	{"d/[.]hidden.txt", []string{}, false},
	{"d/[.h]*", []string{}, false},
	{"d/.hidden.txt", []string{"d/.hidden.txt"}, false},
	{"d/su*", []string{"d/sub"}, false},
	{"d/[a-b].txt", []string{"d/a.txt", "d/b.txt"}, false},
	{"d/.*/x.md", []string{"d/.hid/x.md"}, false},
	{"d/*/.h.md", []string{"d/sub/.h.md"}, false},
	{"d/sub/../.hidden.txt", []string{"d/sub/../.hidden.txt"}, false},
	{"d/**/*.md", []string{"d/sub/c.md"}, false},
}

// Both directions matter. A file here that bash would not send is a block on
// bytes that never cross; a file bash sends that is not here crosses
// unscanned. So the sets are compared whole, after cleaning, since `d/./a.txt`
// and `d/a.txt` are one file.
func TestTheExpansionAgreesWithBash(t *testing.T) {
	root := globFixture(t)
	for _, row := range bashGlobRows {
		t.Run(row.pattern, func(t *testing.T) {
			got, err := expand(row.pattern, root, false, false)
			if row.refused {
				if err == nil {
					t.Fatalf("expanded to %q, want a refusal", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v; bash gave %q", err, row.bash)
			}
			want := make([]string, 0, len(row.bash))
			for _, b := range row.bash {
				want = append(want, filepath.Clean(b))
			}
			have := make([]string, 0, len(got))
			for _, g := range got {
				rel, err := filepath.Rel(root, g)
				if err != nil {
					t.Fatal(err)
				}
				have = append(have, filepath.Clean(rel))
			}
			slices.Sort(want)
			slices.Sort(have)
			if !slices.Equal(have, want) {
				t.Errorf("got %q, bash gave %q", have, want)
			}
		})
	}
}
