package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

func TestGrepMode(t *testing.T) {
	for _, tc := range []struct {
		command          string
		recursive, quiet bool
	}{
		{"grep pat f", false, false},
		{"grep -r pat .", true, false},
		{"grep -R pat .", true, false},
		{"grep -rn pat .", true, false},
		{"grep -nri pat .", true, false},
		{"grep --recursive pat .", true, false},
		{"grep --dereference-recursive pat .", true, false},
		{"grep -d recurse pat .", true, false},
		{"grep -drecurse pat .", true, false},
		{"grep --directories=recurse pat .", true, false},
		{"grep --directories recurse pat .", true, false},
		{"grep -d skip pat .", false, false},
		{"grep pat . -r", true, false}, // both greps permute
		{"grep -rl pat .", true, true},
		{"grep -rL pat .", true, true},
		{"grep -rc pat .", true, true},
		{"grep -rq pat .", true, true},
		{"grep -r --count pat .", true, true},
		{"grep -r --files-with-matches pat .", true, true},
		{"grep -r --quiet pat .", true, true},
		{"grep -r --silent pat .", true, true},
		// A value-taking flag's value is not a flag.
		{"grep -e -r pat f", false, false},
		{"grep -nA3 pat f", false, false},
		{"grep -A 3 -l pat f", false, true},
		{"grep -rnA3l pat .", true, false}, // `3l` is -A's value
		{"grep --include -l -r pat .", true, false},
		{"grep -- -r f", false, false},
		// -s is "no messages", not quiet, in both greps.
		{"grep -rs pat .", true, false},
		// getopt_long takes a unique prefix of a long option, and a prefix of
		// a value-taking one consumes the next token -- here the `-l`, which
		// read as quiet until the review drove it.
		{"grep -r --exclude-d -l x .", true, false},
		{"grep -r --exclude-dir -l x .", true, false},
		{"grep -r --cou x .", true, true},
		{"grep --recur x .", true, false},
		// Ambiguous or unknown: refused, never quiet.
		{"grep -r --co -l x .", true, false},
		{"grep --frobnicate -l x .", true, false},
		// A `--directories` value is abbreviated the same way.
		{"grep -d rec pat .", true, false},
		{"grep --directories=rec pat .", true, false},
		{"grep --dir=read pat .", false, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			recursive, quiet := grepMode(strings.Fields(tc.command))
			if recursive != tc.recursive || quiet != tc.quiet {
				t.Errorf("grepMode = (%v, %v), want (%v, %v)",
					recursive, quiet, tc.recursive, tc.quiet)
			}
		})
	}
}

// grepTree is a directory with a subdirectory and one ordinary file.
func grepTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("func foo() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func denyReason(t *testing.T, payload string) string {
	t.Helper()
	code, stdout, stderr := drive(t, payload)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if got := verdictOf(t, stdout); got != "deny" {
		t.Fatalf("permissionDecision = %q, want deny", got)
	}
	return reasonOf(t, stdout)
}

func allowed(t *testing.T, payload string) {
	t.Helper()
	code, stdout, stderr := drive(t, payload)
	if code != 0 || stdout != "" {
		t.Errorf("got (%d, %q, %q), want a clean allow", code, stdout, stderr)
	}
}

// rewriteIn is the command a reason hands the model, or "" where it handed none.
func rewriteIn(reason string) string {
	_, after, ok := strings.Cut(reason, "run it as `")
	if !ok {
		return ""
	}
	rewrite, _, _ := strings.Cut(after, "` instead")
	return rewrite
}

// The refusal, its fix, and the loop that has to be closed: every rewrite the
// reason names is a command this same hook lets through. A rewrite it refused
// would hand the model a fix that is denied in turn -- which `echo $(grep -r x
// .)` did before allFiltered existed, driven.
func TestARecursiveGrepIsRefusedAndItsRewriteIsAllowed(t *testing.T) {
	dir := grepTree(t)
	for _, command := range []string{
		"grep -rn foo .",
		"grep -rn foo",
		"grep -r foo sub",
		"grep --recursive foo .",
		"egrep -R 'a|b' . 2>/dev/null",
		"grep -r foo . | head -5",
		"cd sub && grep -r foo .",
		"grep -rn foo . ;",
		"grep -r --exclude-d -l foo .",
	} {
		t.Run(command, func(t *testing.T) {
			reason := denyReason(t, bashCall(t, command, dir))
			rewrite := rewriteIn(reason)
			if rewrite == "" {
				t.Fatalf("the reason names no rewrite: %q", reason)
			}
			if !strings.HasPrefix(rewrite, "set -o pipefail; ") ||
				!strings.HasSuffix(rewrite, " filter") {
				t.Errorf("rewrite = %q, want pipefail ahead and the filter last", rewrite)
			}
			allowed(t, bashCall(t, rewrite, dir))
		})
	}
}

// Where appending a stage would not put this grep's output through it, the
// reason says what to do rather than handing over a command that does
// something else.
func TestNoRewriteWhereAppendingWouldNotFilterTheGrep(t *testing.T) {
	dir := grepTree(t)
	for _, command := range []string{
		"echo $(grep -r foo .)",
		"grep -r foo . ; echo done",
		"grep -r foo . &",
		"grep -r foo . # find it",
		"grep -r foo .\necho done",
	} {
		t.Run(command, func(t *testing.T) {
			reason := denyReason(t, bashCall(t, command, dir))
			if rewrite := rewriteIn(reason); rewrite != "" {
				t.Errorf("the reason names a rewrite %q", rewrite)
			}
			if !strings.Contains(reason, "set -o pipefail;") || !strings.Contains(reason, " filter`") {
				t.Errorf("the reason does not say what to append: %q", reason)
			}
		})
	}
}

// The rewrite repeats the caller's string, which is reached before scanCall
// scans it, so a key typed into the pattern would go straight back out.
func TestTheRewriteDoesNotRepeatAKey(t *testing.T) {
	key := testvec.Load(t).Get(t, "aws-access-key-id")
	reason := denyReason(t, bashCall(t, "grep -rn "+key+" .", grepTree(t)))
	if strings.Contains(reason, key) {
		t.Errorf("the reason repeats the key: %q", reason)
	}
}

func TestTheFilteredAndQuietFormsAreNotRefused(t *testing.T) {
	dir := grepTree(t)
	for _, command := range []string{
		"grep -rn foo . | spill-guard filter",
		"grep -rn foo . | /opt/x/spill-guard filter --redact",
		"grep -rn foo . | spill-guard filter | head",
		"set -o pipefail; grep -rn foo . | " + filterCommand(),
		"grep -rl foo .",
		"grep -rc foo sub",
		"grep -rq foo . && echo yes",
		"grep -rn --files-with-matches foo .",
		"grep -n foo a.go",
	} {
		t.Run(command, func(t *testing.T) {
			allowed(t, bashCall(t, command, dir))
		})
	}
}

// A filter in another pipeline filters nothing of this one's.
func TestAFilterElsewhereInTheStringDoesNotCount(t *testing.T) {
	dir := grepTree(t)
	for _, command := range []string{
		"grep -rn foo .; echo x | spill-guard filter",
		"echo x | spill-guard filter; grep -rn foo .",
		"grep -rn foo . | spill-guard scan",
	} {
		t.Run(command, func(t *testing.T) {
			denyReason(t, bashCall(t, command, dir))
		})
	}
}

// The hatch reaches this refusal like the others: a confirmation, not an allow.
func TestTheOverrideDowngradesAGrepRefusal(t *testing.T) {
	code, stdout, stderr := drive(t, bashCall(t,
		`SPILL_GUARD_OVERRIDE="need the raw lines" grep -rn foo .`, grepTree(t)))
	if code != 0 {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	if got := verdictOf(t, stdout); got != "ask" {
		t.Errorf("permissionDecision = %q, want ask", got)
	}
}

func grepToolCall(t *testing.T, cwd string, fields map[string]string) string {
	t.Helper()
	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		parts = append(parts, quote(t, k)+":"+quote(t, v))
	}
	return `{"hook_event_name":"PreToolUse","tool_name":"Grep","cwd":` + quote(t, cwd) +
		`,"tool_input":{` + strings.Join(parts, ",") + `}}`
}

func TestTheGrepToolInContentModeOverADirectoryIsRefused(t *testing.T) {
	dir := grepTree(t)
	for name, fields := range map[string]map[string]string{
		"content over a path":      {"pattern": "foo", "path": dir, "output_mode": "content"},
		"content over the cwd":     {"pattern": "foo", "output_mode": "content"},
		"a relative directory":     {"pattern": "foo", "path": "sub", "output_mode": "content"},
		"no mode, read as content": {"pattern": "foo", "path": dir},
	} {
		t.Run(name, func(t *testing.T) {
			reason := denyReason(t, grepToolCall(t, dir, fields))
			if !strings.Contains(reason, "grep -rn PATTERN PATH | ") {
				t.Errorf("the reason does not name the Bash form: %q", reason)
			}
			if strings.Contains(reason, dir) {
				t.Errorf("the reason repeats the caller's path: %q", reason)
			}
		})
	}
}

func TestTheGrepToolModesThatReturnNoContentAreAllowed(t *testing.T) {
	dir := grepTree(t)
	for _, mode := range []string{"files_with_matches", "count"} {
		t.Run(mode, func(t *testing.T) {
			allowed(t, grepToolCall(t, dir,
				map[string]string{"pattern": "foo", "path": dir, "output_mode": mode}))
		})
	}
}

// One file needs no walk, so it is read and scanned whole, as a Read of it is.
func TestTheGrepToolOverOneFileScansIt(t *testing.T) {
	dir := grepTree(t)
	allowed(t, grepToolCall(t, dir, map[string]string{
		"pattern": "foo", "path": filepath.Join(dir, "a.go"), "output_mode": "content"}))

	key := testvec.Load(t).Get(t, "aws-access-key-id")
	if err := os.WriteFile(filepath.Join(dir, "k.txt"), []byte("id = "+key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reason := denyReason(t, grepToolCall(t, dir, map[string]string{
		"pattern": "id", "path": "k.txt", "output_mode": "content"}))
	if !strings.Contains(reason, `"aws-access-key-id"`) {
		t.Errorf("the reason does not name the rule: %q", reason)
	}
}

func TestTheGrepToolPatternIsScanned(t *testing.T) {
	dir := grepTree(t)
	key := testvec.Load(t).Get(t, "aws-access-key-id")
	reason := denyReason(t, grepToolCall(t, dir, map[string]string{
		"pattern": key, "path": dir, "output_mode": "files_with_matches"}))
	if !strings.Contains(reason, `"aws-access-key-id"`) || !strings.Contains(reason, patternLabel) {
		t.Errorf("the reason does not name the rule in the pattern: %q", reason)
	}
}
