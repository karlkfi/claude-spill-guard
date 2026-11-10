package hook

import (
	"os"
	"path/filepath"
	"runtime"
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
		// A quiet flag after an operand is honoured, POSIXLY_CORRECT
		// notwithstanding: refusing it was measured as the larger cost.
		{"grep -r pat . -l", true, true},
		{"grep pat . -r --count", true, true},
		// `--context` takes the next token on GNU grep and ugrep and only
		// after `=` on BSD grep, so the token is read both ways.
		{"grep --context -r pat", true, false},
		{"grep -r --context -l pat .", true, false},
		{"grep -r --context=3 -l pat .", true, true},
		{"grep -l --context 3 -r pat .", true, true},
		{"grep --context 3 pat f", false, false},
		// A digit is a depth to ugrep, which recurses on it.
		{"grep -2 pat", true, false},
		{"grep -rn2 pat .", true, false},
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
		// The value after a long option is not the pattern, so the pattern
		// is not a file and the walk is of `.`.
		"grep -r --exclude-dir node_modules foo",
		"grep -r --exclude-d node_modules foo",
		"grep -r --after-context 2 foo",
		"grep -r --context 3 foo",
		"grep -2 foo",
		// A pattern file is not an operand, however it is spelled (Q255).
		"grep -r -f a.go",
		"grep -r --file=a.go",
		"grep -r --file a.go",
		"grep -rf a.go",
		"grep -r -f a.go sub",
		// The lexer splits `--file=<(…)` at the `<(`, and the grep's own
		// `<(` is no copy around the filter its rewrite adds.
		"grep -r -f <(echo foo)",
		"grep -r --file=<(echo foo)",
		"grep -r -f <(echo foo) sub",
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

// A pattern file is read, because grep opens it, and is not what the walk is
// over: with no other operand the grep searches `.` (Q255).
func TestAPatternFileIsReadAndIsNotAnOperand(t *testing.T) {
	for _, tc := range []struct {
		command string
		files   []string
		none    bool
	}{
		{"grep -r -f pats", []string{"pats"}, true},
		{"grep -r --file=pats", []string{"pats"}, true},
		{"grep -r --file pats", []string{"pats"}, true},
		{"grep -r -e x -f pats", []string{"pats"}, true},
		{"grep -r -f pats d", []string{"pats", "d"}, false},
		{"grep -r --file=pats d", []string{"pats", "d"}, false},
		{"grep -r -e -f d", []string{"d"}, false},
		{"grep -r -- x -f", []string{"-f"}, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			files, none := grepFiles(strings.Fields(tc.command))
			if strings.Join(files, " ") != strings.Join(tc.files, " ") || none != tc.none {
				t.Errorf("grepFiles = %q, %v; want %q, %v", files, none, tc.files, tc.none)
			}
		})
	}
}

// grepFiles and grepMode have to agree on which long options take the next
// token, or a value is read as the pattern and the pattern as the file. The
// reader table lacked nine that grepLong consumes and consumed `--color`,
// which grepLong does not.
func TestGrepFilesConsumesWhatGrepModeDoes(t *testing.T) {
	for name, consumes := range grepLong {
		if name == "--file" || name == "--regexp" {
			continue // each names the pattern, so P is a file too; pinned in readers
		}
		want := []string{"P", "F"}
		if consumes && !grepLongDisputed[name] {
			want = []string{"F"}
		}
		t.Run(name, func(t *testing.T) {
			files, none := grepFiles([]string{"grep", name, "V", "P", "F"})
			if strings.Join(files, " ") != strings.Join(want, " ") || none {
				t.Errorf("grepFiles = %q, %v; want %q, false", files, none, want)
			}
		})
	}
}

// A file named after an option the table misread is still scanned.
func TestAGrepOfAKeyFileIsBlockedWhateverTheOptions(t *testing.T) {
	dir := grepTree(t)
	key := testvec.Load(t).Get(t, "aws-access-key-id")
	if err := os.WriteFile(filepath.Join(dir, "k.txt"), []byte("id = "+key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"grep --color id k.txt",
		"grep --colour id k.txt",
		"grep --context id k.txt",
		"grep --context 3 id k.txt",
		"grep --exclude-d x id k.txt",
	} {
		t.Run(command, func(t *testing.T) {
			reason := denyReason(t, bashCall(t, command, dir))
			if !strings.Contains(reason, `"aws-access-key-id"`) {
				t.Errorf("the reason does not name the rule: %q", reason)
			}
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

// A filter counts where grep's stdout reaches it, and only there (Q208). Each
// shape was driven on bash 5.3.15 with a stand-in filter that prints a line
// count: the refused ones printed the key, to stderr or past the filter, and
// the allowed ones printed only the count. Main allowed the first group
// silently and refused the second.
func TestAFilterCountsWhereGrepsStdoutReachesIt(t *testing.T) {
	dir := grepTree(t)
	for _, command := range []string{
		"grep -rn foo . >&2 | spill-guard filter",
		"grep -rn foo . 1>&2 | spill-guard filter",
		"grep -rn foo . >&2 2>&1 | spill-guard filter",
		"grep -rn foo . >/dev/stderr | spill-guard filter",
		"grep -rn foo . >/dev/fd/2 | spill-guard filter",
		"grep -rn foo . &>/dev/stderr | spill-guard filter",
		"exec 3>&2; grep -rn foo . >&3 | spill-guard filter",
		"{ grep -rn foo . >&2; } | spill-guard filter",
		"{ grep -rn foo .; } >&2 | spill-guard filter",
		"( grep -rn foo . ) >&2 | spill-guard filter",
		"grep -rn foo . | (cat; spill-guard filter)",
		"grep -rn foo . 2> >(spill-guard filter)",
		"grep -rn foo . <(spill-guard filter)",
	} {
		t.Run(command+" is refused", func(t *testing.T) {
			denyReason(t, bashCall(t, command, dir))
		})
	}
	for _, command := range []string{
		"grep -rn foo . 2>&1 | spill-guard filter",
		"grep -rn foo . 2>&1 >&2 | spill-guard filter",
		"grep -rn foo . 2>/dev/null | spill-guard filter",
		"grep -rn foo . |& spill-guard filter",
		"{ grep -rn foo .; } | spill-guard filter",
		"{ grep -rn foo .; echo; } | spill-guard filter",
		"( grep -rn foo . ) | spill-guard filter",
		"(grep -rn foo .; true) | spill-guard filter",
		"for x in .; do grep -rn foo $x; done | spill-guard filter",
		"if true; then grep -rn foo .; fi | spill-guard filter",
		"grep -rn foo . | (spill-guard filter)",
		"grep -rn foo . | (spill-guard filter; cat)",
		"grep -rn foo . | { spill-guard filter; }",
	} {
		t.Run(command+" is allowed", func(t *testing.T) {
			allowed(t, bashCall(t, command, dir))
		})
	}
}

// A stage between the grep and the filter that copies what it reads elsewhere
// sends it around the filter (Q233). Driven on bash 5.3.15 with the built
// filter and a planted key: every refused shape put the key in stdout or
// stderr, and every allowed one put it in neither. The tee to out.log alone is
// the stated control: allowed, because nothing in this string reads the file
// and a later call that does is scanned then.
func TestAStageThatCopiesAroundTheFilterDoesNotCount(t *testing.T) {
	dir := grepTree(t)
	refused := []string{
		// A device judged where the name lands, not how it is spelled.
		"grep -rn foo . | tee //dev/stderr | spill-guard filter",
		"cd / && grep -rn foo " + dir + " | tee dev/stderr | spill-guard filter",
		"grep -rn foo . | gtee /dev/stderr | spill-guard filter",
		"grep -rn foo . | dd of=/dev/stderr status=none | spill-guard filter",
		"grep -rn foo . | env -C / tee dev/stderr | spill-guard filter",
		"grep -rn foo . | nice -n \"$N\" tee /dev/stderr | spill-guard filter",
	}
	// Under Git Bash /dev is not under the drive root, so neither of these
	// reaches a device there.
	if runtime.GOOS != "windows" {
		if err := os.Symlink("/dev/stderr", filepath.Join(dir, "errlink")); err != nil {
			t.Fatal(err)
		}
		refused = append(refused,
			"grep -rn foo . | tee "+strings.Repeat("../", 40)+"dev/stderr | spill-guard filter",
			"grep -rn foo . | tee errlink | spill-guard filter",
		)
	}
	for _, command := range append(refused,
		"grep -rn foo . | tee /dev/stderr | spill-guard filter",
		"grep -rn foo . | tee /dev/fd/2 | spill-guard filter",
		"grep -rn foo . | tee -a /dev/stderr | spill-guard filter",
		"grep -rn foo . | tee /dev/tty | spill-guard filter",
		"grep -rn foo . | tee >(cat >&2) | spill-guard filter",
		"grep -rn foo . | tee \"$LOG\" | spill-guard filter",
		"grep -rn foo . | cat >&2 | spill-guard filter",
		"grep -rn foo . | head 1>&2 | spill-guard filter",
		"grep -rn foo . > >(cat >&2) | spill-guard filter",
		"grep -rn foo . | tee out.log | spill-guard filter; cat out.log",
		"grep -rn foo . | tee out.log | spill-guard filter | cat out.log",
		"grep -rn foo . | cat > out.log | spill-guard filter; cat out.log",
		"grep -rn foo . 2>err.log | spill-guard filter && cat err.log",
		"cat out.log & grep -rn foo . | tee out.log | spill-guard filter",
	) {
		t.Run(command+" is refused", func(t *testing.T) {
			reason := denyReason(t, bashCall(t, command, dir))
			if rewrite := rewriteIn(reason); rewrite != "" {
				t.Errorf("the reason names a rewrite %q", rewrite)
			}
		})
	}
	for _, command := range []string{
		"grep -rn foo . | tee out.log | spill-guard filter",
		"set -o pipefail; grep -rn foo . | tee -a out.log | spill-guard filter",
		"grep -rn foo . | tee /dev/null | spill-guard filter",
		"grep -rn foo . | head -5 | spill-guard filter",
		"grep -rn foo . | sort 2>/dev/null | spill-guard filter",
		"grep -rn foo . | spill-guard filter | tee out.log",
		"grep -rn foo . | tee //dev/null | spill-guard filter",
		"grep -rn foo . | tee sub/out.log | spill-guard filter",
		"grep -rn foo . | dd of=out.log status=none | spill-guard filter",
		"grep -rn foo . | env -C sub tee out.log | spill-guard filter",
		"grep -rn -f <(echo foo) . | spill-guard filter",
	} {
		t.Run(command+" is allowed", func(t *testing.T) {
			allowed(t, bashCall(t, command, dir))
		})
	}
	// The rewrite of a tee to a file is the control's shape, and is allowed.
	rewrite := rewriteIn(denyReason(t, bashCall(t, "grep -rn foo . | tee out.log", dir)))
	if rewrite == "" {
		t.Fatal("no rewrite for a tee to a file")
	}
	allowed(t, bashCall(t, rewrite, dir))
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
		"content over a path":  {"pattern": "foo", "path": dir, "output_mode": "content"},
		"content over the cwd": {"pattern": "foo", "output_mode": "content"},
		"a relative directory": {"pattern": "foo", "path": "sub", "output_mode": "content"},
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

// No mode is `files_with_matches`, the default the tool's schema declares.
func TestTheGrepToolModesThatReturnNoContentAreAllowed(t *testing.T) {
	dir := grepTree(t)
	for name, fields := range map[string]map[string]string{
		"files_with_matches": {"pattern": "foo", "path": dir, "output_mode": "files_with_matches"},
		"count":              {"pattern": "foo", "path": dir, "output_mode": "count"},
		"no mode":            {"pattern": "foo", "path": dir},
		"no mode or path":    {"pattern": "foo"},
	} {
		t.Run(name, func(t *testing.T) {
			allowed(t, grepToolCall(t, dir, fields))
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

// A pattern is text the call carries whatever its path does, so one that will
// not settle does not hide a key there. Before Q245 every arm here exited 0 with
// no verdict and one record, since the failure returned no buffers.
func TestTheGrepToolPatternIsScannedWhereItsPathCouldNotBeSettled(t *testing.T) {
	dir := t.TempDir()
	shut := filepath.Join(dir, "shut.txt")
	if err := os.WriteFile(shut, []byte("x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	// Root opens a 0o000 file and Windows ignores the mode, so the read succeeds
	// and that arm is not the one this table means.
	shutOpens := runtime.GOOS == "windows" || os.Geteuid() == 0
	for _, tc := range []struct {
		name, cwd, path string
	}{
		{"a relative path with no cwd", "", "notes.txt"},
		{"no path and no cwd", "", ""},
		{"a path that will not stat", dir, filepath.Join(dir, "a\x00b")},
		{"something neither a file nor a directory", dir, os.DevNull},
		{"a file that will not open", dir, shut},
	} {
		call := func(pattern string) string {
			fields := map[string]string{"pattern": pattern, "output_mode": "content"}
			if tc.path != "" {
				fields["path"] = tc.path
			}
			return grepToolCall(t, tc.cwd, fields)
		}
		t.Run(tc.name, func(t *testing.T) {
			if tc.path == shut && shutOpens {
				t.Skip("nothing stops this file being opened here")
			}
			code, stdout, stderr := drive(t, call(secret))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 with a block (stderr: %q)", code, stderr)
			}
			if stdout == "" {
				t.Fatalf("no verdict: the path hid the pattern (stderr: %q)", stderr)
			}
			if got := verdictOf(t, stdout); got != "deny" {
				t.Fatalf("permissionDecision = %q, want deny", got)
			}
			reason := reasonOf(t, stdout)
			if !strings.Contains(reason, `"aws-access-key-id"`) || !strings.Contains(reason, patternLabel) {
				t.Errorf("the reason does not name the rule in the pattern: %q", reason)
			}
			if m, _ := decision(t, stdout)["systemMessage"].(string); !strings.Contains(m, partlyRead) {
				t.Errorf("the verdict does not say the path went unread: %q", stdout)
			}
			if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
				t.Error("the verdict carries the value")
			}
			if got := readCoverage(t); len(got) != 0 {
				t.Errorf("a block wrote %d coverage record(s): %+v", len(got), got)
			}
		})
		t.Run(tc.name+", nothing in the pattern", func(t *testing.T) {
			if tc.path == shut && shutOpens {
				t.Skip("nothing stops this file being opened here")
			}
			code, stdout, stderr := drive(t, call("foo"))
			reason := deferred(t, code, stdout, stderr)
			if !strings.Contains(reason, "Part of this call was read and matched no rule") {
				t.Errorf("coverage reason = %q, want it to say the pattern was read", reason)
			}
			if got := readCoverage(t); len(got) != 1 {
				t.Errorf("wrote %d coverage record(s), want 1: %+v", len(got), got)
			}
		})
	}
}

// A refusal stops the call for what it would do, so a key beside one needs no
// match to stop it, and the reason stays the refusal's.
func TestTheGrepToolRefusalsStandBesideAKeyInThePattern(t *testing.T) {
	dir := grepTree(t)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"a directory": dir, "a guarded path": ".env"} {
		t.Run(name, func(t *testing.T) {
			reason := denyReason(t, grepToolCall(t, dir, map[string]string{
				"pattern": secret, "path": path, "output_mode": "content"}))
			if strings.Contains(reason, "aws-access-key-id") || strings.Contains(reason, secret) {
				t.Errorf("the reason is not the refusal's: %q", reason)
			}
		})
	}
}
