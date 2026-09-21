package hook

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shellNamed points the ladder at a file of this name in a temporary
// directory, made executable, so the pin holds on a machine that has no
// /bin/bash and cannot be moved by one that does. Both variables are written
// on every call: leaving SHELL to the machine is what made this suite depend
// on the login shell of whoever ran it.
func shellNamed(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CODE_SHELL", path)
	t.Setenv("SHELL", path)
	return path
}

// bashShell pins the tool shell to bash, for a test about the expansion
// rather than about the shell. Measured on this change: without it 83
// subtests across seven tests pass under a bash login shell and fail under a
// zsh one, and a GitHub runner sets SHELL=/bin/bash -- so CI would have gone
// green while the machine, not the test, decided what was asserted.
func bashShell(t *testing.T) { shellNamed(t, "bash") }

// The ladder Claude Code picks the Bash tool's shell with, read for the one
// bit the expansion turns on. Q163 drove the harness's own steps; what is
// asserted here is this reading of them, including the two places it is
// deliberately narrower than the harness.
func TestTheToolShellIsBashOnlyWhenSomethingNamesBash(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sub   string // a directory to put it under, for a path-versus-base row
		shell string // the file made, and pointed at by the variable below
		as    string // which variable names it; the other is emptied
		taken bool   // whether the harness's substring test accepts the path
		want  bool
	}{
		{"CLAUDE_CODE_SHELL names bash", "", "bash", "CLAUDE_CODE_SHELL", true, true},
		{"CLAUDE_CODE_SHELL names zsh", "", "zsh", "CLAUDE_CODE_SHELL", true, false},
		{"SHELL names bash", "", "bash", "SHELL", true, true},
		// The 96 tool shells Q163 recovered from this machine's transcripts
		// are this row: a zsh login shell and no setting.
		{"SHELL names zsh", "", "zsh", "SHELL", true, false},
		// Accepted by the harness's substring test over the whole path, and
		// spawned, and it is not bash: the base name is what says how it globs.
		{"a path holding bash whose program is not", "bash-builds", "sh", "CLAUDE_CODE_SHELL", true, false},
		// The same substring, the other way: the harness takes it because the
		// path holds zsh, and it is bash, so it globs like bash.
		{"a bash under a directory named for zsh", "zsh-builds", "bash", "CLAUDE_CODE_SHELL", true, true},
		// Named by neither variable's test, so the harness falls past it --
		// and this falls with it rather than reading the name.
		{"a shell the ladder does not name", "", "fish", "SHELL", false, false},
		// The decoy, and the sharpest case for reading the base name: the
		// harness takes this path on the substring and spawns fish, which
		// recurses `**` as zsh does. Answering bash off the substring would
		// expand the glob and allow -- reintroducing, in the fix for it, the
		// under-scan this whole item exists to close. Both spellings driven
		// against the built binary.
		{"a fish under a directory named for bash", "opt-bashful-bin", "fish", "CLAUDE_CODE_SHELL", true, false},
		{"a fish under a directory named for zsh", "home-zshaw-bin", "fish", "CLAUDE_CODE_SHELL", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.sub != "" {
				dir = filepath.Join(dir, tc.sub)
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, tc.shell)
			if err := os.WriteFile(path, nil, 0o755); err != nil {
				t.Fatal(err)
			}
			// t.TempDir names the directory after the subtest, so a row
			// whose answer turns on the path holding neither word would be
			// decided by what the subtest is called. Asserting the harness's
			// own step separately is what keeps a rename from silently
			// moving a row to a different case.
			if got := shellNames(path); got != tc.taken {
				t.Fatalf("fixture: shellNames(%q) = %v, want %v -- this row is not the case it names", path, got, tc.taken)
			}
			t.Setenv("CLAUDE_CODE_SHELL", "")
			t.Setenv("SHELL", "")
			t.Setenv(tc.as, path)
			if got := toolShellIsBash(); got != tc.want {
				t.Errorf("toolShellIsBash() = %v, want %v for %s=%s", got, tc.want, tc.as, path)
			}
		})
	}
}

// CLAUDE_CODE_SHELL is read first and SHELL only after it, so a setting that
// names zsh is not repaired by a login shell that names bash. The reverse row
// is what this machine runs.
func TestTheSettingIsReadBeforeTheLoginShell(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bash", "zsh"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		setting, login string
		want           bool
	}{
		{"zsh", "bash", false},
		{"bash", "zsh", true},
	} {
		t.Run(tc.setting+" over "+tc.login, func(t *testing.T) {
			t.Setenv("CLAUDE_CODE_SHELL", filepath.Join(dir, tc.setting))
			t.Setenv("SHELL", filepath.Join(dir, tc.login))
			if got := toolShellIsBash(); got != tc.want {
				t.Errorf("toolShellIsBash() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The harness's acceptance test reads the whole path and this reads the base
// name, and the two are not the same reading: a setting naming a `sh` under a
// directory called `bash-builds` is a shell the harness takes and spawns, so
// the bash that SHELL names is never reached. Reading the base for acceptance
// as well would fall past the setting and answer bash for a shell the harness
// is not going to run.
func TestAPathTheHarnessTakesIsNotOvertakenByTheLoginShell(t *testing.T) {
	dir := t.TempDir()
	builds := filepath.Join(dir, "bash-builds")
	if err := os.Mkdir(builds, 0o755); err != nil {
		t.Fatal(err)
	}
	spawned := filepath.Join(builds, "sh")
	login := filepath.Join(dir, "bash")
	for _, p := range []string{spawned, login} {
		if err := os.WriteFile(p, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CLAUDE_CODE_SHELL", spawned)
	t.Setenv("SHELL", login)
	if toolShellIsBash() {
		t.Errorf("toolShellIsBash() = true, want false: the harness spawns %q, not %q",
			spawned, login)
	}
	if got := toolShell(); got != spawned {
		t.Errorf("toolShell() = %q, want %q -- the record names the shell that runs", got, spawned)
	}
}

// executableBy is split by platform -- access(2) on unix, the mode bits
// elsewhere -- and the two agree on every case reachable without an ACL, so
// this pins the contract rather than the difference. The difference is not
// testable here: making them disagree needs an ACL that says one thing and
// mode bits another, which no portable fixture can build, and the reason for
// preferring access(2) is in shell_unix.go.
func TestAFileIsExecutableOrTheShellCannotBeSpawned(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		mode fs.FileMode
		want bool
	}{
		{0o755, true},
		{0o700, true},
		{0o111, true},
		{0o644, false},
		{0o000, false},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("sh%o", tc.mode))
			if err := os.WriteFile(path, nil, tc.mode); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := executableBy(path, info.Mode()); got != tc.want {
				t.Errorf("executableBy(%s) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// A variable naming a file the harness could not spawn is not the shell, and
// the ladder moves on to the next one. The executable test is the harness's
// own, reproduced with the mode bits.
func TestAShellTheHarnessCouldNotSpawnIsNotTheShell(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "bash")
	if err := os.WriteFile(unreadable, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	zsh := filepath.Join(dir, "zsh")
	if err := os.WriteFile(zsh, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		setting, login string
		wantBash       bool
		wantShellNamed string
	}{
		// The bash the setting names cannot be run, so the zsh beside it is
		// the shell -- the arm that makes this a ladder rather than a lookup.
		{"a bash that is not executable falls to SHELL", unreadable, zsh, false, zsh},
		// Nothing names a shell at all. The harness walks a fixed list that
		// tries zsh first; this refuses the step instead and says so with an
		// empty path, which is the reason's other arm.
		{"nothing names a shell", "", "", false, ""},
		{"a relative path is not a path the harness took", "bin/bash", "", false, ""},
		{"a path that does not exist", filepath.Join(dir, "gone", "bash"), "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CLAUDE_CODE_SHELL", tc.setting)
			t.Setenv("SHELL", tc.login)
			if got := toolShellIsBash(); got != tc.wantBash {
				t.Errorf("toolShellIsBash() = %v, want %v", got, tc.wantBash)
			}
			if got := toolShell(); got != tc.wantShellNamed {
				t.Errorf("toolShell() = %q, want %q", got, tc.wantShellNamed)
			}
		})
	}
}

// The defect, end to end on the fixture Q163 drove: zsh recurses `**` and
// bash does not, so a key below the level bash's expansion reaches crossed on
// a clean exit with nothing recorded. The controls are what say the silent arm
// was an allow over the bash file set rather than a call that did nothing.
func TestARecursiveGlobIsNotAllowedUnderAShellThatRecursesIt(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "sub", "deep")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inert := "PORT=8080\n"
	key := "AWS_ACCESS_KEY_ID=" + secret + "\n"
	write(filepath.Join(dir, "top.env"), inert)
	write(filepath.Join(dir, "sub", "mid.env"), inert)
	write(filepath.Join(deep, "low.env"), key)

	t.Run("bash does not reach the key, and allows", func(t *testing.T) {
		bashShell(t)
		code, stdout, stderr := drive(t, bashCall(t, "cat **/*.env", dir))
		if code != 0 || stdout != "" {
			t.Fatalf("exit %d, stdout %q, want the allow this fix leaves alone (stderr: %q)",
				code, stdout, stderr)
		}
	})

	// The control for that allow: the same payload over a tree whose key sits
	// in the one file bash's expansion does reach. A deny here is what makes
	// the row above a considered allow over the bash file set.
	t.Run("bash reaches sub/mid.env, and denies", func(t *testing.T) {
		bashShell(t)
		write(filepath.Join(dir, "sub", "mid.env"), key)
		defer write(filepath.Join(dir, "sub", "mid.env"), inert)
		code, stdout, _ := drive(t, bashCall(t, "cat **/*.env", dir))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
			t.Errorf("reason = %q, want the rule named", reason)
		}
	})

	// The second control: the scanner can read the deep file, so the silence
	// above is the expansion and not the pipeline.
	t.Run("the deep file named directly denies", func(t *testing.T) {
		bashShell(t)
		code, stdout, _ := drive(t, bashCall(t, "cat sub/deep/low.env", dir))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
			t.Errorf("reason = %q, want the rule named", reason)
		}
	})

	t.Run("zsh reaches the key, so the call defers", func(t *testing.T) {
		zsh := shellNamed(t, "zsh")
		code, stdout, stderr := drive(t, bashCall(t, "cat **/*.env", dir))
		reason := deferred(t, code, stdout, stderr)
		if !strings.Contains(reason, "rather than bash") {
			t.Errorf("coverage reason = %q, want it to say the shell is not bash", reason)
		}
		if !strings.Contains(reason, zsh) {
			t.Errorf("coverage reason = %q, want it to name %q", reason, zsh)
		}
	})
}

// Every glob defers under a shell that is not bash, not `**` alone: the
// narrower fix rests on the rest of the expansion agreeing, which Q184 is the
// measurement for. The control below is the same call under bash.
func TestAGlobDefersWhereTheShellIsNotBash(t *testing.T) {
	dir, name := planted(t)
	for _, command := range []string{
		"cat *.env",
		"grep -n AWS *.env",
		"cat " + filepath.Join(dir, "*.env"),
		"cat ?eploy.env",
		"cat deplo[xy].env",
	} {
		t.Run(command, func(t *testing.T) {
			t.Run("zsh defers", func(t *testing.T) {
				shellNamed(t, "zsh")
				code, stdout, stderr := drive(t, bashCall(t, command, dir))
				if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "rather than bash") {
					t.Errorf("coverage reason = %q, want the shell named as the cause", reason)
				}
			})
			t.Run("bash still scans", func(t *testing.T) {
				bashShell(t)
				code, stdout, _ := drive(t, bashCall(t, command, dir))
				if code != 0 {
					t.Fatalf("exit code = %d, want 0", code)
				}
				if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
					t.Errorf("reason = %q, want the rule named", reason)
				}
			})
		})
	}
	// The scope control. A shell that is not bash puts a pattern on the
	// record and changes nothing else: a named file is opened and judged
	// under zsh exactly as under bash, so this is not the Bash surface going
	// quiet.
	t.Run("a named file is scanned under zsh too", func(t *testing.T) {
		shellNamed(t, "zsh")
		code, stdout, _ := drive(t, bashCall(t, "cat "+name, dir))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
			t.Errorf("reason = %q, want the rule named", reason)
		}
	})
}

// Where the ladder settles on nothing the record cannot name a shell, so it
// says what it does know: that nothing on the machine names bash. Reaching
// this arm needs both variables empty, which is the machine the harness would
// answer from its fixed list.
func TestAGlobDefersWhereNothingNamesAShell(t *testing.T) {
	dir, _ := planted(t)
	t.Setenv("CLAUDE_CODE_SHELL", "")
	t.Setenv("SHELL", "")
	code, stdout, stderr := drive(t, bashCall(t, "cat *.env", dir))
	reason := deferred(t, code, stdout, stderr)
	if !strings.Contains(reason, "nothing on this machine names bash") {
		t.Errorf("coverage reason = %q, want the unresolved ladder named", reason)
	}
}
