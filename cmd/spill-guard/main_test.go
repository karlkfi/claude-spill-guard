package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Errorf("stdout = %q, want %q", got, version)
	}
}

func TestRunExitsNonZeroWithoutACommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Errorf("stderr = %q, want the usage text", stderr.String())
	}
}

func TestRunExitsNonZeroOnAnUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan"}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

// The rejected argument reaches a terminal and the API otherwise. Escaping is a
// stated property of every string this binary emits, so it is pinned here at
// the first string it emits.
func TestRunEscapesControlCharactersInTheCommandItRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		escaped string
	}{
		{"C0", "\a", `\a`},
		{"DEL", "\x7f", `\x7f`},
		{"newline", "\n", `\n`},
		{"bidi override", "\u202e", `\u202e`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arg := "a" + tc.raw + "b"
			var stdout, stderr bytes.Buffer
			run([]string{arg}, nil, &stdout, &stderr)
			if strings.Contains(stderr.String(), arg) {
				t.Errorf("stderr carries the argument raw: %q", stderr.String())
			}
			if want := "a" + tc.escaped + "b"; !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want it to name the command as %q", stderr.String(), want)
			}
		})
	}
}

// The launcher passes stdin through untouched because the payload arrives
// there, so `hook` reading os.Stdin rather than an argument is the interface
// hooks.json will invoke. This pins the dispatch and the stream together: a
// `hook` that ignored stdin would pass every other test in this file.
func TestRunHookReadsThePayloadFromStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	payload := `{"hook_event_name":"UserPromptSubmit","prompt":"AKIA0123456789ABCDEF"}`
	if code := run([]string{"hook"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"decision":"block"`) {
		t.Errorf("stdout = %q, want the UserPromptSubmit block object", stdout.String())
	}
}

// The control on the test above: the same command with nothing on stdin has to
// come back blocking rather than clean, or a `hook` that read no payload at all
// would look identical to one that read a clean one.
func TestRunHookWithNoPayloadBlocks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2 (stdout: %q)", code, stdout.String())
	}
}

// TestMain points the coverage log at a temp directory for every test in this
// package.
//
// A coverage failure appends to $XDG_STATE_HOME, so without this the suite
// writes fixture reasons into the developer's own log. That is not a tidiness
// point: the log exists to answer "which resolver limitation costs the most",
// and 126 of the first 180 records on this machine were temp-dir paths from
// test runs, which is an answer to nothing.
//
// TestMain rather than a per-test helper because the helper is the thing that
// gets forgotten. This package reaches hook.Run through run, and a future test
// that calls it another way is covered here and would not be there.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "spill-guard-teststate")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_STATE_HOME", dir); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
