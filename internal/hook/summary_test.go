package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The grouping is the whole value of the subcommand, and it went wrong in the
// direction that looks right: eliding the outer quoted span reported every
// coverage failure on the machine as one class, self-consistently and with a
// plausible-looking count beside it. It was caught by driving the subcommand,
// which is why it is pinned here.
//
// The two directions are separate failures. Keeping the inner span fragments
// one class into one-per-command; dropping the outer span merges every class
// into one. A test asserting only that two identical reasons group together
// would pass for both.
func TestClassKeepsTheReasonAndElidesTheCommandName(t *testing.T) {
	glob := `Nothing scanned this call for secrets, because the scan could not ` +
		`be completed: "in the \"grep\" here, a file operand is a glob, so which ` +
		`files this command would read is not settled here". The call was not stopped.`
	variable := `Nothing scanned this call for secrets, because the scan could not ` +
		`be completed: "in the \"cat\" here, a file operand expands at run time, so ` +
		`what this command would read cannot be known before it runs". The call was not stopped.`

	t.Run("different reasons stay different", func(t *testing.T) {
		if class(glob) == class(variable) {
			t.Errorf("a glob and an unresolvable variable group together, so the "+
				"summary reports one class for every gap on the machine:\n%q", class(glob))
		}
	})

	t.Run("the same reason with a different command groups together", func(t *testing.T) {
		sed := `Nothing scanned this call for secrets, because the scan could not ` +
			`be completed: "in the \"sed\" here, a file operand is a glob, so which ` +
			`files this command would read is not settled here". The call was not stopped.`
		if class(glob) != class(sed) {
			t.Errorf("the same gap under two commands does not group:\n%q\n%q",
				class(glob), class(sed))
		}
	})

	t.Run("the distinguishing clause survives", func(t *testing.T) {
		got := class(glob)
		if !strings.Contains(got, "is a glob") {
			t.Errorf("class dropped the clause that names the gap: %q", got)
		}
		if strings.Contains(got, "grep") {
			t.Errorf("class kept the command name, which fragments the count: %q", got)
		}
	})
}

// The unread() body is the one that writes a path plain, so the quote-level
// elision above cannot reach it. Driven over a real log before this existed:
// fourteen records naming fourteen temp files grouped as fourteen classes.
//
// The negative half matters as much: eliding must not eat the sentence. A
// class that collapsed to "…" would group everything and read as working.
func TestClassElidesABarePathInTheUnreadBody(t *testing.T) {
	body := func(path string) string {
		return "1 buffer(s) of what this call would have sent went unread: " + path +
			" (UTF-32: declared by a byte-order mark, and not decoded). A buffer " +
			"nothing opened produces no findings."
	}
	a := class(body("/var/folders/cs/T/TestOne1409714058/001/notes.utf32"))
	b := class(body("/var/folders/cs/T/TestTwo232487459/001/notes.utf32"))

	if a != b {
		t.Errorf("two records of one shape did not group:\n%q\n%q", a, b)
	}
	if strings.Contains(a, "TestOne") || strings.Contains(a, "notes.utf32") {
		t.Errorf("the path survived the elision: %q", a)
	}
	if !strings.Contains(a, "went unread") || !strings.Contains(a, "UTF-32") {
		t.Errorf("the elision ate the sentence, so every class would collapse: %q", a)
	}
	// A Windows path arrives on the same body from a different machine.
	w := class(body(`C:\Users\k\AppData\Local\Temp\notes.utf32`))
	if strings.Contains(w, "AppData") {
		t.Errorf("a Windows path survived the elision: %q", w)
	}
}

// twoGenerations writes a rotated generation holding two records and a live
// one holding a third, and returns the live path.
func twoGenerations(t *testing.T) string {
	t.Helper()
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := filepath.Join(state, "spill-guard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "coverage.jsonl")
	old := `{"time":"2026-09-01T12:00:00Z","event":"PreToolUse","reason":"older"}` + "\n" +
		`{"time":"2026-09-02T12:00:00Z","event":"PreToolUse","reason":"older"}` + "\n"
	if err := os.WriteFile(path+".1", []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cur := `{"time":"2026-09-20T12:00:00Z","event":"PreToolUse","reason":"newer"}` + "\n"
	if err := os.WriteFile(path, []byte(cur), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func summarize(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	rc := Summarize(args, &out, &errw)
	return rc, out.String(), errw.String()
}

func assertHas(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("the report lacks %q:\n%s", want, got)
		}
	}
}

// A rotation moves every record but the newest into coverage.jsonl.1, so a
// report that read only the live file would describe the machine as having
// one gap. Both generations are counted, and the date range spans them.
func TestSummarizeCountsTheRotatedGeneration(t *testing.T) {
	path := twoGenerations(t)
	rc, out, errs := summarize(t)
	if rc != 0 {
		t.Fatalf("exit %d, stderr %q", rc, errs)
	}
	assertHas(t, out,
		"3 call(s)",
		"2026-09-01 to 2026-09-20",
		"     2  (66.7%)  older",
		"     1  (33.3%)  newer",
		path+".1\n"+path+"\n",
	)
}

// --since drops what was already reported, and says how much it dropped so a
// short report is not read as a machine with few gaps.
func TestSinceLeavesOutEarlierRecordsAndCountsThem(t *testing.T) {
	twoGenerations(t)
	rc, out, errs := summarize(t, "--since", "2026-09-02T13:00:00Z")
	if rc != 0 {
		t.Fatalf("exit %d, stderr %q", rc, errs)
	}
	assertHas(t, out, "2 record(s) before", "1 call(s)", "100.0%)  newer")
	if strings.Contains(out, "  older\n") {
		t.Errorf("a record before --since was counted:\n%s", out)
	}

	rc, out, _ = summarize(t, "--since", "2026-09-21")
	if rc != 0 || !strings.Contains(out, "Nothing was recorded since then.") {
		t.Errorf("exit %d, want the empty-window report:\n%s", rc, out)
	}
}

// A bare name is a file in the state directory; anything with a separator is
// a path as given.
func TestFileReadsOneLog(t *testing.T) {
	path := twoGenerations(t)
	for _, arg := range []string{"coverage.jsonl.1", path + ".1"} {
		rc, out, errs := summarize(t, "--file", arg)
		if rc != 0 {
			t.Fatalf("--file %s: exit %d, stderr %q", arg, rc, errs)
		}
		assertHas(t, out, "2 call(s)", "100.0%)  older")
		if strings.Contains(out, "  newer\n") {
			t.Errorf("--file %s read the live log too:\n%s", arg, out)
		}
	}
}

func TestSummarizeRefusesWhatItCannotHonour(t *testing.T) {
	twoGenerations(t)
	for _, tc := range []struct {
		args []string
		rc   int
	}{
		{[]string{"--file", "coverage.jsonl.2"}, 1},
		{[]string{"--since", "last tuesday"}, 2},
		{[]string{"stray"}, 2},
		{[]string{"--nope"}, 2},
	} {
		if rc, _, _ := summarize(t, tc.args...); rc != tc.rc {
			t.Errorf("%q: exit %d, want %d", tc.args, rc, tc.rc)
		}
	}
}
