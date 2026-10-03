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
// The inner span is a command name, and it used to be elided too. It is kept
// now, because which command hit a gap is what a reader acts on, and the set
// is the reader table's keys. A shell path in the same span is still elided.
func TestClassKeepsTheReasonAndTheCommandName(t *testing.T) {
	reason := func(command, clause string) string {
		return `Nothing scanned this call for secrets, because the scan could not ` +
			`be completed: "in the \"` + command + `\" here, a file operand ` + clause +
			`". The call was not stopped.`
	}
	glob := reason("grep", "is a glob, so which files this command would read is not settled here")
	variable := reason("cat", "expands at run time, so what this command would read cannot be known before it runs")

	t.Run("different reasons stay different", func(t *testing.T) {
		if class(glob) == class(variable) {
			t.Errorf("a glob and an unresolvable variable group together, so the "+
				"summary reports one class for every gap on the machine:\n%q", class(glob))
		}
	})

	t.Run("the same reason under two commands stays apart", func(t *testing.T) {
		sed := reason("sed", "is a glob, so which files this command would read is not settled here")
		if class(glob) == class(sed) {
			t.Errorf("grep and sed group together, so the summary cannot say "+
				"which command hit the gap:\n%q", class(glob))
		}
		again := reason("grep", "is a glob, so which files this command would read is not settled here")
		if class(glob) != class(again) {
			t.Errorf("one gap under one command does not group:\n%q\n%q",
				class(glob), class(again))
		}
	})

	t.Run("the distinguishing clause and the command survive", func(t *testing.T) {
		got := class(glob)
		if !strings.Contains(got, "is a glob") {
			t.Errorf("class dropped the clause that names the gap: %q", got)
		}
		if !strings.Contains(got, `"grep"`) {
			t.Errorf("class dropped the command name: %q", got)
		}
	})

	t.Run("a shell path in the inner span is elided", func(t *testing.T) {
		shell := func(path string) string {
			return `Nothing scanned this call for secrets, because the scan could not ` +
				`be completed: "in the \"cat\" here, a file operand is a glob and the ` +
				`Bash tool's shell is \"` + path + `\" rather than bash". The call was not stopped.`
		}
		a, b := class(shell("/opt/homebrew/bin/fish")), class(shell("/usr/bin/fish"))
		if a != b {
			t.Errorf("one gap on two installs does not group:\n%q\n%q", a, b)
		}
		if strings.Contains(a, "fish") {
			t.Errorf("the shell path survived the elision: %q", a)
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
		{[]string{"--since", "v1.2"}, 2},
		{[]string{"stray"}, 2},
		{[]string{"--nope"}, 2},
	} {
		if rc, _, _ := summarize(t, tc.args...); rc != tc.rc {
			t.Errorf("%q: exit %d, want %d", tc.args, rc, tc.rc)
		}
	}
}

// --since with a version reads the build that wrote each record, which is what
// "has this gap been fixed since" asks. A record no version can place -- one
// from before records carried a version, or a dev build -- is left out and
// counted, rather than guessed into either side.
func TestSinceAVersionLeavesOutOlderBuilds(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	dir := filepath.Join(state, "spill-guard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log := ""
	for _, r := range []struct{ version, reason string }{
		{"", "unversioned"},
		{"dev", "unversioned"},
		{"0.5.0", "older"},
		{"0.6.0-rc.1", "older"},
		{"0.6.0", "newer"},
		{"0.10.0", "newer"},
	} {
		log += `{"time":"2026-09-20T12:00:00Z","event":"PreToolUse","version":"` +
			r.version + `","reason":"` + r.reason + `"}` + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "coverage.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}

	rc, out, errs := summarize(t, "--since", "v0.6.0")
	if rc != 0 {
		t.Fatalf("exit %d, stderr %q", rc, errs)
	}
	assertHas(t, out,
		"2 record(s) before v0.6.0 left out.",
		"2 record(s) name no release",
		"2 call(s)",
		"(100.0%)  newer",
	)
	for _, leaked := range []string{"  older\n", "  unversioned\n"} {
		if strings.Contains(out, leaked) {
			t.Errorf("--since v0.6.0 counted a record it should have left out (%q):\n%s", leaked, out)
		}
	}
}

func TestVersionPrecedence(t *testing.T) {
	ordered := []string{"0.5.0", "0.6.0-alpha", "0.6.0-alpha.1", "0.6.0-alpha.beta",
		"0.6.0-rc.1", "0.6.0-rc.2", "0.6.0-rc.10", "0.6.0", "v0.6.1", "0.10.0", "1.0.0+build.5"}
	for i := 0; i+1 < len(ordered); i++ {
		a, okA := parseVersion(ordered[i])
		b, okB := parseVersion(ordered[i+1])
		if !okA || !okB {
			t.Fatalf("did not parse %q or %q", ordered[i], ordered[i+1])
		}
		if a.compare(b) >= 0 || b.compare(a) <= 0 {
			t.Errorf("%s should sort before %s", ordered[i], ordered[i+1])
		}
	}
	for _, bad := range []string{"", "dev", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "2026-09-28", "v1.x.3"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("%q parsed as a version", bad)
		}
	}
}
