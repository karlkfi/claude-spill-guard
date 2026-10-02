package hook

import (
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
