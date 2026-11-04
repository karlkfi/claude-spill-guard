package hook

import (
	"strings"
	"testing"
)

func powershellCall(t *testing.T, command string) string {
	t.Helper()
	return `{"hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":` +
		quote(t, command) + `}}`
}

// The command string is what this surface reads, so a key in it blocks even
// though the same call also carries the gap.
func TestAKeyInAPowerShellCommandBlocks(t *testing.T) {
	code, stdout, stderr := drive(t, powershellCall(t, "Write-Output "+secret))
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(reasonOf(t, stdout), "aws-access-key-id") {
		t.Errorf("reason does not name the rule: %q", stdout)
	}
}

// A clean command is a record rather than an allow. Nothing here read the file
// this one opens, so exit 0 with nothing on stderr would report a scan that did
// not happen.
func TestACleanPowerShellCommandDefersAndIsRecorded(t *testing.T) {
	code, stdout, stderr := drive(t, powershellCall(t, "Get-Content notes.txt"))
	deferred(t, code, stdout, stderr)
	if !strings.Contains(stderr, "PowerShell") {
		t.Errorf("the record does not say which surface it is: %q", stderr)
	}
	got := readCoverage(t)
	if len(got) != 1 || got[0].Tool != ToolPowerShell {
		t.Fatalf("coverage records = %+v, want one for %s", got, ToolPowerShell)
	}
}

// A payload with no command is one nobody can act on. Falling through as an
// empty string would read as a clean scan of nothing.
func TestAPowerShellCallWithNoCommandDoesNotPassAsClean(t *testing.T) {
	code, stdout, stderr := drive(t, `{"hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{}}`)
	deferred(t, code, stdout, stderr)
	if !strings.Contains(stderr, "names no command") {
		t.Errorf("stderr = %q", stderr)
	}
}
