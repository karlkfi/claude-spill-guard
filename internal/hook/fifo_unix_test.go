//go:build unix

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// How long a call that is supposed to return gets before the test calls it
// hung. Every case here returns in microseconds when the guard is present, so
// this only has to be longer than a scheduler hiccup -- and it has to be
// short, because without the guard it is what the test costs instead of
// hanging the package until go test's own ten-minute deadline.
const fifoDeadline = 5 * time.Second

// mkfifo makes one in a temp dir with nothing on the other end, which is the
// shape that blocks: open(2) for reading waits for a writer that never comes.
func mkfifo(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "p.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no fifo here: %v", err)
	}
	return dir, path
}

// withinDeadline runs the hook and fails rather than waiting, so that a
// regression reports "hung" in five seconds instead of wedging the package.
//
// The goroutine is deliberately left running on the failing path. It is
// blocked in open(2) on a fifo in a directory t.TempDir will try to remove,
// and there is no way to interrupt it -- os.ReadFile takes no context. Losing
// one goroutine and a cleanup error is the price of the test reporting at all,
// and it only happens on the run where the guard is already gone.
func withinDeadline(t *testing.T, payload string) (code int, stdout string) {
	t.Helper()
	type result struct {
		code   int
		stdout string
	}
	done := make(chan result, 1)
	go func() {
		c, out, _ := drive(t, payload)
		done <- result{c, out}
	}()
	select {
	case r := <-done:
		return r.code, r.stdout
	case <-time.After(fifoDeadline):
		t.Fatalf("the hook did not return within %s, so it is opening what it "+
			"should have refused", fifoDeadline)
		return 0, ""
	}
}

// The row's case. `cat` on a fifo with no writer blocks in open(2), so without
// the guard this call never comes back: not a finding, not a refusal, not an
// error, and nothing in the transcript because no decision was reached.
//
// Inverted 2026-08-31 by deleting the IsRegular check in bash.go: this test
// reports "did not return within 5s" and its two neighbours below report the
// same, while every other test in the package still passes. That is what says
// the guard is what these three are measuring.
func TestABashOperandNamingAFifoBlocksInsteadOfHanging(t *testing.T) {
	dir, _ := mkfifo(t)
	code, stdout := withinDeadline(t, `{"hook_event_name":"PreToolUse",`+
		`"tool_name":"Bash","cwd":`+quote(t, dir)+`,`+
		`"tool_input":{"command":"cat p.fifo"}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object", code)
	}
	if !strings.Contains(reasonOf(t, stdout), "neither a file nor a directory") {
		t.Errorf("reason = %q, want it to name what it declined to open",
			reasonOf(t, stdout))
	}
}

// The os.Stat half of the same decision. os.Lstat reports a symlink as a
// symlink whatever it points at, so a guard written on it could not tell this
// case from a link to a regular file -- it would either hang here or refuse
// every symlinked file in a repo. Driven: Lstat gives Lrwxr-xr-x for both,
// os.Stat gives prw------- and -rw-------.
func TestABashOperandNamingASymlinkToAFifoBlocks(t *testing.T) {
	dir, path := mkfifo(t)
	if err := os.Symlink(path, filepath.Join(dir, "link")); err != nil {
		t.Skipf("no symlink here: %v", err)
	}
	code, stdout := withinDeadline(t, `{"hook_event_name":"PreToolUse",`+
		`"tool_name":"Bash","cwd":`+quote(t, dir)+`,`+
		`"tool_input":{"command":"cat link"}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object", code)
	}
	if !strings.Contains(reasonOf(t, stdout), "neither a file nor a directory") {
		t.Errorf("reason = %q, want it to name what it declined to open",
			reasonOf(t, stdout))
	}
}

// The Read arm takes its file_path straight from the tool, so the same fifo
// hangs it by the same open(2).
func TestAReadCallNamingAFifoBlocksInsteadOfHanging(t *testing.T) {
	_, path := mkfifo(t)
	code, stdout := withinDeadline(t, `{"hook_event_name":"PreToolUse",`+
		`"tool_name":"Read","tool_input":{"file_path":`+quote(t, path)+`}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object", code)
	}
	if !strings.Contains(reasonOf(t, stdout), "neither a file nor a directory") {
		t.Errorf("reason = %q, want it to name what it declined to open",
			reasonOf(t, stdout))
	}
}

// The control for all three, and the reason a symlink cannot simply be
// refused. Nothing here hangs, so without it a guard that blocked every
// symlink -- or every call -- would pass the three above and be caught by
// nothing.
func TestASymlinkToARegularFileIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.env")
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, "link.env")); err != nil {
		t.Skipf("no symlink here: %v", err)
	}
	code, stdout, stderr := drive(t, `{"hook_event_name":"PreToolUse",`+
		`"tool_name":"Bash","cwd":`+quote(t, dir)+`,`+
		`"tool_input":{"command":"cat link.env"}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); strings.Contains(reason, "neither a file nor a directory") {
		t.Fatalf("a symlink to a regular file was refused as one: %q", reason)
	}
}

// The decision the row asked to be taken rather than copied, pinned so that
// changing it is a decision too. A device sends nothing a rule can match, and
// it is refused anyway -- see bash.go for the traffic this costs and for why
// the class is not safe. /dev/null stands in for it on every unix and needs no
// mknod, which is also how prompt.go's test drives the same rule.
func TestABashOperandNamingADeviceIsRefusedRatherThanSkipped(t *testing.T) {
	code, stdout := withinDeadline(t, `{"hook_event_name":"PreToolUse",`+
		`"tool_name":"Bash","cwd":"/tmp",`+
		`"tool_input":{"command":"grep -l . /dev/null"}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object", code)
	}
	if !strings.Contains(reasonOf(t, stdout), "neither a file nor a directory") {
		t.Errorf("reason = %q, want the device refused rather than skipped",
			reasonOf(t, stdout))
	}
}
