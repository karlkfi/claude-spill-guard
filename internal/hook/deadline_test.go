package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	embedded "github.com/karlkfi/claude-spill-guard/rules"
)

// unhurried is the budget for an arm that is not about the deadline. It has to
// be long enough that a loaded runner cannot reach it by being slow, because an
// arm that times out where it meant to scan reports the wrong verdict for the
// right reason and reads exactly like the arm above it.
const unhurried = time.Hour

// driveWithin is drive with the budget handed in, which is the whole reason run
// takes one: the shipped budget is forty-five seconds and no test can wait for
// it.
func driveWithin(t *testing.T, budget time.Duration, payload string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	code = run(time.Now(), budget, strings.NewReader(payload), &out, &errs)
	return code, out.String(), errs.String()
}

// slowToScan writes a file the match loop cannot get through quickly, and
// returns its path.
//
// Size alone does not do it. A buffer no rule's prefilter clears runs at about
// 1 GiB/s, so a file big enough to outlast a deadline that way is too big for a
// test to write. What is slow is ordinary text carrying the literals the rules
// gate on -- one occurrence each is enough, and then every rule pays a full
// pass. docs/design/README.md, "The scanner's own budget", has the rates.
//
// The keywords come out of the shipped ruleset rather than a list here, so a
// rule added later is covered without anyone remembering to add it. Separated
// by spaces because a keyword is a prefix and not a match: `AKIA` needs sixteen
// more characters of its own alphabet, and the filler is lowercase and spaces.
func slowToScan(t *testing.T, size int, planted string) string {
	t.Helper()
	set, err := rules.Load(embedded.Shipped, nil)
	if err != nil {
		t.Fatalf("loading the compiled-in ruleset: %v", err)
	}
	var head strings.Builder
	gated := 0
	for _, rule := range set {
		if !rule.Enabled || len(rule.Keywords) == 0 {
			continue
		}
		head.WriteString(rule.Keywords[0])
		head.WriteByte(' ')
		gated++
	}
	if gated == 0 {
		t.Fatal("no enabled rule names a keyword, so nothing here is slow to scan")
	}

	var buf bytes.Buffer
	buf.Grow(size)
	buf.WriteString(head.String())
	for buf.Len() < size {
		buf.WriteString("the quick brown fox jumps over the lazy dog ")
	}
	if planted != "" {
		buf.WriteString("AWS_ACCESS_KEY_ID=" + planted + "\n")
	}

	path := filepath.Join(t.TempDir(), "big.log")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The row's case, and the only verdict that keeps this tool's promise.
//
// A scan that runs past the hook's own timeout is not a slow scan. The process
// is killed, whatever it was going to say is discarded, and the call proceeds
// -- so the choice at the deadline is between blocking and allowing silently,
// and there is no third answer to weigh. Both events, because the block
// encodings are not interchangeable and a wrong one on UserPromptSubmit is
// accepted and ignored.
func TestAScanThatOverrunsItsBudgetBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(path, []byte("nothing to see\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"Read", `{"hook_event_name":"PreToolUse","tool_name":"Read",` +
			`"tool_input":{"file_path":` + quote(t, path) + `}}`},
		{"Bash", `{"hook_event_name":"PreToolUse","tool_name":"Bash",` +
			`"cwd":` + quote(t, dir) + `,"tool_input":{"command":"cat clean.txt"}}`},
		{"prompt", `{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
			`,"prompt":"look at @clean.txt"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A budget already spent when run is entered, which reaches the
			// deadline without waiting for one. What it cannot show is that the
			// deadline fires once the match loop has started, which is the arm
			// below.
			code, stdout, stderr := driveWithin(t, 0, tc.payload)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, stderr)
			}
			reason := reasonOf(t, stdout)
			if !strings.Contains(reason, "did not finish inside its") {
				t.Errorf("reason = %q, want it to say the scan ran out of budget", reason)
			}
			if !strings.Contains(reason, "went unread") {
				t.Errorf("reason = %q, want it to say what the call would have sent went unread", reason)
			}

			// The control for the three above, and without it a hook that
			// blocked every call would pass all of them.
			code, stdout, stderr = driveWithin(t, unhurried, tc.payload)
			if code != 0 {
				t.Fatalf("the control exited %d (stderr %q)", code, stderr)
			}
			if stdout != "" {
				t.Errorf("the control wrote %q, want a clean call allowed silently", stdout)
			}
		})
	}
}

// The mechanism, which the arm above cannot reach: a deadline is worth nothing
// unless it fires while the work is running.
//
// Nothing here interrupts the scan -- os.ReadFile takes no context and neither
// does the match loop -- so the timer has to be scheduled against a goroutine
// that is not yielding. Go preempts one asynchronously and this is what says so
// on the code that ships, rather than on a claim about the runtime.
//
// The pair is the whole test. Over one file, a spent budget blocks on the
// clock and an unhurried one blocks on the key planted at its end, so the
// buffer is demonstrably scannable and demonstrably not scanned in time.
func TestTheDeadlineFiresWhileTheMatchLoopIsRunning(t *testing.T) {
	// Four mebibytes is about 0.6s of match loop at the worst rate measured
	// for this ruleset, which is thirty times the budget below. The ratio is
	// what makes this robust on a slower machine: every one of them moves the
	// scan away from the deadline rather than towards it.
	path := slowToScan(t, 4<<20, secret)
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Read",` +
		`"tool_input":{"file_path":` + quote(t, path) + `}}`

	code, stdout, stderr := driveWithin(t, 20*time.Millisecond, payload)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "did not finish inside its") {
		t.Fatalf("reason = %q, want the deadline to have fired mid-scan", reason)
	}

	// The positive control. The same file scans to a real finding, so the
	// block above is the clock and not the buffer.
	code, stdout, stderr = driveWithin(t, unhurried, payload)
	if code != 0 {
		t.Fatalf("the control exited %d (stderr %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
		t.Fatalf("the control reason = %q, want the planted key found", reason)
	}
}

// An overrun takes the same hatch every other block here takes.
//
// It is the same reading the override is built on: the scan still ran, nothing
// was waved through, and what an approval is worth is what is in front of the
// person approving. A block with no way past it would be the one class of
// refusal in this package that a user cannot answer.
func TestAnOverrunIsDowngradedByAnOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
		quote(t, dir) + `,"tool_input":{"command":` +
		`"SPILL_GUARD_OVERRIDE='it is a build log' cat clean.txt"}}`

	code, stdout, stderr := driveWithin(t, 0, payload)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, stderr)
	}
	got := decision(t, stdout)
	out, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("stdout carries no PreToolUse verdict: %q", stdout)
	}
	if out["permissionDecision"] != "ask" {
		t.Errorf("permissionDecision = %v, want ask", out["permissionDecision"])
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "did not finish inside its") {
		t.Errorf("reason = %q, want the confirmation to say what it is about", reason)
	}
}

// And the one mode where the downgrade has nobody to reach.
//
// A confirmation nobody can answer is not a confirmation, so the block stands
// and the reason goes to the model instead of the session stalling. Same
// branch as every other overridden block, which is why this asserts the arm
// rather than the argument.
func TestAnOverrunUnderBypassPermissionsStillBlocks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
		quote(t, dir) + `,"permission_mode":"bypassPermissions","tool_input":{"command":` +
		`"SPILL_GUARD_OVERRIDE='it is a build log' cat clean.txt"}}`

	code, stdout, stderr := driveWithin(t, 0, payload)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, stderr)
	}
	got := decision(t, stdout)
	out, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("stdout carries no PreToolUse verdict: %q", stdout)
	}
	if out["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision = %v, want deny where nobody can answer an ask",
			out["permissionDecision"])
	}
}

// The budget is spent before the scan starts, not after.
//
// Everything ahead of the scan is bounded by the payload rather than by the
// files a call names, so charging it costs nothing in the ordinary case. It is
// the case where it is not bounded that this is for: a budget started at the
// scan would give the whole timeout away to a prelude that hung, and the harness
// would kill the process rather than this blocking.
func TestThePreludeIsChargedAgainstTheBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Read",` +
		`"tool_input":{"file_path":` + quote(t, path) + `}}`

	var out, errs bytes.Buffer
	// A start an hour ago against a budget of an hour: nothing is left, and
	// the scan is never given a chance to be quick.
	code := run(time.Now().Add(-unhurried), unhurried, strings.NewReader(payload), &out, &errs)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, errs.String())
	}
	if reason := reasonOf(t, out.String()); !strings.Contains(reason, "did not finish inside its") {
		t.Errorf("reason = %q, want the budget already spent when the scan was reached", reason)
	}
}
