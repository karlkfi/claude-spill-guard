package hook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// See drive: a coverage failure appends to the state directory, and the
	// suite must not write into the developer's own log.
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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
	set, err := rules.Load(embedded.Shipped)
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
func TestAScanThatOverrunsItsBudgetDefers(t *testing.T) {
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
			// A budget already spent when run is entered, which within
			// answers without offering the scan a case to win. What it
			// cannot show is that the deadline fires once the match loop
			// has started, which is the arm below.
			code, stdout, stderr := driveWithin(t, 0, tc.payload)
			reason := deferred(t, code, stdout, stderr)
			if !strings.Contains(reason, "did not finish inside its") {
				t.Errorf("coverage reason = %q, want it to say the scan ran out of budget", reason)
			}
			if !strings.Contains(reason, "reached no verdict") {
				t.Errorf("coverage reason = %q, want it to say what the call would have sent reached no verdict", reason)
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
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "did not finish inside its") {
		t.Fatalf("coverage reason = %q, want the deadline to have fired mid-scan", reason)
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

// overrunAt drives a call whose budget runs out at the moment the scan reaches
// the named buffer, and which never gets through that buffer.
//
// No fixture and no timer, which is what makes this a statement about the code
// rather than about a rate: no file here reaches the shipped budget (Q132), and
// a short budget over a real scan is a race the match loop keeps winning as it
// gets faster (Q232). The deadline arrives from inside the scan, so whatever was
// settled ahead of that buffer is settled and nothing behind it can be.
//
// The scan's goroutine stays stalled until the test binary exits. Letting it go
// would have it open a file while the test's temporary directory is removed,
// which Windows refuses.
func overrunAt(t *testing.T, label, payload string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx, expire := context.WithCancel(context.Background())
	defer expire()
	pace := func(at string) {
		if filepath.Base(at) == label {
			expire()
			select {}
		}
	}
	var out, errs bytes.Buffer
	code = runPaced(ctx, pace, time.Now(), unhurried, strings.NewReader(payload), &out, &errs)
	return code, out.String(), errs.String()
}

// The two ways an overrun let a key through, on every surface that carries more
// than one buffer. Each case pairs a small buffer holding a key with a big one
// the budget runs out on, and each has to block naming the rule.
//
// The arms differ in the order the call names them. With the key first, a scan
// in call order finds it and an overrun threw the finding away. With the key
// last, a scan in call order never reached it. So dropping the gather reddens
// both and dropping the sort reddens only the second, which is why a test with
// the key first would not have been enough.
func TestAnOverrunStillBlocksOnTheBuffersItGotThrough(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("notes.txt", "AWS_ACCESS_KEY_ID="+secret+"\n")
	write("big.log", strings.Repeat("the quick brown fox jumps over the lazy dog\n", 1024))
	if err := os.Mkdir(filepath.Join(dir, secret), 0o700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(secret, "big.log"), strings.Repeat("hello\n", 1024))

	prompt := func(text string) string {
		return `{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
			`,"prompt":` + quote(t, text) + `}`
	}
	bash := func(command string) string {
		return `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
			`,"tool_input":{"command":` + quote(t, command) + `}}`
	}
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"prompt, key first", prompt("@notes.txt and @big.log")},
		{"prompt, key last", prompt("@big.log and @notes.txt")},
		{"Bash, key first", bash("cat notes.txt big.log")},
		{"Bash, key last", bash("cat big.log notes.txt")},
		{"Grep, key in the pattern", `{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{` +
			`"pattern":` + quote(t, secret) + `,"output_mode":"content",` +
			`"path":` + quote(t, filepath.Join(dir, "big.log")) + `}}`},
		{"Read, key in the file_path", `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{` +
			`"file_path":` + quote(t, filepath.Join(dir, secret, "big.log")) + `}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := overrunAt(t, "big.log", tc.payload)
			if code != 0 {
				t.Fatalf("exited %d (stderr %q)", code, stderr)
			}
			reason := reasonOf(t, stdout)
			if !strings.Contains(reason, "aws-access-key-id") {
				t.Errorf("reason = %q, want the planted key named", reason)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want no coverage record beside a block", stderr)
			}
			if !strings.Contains(stdout, "no verdict on this call is a report on the rest") {
				t.Errorf("stdout = %q, want it to say the verdict stops short", stdout)
			}
		})
	}
}

// Nothing matched in what the scan reached, so there is nothing to block on and
// the overrun defers as it always did. The control for the test above: without
// it, a hook that blocked on every overrun would pass.
func TestAnOverrunWithNothingFoundStillDefers(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"notes.txt": "nothing here\n", "big.log": strings.Repeat("hello\n", 1024)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := `{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
		`,"prompt":"@big.log and @notes.txt"}`
	code, stdout, stderr := overrunAt(t, "big.log", payload)
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "did not finish inside its") {
		t.Errorf("coverage reason = %q, want the overrun recorded", reason)
	}
}

// The verdict gathers what the scan stored while the scan goes on storing.
// overrunAt cannot show that, because its scan stops at the deadline. This one
// runs a real clock over enough buffers that the deadline lands among them, and
// what it asserts is nothing the verdict says: it is here for -race, and swapping
// an atomic slot for a plain pointer turns it red there.
//
// Cleaned up by hand because the scan can still have the last file open when the
// test ends, which Windows refuses to delete under t.TempDir.
func TestGatheringIsSafeWhileTheScanRuns(t *testing.T) {
	dir, err := os.MkdirTemp("", "spill-guard-gather")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var names []string
	for i := range 200 {
		name := fmt.Sprintf("f%d.txt", i)
		names = append(names, name)
		body := []byte("AWS_ACCESS_KEY_ID=" + secret + "\n")
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
		`,"tool_input":{"command":` + quote(t, "cat "+strings.Join(names, " ")) + `}}`
	for budget := time.Millisecond; budget < 64*time.Millisecond; budget *= 2 {
		if code, _, stderr := driveWithin(t, budget, payload); code != 0 {
			t.Errorf("at %s exited %d (stderr %q)", budget, code, stderr)
		}
	}
}

// A string the call carries goes ahead of every file, however short the file, so
// a read that never comes back cannot keep a key in the string from a verdict. A
// path can be longer than the file it names, and that is the arm size order loses.
func TestAStringTheCallCarriesIsMatchedAheadOfEveryFile(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{dir, filepath.Join(dir, secret)} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "tiny"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bash := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
		`,"tool_input":{"command":` + quote(t, "echo "+secret+"; cat tiny") + `}}`
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"prompt", `{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
			`,"prompt":` + quote(t, secret+" and @tiny") + `}`},
		{"Bash", bash},
		{"Read", `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{` +
			`"file_path":` + quote(t, filepath.Join(dir, secret, "tiny")) + `}}`},
		{"Grep", `{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{` +
			`"pattern":` + quote(t, secret) + `,"output_mode":"content",` +
			`"path":` + quote(t, filepath.Join(dir, "tiny")) + `}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := overrunAt(t, "tiny", tc.payload)
			if code != 0 {
				t.Fatalf("exited %d (stderr %q)", code, stderr)
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
				t.Errorf("reason = %q, want the key in the string named", reason)
			}
		})
	}
}

// Gathering the results walks all of them, so it happens once rather than per
// buffer. A call can name 150,000 files, and per buffer that spent the whole
// budget where base reached a verdict in seconds. Bytes allocated rather than time,
// because a clock is what Q232 says not to race: every file holds a finding, so a
// per-buffer gather copies a growing list and the total goes with the square.
func TestGatheringStaysLinearInTheBuffers(t *testing.T) {
	allocated := func(files int) uint64 {
		dir := t.TempDir()
		names := make([]string, files)
		for i := range names {
			names[i] = fmt.Sprintf("f%d", i)
			if err := os.WriteFile(filepath.Join(dir, names[i]), []byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
			`,"tool_input":{"command":` + quote(t, "cat "+strings.Join(names, " ")) + `}}`
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		code, stdout, stderr := driveWithin(t, unhurried, payload)
		runtime.ReadMemStats(&after)
		if code != 0 || !strings.Contains(stdout, "aws-access-key-id") {
			t.Fatalf("exited %d, stdout %q (stderr %q), want a block", code, stdout, stderr)
		}
		return after.TotalAlloc - before.TotalAlloc
	}
	small, large := allocated(500), allocated(4000)
	if ratio := float64(large) / float64(small); ratio > 16 {
		t.Errorf("8x the files allocated %.1fx the bytes (%d to %d), want about 8x", ratio, small, large)
	}
}

// An override still downgrades the block an overrun now reaches. Every other
// block here can be turned into a confirmation, and one that cannot is a class
// of refusal with no way past it.
func TestAnOverrideDowngradesABlockFromAnOverrun(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"notes.txt": "AWS_ACCESS_KEY_ID=" + secret + "\n", "big.log": strings.Repeat("hello\n", 1024)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
		`,"tool_input":{"command":"SPILL_GUARD_OVERRIDE='a fixture' cat big.log notes.txt"}}`
	code, stdout, stderr := overrunAt(t, "big.log", payload)
	if code != 0 {
		t.Fatalf("exited %d (stderr %q)", code, stderr)
	}
	if !strings.Contains(stdout, `"permissionDecision":"ask"`) {
		t.Errorf("stdout = %q, want a confirmation", stdout)
	}
}

// Smallest first holds for what reaches the disk as well as what reaches the
// match loop. A read has no deadline, so a big file opened ahead of the scan
// spends the budget before any buffer has been looked at.
//
// The file is rewritten as the scan passes the smaller buffer: read when its
// turn comes, the key is there to find, and read during the walk, it is not.
func TestABufferIsReadWhenItsTurnComes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	key := "AWS_ACCESS_KEY_ID=" + secret + "\n"
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
		`,"prompt":"look at @big.log"}`
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	pace := func(label string) {
		if label == promptLabel {
			if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	var out, errs bytes.Buffer
	code := runPaced(context.Background(), pace, time.Now(), unhurried, strings.NewReader(payload), &out, &errs)
	if code != 0 {
		t.Fatalf("exited %d (stderr %q)", code, errs.String())
	}
	if reason := reasonOf(t, out.String()); !strings.Contains(reason, "aws-access-key-id") {
		t.Errorf("reason = %q, want the key written after the walk found", reason)
	}
}

// A verdict names what it found in the order the call named it, however the
// sizes fall, so the sort stays out of the text.
func TestFindingsAreReportedInTheCallsOrder(t *testing.T) {
	dir := t.TempDir()
	key := "AWS_ACCESS_KEY_ID=" + secret + "\n"
	for name, body := range map[string]string{"a.txt": key + strings.Repeat("x ", 512), "b.txt": key} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := `{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
		`,"prompt":"@a.txt and @b.txt"}`
	code, stdout, stderr := driveWithin(t, unhurried, payload)
	if code != 0 {
		t.Fatalf("exited %d (stderr %q)", code, stderr)
	}
	reason := reasonOf(t, stdout)
	a, b := strings.Index(reason, "a.txt"), strings.Index(reason, "b.txt")
	if a < 0 || b < 0 || a > b {
		t.Errorf("reason = %q, want a.txt named ahead of b.txt", reason)
	}
}

// An override on a coverage failure changes nothing, and both modes agree.
//
// This is the half of the override contract that inverted on 2026-09-05. An
// overrun used to block, so the hatch downgraded it to a confirmation; now it
// defers, and there is no block left to downgrade. The hatch is not consulted
// at all -- abstain never reads it -- because a confirmation saying "approving
// sends what is named below" would be describing a call that was already
// proceeding, which is the most misleading string this package could print.
//
// Driven on both permission modes because the old behaviour differed between
// them: default got an ask, bypassPermissions got a deny. Neither happens now,
// and a regression restoring either would show up as a verdict on stdout.
func TestAnOverrideOnACoverageFailureIsInert(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "bypassPermissions"} {
		name := mode
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
				quote(t, dir) + `,"permission_mode":` + quote(t, mode) +
				`,"tool_input":{"command":` +
				`"SPILL_GUARD_OVERRIDE='it is a build log' cat clean.txt"}}`
			code, stdout, stderr := driveWithin(t, 0, payload)
			if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "did not finish inside its") {
				t.Errorf("coverage reason = %q, want the overrun recorded", reason)
			}
		})
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
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	code := run(time.Now().Add(-unhurried), unhurried, strings.NewReader(payload), &out, &errs)
	reason := deferred(t, code, out.String(), errs.String())
	if !strings.Contains(reason, "did not finish inside its") {
		t.Errorf("coverage reason = %q, want the budget already spent when the scan was reached", reason)
	}
}

// A spent budget is a verdict and not a coin flip.
//
// Every arm above that wants a coverage failure manufactures one by handing
// run a budget of zero, and until within answered that case up front it was a
// race: the timer is ready from the first instant, the scan is ready as soon
// as a few bytes are through the match loop, and a select among ready cases
// picks uniformly at random. It failed in CI once, on the fastest scan in the
// suite, and 800 repeats on an idle machine never reproduced it -- so a repeat
// count is not what closes this, and neither is a budget the scan merely
// usually loses.
//
// The file here is one a scan would decide on rather than a clean one, which
// is what makes the assertion about the race and not about the plumbing: if
// the scan is ever allowed to win this, the verdict is a deny naming a rule,
// which deferred() reports rather than absorbs. The control underneath proves
// that is the verdict on the table.
func TestASpentBudgetIsNotRacedByTheScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "planted.log")
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Read",` +
		`"tool_input":{"file_path":` + quote(t, path) + `}}`

	code, stdout, stderr := driveWithin(t, 0, payload)
	if reason := deferred(t, code, stdout, stderr); !strings.Contains(reason, "did not finish inside its") {
		t.Errorf("coverage reason = %q, want the spent budget recorded", reason)
	}

	// The positive control, and the reason the arm above is worth running: the
	// same file through an unhurried budget is a finding, so a defer over it is
	// the clock refusing to look and not a buffer with nothing in it.
	code, stdout, stderr = driveWithin(t, unhurried, payload)
	if code != 0 {
		t.Fatalf("the control exited %d (stderr %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
		t.Fatalf("the control reason = %q, want the planted key found", reason)
	}
}
