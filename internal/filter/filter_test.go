package filter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

func run(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// The half that keeps this usable: output that matches nothing crosses whole
// and unchanged, with nothing on stderr to read as a finding.
func TestCleanOutputIsWrittenUnchanged(t *testing.T) {
	in := "./a.go:1:func foo() {}\n./b.go:7:\tfoo()\n"
	code, stdout, stderr := run(t, in)
	if code != 0 || stdout != in || stderr != "" {
		t.Errorf("got (%d, %q, %q), want (0, the input, nothing)", code, stdout, stderr)
	}
}

// A finding withholds everything, not only its own line, and says where it was
// without saying what.
func TestAFindingBlocksTheWholeOutput(t *testing.T) {
	key := testvec.Load(t).Get(t, "aws-access-key-id")
	in := "./a.go:1:func foo() {}\n./k.env:2:AWS_ACCESS_KEY_ID=" + key + "\n"
	code, stdout, stderr := run(t, in)
	if code != Blocked {
		t.Errorf("exit = %d, want %d", code, Blocked)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	for _, want := range []string{`"aws-access-key-id" on line 2`, "--redact", "grep -rl"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not name %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, key) || strings.Contains(stderr, key[4:12]) {
		t.Errorf("stderr carries the value: %q", stderr)
	}
}

// The exit statuses have to stay clear of grep's, or `set -o pipefail` reports
// a block that reads as "no match" or as grep's own error.
func TestTheExitStatusesAreNotGreps(t *testing.T) {
	for _, code := range []int{Blocked, Failed} {
		if code <= 2 {
			t.Errorf("status %d collides with one grep returns", code)
		}
	}
	if Blocked == Failed {
		t.Error("a block and a failure to run share a status")
	}
}

func TestRedactReplacesTheValueAndKeepsTheRest(t *testing.T) {
	key := testvec.Load(t).Get(t, "aws-access-key-id")
	in := "./a.go:1:func foo() {}\n./k.env:2:AWS_ACCESS_KEY_ID=" + key + " # prod\n"
	code, stdout, stderr := run(t, in, "--redact")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
	}
	want := "./a.go:1:func foo() {}\n./k.env:2:AWS_ACCESS_KEY_ID=" +
		"[spill-guard redacted: aws-access-key-id] # prod\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if !strings.Contains(stderr, "redacted") || !strings.Contains(stderr, "do not write it back") {
		t.Errorf("stderr does not say the output was changed: %q", stderr)
	}
}

// A value at the very start of the stream is the boundary the first version of
// redacted() got wrong: it wrote the bytes before a span only when there were
// any, and wrote the marker in the same branch, so a span at 0 kept no marker.
func TestRedactAtOffsetZero(t *testing.T) {
	key := testvec.Load(t).Get(t, "aws-access-key-id")
	_, stdout, _ := run(t, key+"\n", "--redact")
	if want := "[spill-guard redacted: aws-access-key-id]\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestAnUnknownArgumentWritesNothing(t *testing.T) {
	code, stdout, stderr := run(t, "anything\n", "--redcat")
	if code != Failed || stdout != "" || !strings.Contains(stderr, `"--redcat"`) {
		t.Errorf("got (%d, %q, %q), want (%d, nothing, the argument named)",
			code, stdout, stderr, Failed)
	}
}

// Output this cannot read is withheld rather than passed through. The hook can
// defer on such a buffer; this was asked for by name, and its only power is to
// withhold.
func TestUnreadableOutputIsWithheld(t *testing.T) {
	// A UTF-32LE byte-order mark, which this build declines to decode.
	code, stdout, stderr := run(t, "\xff\xfe\x00\x00h\x00\x00\x00")
	if code != Blocked || stdout != "" || !strings.Contains(stderr, "UTF-32") {
		t.Errorf("got (%d, %q, %q), want (%d, nothing, the reason)",
			code, stdout, stderr, Blocked)
	}
}
