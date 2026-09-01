package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/karlkfi/claude-spill-guard/internal/scan"
)

// A counting sequence and the first six hex letters, so a reader meeting it in
// a public repo can see it is synthetic without taking a comment's word for
// it. internal/rules/capture_test.go already uses it, which is where it comes
// from; it matches the rule and clears the entropy floor.
//
// Not AWS's own documented example key: a rule that drops what a vendor
// publishes as an example is one this repo wants, and it would leave every
// test below passing while asserting nothing.
const secret = "AKIA0123456789ABCDEF"

// drive runs the hook over one payload and hands back everything a caller of
// the process would see.
func drive(t *testing.T, payload string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	code = Run(strings.NewReader(payload), &out, &errs)
	return code, out.String(), errs.String()
}

// decision is the verdict on stdout, or a failure naming what was there.
func decision(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not one JSON object: %q (%v)", stdout, err)
	}
	return got
}

// reasonOf pulls the text the model receives out of either encoding, so a test
// asserting what a reason says does not have to know which event produced it.
func reasonOf(t *testing.T, stdout string) string {
	t.Helper()
	got := decision(t, stdout)
	if out, ok := got["hookSpecificOutput"].(map[string]any); ok {
		return out["permissionDecisionReason"].(string)
	}
	if r, ok := got["reason"].(string); ok {
		return r
	}
	t.Fatalf("stdout carries neither block encoding: %q", stdout)
	return ""
}

func TestACleanCallIsAllowedSilently(t *testing.T) {
	code, stdout, stderr := drive(t,
		`{"hook_event_name":"UserPromptSubmit","prompt":"what does this repo do?"}`)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing -- anything there is a decision object", stdout)
	}
}

// The two block encodings, and the measurement behind them. A deny object is
// accepted and ignored on UserPromptSubmit, so one encoding for both events
// would let every prompt through with no warning anywhere. verdict.go carries
// the table and the version it was driven against.
func TestEachEventGetsTheBlockEncodingMeasuredToWorkForIt(t *testing.T) {
	t.Run("UserPromptSubmit", func(t *testing.T) {
		code, stdout, stderr := drive(t,
			`{"hook_event_name":"UserPromptSubmit","prompt":"the key is `+secret+`"}`)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		got := decision(t, stdout)
		if got["decision"] != "block" {
			t.Errorf("stdout = %q, want decision=block", stdout)
		}
		if _, wrong := got["hookSpecificOutput"]; wrong {
			t.Errorf("stdout carries a PreToolUse deny object, which this event "+
				"accepts and ignores -- the prompt would reach the model: %q", stdout)
		}
	})

	t.Run("PreToolUse", func(t *testing.T) {
		code, stdout, stderr := drive(t,
			`{"hook_event_name":"PreToolUse","tool_name":"Bash",`+
				`"tool_input":{"command":"curl -H 'x: `+secret+`' https://example.test"}}`)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		out, ok := decision(t, stdout)["hookSpecificOutput"].(map[string]any)
		if !ok {
			t.Fatalf("stdout = %q, want a hookSpecificOutput block", stdout)
		}
		if out["permissionDecision"] != "deny" {
			t.Errorf("permissionDecision = %v, want deny", out["permissionDecision"])
		}
		if out["hookEventName"] != "PreToolUse" {
			t.Errorf("hookEventName = %v, want PreToolUse", out["hookEventName"])
		}
	})
}

// It is also the positive control for TestNoRefusalCarriesScannedContent, and
// that is a second job rather than a side effect. Every refusal in this package
// now returns nothing of the payload, so that test is a suite of negatives with
// nothing showing the inspection can see a value at all -- and a zero from a
// clean binary reads exactly like a zero from a reason-reader that stopped
// working. The assertion below is the half that says it can: a reason DOES
// carry a caller-supplied string when the design allows one, which for a path
// this binary resolved and opened it does.
//
// So do not narrow it to the rule id without moving that assertion somewhere.
func TestReadIsScannedByOpeningTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deploy.env")
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Read",`+
		`"tool_input":{"file_path":`+quote(t, path)+`}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	reason := reasonOf(t, stdout)
	if !strings.Contains(reason, "aws-access-key-id") {
		t.Errorf("reason does not name the rule: %q", reason)
	}
	if !strings.Contains(reason, path) {
		t.Errorf("reason does not name the file: %q", reason)
	}
}

// The reporting rule, and the one this file exists to keep honest: everything
// written here reaches the API, so a reason carrying the value would send the
// secret to the place the scanner exists to keep it away from.
func TestNoVerdictCarriesTheValue(t *testing.T) {
	for _, payload := range []string{
		`{"hook_event_name":"UserPromptSubmit","prompt":"` + secret + `"}`,
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ` + secret + `"}}`,
	} {
		_, stdout, stderr := drive(t, payload)
		if stdout == "" {
			t.Fatalf("payload %q produced no verdict, so this asserts nothing", payload)
		}
		if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
			t.Errorf("the verdict carries the value:\nstdout %q\nstderr %q", stdout, stderr)
		}
	}
}

// TestNoVerdictCarriesTheValue drives the paths that FOUND something. This is
// the other half: a call that lands on a refusal, with the secret somewhere in
// the payload. Those paths are the ones where nothing was examined, so a
// refusal that echoed the payload back would send the very thing it declined
// to scan -- and no test went near them until #43's reviewer said so.
//
// What a refusal may name is a path and an operand, both of which the design
// allows and both of which are decisions rather than accidents. What it must
// not carry is scanned content: a prompt body, a command string, or a file's
// contents.
// Its positive control is TestReadIsScannedByOpeningTheFile, which asserts a
// reason carries the path it names. Without that pairing every case here could
// pass against a reason-reader that had stopped seeing values, which is the
// shape this file spent a day finding in other people's tests and then in its
// own.
func TestNoRefusalCarriesScannedContent(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		payload string
	}{
		// The secret goes INSIDE the operand the refusal is about. The first
		// version of this case put it in a neighbouring segment -- `echo
		// <secret> && cat $UNSET` -- which passes whatever the refusal quotes,
		// so it could not fail for the shape that matters. Four resolve paths
		// were echoing the operand verbatim and this test said they were not.
		{"a variable in the operand",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"cat $HOME/` + secret + `"}}`},
		{"a glob in the operand",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"cat /secrets/` + secret + `*"}}`},
		{"another user's home in the operand",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"cat ~alice/` + secret + `"}}`},
		{"a relative operand after a directory change",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"cd /tmp && cat rel/` + secret + `"}}`},
		{"a relative operand with no cwd to resolve against",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash",` +
				`"tool_input":{"command":"cat rel/` + secret + `"}}`},
		{"an indirectly named list",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"sort --files0-from=` + secret + `"}}`},
		// argv[0] is the way the leak survives naming the command: the reader
		// is found by basename, so the directories above it are free text.
		{"a secret in the reader's own argv[0]",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"/tmp/` + secret + `/cat $UNSET"}}`},
		{"a command string beside an unresolvable operand",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + quote(t, dir) +
				`,"tool_input":{"command":"echo ` + secret + ` && cat $UNSET"}}`},
		// The Read arm quoted its file_path where the Bash arm had stopped
		// quoting its operand -- same binary, same unresolved token, opposite
		// answers. `file_path` being a path by contract does not change what
		// happened to this one, which is nothing.
		{"a relative file_path on a Read",
			`{"hook_event_name":"PreToolUse","tool_name":"Read",` +
				`"tool_input":{"file_path":"rel/` + secret + `"}}`},
		{"a prompt on an event that cannot withhold",
			`{"hook_event_name":"PostToolUse","prompt":"` + secret + `"}`},
		{"a tool_input that does not decode",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"` + secret + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, tc.payload)
			if code == 0 && stdout == "" {
				t.Fatalf("the call was allowed, so this asserts nothing about a refusal")
			}
			if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
				t.Errorf("a refusal carries the value:\nstdout %q\nstderr %q", stdout, stderr)
			}
		})
	}
}

// The one payload field a refusal echoes that is neither a path nor a rule id.
// Its length is not this binary's to assume, and the reason reaches the API.
func TestARefusalBoundsTheEventNameItEchoes(t *testing.T) {
	long := strings.Repeat("A", maxEventName*3)
	_, _, stderr := drive(t, `{"hook_event_name":"`+long+`"}`)
	if strings.Contains(stderr, long) {
		t.Errorf("the refusal echoed the whole event name: %q", stderr)
	}
	if !strings.Contains(stderr, long[:maxEventName]) {
		t.Errorf("stderr = %q, want it to name what arrived, clipped", stderr)
	}
}

// A file that is not there sends nothing, so blocking would claim a safety
// nobody needed and hide the tool's own error. Every other read failure is a
// file that exists and went unchecked, which blocks.
func TestAReadThatCannotBeCheckedBlocksAndAMissingFileDoesNot(t *testing.T) {
	dir := t.TempDir()

	t.Run("absent", func(t *testing.T) {
		code, stdout, stderr := drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Read",`+
			`"tool_input":{"file_path":`+quote(t, filepath.Join(dir, "gone.env"))+`}}`)
		if code != 0 || stdout != "" {
			t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
		}
	})

	// A directory rather than a mode-000 file: the read fails for every uid,
	// including the one CI runs as, so the control cannot pass by accident.
	t.Run("unreadable", func(t *testing.T) {
		code, stdout, _ := drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Read",`+
			`"tool_input":{"file_path":`+quote(t, dir)+`}}`)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 with a deny object", code)
		}
		if !strings.Contains(reasonOf(t, stdout), "scan could not be completed") {
			t.Errorf("reason = %q, want it to say the scan did not finish", reasonOf(t, stdout))
		}
	})
}

// A payload shape the decoder cannot act on blocks. Each of these is a call
// nothing scanned, and letting one through reports a safety it is not
// providing while leaving nothing in the transcript to say so.
func TestAPayloadThatCannotBeActedOnBlocks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		// exit2 is true where there is no event to encode a decision object
		// in, which is the only thing left that blocks without one.
		exit2 bool
	}{
		{"not JSON", `{"hook_event_name":`, true},
		{"no event", `{"prompt":"hello"}`, true},
		{"an event that cannot withhold", `{"hook_event_name":"PostToolUse"}`, true},
		{"no prompt", `{"hook_event_name":"UserPromptSubmit"}`, false},
		{"no tool_name at all",
			`{"hook_event_name":"PreToolUse","tool_input":{"command":"echo hi"}}`, false},
		{"an empty tool_name",
			`{"hook_event_name":"PreToolUse","tool_name":"","tool_input":{}}`, false},
		{"no tool_input", `{"hook_event_name":"PreToolUse","tool_name":"Read"}`, false},
		{"tool_input is not an object",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"echo hi"}`, false},
		{"no file_path",
			`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}}`, false},
		{"no command",
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, tc.payload)
			if tc.exit2 {
				if code != 2 {
					t.Errorf("exit code = %d, want 2 (stdout %q)", code, stdout)
				}
				if !strings.Contains(stderr, "spill-guard: blocked") {
					t.Errorf("stderr = %q, want a reason -- exit 2 sends it there", stderr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 with a decision object", code)
			}
			if !strings.Contains(reasonOf(t, stdout), "scan could not be completed") {
				t.Errorf("reason = %q, want it to say the scan did not finish",
					reasonOf(t, stdout))
			}
		})
	}
}

// A newer Claude Code adding a field must not block every call in every
// session until this binary is upgraded, which is the opposite of what the
// ruleset loader does with an unknown field and the same argument reversed.
func TestAFieldThisBinaryDoesNotKnowIsTolerated(t *testing.T) {
	code, stdout, stderr := drive(t, `{"hook_event_name":"UserPromptSubmit",`+
		`"prompt":"hello","some_field_from_a_later_release":{"a":1}}`)
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// The scanned set is closed and named. A tool outside it is a hooks.json
// matcher wider than the scanner rather than a call to judge -- and this is
// the test that goes red when the two stop agreeing.
func TestAToolThisPackageDoesNotScanIsNotJudged(t *testing.T) {
	code, stdout, stderr := drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Glob",`+
		`"tool_input":{"pattern":"**/*.env"}}`)
	if code != 0 || stdout != "" {
		t.Errorf("exit %d, stdout %q, want a silent 0 (stderr: %q)", code, stdout, stderr)
	}
}

// quote renders s as a JSON string, so a temp path with a backslash or a quote
// in it builds a payload rather than breaking one.
func quote(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A relative path resolves against this process's directory and not the
// tool's, so an os.ReadFile miss here would be a hit there. Refusing costs
// nothing: driven against a live Claude Code on 2026-08-27, file_path arrived
// absolute even where the model had only named the file.
func TestAReadWithARelativePathBlocks(t *testing.T) {
	code, stdout, _ := drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Read",`+
		`"tool_input":{"file_path":"secrets.env"}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a deny object", code)
	}
	if !strings.Contains(reasonOf(t, stdout), "relative file_path") {
		t.Errorf("reason = %q, want it to name the relative path", reasonOf(t, stdout))
	}
}

// The per-reason verdict Q74 decided. blocks() carries the argument for it; this
// pins both arms end to end, through the process a caller actually runs.
func TestAnUnreadBufferBlocksByTheReasonItWentUnread(t *testing.T) {
	read := func(t *testing.T, path string) (int, string, string) {
		t.Helper()
		return drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Read",`+
			`"tool_input":{"file_path":`+quote(t, path)+`}}`)
	}

	t.Run("UTF-32 blocks", func(t *testing.T) {
		// A byte-order mark is a declaration the file makes about itself, so
		// this is text this build cannot read rather than a buffer something
		// inferred was not text. The content is innocuous on purpose: the block
		// has to come from the skip, and a secret in here would leave a reader
		// unable to say which of the two produced it.
		body := []byte{0xFF, 0xFE, 0x00, 0x00}
		for _, r := range "the quick brown fox" {
			body = append(body, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
		}
		path := filepath.Join(t.TempDir(), "notes.txt")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := read(t, path)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if stdout == "" {
			t.Fatal("the call was allowed with nothing on stdout, so a buffer " +
				"that declared itself text and went unread was reported clean")
		}
		reason := reasonOf(t, stdout)
		if !strings.Contains(reason, string(scan.SkippedUTF32)) {
			t.Errorf("the reason does not say why the buffer went unread: %q", reason)
		}
		if !strings.Contains(reason, path) {
			t.Errorf("the reason does not name the file that went unread: %q", reason)
		}
		if strings.Contains(reason, "rule match") {
			t.Errorf("this is found()'s verdict, whose sentence claims a coverage "+
				"this call did not have: %q", reason)
		}
	})

	// The allowed arm, and the control beside it is what makes it a measurement.
	// Identical bytes without the leading NUL are scanned and blocked, so the
	// silence above is the skip rather than there being nothing in the file to
	// find -- which is the one other thing that would produce it.
	t.Run("a binary is allowed, and the same bytes without the NUL are not", func(t *testing.T) {
		body := "AWS_ACCESS_KEY_ID=" + secret + "\n"
		dir := t.TempDir()

		skipped := filepath.Join(dir, "core.dump")
		if err := os.WriteFile(skipped, append([]byte{0x00}, body...), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := read(t, skipped)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want nothing -- the binary skip is the one the "+
				"design took with a measurement, and it is allowed", stdout)
		}

		control := filepath.Join(dir, "deploy.env")
		if err := os.WriteFile(control, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr = read(t, control)
		if code != 0 {
			t.Fatalf("control: exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if stdout == "" {
			t.Fatal("the control was allowed too, so these bytes carry nothing " +
				"this ruleset matches and the arm above asserted nothing")
		}
		if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
			t.Errorf("the control blocks for some other reason than the key in it: %q", reason)
		}
	})
}

// The default arm, which is the half no fixture reaches: internal/scan can grow
// a skip reason without internal/hook being taught it, and a switch that let an
// unknown one through would allow a buffer nothing opened.
func TestASkipReasonThisPackageWasNotTaughtBlocks(t *testing.T) {
	if !blocks(scan.Skip("a reason internal/scan grew after this switch was written")) {
		t.Error("an unrecognised skip reason does not block, which is the fail-open direction")
	}
	// The three it was taught, so a default arm wide enough to swallow them all
	// fails here rather than passing as a stricter policy.
	if blocks(scan.Scanned) {
		t.Error("a buffer the pipeline read blocks")
	}
	if blocks(scan.SkippedBinary) {
		t.Error("SkippedBinary blocks; blocks() is where the argument for it not to lives")
	}
	if !blocks(scan.SkippedUTF32) {
		t.Error("SkippedUTF32 does not block")
	}
	// Q91's constant reaches the default arm on purpose rather than by
	// omission: it is a declared encoding, so it blocks for the reason
	// SkippedUTF32 does, and there is no case for it because the default
	// already gives that answer. Asserted here so the reasoning is exercised
	// and not merely written down -- adding a case returning false would leave
	// every other assertion in this test green.
	if !blocks(scan.SkippedUTF16Binary) {
		t.Error("SkippedUTF16Binary does not block; a declared encoding whose " +
			"decoded text is binary is still a buffer that declared itself text")
	}
}

// utf16bom is a UTF-16 buffer with its mark, for the pin below. The first
// character is deliberately not U+0000: FF FE 00 00 is the UTF-32LE mark and
// takes a different branch, which is a different assertion.
func utf16bom(t *testing.T, s string, bigEndian bool) []byte {
	t.Helper()
	out := []byte{0xFF, 0xFE}
	if bigEndian {
		out = []byte{0xFE, 0xFF}
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}

// The population that used to satisfy blocks()' description of what blocks and
// be allowed anyway. A UTF-16 mark declares the buffer text; internal/scan
// decodes it and finds a U+0000 in the sniff window. That returned
// SkippedBinary, which this package allows, so declaration and decoded content
// disagreed and the decoded side won.
//
// The predecessor of this test pinned that, said it pinned what the tree did
// rather than what it should do, and named the row that would rewrite it. This
// is the rewrite: internal/scan returns SkippedUTF16Binary now, which reaches
// blocks() as a reason it was never taught and blocks on the default arm.
//
// Nothing about the decode changed. The buffer is still classified binary and
// still classified so on its decoded content -- what it also carries now is
// that an encoding was declared before that check ran, which is the fact this
// package's verdict was always keyed on and the one the old constant dropped.
func TestADeclaredUTF16BufferWithANULBlocks(t *testing.T) {
	read := func(t *testing.T, path string) (int, string, string) {
		t.Helper()
		return drive(t, `{"hook_event_name":"PreToolUse","tool_name":"Read",`+
			`"tool_input":{"file_path":`+quote(t, path)+`}}`)
	}
	// Both marks, because the decode stage has an arm for each and they are only
	// the same constant today. A split that fixed one and missed the other would
	// leave a little-endian-only pin green with half the class still crossing.
	for _, mark := range []struct {
		name      string
		bigEndian bool
	}{{"UTF-16LE", false}, {"UTF-16BE", true}} {
		t.Run(mark.name, func(t *testing.T) {
			dir := t.TempDir()
			body := "# notes\nAWS_ACCESS_KEY_ID=" + secret + "\n"

			nulled := filepath.Join(dir, "declared.env")
			withNUL := utf16bom(t, "# notes\n\x00AWS_ACCESS_KEY_ID="+secret+"\n", mark.bigEndian)
			if err := os.WriteFile(nulled, withNUL, 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := read(t, nulled)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if stdout == "" {
				t.Fatalf("stdout is empty, so the call was allowed -- a declared " +
					"UTF-16 buffer holding a key crossed with nothing said")
			}
			// The reason, not just the block. What this buffer's user can act
			// on is being told the encoding and that the decoded text is what
			// held the NUL; the undeclared class's phrase would tell them their
			// file is binary, which for a PowerShell-written .env it is not.
			if reason := reasonOf(t, stdout); !strings.Contains(reason, string(scan.SkippedUTF16Binary)) {
				t.Errorf("the reason is %q, and it does not name the declared "+
					"UTF-16 skip", reason)
			}

			// The control, and it is what stops the assertion above being
			// satisfied by a buffer with nothing in it to find: the same text
			// without the U+0000 is decoded, scanned, and blocked on the key.
			control := filepath.Join(dir, "control.env")
			if err := os.WriteFile(control, utf16bom(t, body, mark.bigEndian), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr = read(t, control)
			if code != 0 {
				t.Fatalf("control: exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if stdout == "" {
				t.Fatal("the control was allowed too, so this UTF-16 text carries " +
					"nothing the ruleset matches and the assertion above asserted nothing")
			}
			if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
				t.Errorf("the control blocks for some other reason than the key in it: %q", reason)
			}
		})
	}
}

// The Read arm's directory case, told apart from a fifo for bash.go's reason.
// Before the guard the OS error said `is a directory`; the refusal replaced it
// and has to say at least as much.
func TestAReadCallNamingADirectorySaysSo(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := drive(t, `{"hook_event_name":"PreToolUse",`+
		`"tool_name":"Read","tool_input":{"file_path":`+quote(t, dir)+`}}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a deny object (stderr %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "names a directory") {
		t.Errorf("reason = %q, want it to name the directory case", reason)
	}
}
