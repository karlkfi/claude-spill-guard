package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/scan"
)

// A rule id comes out of a JSON file and a path comes out of the call, so
// neither is this binary's own text, and both reach a terminal and the API.
// main.go pins the same property at the first string the binary emits.
func TestAReasonEscapesControlCharactersInWhatItNames(t *testing.T) {
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
			path := "a" + tc.raw + "b"
			reason := found([]scan.Finding{{RuleID: "some-rule", Path: path, Offset: 1}})
			if strings.Contains(reason, path) {
				t.Errorf("the reason carries the path raw: %q", reason)
			}
			if want := "a" + tc.escaped + "b"; !strings.Contains(reason, want) {
				t.Errorf("reason = %q, want it to name the path as %q", reason, want)
			}
		})
	}
}

// Past the first few the list stops telling anyone anything and starts being
// the message. The total still has to be the real one, or the reason
// under-reports what was found.
func TestAReasonCapsTheFindingsItNamesAndStillCountsThemAll(t *testing.T) {
	findings := make([]scan.Finding, maxListed+3)
	for i := range findings {
		findings[i] = scan.Finding{RuleID: "some-rule", Path: "f.env", Offset: i}
	}
	reason := found(findings)
	if got := strings.Count(reason, "some-rule"); got != maxListed {
		t.Errorf("the reason names %d finding(s), want %d", got, maxListed)
	}
	if !strings.Contains(reason, "and 3 more") {
		t.Errorf("reason = %q, want it to say how many it left out", reason)
	}
	if !strings.Contains(reason, "13 rule match(es)") {
		t.Errorf("reason = %q, want the real total", reason)
	}
}

// No reason tells the model how to proceed without a scan. The launcher's two
// reasons hold the same line, and for the same argument: naming the escape
// hatch in text the model reads is handing it the bypass. The confirmation is
// in here too -- it is the one reason that says an override exists, and it
// still must not spell what to type.
//
// The list is hand-kept, so a new verdict helper joins it by somebody
// remembering, and it has now been missed four times. unread() twice -- once
// when Q74 added it, and again when this crossing was written against a trunk
// that did not yet carry it -- then overran() with the scan's budget and
// dumped() with the shape refusal, added in two lanes that never saw each
// other's diff and each caught by a reviewer reading the change. No gate has
// said so on any of the four, which is the whole of Q89's argument and now has
// instances behind it.
func TestNoReasonNamesTheOverride(t *testing.T) {
	finding := []scan.Finding{{RuleID: "some-rule", Path: "f.env"}}
	skips := []skipped{{"f.bin", scan.SkippedUTF32}}
	// Every lead crossed with every body that lead can carry, rather than the
	// four somebody happened to think of. Still a hand-kept population -- Q89
	// is the row for deriving it -- but the crossing is what caught
	// confirmLead+failed, which Run reaches whenever a scan errors on an
	// overridden call.
	reasons := []string{blockedLead + unattended + found(finding)}
	for _, lead := range []string{blockedLead, confirmLead} {
		for _, body := range []string{found(finding), unread(skips),
			failed(errNoEvent), noReasonGiven, overran(budget), dumped("env")} {
			reasons = append(reasons, lead+body)
		}
	}
	// The notices are not bodies of a lead -- they carry noticeLead and reach
	// the person rather than the model -- so the crossing above cannot reach
	// them and they are named here. The property is the same one: a text that
	// tells its reader how to proceed without a scan is the bypass, whoever
	// reads it.
	reasons = append(reasons,
		noticeLead+unscanned(skips), noticeLead+alsoUnread(skips))
	// refuse writes to stderr rather than through a lead, so it is outside the
	// crossing above and has to be named separately -- which is itself the
	// argument for Q89.
	var errs bytes.Buffer
	refuse(&errs, errNoEvent)
	reasons = append(reasons, errs.String())

	for _, reason := range reasons {
		if strings.Contains(reason, "SPILL_GUARD_OVERRIDE") {
			t.Errorf("reason names the override: %q", reason)
		}
		if !strings.HasPrefix(reason, "spill-guard: ") {
			t.Errorf("reason does not open with the plugin name: %q", reason)
		}
	}
}

// block has one arm per event and no default that writes something. An event
// it has no encoding for has to return an error rather than an empty stdout,
// because empty stdout blocks nothing.
func TestBlockRefusesAnEventItHasNoEncodingFor(t *testing.T) {
	var out bytes.Buffer
	if err := block(&out, Event("PostToolUse"), "because", ""); err == nil {
		t.Errorf("block accepted an event it cannot encode, writing %q", out.String())
	}
	if out.Len() != 0 {
		t.Errorf("block wrote %q for an event it cannot encode", out.String())
	}
}

// Every verdict is one JSON object and nothing else, because Claude Code reads
// stdout as one and a second line is not a second verdict.
func TestEveryVerdictIsOneJSONObject(t *testing.T) {
	for _, event := range []Event{PreToolUse, UserPromptSubmit} {
		var out bytes.Buffer
		if err := block(&out, event, "because", ""); err != nil {
			t.Fatalf("%s: %v", event, err)
		}
		decoder := json.NewDecoder(&out)
		var first map[string]any
		if err := decoder.Decode(&first); err != nil {
			t.Fatalf("%s: %v", event, err)
		}
		if decoder.More() {
			t.Errorf("%s: stdout carries more than one object", event)
		}
	}
}

// A call that blocks and also carried a buffer nothing read says both, and the
// channel it says the second one on is per event.
//
// That split is measured rather than reasoned about: carry carries the table.
// Q84's field served both events on its own, so the reasonable prior was that
// it would here too -- and beside a decision object it does not. Each arm below
// asserts the shape its own event was driven on, because asserting the other
// one would pass on a build that had swapped them and shipped a notice nobody
// is shown.
func TestABlockingVerdictCarriesTheNoticeToo(t *testing.T) {
	// planted() writes the file the rule matches; this is the buffer beside it
	// that nothing opens. A leading NUL is what internal/scan sniffs for, and
	// SkippedBinary is the one skip reason that does not stop the call.
	unopened := func(t *testing.T, dir string) string {
		t.Helper()
		path := filepath.Join(dir, "core.dump")
		if err := os.WriteFile(path, []byte{0x00, 'j', 'u', 'n', 'k'}, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("PreToolUse writes it beside the deny", func(t *testing.T) {
		dir, name := planted(t)
		skipped := unopened(t, dir)
		_, stdout, _ := drive(t, bashCall(t, "cat "+name+" core.dump", dir))

		got := decision(t, stdout)
		if verdictOf(t, stdout) != "deny" {
			t.Fatalf("the call was not blocked: %q", stdout)
		}
		message, ok := got["systemMessage"].(string)
		if !ok {
			t.Fatalf("the block carries no notice, so the unread buffer told "+
				"nobody: %q", stdout)
		}
		if !strings.Contains(message, skipped) ||
			!strings.Contains(message, string(scan.SkippedBinary)) {
			t.Errorf("the notice does not name the buffer and why: %q", message)
		}
		// The notice reports that nothing looked. A sentence of found()'s in it
		// would make it a claim about coverage, which is the defect the notice
		// exists to close rather than one to reproduce.
		if strings.Contains(message, "rule match") {
			t.Errorf("the notice claims coverage of the buffer nothing read: %q", message)
		}
		// "went unread" rather than the sentence around it: a notice's wording
		// is rewritten by any change to what the pipeline can do, and this has
		// to keep asserting the claim across that. Weaker than a literal
		// phrase, so verdict.go's own inversion is what says it can still fail.
		if !strings.Contains(message, "went unread") {
			t.Errorf("the notice does not say nothing looked: %q", message)
		}
	})

	t.Run("UserPromptSubmit writes it into the reason", func(t *testing.T) {
		dir, name := planted(t)
		skipped := unopened(t, dir)
		_, stdout, _ := drive(t, `{"hook_event_name":"UserPromptSubmit","cwd":`+
			quote(t, dir)+`,"prompt":"read @`+name+` and @core.dump"}`)

		if _, ok := decision(t, stdout)["systemMessage"]; ok {
			t.Errorf("this event drops a systemMessage beside a block, so one "+
				"written here reaches nobody: %q", stdout)
		}
		reason := reasonOf(t, stdout)
		if !strings.Contains(reason, "aws-access-key-id") {
			t.Errorf("the reason does not name the rule that blocked: %q", reason)
		}
		if !strings.Contains(reason, skipped) {
			t.Errorf("the reason does not name the buffer nothing read: %q", reason)
		}
	})

	t.Run("a confirmation carries it as well", func(t *testing.T) {
		dir, name := planted(t)
		skipped := unopened(t, dir)
		_, stdout, _ := drive(t, bashCall(t,
			`echo hi && SPILL_GUARD_OVERRIDE="reviewed" cat `+name+" core.dump", dir))

		if got := verdictOf(t, stdout); got != "ask" {
			t.Fatalf("permissionDecision = %q, want ask", got)
		}
		// Worse here than on a block, because approving is the whole of what
		// this prompt is for: a human told what they are sending and not told
		// what went unread is approving a coverage nobody has.
		message, ok := decision(t, stdout)["systemMessage"].(string)
		if !ok || !strings.Contains(message, skipped) {
			t.Fatalf("the confirmation does not name the buffer nothing read: %q", stdout)
		}
	})

	// The arm that says the three above assert something. Same command with the
	// unread buffer taken out of it: still a block, and now no notice at all.
	// Without this, a build writing a notice on every verdict passes all three.
	t.Run("nothing unread, nothing said", func(t *testing.T) {
		dir, name := planted(t)
		_, stdout, _ := drive(t, bashCall(t, "cat "+name, dir))

		if verdictOf(t, stdout) != "deny" {
			t.Fatalf("the control did not block, so the arms above blocked for "+
				"some other reason: %q", stdout)
		}
		if _, ok := decision(t, stdout)["systemMessage"]; ok {
			t.Errorf("a call with nothing unread carries a notice: %q", stdout)
		}
	})
}
