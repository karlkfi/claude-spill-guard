package hook

import (
	"bytes"
	"encoding/json"
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
// remembering. It has already been missed once -- unread() was added without
// it -- and there is no gate that would have said so.
func TestNoReasonNamesTheOverride(t *testing.T) {
	finding := []scan.Finding{{RuleID: "some-rule", Path: "f.env"}}
	// Every lead crossed with every body that lead can carry, rather than the
	// four somebody happened to think of. Still a hand-kept population -- Q89
	// is the row for deriving it -- but the crossing is what caught
	// confirmLead+failed, which Run reaches whenever a scan errors on an
	// overridden call.
	reasons := []string{blockedLead + unattended + found(finding)}
	for _, lead := range []string{blockedLead, confirmLead} {
		for _, body := range []string{found(finding), failed(errNoEvent), noReasonGiven} {
			reasons = append(reasons, lead+body)
		}
	}
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
	if err := block(&out, Event("PostToolUse"), "because"); err == nil {
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
		if err := block(&out, event, "because"); err != nil {
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
