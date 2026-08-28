package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/scan"
)

// The two block encodings, one per event. They are not interchangeable, and
// the way they fail is silent in the direction this whole project is about.
//
// Measured 2026-08-27 against Claude Code 2.1.238 on darwin/arm64, by driving
// a real hook in a throwaway project and reading `--output-format stream-json`
// for whether the content reached the model:
//
//	                                | PreToolUse (Bash) | UserPromptSubmit
//	a `deny` decision object        | blocked           | RUNS
//	{"decision":"block","reason":…} | blocked           | blocked
//	exit 2, reason on stderr        | blocked           | blocked
//
// So the PreToolUse deny object -- the shape docs/design/README.md measures,
// and the one hooks/run-spill-guard.cmd writes -- is accepted, ignored, and
// the prompt goes to the model. No warning anywhere. Writing one encoding for
// both events would report a safety it is not providing on half of them.
//
// PreToolUse keeps the deny object rather than moving to the shape that works
// for both: it is what the design measured, it is what the launcher already
// emits and check-launcher.py already parses, and `decision`/`reason` is the
// older spelling of a PreToolUse verdict.
//
// docs/design/README.md, "The exit-code contract, measured", carries the table
// and the version it was taken against.
type preToolUseOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type preToolUseVerdict struct {
	HookSpecificOutput preToolUseOutput `json:"hookSpecificOutput"`
}

type promptVerdict struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// block writes the block encoding for event, carrying reason.
//
// It is stdout and exit 0, not exit 2: on exit 2 stdout is discarded and the
// model is told the hook errored, so the reason never arrives. A decision
// object blocks whatever the process then exits with, which is the one
// spelling that fails closed on its own.
func block(stdout io.Writer, event Event, reason string) error {
	var verdict any
	switch event {
	case PreToolUse:
		verdict = preToolUseVerdict{preToolUseOutput{
			HookEventName:            string(PreToolUse),
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		}}
	case UserPromptSubmit:
		verdict = promptVerdict{Decision: "block", Reason: reason}
	default:
		// decode returns errNoEvent rather than an unhandled event, and Run
		// takes exit 2 on that. Reaching here means this switch and that one
		// disagree, and writing nothing would let the call through.
		return fmt.Errorf("no block encoding for event %q", event)
	}
	return json.NewEncoder(stdout).Encode(verdict)
}

// The most findings a reason names. A file can match a rule hundreds of times
// and the reason is read by a model, not walked by a tool: past the first few
// the list stops telling anyone anything and starts being the message.
const maxListed = 10

// found is what the model is told about a blocked call.
//
// Rule id, path and byte offset, and nothing else. This text reaches the API,
// so a redacted eight-character window would be eight characters of the secret
// delivered to the place this tool exists to keep it away from.
//
// It does not name SPILL_GUARD_OVERRIDE, matching the launcher's reasons:
// telling the model how to proceed without a scan is handing it the bypass.
func found(findings []scan.Finding) string {
	listed, extra := findings, 0
	if len(listed) > maxListed {
		extra = len(listed) - maxListed
		listed = listed[:maxListed]
	}
	items := make([]string, 0, len(listed))
	for _, f := range listed {
		// %q escapes C0, DEL and the bidi overrides and delimits a path
		// carrying a space. Neither the rule id nor the path is this binary's
		// own text: one comes out of a JSON file and the other out of the
		// call, and both reach a terminal.
		items = append(items, fmt.Sprintf("%q at byte %d of %q", f.RuleID, f.Offset, f.Path))
	}
	if extra > 0 {
		items = append(items, fmt.Sprintf("and %d more", extra))
	}
	return fmt.Sprintf("spill-guard: blocked. %d rule match(es) in what this call "+
		"would have sent: %s. Nothing was sent. The values are not repeated here, "+
		"because this text reaches the API as well. Remove or rotate what the rules "+
		"name, then try again.", len(findings), strings.Join(items, "; "))
}

// unread is what the model is told about a call carrying a buffer the pipeline
// declined to read.
//
// It is not failed(), which says nothing scanned this call: here the rest of the
// call was scanned, and a verdict that misreports its own coverage is the shape
// this package exists to refuse. It is not found() either, whose sentence names
// the matches in what this call would have sent -- true only of a call every
// buffer of which was read, which is why hook.go writes this one ahead of it.
//
// The label comes out of the call, so %q escapes it; the reason is this
// package's own fixed text and is not escaped. It does not name
// SPILL_GUARD_OVERRIDE, for found()'s reason.
func unread(skips []skipped) string {
	listed, extra := skips, 0
	if len(listed) > maxListed {
		extra = len(listed) - maxListed
		listed = listed[:maxListed]
	}
	items := make([]string, 0, len(listed)+1)
	for _, s := range listed {
		items = append(items, fmt.Sprintf("%q (%s)", s.label, s.why))
	}
	if extra > 0 {
		items = append(items, fmt.Sprintf("and %d more", extra))
	}
	return fmt.Sprintf("spill-guard: blocked. %d buffer(s) of what this call would "+
		"have sent went unread: %s. A buffer nothing opened produces no findings, "+
		"exactly like one that was read and held none, so this blocks rather than "+
		"reporting a clean result for content nothing examined.",
		len(skips), strings.Join(items, "; "))
}

// failed is what the model is told when the scan could not be completed.
//
// Every internal error blocks. That is the inversion this project makes
// against its sibling guards, and it is the whole of what a hook entry is for:
// a decoder that shrugs at a payload it cannot read, and lets the call
// through, reports a safety it is not providing and leaves nothing in the
// transcript to say so.
func failed(err error) string {
	return fmt.Sprintf("spill-guard: blocked. Nothing scanned this call for secrets, "+
		"because the scan could not be completed: %q. A scanner that cannot run blocks "+
		"rather than passing quietly -- silence from this hook is supposed to mean "+
		"checked.", err.Error())
}
