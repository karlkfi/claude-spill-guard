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
// So the PreToolUse deny object -- the shape docs/design/README.md measures --
// is accepted, ignored, and the prompt goes to the model. No warning anywhere.
// Writing one encoding for both events would report a safety it is not
// providing on half of them.
//
// PreToolUse keeps the deny object rather than moving to the shape that works
// for both: it is what the design measured, and `decision`/`reason` is the
// older spelling of a PreToolUse verdict.
//
// The launcher deliberately disagrees with this package, and that is not
// drift. It writes `{"decision":"block","reason":…}` on both events, because
// it never learns which event it was invoked for -- hooks.json points it at
// both and the payload naming the event goes past on stdin. This package does
// know, so it writes the row the table gives each event; a component that does
// not has to write the row that holds for every event.
// scripts/check-launcher.py refuses the deny object there by name for exactly
// that reason. Restoring "consistency" between the two by moving the launcher
// back is the change that reintroduces a measured fail-open on every prompt.
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

// confirm writes the PreToolUse ask encoding, which is what the override
// downgrades a block to. It is stdout and exit 0 for the reason block is.
//
// Measured 2026-08-28 against Claude Code 2.1.238 on darwin/arm64, driving a
// real hook under `-p --output-format stream-json` and reading whether a
// marker the command echoes comes back in a tool_result:
//
//	hook stdout       | permission mode   | the marker | the model receives
//	empty (control)   | default           | present    | the command's output
//	a `deny` object   | default           | ABSENT     | the reason, verbatim
//	an `ask` object   | default           | ABSENT     | the reason, verbatim
//	an `ask` object   | bypassPermissions | ABSENT     | the reason, verbatim
//
// So an ask nobody can answer withholds the result exactly as a deny does,
// rather than running the call -- which is the direction that had to be ruled
// out before an escape hatch could be built on it, because the failure would
// have been an override that silently sent the secret.
//
// What that table does not establish is the other half: `-p` has no human in
// it, so it cannot show an ask reaching one. That rests on prod-guard 2.5.2
// shipping this encoding as its own override downgrade, and on the 2,457 asks
// resolved at a 41-second median in the corpus behind the `hook-verdict`
// skill. An interactive session under bypassPermissions is undriven.
//
// There is no ask on UserPromptSubmit, so this refuses that event rather than
// encoding one, exactly as block refuses an event it has no shape for. The
// override is read from command position and only PreToolUse has one, so no
// caller reaches the refusal today -- and the cost of it being a caller's
// branch instead of this function's is a future caller emitting a PreToolUse
// object on UserPromptSubmit, which the table above measures as accepted and
// ignored. The prompt would run with the secret in it and nothing would turn
// red.
func confirm(stdout io.Writer, event Event, reason string) error {
	if event != PreToolUse {
		return fmt.Errorf("no confirmation encoding for event %q", event)
	}
	return json.NewEncoder(stdout).Encode(preToolUseVerdict{preToolUseOutput{
		HookEventName:            string(PreToolUse),
		PermissionDecision:       "ask",
		PermissionDecisionReason: reason,
	}})
}

// The most findings a reason names. A file can match a rule hundreds of times
// and the reason is read by a model, not walked by a tool: past the first few
// the list stops telling anyone anything and starts being the message.
const maxListed = 10

// The opener on every reason this package writes, one per verdict. The name is
// at position 0 of both: a hook leaves no other record of having run, and a
// session with several installed cannot attribute a refusal that does not say
// which one made it.
//
// Neither names SPILL_GUARD_OVERRIDE, matching the launcher's reasons: telling
// the model how to proceed without a scan is handing it the bypass. The
// confirmation says an override is in play because one demonstrably is -- the
// text is unreachable otherwise -- and still does not spell it, because the
// human being asked can read it in the command in front of them.
const (
	blockedLead = "spill-guard: blocked. "
	confirmLead = "spill-guard: an override on this command turned a block " +
		"into this confirmation. Nothing has been waved through, and " +
		"approving sends what is named below. "
)

// unattended is the body for a hatch armed where no one can answer a
// confirmation.
//
// The downgrade's whole safety property is that somebody is told before the
// call runs, so it must not fire where the telling cannot happen. Blocking
// costs the user nothing they had: an ask nobody answers stops the call too,
// and this way the reason reaches the model instead of the session stalling on
// an unanswerable prompt. prod-guard 2.5.2 takes the same branch at
// scripts/bash-prod-guard.py:2547, for both halves of that argument.
//
// bypassPermissions and nothing else. The set of human-free modes is exactly
// that one, which is branch-guard's #33 rather than a reading of the docs:
// treating `auto` as unattended too was the defect there, because an ask in
// `auto` reaches a prompt somebody answers.
const unattended = "an override on this command asked to downgrade this to a " +
	"confirmation, and this session runs with permission prompts bypassed, so " +
	"there is nobody to answer one. The block stands. "

// noReasonGiven is the body for an override with nothing after the `=`.
//
// Articulating why is the whole of what this hatch controls for: it cannot
// stop a session that means it, and it can make one that is about to send a
// key by accident say out loud why it is fine. An empty value skips exactly
// that, so it is not an override.
const noReasonGiven = "The override on this command says nothing about why. " +
	"An override is an audit record before it is a switch, and an empty one " +
	"is a record nobody can read -- give it a reason and try again."

// found is the body of what the model is told about a call that matched.
//
// Rule id, path and byte offset, and nothing else. This text reaches the API,
// so a redacted eight-character window would be eight characters of the secret
// delivered to the place this tool exists to keep it away from.
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
	return fmt.Sprintf("%d rule match(es) in what this call would have sent: %s. "+
		"Nothing was sent. The values are not repeated here, because this text "+
		"reaches the API as well. Remove or rotate what the rules name, then try "+
		"again.", len(findings), strings.Join(items, "; "))
}

// unread is the body for a call carrying a buffer the pipeline declined to
// read.
//
// It is not failed(), which says nothing scanned this call: here the rest of the
// call was scanned, and a verdict that misreports its own coverage is the shape
// this package exists to refuse. It is not found() either, whose sentence names
// the matches in what this call would have sent -- true only of a call every
// buffer of which was read, which is why hook.go writes this one ahead of it.
//
// The label comes out of the call, so %q escapes it; the reason is this
// package's own fixed text and is not escaped.
// listSkips names each buffer and why it went unread, capped at maxListed. The
// label comes out of the call, so %q escapes it; the reason is this package's
// own fixed text.
func listSkips(skips []skipped) string {
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
	return strings.Join(items, "; ")
}

func unread(skips []skipped) string {
	return fmt.Sprintf("%d buffer(s) of what this call would have sent went "+
		"unread: %s. A buffer nothing opened produces no findings, exactly like "+
		"one that was read and held none, so an unread buffer is never reported "+
		"as a clean one.",
		len(skips), listSkips(skips))
}

// failed is the body for a scan that could not be completed.
//
// Every internal error blocks. That is the inversion this project makes
// against its sibling guards, and it is the whole of what a hook entry is for:
// a decoder that shrugs at a payload it cannot read, and lets the call
// through, reports a safety it is not providing and leaves nothing in the
// transcript to say so.
func failed(err error) string {
	return fmt.Sprintf("Nothing scanned this call for secrets, because the scan "+
		"could not be completed: %q. A scanner that cannot run blocks rather than "+
		"passing quietly -- silence from this hook is supposed to mean checked.",
		err.Error())
}

// noticeVerdict is text for the person, on a call this hook is allowing.
//
// `systemMessage` rather than stderr or a reason field, and that is measured.
// Driven 2026-09-01 against Claude Code 2.1.251 on darwin/arm64: six shapes
// from a real `UserPromptSubmit` hook, read back out of the
// `--output-format stream-json` stream and the session transcript both.
//
//	the hook writes (exit 0 unless noted) | the stream                   | the transcript
//	nothing -- the control                | --                           | --
//	a marker on stderr                    | --                           | --
//	a marker on stderr, exit 1            | --                           | hook_non_blocking_error
//	a marker on stdout, plain text        | --                           | hook_success, as context
//	{"systemMessage": marker}             | system/informational, notice | hook_system_message
//	{"…additionalContext": marker}        | --                           | hook_additional_context
//
// The `systemMessage` rows are the control for the blanks: the same instrument
// found the marker there, so those are absences rather than a probe that could
// not fire. None of the six withheld anything.
//
// PreToolUse is not measured and this does not claim it. It cannot reach a hook
// before the model has chosen a tool call, so an unauthenticated session cannot
// drive it. Emitting the field there anyway is safe in the direction that
// matters, and the table above the block encodings is what says so: stdout that
// is not a decision object runs the call, so a dropped field costs the silence
// that was already there rather than a call that should have stopped.
//
// docs/design/README.md, "An allowed skip says so", carries the argument, the
// corpus census behind it, and what would make it worth re-driving.
type noticeVerdict struct {
	SystemMessage string `json:"systemMessage"`
}

// notify writes a notice and withholds nothing. It is stdout and exit 0, and
// unlike block and confirm it takes no event: the field is the same on both,
// which is the half of the table above that is measured on one of them.
func notify(stdout io.Writer, message string) error {
	return json.NewEncoder(stdout).Encode(noticeVerdict{message})
}

// The opener on the notice, at position 0 for blockedLead's reason: a hook
// leaves no other record of having run, and this one is addressed to a person
// reading a session with several installed.
const noticeLead = "spill-guard: "

// unscanned is the body for buffers the pipeline declined to read on a call
// that is being allowed anyway.
//
// It is addressed to the person because the remedies are -- converting a file,
// arming an override -- and because the model would pay for it on every image
// read. It names the two text populations because the skip reason cannot tell them
// from an image: SkippedBinary is one reason over a NUL in the sniff window,
// so a UTF-16 buffer with no byte-order mark and a UTF-8 mark ahead of a NUL
// arrive here wearing a screenshot's label. Naming them is what lets a reader
// who knows their file is text act on a notice that says "binary".
func unscanned(skips []skipped) string {
	return fmt.Sprintf("this call was allowed, and %d buffer(s) of it went "+
		"unread: %s. Nothing scanned those for secrets. Text this build cannot "+
		"read arrives here wearing the same label as an image -- UTF-16 written "+
		"with no byte-order mark, or a UTF-8 mark ahead of a NUL -- so if one of "+
		"them is text, converting it to UTF-8 gets it scanned.",
		len(skips), listSkips(skips))
}
