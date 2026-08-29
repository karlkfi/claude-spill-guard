package hook

import (
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
)

// overrideVar is the escape hatch the design names, and an inline assignment
// prefix on the Bash command is the only place it is read from.
//
// Never os.Getenv. An exported variable and a settings.json `env` block are
// both durable, both silent, and both writable by the model --
// .claude/settings.local.json is one of them -- so an environment read would
// turn a per-call hatch into a standing one that nothing reports. A prefix
// sits in the command string itself, which is a place the model cannot reach
// from inside a scanned buffer and which the human sees in the transcript
// beside the call it excuses.
const overrideVar = "SPILL_GUARD_OVERRIDE"

// override reports whether this call carries the hatch, and what the caller
// gave as the reason.
//
// PreToolUse Bash only. A prompt and a Read path have no command position, so
// there is nowhere on either that is not content, and reading it out of one
// would be the in-band tag the design refuses.
//
// A prefix on any segment covers the whole call, matching prod-guard, because
// the call is what Claude Code approves and what this scans: the command
// string and every operand of it are one verdict, and there is no half of it
// to excuse separately.
//
// Every unreadable payload here comes back as no override, and every one of
// them is a call scanCall fails on for the same reason -- so the call blocks,
// which is what a hatch nobody could find has to mean.
func override(call payload, event Event) (why string, present bool) {
	if event != PreToolUse || call.ToolName == nil || *call.ToolName != ToolBash {
		return "", false
	}
	var in bashInput
	if err := unmarshalToolInput(ToolBash, call.ToolInput, &in); err != nil || in.Command == nil {
		return "", false
	}
	segments, err := bash.Segments(*in.Command)
	if err != nil {
		return "", false
	}
	for _, segment := range segments {
		// The assignments are what StripEnvPrefix drops, so they are the head
		// it did not return. Taking them by difference rather than by matching
		// the shape again keeps the one assignment regex in internal/bash,
		// which is a port and is not diverged from here.
		head := bash.StripShKeywords(segment.Tokens)
		rest := bash.StripEnvPrefix(head)
		for _, assignment := range head[:len(head)-len(rest)] {
			name, value, _ := strings.Cut(assignment, "=")
			if name == overrideVar {
				return value, true
			}
		}
	}
	return "", false
}
