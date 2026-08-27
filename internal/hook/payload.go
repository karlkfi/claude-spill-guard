package hook

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Event is the hook event a payload announces in `hook_event_name`.
//
// Only two of them can withhold content, so only two are worth wiring: a
// PostToolUse hook's verdict arrives after the result has been sent, measured
// in docs/design/README.md. Anything else reaching this binary is a hooks.json
// that asks for a scan this package cannot deliver, which is a configuration
// error rather than a call to wave through.
type Event string

const (
	PreToolUse       Event = "PreToolUse"
	UserPromptSubmit Event = "UserPromptSubmit"
)

// payload is a hook payload, in the fields this package reads.
//
// Unknown fields are tolerated on purpose, which is the opposite of what the
// ruleset loader does with its own file and is the same argument pointed the
// other way. A ruleset carrying a field the schema has no room for is a rule
// somebody wrote wrong, and refusing it costs one startup. A payload carrying
// one is a Claude Code that grew a field, and refusing that blocks every call
// in every session until this binary is upgraded. So the fail-closed line is
// drawn at the fields a decision actually rests on: each is a pointer, and a
// path that needs one and does not have it blocks.
type payload struct {
	HookEventName string `json:"hook_event_name"`
	// Prompt is the text the human typed, on UserPromptSubmit. Nil means the
	// field was absent, which is not the same as an empty prompt.
	Prompt *string `json:"prompt"`
	// ToolName and ToolInput describe the call, on PreToolUse. ToolName is a
	// pointer for the reason Prompt is: absent is a payload nobody can act on,
	// and as a plain string it collapsed onto "a tool this package does not
	// scan" -- which is an allow. Driven on a built binary, a PreToolUse
	// payload with a secret in its command and no tool_name exited 0 with
	// nothing on either stream, and the same payload naming Bash blocked.
	//
	// ToolInput stays raw because its shape is the tool's, and which tool it
	// is decides which shape to expect.
	ToolName  *string         `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// errNoEvent is what a caller cannot encode a verdict for: without an event
// there is no shape to write a block in, and Run falls back to exit 2.
var errNoEvent = errors.New("no hook event")

// decode reads a payload and returns the event it announces.
//
// The event comes back separately because everything after this point needs
// it to encode a verdict, and a payload that does not name one is the case the
// caller has to handle differently rather than a case with a default.
func decode(raw []byte) (payload, Event, error) {
	var got payload
	if err := json.Unmarshal(raw, &got); err != nil {
		return got, "", fmt.Errorf("%w: the payload on stdin is not JSON: %v",
			errNoEvent, err)
	}
	switch Event(got.HookEventName) {
	case PreToolUse, UserPromptSubmit:
		return got, Event(got.HookEventName), nil
	case "":
		return got, "", fmt.Errorf("%w: the payload names none", errNoEvent)
	default:
		return got, "", fmt.Errorf(
			"%w: %q is not an event this binary can withhold content at",
			errNoEvent, got.HookEventName)
	}
}

// readInput is one tool's arguments, in the fields this package reads. Both
// are pointers for the reason payload's are: absent and empty differ, and only
// one of them is a payload nobody can act on.
type readInput struct {
	FilePath *string `json:"file_path"`
}

type bashInput struct {
	Command *string `json:"command"`
}

// unmarshalToolInput decodes tool_input into v, naming the tool on failure.
func unmarshalToolInput(tool string, raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("the %s call carries no tool_input", tool)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("the %s call's tool_input does not decode: %v", tool, err)
	}
	return nil
}
