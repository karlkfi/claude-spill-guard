package hook

import (
	"errors"
	"strings"
	"testing"
)

// decode is the outermost of several refusals, and the only one that can name
// the event in its reason. Run's own tests cannot see it: with decode leaking
// an event, targets and block both refuse downstream and the call still exits
// 2, so the observable contract holds while the layer that should have caught
// it does not. Driven as a mutation, that is the difference between a test
// that goes red and one that passes with the defect present.
func TestDecodeRefusesAPayloadItCannotActOn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		names   string
	}{
		{"not JSON", `{`, "not JSON"},
		{"no event", `{"prompt":"hello"}`, "names none"},
		{"an event that cannot withhold", `{"hook_event_name":"PostToolUse"}`, "PostToolUse"},
		{"an event nobody has heard of", `{"hook_event_name":"Whatever"}`, "Whatever"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, event, err := decode([]byte(tc.payload))
			if err == nil {
				t.Fatalf("decode accepted it, returning event %q", event)
			}
			if !errors.Is(err, errNoEvent) {
				t.Errorf("err = %v, want it to wrap errNoEvent -- that is what "+
					"sends Run to exit 2 rather than to a decision object", err)
			}
			if event != "" {
				t.Errorf("event = %q, want it empty when there is no verdict shape", event)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("err = %v, want it to name %q", err, tc.names)
			}
		})
	}
}

func TestDecodeAcceptsTheTwoEventsThatCanWithholdContent(t *testing.T) {
	for _, want := range []Event{PreToolUse, UserPromptSubmit} {
		_, got, err := decode([]byte(`{"hook_event_name":"` + string(want) + `"}`))
		if err != nil {
			t.Errorf("decode(%s): %v", want, err)
		}
		if got != want {
			t.Errorf("event = %q, want %q", got, want)
		}
	}
}
