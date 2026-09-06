package hook

import (
	"strings"
	"testing"
)

// The grouping is the whole value of the subcommand, and it went wrong in the
// direction that looks right: eliding the outer quoted span reported every
// coverage failure on the machine as one class, self-consistently and with a
// plausible-looking count beside it. It was caught by driving the subcommand,
// which is why it is pinned here.
//
// The two directions are separate failures. Keeping the inner span fragments
// one class into one-per-command; dropping the outer span merges every class
// into one. A test asserting only that two identical reasons group together
// would pass for both.
func TestClassKeepsTheReasonAndElidesTheCommandName(t *testing.T) {
	glob := `Nothing scanned this call for secrets, because the scan could not ` +
		`be completed: "in the \"grep\" here, a file operand is a glob, so which ` +
		`files this command would read is not settled here". The call was not stopped.`
	variable := `Nothing scanned this call for secrets, because the scan could not ` +
		`be completed: "in the \"cat\" here, a file operand expands at run time, so ` +
		`what this command would read cannot be known before it runs". The call was not stopped.`

	t.Run("different reasons stay different", func(t *testing.T) {
		if class(glob) == class(variable) {
			t.Errorf("a glob and an unresolvable variable group together, so the "+
				"summary reports one class for every gap on the machine:\n%q", class(glob))
		}
	})

	t.Run("the same reason with a different command groups together", func(t *testing.T) {
		sed := `Nothing scanned this call for secrets, because the scan could not ` +
			`be completed: "in the \"sed\" here, a file operand is a glob, so which ` +
			`files this command would read is not settled here". The call was not stopped.`
		if class(glob) != class(sed) {
			t.Errorf("the same gap under two commands does not group:\n%q\n%q",
				class(glob), class(sed))
		}
	})

	t.Run("the distinguishing clause survives", func(t *testing.T) {
		got := class(glob)
		if !strings.Contains(got, "is a glob") {
			t.Errorf("class dropped the clause that names the gap: %q", got)
		}
		if strings.Contains(got, "grep") {
			t.Errorf("class kept the command name, which fragments the count: %q", got)
		}
	})
}
