package hook

import (
	"strings"
	"testing"
)

// The corpus, in both directions.
//
// This rule matches no bytes, so it has no file in testdata/corpus/ -- what
// stands in for the clean corpus is the second table, and its entries are the
// shapes a week of real sessions actually wrote. All 18 `env` calls in the
// seven days to 2026-08-31 were filtered, and the row that filed this says
// why that matters more than the positives: a guard that fires on the careful
// form teaches the session to stop being careful, which is worse than no guard.
var (
	dumps = []string{
		"env",
		"printenv",
		"set",
		"export",
		"export -p",
		"declare -p",
		"typeset -p",
		"/usr/bin/env",
		"cd /tmp && env",
		"env > vars.txt",
		"env; echo done",
		"echo $(env)",
		`python3 -c "print(dict(os.environ))"`,
		`python3 -c 'print(os.environ)'`,
		`node -e "console.log(process.env)"`,
	}
	// Every entry here is a command that names or filters, and none of them
	// writes the environment where the model reads it.
	filtered = []string{
		"env | cut -d= -f1",
		"env | grep -E '^CCTEST_'",
		"env | wc -l",
		"env | sort | head -20",
		"printenv PATH",
		"printenv PATH HOME",
		"env FOO=1 make",
		"env -i sh -c 'echo hi'",
		"set -euo pipefail",
		"set -e",
		"declare -p PATH",
		"export FOO=1",
		"echo hi",
		`python3 -c "print(os.environ['PATH'])"`,
		`python3 -c "print(os.environ.get('PATH'))"`,
		`node -e "console.log(process.env.PATH)"`,
		`node -e "console.log(process.env['PATH'])"`,
	}
)

func TestAnEnvironmentDumpIsRefusedOnItsShape(t *testing.T) {
	for _, command := range dumps {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if got := verdictOf(t, stdout); got != "deny" {
				t.Errorf("permissionDecision = %q, want deny", got)
			}
		})
	}
}

// The half that decides whether this rule is worth having. A deny here is not
// a false positive to be traded off -- it is the rule doing the thing the row
// says is worse than doing nothing.
func TestTheFilteredFormsAreNotRefused(t *testing.T) {
	for _, command := range filtered {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := drive(t, bashCall(t, command, t.TempDir()))
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing -- this call carries no "+
					"secret and dumps nothing, so nothing should be written",
					stdout)
			}
		})
	}
}

// A deny that only says no costs a turn and teaches nothing. The whole
// argument for denying rather than asking is that the model can apply what the
// reason names, so the reason has to name it.
func TestTheRefusalNamesTheFilteredForm(t *testing.T) {
	_, stdout, _ := drive(t, bashCall(t, "env", t.TempDir()))
	reason := reasonOf(t, stdout)
	for _, want := range []string{"printenv PATH HOME", "env | cut -d= -f1", "${FOO:+set}"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not name %q: %q", want, reason)
		}
	}
	// One opener, not two. decide() is what prepends it, so a body that
	// carries its own arrives doubled -- and every assertion above passes
	// either way, because HasPrefix and Contains are both satisfied by the
	// broken string. This was the shipped state until the binary was driven.
	if n := strings.Count(reason, blockedLead); n != 1 {
		t.Errorf("the reason carries %d copies of %q: %q", n, blockedLead, reason)
	}
	// Not failed()'s sentence. That one says nothing scanned this call, which
	// is true here and is not why the call was refused; a reader who meets it
	// goes looking for a scan that broke.
	if strings.Contains(reason, "could not be completed") {
		t.Errorf("the reason reads as a scan that failed: %q", reason)
	}
}

// The hatch reaches this refusal like any other block. A session that has said
// out loud why it needs the dump gets a confirmation rather than a wall, which
// is what keeps the control proportionate to a threat model of accident.
func TestTheOverrideDowngradesAShapeRefusal(t *testing.T) {
	code, stdout, stderr := drive(t, bashCall(t,
		`SPILL_GUARD_OVERRIDE="checking what the harness injects" env`, t.TempDir()))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if got := verdictOf(t, stdout); got != "ask" {
		t.Errorf("permissionDecision = %q, want ask", got)
	}
	reason := reasonOf(t, stdout)
	if !strings.Contains(reason, "env | cut -d= -f1") {
		t.Errorf("the confirmation does not name the filtered form: %q", reason)
	}
	// A confirmation that also says "blocked" is telling the person being
	// asked two different things about what happened to their call.
	if strings.Contains(reason, blockedLead) {
		t.Errorf("the confirmation reads as a block: %q", reason)
	}
}

// The discriminator in an inline script is the character after the object, so
// these are the cases that decide it. Driven through the function rather than
// the hook because the hook cannot show which of the two spellings matched.
func TestWholeEnvironmentSeparatesTheMapFromOneVariable(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   bool
	}{
		{"print(dict(os.environ))", true},
		{"print(os.environ)", true},
		{"console.log(process.env)", true},
		{"import os,json;print(json.dumps(dict(os.environ)))", true},
		{"print(os.environ['PATH'])", false},
		{"print(os.environ.get('PATH'))", false},
		{"console.log(process.env.PATH)", false},
		{"console.log(process.env['PATH'])", false},
		{"print('nothing here')", false},
		// One reference either way in the same script: the map still crosses.
		{"print(os.environ['PATH']);print(os.environ)", true},
	} {
		if got := wholeEnvironment(tc.script); got != tc.want {
			t.Errorf("wholeEnvironment(%q) = %v, want %v", tc.script, got, tc.want)
		}
	}
}

// A dump inside a pipeline is the careful form and a dump at the end of one is
// not, which is the whole of what Segment.Pipe is read for here. The second
// arm is the one no plausible session writes and the one a rule keyed on
// position has to get right anyway.
func TestPositionInThePipelineDecidesIt(t *testing.T) {
	for command, wantRefused := range map[string]bool{
		"env | cut -d= -f1":       false,
		"cat /etc/hosts | env":    true,
		"env | cut -d= -f1 | env": true,
	} {
		t.Run(command, func(t *testing.T) {
			_, stdout, _ := drive(t, bashCall(t, command, t.TempDir()))
			refused := stdout != ""
			if refused != wantRefused {
				t.Errorf("refused = %v, want %v (stdout: %q)", refused, wantRefused, stdout)
			}
		})
	}
}
