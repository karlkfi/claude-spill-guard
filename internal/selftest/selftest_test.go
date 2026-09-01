package selftest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/hook"
	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

// run drives the subcommand the way main.go does and hands back everything a
// caller of the process would see.
func run(t *testing.T) (code int, stdout, stderr string) {
	t.Helper()
	var out, errs strings.Builder
	code = Run("test", &out, &errs)
	return code, out.String(), errs.String()
}

// The whole point of the subcommand: the shipped ruleset, driven through the
// real hook entry, does what every arm says it must.
//
// This is the arm that would go red if a rule were renamed, an encoding
// changed, or the operand resolver stopped resolving -- which is why the
// canary rule is named in the report rather than "blocked" alone.
func TestSelftestPassesOnTheShippedRuleset(t *testing.T) {
	code, stdout, stderr := run(t)
	if code != 0 {
		t.Fatalf("selftest exited %d, stderr %q\nstdout:\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Errorf("stderr is not empty on a clean run: %q", stderr)
	}
	if strings.Contains(stdout, "FAIL") {
		t.Errorf("an arm failed on the shipped ruleset:\n%s", stdout)
	}
	for _, a := range arms("a", "b") {
		if !strings.Contains(stdout, a.name) {
			t.Errorf("the report does not name the %q arm, so it either did "+
				"not run or ran without saying so:\n%s", a.name, stdout)
		}
	}
}

// Every arm has to be capable of failing, which is a different claim from
// every arm passing.
//
// An arm whose payload the hook treats the same either way passes whatever it
// expects, and a report made of such arms is green for a completely broken
// binary. So each expectation is flipped in turn and the run must disagree
// with exactly that one: no more, because a flip that breaks a neighbour means
// the arms are not independent, and no fewer, because a flip nothing notices
// is an arm asserting nothing.
func TestEveryArmDiscriminates(t *testing.T) {
	planted, quiet := fixtures(t)
	list := arms(planted, quiet)
	if len(list) < 4 {
		t.Fatalf("only %d arms, which is too few for the report to mean "+
			"anything -- every surface needs a blocking arm and a control", len(list))
	}

	var out strings.Builder
	if failed := report(&out, list); failed != 0 {
		t.Fatalf("%d arm(s) already fail, so a flip proves nothing:\n%s",
			failed, out.String())
	}

	for i := range list {
		flipped := arms(planted, quiet)
		was := flipped[i].want
		if was == blocks {
			flipped[i].want = allows
		} else {
			flipped[i].want = blocks
		}
		if flipped[i].want == was {
			t.Fatalf("arm %d (%q) did not flip, so this case tested nothing",
				i, list[i].name)
		}
		var got strings.Builder
		if failed := report(&got, flipped); failed != 1 {
			t.Errorf("flipping arm %d (%q) from %s to %s produced %d failure(s), "+
				"want exactly 1:\n%s", i, list[i].name, was, flipped[i].want,
				failed, got.String())
		}
	}
}

// A failing arm has to reach the exit code and the report, not just a counter.
func TestAFailingArmIsVisibleAndNonZero(t *testing.T) {
	planted, quiet := fixtures(t)
	broken := arms(planted, quiet)
	broken[0].want = allows
	if broken[0].want == blocks {
		t.Fatal("the first arm was already an allowing one, so this case " +
			"tested nothing -- reorder or pick another index")
	}

	var out strings.Builder
	failed := report(&out, broken)
	if failed != 1 {
		t.Fatalf("report counted %d failure(s), want 1:\n%s", failed, out.String())
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("a failing arm is not marked in the report:\n%s", out.String())
	}
}

// The report says what it cannot establish, and that sentence is the one most
// likely to be dropped by an edit tightening the output.
//
// Without it a green run reads as "the hook is live", which is exactly the
// claim no offline check can make and exactly the failure this project
// indicts its predecessor for.
func TestTheReportStatesWhatItCannotEstablish(t *testing.T) {
	_, stdout, _ := run(t)
	if !strings.Contains(stdout, "does not prove Claude Code is invoking the hook") {
		t.Errorf("the report does not say a green run leaves the live "+
			"question open:\n%s", stdout)
	}
}

// The canary has to be one the shipped ruleset still matches, and the rule
// named has to be the one that matches it. Both are asserted by the run above;
// this says so out loud, because the constant is what a rule rename breaks and
// the failure would otherwise read as "selftest is broken".
func TestTheCanaryIsMatchedByTheRuleItNames(t *testing.T) {
	planted, quiet := fixtures(t)
	var out strings.Builder
	if failed := report(&out, arms(planted, quiet)); failed != 0 {
		t.Fatalf("%d arm(s) failed:\n%s", failed, out.String())
	}
	if !strings.Contains(out.String(), "blocked ("+canaryRule+")") {
		t.Errorf("no arm was blocked by %s, so either the canary or the rule "+
			"id has moved:\n%s", canaryRule, out.String())
	}
}

// Every anomaly `drive` can report, and the branch each one reaches.
//
// One payload per branch, because a test driving only the cheapest of them
// pins only the cheapest of them. The first version of this pinned the refusal
// alone, and reverting either of the other two branches to `allows` left the
// whole repository's suite green -- including the wrong-rule branch, which is
// the one the review was about. A test that cannot fail for the reason it was
// written is worth what the branch it guards is worth.
//
// `payload could not be encoded` is deliberately absent. Every payload here is
// a map of strings, which `json.Marshal` cannot fail on, so a case for it
// would assert an unreachable line and read as coverage.
func anomalies(t *testing.T) []struct {
	name    string
	payload map[string]any
} {
	t.Helper()
	other := testvec.Load(t)["google-api-key"].Value
	if other == "" {
		t.Fatal("the vectors file has no google-api-key, so the wrong-rule case " +
			"below would drive a clean payload and test nothing")
	}
	return []struct {
		name    string
		payload map[string]any
	}{{
		// Refused rather than scanned: hook.Run takes exit 2 on an event it
		// cannot withhold content at.
		name:    "a payload the hook refuses",
		payload: map[string]any{"hook_event_name": "PostToolUse"},
	}, {
		// An override downgrades a block to a confirmation, whose reason opens
		// with confirmLead. Reading that as a pass would report a call the user
		// has not yet approved as one that was clean.
		name: "a confirmation rather than a block",
		payload: map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       hook.ToolBash,
			"permission_mode": "default",
			"tool_input": map[string]any{
				"command": "SPILL_GUARD_OVERRIDE=driving-a-selftest-case echo " + canary,
			},
		},
	}, {
		// Blocked, by a rule that is not the canary's. This is what a ruleset
		// that would not compile does to every call, and what one rule too many
		// does to a clean one.
		name: "a block by a rule that is not the canary's",
		payload: map[string]any{
			"hook_event_name": "UserPromptSubmit",
			"prompt":          "key " + other + " here",
		},
	}}
}

// An outcome that is neither a clean allow nor a block by the canary rule
// fails whatever the arm wanted.
//
// This is the hole the third state closed. With two states, `drive` reported
// four situations as two, and the anomalies collapsed onto `allows` -- so a
// *blocking* arm caught them and an *allowing* arm reported `ok`. A scanner
// that blocks everything then produces "7 of 7 arms as expected" at exit 0,
// which is the precision regression this repo calls the product.
//
// Each case runs both ways off one payload, so a later change that loosened
// the comparison for one direction is caught by the other.
func TestEveryAnomalyFailsWhicheverWayTheArmLeans(t *testing.T) {
	for _, c := range anomalies(t) {
		t.Run(c.name, func(t *testing.T) {
			got, detail := drive(arm{payload: c.payload})
			if got != anomalous {
				t.Fatalf("came back %s (%s), not anomalous, so neither case "+
					"below tests anything", got, detail)
			}
			for _, want := range []expectation{blocks, allows} {
				var out strings.Builder
				failed := report(&out, []arm{{
					name:    "an anomaly, wanted as " + want.String(),
					want:    want,
					payload: c.payload,
				}})
				if failed != 1 {
					t.Errorf("an arm wanting %s got an anomaly and %d failure(s) "+
						"were counted, want 1:\n%s", want, failed, out.String())
				}
				if !strings.Contains(out.String(), "FAIL") {
					t.Errorf("an arm wanting %s got an anomaly and was not "+
						"marked:\n%s", want, out.String())
				}
			}
		})
	}
}

// No arm may want the anomalous outcome.
//
// report() fails such an arm unconditionally, so setting one would produce a
// permanently red report rather than a silent hole -- but the shipped set
// asking for it at all would mean somebody had misread what the state is for.
func TestNoArmWantsTheAnomalousOutcome(t *testing.T) {
	for i, a := range arms("a", "b") {
		if a.want == anomalous {
			t.Errorf("arm %d (%q) wants the outcome no arm may want", i, a.name)
		}
	}
}

// fixtures writes the two files the payloads point at.
func fixtures(t *testing.T) (planted, quiet string) {
	t.Helper()
	dir := t.TempDir()
	planted = filepath.Join(dir, "deploy.env")
	if err := os.WriteFile(planted, []byte("AWS_ACCESS_KEY_ID="+canary+"\n"), 0o600); err != nil {
		t.Fatalf("writing the canary file: %v", err)
	}
	quiet = filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(quiet, []byte("no credentials in this one\n"), 0o600); err != nil {
		t.Fatalf("writing the control file: %v", err)
	}
	return planted, quiet
}
