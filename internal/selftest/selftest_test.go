package selftest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/hook"
	"github.com/karlkfi/claude-spill-guard/internal/scan"
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
	for _, a := range arms("a", "b", "c", "d") {
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
	planted, quiet, undecodable, binary := fixtures(t)
	list := arms(planted, quiet, undecodable, binary)
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
		flipped := arms(planted, quiet, undecodable, binary)
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
	planted, quiet, undecodable, binary := fixtures(t)
	broken := arms(planted, quiet, undecodable, binary)
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
	planted, quiet, undecodable, binary := fixtures(t)
	var out strings.Builder
	if failed := report(&out, arms(planted, quiet, undecodable, binary)); failed != 0 {
		t.Fatalf("%d arm(s) failed:\n%s", failed, out.String())
	}
	if !strings.Contains(out.String(), "blocked ("+canaryRule+")") {
		t.Errorf("no arm was blocked by %s, so either the canary or the rule "+
			"id has moved:\n%s", canaryRule, out.String())
	}
}

// The unread-buffer arm is blocked by a skip reason and by no rule at all,
// and the same payload is still an anomaly to an arm that expects a rule.
//
// Both halves are needed. The first is the branch the arm was added for: a
// verdict hook.Run reaches with zero findings, through `len(skips) > 0`, which
// no other arm here produces. The second is the control that keeps it from
// being a loosening -- `drive` reporting a block by anything other than what
// the arm named is what catches an over-matching rule, and an arm that has not
// named the skip has to still land there.
//
// What this does not establish is anything about an *allowing* arm. The arm is
// a blocking one, so it disagrees with every wrong value the way the blocking
// arms already did; the asymmetry Q107 named is untouched.
func TestTheUnreadArmNamesTheSkipAndTheCanaryArmsStillDoNot(t *testing.T) {
	planted, quiet, undecodable, binary := fixtures(t)
	var unread arm
	for _, a := range arms(planted, quiet, undecodable, binary) {
		if a.by == string(scan.SkippedUTF32) {
			unread = a
		}
	}
	if unread.payload == nil {
		t.Fatal("no arm names the UTF-32 skip, so the branch reached with no " +
			"findings behind it is unexercised again")
	}

	got, detail := drive(unread)
	if got != blocks {
		t.Errorf("the unread arm came back %s (%s), want blocked", got, detail)
	}
	if strings.Contains(detail, canaryRule) {
		t.Errorf("the unread arm's block names %s, so it is not the "+
			"no-finding branch: %s", canaryRule, detail)
	}

	// The same payload with no marker of its own, which is what every other
	// arm is. It has to be an anomaly, or naming a skip would have widened
	// what counts as a block for all of them.
	got, detail = drive(arm{payload: unread.payload})
	if got != anomalous {
		t.Errorf("the same payload wanting the canary's rule came back %s "+
			"(%s), want anomalous", got, detail)
	}
}

// Every anomaly `drive` can report, and the branch each one reaches.
//
// One payload per branch, because a test driving only the cheapest of them
// pins only the cheapest of them. The first version of this pinned the refusal
// alone, and reverting either of the other two branches to `allows` left the
// whole repository's suite green -- including the wrong-rule branch, which is
// the one the review was about.
//
// The three are not equally load-bearing, and the difference is worth knowing
// before anyone trims this table. A collapsed outcome is a *fail-open* only
// where a payload that produces no findings can reach it: a blocking arm
// disagrees with `allows` and `anomalous` alike and fails either way, so only
// an allowing arm can silently agree.
//
//   - the wrong-rule branch is that. Two ways in, not one: a rule that matches
//     too much, and -- with a perfectly correct ruleset -- any buffer the
//     pipeline declines to read, whose block names the skip rather than a rule.
//     It is the defect this table was written for. An arm that names that skip
//     as its own `by` lands on `blocks` instead, which is the point of the
//     field and is why the case below leaves `by` unset.
//   - the confirmation branch is not, for THIS arm list, because no arm here
//     carries an override. That is a property of the list rather than of
//     hook.Run: a zero-findings payload does reach a confirmation, through the
//     `len(skips) > 0` arm that sits ahead of the `len(findings) == 0` early
//     return -- driven, with an override and a UTF-32 file, giving an `ask`
//     carrying `unread` and no findings at all. So it is pinned as hardening
//     against an arm list somebody edits, not because it is a fail-open today.
//
// `payload could not be encoded` is absent for a stronger reason than either:
// every payload here is a map of strings and nested maps of strings, neither
// of which `json.Marshal` can fail on,
// so a case for it would assert an unreachable line and read as coverage.
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
	for i, a := range arms("a", "b", "c", "d") {
		if a.want == anomalous {
			t.Errorf("arm %d (%q) wants the outcome no arm may want", i, a.name)
		}
	}
}

// fixtures writes the three files the payloads point at.
func fixtures(t *testing.T) (planted, quiet, undecodable, binary string) {
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
	undecodable = filepath.Join(dir, "notes.utf32")
	if err := os.WriteFile(undecodable, utf32LE("no credentials in this one\n"), 0o600); err != nil {
		t.Fatalf("writing the undecodable file: %v", err)
	}
	binary = filepath.Join(dir, "heap.dump")
	if err := os.WriteFile(binary, append([]byte{0x00}, "AWS_ACCESS_KEY_ID="+canary+"\n"...), 0o600); err != nil {
		t.Fatalf("writing the binary canary file: %v", err)
	}
	return planted, quiet, undecodable, binary
}
