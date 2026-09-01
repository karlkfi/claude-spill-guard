package selftest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
