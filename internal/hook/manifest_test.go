package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The wiring Claude Code reads, in the fields a matcher is decided by.
type hookWiring struct {
	Hooks map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
		} `json:"hooks"`
	} `json:"hooks"`
}

// manifestPath is hooks.json from the package directory a `go test` runs in.
var manifestPath = filepath.Join("..", "..", "hooks", "hooks.json")

func loadWiring(t *testing.T) hookWiring {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		// Not a skip. A missing manifest is the omission this file exists to
		// catch, and a skipped test reports it as a green run.
		t.Fatalf("reading %s: %v", manifestPath, err)
	}
	var got hookWiring
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%s is not JSON Claude Code can read: %v", manifestPath, err)
	}
	if len(got.Hooks) == 0 {
		t.Fatalf("%s declares no hooks, so nothing fires", manifestPath)
	}
	return got
}

// The manifest decides what this package is handed, and the two ways of
// getting it wrong fail in opposite directions.
//
// A matcher wider than the scanner delivers calls toolTargets waves through:
// noisy at worst, and visible, because the hook runs and returns.
//
// An event the scanner handles and the manifest omits fires nothing at all --
// no payload, no verdict, nothing in the transcript -- so the surface is
// simply absent and reads exactly like a call that carried no secret. That is
// the failure this project indicts its predecessor for, and it is why the
// assertions below are set equality rather than containment.
func TestTheManifestNamesEveryEventThisPackageScans(t *testing.T) {
	wiring := loadWiring(t)

	events := make([]string, 0, len(wiring.Hooks))
	for name := range wiring.Hooks {
		events = append(events, name)
	}
	// decode() answers to exactly these two and refuses anything else. An
	// event here that decode refuses is a hook that blocks every call it sees;
	// one decode answers and this omits is the silent direction.
	want := []string{string(PreToolUse), string(UserPromptSubmit)}
	if diff := setDiff(events, want); diff != "" {
		t.Errorf("%s wires the wrong events: %s", manifestPath, diff)
	}
}

// The PreToolUse matcher is held to the constants rather than kept in step by
// hand, which is what ToolRead and ToolBash are exported for.
func TestThePreToolUseMatcherNamesExactlyTheScannedTools(t *testing.T) {
	wiring := loadWiring(t)

	entries := wiring.Hooks[string(PreToolUse)]
	if len(entries) != 1 {
		t.Fatalf("%s has %d PreToolUse entries; the matcher is one alternation "+
			"so that this test reads all of it", manifestPath, len(entries))
	}
	named := strings.Split(entries[0].Matcher, "|")
	if diff := setDiff(named, []string{ToolRead, ToolBash}); diff != "" {
		t.Errorf("the PreToolUse matcher %q does not name what toolTargets "+
			"scans: %s", entries[0].Matcher, diff)
	}
}

// UserPromptSubmit is not a tool event and takes no matcher. A matcher written
// on it is not an error Claude Code reports -- it has no tool name to compare
// against -- so nothing outside this test would say the entry was wrong.
func TestThePromptEntryCarriesNoMatcher(t *testing.T) {
	wiring := loadWiring(t)

	for i, entry := range wiring.Hooks[string(UserPromptSubmit)] {
		if entry.Matcher != "" {
			t.Errorf("UserPromptSubmit entry %d carries matcher %q", i, entry.Matcher)
		}
	}
}

// Every entry runs the launcher, and runs it with the subcommand that scans.
//
// hooks.json naming the binary directly is the fail-open this repo has
// measured twice: an absent binary exits 127 and a non-executable one exits
// 126, and neither blocks. The launcher turns both into a deny. The subcommand
// is chosen here rather than in the launcher, so a manifest that forgot it
// would run `spill-guard` with no arguments -- usage on stderr, exit 1, and
// the call goes through.
func TestEveryEntryRunsTheLauncherWithTheHookSubcommand(t *testing.T) {
	wiring := loadWiring(t)

	seen := 0
	for event, entries := range wiring.Hooks {
		for i, entry := range entries {
			for _, h := range entry.Hooks {
				seen++
				if h.Type != "command" {
					t.Errorf("%s entry %d: type is %q, not \"command\"", event, i, h.Type)
				}
				if !strings.Contains(h.Command, "run-spill-guard.cmd") {
					t.Errorf("%s entry %d runs %q, which is not the launcher",
						event, i, h.Command)
				}
				if !strings.HasSuffix(h.Command, " hook") {
					t.Errorf("%s entry %d runs %q, which names no subcommand to "+
						"scan with", event, i, h.Command)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no hook commands were examined, so every assertion above was vacuous")
	}
}

// setDiff reports what one set has that the other does not, or "" when they
// are equal. Both directions, because each is a different defect.
func setDiff(got, want []string) string {
	missing := minus(want, got)
	extra := minus(got, want)
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		parts = append(parts, "unexpected "+strings.Join(extra, ", "))
	}
	return strings.Join(parts, "; ")
}

func minus(from, remove []string) []string {
	drop := make(map[string]bool, len(remove))
	for _, s := range remove {
		drop[s] = true
	}
	var left []string
	for _, s := range from {
		if !drop[s] {
			left = append(left, s)
		}
	}
	sort.Strings(left)
	return left
}
