package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
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

// The budget the scan runs under has to fit inside the timeout the manifest
// gives this process, and nothing but this says so.
//
// The two numbers live in different files and neither reads the other: this
// binary never opens hooks.json, and hooks.json cannot see a Go constant. What
// happens when they disagree is silent in the direction the whole row was about
// -- a budget at or above the timeout means the harness kills the process while
// the scan is still running, whatever it was going to say is discarded, and the
// call proceeds unscanned. So this asserts the manifest against the constant
// rather than the other way round: hookTimeout is a copy, and a copy that has
// stopped matching is what this catches.
func TestTheBudgetFitsInsideTheTimeoutTheManifestGives(t *testing.T) {
	wiring := loadWiring(t)

	seen := 0
	for event, entries := range wiring.Hooks {
		for i, entry := range entries {
			for _, h := range entry.Hooks {
				seen++
				if got := time.Duration(h.Timeout) * time.Second; got != hookTimeout {
					t.Errorf("%s %s entry %d gives this process %s, and the budget "+
						"is picked against %s", manifestPath, event, i, got, hookTimeout)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no hook entries were examined, so every assertion above was vacuous")
	}

	if budget >= hookTimeout {
		t.Fatalf("the budget is %s against a %s timeout, so a scan that uses all "+
			"of it is killed before it can block", budget, hookTimeout)
	}
	// A margin the verdict cannot be written inside is the same defect wearing
	// a smaller number. Measured: the launcher, this binary and a trivial
	// payload are milliseconds, and the write after the deadline fires is less
	// than one. A second is orders of magnitude past both and is here so that
	// the assertion is about the shape rather than about the measurement.
	if hookTimeout-budget < time.Second {
		t.Errorf("the budget leaves %s of the timeout, which is not long enough "+
			"to be sure of writing a verdict in", hookTimeout-budget)
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

// pluginPath and marketplacePath are the two manifests, from the package
// directory a `go test` runs in.
var (
	pluginPath      = filepath.Join("..", "..", ".claude-plugin", "plugin.json")
	marketplacePath = filepath.Join("..", "..", ".claude-plugin", "marketplace.json")
)

func loadJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s does not decode: %v", path, err)
	}
}

// The two manifests have to agree on the version, and nothing else in the tree
// says so.
//
// A marketplace entry compares that string and nothing else, so a release
// whose plugin.json still names the old number cannot be delivered by `claude
// plugin update` at all -- the tag publishes archives no plugin install ever
// reaches. docs/development/release-process.md makes the bump a step a person
// takes, and a step a person takes is a step a person forgets.
//
// `claude plugin validate` does not cover it: run against this repo as it
// ships, with a marketplace.json beside the plugin.json, it validates the
// marketplace manifest only and never opens the other file. Driven 2026-08-31
// -- deleting `name` from plugin.json with both files present exits 0, and the
// same deletion with plugin.json alone exits 1. So the shipped layout is the
// one arrangement where that command says nothing, which is why this is here
// and not on the CLI.
func TestTheTwoManifestsCarryTheSameVersion(t *testing.T) {
	var plugin struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	loadJSON(t, pluginPath, &plugin)

	var market struct {
		Plugins []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"plugins"`
	}
	loadJSON(t, marketplacePath, &market)

	if plugin.Version == "" {
		t.Fatalf("%s carries no version, so a marketplace entry has nothing to "+
			"compare and `claude plugin update` can never deliver a release",
			pluginPath)
	}
	if len(market.Plugins) != 1 {
		t.Fatalf("%s lists %d plugins; this repo ships one, and the loop below "+
			"is written for that", marketplacePath, len(market.Plugins))
	}
	entry := market.Plugins[0]
	if entry.Name != plugin.Name {
		t.Errorf("the marketplace entry names %q and the plugin manifest names "+
			"%q", entry.Name, plugin.Name)
	}
	if entry.Version != plugin.Version {
		t.Errorf("the marketplace entry says version %q and %s says %q -- one "+
			"of them is the number a release will publish and the other is "+
			"what an install compares against", entry.Version, pluginPath,
			plugin.Version)
	}
}

// Every key the install channels read is present.
//
// docs/design/distribution.md counted these across the five sibling plugins
// installed on the author's machine and found the same eight everywhere, which
// is the closest thing to a schema this format has. A missing one is not a
// parse error -- Claude Code tolerates it -- so nothing else in this tree
// would say the manifest had lost `repository` or `license`.
func TestThePluginManifestCarriesEveryKeyTheChannelsRead(t *testing.T) {
	var got map[string]json.RawMessage
	loadJSON(t, pluginPath, &got)

	want := []string{"name", "version", "description", "author",
		"homepage", "repository", "license", "keywords"}
	var missing []string
	for _, key := range want {
		if len(got[key]) == 0 {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%s is missing %s", pluginPath, strings.Join(missing, ", "))
	}
	// Both directions, for the reason the matcher above is checked both ways:
	// a key nothing reads is a key somebody added expecting it to do something.
	for key := range got {
		if !slicesContains(want, key) {
			t.Errorf("%s carries %q, which no install channel reads -- either "+
				"it does something and this list is stale, or it does nothing",
				pluginPath, key)
		}
	}
}

func slicesContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
