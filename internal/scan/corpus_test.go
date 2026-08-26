package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
)

// The precision corpus. Every other test here pins a mechanism against a
// fixture written to exercise it; this one pins the shipped ruleset against
// files nobody wrote for it. testdata/corpus/README.md is the specification.
const (
	corpusRoot = "../../testdata/corpus"
	shipped    = "../../rules/spill-guard.json"
)

// The count CI pins.
const cleanFindings = 0

// Floors, because an empty walk reports the same zero as a clean one.
const (
	minCleanFiles   = 10
	minCleanBytes   = 8 << 10
	minPlantedFiles = 10
)

// loadShipped is the ruleset as the binary will load it, no project overrides.
func loadShipped(t *testing.T) []rules.Rule {
	t.Helper()
	set, err := rules.LoadFiles(shipped, filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("loading %s: %v", shipped, err)
	}
	return set
}

// reading is one walk over one half of the corpus.
type reading struct {
	files    int
	bytes    int
	findings []Finding
}

// byRule counts findings per rule id, so a message names what fired.
func (r reading) byRule() map[string]int {
	counts := make(map[string]int, len(r.findings))
	for _, f := range r.findings {
		counts[f.RuleID]++
	}
	return counts
}

// walk scans every file under one half of the corpus. It is the single path
// every test below takes, so the planted half reporting is what makes the
// clean half's zero a measurement rather than a silence.
func walk(t *testing.T, half string, ruleset []rules.Rule) reading {
	t.Helper()
	dir := filepath.Join(corpusRoot, half)
	var got reading
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found, err := Buffer(filepath.ToSlash(path), buf, ruleset)
		if err != nil {
			return err
		}
		got.files++
		got.bytes += len(buf)
		got.findings = append(got.findings, found...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return got
}

// report prints the rule, the path and the offset -- everything a finding is
// allowed to carry.
func report(findings []Finding) string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, f.RuleID+" "+f.Path+" @"+strconv.Itoa(f.Offset))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestCorpusIsBigEnoughToMeanSomething(t *testing.T) {
	set := loadShipped(t)
	clean := walk(t, "clean", set)
	planted := walk(t, "planted", set)
	t.Logf("clean: %d files, %d bytes; planted: %d files",
		clean.files, clean.bytes, planted.files)

	if clean.files < minCleanFiles {
		t.Errorf("clean corpus is %d file(s), floor is %d -- a corpus that lost "+
			"its files reports zero findings for the wrong reason",
			clean.files, minCleanFiles)
	}
	if clean.bytes < minCleanBytes {
		t.Errorf("clean corpus is %d bytes, floor is %d", clean.bytes, minCleanBytes)
	}
	if planted.files < minPlantedFiles {
		t.Errorf("planted corpus is %d file(s), floor is %d -- the planted half "+
			"is what proves the walk can report anything at all",
			planted.files, minPlantedFiles)
	}
}

func TestShippedRulesetFlagsNothingInTheCleanCorpus(t *testing.T) {
	got := walk(t, "clean", loadShipped(t))
	t.Logf("clean: %d files, %d bytes, %d finding(s)", got.files, got.bytes, len(got.findings))
	if len(got.findings) != cleanFindings {
		t.Errorf("clean corpus produced %d finding(s), pinned at %d:\n%s\n\n"+
			"A rule that needs an exception to stay quiet is a rule to drop. "+
			"Raising this number is a precision regression, and precision "+
			"regressions are the ones nobody reports.",
			len(got.findings), cleanFindings, report(got.findings))
	}
}

// inherited is two of the rules that produced the 5,679, verbatim from
// docs/design/language-choice.md section 3. They have no validator and no
// prefilter, so they fire on the NodePorts, the buffer constants and the
// amdgpu string the clean half exists to hold -- which is what stops the zero
// above being a zero over bland material.
var inherited = []struct {
	id    string
	regex string
	// floor is under what each reported when the corpus was assembled on
	// 2026-08-25 -- 30 and 8 -- with room for a fixture to be edited.
	floor int
}{
	{"pii-postal-code", `\b\d{5}(?:-\d{4})?\b`, 20},
	{"pii-phone-cn", `(?:\+86[-\s]?)?(?:1[3-9]\d{9}|0\d{2,3}[-\s]?\d{7,8})`, 6},
}

func TestCleanCorpusWouldFlagUnderTheInheritedRules(t *testing.T) {
	for _, want := range inherited {
		control := []rules.Rule{{
			ID:          want.id,
			Family:      rules.PII,
			Description: "inherited, as a control",
			Regex:       regexp.MustCompile(want.regex),
			Enabled:     true,
		}}
		got := walk(t, "clean", control)
		t.Logf("%s reports %d match(es) on the clean corpus", want.id, len(got.findings))
		if len(got.findings) < want.floor {
			t.Errorf("%s reported %d match(es) on the clean corpus, floor is %d -- "+
				"the material the corpus exists to hold has drifted out of it, so "+
				"the shipped ruleset's zero is no longer evidence of precision",
				want.id, len(got.findings), want.floor)
		}
	}
}

// planted maps each fixture to the rule it carries. Written out rather than
// derived from the filename, because the count is the part a naming convention
// cannot carry.
var planted = map[string]string{
	"aws-access-key-id.env":       "aws-access-key-id",
	"github-token.sh":             "github-token",
	"github-fine-grained-pat.txt": "github-fine-grained-pat",
	"slack-token.json":            "slack-token",
	"slack-webhook-url.yaml":      "slack-webhook-url",
	"stripe-live-secret-key.env":  "stripe-live-secret-key",
	"openai-api-key.py":           "openai-api-key",
	"google-api-key.js":           "google-api-key",
	"private-key-block.pem":       "private-key-block",
	"jwt.txt":                     "jwt",
}

func TestEveryPlantedSecretIsFoundExactlyOnce(t *testing.T) {
	set := loadShipped(t)
	dir := filepath.Join(corpusRoot, "planted")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		seen[name] = true
		want, known := planted[name]
		if !known {
			t.Errorf("%s is in the planted corpus and in no expectation, so "+
				"nothing says what it should report", name)
			continue
		}
		buf, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		found, err := Buffer(name, buf, set)
		if err != nil {
			t.Fatalf("scanning %s: %v", name, err)
		}
		if len(found) != 1 || found[0].RuleID != want {
			t.Errorf("%s: want exactly one %s finding, got %d:\n%s",
				name, want, len(found), report(found))
		}
	}
	for name := range planted {
		if !seen[name] {
			t.Errorf("%s is expected and is not in the planted corpus", name)
		}
	}
}

func TestEveryEnabledRuleHasAPlantedFile(t *testing.T) {
	covered := make(map[string]bool, len(planted))
	for _, id := range planted {
		covered[id] = true
	}
	for _, rule := range loadShipped(t) {
		if rule.Enabled && !covered[rule.ID] {
			t.Errorf("%q ships enabled with no planted file, so nothing shows it "+
				"can fire -- a rule that matches nothing reports the same clean "+
				"result as a rule that checked", rule.ID)
		}
	}
}

// Every one of the 5,679 inherited false positives came from the numeric PII
// family, so shipping it off is the finding rather than a deferral. Flipping
// one back on is a one-word edit in a data file that nothing else would catch.
func TestNumericPIIFamilyShipsDisabled(t *testing.T) {
	set := loadShipped(t)
	forced := make([]rules.Rule, 0, len(set))
	for _, rule := range set {
		if rule.Family == rules.PII {
			if rule.Enabled {
				t.Errorf("%q is a pii rule and ships enabled", rule.ID)
			}
			rule.Enabled = true
			forced = append(forced, rule)
		}
	}
	if len(forced) == 0 {
		t.Fatal("the shipped ruleset carries no pii rule, so this test asserts nothing")
	}

	// What turning the family on would cost today. Zero is the checksums, the
	// reserved ranges and the label proximity working, over one small corpus --
	// which is not enough to ship the family on.
	got := walk(t, "clean", forced)
	t.Logf("the pii family, force-enabled, reports %d finding(s) on the clean corpus: %v",
		len(got.findings), got.byRule())
	if len(got.findings) != 0 {
		t.Errorf("the pii family reports %d finding(s) on clean files:\n%s",
			len(got.findings), report(got.findings))
	}
}
