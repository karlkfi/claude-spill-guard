package scan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
)

// The benchmark for the two match paths, held to the four rules
// docs/design/README.md sets for benchmarking this workload.
//
// Real heterogeneous files, so the corpus is this repository's own text --
// Go, Markdown, JSON, Python, YAML -- rather than anything written for the
// measurement. Never a repeated chunk, which is the rule that cost the most to
// learn: a 176-byte block repeated 47,662 times overstated one engine by
// roughly 10x by keeping the DFA cache warm and letting literal prefilters skip
// everything. Match counts reconciled before any two timings are compared,
// which benchArms does and fails the benchmark over. And fixed cost measured
// separately, because below about 8 KB it is all there is --
// BenchmarkOneAttempt is that half.
//
// What it does not do is scale to the sizes docs/queue/Q123.md quoted. The
// corpus is about 1.7 MiB, which is two orders of magnitude past where fixed
// cost dominates and two short of the 64 MiB the row measured on synthetic
// buffers. Read the rates rather than the totals.

// benchDirs are the parts of the tree worth reading: text somebody wrote, no
// worktrees, no git objects, no corpus fixtures written to carry secrets.
var benchDirs = []string{"cmd", "docs", "internal", "rules", "scripts"}

const (
	minBenchBytes = 1 << 20
	minBenchFiles = 100
)

// benchCorpus is every text file under benchDirs, concatenated.
func benchCorpus(tb testing.TB) []byte {
	tb.Helper()
	var buf bytes.Buffer
	files := 0
	for _, dir := range benchDirs {
		err := filepath.WalkDir(filepath.Join("../..", dir),
			func(path string, entry os.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				b, err := os.ReadFile(path)
				if err != nil || bytes.IndexByte(b, 0) >= 0 {
					return err
				}
				files++
				buf.Write(b)
				return nil
			})
		if err != nil {
			tb.Fatalf("walking %s: %v", dir, err)
		}
	}
	// Floors, because a walk that read nothing benchmarks an empty buffer at a
	// throughput nobody can interpret.
	if buf.Len() < minBenchBytes || files < minBenchFiles {
		tb.Fatalf("the corpus is %d bytes in %d files, under the floor of %d in %d",
			buf.Len(), files, minBenchBytes, minBenchFiles)
	}
	return buf.Bytes()
}

// The benchmark's corpus is a fixture like any other, and one nobody checks
// drifts. This is what pins the floors, and it logs what the design doc quotes.
func TestTheBenchmarkCorpusIsRealAndBigEnough(t *testing.T) {
	buf := benchCorpus(t)
	files := 0
	for _, dir := range benchDirs {
		err := filepath.WalkDir(filepath.Join("../..", dir),
			func(path string, entry os.DirEntry, err error) error {
				if err == nil && !entry.IsDir() {
					files++
				}
				return err
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("benchmark corpus: %d bytes (%.2f MB) over %d files under %v",
		len(buf), float64(len(buf))/1e6, files, benchDirs)
}

// benchRule is the shipped rule with that id.
func benchRule(tb testing.TB, ruleset []rules.Rule, id string) rules.Rule {
	tb.Helper()
	for _, rule := range ruleset {
		if rule.ID == id {
			return rule
		}
	}
	tb.Fatalf("no rule %s in the shipped set", id)
	return rules.Rule{}
}

// benchArms times both paths for one rule over one buffer, after proving they
// report the same findings. The reconciliation is the rule the design states in
// as many words: an early run of this workload compared 75 patterns against 66.
func benchArms(b *testing.B, rule rules.Rule, buf []byte) {
	at, ok := keywordPositions(buf, rule.Keywords, len(buf)+1)
	if !ok {
		b.Fatalf("rule %s: the hit list went over a budget of the whole buffer", rule.ID)
	}
	whole, err := matchAll("b", buf, identity, rule)
	if err != nil {
		b.Fatal(err)
	}
	anchored, err := matchAt("b", buf, identity, rule, at)
	if err != nil {
		b.Fatal(err)
	}
	if !reflect.DeepEqual(whole, anchored) {
		b.Fatalf("rule %s: the two paths disagree, so their times are not comparable",
			rule.ID)
	}

	b.Run("whole-buffer", func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		b.ReportMetric(float64(len(whole)), "findings")
		for b.Loop() {
			if _, err := matchAll("b", buf, identity, rule); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("from-keyword-positions", func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		b.ReportMetric(float64(len(at)), "hits")
		for b.Loop() {
			at, ok := keywordPositions(buf, rule.Keywords, len(buf)+1)
			if !ok {
				b.Fatal("over budget")
			}
			if _, err := matchAt("b", buf, identity, rule, at); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRule is the two arms per rule, over the real corpus as it stands and
// over the same corpus carrying one occurrence of every keyword.
//
// Both halves are worth having. As-is is what a session's own files look like,
// and the planted half is the case the change is about: a buffer holding one
// `sk-` or one `eyJ` clears the prefilter and pays a whole pass for it.
func BenchmarkRule(b *testing.B) {
	ruleset := loadShipped(b)
	corpus := benchCorpus(b)
	planted := append(append([]byte(nil), corpus...),
		"\nAKIA ghp_ github_pat_ xoxb- sk_live_ sk- AIza\n"...)

	for _, id := range []string{
		"aws-access-key-id", "github-token", "github-fine-grained-pat",
		"slack-token", "stripe-live-secret-key", "openai-api-key", "google-api-key",
	} {
		rule := benchRule(b, ruleset, id)
		for _, corpus := range []struct {
			name string
			buf  []byte
		}{{"as-is", corpus}, {"one-keyword-each", planted}} {
			b.Run(fmt.Sprintf("%s/%s", id, corpus.name), func(b *testing.B) {
				benchArms(b, rule, corpus.buf)
			})
		}
	}
}

// BenchmarkRuleset is the whole shipped set over the same two buffers, through
// the entry point the hook uses. The per-rule numbers say where the time goes;
// this one says what a caller gets.
//
// The second arm is what the pipeline did before any rule had an Anchor:
// clearing the field sends every rule down the whole-buffer pass behind the
// prefilter's yes-or-no, which is the shape this replaced. Same binary and same
// buffer, so the pair is a comparison rather than two readings from two builds.
func BenchmarkRuleset(b *testing.B) {
	shipped := loadShipped(b)
	whole := append([]rules.Rule(nil), shipped...)
	anchors := 0
	for i := range whole {
		if whole[i].Anchor != nil {
			anchors++
		}
		whole[i].Anchor = nil
	}
	if anchors == 0 {
		b.Fatal("no shipped rule has an Anchor, so both arms here are the same one")
	}

	corpus := benchCorpus(b)
	planted := append(append([]byte(nil), corpus...),
		"\nAKIA ghp_ github_pat_ xoxb- sk_live_ sk- AIza eyJ\n"...)

	for _, c := range []struct {
		name string
		buf  []byte
	}{{"as-is", corpus}, {"one-keyword-each", planted}} {
		before, err := Buffer("b", c.buf, whole)
		if err != nil {
			b.Fatal(err)
		}
		after, err := Buffer("b", c.buf, shipped)
		if err != nil {
			b.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			b.Fatalf("%s: the two arms disagree, so their times are not comparable", c.name)
		}
		for _, arm := range []struct {
			name string
			set  []rules.Rule
		}{{"as-shipped", shipped}, {"whole-buffer", whole}} {
			b.Run(fmt.Sprintf("%s/%s", c.name, arm.name), func(b *testing.B) {
				b.SetBytes(int64(len(c.buf)))
				b.ReportMetric(float64(len(before.Findings)), "findings")
				for b.Loop() {
					if _, err := Buffer("b", c.buf, arm.set); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkOneAttempt is the fourth rule: fixed cost, measured on its own.
//
// One anchored attempt against a buffer that fails at its first byte, which is
// what most hits cost. attemptCost in scan.go is this number divided by the
// per-byte cost of the pass it is weighed against, and the budget is built on
// the ratio -- so a machine where these move together needs no new constant.
func BenchmarkOneAttempt(b *testing.B) {
	ruleset := loadShipped(b)
	buf := []byte(strings.Repeat("qz", 32))
	for _, id := range []string{"aws-access-key-id", "google-api-key", "openai-api-key"} {
		rule := benchRule(b, ruleset, id)
		if rule.Anchor.Match(buf) {
			b.Fatalf("rule %s matches the fixed-cost buffer, so this times a "+
				"match rather than an attempt", id)
		}
		b.Run(id, func(b *testing.B) {
			for b.Loop() {
				rule.Anchor.FindSubmatchIndex(buf)
			}
		})
	}
}
