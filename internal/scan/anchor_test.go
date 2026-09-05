package scan

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
)

// identity is the offset map for a buffer nothing decoded.
func identity(i int) int { return i }

// runner is one way of producing a rule's findings over a buffer. The point of
// the differential below is that every correct one has to produce the same
// list, so the real path and a deliberately wrong one take the same shape here.
type runner func(path string, text []byte, source func(int) int, rule rules.Rule) ([]Finding, error)

// differ runs run against the whole-buffer pass over every buffer and every
// enabled rule, and reports how many (buffer, rule) pairs disagreed and how
// many findings the whole-buffer pass produced.
//
// The second number is what stops a clean result meaning nothing: two empty
// lists agree, so a differential over buffers no rule fires on reports zero
// disagreements without having compared anything.
func differ(t *testing.T, ruleset []rules.Rule, bufs [][]byte, run runner) (disagreed int, found map[string]int) {
	t.Helper()
	found = make(map[string]int)
	for n, buf := range bufs {
		for _, rule := range ruleset {
			if !rule.Enabled {
				continue
			}
			want, err := matchAll("b", buf, identity, rule)
			if err != nil {
				t.Fatalf("buffer %d, rule %s: whole-buffer pass: %v", n, rule.ID, err)
			}
			found[rule.ID] += len(want)
			got, err := run("b", buf, identity, rule)
			if err != nil {
				t.Fatalf("buffer %d, rule %s: %v", n, rule.ID, err)
			}
			if !reflect.DeepEqual(want, got) {
				disagreed++
				if disagreed <= 3 {
					// Rule id and offsets, never the buffer. These are
					// credential-shaped by construction and this text reaches
					// the API, which is the reporting rule a Finding's own
					// shape exists to keep.
					t.Logf("buffer %d, rule %s: whole buffer %v, candidates %v",
						n, rule.ID, offsets(want), offsets(got))
				}
			}
		}
	}
	return disagreed, found
}

// offsets is what a disagreement may say about a buffer: where, and nothing
// about what is there.
func offsets(findings []Finding) []int {
	out := make([]int, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Offset)
	}
	return out
}

// candidates is the hit list matchRule would drive the rule from, with a budget
// no test buffer can exceed. A rule the loader gave no Anchor has no hit list,
// and nil is what the wrong loops below then run over.
func candidates(t *testing.T, text []byte, rule rules.Rule) ([]int, bool) {
	t.Helper()
	if rule.Anchor == nil || !boundedKeywords(rule.Keywords) {
		return nil, false
	}
	at, ok := keywordPositions(text, rule.Keywords, len(text)+1)
	if !ok {
		t.Fatalf("rule %s: the hit list went over a budget of the whole buffer", rule.ID)
	}
	return at, true
}

// corpusBuffers is every file in the precision corpus, which is the half of the
// input nobody wrote for this test.
func corpusBuffers(t *testing.T) [][]byte {
	t.Helper()
	var bufs [][]byte
	for _, half := range []string{"clean", "planted"} {
		err := filepath.WalkDir(filepath.Join(corpusRoot, half),
			func(path string, entry os.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				buf, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				bufs = append(bufs, buf)
				return nil
			})
		if err != nil {
			t.Fatalf("walking the %s corpus: %v", half, err)
		}
	}
	return bufs
}

// randomBuffers is the other half: short buffers over a deliberately small
// alphabet, so near-misses, real matches and boundary characters are all common
// and the two paths get many chances to disagree over a few thousand cases.
//
// The pieces are the shipped keywords, runs from the character classes the
// rules use, and the bytes that decide a word boundary. A uniform random buffer
// would clear no prefilter and compare nothing.
func randomBuffers(n int) [][]byte {
	pieces := []string{
		"AKIA", "ASIA", "ABIA", "ACCA", "A3T", "AIza", "eyJ", "sk-", "sk_live_",
		"rk_live_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
		"xoxa-", "xoxb-", "xoxs-", "T3BlbkFJ", "akia", "Sk-", "GHP_",
		" ", "-", "_", ".", "\n", "=", "\"", "/", ":", "x", "0",
	}
	r := rand.New(rand.NewPCG(1, 2))
	bufs := make([][]byte, 0, n)
	for len(bufs) < n {
		var b strings.Builder
		for parts := 4 + r.IntN(24); parts > 0; parts-- {
			switch r.IntN(3) {
			case 0:
				b.WriteString(pieces[r.IntN(len(pieces))])
			case 1:
				b.WriteString(run(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", runLength(r)))
			default:
				b.WriteString(run(r, "abcdefghijklmnopqrstuvwxyz0123456789_-", runLength(r)))
			}
		}
		bufs = append(bufs, []byte(b.String()))
	}
	return bufs
}

// runLength is biased towards the lengths the shipped rules count, so a
// keyword the generator emits is often followed by exactly enough of the class
// after it to make a real match. Uniform lengths produce a differential that
// compares mostly empty lists.
func runLength(r *rand.Rand) int {
	counted := []int{16, 20, 24, 35, 36, 40, 70, 90}
	if r.IntN(2) == 0 {
		return counted[r.IntN(len(counted))]
	}
	return 1 + r.IntN(40)
}

// awkwardBuffers are the shapes a candidate loop gets wrong, written rather
// than waited for: the random generator produces each of them eventually and
// not reliably, and a harness whose discriminating power depends on a seed is
// one that stops discriminating the next time somebody changes the generator.
func awkwardBuffers() [][]byte {
	return [][]byte{
		// A hit inside a match. slack-token's body admits `-`, which is not a
		// word byte, so the prefilter reports a boundary in the middle of a
		// token -- and FindAll steps over it where a loop with no non-overlap
		// rule reports it again.
		[]byte(" xoxa-AAAAAAAAAAAAAAAA-xoxb-BBBBBBBBBBBB "),
		// Two matches back to back, so the second starts exactly where the
		// first ends and a non-overlap rule that goes one byte too far loses it.
		[]byte(" AKIAAAAAAAAAAAAAAAAB AKIACCCCCCCCCCCCCCCD "),
		// Hits that are not matches in front of one that is, which is what an
		// unanchored search from a hit reports the wrong offset for.
		[]byte(" AKIA AKIAX AKIA-Y AKIAEEEEEEEEEEEEEEEF "),
		// A hit at the very start of the buffer, where the boundary is the
		// absence of a byte in front rather than a byte that is not a word one.
		[]byte("AIzaSyA0123456789012345678901234567890 tail"),
	}
}

func run(r *rand.Rand, alphabet string, n int) string {
	var b strings.Builder
	for ; n > 0; n-- {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

// The findings the pipeline reports have to be the findings the pass it
// replaced reported: same rules, same offsets, same order. Anything else is a
// precision or a recall change wearing a performance change's clothes.
func TestTheAnchoredPathFindsWhatTheWholeBufferPassFinds(t *testing.T) {
	ruleset := loadShipped(t)
	bufs := append(corpusBuffers(t), awkwardBuffers()...)
	bufs = append(bufs, randomBuffers(20000)...)

	disagreed, found := differ(t, ruleset, bufs, matchRule)
	if disagreed > 0 {
		t.Errorf("%d of the %d (buffer, rule) pairs disagreed", disagreed, len(bufs)*len(ruleset))
	}
	// Per rule, because a total says nothing about the rule that produced
	// none: two empty lists agree, so a rule the buffers never fire is a rule
	// this compared nothing for.
	total := 0
	for _, rule := range ruleset {
		if !rule.Enabled {
			continue
		}
		total += found[rule.ID]
		if rule.Anchor != nil && found[rule.ID] == 0 {
			t.Errorf("rule %s runs from its keyword positions and fired on none "+
				"of these buffers, so nothing here compared the two paths for it",
				rule.ID)
		}
	}
	t.Logf("differential: %d buffers, %d findings compared, %d disagreements; per rule %v",
		len(bufs), total, disagreed, found)
}

// The clean result above is worth what the harness could have caught, so this
// runs two wrong candidate loops through the same buffers. Each is a mistake
// the real one has to avoid rather than an arbitrary corruption.
func TestTheDifferentialCatchesAWrongCandidateLoop(t *testing.T) {
	ruleset := loadShipped(t)
	bufs := append(corpusBuffers(t), awkwardBuffers()...)
	bufs = append(bufs, randomBuffers(20000)...)

	for _, wrong := range []struct {
		name string
		run  runner
	}{
		{
			// Searching from the hit instead of matching at it. The engine
			// finds the next match anywhere after the hit, so a hit that is not
			// a match reports one belonging to a later hit -- and every match
			// comes back once per hit in front of it.
			"unanchored, so a hit reports a match that is not at it",
			func(path string, text []byte, source func(int) int, rule rules.Rule) ([]Finding, error) {
				at, ok := candidates(t, text, rule)
				if !ok {
					return matchAll(path, text, source, rule)
				}
				var out []Finding
				for _, hit := range at {
					m := rule.Regex.FindSubmatchIndex(text[hit:])
					if m == nil {
						continue
					}
					for i, v := range m {
						if v >= 0 {
							m[i] = v + hit
						}
					}
					found, keep, err := accept(path, text, source, rule, m)
					if err != nil {
						return nil, err
					}
					if keep {
						out = append(out, found)
					}
				}
				return out, nil
			},
		},
		{
			// Anchored, and without the step FindAll takes over a match it has
			// already returned. A hit inside a match then reports a second
			// overlapping finding.
			"overlapping, so a hit inside a match reports again",
			func(path string, text []byte, source func(int) int, rule rules.Rule) ([]Finding, error) {
				at, ok := candidates(t, text, rule)
				if !ok {
					return matchAll(path, text, source, rule)
				}
				var out []Finding
				for _, hit := range at {
					m := rule.Anchor.FindSubmatchIndex(text[hit:])
					if m == nil {
						continue
					}
					for i, v := range m {
						if v >= 0 {
							m[i] = v + hit
						}
					}
					found, keep, err := accept(path, text, source, rule, m)
					if err != nil {
						return nil, err
					}
					if keep {
						out = append(out, found)
					}
				}
				return out, nil
			},
		},
	} {
		t.Run(wrong.name, func(t *testing.T) {
			disagreed, found := differ(t, ruleset, bufs, wrong.run)
			if len(found) == 0 {
				t.Fatal("the whole-buffer pass found nothing, so this compared nothing")
			}
			if disagreed == 0 {
				t.Errorf("the harness did not catch %q, so a clean run of it "+
					"establishes nothing", wrong.name)
			}
			t.Logf("caught on %d (buffer, rule) pairs", disagreed)
		})
	}
}

// Which shipped rules the loader hands an Anchor to, and what each of the rest
// gives up. The set is pinned because a rule added later whose keyword is not
// at the head of its match must not silently get the anchored path -- and
// because a rule that quietly stops getting it loses the whole change with
// nothing failing.
func TestWhichShippedRulesRunFromTheirKeywordPositions(t *testing.T) {
	// Reach is pinned beside the boolean because the two fail differently. A
	// rule losing its Anchor is loud -- the boolean flips. A rule whose Reach
	// moves keeps the boolean and changes the budget under it, which costs
	// throughput silently, so an unpinned Reach is a regression nothing sees.
	want := map[string]struct {
		anchored bool
		reach    int
	}{
		"aws-access-key-id":       {true, 20},
		"github-token":            {true, 40},
		"github-fine-grained-pat": {true, 101},
		"slack-token":             {true, 95},
		"stripe-live-secret-key":  {true, 107},
		"openai-api-key":          {true, 171},
		"google-api-key":          {true, 39},

		// The two the whole-buffer pass already costs nothing for: regexp
		// derives a literal prefix from each, so there is nothing to win.
		"slack-webhook-url": {false, 0},
		"private-key-block": {false, 0},
		// Unbounded: `eyJ[A-Za-z0-9_-]{8,}` keeps the engine's threads alive
		// for as long as the class matches, so one attempt reads to the end of
		// the buffer. Measured on a 64 KiB buffer of `-eyJ` repeated -- every
		// four bytes a hit, and every byte in the class -- the anchored path
		// took 29.8s against 12.2ms for one whole-buffer pass.
		"jwt": {false, 0},

		// The pii family is not gated on keywords at all.
		"payment-card":   {false, 0},
		"us-ssn":         {false, 0},
		"cn-resident-id": {false, 0},
		"ipv4-public":    {false, 0},
	}
	for _, rule := range loadShipped(t) {
		got := rule.Anchor != nil && boundedKeywords(rule.Keywords)
		expected, known := want[rule.ID]
		if !known {
			t.Errorf("rule %s is not in this table; say which arm it takes and why", rule.ID)
			continue
		}
		if got != expected.anchored {
			t.Errorf("rule %s runs from its keyword positions = %v, want %v",
				rule.ID, got, expected.anchored)
		}
		if rule.Reach != expected.reach {
			t.Errorf("rule %s has reach %d, want %d -- a moved reach moves the budget",
				rule.ID, rule.Reach, expected.reach)
		}
	}
}

// The eligibility conditions are not decoration: this is what anchoring a rule
// that fails one of them costs, driven rather than argued. Both rules here are
// ones the loader refuses, so neither can reach the pipeline -- the anchored
// form is built by hand to show what the refusal is buying.
func TestAnchoringARuleTheLoaderRefusesLosesFindings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		keyword string
		buf     string
	}{
		{
			// The keyword sits inside the match rather than at its head, so
			// the hit is four bytes past where the match starts and an attempt
			// there matches nothing.
			"a keyword the match does not begin with",
			`\b(id-(TOKEN[0-9]{6}))\b`, "TOKEN", "x id-TOKEN123456 y",
		},
		{
			// No \b in front, so the pattern matches where the prefilter's
			// boundary refuses to report a hit.
			"a pattern with no boundary in front of its keyword",
			`(TOKEN[0-9]{6})`, "TOKEN", "xTOKEN123456",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ruleset := load(t, fmt.Sprintf(`{"rules": [{
				"id": "probe",
				"family": "credential",
				"description": "probe",
				"regex": %q,
				"group": 1,
				"keywords": [%q],
				"enabled": true
			}]}`, tc.pattern, tc.keyword))
			rule := ruleset[0]
			if rule.Anchor != nil {
				t.Fatalf("the loader gave this rule an Anchor, so the refusal "+
					"this measures is not happening: %s", tc.pattern)
			}
			want, err := matchAll("b", []byte(tc.buf), identity, rule)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) == 0 {
				t.Fatal("the whole-buffer pass found nothing, so there is no " +
					"finding for the anchored form to lose")
			}
			// The anchored form the loader declined to build.
			rule.Anchor = regexp.MustCompile(`\A(?:` + tc.pattern + `)`)
			at, _ := candidates(t, []byte(tc.buf), rule)
			got, err := matchAt("b", []byte(tc.buf), identity, rule, at)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(want, got) {
				t.Errorf("anchoring this rule lost nothing, so the loader's "+
					"refusal of it is untested here: %v", want)
			}
		})
	}
}

// Past the budget the hit list is not worth an attempt each, and the answer is
// the whole-buffer pass rather than a slower spelling of it.
//
// What this asserts is the budget arithmetic over Reach: a dense hit list is
// refused and a sparse one is kept, for every anchored rule rather than for
// one. Every rule, because Reach is what the budget divides by and the loader
// never looks at it -- a rule whose Reach grew would keep a non-nil Anchor, so
// the table above stays green, while its budget shrank toward zero and it fell
// back on every buffer.
//
// It does not observe which arm matchRule takes. This recomputes the
// eligibility condition rather than reading matchRule's, so a change to
// matchRule's own gate leaves this green -- driven, and filed as
// docs/queue/Q140.md, which is also where the duplication on the line below is
// recorded. Do not read this test as a gate on the arm.
//
// Not that the arm is unobservable: testing.AllocsPerRun separates the two at
// 16 against 3 on one sparse buffer, because the anchored arm builds a hit
// list and the whole-buffer pass does not. Q140 carries that measurement and
// what it would take to make a gate of it.
func TestEveryAnchoredRuleRefusesADenseHitListAndKeepsASparseOne(t *testing.T) {
	anchored := 0
	for _, rule := range loadShipped(t) {
		if rule.Anchor == nil || !boundedKeywords(rule.Keywords) {
			continue
		}
		anchored++
		// The space is what gives the keyword its word boundary, so every
		// repeat is a hit the prefilter reports.
		keyword := rule.Keywords[0]
		dense := []byte(strings.Repeat(" "+keyword, 4096))
		if _, ok := keywordPositions(dense, rule.Keywords, budget(len(dense), rule.Reach)); ok {
			t.Errorf("%s: a hit every %d bytes stayed inside a budget of one per %d",
				rule.ID, len(keyword)+1, rule.Reach+attemptCost)
		}
		sparse := []byte(strings.Repeat("x", 1<<16) + " " + keyword)
		if _, ok := keywordPositions(sparse, rule.Keywords, budget(len(sparse), rule.Reach)); !ok {
			t.Errorf("%s: one hit in 64 KiB went over a budget of one per %d",
				rule.ID, rule.Reach+attemptCost)
		}
	}
	if anchored == 0 {
		t.Fatal("no shipped rule is anchored, so this asserted nothing")
	}
}
