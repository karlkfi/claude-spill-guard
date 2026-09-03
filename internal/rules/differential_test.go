package rules

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// Both capture bounds are one-sided by design: maxCaptureBytes may over-state a
// group's length and captureSymbols may over-state its alphabet, and neither may
// ever under-state, because an under-estimate refuses a live rule at startup and
// takes the scanner down over a rule that works.
//
// The unit tables pin about twenty patterns by hand, which is a sample. This is
// the property: run each pattern over one corpus, and check the bound against
// what the compiled regex really captured out of it. Only under-estimates fail,
// since over-estimating is the design.

// corpusRunes is what the random half of the corpus is drawn from: plain ASCII,
// then the folds and the widths that make bytes and runes disagree. The K is
// U+212A KELVIN SIGN rather than an ASCII K, and the long s beside it is the
// other rune the fold walk exists for -- ASCII cases arrive in the seeded
// literals below.
var corpusRunes = []rune{
	'a', 'z', 'A', 'Z', '0', '9', '-', ' ',
	'é', 'ß', 'ſ', 'K', 'İ', 'ı', 'Ω', 'ω', '\U00010348',
	'\n', 'x',
}

// corpusSeeds are spliced in at a fixed stride. A pattern needing a literal
// sequence -- (?i)(straße), ((?:ab){1,3}), (?i)(kelvin) -- would never meet one
// in a corpus assembled from random runes, so its match set would come back
// empty and its case would pass having compared nothing.
var corpusSeeds = []string{
	"straße", "STRASSE", "ſtraße",
	"ababab", "kelvin", "KELVIN", "Kelvin",
	"aaaaaa", "bbbbbb",
}

const (
	// A corpus reseeded per run is a flake generator, and this is a gate.
	corpusSeed   = 0x5CA1AB1E
	corpusBytes  = 400 << 10
	corpusStride = 512
)

// buildCorpus is deterministic in corpusSeed. Nothing here reads the clock, the
// environment, or the tree.
func buildCorpus() []byte {
	r := rand.New(rand.NewSource(corpusSeed))
	var b strings.Builder
	b.Grow(corpusBytes + 64)
	for i := 0; b.Len() < corpusBytes; i++ {
		if i%corpusStride == 0 {
			b.WriteString(corpusSeeds[(i/corpusStride)%len(corpusSeeds)])
			continue
		}
		b.WriteRune(corpusRunes[r.Intn(len(corpusRunes))])
	}
	return []byte(b.String())
}

// observation is what one pattern actually produced over the corpus: how many
// times it matched, the longest group-1 capture in bytes, and the most distinct
// byte values any one capture held.
type observation struct {
	matches int
	longest int
	widest  int
	sample  []byte
}

func observe(re *regexp.Regexp, corpus []byte) observation {
	var o observation
	for _, m := range re.FindAllSubmatch(corpus, -1) {
		o.matches++
		if len(m[1]) > o.longest {
			o.longest, o.sample = len(m[1]), m[1]
		}
		var seen [256]bool
		n := 0
		for _, c := range m[1] {
			if !seen[c] {
				seen[c] = true
				n++
			}
		}
		if n > o.widest {
			o.widest = n
		}
	}
	return o
}

// compareBounds is the assertion, kept separate from the walk that produces the
// numbers so a control can hand it a bound it must reject.
func compareBounds(pattern string, bytes, symbols int, o observation) error {
	// The load-bearing line, and it is not about the corpus. A pattern that
	// matched nothing compared nothing, so its case passes -- silently, and
	// reading exactly like coverage. These patterns are carried because trouble
	// was expected and not found, which is the reading an empty match set
	// counterfeits.
	if o.matches == 0 {
		return fmt.Errorf("%s matched nothing, so it compared nothing", pattern)
	}
	// The same defect one level down. A pattern matching the empty string at
	// every position matches a quarter of a million times and captures nothing,
	// so both comparisons below are satisfied by any bound at all. Every case
	// here captures at least two bytes today; this is what keeps that true.
	if o.longest == 0 {
		return fmt.Errorf("%s matched %d time(s) and captured nothing either time",
			pattern, o.matches)
	}
	if bytes < o.longest {
		return fmt.Errorf("%s: maxCaptureBytes = %d, but it captured %q, which is %d bytes",
			pattern, bytes, o.sample, o.longest)
	}
	if symbols < o.widest {
		return fmt.Errorf("%s: captureSymbols = %d, but one capture held %d distinct bytes",
			pattern, symbols, o.widest)
	}
	return nil
}

func checkPattern(pattern string, corpus []byte) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%s does not compile: %w", pattern, err)
	}
	bytes, err := maxCaptureBytes(pattern, 1)
	if err != nil {
		return fmt.Errorf("%s: maxCaptureBytes: %w", pattern, err)
	}
	symbols, err := captureSymbols(pattern, 1)
	if err != nil {
		return fmt.Errorf("%s: captureSymbols: %w", pattern, err)
	}
	return compareBounds(pattern, bytes, symbols, observe(re, corpus))
}

// The patterns are the ones where trouble was expected and not found, since
// those are what an edit to either walk would break first. Folding is the half
// most likely to rot: syntax.Parse expands a class's folds into its ranges but
// leaves FoldCase on a literal, so the two arms reach the same answer by
// different routes and only one of them walks unicode.SimpleFold. A refactor
// that unifies them is exactly what this catches.
func TestBoundsNeverUnderEstimateOverACorpus(t *testing.T) {
	corpus := buildCorpus()
	for _, tc := range []struct{ pattern, probes string }{
		{`(?U)([a-z]{2,6})`, "non-greedy, where the longest match is not what the engine returns"},
		{`(?i)([a-z]+?)`, "non-greedy over an unbounded repeat"},
		{`((?:a*){3})`, "a repeat over a star, which matches the empty string everywhere"},
		{`([^a]{2})`, "one range spanning encoding widths, one byte to four"},
		{`([\x{10000}-\x{10FFFF}]{1,2})`, "astral ranges, four bytes a rune"},
		{`(\p{L}{1,4})`, "a Unicode class"},
		{`(\p{Greek}{2})`, "a Unicode script class, two runes deep"},
		{`(?i)(straße)`, "folding that changes encoded width"},
		{`(?i)(SS)`, "the sharp s and the long s reached from the other side"},
		{`([\x{0130}\x{0131}i]{1,3})`, "the dotted and dotless I"},
		{`(?i)([\x{017F}\x{212A}s k]{1,2})`, "long s and Kelvin, the two cases the fold walk exists for"},
		{`((?:ab){1,3})`, "a bounded repeat over a group, where both bounds are exact"},
		{`(?i)(kelvin)`, "a folded literal needing every case of itself"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			if err := checkPattern(tc.pattern, corpus); err != nil {
				t.Errorf("%v (%s)", err, tc.probes)
			}
		})
	}
}

// The empty-match guard is the line this whole harness turns on, so it is driven
// rather than trusted: a pattern the corpus cannot produce has to be reported,
// not passed over.
func TestTheEmptyMatchGuardFires(t *testing.T) {
	corpus := buildCorpus()
	const absent = `(qqqjjjvvv)`
	if strings.Contains(string(corpus), "qqqjjjvvv") {
		t.Fatalf("%s is in the corpus, so this control proves nothing", absent)
	}
	err := checkPattern(absent, corpus)
	if err == nil {
		t.Fatal("checkPattern() = nil for a pattern the corpus cannot match")
	}
	if !strings.Contains(err.Error(), "matched nothing") {
		t.Errorf("checkPattern() = %v, want the empty match set named", err)
	}

	// And a pattern that matches everywhere while capturing nothing, which is
	// the same vacuity arriving past the guard above.
	const empty = `((?:qqqjjj)*)`
	err = checkPattern(empty, corpus)
	if err == nil {
		t.Fatal("checkPattern() = nil for a pattern that only ever captured the empty string")
	}
	if !strings.Contains(err.Error(), "captured nothing") {
		t.Errorf("checkPattern() = %v, want the empty capture named", err)
	}
}

// The other two guards, driven the same way. Each is handed a bound one under
// what the corpus produced, which is the smallest under-estimate there is.
func TestTheUnderEstimateGuardsFire(t *testing.T) {
	corpus := buildCorpus()
	const pattern = `((?:ab){1,3})`
	re := regexp.MustCompile(pattern)
	o := observe(re, corpus)
	if o.matches == 0 || o.longest == 0 || o.widest == 0 {
		t.Fatalf("%s produced %+v, so neither control below proves anything", pattern, o)
	}
	if err := compareBounds(pattern, o.longest-1, o.widest, o); err == nil {
		t.Error("compareBounds() = nil for a length one byte under what was captured")
	}
	if err := compareBounds(pattern, o.longest, o.widest-1, o); err == nil {
		t.Error("compareBounds() = nil for an alphabet one symbol under what was captured")
	}
	// And the same numbers, unmutated, must pass -- otherwise the two above
	// would fail whatever they were handed.
	if err := compareBounds(pattern, o.longest, o.widest, o); err != nil {
		t.Errorf("compareBounds() = %v on the observation itself", err)
	}
}

// Every seed has to be findable, because a splice that silently stopped landing
// would empty the match set of every pattern that needs a literal -- and the
// guard above would then report thirteen failures rather than one cause.
func TestEverySeedIsInTheCorpus(t *testing.T) {
	corpus := string(buildCorpus())
	for _, s := range corpusSeeds {
		if !strings.Contains(corpus, s) {
			t.Errorf("the corpus does not contain the seed %q", s)
		}
	}
}
