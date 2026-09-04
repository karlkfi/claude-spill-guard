package rules

import "testing"

// Each row is a condition the anchored path turns on, and the false ones are
// the ones worth having: a rule that quietly gets the anchored path without
// meeting one of them reports fewer findings than the pass it replaced, which
// no output distinguishes from a clean scan.
func TestAnchorTakesOnlyRulesTheTwoPathsAgreeOn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pattern  string
		keywords []string
		want     bool
	}{
		{"a keyword that is the whole literal head",
			`\b(AIza[A-Za-z0-9_-]{35})\b`, []string{"AIza"}, true},
		{"an alternation the parser factors a common byte out of",
			`\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16})\b`,
			[]string{"AKIA", "ASIA", "A3T"}, true},
		{"a character class between two literals",
			`\b(gh[oprsu]_[A-Za-z0-9]{36})\b`,
			[]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, true},
		{"an alternation whose branches are covered by what follows them",
			`\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b`,
			[]string{"sk_live_", "rk_live_"}, true},

		// The class enumerates to five and the list covers four of them, so
		// one string the rule matches starts at no keyword.
		{"a class one of whose branches no keyword covers",
			`\b(gh[oprsu]_[A-Za-z0-9]{36})\b`,
			[]string{"ghp_", "gho_", "ghu_", "ghs_"}, false},
		{"a keyword the match does not begin with",
			`\b(id-(TOKEN[0-9]{6}))\b`, []string{"TOKEN"}, false},
		{"no boundary in front, so the prefilter refuses hits the pattern takes",
			`(AIza[A-Za-z0-9_-]{35})\b`, []string{"AIza"}, false},
		{"a pattern that asks where the text begins",
			`^\b(AIza[A-Za-z0-9_-]{35})\b`, []string{"AIza"}, false},
		{"an unbounded repeat, which reads to the end of the buffer per hit",
			`\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,})`, []string{"eyJ"}, false},
		{"a folded literal, which matches runes the prefilter cannot find",
			`(?i)\b(AIza[A-Za-z0-9_-]{35})\b`, []string{"AIza"}, false},
		{"a keyword written in the other case from the pattern",
			`\b(AIza[A-Za-z0-9_-]{35})\b`, []string{"aiza"}, false},
		{"no keywords at all",
			`\b(AIza[A-Za-z0-9_-]{35})\b`, nil, false},
		{"an empty keyword, which would cover every head there is",
			`\b(AIza[A-Za-z0-9_-]{35})\b`, []string{""}, false},

		// The keyword straddles the alternation, which the walk carries
		// because it threads the prefixes it is holding through every element
		// of the concatenation rather than asking each branch alone.
		{"an alternation the keyword straddles",
			`\b(A(?:KI|SI)A[A-Z0-9]{16})\b`, []string{"AKIA", "ASIA"}, true},

		// The three shapes the walk gives up on, none of which any shipped
		// rule has. Each costs the rule the anchored path and no finding.
		{"a class wider than the walk will expand",
			`\b(K[ -~]X[A-Z]{8})\b`, []string{"KAX"}, false},
		{"an optional group in front of the keyword",
			`\b((?:RSA )?TOKEN[0-9]{6})\b`, []string{"TOKEN"}, false},
		{"a repeat in front of the keyword",
			`\b([A-Z]+TOKEN[0-9]{6})\b`, []string{"TOKEN"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			re, reach := anchor(tc.pattern, tc.keywords)
			if got := re != nil; got != tc.want {
				t.Fatalf("anchor(%q, %q) gave a regex = %v, want %v",
					tc.pattern, tc.keywords, got, tc.want)
			}
			if tc.want && reach <= 0 {
				t.Errorf("reach = %d, want the length of the longest match", reach)
			}
			if !tc.want && reach != 0 {
				t.Errorf("reach = %d on a rule with no Anchor, want 0", reach)
			}
		})
	}
}

// The reach is what one attempt costs, so an under-estimate would let the
// pipeline take the anchored arm past where it is the cheaper one. These are
// the shipped patterns, each counted by hand from its own repetition bounds.
func TestReachIsTheLongestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern  string
		keywords []string
		want     int
	}{
		{`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`,
			[]string{"AKIA", "ASIA", "ABIA", "ACCA", "A3T"}, 20},
		{`\b(gh[oprsu]_[A-Za-z0-9]{36})\b`,
			[]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, 40},
		{`\b(github_pat_[A-Za-z0-9_]{70,90})\b`, []string{"github_pat_"}, 101},
		{`\b(AIza[A-Za-z0-9_-]{35})\b`, []string{"AIza"}, 39},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			if _, reach := anchor(tc.pattern, tc.keywords); reach != tc.want {
				t.Errorf("reach = %d, want %d", reach, tc.want)
			}
		})
	}
}
