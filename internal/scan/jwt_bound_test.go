package scan

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	embedded "github.com/karlkfi/claude-spill-guard/rules"
)

// The jwt rule's three repeats are bounded at 1000, which is RE2's own cap and
// what buys the rule the anchored path -- anchor.go's last condition is that
// the longest match is bounded, and an unbounded repeat over a class that
// covers the text keeps the engine's threads alive to the end of the buffer.
//
// A bound is a recall ceiling, so it is stated and driven rather than assumed
// harmless. Two populations were read for what a real token reaches, both of
// them examples and fixtures rather than production traffic, so both are a
// floor on what a live token can be:
//
//	4.66 GB in 244,089 files under ~/go/pkg/mod, 118 JWT-shaped runs, every one
//	decoding to a JSON header: header max 102, payload max 883 (p99 472),
//	signature max 342.
//
//	2.28 GB in 2,338 session transcripts under ~/.claude/projects, 31 runs:
//	header max 36, payload max 222, signature max 86.
//
// So the 1,003-byte segment ceiling this buys clears every payload either
// population holds with room over, and a token past it is missed. The two edges below are what make that a claim
// somebody can check rather than a sentence.

// jwtSegments is a token whose three segments are exactly the lengths given.
func jwtSegments(tb testing.TB, header, payload, sig int) string {
	tb.Helper()
	seg := func(n int) string { return "eyJ" + strings.Repeat("a", n-3) }
	return seg(header) + "." + seg(payload) + "." + strings.Repeat("b", sig)
}

func shippedJWT(tb testing.TB) rules.Rule {
	tb.Helper()
	for _, rule := range loadShipped(tb) {
		if rule.ID == "jwt" {
			return rule
		}
	}
	tb.Fatal("no jwt rule in the shipped set")
	return rules.Rule{}
}

// The header and payload are each followed by a literal `.`, so a segment
// longer than the bound leaves the pattern nothing to reach the dot with and
// the whole token goes unmatched. That is the recall this change spends.
//
// The ceiling on a *segment* is 1003 rather than 1000: `eyJ` is written out in
// front of the repeat, so the bound governs what follows it. Both numbers are
// here because the off-by-three is the one a reader will assume away -- an edge
// case written at 1000 and 1001 passes on both sides and pins nothing.
func TestTheJWTBoundIsAnEdgeAndNotATruncation(t *testing.T) {
	rule := shippedJWT(t)
	for _, tc := range []struct {
		name                 string
		header, payload, sig int
		want                 bool
	}{
		{"payload at the bound", 36, 1003, 43, true},
		{"payload one past it", 36, 1004, 43, false},
		{"header at the bound", 1003, 74, 43, true},
		{"header one past it", 1004, 74, 43, false},
		// Nothing follows the signature, so its bound truncates the capture
		// rather than refusing the token. A 2,000-byte signature still matches.
		{"signature far past its bound", 36, 74, 2000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := jwtSegments(t, tc.header, tc.payload, tc.sig)
			if got := rule.Regex.MatchString("x " + tok); got != tc.want {
				t.Errorf("matched = %v, want %v for header %d, payload %d, signature %d",
					got, tc.want, tc.header, tc.payload, tc.sig)
			}
		})
	}
}

// The signature bound reads as the free one -- nothing follows it, so it cannot
// cost a match -- and it is the one bound that can cost precision instead.
// jwt-sample-key recomputes the HMAC over `header.payload` and compares it to
// the decoded signature, so a bound below the longest HMAC signature hands the
// check a truncated one, the comparison fails, and a published sample token
// stops being suppressed and is reported as a credential.
//
// HS512 is the longest at 86 bytes of base64url. 1000 clears it; 43 -- the
// HS256 length, which is what both corpus tokens carry and so the number a
// bound picked from the fixtures would land on -- does not.
func TestABoundBelowTheHMACSignatureUnsuppressesAPublishedSample(t *testing.T) {
	enc := base64.RawURLEncoding
	head, err := json.Marshal(map[string]string{"alg": "HS512", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"sub": "1234567890", "iat": 1516239022})
	if err != nil {
		t.Fatal(err)
	}
	signing := enc.EncodeToString(head) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha512.New, []byte("your-256-bit-secret"))
	mac.Write([]byte(signing))
	sample := signing + "." + enc.EncodeToString(mac.Sum(nil))
	if got := len(sample) - len(signing) - 1; got != 86 {
		t.Fatalf("the HS512 signature is %d bytes, so this is not the case "+
			"this control was written for", got)
	}
	buf := []byte("token: " + sample + "\n")

	for _, tc := range []struct {
		name  string
		regex string
		want  int
	}{
		{"as shipped", "", 0},
		{
			"signature bounded at the HS256 length",
			`\b(eyJ[A-Za-z0-9_-]{8,1000}\.eyJ[A-Za-z0-9_-]{8,1000}\.[A-Za-z0-9_-]{10,43})`,
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := shippedJWT(t)
			if tc.regex != "" {
				rule = rewrittenJWT(t, tc.regex)
			}
			res, err := Buffer("p", buf, []rules.Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != tc.want {
				t.Errorf("%d findings, want %d -- 0 means jwt-sample-key still "+
					"recognised the published sample", len(res.Findings), tc.want)
			}
		})
	}
}

// rewrittenJWT loads the shipped ruleset with the jwt pattern replaced, so a
// control goes through the same loader the binary uses rather than around it.
func rewrittenJWT(tb testing.TB, pattern string) rules.Rule {
	tb.Helper()
	var doc map[string]any
	if err := json.Unmarshal(embedded.Shipped, &doc); err != nil {
		tb.Fatal(err)
	}
	for _, entry := range doc["rules"].([]any) {
		if m := entry.(map[string]any); m["id"] == "jwt" {
			m["regex"] = pattern
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		tb.Fatal(err)
	}
	set, err := rules.Load(raw)
	if err != nil {
		tb.Fatalf("loading the rewritten ruleset: %v", err)
	}
	for _, rule := range set {
		if rule.ID == "jwt" {
			return rule
		}
	}
	tb.Fatal("no jwt rule in the rewritten set")
	return rules.Rule{}
}
