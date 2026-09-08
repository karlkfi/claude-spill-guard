package scan

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/rules"
	embedded "github.com/karlkfi/claude-spill-guard/rules"
)

// The jwt rule detects with a pattern and measures with an extent, and the
// split is what removes a recall ceiling that was Go's rather than the format's.
//
// Q133 bounded the rule's three repeats at 1000 so the loader would hand it an
// Anchor, which took the shipped set from 35 MB/s to 78. RE2 caps a bounded
// repeat at 1000 -- driven, {8,1000} compiles and {8,1001} returns `invalid
// repeat count` -- so 1,003 bytes per segment was the largest ceiling
// expressible in one repeat, and nothing measured it as sufficient. A
// production access token with many claims is past it, and went unmatched in
// silence.
//
// Two populations were read for what a token reaches, both of them examples and
// fixtures rather than production traffic, so both are a floor on what a live
// token can be:
//
//	4.66 GB in 244,089 files under ~/go/pkg/mod, 118 JWT-shaped runs, every one
//	decoding to a JSON header: header max 102, payload max 883 (p99 472),
//	signature max 342.
//
//	2.28 GB in 2,338 session transcripts under ~/.claude/projects, 31 runs:
//	header max 36, payload max 222, signature max 86.
//
// Neither population reaches the ceiling, which is why nothing here caught it:
// a corpus of samples is a corpus of small tokens. That is the argument for
// removing a bound rather than raising one.

// base64URL is the segment alphabet, and filler cycles through it so a fixture
// clears the rule's entropy floor of 3.5 bits.
//
// A run of one byte does not, which is worth stating because it is the shape a
// fixture reaches for and it fails in the direction that reads as a pass: the
// rule reports nothing, exactly as it would over a token it could not match.
// The old bound test compared against rule.Regex directly, so it never met the
// floor; these arms go through the pipeline, where every check runs.
const base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func filler(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = base64URL[i%len(base64URL)]
	}
	return string(b)
}

// q133JWT is the pattern the rule shipped with between Q133 and Q164: the whole
// three-segment structure, every repeat at RE2's cap. It is the before arm for
// both the ceiling test and the benchmark, and it is written once because the
// two have to be comparing the same thing.
const q133JWT = `\b(eyJ[A-Za-z0-9_-]{8,1000}\.eyJ[A-Za-z0-9_-]{8,1000}\.[A-Za-z0-9_-]{10,1000})`

// jwtSegments is a token whose three segments are exactly the lengths given.
func jwtSegments(tb testing.TB, header, payload, sig int) string {
	tb.Helper()
	seg := func(n int) string { return "eyJ" + filler(n-3) }
	return seg(header) + "." + seg(payload) + "." + filler(sig)
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

// The ceiling is gone, driven end to end through the pipeline rather than
// against the pattern -- the pattern no longer knows how long a token is, which
// is the change.
//
// The second arm is the positive control, and it is what makes the first one
// worth reading. It loads the same ruleset carrying Q133's bounded pattern with
// no extent beside it, so the two arms differ in exactly the thing under
// change: same loader, same pipeline, same buffer, one finding against none.
// Without it a green first arm is equally consistent with a fixture that was
// never past the ceiling.
func TestTheSegmentCeilingIsGone(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		header, payload, sig int
	}{
		{"a payload one byte past the old ceiling", 36, 1004, 43},
		{"a header one byte past it", 1004, 74, 43},
		{"an access token with many claims", 36, 20000, 43},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := []byte("token: " + jwtSegments(t, tc.header, tc.payload, tc.sig) + "\n")

			res, err := Buffer("p", buf, []rules.Rule{shippedJWT(t)})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 1 {
				t.Errorf("as shipped: %d findings, want 1", len(res.Findings))
			}

			res, err = Buffer("p", buf, []rules.Rule{rewrittenJWT(t, q133JWT, false)})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 0 {
				t.Errorf("with Q133's bounded pattern: %d findings, want 0 -- "+
					"this token is inside the old ceiling, so the arm above "+
					"proves nothing", len(res.Findings))
			}
		})
	}
}

// The floors survive, and they are the half of the old bounds that was about
// JWTs rather than about RE2. A pattern of eleven bytes finds every `eyJ` in a
// tree; the extent is the whole of what keeps the rule quiet on them.
func TestTheDetectionPatternAloneReportsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"an encoded JSON object", "eyJhbGciOiJIUzI1NiJ9"},
		{"two of them and no signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
		{"an object in a config line", `{"claims":"eyJhbGciOiJIUzI1NiJ9"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := shippedJWT(t)
			if !rule.Regex.MatchString(tc.text) {
				t.Fatal("the detection pattern does not match, so this " +
					"establishes nothing about the extent")
			}
			res, err := Buffer("p", []byte(tc.text), []rules.Rule{rule})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 0 {
				t.Errorf("%d findings, want 0", len(res.Findings))
			}

			// Which of the checks said no. A zero from the entropy floor reads
			// exactly like a zero from the extent, and here it would be the
			// floor: the capture before the extent is eleven bytes, which
			// cannot carry more than log2(11) = 3.459 bits against a floor of
			// 3.5, so a rule with this pattern and no extent reports nothing on
			// any input at all. TestTheFloorIsOnlyMeetableBecauseOfTheExtent in
			// internal/rules is that coupling, and the loader refuses such a
			// rule at startup.
			//
			// So the control strips the checks as well, leaving the pattern.
			// It reports on all of these, which is what says the extent is the
			// whole of what keeps the shipped rule quiet on them.
			bare := rule
			bare.Extent = ""
			bare.Validators = nil
			res, err = Buffer("p", []byte(tc.text), []rules.Rule{bare})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) == 0 {
				t.Error("the pattern alone reports nothing here, so the arm " +
					"above says nothing about the extent")
			}
		})
	}
}

// A token holds two `eyJ`s, and the prefilter reports both. The old pattern
// matched the whole token, so FindAll stepped over the second; the detection
// pattern matches eleven bytes, so the step has to come from the extent
// instead -- and it does, at exactly one place, for both match arms.
//
// Getting this wrong reports one token as two findings, which is a precision
// regression of the kind this repo calls the product.
func TestATokenIsOneFindingAndNotOnePerSegment(t *testing.T) {
	seg := func(n int) string { return "eyJ" + filler(n-3) }
	for _, tc := range []struct {
		name string
		text string
		hits int
		want int
	}{
		{
			// Two ordinary tokens, four `eyJ`s. The second in each is the
			// payload, and the extent has to be what steps over it.
			"two tokens",
			jwtSegments(t, 200, 2000, 43) + " b " + jwtSegments(t, 36, 74, 86),
			4, 2,
		},
		{
			// Four dot-separated segments, three of them opening on `eyJ` --
			// the shape a JWE compact serialization has five of. A whole token
			// starts at the first segment and another starts at the second, and
			// they overlap, so whichever arm does not step over the extent
			// reports the same bytes twice. FindAll's own step is eleven bytes
			// here and cannot reach it.
			"a four-segment string that starts a token twice",
			seg(40) + "." + seg(40) + "." + seg(40) + "." + filler(43),
			3, 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := shippedJWT(t)
			buf := []byte("a " + tc.text + " c\n")

			at, ok := keywordPositions(buf, rule.Keywords, len(buf)+1)
			if !ok {
				t.Fatal("over budget")
			}
			if len(at) != tc.hits {
				t.Fatalf("the prefilter reports %d hits, want %d -- otherwise "+
					"this does not exercise the step", len(at), tc.hits)
			}

			whole, err := matchAll("p", buf, identity, rule)
			if err != nil {
				t.Fatal(err)
			}
			anchored, err := matchAt("p", buf, identity, rule, at)
			if err != nil {
				t.Fatal(err)
			}
			if len(whole) != tc.want {
				t.Errorf("the whole-buffer pass reports %d findings, want %d",
					len(whole), tc.want)
			}
			if !reflect.DeepEqual(whole, anchored) {
				t.Errorf("the arms disagree: whole-buffer %d, anchored %d",
					len(whole), len(anchored))
			}
		})
	}
}

// hs512Sample is jwt.io's published example signed HS512 with its published
// key, and the length of its signature. HS512 is the longest of the three HMACs
// the check knows, so it is the case a bound would truncate first.
func hs512Sample(tb testing.TB) (string, int) {
	tb.Helper()
	enc := base64.RawURLEncoding
	head, err := json.Marshal(map[string]string{"alg": "HS512", "typ": "JWT"})
	if err != nil {
		tb.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"sub": "1234567890", "iat": 1516239022})
	if err != nil {
		tb.Fatal(err)
	}
	signing := enc.EncodeToString(head) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha512.New, []byte("your-256-bit-secret"))
	mac.Write([]byte(signing))
	sample := signing + "." + enc.EncodeToString(mac.Sum(nil))
	return sample, len(sample) - len(signing) - 1
}

// The signature is the segment whose exact end decides precision, and this is
// that property driven through the pipeline rather than against the extent.
//
// jwt-sample-key recomputes the HMAC over `header.payload` and compares it to
// the signature it was handed. Hand it a prefix and the comparison fails, the
// published sample stops being recognised as published, and a token anyone can
// look up is reported as a credential. The detection pattern is eleven bytes
// and this signature is 86, so a zero here is a statement that the extent --
// and nothing else -- is what the check read.
//
// Q133 drove this as a bound: the same ruleset with the signature repeat at 43
// reported the sample. That mutation can no longer land, because no bound in
// the pattern reaches the capture any more, and a control whose mutation does
// not bite tests nothing while reading exactly like one that works. So it moved
// to the layer that can still produce the truncation, in
// validate.TestATruncatedSignatureUnsuppressesAPublishedSample.
func TestTheWholeSignatureReachesTheSampleCheck(t *testing.T) {
	sample, sig := hs512Sample(t)
	if sig != 86 {
		t.Fatalf("the HS512 signature is %d bytes, so this is not the case "+
			"this was written for", sig)
	}
	rule := shippedJWT(t)
	if reach := rule.Reach; reach >= sig {
		t.Fatalf("the pattern reaches %d bytes and the signature is %d, so a "+
			"pass here does not say the extent supplied the rest", reach, sig)
	}

	res, err := Buffer("p", []byte("token: "+sample+"\n"), []rules.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%d findings, want 0 -- a finding means jwt-sample-key was "+
			"handed something other than the whole signature", len(res.Findings))
	}
}

// rewrittenJWT loads the shipped ruleset with the jwt pattern replaced, so a
// control goes through the same loader the binary uses rather than around it.
// extent says whether the rewritten rule keeps the extent beside it: a control
// standing in for the rule as Q133 shipped it needs the pattern and the absence
// of an extent together, since either alone is a rule that never existed.
func rewrittenJWT(tb testing.TB, pattern string, extent bool) rules.Rule {
	tb.Helper()
	for _, rule := range rewrittenSet(tb, pattern, extent) {
		if rule.ID == "jwt" {
			return rule
		}
	}
	tb.Fatal("no jwt rule in the rewritten set")
	return rules.Rule{}
}

// rewrittenSet is the whole shipped ruleset with the jwt rule rewritten, which
// is what a benchmark needs: the two arms have to be two rulesets in one
// process, or the difference between them is the machine.
func rewrittenSet(tb testing.TB, pattern string, extent bool) []rules.Rule {
	tb.Helper()
	var doc map[string]any
	if err := json.Unmarshal(embedded.Shipped, &doc); err != nil {
		tb.Fatal(err)
	}
	for _, entry := range doc["rules"].([]any) {
		if m := entry.(map[string]any); m["id"] == "jwt" {
			m["regex"] = pattern
			if !extent {
				delete(m, "extent")
			}
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
	return set
}
