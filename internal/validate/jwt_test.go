package validate

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The token on jwt.io's front page, and what it measures at. Its signature is
// HMAC-SHA256 over the first two segments keyed with your-256-bit-secret, which
// is what publishedSampleKeys asserts and what this table drives.
const sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

// The survivors carry the claim, as they do for the other two drop-lists here.
// A signature check tested only on tokens it drops passes for a function that
// returns false, and every bearer token in the corpus goes quiet with nothing
// to show it.
func TestNotSampleJWT(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"the token on the debugger's front page", sampleJWT, false},
		// The case a token denylist cannot reach: same published key, a payload
		// somebody edited in the debugger before pasting the result.
		{"an edited payload re-signed with the same key",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgUm9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
				"8-PNa_8kYAU1vpJEf1WAYGRLjhcGyTSqSbTsm3HkUMA", false},
		{"the same key under HS384",
			"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
				"r3V1vcaaoGcwaOLRxgwEzUpx1Y7wxUdJTdCSgGDZ4bRL4vyON3RoUD--yBNJU7-Z", false},
		{"the same key under HS512",
			"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
				"Kcj1mjUmQNrkibaCkqBl4WvP4rq6GiLFT1u6ZxumzJ120UHZmiu0qvGYeXaBK6L0AVTqidtem4ZQXMgNOZw5pg", false},

		{"the same claims signed with a secret nobody published",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
				"nna48HajZ_5M66CuuTZ4qsslFt5RBMgK4BznEXH3q7U", true},
		// alg is read rather than assumed. The signature here does verify under
		// the published key, and RS256 says it was never meant to be an HMAC --
		// so recomputing one is not evidence about this token.
		{"an RS256 header over a signature that would verify as HS256",
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
				"ufp8ajzhS9qvYRRmzhfih3WtlDjvz_NMhJN_xdLO894", true},

		// Nothing below can be shown to be a sample, and this check reports on
		// that reading rather than dropping.
		{"the sample with its signature removed",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", true},
		{"a fourth segment", sampleJWT + ".Zm9v", true},
		{"no dots at all", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", true},
		{"a header that is not base64url", "!!!.eyJzdWIiOiIxIn0.Zm9vYmFyYmF6", true},
		{"a header that is base64url and not JSON", "bm90IGpzb24.eyJzdWIiOiIxIn0.Zm9vYmFyYmF6", true},
		{"a header carrying no alg", "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.Zm9vYmFyYmF6", true},
		{"a signature that is not base64url",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.++++", true},
		{"the empty string", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NotSampleJWT(tc.candidate); got != tc.want {
				t.Errorf("NotSampleJWT(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}

// The failure a truncated signature produces, kept because the truncation is
// what the extent exists to prevent and a mechanism nothing drives is a
// mechanism nobody can check.
//
// Q133 drove this one rung up, as a bound: the jwt pattern's signature repeat
// looked like the free one -- nothing follows it, so a short bound truncates
// the capture rather than refusing the token -- and setting it to 43, the HS256
// length and so the number a bound picked from the corpus fixtures would land
// on, took a published sample from suppressed to reported. Q164 removed the
// bounds, so that mutation can no longer land: the extent measures the token
// and no repeat in the pattern reaches the capture. A control whose mutation
// does not bite reads exactly like one that works, so it moved here, to the
// check that still takes a string and can still be handed a prefix of one.
//
// What it establishes is the cost of an extent that ends one byte early, which
// is why TestTheExtentEndsWhereTheTokenDoes drives every terminator.
func TestATruncatedSignatureUnsuppressesAPublishedSample(t *testing.T) {
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

	if NotSampleJWT(sample) {
		t.Fatal("the whole sample is not recognised as published, so a " +
			"difference below is not the truncation")
	}
	for _, short := range []int{1, 43} {
		if !NotSampleJWT(sample[:len(sample)-short]) {
			t.Errorf("a signature %d byte(s) short is still recognised as "+
				"published, so this does not show what truncation costs", short)
		}
	}
}
