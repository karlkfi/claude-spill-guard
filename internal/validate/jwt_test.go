package validate

import "testing"

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
