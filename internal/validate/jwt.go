package validate

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
)

// publishedSampleKeys is the HMAC secrets a JWT debugger prints beside its own
// example token, so that anyone can reproduce the signature in the third pane.
//
// One entry, and it is measured rather than recalled: HMAC-SHA256 over the
// header and payload of the token on jwt.io's front page, keyed with this
// string, reproduces that token's signature byte for byte.
//
// jwt.io has changed this default at least once, so a second entry is likely
// owed. Adding one needs a token to measure it against: an unmeasured entry
// suppresses a real credential, invisibly, which is the hazard
// NotPlaceholderCard's own comment names.
var publishedSampleKeys = [][]byte{
	[]byte("your-256-bit-secret"),
}

// hmacHashes is the JWS algorithms this can check. Only the symmetric ones: a
// published RS256 sample is signed with a private key nobody prints, so there
// is nothing to recompute.
var hmacHashes = map[string]func() hash.Hash{
	"HS256": sha256.New,
	"HS384": sha512.New384,
	"HS512": sha512.New,
}

// NotSampleJWT reports whether a JWT candidate is something other than a token
// signed with a published sample key.
//
// This is the second check the jwt rule names, beside its entropy floor, and
// the floor cannot do this job: the jwt.io sample measures 5.4441 bits per byte
// against a floor of 3.5, because a sample token and a live one are the same
// object. What separates them is the signing key, which a debugger has to
// publish for its own example to be reproducible. rules/README.md carries why
// keys are the better half of that pair to enumerate, and what the check costs.
//
// Anything unparseable survives: three segments, a JSON header and one of the
// HMACs above are what it takes to show a candidate is a sample, and short of
// that there is nothing to drop it on. That is the opposite reading to
// NotPlaceholderCard, where a malformed candidate is not evidence of a card.
//
// The polarity is the package's: true means the candidate survives.
func NotSampleJWT(candidate string) bool {
	header, rest, found := strings.Cut(candidate, ".")
	if !found {
		return true
	}
	payload, signature, found := strings.Cut(rest, ".")
	if !found || strings.Contains(signature, ".") {
		return true
	}

	newHash, ok := hmacHashes[algorithm(header)]
	if !ok {
		return true
	}
	want, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return true
	}

	signing := header + "." + payload
	for _, key := range publishedSampleKeys {
		mac := hmac.New(newHash, key)
		mac.Write([]byte(signing))
		if hmac.Equal(mac.Sum(nil), want) {
			return false
		}
	}
	return true
}

// algorithm decodes a JWS header segment and returns its alg, or "" if the
// segment is not base64url, not JSON, or carries no alg.
func algorithm(segment string) string {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return ""
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ""
	}
	return header.Alg
}
