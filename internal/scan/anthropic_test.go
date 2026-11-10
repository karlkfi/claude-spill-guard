// The two Anthropic rules against the edges of the shapes they match, because
// Anthropic publishes no format and every length here is taken on another
// scanner's word. rules/README.md carries the sources.

package scan

import (
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

type shapeCase struct {
	name string
	text string
	want int
}

func checkShapes(t *testing.T, rule string, cases []shapeCase) {
	t.Helper()
	set := loadShipped(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Buffer("t", []byte(tc.text+"\n"), set)
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}
			if got.Skipped != Scanned {
				t.Fatalf("not read: %s", got.Skipped)
			}
			if len(got.Findings) != tc.want {
				t.Fatalf("%d finding(s), want %d:\n%s", len(got.Findings), tc.want, report(got.Findings))
			}
			if tc.want == 1 && got.Findings[0].RuleID != rule {
				t.Errorf("reported by %q", got.Findings[0].RuleID)
			}
		})
	}
}

func TestAnthropicKeyShapes(t *testing.T) {
	vec := testvec.Load(t)
	key := vec.Get(t, "anthropic-api-key")
	admin := vec.Get(t, "anthropic-admin-api-key")
	body := strings.TrimPrefix(key, "sk-ant-api03-")

	checkShapes(t, "anthropic-api-key", []shapeCase{
		{"an API key", key, 1},
		{"an admin key", admin, 1},
		{"quoted, as source holds one", `key = "` + key + `"`, 1},
		{"one byte short", "sk-ant-api03-" + body[1:], 0},
		{"one byte long", "sk-ant-api03-x" + body, 0},
		{"glued to a word in front", "x" + key, 0},
		{"glued to a word behind", key + "x", 0},
		{"a prefix no source names", "sk-ant-api02-" + body, 0},
		{"no closing AA", "sk-ant-api03-" + body[:len(body)-2] + "ZZ", 0},
		{"a padded placeholder", "sk-ant-api03-" + strings.Repeat("X", 93) + "AA", 0},
	})
}

// The floor is Claude Code's own scanner's, 20 body bytes. Prose quotes the
// bare prefix, and that is what the floor keeps quiet.
func TestAnthropicTokenShapes(t *testing.T) {
	vec := testvec.Load(t)
	oat := vec.Get(t, "anthropic-oauth-token")
	body := strings.TrimPrefix(oat, "sk-ant-oat01-")
	floor := body[:20]

	checkShapes(t, "anthropic-token", []shapeCase{
		{"an OAuth access token", oat, 1},
		{"a session key", vec.Get(t, "anthropic-session-key"), 1},
		{"an OAuth refresh token", "sk-ant-ort01-" + body, 1},
		{"a session git credential", "sk-ant-ccsr-" + body, 1},
		{"a later version digit", "sk-ant-oat02-" + body, 1},
		{"at the floor", "sk-ant-oat01-" + floor, 1},
		// No hyphen, so no word boundary anywhere past the 1000-byte cap.
		{"a body past the cap", "sk-ant-oat01-" + strings.Repeat("q7Zk3Wb9", 160), 1},
		// Words clear the entropy floor; only a padded placeholder falls to it.
		{"a placeholder written in words", vec.Get(t, "anthropic-token-word-placeholder"), 1},
		{"one byte under the floor", "sk-ant-oat01-" + floor[1:], 0},
		{"the prefix quoted in prose", "tokens begin `sk-ant-oat01-` and expire", 0},
		{"the prefix with an ellipsis", "sk-ant-oat01-...", 0},
		{"glued to a word in front", "x" + oat, 0},
		{"a padded placeholder", "sk-ant-oat01-" + strings.Repeat("x", 40), 0},
		{"a prefix no source names", "sk-ant-oak01-" + body, 0},
		{"a version with one digit", "sk-ant-oat1-" + body, 0},
	})
}
