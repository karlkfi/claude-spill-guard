// anthropic-api-key against the edges of the shape it matches, because Anthropic
// publishes no format and the length is the one thing here taken on another
// detector's word. rules/README.md carries the sources.

package scan

import (
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/testvec"
)

func TestAnthropicKeyShapes(t *testing.T) {
	set := loadShipped(t)
	vec := testvec.Load(t)
	key := vec.Get(t, "anthropic-api-key")
	admin := vec.Get(t, "anthropic-admin-api-key")
	body := strings.TrimPrefix(key, "sk-ant-api03-")

	cases := []struct {
		name string
		text string
		want int
	}{
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
	}
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
			if tc.want == 1 && got.Findings[0].RuleID != "anthropic-api-key" {
				t.Errorf("reported by %q", got.Findings[0].RuleID)
			}
		})
	}
}
