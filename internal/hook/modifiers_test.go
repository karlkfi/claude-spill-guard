package hook

import (
	"strings"
	"testing"
)

// Q220's table, driven 2026-11-09 against zsh 5.9 (`zsh -f -c`) and bash
// 5.3.15 over a file holding the planted key: each shell's column is what
// that shell printed, and the hook must block exactly where it did. In bash
// the zsh words are a command not found, so a block there would be over a
// file nothing opens.
//
// bash's coproc arm is driven rather than inferred: `coproc cat k.env; read
// -r l <&"${COPROC[0]}"; echo "$l"` printed the key. A drive that slept before
// reading found the descriptors closed, because the coprocess had exited.
func TestAShellModifierHidesNoReaderUnderTheShellThatHasIt(t *testing.T) {
	for _, tc := range []struct {
		form      string
		bash, zsh bool // whether each shell printed the key
	}{
		{"cat %s", true, true},
		{"noglob cat %s", false, true},
		{"nocorrect cat %s", false, true},
		{"repeat 1 cat %s", false, true},
		{"coproc cat %s; sleep 1; cat <&p", true, true},
		{"coproc cat %s", true, true},
		{"time cat %s", true, true},
		// The row read this as covered because `zsh -f -c '- cat k.env'`
		// printed nothing. That run measured zsh's own option parsing, which
		// takes a -c string opening with `-` as flags: `bad option string`.
		// `eval '- cat k.env'`, and the same line after another command, both
		// print the key.
		{"- cat %s", false, true},
		{"repeat 0 cat %s", false, false},
		{"command noglob cat %s", false, false},
	} {
		for _, shell := range []string{"bash", "zsh"} {
			want := tc.bash
			if shell == "zsh" {
				want = tc.zsh
			}
			t.Run(shell+"/"+tc.form, func(t *testing.T) {
				shellNamed(t, shell)
				dir, name := planted(t)
				code, stdout, stderr := drive(t, bashCall(t, strings.ReplaceAll(tc.form, "%s", name), dir))
				if code != 0 {
					t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
				}
				if !want {
					if stdout != "" || stderr != "" {
						t.Errorf("stdout %q, stderr %q; want silent", stdout, stderr)
					}
					return
				}
				if reason := reasonOf(t, stdout); !strings.Contains(reason, name) {
					t.Errorf("reason = %q, want the file blocked", reason)
				}
			})
		}
	}
}
