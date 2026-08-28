package bash

import (
	"fmt"
	"testing"
)

func TestCommandSubstitutions(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		quotes   bool
		want     []string
	}{
		{"a single-quoted substitution is literal", "echo '$(rm -rf /)'", true, nil},
		{"a double-quoted one is live", `echo "$(id)"`, true, []string{"id"}},
		{"a bare one is live", "echo $(id)", true, []string{"id"}},
		{"a backtick one is live", "echo `id`", true, []string{"id"}},
		// A backslash inside a backtick body escapes the next byte, so an
		// escaped backtick does not close it.
		{"an escaped backtick does not close the body", "cat `a\\`b`", true,
			[]string{"a\\`b"}},
		{"arithmetic holds no command", "echo $((1+2))", true, nil},
		// How bash reads an unquoted heredoc body: the apostrophe in a `don't`
		// must not switch the scanner off for the rest of the body (Q50).
		{"quotes off makes every substitution live", "don't $(id)", false,
			[]string{"id"}},
		{"quotes on and the same input finds nothing", "don't $(id)", true, nil},
		// Fail-safe: a possible missed offender, never a fabricated one.
		{"an unterminated substitution contributes nothing", `echo "$(id`, true, nil},
		{"an unterminated backtick likewise", "echo `id", true, nil},
		// Only the outermost, so the caller recurses on the body.
		{"only the outermost comes back", `echo "$(echo "$(id)")"`, true,
			[]string{`echo "$(id)"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CommandSubstitutions(tc.in, tc.quotes)
			if !equalStrings(got, tc.want) {
				t.Errorf("CommandSubstitutions(%q, %v) = %q, want %q",
					tc.in, tc.quotes, got, tc.want)
			}
		})
	}
}

// A `case` pattern's `)` needs no opener, so it must not end a `$(…)` (Q81).
//
// Every command here was run under bash 5.3 while the upstream tests were
// written: each prints its clause's output followed by the `T` after the
// substitution, which is what says bash read the whole clause as inside it.
// Only bash 3.2 agrees with the pre-fix reading, where the body came back as
// `case $x in a` and the clause -- heredocs included -- was never scanned.
func TestCaseClauseDoesNotCloseSubstitution(t *testing.T) {
	bodies := []struct{ name, body string }{
		{"a bare pattern", "case $x in a) cat /etc/passwd;; esac"},
		{"a parenthesised pattern", "case $x in (a) cat /etc/passwd;; esac"},
		{"a nested case closes only its own clause",
			"case $x in a) case $y in b) cat /etc/passwd;; esac;; esac"},
		// `case $x in esac` is a clause with no patterns, so the next `)` is
		// the substitution's own.
		{"esac may stand where a pattern would", "case $x in esac"},
		{"a quoted pattern keeps its paren literal",
			`case $x in "a)b") cat /etc/passwd;; esac`},
		{"a keyword reopens command position",
			"if true; then case $x in a) cat /etc/passwd;; esac; fi"},
		// The gap Q81 closes: the clause body was never scanned, so a heredoc
		// written there went with it.
		{"a heredoc in a clause is reached",
			"case $x in a) cat <<EOF\n$(cat /etc/passwd)\nEOF\n;; esac"},
		// `echo case` passes an operand. Reading it as the keyword would
		// swallow the real close and drop a substitution that reads fine.
		{"case as an operand", "echo case"},
		{"case as an operand after a flag", "grep -c case /dev/null"},
		{"esac and in as operands", "echo esac in case"},
	}
	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			in := fmt.Sprintf(`echo "$(%s)" T`, tc.body)
			got := CommandSubstitutions(in, true)
			if !equalStrings(got, []string{tc.body}) {
				t.Errorf("CommandSubstitutions(%q) = %q, want [%q]", in, got, tc.body)
			}
		})
	}

	for _, term := range []string{";;", ";&", ";;&"} {
		t.Run("clause terminator "+term, func(t *testing.T) {
			body := fmt.Sprintf("case $x in a) echo P%s b) cat /etc/passwd;; esac", term)
			in := fmt.Sprintf(`echo "$(%s)" T`, body)
			if got := CommandSubstitutions(in, true); !equalStrings(got, []string{body}) {
				t.Errorf("got %q, want [%q]", got, body)
			}
		})
	}
}

// A heredoc body inside a `$(…)` is data, so the scan steps over it (Q109).
//
// Read as shell syntax, an apostrophe in the body opened a single-quoted run
// that never closed: the scan ran to end of input, returned no terminator, and
// the whole substitution went unexamined. StripHeredocBodies does not pre-empt
// this in a `case` clause, where its own context tracking ends the substitution
// at the pattern's `)` before the `<<` is reached.
func TestHeredocInSubstitution(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"an apostrophe in a body does not swallow the substitution",
			"case $x in a) cat <<EOF\nit's fine\nEOF\ncat /etc/passwd;; esac"},
		{"a tab-stripped delimiter is recognised",
			"case $x in a) cat <<-EOF\n\tit's fine\n\tEOF\ncat /etc/passwd;; esac"},
		{"a quoted delimiter still ends its body",
			"case $x in a) cat <<'EOF'\nit's fine\nEOF\ncat /etc/passwd;; esac"},
		{"a here-string arms nothing", `grep pat <<< "it's fine"`},
		// `1<<4` is a shift. Armed as a delimiter it would swallow `4));…` as
		// body text and the substitution would never close.
		{"an arithmetic shift arms nothing", "n=$((1<<4)); cat /etc/passwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := fmt.Sprintf(`echo "$(%s)" T`, tc.body)
			if got := CommandSubstitutions(in, true); !equalStrings(got, []string{tc.body}) {
				t.Errorf("got %q, want [%q]", got, tc.body)
			}
		})
	}

	// bash swallows a body with no terminator to end of input, so no `)` after
	// it can close the substitution -- returning nothing is correct.
	t.Run("an unterminated body runs to the end", func(t *testing.T) {
		in := "echo \"$(cat <<EOF\nit's fine\n)\" T"
		if got := CommandSubstitutions(in, true); len(got) != 0 {
			t.Errorf("got %q, want nothing", got)
		}
	})
}
