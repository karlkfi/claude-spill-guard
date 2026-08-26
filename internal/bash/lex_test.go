package bash

import "testing"

// tokenize is the whole token pipeline, as every caller runs it and as the
// upstream suite's own helper does.
func tokenize(t *testing.T, cmd string) []string {
	t.Helper()
	toks, err := lex(cmd)
	if err != nil {
		t.Fatalf("lex(%q): %v", cmd, err)
	}
	return glueDollarParen(splitOperatorRuns(toks))
}

func TestLex(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     []string
	}{
		// From LexTests upstream.
		{"operators become their own tokens", "a && b | c",
			[]string{"a", "&&", "b", "|", "c"}},
		// `|&` split into `|` and `&` reads as a backgrounded command that
		// never ran. Only exit-status-guard's copy had it as one operator.
		{"pipe-both-streams is one operator", "a |& b", []string{"a", "|&", "b"}},
		{"a newline is a boundary, not whitespace", "a\nb", []string{"a", "\n", "b"}},

		// The runs shlex glues, which splitOperatorRuns has to take apart: a
		// run left whole matches no operator the group loop keys on, so the
		// command boundary is missed and two commands merge into one segment.
		{"a subshell close glued to a separator", "(cd x); echo done",
			[]string{"(", "cd", "x", ")", ";", "echo", "done"}},
		{"a doubled paren", "((echo hi))",
			[]string{"(", "(", "echo", "hi", ")", ")"}},
		{"longest-first, so the three-character operator wins", "a &>> b",
			[]string{"a", "&>>", "b"}},
		{"and the here-string operator beats the heredoc one", "a <<< b",
			[]string{"a", "<<<", "b"}},

		// Quoting. A word token holding an operator character is not an
		// operator run and is left intact.
		{"a quoted operator character stays in its word", `cat "a;b"`,
			[]string{"cat", "a;b"}},
		{"a quoted newline stays in its word", "cat 'a\nb'",
			[]string{"cat", "a\nb"}},
		{"an escaped space keeps one word", `cat a\ b`, []string{"cat", "a b"}},
		{"a backslash inside double quotes escapes only what it can", `echo "a\"b"`,
			[]string{"echo", `a"b`}},
		{"a backslash inside single quotes is literal", `echo 'a\b'`,
			[]string{"echo", `a\b`}},
		// A trailing backslash inside single quotes is literal too, so the
		// quote closes. Treating it as an escape swallows the closing `'`
		// and the parse errors instead.
		{"a backslash before the closing single quote", `cat 'a\'`,
			[]string{"cat", `a\`}},
		{"an empty quoted word is a token", "echo '' x", []string{"echo", "", "x"}},

		// glueDollarParen: without it `$(` tokenizes as a lone `$`, which
		// reads as a literal filename, and the substitution slips through.
		{"a substitution keeps its dollar attached to the paren", "echo $(id)",
			[]string{"echo", "$(", "(", "id", ")"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenize(t, tc.in); !equalStrings(got, tc.want) {
				t.Errorf("tokenize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A command the lexer cannot read is one no caller should judge, so it reports
// rather than guessing at a token stream.
func TestLexUnbalanced(t *testing.T) {
	for _, in := range []string{
		`echo "unclosed`,
		"echo 'unclosed",
		`echo trailing\`,
		// The other direction of the same rule: the `\` is literal, so the
		// `'` after it closes and the final `'` opens a quote nothing shuts.
		`echo 'x\'y'`,
	} {
		if _, err := lex(in); err == nil {
			t.Errorf("lex(%q) succeeded, want an error", in)
		}
	}
}

func TestStripEnvPrefix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in, want []string
	}{
		{"the prefix is peeled", []string{"A=1", "B=2", "cmd", "arg"},
			[]string{"cmd", "arg"}},
		{"a bare assignment is not a command", []string{"A=1"}, nil},
		{"a token that only looks like one is left", []string{"1=x", "cmd"},
			[]string{"1=x", "cmd"}},
		{"nothing to peel", []string{"cmd", "A=1"}, []string{"cmd", "A=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripEnvPrefix(tc.in); !equalStrings(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStripShKeywords(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in, want []string
	}{
		{"a leading keyword is peeled", []string{"if", "cmd"}, []string{"cmd"}},
		{"several are", []string{"while", "!", "cmd"}, []string{"cmd"}},
		{"a keyword used as an operand is not", []string{"echo", "if"},
			[]string{"echo", "if"}},
		// Bash's order in a simple command is reserved word, then inline env
		// assignment, then the command name -- so the keywords come off first.
		{"and the env prefix comes off after", []string{"until", "LC_ALL=C", "grep"},
			[]string{"grep"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StripEnvPrefix(StripShKeywords(tc.in))
			if !equalStrings(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
