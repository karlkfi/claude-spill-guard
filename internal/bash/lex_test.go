package bash

import "testing"

// tokenize is the whole token pipeline, as every caller runs it and as the
// upstream suite's own helper does.
func tokenize(t *testing.T, cmd string) []string {
	t.Helper()
	toks, qf, err := lex(cmd)
	if err != nil {
		t.Fatalf("lex(%q): %v", cmd, err)
	}
	toks, qf = splitOperatorRuns(toks, qf)
	toks, _ = glueDollarParen(toks, qf)
	return toks
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
		if _, _, err := lex(in); err == nil {
			t.Errorf("lex(%q) succeeded, want an error", in)
		}
	}
}

// lexOne is the lexer's answer for a single word: the stripped token and where
// quoting first appeared in it.
func lexOne(t *testing.T, word string) (string, int) {
	t.Helper()
	toks, qf, err := lex(word)
	if err != nil {
		t.Fatalf("lex(%q): %v", word, err)
	}
	if len(toks) != 1 {
		t.Fatalf("lex(%q) gave %d tokens, want 1: %q", word, len(toks), toks)
	}
	return toks[0], qf[0]
}

// Bash settles what a word IS before it removes the quotes, so quoting decides
// whether a word assigns a variable or names a program to run.
//
// The table is bash 5.3.15's own answer, driven 2026-09-09 rather than reasoned
// about, with `bash -c "<word>; printf '[%s]' \"${SP-UNSET}\""` -- the `${SP-}`
// form rather than a bare `$SP`, because `SP=”` assigns and prints nothing, so
// a bare probe cannot tell it from the ten words that assign nothing at all. Six
// rows set the variable and ten leave it unset, which is what says the drive can
// print either answer.
//
// The rule it establishes: quoting or escaping any character up to and including
// the `=` makes the word a command; quoting inside the VALUE leaves it an
// assignment. Escaping is the half a pass over `'` and `"` never reaches, and
// `SP\=/x` is the row that breaks a rule written as "quoting the name" -- the
// escaped character is the `=` itself, which is neither name nor value.
func TestQuotingDecidesWhetherAWordAssigns(t *testing.T) {
	for _, tc := range []struct {
		word string
		want bool // bash set SP
	}{
		{`SP=/x`, true},
		{`SP="/x"`, true},
		{`SP='/x'`, true},
		{`SP=x"y"`, true},
		{`SP='a b'`, true},
		{`SP=''`, true},

		{`'SP=/x'`, false},
		{`"SP=/x"`, false},
		{`S'P'=/x`, false},
		{`S"P"=/x`, false},
		{`S''P=/x`, false},
		{`SP""=x`, false},
		{`SP"="/x`, false},
		{`SP\=/x`, false},
		{`\SP=/x`, false},
		{`S\P=/x`, false},
	} {
		t.Run(tc.word, func(t *testing.T) {
			tok, qf := lexOne(t, tc.word)
			if got := isAssignment(tok, qf); got != tc.want {
				t.Errorf("isAssignment(%q, %d) = %v, want %v (bash: %v)",
					tok, qf, got, tc.want, tc.want)
			}
		})
	}
}

// The same boundary at the neighbouring predicate, and blunter: a keyword has no
// `=` for the quoting to sit after, so quoting any part of it is enough.
//
// Driven the same day on 5.3.15 as `cd <dir> && bash -c "<word> cd sub; basename
// $PWD"`. `time` and `!` are the controls that make the table readable: written
// plainly they are reserved words whose `cd` really does persist -- neither
// forks -- and every quoted spelling of them runs a program bash cannot find, so
// the shell never leaves the directory it started in. `if` and `while` are not
// controls here: written plainly they are a syntax error without their `then` or
// `do`, which is why upstream reaches for `time` too.
func TestQuotingDecidesWhetherAWordIsAKeyword(t *testing.T) {
	for _, tc := range []struct {
		word string
		want bool // bash honoured the reserved word
	}{
		{`time`, true},
		{`!`, true},

		{`'time'`, false},
		{`'if'`, false},
		{`"if"`, false},
		{`i"f"`, false},
		{`\if`, false},
		{`'while'`, false},
	} {
		t.Run(tc.word, func(t *testing.T) {
			tok, qf := lexOne(t, tc.word)
			if got := isReservedWord(tok, qf); got != tc.want {
				t.Errorf("isReservedWord(%q, %d) = %v, want %v", tok, qf, got, tc.want)
			}
		})
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
			if got := StripEnvPrefix(tc.in, Unquoted(len(tc.in))); !equalStrings(got, tc.want) {
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
			qf := Unquoted(len(tc.in))
			k := ShKeywordPeel(tc.in, qf)
			got := StripEnvPrefix(tc.in[k:], qf[k:])
			if !equalStrings(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
