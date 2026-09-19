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

		// The append operator, driven the same way: `+=` assigns, and the
		// quoting boundary moves one byte right with it -- an escape ON the
		// `+` or on the `=` is still inside the operator, so both run a
		// program bash cannot find. `SP++=x` is not an operator at all.
		{`SP+=/x`, true},
		{`SP+='/x'`, true},
		{`SP+=`, true},
		{`SP=+x`, true},
		{`'SP+=/x'`, false},
		{`SP\+=/x`, false},
		{`SP+\=/x`, false},
		{`SP++=/x`, false},

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
		// A subscripted prefix is peeled, because bash peels it and runs the
		// command behind it (Q175).
		{"a subscripted prefix is peeled", []string{"A[0]=1", "cmd", "arg"},
			[]string{"cmd", "arg"}},
		{"and one bash reads as a command name is not",
			[]string{"A[0]]=1", "cmd"}, []string{"A[0]]=1", "cmd"}},
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

// The name has to come off the token the way bash takes it off, because the
// `+` belongs to the operator. Splitting on the first `=` instead yields
// `SP+`, a name nothing ever reads -- so a tracker poisons `SP+` and leaves
// `SP` on the map at a value bash has already appended to.
//
// The value rows are the ones that keep the split from being done by a trim:
// `A+=b=c` has an `=` inside the value, and `A+=` has no value at all.
func TestSplitAssignment(t *testing.T) {
	for _, tc := range []struct {
		tok   string
		name  string
		form  AssignForm
		value string
	}{
		{"A=1", "A", AssignPlain, "1"},
		{"A+=1", "A", AssignAppend, "1"},
		{"A+=b=c", "A", AssignAppend, "b=c"},
		{"A=b=c", "A", AssignPlain, "b=c"},
		{"A+=", "A", AssignAppend, ""},
		{"A=", "A", AssignPlain, ""},
		{"A=+1", "A", AssignPlain, "+1"},
		// The subscript sits on the name's side of the `=` exactly as the `+`
		// does, so a Cut holds `A[0]` -- a name no read of `$A` will find.
		{"A[0]=1", "A", AssignSubscript, "1"},
		{"A[]=1", "A", AssignSubscript, "1"},
		{"A[b[0]]=1", "A", AssignSubscript, "1"},
		// A subscript whose own text holds an `=`: the Cut takes the first
		// one, which is inside the brackets, so the name survives only
		// because the `[` is what ends it.
		{"A[b=c]=1", "A", AssignSubscript, "c]=1"},
		// Subscripted AND appending. AssignSubscript wins: it is the stronger
		// refusal, and no caller wants the weaker one here.
		{"A[0]+=1", "A", AssignSubscript, "1"},
		// Outside the precondition, pinned rather than asserted as correct: a
		// caller comparing names would read this as an assignment to `A`.
		{"A", "A", AssignPlain, ""},
	} {
		t.Run(tc.tok, func(t *testing.T) {
			name, form, value := SplitAssignment(tc.tok)
			if name != tc.name || form != tc.form || value != tc.value {
				t.Errorf("SplitAssignment(%q) = (%q, %v, %q), want (%q, %v, %q)",
					tc.tok, name, form, value, tc.name, tc.form, tc.value)
			}
		})
	}
}

// An array subscript makes a word an assignment prefix, and bash runs the
// command behind it. `FOO[0]=x cat f` prints f: the shell peels the word as a
// prefix, fails to export it -- `FOO[0]: not a valid identifier` on stderr --
// and runs cat anyway. So a reader behind such a prefix opens its operands,
// and a peel that stops at the `[` reads the command name as `FOO[0]=x`,
// finds no reader row, and lets the file cross unscanned (Q175).
//
// Driven 2026-09-19 on bash 5.3.15 as `env -i bash --norc --noprofile -c
// '<word> cat f'` over a file holding one line, reading whether that line was
// printed. Six rows peel and five do not, which is what says the drive can
// print either answer -- and the five split three ways, so the table is not
// one rule wearing five hats: `FOO[a]b]=x` and `FOO[]]=x` report `command not
// found` and read nothing, `FOO[0=x` and `FOO[a[b]=x` die at parse time with
// `unexpected EOF while looking for matching ']'`, and `0FOO[0]=x` is not a
// name at all.
//
// The depth count is the half a regex cannot do, and both directions of it are
// here: `FOO[a[0]]=x` peels, so the first `]` does not always close, and
// `FOO[a]b]=x` does not, so the last one does not always close either.
func TestASubscriptedAssignmentIsOneBashPeels(t *testing.T) {
	for _, tc := range []struct {
		word string
		want bool // bash peeled it and ran the command behind it
	}{
		{`FOO[0]=x`, true},
		{`FOO[0]+=x`, true},
		{`FOO[]=x`, true},
		{`FOO[a]=x`, true},
		{`FOO[a[0]]=x`, true},
		{`FOO[0]="a b"`, true},

		{`FOO[a]b]=x`, false},
		{`FOO[]]=x`, false},
		{`FOO[0=x`, false},
		{`FOO[a[b]=x`, false},
		{`0FOO[0]=x`, false},
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

// Quoting disarms a subscripted assignment the way it disarms a plain one, and
// the boundary is the same offset: everything up to and including the `=`.
//
// Driven the same day and the same way as the table above.
func TestQuotingDisarmsASubscriptedAssignment(t *testing.T) {
	for _, tc := range []struct {
		word string
		want bool // bash peeled it and ran the command behind it
	}{
		{`FOO[0]=x`, true},
		{`FOO[0]="a b"`, true},

		{`'FOO[0]=x'`, false},
		{`"FOO[0]=x"`, false},
		{`FOO\[0]=x`, false},
		{`F'O'O[0]=x`, false},
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

// Four subscripts bash peels and this does not, all for one reason: bash scans
// for the closing `]` over the word as WRITTEN, and this scans what the lexer
// left of it.
//
// The lexer splits a word on whitespace and on shell punctuation, and removes
// quotes before anything asks what the word is. So a subscript holding any of
// those either arrives as several tokens, or arrives as one token whose quotes
// are gone and whose provenance is a single offset -- which says where quoting
// began and cannot say which `]` it covered. Each row is read as a command
// name, and a reader behind such a prefix has its operands go unscanned:
// under-peeling, the fail-open direction, and the one Q175 closed for the
// ordinary spelling.
//
// Closing these means keeping `NAME[...]` whole in the lexer, quotes and all,
// which closes all four at once -- one mechanism, so one row: Q185.
//
// Every word below peels in bash and prints the file, driven 2026-09-19 on
// 5.3.15 the same way as the tables above. The rows are here so the gap is a
// failing expectation somebody has to delete rather than a case nobody wrote.
func TestASubscriptTheLexerCannotKeepWholeIsUnderPeeled(t *testing.T) {
	for _, tc := range []struct {
		word string
		why  string
	}{
		{`FOO[$((1+1))]=x`, "the parens are punctuation, so the word lexes as five tokens"},
		{`FOO[a b]=x`, "the space splits the word in two"},
		{`FOO["a]b"]=x`, "the quoted `]` closes the subscript once the quotes are gone"},
		{`FOO[a\]b]=x`, "the escaped `]` closes it the same way"},
	} {
		t.Run(tc.word, func(t *testing.T) {
			toks, qf, err := lex(tc.word)
			if err != nil {
				t.Fatalf("lex(%q): %v", tc.word, err)
			}
			if len(toks) == 1 && isAssignment(toks[0], qf[0]) {
				t.Errorf("%q now reads as an assignment, which is bash's own answer"+
					" -- Q185 has closed, so drop this row (%s)", tc.word, tc.why)
			}
		})
	}
}
