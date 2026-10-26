package bash

import "testing"

// The cases in this file are the upstream suite's, brought across with the
// code: tests/test_bouncer_parse.py at workspace-guard/v1.11.0, classes
// StripCommentsTests, StripHeredocBodiesTests and OwnLevelHeredocStripTests.
// A port whose tests are written fresh is a port whose agreement with the
// original was never measured -- the PR body records the differential that
// measured it over the whole corpus, and these are what defends the port
// afterwards, in a repo that cannot run the Python.

func TestStripComments(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		// The newline has to survive: shlex's own comment handling eats it,
		// and the next line's tokens then merge into the commented command.
		{"an unquoted comment goes and its newline stays",
			"echo hi # note\ncat x", "echo hi \ncat x"},
		{"a single-quoted hash is text", "echo 'a # b'", "echo 'a # b'"},
		{"a double-quoted hash is text", `echo "a # b"`, `echo "a # b"`},
		// bash starts a comment only at the start of a word; shlex does not.
		{"a mid-word hash is not a comment", "echo file#1", "echo file#1"},
		// Left in place, lex makes the newline a command boundary and an `&&`
		// chain written across two lines reads as a `;` sequence -- a
		// different rule, and the wrong verdict.
		{"a continuation is folded", "make check \\\n && echo ok",
			"make check  && echo ok"},
		// A `"` in a substitution in double quotes ends nothing, so the `#`
		// after it is text and `id` survives (claude-bouncer Q257). Read as ending
		// it, the strip took `id` with the comment.
		{"a hash in a double-quoted substitution's own string",
			`echo "$(echo "a # c")" ; id`, `echo "$(echo "a # c")" ; id`},
		{"and in backticks", "echo \"`echo \"a # c\"`\" ; id",
			"echo \"`echo \"a # c\"`\" ; id"},
		{"a continuation inside a held span is still folded",
			"echo \"$(echo a \\\n b)\" # c", "echo \"$(echo a  b)\" "},
		// bash 5.3.15 reads `FOO[a #b]=x cat f` as a prefix and prints f
		// (claude-bouncer Q217).
		{"an assignment subscript holds no comment", "FOO[a #b]=x cat f", "FOO[a #b]=x cat f"},
		{"nor an appending one", "X=1 FOO[a #b]+=x cat f", "X=1 FOO[a #b]+=x cat f"},
		// Outside an assignment, bash starts the comment there.
		{"a subscript that assigns nothing", "echo a[x #y]", "echo a[x "},
		// bash 5.3.15 prints each `#b` as part of its word and runs `id`: the
		// close of a substitution does not end the word (claude-bouncer Q264).
		{"a substitution close holds no comment", "echo $(true)#b; id", "echo $(true)#b; id"},
		{"nor a process substitution's", "cat <(true)#b; id", "cat <(true)#b; id"},
		{"nor an output one's", "echo >(true)#b; id", "echo >(true)#b; id"},
		{"nor arithmetic's", "echo $((1))#b; id", "echo $((1))#b; id"},
		{"nor one nested in an assignment", "x=$(cat <(echo a)#b); id", "x=$(cat <(echo a)#b); id"},
		{"nor one holding a case arm", "echo $(case x in a) echo;; esac)#b; id",
			"echo $(case x in a) echo;; esac)#b; id"},
		{"nor one holding a quoted paren", `echo $(echo ")")#b; id`, `echo $(echo ")")#b; id`},
		{"a continuation joins the close and the hash", "echo $(true)\\\n#b; id", "echo $(true)#b; id"},
		// A subshell's close does end the word, and so does a space.
		{"a subshell close ends the word", "(true)#b; id", "(true)"},
		{"a space ends it", "echo $(true) #b; id", "echo $(true) "},
		// bash 5.3.15 runs `id` after each: a comment in backticks ends at the
		// closing backtick, and a `#` in `${...}` is text (claude-bouncer Q254).
		{"a backtick span holds no comment", "echo `true # c` ; id", "echo `true # c` ; id"},
		{"nor one glued to a hash", "echo `true # c`#x ; id", "echo `true # c`#x ; id"},
		{"a brace expansion holds no comment", "echo ${x:- #} ; id", "echo ${x:- #} ; id"},
		{"nor a nested one", "echo ${x:-${y:- #}} ; id", "echo ${x:-${y:- #}} ; id"},
		{"nor one holding a substitution's brace", "echo ${x:-$(echo }) #} ; id",
			"echo ${x:-$(echo }) #} ; id"},
		{"nor one holding a backtick's brace", "echo ${x:-`echo } #`} ; id",
			"echo ${x:-`echo } #`} ; id"},
		{"nor a double-quoted one", `echo "${x:-" #"}" ; id`, `echo "${x:-" #"}" ; id`},
		{"nor one holding an ANSI-C apostrophe", `echo ${x:-$'\'} #'} ; id`,
			`echo ${x:-$'\'} #'} ; id`},
		{"a continuation inside one is folded", "echo ${x:-a\\\n #} ; id", "echo ${x:-a #} ; id"},
		// A quoted `}` does not close one, and a bare `{` does not nest, so the
		// comment after the real close still goes.
		{"a double-quoted brace closes nothing", `echo ${x:-"}"} #c`, `echo ${x:-"}"} `},
		{"a single-quoted brace closes nothing", "echo ${x:-'}'} #c", "echo ${x:-'}'} "},
		{"an escaped brace closes nothing", `echo ${x:-\}} #c`, `echo ${x:-\}} `},
		{"a bare brace does not nest", "echo ${x:-{a} #c}", "echo ${x:-{a} "},
		{"a length expansion", "echo ${#x} #c", "echo ${#x} "},
		{"a special parameter", "echo $# #c", "echo $# "},
		{"a backtick glued to a hash", "echo `echo a`#x #c", "echo `echo a`#x "},
		// An escaped apostrophe does not close a `$'…'` (claude-bouncer Q225).
		{"an ANSI-C string holds no comment", `echo $'\' #' ; id`, `echo $'\' #' ; id`},
		// Unterminated, each is read as before.
		{"an unterminated brace expansion", "echo ${x:- # c", "echo ${x:- "},
		{"an unterminated backtick span", "echo `true # c", "echo `true "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripComments(tc.in); got != tc.want {
				t.Errorf("StripComments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripHeredocBodies(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"the body and its terminator go", "cat <<EOF\nbody\nEOF\n", "cat <<EOF\n"},
		// This case does not carry the tab rule on its own: with the tabs
		// left on, no line equals the terminator, the body swallows to end
		// of input, and the returned string is the same. What discriminates
		// is whether the terminator was found -- see the collecting test.
		{"the tab-stripping form", "cat <<-EOF\n\tb\n\tEOF\n", "cat <<-EOF\n"},
		// The other guard's copy pre-scanned for the closing `)` while
		// tracking quotes, so the unbalanced `"` in the body read as an
		// unterminated substitution and the whole body survived -- and a
		// commit message containing a quote is the shape that produces it.
		{"a heredoc inside a quoted substitution with a stray quote",
			"git commit -F \"$(cat <<'MSG'\nhello \"world\nMSG\n)\"",
			"git commit -F \"$(cat <<'MSG'\n)\""},
		{"an arithmetic shift is not a heredoc",
			"echo $((1<<3))", "echo $((1<<3))"},
		{"an arithmetic shift outside a substitution either",
			"((a<<b)); echo hi", "((a<<b)); echo hi"},
		// The delimiter may be separated from the operator. Without the
		// space skip the delimiter reads as empty, nothing is armed, and
		// the body survives into the lexer as phantom operands.
		{"whitespace between the operator and the delimiter",
			"cat << EOF\nbody\nEOF\n", "cat << EOF\n"},
		{"a here-string is a different operator",
			`grep x <<< "$v"`, `grep x <<< "$v"`},
		{"a quoted operator is text",
			"echo '<<EOF' ; echo real", "echo '<<EOF' ; echo real"},
		// An escaped apostrophe does not close a `$'…'`, so the `<<` after one
		// is still an operator (claude-bouncer Q225).
		{"a heredoc after an ANSI-C string",
			"cat <<EOF ; echo $'\\''\nx\nEOF\nid", "cat <<EOF ; echo $'\\''\nid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripHeredocBodies(tc.in, nil, false); got != tc.want {
				t.Errorf("StripHeredocBodies(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripHeredocBodiesCollects(t *testing.T) {
	for _, tc := range []struct {
		name, in               string
		expanded, unterminated []string
	}{
		{"an unquoted delimiter's body comes back expanded",
			"cat <<EOF\nbody\nEOF\n", []string{"body\nEOF\n"}, nil},
		{"a quoted delimiter's does not",
			"cat <<'EOF'\nbody\nEOF\n", nil, nil},
		// The other two spellings of a quoted delimiter. Any quoting is
		// bash's expansion switch, so each arm has to set it: a body that
		// comes back expanded is one a substitution scan will read.
		{"a backslash-quoted delimiter does not either",
			"cat <<\\EOF\n$(id)\nEOF\n", nil, nil},
		{"nor a double-quoted one",
			"cat <<\"EOF\"\n$(id)\nEOF\n", nil, nil},
		// Bash hands an unterminated body over as data, so it is stripped. A
		// caller that would rather keep judging the text reads it back out.
		{"an unterminated body is swallowed and reportable",
			"cat <<'EOF'\nkubectl delete ns payments",
			nil, []string{"kubectl delete ns payments"}},
		{"a terminated body is not reported as unterminated",
			"cat <<EOF\nbody\nEOF\n", []string{"body\nEOF\n"}, nil},
		// The one assertion that separates a stripped tab from a body run
		// to end of input, which strip to the same string.
		{"the tab-stripping form finds its terminator",
			"cat <<-EOF\n\tb\n\tEOF\n", []string{"\tb\n\tEOF\n"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Heredocs{}
			StripHeredocBodies(tc.in, h, false)
			if !equalStrings(h.Expanded, tc.expanded) {
				t.Errorf("Expanded = %q, want %q", h.Expanded, tc.expanded)
			}
			if !equalStrings(h.Unterminated, tc.unterminated) {
				t.Errorf("Unterminated = %q, want %q", h.Unterminated, tc.unterminated)
			}
		})
	}
}

// A caller re-scanning the raw string for substitution bodies needs the top
// level's heredoc data gone -- an apostrophe in one opens a quoted run that
// swallows the scan -- and needs each substitution's own heredocs left whole,
// terminators included, because that is the text the recursion strips next
// (Q119). Stripping every level gives it a body whose `<<WORD` has lost its
// terminator, which is the Q113 trap the recovery exists to avoid.
func TestStripHeredocBodiesOwnLevel(t *testing.T) {
	const nested = "cat <<EOF\ndon't\nEOF\necho \"$(cat <<X\nb\nX\ncat /outside)\""

	t.Run("a top-level body is dropped", func(t *testing.T) {
		got := StripHeredocBodies("cat <<EOF\nbody\nEOF\necho after", nil, true)
		if want := "cat <<EOF\necho after"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a substitution's own body is copied through", func(t *testing.T) {
		cmd := "echo \"$(cat <<X\nb\nX\ncat /outside)\""
		if got := StripHeredocBodies(cmd, nil, true); got != cmd {
			t.Errorf("got %q, want it unchanged", got)
		}
	})

	t.Run("a backtick substitution keeps its body too", func(t *testing.T) {
		cmd := "echo \"`cat <<X\nb\nX\ncat /outside`\""
		if got := StripHeredocBodies(cmd, nil, true); got != cmd {
			t.Errorf("got %q, want it unchanged", got)
		}
	})

	t.Run("the default still strips every level", func(t *testing.T) {
		got := StripHeredocBodies("echo \"$(cat <<X\nb\nX\ncat /outside)\"", nil, false)
		if want := "echo \"$(cat <<X\ncat /outside)\""; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	// The row's mechanism at parser level: flat, the `'` in the first body
	// opens a run that swallows the `$(…)` and the scan returns nothing.
	t.Run("an apostrophe above no longer hides the substitution", func(t *testing.T) {
		got := CommandSubstitutions(StripHeredocBodies(nested, nil, true), true)
		if want := []string{"cat <<X\nb\nX\ncat /outside"}; !equalStrings(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
		if got := CommandSubstitutions(nested, true); len(got) != 0 {
			t.Errorf("flat scan found %q, want nothing", got)
		}
	})

	// The property the recovery rests on, and it is about the BODIES rather
	// than the returned string: each still carries its terminator, so the full
	// strip that follows drops the data and leaves the read after it. The
	// returned string itself is not re-strippable -- the top level's own
	// `<<EOF` is disarmed there exactly as the default strip disarms it, and a
	// second pass would swallow the rest (the Q113 trap, one level up).
	t.Run("a yielded body survives the full strip the recursion runs", func(t *testing.T) {
		bodies := CommandSubstitutions(StripHeredocBodies(nested, nil, true), true)
		if len(bodies) != 1 {
			t.Fatalf("got %d bodies, want 1", len(bodies))
		}
		got := StripHeredocBodies(bodies[0], nil, false)
		if want := "cat <<X\ncat /outside"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// UnstrippedSubstBodies is what carries that property into the recursion: the
// body handed back has its terminator, so the next strip disarms it cleanly
// instead of swallowing everything after the newline (Q113).
func TestUnstrippedSubstBodies(t *testing.T) {
	const cmd = "echo \"$(cat <<EOF\nb\nEOF\ncat /outside)\""
	stripped := CommandSubstitutions(StripHeredocBodies(cmd, nil, false), true)
	if want := []string{"cat <<EOF\ncat /outside"}; !equalStrings(stripped, want) {
		t.Fatalf("stripped scan gave %q, want %q", stripped, want)
	}

	raw := UnstrippedSubstBodies(cmd, stripped)
	if want := []string{"cat <<EOF\nb\nEOF\ncat /outside"}; !equalStrings(raw, want) {
		t.Fatalf("raw bodies %q, want %q", raw, want)
	}
	// The point of the swap: stripping the raw body a second time leaves the
	// read after the heredoc, where stripping the already-stripped one loses
	// it.
	if got := StripHeredocBodies(raw[0], nil, false); got != "cat <<EOF\ncat /outside" {
		t.Errorf("re-strip of the raw body = %q", got)
	}
	if got := StripHeredocBodies(stripped[0], nil, false); got != "cat <<EOF\n" {
		t.Errorf("re-strip of the stripped body = %q, expected the read gone", got)
	}

	t.Run("a command with no heredoc is handed back untouched", func(t *testing.T) {
		subs := []string{"id"}
		if got := UnstrippedSubstBodies(`echo "$(id)"`, subs); !equalStrings(got, subs) {
			t.Errorf("got %q, want %q", got, subs)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bash ends `<<$'E\x4fF'` at an `EOF` line, prints `$(echo SUB)` unexpanded,
// and runs the line after (claude-bouncer Q225). Read as `$` and a quoted
// word, the body ran to the end of the input and swallowed that line.
func TestAnANSICHeredocDelimiterEndsWhereBashEndsIt(t *testing.T) {
	for _, word := range []string{`$'EOF'`, `$'E\x4fF'`} {
		h := &Heredocs{}
		got := StripHeredocBodies("cat <<"+word+"\n$(echo SUB)\nEOF\nid", h, false)
		if want := "cat <<" + word + "\nid"; got != want {
			t.Errorf("StripHeredocBodies with delimiter %s = %q, want %q", word, got, want)
		}
		if len(h.Expanded) != 0 {
			t.Errorf("delimiter %s: Expanded = %q, want none, since quoting makes the body literal", word, h.Expanded)
		}
	}
}
