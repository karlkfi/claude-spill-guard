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
		{"a here-string is a different operator",
			`grep x <<< "$v"`, `grep x <<< "$v"`},
		{"a quoted operator is text",
			"echo '<<EOF' ; echo real", "echo '<<EOF' ; echo real"},
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
