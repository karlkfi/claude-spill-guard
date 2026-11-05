package bash

import (
	"slices"
	"testing"
)

// The expected values here were taken from the upstream group loop itself --
// the loop at plugins/workspace-guard/scripts/bash-workspace-guard.py:3082-3129
// of workspace-guard/v1.11.0, run over these commands against the shared
// parser. Upstream has no unit test at this layer (its own suite exercises
// segmentation through whole hook decisions, which need a filesystem), so
// these are the port's, with the upstream's answers rather than guesses.

// CaseArm, which is this repo's field and not upstream's. The `)` that ends a
// pattern needs no opener, so the shapes that produce a `)` at paren depth 0
// for other reasons are here as well -- a process substitution reaches this
// loop as a redirect target that never incremented the depth, and would be
// read as a pattern close by anything keying on the bare `)`.
func TestSegmentsMarksACaseArm(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     []bool // one per segment, in order
	}{
		{"an arm's body", "case x in y) P=1;; esac; cat f",
			[]bool{false, true, false, false}},
		{"a later arm's pattern and body", "case x in y) P=1;; z) Q=2;; esac",
			[]bool{false, true, true, true, false}},
		{"bash's optional pattern opener", "case $x in (y) P=1;; esac",
			[]bool{false, false, true, false}},
		{"an alternation", "case x in y|z) P=1;; esac",
			[]bool{false, false, true, false}},
		{"a nested case, header included", "case x in y) case q in r) P=1;; esac;; esac",
			[]bool{false, true, true, true, false}},
		{"an operator inside an arm", "case x in y) cd a && P=1;; esac",
			[]bool{false, true, true, false}},
		{"an unterminated case keeps marking", "case x in y) P=1; cat f",
			[]bool{false, true, true}},
		{"a case with no in marks nothing", "case x; cat f",
			[]bool{false, false}},

		// Not a case, and each ends a `)` at depth 0 or looks like the keyword.
		{"a process substitution", "cat <(grep p f); P=1",
			[]bool{false, false, false}},
		{"two process substitutions", "diff <(a) <(b); P=1",
			[]bool{false, false, false, false}},
		{"a subshell", "(cd x); P=1", []bool{false, false}},
		{"a function definition", "f() { echo hi; }; P=1",
			[]bool{false, false, false}},
		{"a substitution", "echo $(cat y); P=1", []bool{false, false, false}},
		// The command-position gate, which needs a `)` at depth 0 after it to
		// bite: the operand pushes a clause, the `in` promotes it to a
		// pattern, and the subshell's close then opens an arm that is not
		// there. Without the gate `P=1` comes back marked.
		{"the word as an operand", "echo case in; (cd /tmp); P=1",
			[]bool{false, false, false}},
		// An empty body leaves the loop in command position, so these two need
		// the command's own position back, and the second would read the `case`.
		{"the word after a substitution is no keyword", "echo $(a) case in; (cd /tmp); P=1",
			[]bool{false, false, false, false}},
		{"nor after an empty one", "echo $() case in; (cd /tmp); P=1",
			[]bool{false, false, false}},
		// A pattern's parens are pattern syntax, a substitution's included.
		{"a substitution in a pattern", "case x in $(a)) P=1;; esac",
			[]bool{false, false, true, false}},
		{"the word after a keyword is the keyword", "if x; then case q in r) P=1;; esac; fi",
			[]bool{false, false, true, false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs, err := Segments(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(segs) != len(tc.want) {
				t.Fatalf("got %d segments, want %d: %+v", len(segs), len(tc.want), segs)
			}
			for i, want := range tc.want {
				if segs[i].CaseArm != want {
					t.Errorf("segment %d %q: CaseArm = %v, want %v",
						i, segs[i].Tokens, segs[i].CaseArm, want)
				}
			}
		})
	}
}

// A substitution interrupts the command it sits in. Each row was run on bash
// 5.3.15: with f holding text, the command after the `)` prints it or the words
// after the `)` are that command's arguments.
func TestSegmentsResumeTheCommandASubstitutionInterrupted(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     [][]string
	}{
		{"an operand after it", "cat $(a) f", [][]string{{"a"}, {"cat", "$(", "f"}}},
		{"a word glued to the close", "cat $(a)/x f", [][]string{{"a"}, {"cat", "$(", "f"}}},
		{"a quoted word glued to the close", "cat $(a)'x y' f", [][]string{{"a"}, {"cat", "$(", "f"}}},
		{"a quoted word that is not glued", "cat $(a) 'x y'", [][]string{{"a"}, {"cat", "$(", "x y"}}},
		{"both sides of the word", "cat p$(a)q f", [][]string{{"a"}, {"cat", "p$(", "f"}}},
		{"two in one word", "cat $(a)$(b) f", [][]string{{"a"}, {"b"}, {"cat", "$(", "f"}}},
		{"two glued by a word", "cat $(a)x$(b) f", [][]string{{"a"}, {"b"}, {"cat", "$(", "f"}}},
		{"nested", "cat $(a $(b) c) f", [][]string{{"b"}, {"a", "$(", "c"}, {"cat", "$(", "f"}}},
		{"arithmetic", "head -n $((1+1)) f", [][]string{{"1+1"}, {"head", "-n", "$((", "f"}}},
		{"a process substitution", "cat <(a) f", [][]string{{"a"}, {"cat", "f"}}},
		{"an output one", "tee >(a) f", [][]string{{"a"}, {"tee", "f"}}},
		{"in an assignment prefix", "P=$(a) cat f", [][]string{{"a"}, {"P=$(", "cat", "f"}}},
		{"a keyword after it is a word", "echo $(a) if", [][]string{{"a"}, {"echo", "$(", "if"}}},
		{"a command name after it is a word", "echo $(a) env", [][]string{{"a"}, {"echo", "$(", "env"}}},
		{"as a redirect's target", "cat < $(a) f", [][]string{{"a"}, {"cat", "f"}}},
		{"a quoted paren as a redirect's target", "cat < '(' f", [][]string{{"cat", "f"}}},
		{"inside a parameter expansion", "cat ${X:-$(a)} f", [][]string{{"a"}, {"cat", "${X:-$(", "f"}}},
		{"a word spelling a reader", "cat $(a) cat f", [][]string{{"a"}, {"cat", "$(", "cat", "f"}}},
		{"an empty one", "cat $() f", [][]string{{"cat", "$(", "f"}}},
		{"a case arm in the body", "cat $(case x in y) a;; esac) f",
			[][]string{{"case", "x", "in", "y"}, {"a"}, {"esac"}, {"cat", "$(", "f"}}},
		{"unterminated", "cat $(a f", [][]string{{"a", "f"}, {"cat", "$("}}},
		// A subshell's close ends its command, and bash rejects a word after one.
		{"a subshell", "(a) f", [][]string{{"a"}, {"f"}}},
		{"a pattern's close", "case x in y)cat f;; esac",
			[][]string{{"case", "x", "in", "y"}, {"cat", "f"}, {"esac"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs, err := Segments(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			got := make([][]string, len(segs))
			for i, s := range segs {
				got[i] = s.Tokens
				if len(s.QuotedFrom) != len(s.Tokens) {
					t.Errorf("segment %d: %d tokens, %d provenance", i, len(s.Tokens), len(s.QuotedFrom))
				}
			}
			if !slices.EqualFunc(got, tc.want, slices.Equal[[]string]) {
				t.Errorf("Segments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// What the command's own separators decide stays with the command. The numbers
// are compared rather than pinned, since only which segments share one means
// anything, and a resumed command must not share one with a later pipeline.
func TestAResumedCommandKeepsItsOwnSeparators(t *testing.T) {
	segsOf := func(t *testing.T, in string) []Segment {
		t.Helper()
		segs, err := Segments(in)
		if err != nil {
			t.Fatal(err)
		}
		return segs
	}
	t.Run("the pipeline it writes to", func(t *testing.T) {
		s := segsOf(t, "a | cat $(b) f | c")
		if len(s) != 4 || s[0].Pipe != s[2].Pipe || s[2].Pipe != s[3].Pipe || s[1].Pipe == s[2].Pipe {
			t.Errorf("Pipe = %d %d %d %d, want the body alone apart", s[0].Pipe, s[1].Pipe, s[2].Pipe, s[3].Pipe)
		}
		if !s[2].Forked || s[1].Forked {
			t.Errorf("Forked = %v on the command and %v on the body", s[2].Forked, s[1].Forked)
		}
	})
	// `}` after an empty body is an argument, so the function goes on past it.
	t.Run("whether a closer is one", func(t *testing.T) {
		s := segsOf(t, "f () { echo $() }; cd w; }")
		if cd := s[len(s)-2]; cd.Tokens[0] != "cd" || cd.Function != "f" {
			t.Errorf("segment %q: Function = %q, want f", cd.Tokens, cd.Function)
		}
	})
	t.Run("the stage it is in the pipeline", func(t *testing.T) {
		s := segsOf(t, "a | cat $(b) f")
		if !s[2].Forked || !s[2].LastStage || s[1].Forked {
			t.Errorf("command Forked = %v, LastStage = %v; body Forked = %v", s[2].Forked, s[2].LastStage, s[1].Forked)
		}
	})
	t.Run("a pipeline number the body used is not reused", func(t *testing.T) {
		s := segsOf(t, "cat $(b | c) f; d | e")
		if len(s) != 5 || s[0].Pipe == s[3].Pipe || s[0].Pipe == s[2].Pipe {
			t.Errorf("Pipe = %+v", s)
		}
	})
	t.Run("the operator it is reached through", func(t *testing.T) {
		s := segsOf(t, "a && cat $(b) f")
		if s[2].Conditional != "&&" || s[1].Conditional != "" {
			t.Errorf("Conditional = %q on the command and %q on the body", s[2].Conditional, s[1].Conditional)
		}
	})
	t.Run("whether an assignment persists", func(t *testing.T) {
		s := segsOf(t, "P=$(a); cat f")
		if !s[1].Persists || s[0].Persists {
			t.Errorf("Persists = %v on the assignment and %v on the body", s[1].Persists, s[0].Persists)
		}
	})
	t.Run("the subshells it sits in", func(t *testing.T) {
		s := segsOf(t, "(cat $(a) f); b")
		if !slices.Equal(s[1].Shells, []int{1}) || !slices.Equal(s[0].Shells, []int{1, 2}) || len(s[2].Shells) != 0 {
			t.Errorf("Shells = %v %v %v", s[0].Shells, s[1].Shells, s[2].Shells)
		}
	})
	t.Run("where its stdout goes", func(t *testing.T) {
		s := segsOf(t, "cat >&2 $(a) f | b")
		if !s[1].StdoutAway || s[0].StdoutAway {
			t.Errorf("StdoutAway = %v on the command and %v on the body", s[1].StdoutAway, s[0].StdoutAway)
		}
	})
	// A compound or subshell closed ahead of the substitution is still the stage
	// the pipe after it applies to.
	t.Run("a group closed before it", func(t *testing.T) {
		for _, in := range []string{"(x; a) > $(b) | c", "{ x; a; } > $(b) | c"} {
			s := segsOf(t, in)
			if s[0].Pipe != s[len(s)-1].Pipe {
				t.Errorf("%s: Pipe = %d on the group and %d on the last stage", in, s[0].Pipe, s[len(s)-1].Pipe)
			}
		}
	})
	t.Run("a later stage closed before it", func(t *testing.T) {
		s := segsOf(t, "a | { b; } > $(c)")
		if last := s[len(s)-1]; !last.LastStage || !slices.Contains(last.Tokens, "}") {
			t.Errorf("segment %q: LastStage = %v, want the closer's", last.Tokens, last.LastStage)
		}
	})
	t.Run("the shell an unterminated one leaves behind", func(t *testing.T) {
		s := segsOf(t, "(cat $(a")
		if !slices.Equal(s[1].Shells, []int{1}) || !slices.Equal(s[0].Shells, []int{1, 2}) {
			t.Errorf("Shells = %v on the body and %v on the command", s[0].Shells, s[1].Shells)
		}
	})
	t.Run("the redirects written either side", func(t *testing.T) {
		s := segsOf(t, "cat <a $(b) <c f")
		if !slices.Equal(s[1].Inputs, []string{"a", "c"}) {
			t.Errorf("Inputs = %q", s[1].Inputs)
		}
	})
}

func TestSegments(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     []Segment
	}{
		{"one command", "cat a b",
			[]Segment{{[]string{"cat", "a", "b"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},

		// A redirect target is collected into the segment it textually appears
		// in, so it later resolves against THAT segment's working directory --
		// which is what lets this one name /tmp/evil rather than ./evil.
		{"a redirect belongs to the segment it was written in",
			"cd /tmp && cat /dev/null > evil",
			[]Segment{
				{[]string{"cd", "/tmp"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{[]string{"cat", "/dev/null"}, []string{"evil"}, nil, true, "&&", false, 1, nil, nil, false, false, "", "", false},
			}},

		// `pipe` advances on every separator except `|`, so the stages of one
		// pipeline share a number and nothing else does.
		{"a pipeline's stages share a number", "a | b | c",
			[]Segment{
				{[]string{"a"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"b"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"c"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
			}},

		// Persistence: an assignment survives at paren depth 0, outside a
		// pipeline stage, and not backgrounded.
		{"an assignment at the top level persists", "f=x; cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{[]string{"cat", "$f"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},
		{"one in a subshell does not", "(f=x); cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, nil, false, "", false, 0, nil, []int{1}, false, false, "", "", false},
				{[]string{"cat", "$f"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},
		{"a backgrounded one does not", "f=x & cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"cat", "$f"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},
		{"nor one in a |& stage", "a |& f=x; cat $f",
			[]Segment{
				{[]string{"a"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"f=x"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"cat", "$f"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},
		{"one in a pipeline stage does not", "a | f=x; cat $f",
			[]Segment{
				{[]string{"a"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"f=x"}, nil, nil, false, "", false, 0, nil, nil, true, false, "", "", false},
				{[]string{"cat", "$f"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},

		// An fd number glued to a redirect operator lands as the previous
		// token; popped, so it does not leak as a positional file argument.
		{"an fd number before a redirect is not an operand", "cat x 2> err",
			[]Segment{{[]string{"cat", "x"}, []string{"err"}, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		// A duplication target is an fd or `-`, not a path.
		{"a dup target is not a path", "cat x 2>&1",
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"nor a close", "cat x 2>&-",
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"nor an input dup", "cat x <&3",
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		// But `>&file` -- target is not a bare fd -- redirects to a file.
		{"a dup operator with a filename target does name a path", "cat x >&out",
			[]Segment{{[]string{"cat", "x"}, []string{"out"}, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		// The documented limitation: a file literally named `2` written right
		// before a redirect is indistinguishable post-tokenization.
		{"a file named 2 before a redirect is lost, as upstream loses it",
			"cat 2 > out",
			[]Segment{{[]string{"cat"}, []string{"out"}, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"every target of a multiply-redirected command", "sort <in >out 2>err",
			[]Segment{{[]string{"sort"}, []string{"in", "out", "err"}, []string{"in"}, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"the three-character redirect operators", "a &>> both",
			[]Segment{{[]string{"a"}, []string{"both"}, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"a clobbering redirect", "a >| clobber",
			[]Segment{{[]string{"a"}, []string{"clobber"}, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"a redirect with nothing after it names nothing", "echo hi >",
			[]Segment{{[]string{"echo", "hi"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},

		// A heredoc delimiter and a here-string's content are not paths.
		{"a heredoc delimiter is not a redirect target",
			"cat <<TAG\nx\nTAG\n> after",
			[]Segment{
				{[]string{"cat"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{nil, []string{"after"}, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},
		{"a here-string's content is not one either", `cat x <<<"here string"`,
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},

		// A newline is a command boundary. Left as whitespace it merges the
		// commands on either side, and the second one's operands are read as
		// arguments to the first.
		{"a newline separates two commands", "echo one\necho two",
			[]Segment{
				{[]string{"echo", "one"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{[]string{"echo", "two"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},
		{"and a comment does not eat it", "echo hi # note\ncat x",
			[]Segment{
				{[]string{"echo", "hi"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{[]string{"cat", "x"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},

		{"a subshell's parens are separators", "(cd x); echo done",
			[]Segment{
				{[]string{"cd", "x"}, nil, nil, false, "", false, 0, nil, []int{1}, false, false, "", "", false},
				{[]string{"echo", "done"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
			}},

		// Keywords and the env prefix stay in the segment; finding the real
		// command word is StripShKeywords and StripEnvPrefix, per segment.
		{"a compound statement keeps its keywords", "until LC_ALL=C grep x f; do :; done",
			[]Segment{
				{[]string{"until", "LC_ALL=C", "grep", "x", "f"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{[]string{"do", ":"}, nil, nil, true, "", false, 1, nil, nil, false, false, "", "", false},
				{[]string{"done"}, nil, nil, true, "", false, 2, nil, nil, false, false, "", "", false},
			}},

		// Inputs is the `<` subset of Redirects, and it is this repo's field:
		// upstream asks whether a target is outside the workspace, which a
		// read and a write answer alike, so it never needed the operator.
		{"an input redirect is recorded as one", "cat < in",
			[]Segment{{[]string{"cat"}, []string{"in"}, []string{"in"}, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"glued to its target as well", "cat <in",
			[]Segment{{[]string{"cat"}, []string{"in"}, []string{"in"}, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		// The descriptor is popped like any other and the target is still an
		// input: `0<in` is `<in` spelled out, and `3<in` opens in for reading
		// whether or not the command reads fd 3.
		{"with an explicit descriptor", "cat 0<in",
			[]Segment{{[]string{"cat"}, []string{"in"}, []string{"in"}, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		{"an output redirect is not an input", "cat x > out",
			[]Segment{{[]string{"cat", "x"}, []string{"out"}, nil, true, "", false, 0, nil, nil, false, false, "", "", false}}},
		// `<(cmd)` lexes as `<` then `(`. Upstream records the paren as a
		// target, absorbs the substitution's tokens into the command, and
		// splits on the closing paren -- all kept here -- but the paren is not
		// a file and is not an input. Measured over the week to 2026-09-04, 49
		// of 219 input redirects on a known reader were this shape.
		{"a process substitution is a redirect target and not an input",
			"diff <(sort a) <(sort b)",
			[]Segment{
				{[]string{"sort", "a"}, nil, nil, false, "", false, 1, nil, []int{1}, false, false, "", "", false},
				{[]string{"sort", "b"}, nil, nil, false, "", false, 2, nil, []int{2}, false, false, "", "", false},
				{[]string{"diff"}, []string{"(", "("}, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
			}},

		// The operator a segment is reached through, which Persists never
		// reads: the assignment after `&&` persists by upstream's rule and is
		// conditional by this one, and the `;` after it opens a segment that
		// is neither.
		{"a segment reached through && or || says so",
			"false && P=/x || cat $P/f; cat g",
			[]Segment{
				{[]string{"false"}, nil, nil, true, "", false, 0, nil, nil, false, false, "", "", false},
				{[]string{"P=/x"}, nil, nil, true, "&&", false, 1, nil, nil, false, false, "", "", false},
				{[]string{"cat", "$P/f"}, nil, nil, true, "||", false, 2, nil, nil, false, false, "", "", false},
				{[]string{"cat", "g"}, nil, nil, true, "", false, 3, nil, nil, false, false, "", "", false},
			}},
		{"an empty command has no segments", "   ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Segments(tc.in)
			if err != nil {
				t.Fatalf("Segments(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("Segments(%q) gave %d segments, want %d: %+v",
					tc.in, len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				g := got[i]
				if !equalStrings(g.Tokens, w.Tokens) ||
					!equalStrings(g.Redirects, w.Redirects) ||
					!equalStrings(g.Inputs, w.Inputs) ||
					g.Persists != w.Persists || g.Conditional != w.Conditional || g.Pipe != w.Pipe ||
					!slices.Equal(g.Shells, w.Shells) || g.Forked != w.Forked {
					t.Errorf("segment %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

// Shells and Forked, which say where a `cd` in the segment stops counting.
// Each `(` is a shell of its own, numbered in the order it opened, so the
// second of two sibling subshells is not the first; the shapes that write a
// `(` or a `)` for some other reason are here too, because a `)` read as a
// close leaves the segments after it, still inside, reading as outside.
func TestSegmentsNumbersTheShellsASegmentRunsIn(t *testing.T) {
	type want struct {
		shells []int
		forked bool
	}
	for _, tc := range []struct {
		name, in string
		want     []want // one per segment, in order
	}{
		{"a subshell and what follows it", "(cd w; cat x); cat x",
			[]want{{[]int{1}, false}, {[]int{1}, false}, {nil, false}}},
		{"two siblings are two shells", "(cd a); (cd b)",
			[]want{{[]int{1}, false}, {[]int{2}, false}}},
		{"a nested one", "(cd w; (cd v; cat x); cat x); cat x",
			[]want{{[]int{1}, false}, {[]int{1, 2}, false}, {[]int{1, 2}, false},
				{[]int{1}, false}, {nil, false}}},
		{"a substitution", "echo $(cd w; cat x)",
			[]want{{[]int{1}, false}, {[]int{1}, false}, {nil, false}}},
		{"a process substitution's ) closes its own shell",
			"(cd a; diff <(cat x) y; cat z)",
			[]want{{[]int{1}, false}, {[]int{1, 2}, false}, {[]int{1}, false},
				{[]int{1}, false}}},
		{"a case pattern's ) closes nothing", "(cd w; case q in z) :;; q) :;; esac; cat x)",
			[]want{{[]int{1}, false}, {[]int{1}, false}, {[]int{1}, false},
				{[]int{1}, false}, {[]int{1}, false}, {[]int{1}, false},
				{[]int{1}, false}}},
		{"nor its optional opener, nor an extglob group",
			"(cd w; case q in (@(q)) :;; esac; cat x)",
			[]want{{[]int{1}, false}, {[]int{1}, false}, {[]int{1}, false},
				{[]int{1}, false}, {[]int{1}, false}, {[]int{1}, false},
				{[]int{1}, false}}},
		{"a pipeline's stages are forked", "cd a | cat x",
			[]want{{nil, true}, {nil, true}}},
		{"and so is a |& stage",
			"true |& cd w; cat x",
			[]want{{nil, true}, {nil, true}, {nil, false}}},
		{"and a backgrounded one", "cd a & cat x",
			[]want{{nil, true}, {nil, false}}},
		{"a subshell piped as a whole is a shell, not a stage", "(cd a) | cat x",
			[]want{{[]int{1}, false}, {nil, true}}},
		// Upstream's Q272: a compound piped or backgrounded as a whole is a
		// shell, numbered once its closer's separator says so, and as a later
		// stage from its opener, whose segment is then no stage of its own.
		{"a group piped as a whole", "{ cd w; cat x; } | cat; cat x",
			[]want{{[]int{1}, false}, {[]int{1}, false}, {[]int{1}, true},
				{nil, true}, {nil, false}}},
		{"a group as a later stage", "cat | { cd w; }; cat x",
			[]want{{nil, true}, {[]int{1}, false}, {nil, false}, {nil, false}}},
		{"a backgrounded loop inside a subshell", "(for i in 1; do cd w; done &)",
			[]want{{[]int{1, 2}, false}, {[]int{1, 2}, false}, {[]int{1, 2}, true}}},
		{"an unpiped group is the current shell", "{ cd w; }; cat x",
			[]want{{nil, false}, {nil, false}, {nil, false}}},
		// Upstream's Q265: a function body is a shell, and its header is no
		// segment at all.
		{"a function body", "f() { cd w; }; cat x",
			[]want{{[]int{1}, false}, {nil, false}, {nil, false}}},
		{"a function body in parens", "f() ( cd w ); cat x",
			[]want{{[]int{1, 2}, false}, {nil, false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs, err := Segments(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(segs) != len(tc.want) {
				t.Fatalf("got %d segments, want %d: %+v", len(segs), len(tc.want), segs)
			}
			for i, w := range tc.want {
				if !slices.Equal(segs[i].Shells, w.shells) || segs[i].Forked != w.forked {
					t.Errorf("segment %d %q: Shells, Forked = %v, %v, want %v, %v",
						i, segs[i].Tokens, segs[i].Shells, segs[i].Forked, w.shells, w.forked)
				}
			}
		})
	}
}

// Function names the body a segment sits directly in and no other, and
// LastStage marks the stage `lastpipe` would run in the current shell: a last
// stage, and the closer of a compound that was one.
func TestSegmentsNameTheFunctionAndTheLastStage(t *testing.T) {
	type want struct {
		function  string
		lastStage bool
	}
	for _, tc := range []struct {
		name, in string
		want     []want
	}{
		{"a body", "f() { cd w; }; f", []want{{"f", false}, {"", false}, {"", false}}},
		{"the function keyword", "function g { cd w; }",
			[]want{{"g", false}, {"", false}}},
		{"a subshell inside one is not directly in it", "f() { (cd w); }",
			[]want{{"f", false}, {"", false}, {"", false}}},
		{"a plain pipeline", "a | b", []want{{"", false}, {"", true}}},
		{"a later-stage group's closer", "a | { cd w; }",
			[]want{{"", false}, {"", false}, {"", true}}},
		{"a quoted name, whose body bash rejects unrun", "'f'() { cd w; }",
			[]want{{"f", false}, {"", false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs, err := Segments(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(segs) != len(tc.want) {
				t.Fatalf("got %d segments, want %d: %+v", len(segs), len(tc.want), segs)
			}
			for i, w := range tc.want {
				if segs[i].Function != w.function || segs[i].LastStage != w.lastStage {
					t.Errorf("segment %d %q: Function, LastStage = %q, %v, want %q, %v",
						i, segs[i].Tokens, segs[i].Function, segs[i].LastStage, w.function, w.lastStage)
				}
			}
		})
	}
}

// Body names the function a segment sits in at any depth, which is how a
// paren-bodied definition is seen at all: none of its segments sits directly
// in the body, so Function is empty for every one of them.
func TestSegmentsNameTheBodyAtAnyDepth(t *testing.T) {
	for _, tc := range []struct {
		in             string
		function, body []string
	}{
		{"cd () ( : ); cd w", []string{"", ""}, []string{"cd", ""}},
		{"f() { (cd w); }", []string{"f", "", ""}, []string{"f", "f", ""}},
		{"f() { cd w; }; f", []string{"f", "", ""}, []string{"f", "", ""}},
		{"a | { cd w; }", []string{"", "", ""}, []string{"", "", ""}},
		// Behind a list opener the header is still read (Q212); a quoted
		// 'do' is a command name and heads none.
		{"if true; then f() { cd w; }; fi", []string{"", "f", "", ""}, []string{"", "f", "", ""}},
		{"{ f() { cd w; }; }", []string{"f", "", ""}, []string{"f", "", ""}},
		{"for i in 1; do 'do' f() { :; }; done", []string{"", "", "", "", ""}, []string{"", "", "", "", ""}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			segs, err := Segments(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(segs) != len(tc.body) {
				t.Fatalf("got %d segments, want %d: %+v", len(segs), len(tc.body), segs)
			}
			for i := range segs {
				if segs[i].Function != tc.function[i] || segs[i].Body != tc.body[i] {
					t.Errorf("segment %d %q: Function, Body = %q, %q, want %q, %q",
						i, segs[i].Tokens, segs[i].Function, segs[i].Body, tc.function[i], tc.body[i])
				}
			}
		})
	}
}

// The whole point of the layer: the operand a reader is pointed at, found
// through the segment it was written in.
func TestSegmentsFindsTheReaderOperand(t *testing.T) {
	const cmd = "git status && LC_ALL=C cat secrets.env | grep -i token"
	segs, err := Segments(cmd)
	if err != nil {
		t.Fatal(err)
	}
	var readers [][]string
	for _, s := range segs {
		k := ShKeywordPeel(s.Tokens, s.QuotedFrom)
		head := StripEnvPrefix(s.Tokens[k:], s.QuotedFrom[k:])
		if len(head) > 0 && head[0] == "cat" {
			readers = append(readers, head[1:])
		}
	}
	if len(readers) != 1 || !equalStrings(readers[0], []string{"secrets.env"}) {
		t.Fatalf("cat operands = %q, want [[secrets.env]]", readers)
	}
}

// A command the lexer cannot read is one no caller should judge.
func TestSegmentsDefersOnUnbalancedQuotes(t *testing.T) {
	segs, err := Segments(`cat "unclosed`)
	if err == nil {
		t.Fatalf("Segments returned %+v and no error", segs)
	}
	if segs != nil {
		t.Errorf("Segments returned %+v alongside the error", segs)
	}
}

func TestIsDigits(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{{"2", true}, {"10", true}, {"", false}, {"2a", false}, {"-", false}} {
		if got := isDigits(tc.in); got != tc.want {
			t.Errorf("isDigits(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A word made entirely of punctuation has the TEXT of an operator and is not
// one. Reading it as a separator cuts the command there, so the reader keeps no
// operands and every later operand is read as a command name -- for this repo a
// silent allow on a file the command really does open.
//
// Measured on bash 5.3.15 in a directory holding only `f`: `cat ';' f` prints
// `cat: ;: No such file or directory` and then the contents of `f`, rc=1. So no
// file named `;` has to exist -- cat reports the missing operand and reads the
// rest.
func TestSegmentsReadsAQuotedOperatorAsAWord(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     [][]string // tokens per segment, in order
	}{
		// A single-character run is byte-identical either side of
		// splitOperatorRuns, so these are the arms only the vocabulary tests
		// in Segments can fix.
		{"a quoted separator", "cat ';' f", [][]string{{"cat", ";", "f"}}},
		{"a quoted redirect", "cat '>' f", [][]string{{"cat", ">", "f"}}},
		{"a quoted pipe", "cat '|' f", [][]string{{"cat", "|", "f"}}},
		{"a double-quoted separator", `cat ";" f`, [][]string{{"cat", ";", "f"}}},
		{"an escaped separator", `cat \; f`, [][]string{{"cat", ";", "f"}}},

		// A multi-character run is the half splitOperatorRuns decides.
		{"a quoted operator run", "cat ';;' f", [][]string{{"cat", ";;", "f"}}},
		{"a quoted and-list operator", "cat '&&' f", [][]string{{"cat", "&&", "f"}}},

		// Controls: the plain spellings must still segment and redirect.
		{"a plain separator still splits", "cat ; f",
			[][]string{{"cat"}, {"f"}}},
		{"a plain and-list still splits", "cat a && cat b",
			[][]string{{"cat", "a"}, {"cat", "b"}}},
		{"a token holding non-punctuation was never a candidate", "cat 'x;y' f",
			[][]string{{"cat", "x;y", "f"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			segs, err := Segments(tc.in)
			if err != nil {
				t.Fatalf("Segments(%q) = error %v", tc.in, err)
			}
			if len(segs) != len(tc.want) {
				t.Fatalf("Segments(%q) gave %d segment(s), want %d: %v",
					tc.in, len(segs), len(tc.want), segs)
			}
			for i, want := range tc.want {
				if got := segs[i].Tokens; !equalStrings(got, want) {
					t.Errorf("Segments(%q) segment %d tokens = %q, want %q",
						tc.in, i, got, want)
				}
			}
		})
	}
}

// A quoted redirect operator is a word, so it names no target: `cat '>' f`
// reads two files where `cat > f` reads none and writes one.
func TestSegmentsRecordsNoTargetForAQuotedRedirect(t *testing.T) {
	segs, err := Segments("cat '>' f")
	if err != nil {
		t.Fatalf("Segments = error %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("got %d segment(s), want 1: %v", len(segs), segs)
	}
	if len(segs[0].Redirects) != 0 {
		t.Errorf("Redirects = %q, want none", segs[0].Redirects)
	}

	// Control: the plain spelling still records the target, so the assertion
	// above is about the quoting rather than about redirects being unread.
	plain, err := Segments("cat > f")
	if err != nil {
		t.Fatalf("Segments = error %v", err)
	}
	if len(plain) != 1 || !equalStrings(plain[0].Redirects, []string{"f"}) {
		t.Errorf("plain redirect: Redirects = %q, want [f]", plain[0].Redirects)
	}
}

// Where a segment's redirects leave fd 1, read left to right as bash applies
// them (Q208). Each row's answer is where `echo X` put its X on bash 5.3.15:
// stderr is away, and the pipe, a file or nowhere is not.
func TestStdoutAwayFollowsTheRedirectsInOrder(t *testing.T) {
	for _, tc := range []struct {
		command string
		away    bool
	}{
		{"echo X >&2", true},
		{"echo X 1>&2", true},
		{"echo X >&2 2>&1", true},
		{"echo X >&2 2>o", true},
		{"echo X >/dev/stderr", true},
		{"echo X 1>/dev/fd/2", true},
		{"echo X &>/dev/stderr", true},
		{"echo X >&3", true},
		{"echo X", false},
		{"echo X 2>&1", false},
		{"echo X 2>&1 >&2", false},
		{"echo X 2>o >&2", false},
		{"echo X 2>/dev/stderr", false},
		{"echo X >/dev/stdout", false},
		{"echo X >&-", false},
		{"echo X >o", false},
		{"echo X &>o", false},
		{"echo X >&o", false},
		{"echo X <&2", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			segs, err := Segments(tc.command)
			if err != nil || len(segs) != 1 {
				t.Fatalf("Segments = %v, %v; want one segment", segs, err)
			}
			if segs[0].StdoutAway != tc.away {
				t.Errorf("StdoutAway = %v, want %v", segs[0].StdoutAway, tc.away)
			}
		})
	}
}

// A compound or subshell piped as a whole is one stage, so every command in
// it shares the pipe of the stage it feeds, and a subshell that opens a stage
// starts in that stage's pipe (Q208). A substitution's body does neither: it
// reaches the command as a file or as words.
func TestAPipedGroupSharesThePipeItFeeds(t *testing.T) {
	for _, tc := range []struct {
		command string
		same    bool // whether grep's segment and f's share a Pipe
	}{
		{"{ grep x d; } | f", true},
		{"{ grep x d; echo; } | f", true},
		{"( grep x d ) | f", true},
		{"(grep x d; true) | f", true},
		{"for x in d; do grep x $x; done | f", true},
		{"grep x d | (f)", true},
		{"grep x d | { f; }", true},
		{"grep x d | (cat; f)", false},
		{"grep x d; (f)", false},
		{"(grep x d); f", false},
		{"grep x d 2> >(f)", false},
		{"echo $(grep x d) | f", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			segs, err := Segments(tc.command)
			if err != nil {
				t.Fatal(err)
			}
			writer, reader := -1, -1
			for k, seg := range segs {
				if slices.Contains(seg.Tokens, "grep") {
					writer = k
				}
				if slices.Contains(seg.Tokens, "f") {
					reader = k
				}
			}
			if writer < 0 || reader < 0 || writer == reader {
				t.Fatalf("no separate grep and f segments in %+v", segs)
			}
			if got := segs[writer].Pipe == segs[reader].Pipe; got != tc.same {
				t.Errorf("grep pipe %d, f pipe %d: same = %v, want %v",
					segs[writer].Pipe, segs[reader].Pipe, got, tc.same)
			}
		})
	}
}
