package bash

import "testing"

// The expected values here were taken from the upstream group loop itself --
// the loop at plugins/workspace-guard/scripts/bash-workspace-guard.py:3082-3129
// of workspace-guard/v1.11.0, run over these commands against the shared
// parser. Upstream has no unit test at this layer (its own suite exercises
// segmentation through whole hook decisions, which need a filesystem), so
// these are the port's, with the upstream's answers rather than guesses.
func TestSegments(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     []Segment
	}{
		{"one command", "cat a b",
			[]Segment{{[]string{"cat", "a", "b"}, nil, nil, true, "", 0}}},

		// A redirect target is collected into the segment it textually appears
		// in, so it later resolves against THAT segment's working directory --
		// which is what lets this one name /tmp/evil rather than ./evil.
		{"a redirect belongs to the segment it was written in",
			"cd /tmp && cat /dev/null > evil",
			[]Segment{
				{[]string{"cd", "/tmp"}, nil, nil, true, "", 0},
				{[]string{"cat", "/dev/null"}, []string{"evil"}, nil, true, "&&", 1},
			}},

		// `pipe` advances on every separator except `|`, so the stages of one
		// pipeline share a number and nothing else does.
		{"a pipeline's stages share a number", "a | b | c",
			[]Segment{
				{[]string{"a"}, nil, nil, false, "", 0},
				{[]string{"b"}, nil, nil, false, "", 0},
				{[]string{"c"}, nil, nil, false, "", 0},
			}},

		// Persistence: an assignment survives at paren depth 0, outside a
		// pipeline stage, and not backgrounded.
		{"an assignment at the top level persists", "f=x; cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, nil, true, "", 0},
				{[]string{"cat", "$f"}, nil, nil, true, "", 1},
			}},
		{"one in a subshell does not", "(f=x); cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, nil, false, "", 1},
				{[]string{"cat", "$f"}, nil, nil, true, "", 3},
			}},
		{"a backgrounded one does not", "f=x & cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, nil, false, "", 0},
				{[]string{"cat", "$f"}, nil, nil, true, "", 1},
			}},
		{"one in a pipeline stage does not", "a | f=x; cat $f",
			[]Segment{
				{[]string{"a"}, nil, nil, false, "", 0},
				{[]string{"f=x"}, nil, nil, false, "", 0},
				{[]string{"cat", "$f"}, nil, nil, true, "", 1},
			}},

		// An fd number glued to a redirect operator lands as the previous
		// token; popped, so it does not leak as a positional file argument.
		{"an fd number before a redirect is not an operand", "cat x 2> err",
			[]Segment{{[]string{"cat", "x"}, []string{"err"}, nil, true, "", 0}}},
		// A duplication target is an fd or `-`, not a path.
		{"a dup target is not a path", "cat x 2>&1",
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", 0}}},
		{"nor a close", "cat x 2>&-",
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", 0}}},
		{"nor an input dup", "cat x <&3",
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", 0}}},
		// But `>&file` -- target is not a bare fd -- redirects to a file.
		{"a dup operator with a filename target does name a path", "cat x >&out",
			[]Segment{{[]string{"cat", "x"}, []string{"out"}, nil, true, "", 0}}},
		// The documented limitation: a file literally named `2` written right
		// before a redirect is indistinguishable post-tokenization.
		{"a file named 2 before a redirect is lost, as upstream loses it",
			"cat 2 > out",
			[]Segment{{[]string{"cat"}, []string{"out"}, nil, true, "", 0}}},
		{"every target of a multiply-redirected command", "sort <in >out 2>err",
			[]Segment{{[]string{"sort"}, []string{"in", "out", "err"}, []string{"in"}, true, "", 0}}},
		{"the three-character redirect operators", "a &>> both",
			[]Segment{{[]string{"a"}, []string{"both"}, nil, true, "", 0}}},
		{"a clobbering redirect", "a >| clobber",
			[]Segment{{[]string{"a"}, []string{"clobber"}, nil, true, "", 0}}},
		{"a redirect with nothing after it names nothing", "echo hi >",
			[]Segment{{[]string{"echo", "hi"}, nil, nil, true, "", 0}}},

		// A heredoc delimiter and a here-string's content are not paths.
		{"a heredoc delimiter is not a redirect target",
			"cat <<TAG\nx\nTAG\n> after",
			[]Segment{
				{[]string{"cat"}, nil, nil, true, "", 0},
				{nil, []string{"after"}, nil, true, "", 1},
			}},
		{"a here-string's content is not one either", `cat x <<<"here string"`,
			[]Segment{{[]string{"cat", "x"}, nil, nil, true, "", 0}}},

		// A newline is a command boundary. Left as whitespace it merges the
		// commands on either side, and the second one's operands are read as
		// arguments to the first.
		{"a newline separates two commands", "echo one\necho two",
			[]Segment{
				{[]string{"echo", "one"}, nil, nil, true, "", 0},
				{[]string{"echo", "two"}, nil, nil, true, "", 1},
			}},
		{"and a comment does not eat it", "echo hi # note\ncat x",
			[]Segment{
				{[]string{"echo", "hi"}, nil, nil, true, "", 0},
				{[]string{"cat", "x"}, nil, nil, true, "", 1},
			}},

		{"a subshell's parens are separators", "(cd x); echo done",
			[]Segment{
				{[]string{"cd", "x"}, nil, nil, false, "", 1},
				{[]string{"echo", "done"}, nil, nil, true, "", 3},
			}},

		// Keywords and the env prefix stay in the segment; finding the real
		// command word is StripShKeywords and StripEnvPrefix, per segment.
		{"a compound statement keeps its keywords", "until LC_ALL=C grep x f; do :; done",
			[]Segment{
				{[]string{"until", "LC_ALL=C", "grep", "x", "f"}, nil, nil, true, "", 0},
				{[]string{"do", ":"}, nil, nil, true, "", 1},
				{[]string{"done"}, nil, nil, true, "", 2},
			}},

		// Inputs is the `<` subset of Redirects, and it is this repo's field:
		// upstream asks whether a target is outside the workspace, which a
		// read and a write answer alike, so it never needed the operator.
		{"an input redirect is recorded as one", "cat < in",
			[]Segment{{[]string{"cat"}, []string{"in"}, []string{"in"}, true, "", 0}}},
		{"glued to its target as well", "cat <in",
			[]Segment{{[]string{"cat"}, []string{"in"}, []string{"in"}, true, "", 0}}},
		// The descriptor is popped like any other and the target is still an
		// input: `0<in` is `<in` spelled out, and `3<in` opens in for reading
		// whether or not the command reads fd 3.
		{"with an explicit descriptor", "cat 0<in",
			[]Segment{{[]string{"cat"}, []string{"in"}, []string{"in"}, true, "", 0}}},
		{"an output redirect is not an input", "cat x > out",
			[]Segment{{[]string{"cat", "x"}, []string{"out"}, nil, true, "", 0}}},
		// `<(cmd)` lexes as `<` then `(`. Upstream records the paren as a
		// target, absorbs the substitution's tokens into the command, and
		// splits on the closing paren -- all kept here -- but the paren is not
		// a file and is not an input. Measured over the week to 2026-09-04, 49
		// of 219 input redirects on a known reader were this shape.
		{"a process substitution is a redirect target and not an input",
			"diff <(sort a) <(sort b)",
			[]Segment{
				{[]string{"diff", "sort", "a"}, []string{"("}, nil, false, "", 0},
				{[]string{"sort", "b"}, []string{"("}, nil, false, "", 1},
			}},

		// The operator a segment is reached through, which Persists never
		// reads: the assignment after `&&` persists by upstream's rule and is
		// conditional by this one, and the `;` after it opens a segment that
		// is neither.
		{"a segment reached through && or || says so",
			"false && P=/x || cat $P/f; cat g",
			[]Segment{
				{[]string{"false"}, nil, nil, true, "", 0},
				{[]string{"P=/x"}, nil, nil, true, "&&", 1},
				{[]string{"cat", "$P/f"}, nil, nil, true, "||", 2},
				{[]string{"cat", "g"}, nil, nil, true, "", 3},
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
					g.Persists != w.Persists || g.Conditional != w.Conditional || g.Pipe != w.Pipe {
					t.Errorf("segment %d = %+v, want %+v", i, g, w)
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
		head := StripEnvPrefix(StripShKeywords(s.Tokens))
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
