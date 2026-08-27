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
			[]Segment{{[]string{"cat", "a", "b"}, nil, true, 0}}},

		// A redirect target is collected into the segment it textually appears
		// in, so it later resolves against THAT segment's working directory --
		// which is what lets this one name /tmp/evil rather than ./evil.
		{"a redirect belongs to the segment it was written in",
			"cd /tmp && cat /dev/null > evil",
			[]Segment{
				{[]string{"cd", "/tmp"}, nil, true, 0},
				{[]string{"cat", "/dev/null"}, []string{"evil"}, true, 1},
			}},

		// `pipe` advances on every separator except `|`, so the stages of one
		// pipeline share a number and nothing else does.
		{"a pipeline's stages share a number", "a | b | c",
			[]Segment{
				{[]string{"a"}, nil, false, 0},
				{[]string{"b"}, nil, false, 0},
				{[]string{"c"}, nil, false, 0},
			}},

		// Persistence: an assignment survives at paren depth 0, outside a
		// pipeline stage, and not backgrounded.
		{"an assignment at the top level persists", "f=x; cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, true, 0},
				{[]string{"cat", "$f"}, nil, true, 1},
			}},
		{"one in a subshell does not", "(f=x); cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, false, 1},
				{[]string{"cat", "$f"}, nil, true, 3},
			}},
		{"a backgrounded one does not", "f=x & cat $f",
			[]Segment{
				{[]string{"f=x"}, nil, false, 0},
				{[]string{"cat", "$f"}, nil, true, 1},
			}},
		{"one in a pipeline stage does not", "a | f=x; cat $f",
			[]Segment{
				{[]string{"a"}, nil, false, 0},
				{[]string{"f=x"}, nil, false, 0},
				{[]string{"cat", "$f"}, nil, true, 1},
			}},

		// An fd number glued to a redirect operator lands as the previous
		// token; popped, so it does not leak as a positional file argument.
		{"an fd number before a redirect is not an operand", "cat x 2> err",
			[]Segment{{[]string{"cat", "x"}, []string{"err"}, true, 0}}},
		// A duplication target is an fd or `-`, not a path.
		{"a dup target is not a path", "cat x 2>&1",
			[]Segment{{[]string{"cat", "x"}, nil, true, 0}}},
		{"nor a close", "cat x 2>&-",
			[]Segment{{[]string{"cat", "x"}, nil, true, 0}}},
		{"nor an input dup", "cat x <&3",
			[]Segment{{[]string{"cat", "x"}, nil, true, 0}}},
		// But `>&file` -- target is not a bare fd -- redirects to a file.
		{"a dup operator with a filename target does name a path", "cat x >&out",
			[]Segment{{[]string{"cat", "x"}, []string{"out"}, true, 0}}},
		// The documented limitation: a file literally named `2` written right
		// before a redirect is indistinguishable post-tokenization.
		{"a file named 2 before a redirect is lost, as upstream loses it",
			"cat 2 > out",
			[]Segment{{[]string{"cat"}, []string{"out"}, true, 0}}},
		{"every target of a multiply-redirected command", "sort <in >out 2>err",
			[]Segment{{[]string{"sort"}, []string{"in", "out", "err"}, true, 0}}},
		{"the three-character redirect operators", "a &>> both",
			[]Segment{{[]string{"a"}, []string{"both"}, true, 0}}},
		{"a clobbering redirect", "a >| clobber",
			[]Segment{{[]string{"a"}, []string{"clobber"}, true, 0}}},
		{"a redirect with nothing after it names nothing", "echo hi >",
			[]Segment{{[]string{"echo", "hi"}, nil, true, 0}}},

		// A heredoc delimiter and a here-string's content are not paths.
		{"a heredoc delimiter is not a redirect target",
			"cat <<TAG\nx\nTAG\n> after",
			[]Segment{
				{[]string{"cat"}, nil, true, 0},
				{nil, []string{"after"}, true, 1},
			}},
		{"a here-string's content is not one either", `cat x <<<"here string"`,
			[]Segment{{[]string{"cat", "x"}, nil, true, 0}}},

		// A newline is a command boundary. Left as whitespace it merges the
		// commands on either side, and the second one's operands are read as
		// arguments to the first.
		{"a newline separates two commands", "echo one\necho two",
			[]Segment{
				{[]string{"echo", "one"}, nil, true, 0},
				{[]string{"echo", "two"}, nil, true, 1},
			}},
		{"and a comment does not eat it", "echo hi # note\ncat x",
			[]Segment{
				{[]string{"echo", "hi"}, nil, true, 0},
				{[]string{"cat", "x"}, nil, true, 1},
			}},

		{"a subshell's parens are separators", "(cd x); echo done",
			[]Segment{
				{[]string{"cd", "x"}, nil, false, 1},
				{[]string{"echo", "done"}, nil, true, 3},
			}},

		// Keywords and the env prefix stay in the segment; finding the real
		// command word is StripShKeywords and StripEnvPrefix, per segment.
		{"a compound statement keeps its keywords", "until LC_ALL=C grep x f; do :; done",
			[]Segment{
				{[]string{"until", "LC_ALL=C", "grep", "x", "f"}, nil, true, 0},
				{[]string{"do", ":"}, nil, true, 1},
				{[]string{"done"}, nil, true, 2},
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
					g.Persists != w.Persists || g.Pipe != w.Pipe {
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
