package hook

import (
	"strings"
	"testing"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
)

// The port driven against bash rather than read. Each row is a command string
// and a probe token; `want` is what bash 5.3.15 printed for the probe after
// running the string, taken 2026-09-06 with P and Q preset to /env in the
// environment and HOME=/home/me, so an assignment the string does not make
// shows as the environment's value. The property under test is the port's
// fail-closed direction: whatever the port resolves, it never resolves to a
// literal bash would not have used. Rows the port declines are allowed to keep
// their `$`; rows in `resolves` must not.
//
// Four rows are the exception and are pinned as such. A quoted or escaped
// assignment is a command to bash and an assignment to this lexer, which is
// the Q92 divergence arriving in the resolver, three spellings; and a `case`
// arm is conditional to bash and a plain segment to the segmenter, which is
// Q151's. Each is asserted rather than tolerated so a fix upstream of the
// resolver is a decision here too. Outside those four the property holds on
// every row, and it is a property of the rows rather than a law: the next
// shape bash evaluates conditionally is a drive away.
func TestThePortNeverResolvesToALiteralBashWouldNotUse(t *testing.T) {
	t.Setenv("HOME", "/home/me")
	rows := []struct{ setup, probe, want string }{
		{"P=/lit", "$P/f", "/lit/f"},
		{"P=/lit", "${P}/f", "/lit/f"},
		{"P=/lit", "${P}x", "/litx"},
		{"P=/lit", "$Px", ""},
		{"P=/lit", "${P%/lit}/f", "/f"},
		{"P='/with space'", "$P/f", "/withspace/f"},
		{`P="/dq"`, "$P/f", "/dq/f"},
		{"P=~/h", "$P/f", "/home/me/h/f"},
		{"P=~", "$P/f", "/home/me/f"},
		{"P=~someone", "$P/f", "~someone/f"},
		{"P=$(echo /sub)", "$P/f", "/sub/f"},
		{"P=`echo /sub`", "$P/f", "/sub/f"},
		{"P=$HOME/x", "$P/f", "/home/me/x/f"},
		{"P=/a:/b", "$P/f", "/a:/b/f"},
		{"P=/lit*", "$P/f", "/lit*/f"},
		{"P=", "$P/f", "/f"},
		{"P=(a b)", "$P/f", "a/f"},
		{"A=/a; P=$A/b", "$P/f", "/a/b/f"},
		{"A=/a P=$A/b", "$P/f", "/a/b/f"},
		{"P=/lit cat /dev/null", "$P/f", "/env/f"},
		{"(P=/lit)", "$P/f", "/env/f"},
		{"P=/lit | cat", "$P/f", "/env/f"},
		{"P=/lit &", "$P/f", "/env/f"},
		{"export P=/lit", "$P/f", "/lit/f"},
		{"export -n P=/lit", "$P/f", "/lit/f"},
		{"export P", "$P/f", "/env/f"},
		{"local P=/lit 2>/dev/null", "$P/f", "/env/f"},
		{"declare P=/lit", "$P/f", "/lit/f"},
		{"readonly Q=/lit", "$Q/f", "/lit/f"},
		{"P=/lit; P=/other", "$P/f", "/other/f"},
		{"P=/lit; P+=/more", "$P/f", "/lit/more/f"},
		{"P=/lit; read -r P <<< /read", "$P/f", "/read/f"},
		{"P=/lit; printf -v P /pf", "$P/f", "/pf/f"},
		{"P=/lit; printf '%s' P >/dev/null", "$P/f", "/lit/f"},
		{"P=/lit; eval P=/ev", "$P/f", "/ev/f"},
		{"P=/lit; unset P", "$P/f", "/f"},
		{"P=/lit; for P in /loop; do :; done", "$P/f", "/loop/f"},
		{"P=/lit; (( P = 5 ))", "$P/f", "5/f"},
		// Reached through && or ||: the assignment ran only on one branch, and
		// the probe is the next statement, which runs on both. andOr in
		// vars.go carries the rule; `true` is a command whose status the port
		// does not know, so the fourth row is the allowed direction.
		{"false && P=/other", "$P/f", "/env/f"},
		{"P=/lit; false && P=/other", "$P/f", "/lit/f"},
		{`[ -d "$D" ] || D=/fallback`, "$D/f", "/env/f"},
		{"true && P=/lit", "$P/f", "/lit/f"},
		{"true || P=/other", "$P/f", "/env/f"},
		{"false || P=/other", "$P/f", "/other/f"},
		{"false && P=/other || :", "$P/f", "/env/f"},
		{"P=/lit && Q=/lit2", "$Q/f", "/lit2/f"},
		{"cd /tmp && P=/lit", "$P/f", "/lit/f"},
		{"cd /nowhere-such && P=/lit", "$P/f", "/env/f"},
		// An assignment is not always exit 0: one whose value runs a command
		// takes that command's status, and a redirect that cannot open fails
		// the segment. The `$(…)` spelling came out unresolved before assigned
		// learned this, because Segments flattens the body into a segment of
		// its own ahead of the assignment and ran() unsettles on it; the
		// backtick body is not flattened, so it reached assigned as a plain
		// segment. `export` returns 0 whatever its value did, so the last row
		// is the port under-resolving, which is the allowed direction.
		{"X=`false` && Q=/lit", "$Q/f", "/env/f"},
		{"X=/x >/nonexistent-dir/z && Q=/lit", "$Q/f", "/env/f"},
		{"X=$(false) && Q=/lit", "$Q/f", "/env/f"},
		{"export X=$(false) && Q=/lit", "$Q/f", "/lit/f"},
		{"P=/lit; IFS=/", "$P/f", "lit/f"},
		{"if P=/lit; then :; fi", "$P/f", "/lit/f"},
		{"RANDOM=5", "$RANDOM", "18498"},
		{"PWD=/x", "$PWD/f", "/x/f"},
		{"P=/lit; echo $(P=/in)", "$P/f", "/lit/f"},
		{"P=/lit; cd /tmp", "$P/f", "/lit/f"},
		{`P=/l\ it`, "$P/f", "/lit/f"},
		{`P=/lit\$x`, "$P/f", "/lit$x/f"},
		{"P=/lit; P[0]=/arr", "$P/f", "/arr/f"},
		{"P=/lit; P++", "$P/f", "/lit/f"},
		{"P=/lit; mapfile P < /dev/null", "$P/f", "/f"},
		{"P=/lit; source /dev/null", "$P/f", "/lit/f"},
		{"P=/lit; . /dev/null", "$P/f", "/lit/f"},
		{"P=/lit; let P=3", "$P/f", "3/f"},
		{"P=/lit; LC_ALL=C read -r P <<< /read", "$P/f", "/read/f"},
		{"P=/lit; while read -r P; do :; done < /dev/null", "$P/f", "/f"},
	}
	// The rows the port must resolve, not merely not get wrong. Everything the
	// row Q136 measured -- a literal path assigned once and used later -- is
	// one of these shapes.
	resolves := map[string]bool{
		"P=/lit ; $P/f": true, "P=/lit ; ${P}/f": true, "P=/lit ; ${P}x": true,
		`P="/dq" ; $P/f`: true, "P=~/h ; $P/f": true, "P=~ ; $P/f": true,
		"A=/a; P=$A/b ; $P/f": true, "A=/a P=$A/b ; $P/f": true,
		"export P=/lit ; $P/f": true, "export -n P=/lit ; $P/f": true,
		"P=/lit; P=/other ; $P/f":                 true,
		"P=/lit; printf '%s' P >/dev/null ; $P/f": true, "P=/lit; cd /tmp ; $P/f": true,
		"P=/lit && Q=/lit2 ; $Q/f": true, "cd /tmp && P=/lit ; $P/f": true,
	}
	for _, row := range rows {
		name := row.setup + " ; " + row.probe
		t.Run(name, func(t *testing.T) {
			got := probeVars(t, row.setup, row.probe)
			if got != row.want && !strings.Contains(got, "$") {
				t.Errorf("port resolved %q, bash gave %q", got, row.want)
			}
			if resolves[name] && strings.Contains(got, "$") {
				t.Errorf("port left %q unresolved, bash gave %q", got, row.want)
			}
		})
	}
	// The three Q92 spellings. bash ran a command it could not find and left P
	// at the environment's /env; the lexer handed the port `P=/lit` with its
	// quotes gone, and the port assigned it. Pinned so a lexer fix that keeps
	// quote provenance is a decision here, as it is in override_test.go.
	for _, setup := range []string{`'P=/lit'`, `"P=/lit"`, `P\=/lit`} {
		t.Run("Q92: "+setup, func(t *testing.T) {
			if got := probeVars(t, setup, "$P/f"); got != "/lit/f" {
				t.Errorf("got %q, want the inherited divergence to resolve /lit/f -- if the "+
					"lexer now keeps quote provenance, this pin and Q92's are the ones to revisit", got)
			}
		})
	}
	// A case arm. bash 5.3.15 ran none of it; the segmenter sees `)` at paren
	// depth 0 and a plain segment after it, so the port assigns. Q151's
	// class, pinned so a segmenter that learns case bodies is a decision here.
	t.Run("Q151: case x in y) P=/case;; esac", func(t *testing.T) {
		if got := probeVars(t, "case x in y) P=/case;; esac", "$P/f"); got != "/case/f" {
			t.Errorf("got %q, want the pinned divergence to resolve /case/f -- if the "+
				"segmenter now reads case arms, this pin and Q151 are the ones to revisit", got)
		}
	})
}

// probeVars runs the propagation over setup the way bashTargets does, then
// expands probe against what it holds.
func probeVars(t *testing.T, setup, probe string) string {
	t.Helper()
	segments, err := bash.Segments(setup)
	if err != nil {
		t.Fatal(err)
	}
	v := newVars()
	list := andOr{settled: true}
	var dirUnknown bool
	for _, segment := range segments {
		list.enter(segment, v, &dirUnknown)
		switch names, observed := v.observe(segment.Tokens, v.expand(segment.Tokens),
			list.persists(segment), list.binds(segment)); observed {
		case observedAssignments:
			list.assigned(segment, names)
			continue
		case observedLoopHeader:
			list.ran()
			continue
		}
		if kind, arg := classifyCd(bash.StripEnvPrefix(bash.StripShKeywords(segment.Tokens))); kind != "" {
			var dir string
			dir, dirUnknown = follow(kind, arg, "/", dirUnknown, segment)
			_ = dir
			list.moved(segment, dirUnknown)
			continue
		}
		list.ran()
	}
	// The probe stands for a reader in the next statement, as `; echo $P/f`
	// did when the table was taken.
	list.close(v, &dirUnknown)
	return v.expand([]string{probe})[0]
}

// Upstream's own unit cases for the four functions, carried across so a
// divergence in the port is caught at the function rather than through a
// verdict.
func TestSubstituteVars(t *testing.T) {
	m := map[string]string{"SP": "/opt/scratch", "f": "in.txt"}
	for tok, want := range map[string]string{
		"$SP/q.csv":   "/opt/scratch/q.csv",
		"${SP}.bak":   "/opt/scratch.bak",
		"$SPX":        "$SPX",
		"$nope/x":     "$nope/x",
		"${f%.txt}":   "${f%.txt}",
		"$f`cmd`":     "$f`cmd`",
		"plain":       "plain",
		"$SP/$f":      "/opt/scratch/in.txt",
		"${SP}/${f}x": "/opt/scratch/in.txtx",
	} {
		if got := substituteVars(tok, m); got != want {
			t.Errorf("substituteVars(%q) = %q, want %q", tok, got, want)
		}
	}
	if got := substituteVars("$SP", map[string]string{}); got != "$SP" {
		t.Errorf("empty map: got %q", got)
	}
}

func TestApplyAssignmentGroup(t *testing.T) {
	type tc struct {
		name     string
		tokens   []string
		before   map[string]string
		persists bool
		ok       bool
		names    []string
		after    map[string]string
	}
	for _, c := range []tc{
		{"single", []string{"f=in.txt"}, nil, true, true, []string{"f"}, map[string]string{"f": "in.txt"}},
		{"sequential", []string{"a=sub", "b=$a/x.txt"}, nil, true, true, []string{"a", "b"}, map[string]string{"a": "sub", "b": "sub/x.txt"}},
		{"export", []string{"export", "f=in.txt"}, nil, true, true, []string{"f"}, map[string]string{"f": "in.txt"}},
		{"export bare name", []string{"export", "f"}, map[string]string{"f": "in.txt"}, true, true, []string{}, map[string]string{"f": "in.txt"}},
		{"impure value", []string{"f=$(cmd)"}, map[string]string{"f": "in.txt"}, true, true, []string{"f"}, map[string]string{}},
		{"non-persisting", []string{"f=new.txt"}, map[string]string{"f": "old.txt"}, false, true, []string{"f"}, map[string]string{}},
		{"special names", []string{"RANDOM=5", "PWD=/x", "_=/y"}, nil, true, true, []string{"RANDOM", "PWD", "_"}, map[string]string{}},
		{"prefix on a command", []string{"f=x", "cat", "y"}, nil, true, false, nil, map[string]string{}},
		{"plain command", []string{"cat", "x"}, nil, true, false, nil, map[string]string{}},
		{"export of a non-name", []string{"export", "f=x", "y/z"}, nil, true, false, nil, map[string]string{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range c.before {
				m[k] = v
			}
			names, ok := applyAssignmentGroup(c.tokens, m, c.persists)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && strings.Join(names, ",") != strings.Join(c.names, ",") {
				t.Errorf("names = %q, want %q", names, c.names)
			}
			if !mapsEqual(m, c.after) {
				t.Errorf("map = %v, want %v", m, c.after)
			}
		})
	}
}

func TestPoisonVars(t *testing.T) {
	for _, c := range []struct {
		name   string
		tokens []string
		before map[string]string
		after  map[string]string
	}{
		{"eval clears", []string{"eval", "echo"}, map[string]string{"f": "x", "g": "y"}, map[string]string{}},
		{"source clears", []string{"source", "lib.sh"}, map[string]string{"f": "x"}, map[string]string{}},
		{"dot clears", []string{".", "lib.sh"}, map[string]string{"f": "x"}, map[string]string{}},
		{"read poisons its names", []string{"read", "-r", "f"}, map[string]string{"f": "x", "g": "y"}, map[string]string{"g": "y"}},
		{"read with a $ arg clears", []string{"read", "$n"}, map[string]string{"f": "x"}, map[string]string{}},
		{"read clobbers REPLY", []string{"read"}, map[string]string{"REPLY": "x", "g": "y"}, map[string]string{"g": "y"}},
		{"keyword prefix skipped", []string{"while", "read", "-r", "f"}, map[string]string{"f": "x"}, map[string]string{}},
		{"for poisons the loop var", []string{"for", "f", "in", "a", "b"}, map[string]string{"f": "x", "g": "y"}, map[string]string{"g": "y"}},
		{"env prefix skipped before dispatch", []string{"LC_ALL=C", "read", "-r", "f"}, map[string]string{"f": "x"}, map[string]string{}},
		{"env prefix name still poisoned", []string{"f=/y", "read", "g"}, map[string]string{"f": "x", "g": "y"}, map[string]string{}},
		{"prefix assignment poisons", []string{"f=/y", "cat", "z"}, map[string]string{"f": "x"}, map[string]string{}},
		{"append", []string{"f+=/y"}, map[string]string{"f": "x"}, map[string]string{}},
		{"array element", []string{"f[0]=/y"}, map[string]string{"f": "x"}, map[string]string{}},
		{"increment", []string{"f++"}, map[string]string{"f": "x"}, map[string]string{}},
		{"torn arithmetic", []string{"f", "=", "5"}, map[string]string{"f": "x"}, map[string]string{}},
		{"plain command leaves it", []string{"grep", "PAT", "y.txt"}, map[string]string{"f": "x"}, map[string]string{"f": "x"}},
		{"printf without -v leaves it", []string{"printf", "%s\n", "$UNSET"}, map[string]string{"f": "x"}, map[string]string{"f": "x"}},
		{"printf -- -v leaves it", []string{"printf", "--", "-v", "f"}, map[string]string{"f": "x"}, map[string]string{"f": "x"}},
		{"printf -v poisons", []string{"printf", "-v", "f", "%s", "y"}, map[string]string{"f": "x"}, map[string]string{}},
		{"printf -vNAME poisons", []string{"printf", "-vf", "%s", "y"}, map[string]string{"f": "x"}, map[string]string{}},
		{"printf option-region $ clears", []string{"printf", "$fmt", "%s", "y"}, map[string]string{"f": "x"}, map[string]string{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range c.before {
				m[k] = v
			}
			poisonVars(c.tokens, m)
			if !mapsEqual(m, c.after) {
				t.Errorf("map = %v, want %v", m, c.after)
			}
		})
	}
}

func TestClobbersIFS(t *testing.T) {
	for _, c := range []struct {
		tokens []string
		want   bool
	}{
		{[]string{"eval", "x"}, true},
		{[]string{"declare", "IFS=x"}, true},
		{[]string{"read", "IFS"}, true},
		{[]string{"printf", "-v", "IFS", "x"}, true},
		{[]string{"read", "$n"}, true},
		{[]string{"unset", "IFS"}, false},
		{[]string{"printf", "%s", "IFS"}, false},
		{[]string{"cat", "IFS"}, false},
		{[]string{"IFS=x", "cat", "f"}, false},
	} {
		if got := clobbersIFS(c.tokens); got != c.want {
			t.Errorf("clobbersIFS(%q) = %v, want %v", c.tokens, got, c.want)
		}
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Upstream's unit cases for the loop functions, carried across beside the four
// above. `for` is not a shell keyword to StripShKeywords -- upstream's list
// omits it for the same reason -- so a header reaches these with its own first
// token, and a nested loop's `do for f in …` arrives with the `do` off.
func TestLiteralLoopItem(t *testing.T) {
	t.Setenv("HOME", "/home/me")
	for raw, want := range map[string]string{
		"docs/a.md":  "docs/a.md",
		"docs/*.md":  "docs/*.md", // a pattern is kept; expand globs it later
		"a?.md":      "a?.md",
		"[ab].md":    "[ab].md",
		"~/notes.md": "/home/me/notes.md",
		"{a,b}.md":   "", // brace-expanded by bash, so the literal is not a path
		"a{1..3}":    "",
		"$SP/a.md":   "",
		"a b":        "",
		"/a:/b":      "",
		"~someone/x": "",
		"":           "",
	} {
		t.Run(raw, func(t *testing.T) {
			got, ok := literalLoopItem(raw)
			if want == "" {
				if ok {
					t.Errorf("literalLoopItem(%q) = %q, want it declined", raw, got)
				}
				return
			}
			if !ok || got != want {
				t.Errorf("literalLoopItem(%q) = %q, %v; want %q, true", raw, got, ok, want)
			}
		})
	}
}

func TestForLoopBinding(t *testing.T) {
	outer := map[string][]string{"d": {"d1", "d2"}}
	for _, c := range []struct {
		name   string
		tokens []string
		loops  map[string][]string
		want   []string // nil with isFor true is the poison
		isFor  bool
	}{
		{"a literal list", []string{"for", "f", "in", "/a", "/b"}, nil, []string{"/a", "/b"}, true},
		{"an absolute path to for", []string{"/usr/bin/for", "f", "in", "/a"}, nil, []string{"/a"}, true},
		{"a glob item", []string{"for", "f", "in", "d/*.md"}, nil, []string{"d/*.md"}, true},
		{"over the outer variable", []string{"for", "f", "in", "$d/c.env"}, outer,
			[]string{"d1/c.env", "d2/c.env"}, true},
		{"a non-literal item", []string{"for", "f", "in", "$X"}, nil, nil, true},
		{"a brace item", []string{"for", "f", "in", "{a,b}"}, nil, nil, true},
		{"no in", []string{"for", "f"}, nil, nil, true},
		{"an empty list", []string{"for", "f", "in"}, nil, nil, true},
		{"a name bash treats specially", []string{"for", "IFS", "in", "/a"}, nil, nil, false},
		{"the arithmetic form", []string{"for", "((", "i=0", "))"}, nil, nil, false},
		{"not a for", []string{"cat", "f", "in", "/a"}, nil, nil, false},
		{"nothing to read", []string{"for"}, nil, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, values, isFor := forLoopBinding(c.tokens, c.loops)
			if isFor != c.isFor {
				t.Fatalf("isFor = %v, want %v", isFor, c.isFor)
			}
			if strings.Join(values, " ") != strings.Join(c.want, " ") {
				t.Errorf("values = %q, want %q", values, c.want)
			}
		})
	}
}

func TestExpandLoopCandidates(t *testing.T) {
	loops := map[string][]string{"f": {"/a", "/b"}, "g": {"x", "y"}}
	for _, c := range []struct {
		tok  string
		want []string
		ok   bool
	}{
		{"$f/deploy.env", []string{"/a/deploy.env", "/b/deploy.env"}, true},
		{"${f}x", []string{"/ax", "/bx"}, true},
		{"$f/$g", []string{"/a/x", "/a/y", "/b/x", "/b/y"}, true},
		{"$f/$f", []string{"/a//a", "/b//b"}, true}, // one variable, one axis
		{"plain.env", []string{"plain.env"}, true},
		{"$UNKNOWN/x", []string{"$UNKNOWN/x"}, true},
		{"`echo $f`", []string{"`echo $f`"}, true},
	} {
		t.Run(c.tok, func(t *testing.T) {
			got, ok := expandLoopCandidates(c.tok, loops)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("expandLoopCandidates(%q) = %q, want %q", c.tok, got, c.want)
			}
		})
	}
	t.Run("over the cap", func(t *testing.T) {
		big := map[string][]string{}
		var wide []string
		for i := 0; i <= maxLoopCandidates; i++ {
			wide = append(wide, "v")
		}
		big["w"] = wide
		if got, ok := expandLoopCandidates("$w/x", big); ok {
			t.Errorf("expandLoopCandidates returned %d candidates, want the cap to refuse", len(got))
		}
	})
}
