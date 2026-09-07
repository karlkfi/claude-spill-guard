package hook

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
)

// The literal-variable propagation of bash-workspace-guard.py (its issues 58
// and 70), ported function for function: literal_assignment_value,
// literal_for_item, for_loop_binding, expand_loop_candidates, substitute_vars,
// apply_assignment_group, poison_vars, printf_assigns, unglue_printf_v and
// clobbers_ifs, with the constants they read. A `$NAME` in a reader's operand
// whose NAME the same command string assigned a literal -- or bound to a `for`
// list -- is what bash and this hook can both read off the string; everything
// else keeps the `$`, and resolve records it as it did before.
//
// Fail-closed direction is the port's own. A value that is not a provable
// literal, an assignment that cannot persist, a builtin that might assign, a
// name bash treats specially -- each POISONS the name, which only ever restores
// the unresolved operand. Nothing here guesses.
//
// What is not ported, and why, is at each site: the Windows drive-prefix
// exemption (Q79's class), the stable subset the upstream recursion starts from
// (Q147), and the loop bindings that subset seeds, which are the same argument.

// varUseRE is a plain `$NAME` or `${NAME}`. A parameter-expansion operator
// (`${f:-x}`, `${f%.*}`) deliberately does not match, so its `$` stays and the
// operand stays unresolved.
var varUseRE = regexp.MustCompile(`\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// identRE matches at the head of a token, as Python's IDENT_RE.match does; a
// full-token test is identRE plus a length check at the site.
var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// assignishRE is a token that mutates a variable outside the plain form:
// `f=…` as a command prefix, `f+=…`, `f[0]=…`, `f++`, `f--`.
var assignishRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\+?=|\[|\+\+|--)`)

// impureValueChars make an assignment value unsafe to treat as a literal,
// checked after the lexer's quote removal: expansions, glob metacharacters
// (an unquoted use of the variable would glob), and word-splitting characters
// -- whitespace for the default IFS, and `:` so a PATH-shaped value cannot be
// split by an IFS this never saw.
const impureValueChars = " \t\n$`*?[:"

// impureItemChars is that set with the glob metacharacters back out, for a
// `for` list item, which bash expands as a pattern. literalLoopItem carries
// what makes a pattern safe to keep here.
const impureItemChars = " \t\n$`:"

// maxLoopCandidates bounds what a loop variable expands to: the values one
// variable may be bound to, and the cross product a token naming several of
// them stands for. Upstream's MAX_LOOP_CANDIDATES, at its number.
//
// The scanner's own budget does not stand in for it, because what the cap
// bounds is where the time goes rather than how much there is. Three nested
// loops over 256 literals each make `cat $a/$b/$c` 16.7M tokens to build before
// a byte is read, so the budget would be spent producing paths instead of
// scanning what the call sends -- and the verdict at the end of it is the
// coverage record the cap reaches at once. Upstream measured that shape past
// two minutes, at which point its hook answered nothing at all.
//
// The product is known before any expansion happens, so the cap costs nothing
// to enforce, and it POISONS rather than truncating: checking a prefix of the
// candidates would report a clean scan for the files after it.
const maxLoopCandidates = 256

// neverPropagate are the names bash treats specially: assigning one does not
// make `$NAME` expand to the literal.
var neverPropagate = map[string]bool{
	"_": true, "IFS": true, "PWD": true, "OLDPWD": true, "RANDOM": true,
	"SRANDOM": true, "SECONDS": true, "LINENO": true, "BASHPID": true,
	"PPID": true, "UID": true, "EUID": true, "GROUPS": true,
	"EPOCHSECONDS": true, "EPOCHREALTIME": true, "BASH_SUBSHELL": true,
	"BASH_COMMAND": true, "PIPESTATUS": true, "FUNCNAME": true, "DIRSTACK": true,
}

// poisonAllCmds can assign any variable invisibly, so the whole map dies.
var poisonAllCmds = map[string]bool{"eval": true, "source": true, ".": true}

// argAssignerCmds assign to the variables their arguments name. `printf`
// assigns only under `-v`, which printfAssigns gates.
var argAssignerCmds = map[string]bool{
	"read": true, "readarray": true, "mapfile": true, "getopts": true,
	"declare": true, "typeset": true, "local": true, "readonly": true,
	"export": true, "unset": true, "let": true, "printf": true, "for": true,
	"select": true,
}

// vars is the live map for one command string, advanced a segment at a time.
// A queued substitution body starts a map of its own, empty: it has no
// position in the string, so a value assigned after it would be substituted
// into a body bash expanded with the environment's -- the direction this
// resolver must not take, and the reason upstream's stable-subset seed is not
// ported (Q147).
type vars struct {
	m map[string]string
	// loops is the candidate set each `for` variable stands for, kept apart
	// from m as upstream keeps it: the two poison each other, since a name
	// assigned a scalar is no longer a loop variable and a name a `for` binds
	// is no longer a scalar.
	loops     map[string][]string
	propagate bool
}

func newVars() *vars {
	return &vars{m: map[string]string{}, loops: map[string][]string{}, propagate: true}
}

// expand substitutes what the map holds into tokens, so the readers and the
// cd tracker see the argv bash would have run.
func (v *vars) expand(tokens []string) []string {
	if len(v.m) == 0 {
		return tokens
	}
	out := make([]string, len(tokens))
	for i, t := range tokens {
		out[i] = substituteVars(t, v.m)
	}
	return out
}

// observation is what observe made of a segment: a command for the caller to
// judge, assignments alone, or a `for NAME in …` header. The three arms are
// upstream's, in its order -- an assignment group first, because bash decides
// what is an assignment before expansion, then the header, then the poison
// every other segment gets.
type observation int

const (
	observedCommand observation = iota
	observedAssignments
	observedLoopHeader
)

// observe folds one segment into the maps and says which of the three it was.
// raw is the segment's own tokens, which is what decides whether it is an
// assignment; sub is raw with the map substituted, which is what a builtin's
// arguments name and what a `for` list iterates. An IFS change stops
// propagation for the rest of the string: every later expansion is re-split by
// a value this never saw. binds is andOr's, and gates the header alone.
func (v *vars) observe(raw, sub []string, persists, binds bool) ([]string, observation) {
	if !v.propagate {
		return nil, observedCommand
	}
	if names, ok := applyAssignmentGroup(raw, v.m, persists); ok {
		for _, name := range names {
			delete(v.loops, name) // a name set as a scalar is no longer a loop variable
			if name == "IFS" {
				v.stop()
			}
		}
		return names, observedAssignments
	}
	if name, values, ok := forLoopBinding(bash.StripShKeywords(sub), v.loops); ok {
		delete(v.m, name) // and a loop variable is not a scalar
		if values == nil || !binds {
			delete(v.loops, name)
		} else {
			v.loops[name] = values
		}
		return nil, observedLoopHeader
	}
	if clobbersIFS(sub) {
		v.stop()
	} else {
		poisonVars(sub, v.m)
		poisonVars(sub, v.loops) // the same rules invalidate a binding
	}
	return nil, observedCommand
}

// candidates is the concrete tokens a loop variable in tok stands for, one per
// value bash iterates, or false when that set is over maxLoopCandidates.
func (v *vars) candidates(tok string) ([]string, bool) {
	return expandLoopCandidates(tok, v.loops)
}

// andOr is the and-or list a pass is inside, which is what says whether an
// assignment or a cd that bash reached through `&&` had run by the time a
// later segment does. Upstream does not ask: its Persists reads the separator
// after a segment, so `false && P=/x; cat $P/f` assigns P there and resolves a
// path bash never used. This resolver opens the file the path names, so it
// asks, and the answer is bash's own evaluation order rather than a guess in
// either direction:
//
//   - A segment reached through `&&` ran only if everything before it in the
//     list exited 0. That is certain while the list holds nothing but plain
//     assignments -- no substitution, whose status the assignment takes, and
//     no redirect, which fails the segment when it cannot open -- and moves
//     this tracker followed to a directory that exists; a command whose
//     status nothing here knows makes the rest of the list unsettled. `cd
//     "$(git rev-parse --show-toplevel)" && SP=/x; tail $SP/f` resolves, and
//     is 220 of the 655 conditional assignments in a week of this machine's
//     Bash calls; `mkdir -p x && SP=/x; tail $SP/f` does not.
//   - What an unsettled `&&` segment assigns still holds for the rest of its
//     own list -- a later `&&` segment runs only if this one did -- and is
//     dropped at the list's end, where a new statement runs on both branches.
//   - A `||` picks the branch nothing here can pick, so what it reaches is
//     poisoned outright and what was tentative before it is dropped: `false
//     && P=/x || cat $P/f` runs the cat on the branch where P was never set.
//
// A `case` arm is not an and-or list and is read as unconditional, which is
// Q151's class and is pinned in vars_test.go.
type andOr struct {
	settled      bool
	tentative    []string
	tentativeDir bool
}

// enter opens the segment. One reached through neither operator starts a new
// list; `||` ends certainty for the rest of this one. Both drop what was
// tentative, because what follows runs on branches where it was never set.
func (l *andOr) enter(segment bash.Segment, v *vars, dirUnknown *bool) {
	switch segment.Conditional {
	case "":
		l.close(v, dirUnknown)
		l.settled = true
	case "||":
		l.close(v, dirUnknown)
		l.settled = false
	}
}

func (l *andOr) close(v *vars, dirUnknown *bool) {
	if !l.settled {
		for _, name := range l.tentative {
			delete(v.m, name)
		}
		if l.tentativeDir {
			*dirUnknown = true
		}
	}
	l.tentative, l.tentativeDir = nil, false
}

// persists is whether an assignment in segment may be applied at all.
func (l *andOr) persists(segment bash.Segment) bool {
	return segment.Persists && segment.Conditional != "||"
}

// binds is whether a `for` header here may record its candidate set. Narrower
// than persists, and asked separately: a binding is read by the operands
// INSIDE the loop and not only after it, so the tentative hold assigned gives
// an `&&` cannot serve it -- those names are dropped at the list's end, and the
// body sits after that end. So a header the shell may not have reached, or one
// whose loop runs where the segments after it are not -- a subshell, a pipeline
// stage, a background job -- poisons the name instead, which is how follow
// refuses a `cd`. l.settled is post-enter, so it is already false after a `||`.
//
// Upstream binds through all of those, because a candidate bash never took
// only ever adds a prompt there where here it decides which file gets opened.
func (l *andOr) binds(segment bash.Segment) bool {
	return segment.Persists && l.settled
}

// assigned records an assignment-only segment that applied names. One whose
// value runs a command exits with that command's status, and one with a
// redirect fails when the target cannot open, so either unsettles the list
// as a command would. Only the backtick spelling reaches this: Segments
// flattens an unquoted `$(…)` body into a segment of its own ahead of the
// assignment, and that segment is a command to ran().
func (l *andOr) assigned(segment bash.Segment, names []string) {
	if segment.Conditional == "&&" && !l.settled {
		l.tentative = append(l.tentative, names...)
	}
	if len(segment.Redirects) > 0 {
		l.settled = false
	}
	for _, tok := range segment.Tokens {
		if strings.ContainsAny(tok, "`") || strings.Contains(tok, "$(") {
			l.settled = false
		}
	}
}

// moved records a cd, followed or not.
func (l *andOr) moved(segment bash.Segment, unknown bool) {
	if unknown {
		l.settled = false
		return
	}
	if segment.Conditional == "&&" && !l.settled {
		l.tentativeDir = true
	}
}

// ran records a command, whose exit status nothing here knows.
func (l *andOr) ran() { l.settled = false }

func (v *vars) stop() {
	clear(v.m)
	clear(v.loops)
	v.propagate = false
}

// isAssignment is ASSIGNMENT_RE.match, asked of internal/bash so the one
// assignment regex stays there.
func isAssignment(tok string) bool {
	return len(bash.StripEnvPrefix([]string{tok})) == 0
}

// literalAssignmentValue is the literal an assignment's value resolves to, or
// false if bash might expand or word-split it into something this cannot
// predict. raw is post-lexer, quotes removed. A leading `~` or `~/…` expands
// as bash expands it in an assignment; `~user` and an unresolvable home stay
// unresolvable. An empty value is rejected because `f=(a b)` lexes as `f=`
// plus a paren run, and the scalar empty string would miss the array's real
// `$f`.
//
// allowGlob keeps `*?[` instead of rejecting them; only literalLoopItem passes
// it, and only it carries the argument for why a pattern is safe to keep.
//
// Upstream exempts a Windows drive prefix from the `:` rule. Not here: nothing
// in this resolver reads a drive path, and Q79 is where that divergence lives.
func literalAssignmentValue(raw string, allowGlob bool) (string, bool) {
	if raw == "" {
		return "", false
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		raw = expandTilde(raw)
	}
	if strings.HasPrefix(raw, "~") {
		return "", false
	}
	impure := impureValueChars
	if allowGlob {
		impure = impureItemChars
	}
	if strings.ContainsAny(raw, impure) {
		return "", false
	}
	return raw, true
}

// literalLoopItem is the literal a `for NAME in <list>` item resolves to, or
// false when bash would expand it into paths this cannot predict (upstream's
// literal_for_item, its issue 70). It reuses the assignment-value purity test
// -- same tilde handling, same rejection of `$`, a backtick and whitespace --
// and then rejects a brace item: unlike an assignment value, a for-list item IS
// brace-expanded, so `{a,b}` kept as the literal string would miss the real `a`
// and `b`. A rejected item poisons the loop variable, which is the coverage
// record the operand had before any of this.
//
// A glob item is kept, as the pattern itself (upstream's issue 99), and what
// makes that sound here is not what makes it sound there. Upstream only asks
// where a path lands, and a pattern proxies its whole expansion because `*`,
// `?` and `[…]` never match `/`, so every path it expands to sits in the same
// directory. This opens the file, where a proxy settles nothing -- the
// candidate is sound because it goes on to expand, which globs it into the
// files bash would hand the command. A token built around the candidate keeps
// that: `cat "$f.bak"` over `docs/*.md` reaches expand as `docs/*.md.bak`,
// which matches every file bash reads that exists, and one that does not exist
// sends nothing either way.
func literalLoopItem(raw string) (string, bool) {
	val, ok := literalAssignmentValue(raw, true)
	if !ok || strings.ContainsAny(val, "{}") {
		return "", false
	}
	return val, true
}

// forLoopBinding classifies a segment as a `for NAME in <list>` header
// (upstream's for_loop_binding, its issue 70).
//
//	"", nil, false     not a `for NAME in` header: the caller's poison path
//	                   runs unchanged, which is where `for ((…))` goes, since
//	                   the arithmetic form lexes a `(` where the name would be
//	name, nil, true    a list this cannot expand -- a non-literal or brace
//	                   item, a `for NAME` over "$@", an empty list, or more
//	                   values than the cap. The caller drops NAME from both
//	                   maps, which is the poison it had before loops existed
//	name, values, true the candidate set, so a `$NAME` in a later operand is
//	                   one path per value bash iterates
//
// Called on the post-substitution tokens with the reserved words already off:
// `SP=/x; for f in $SP/a` binds what bash iterates, and a nested loop's header
// shares its segment with the enclosing `do`.
//
// A list item may use an enclosing loop's variable -- `for d in docs/*; do for
// f in "$d"/*.md` -- so items are expanded over loops first and the inner
// variable binds one candidate per (outer candidate, item) pair, which is what
// bash visits. Expanding before the caller rebinds the name reads the outer
// value, which is what bash expands the list with even where the inner loop
// reuses the name. The count is capped per item as well as in total, so a list
// that would blow past the cap stops there rather than after materialising the
// whole cross product.
func forLoopBinding(tokens []string, loops map[string][]string) (string, []string, bool) {
	if len(tokens) < 2 || filepath.Base(tokens[0]) != "for" {
		return "", nil, false
	}
	name := tokens[1]
	if name == "" || identRE.FindString(name) != name || neverPropagate[name] {
		return "", nil, false
	}
	if len(tokens) < 3 || tokens[2] != "in" {
		return name, nil, true // `for NAME` over "$@"
	}
	items := tokens[3:]
	if len(items) == 0 {
		return name, nil, true // empty list -> the body never runs
	}
	var values []string
	for _, item := range items {
		cands, ok := expandLoopCandidates(item, loops)
		if !ok {
			return name, nil, true // over-cap item
		}
		for _, cand := range cands {
			val, ok := literalLoopItem(cand)
			if !ok {
				return name, nil, true // non-literal item
			}
			values = append(values, val)
			if len(values) > maxLoopCandidates {
				return name, nil, true // over-cap list
			}
		}
	}
	return name, values, true
}

// expandLoopCandidates expands every `$NAME`/`${NAME}` whose NAME is a loop
// variable into the concrete tokens bash iterates over (upstream's
// expand_loop_candidates, its issue 70). A token using one stands for one path
// per candidate and bash visits all of them, so the caller reads all of them --
// which is the file set the command sends rather than a walk of anything, the
// reading the directory refusal in bash.go turns on.
//
// Comes back as tok alone when the token uses no loop variable, or holds a
// backtick this will not evaluate. Several distinct loop variables in one token
// expand as the cross product; the order is variable order then candidate
// order, so a reason and a test read the same twice.
//
// False when that cross product would exceed maxLoopCandidates. Its size is the
// product of the per-variable counts, so it is known before any expansion
// happens and the work is never done; the caller records the operand, which is
// the verdict a runtime-expanded token had before loops existed.
func expandLoopCandidates(tok string, loops map[string][]string) ([]string, bool) {
	if len(loops) == 0 || !strings.Contains(tok, "$") || strings.Contains(tok, "`") {
		return []string{tok}, true
	}
	var names []string
	for _, m := range varUseRE.FindAllStringSubmatch(tok, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if _, ok := loops[name]; ok && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return []string{tok}, true
	}
	total := 1
	for _, name := range names {
		total *= len(loops[name])
		if total > maxLoopCandidates {
			return nil, false
		}
	}
	results := []string{tok}
	for _, name := range names {
		expanded := make([]string, 0, len(results)*len(loops[name]))
		for _, r := range results {
			for _, val := range loops[name] {
				expanded = append(expanded, substituteVars(r, map[string]string{name: val}))
			}
		}
		results = expanded
	}
	return results, true
}

// substituteVars replaces the plain `$NAME` and `${NAME}` uses whose literal
// is known. An unknown name is left in place, so the `$` keeps the operand
// unresolved. A token holding a backtick comes back untouched: it is a command
// substitution this does not evaluate, and leaving the `$` alone is the secure
// default.
func substituteVars(tok string, varmap map[string]string) string {
	if len(varmap) == 0 || !strings.Contains(tok, "$") || strings.Contains(tok, "`") {
		return tok
	}
	return varUseRE.ReplaceAllStringFunc(tok, func(m string) string {
		sub := varUseRE.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[2]
		}
		if val, ok := varmap[name]; ok {
			return val
		}
		return m
	})
}

// applyAssignmentGroup folds a segment that is nothing but assignments --
// `NAME=VAL …` or `export [-flag] NAME=VAL …` -- into varmap and reports the
// names it assigned, or false with varmap untouched when the segment is
// something else.
//
// Called on the PRE-substitution tokens: bash decides what is an assignment
// before expansion, so `$f` expanding to `g=x` runs a command named `g=x`.
// Values are substituted and applied left to right, matching bash (`a=x b=$a`
// sets b from the new a). A name is dropped rather than set when its value is
// not a provable literal, when the segment cannot persist (Persists false: a
// subshell, a pipeline stage, a background job), or when bash treats the name
// specially. A bare `export NAME` re-exports without changing the value, so
// it neither sets nor drops.
func applyAssignmentGroup(tokens []string, varmap map[string]string, persists bool) ([]string, bool) {
	var pairs []string
	if len(tokens) > 0 && tokens[0] == "export" {
		for _, t := range tokens[1:] {
			switch {
			case strings.HasPrefix(t, "-"):
			case isAssignment(t):
				pairs = append(pairs, t)
			case identRE.FindString(t) != t:
				return nil, false
			}
		}
	} else {
		if len(tokens) == 0 {
			return nil, false
		}
		for _, t := range tokens {
			if !isAssignment(t) {
				return nil, false
			}
		}
		pairs = tokens
	}
	names := []string{}
	for _, t := range pairs {
		name, raw, _ := strings.Cut(t, "=")
		names = append(names, name)
		val, ok := literalAssignmentValue(substituteVars(raw, varmap), false)
		if !ok || !persists || neverPropagate[name] {
			delete(varmap, name)
		} else {
			varmap[name] = val
		}
	}
	return names, true
}

// printfAssigns reports whether a printf invocation could assign: `-v NAME` is
// its only assigning form, and bash stops reading options at the first
// non-option word, so `printf "%s" "$f"` cannot assign however its arguments
// expand. Only the leading option region is scanned -- `--` ends it, `-v` and
// the glued `-vNAME` are the assigning form, and an option-region token still
// holding a `$` is unresolvable (unquoted, it word-splits into `-v NAME`), so
// it counts as one.
func printfAssigns(args []string) bool {
	for _, t := range args {
		if t == "--" {
			return false
		}
		if strings.HasPrefix(t, "-v") || strings.Contains(t, "$") {
			return true
		}
		if !strings.HasPrefix(t, "-") {
			return false
		}
	}
	return false
}

// ungluePrintfV strips a leading `-v` from a glued `printf -vNAME` argument, so
// the name behind it is where identRE can see it.
func ungluePrintfV(t string) string {
	if strings.HasPrefix(t, "-v") && t != "-v" {
		return t[2:]
	}
	return t
}

// poisonVars drops the entries a segment that is not an assignment might
// mutate. Called on the post-substitution tokens, so an expanded builtin name
// (`R=read; $R f`) is still recognised.
//
// `eval`, `source` and `.` can assign anything: the map dies. An arg-assigner
// builtin poisons every argument that could be a name, and an argument still
// holding a `$` names a variable this cannot identify, so the map dies there
// too (`read` and its kin also clobber their implicit result names). Any token
// shaped like a mutation poisons that name -- a `f=…` command prefix, `f+=…`,
// `f[0]=…`, `f++`, or an `f` followed by an `=…` token from a torn `(( f = x
// ))`. Poisoning only removes entries, so it can only leave an operand
// unresolved, never resolve one wrongly.
//
// The inline env prefix comes off before the dispatch, or it hides the
// command behind it: `LC_ALL=C read f` matched no rule upstream and left f at
// its stale literal (its Q69). The prefix names are still poisoned, because a
// special builtin under `set -o posix` keeps such an assignment.
//
// Generic over the value type because upstream runs it on both maps and this
// port has to as well: it only ever deletes keys, so what a map holds never
// reaches it.
func poisonVars[V any](tokens []string, varmap map[string]V) {
	if len(varmap) == 0 {
		return
	}
	kw := bash.StripShKeywords(tokens)
	rest := bash.StripEnvPrefix(kw)
	for _, t := range kw[:len(kw)-len(rest)] {
		name, _, _ := strings.Cut(t, "=")
		delete(varmap, name)
	}
	if len(rest) > 0 {
		name0 := filepath.Base(rest[0])
		if poisonAllCmds[name0] {
			clear(varmap)
			return
		}
		args := rest[1:]
		if argAssignerCmds[name0] && (name0 != "printf" || printfAssigns(args)) {
			for _, t := range args {
				if name0 == "printf" {
					t = ungluePrintfV(t)
				}
				if strings.Contains(t, "$") {
					clear(varmap)
					return
				}
				if m := identRE.FindString(t); m != "" {
					delete(varmap, m)
				}
			}
			for _, n := range []string{"REPLY", "MAPFILE", "OPTARG", "OPTIND"} {
				delete(varmap, n)
			}
			return
		}
	}
	for j, t := range tokens {
		if m := assignishRE.FindStringSubmatch(t); m != nil {
			delete(varmap, m[1])
		} else if identRE.FindString(t) == t && j+1 < len(tokens) && strings.HasPrefix(tokens[j+1], "=") {
			delete(varmap, t)
		}
	}
}

// clobbersIFS reports whether the segment may leave IFS holding a value this
// never saw. A changed IFS re-splits every later expansion, so a value checked
// here as one word can reach the command as several. applyAssignmentGroup
// catches the plain and `export` forms; this catches the rest -- the
// poison-all commands, which can set it invisibly, and the arg-assigner
// builtins whose arguments name it. The dispatch mirrors poisonVars so the two
// cannot disagree about what a segment assigns. `unset` is exempt: bash
// word-splits on the default IFS while IFS is unset, and the default is what
// this already models.
func clobbersIFS(tokens []string) bool {
	rest := bash.StripEnvPrefix(bash.StripShKeywords(tokens))
	if len(rest) == 0 {
		return false
	}
	name0 := filepath.Base(rest[0])
	if poisonAllCmds[name0] {
		return true
	}
	if name0 == "unset" || !argAssignerCmds[name0] {
		return false
	}
	args := rest[1:]
	if name0 == "printf" && !printfAssigns(args) {
		return false
	}
	for _, t := range args {
		if name0 == "printf" {
			t = ungluePrintfV(t)
		}
		if strings.Contains(t, "$") {
			return true
		}
		if identRE.FindString(t) == "IFS" {
			return true
		}
	}
	return false
}
