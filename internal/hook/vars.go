package hook

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/karlkfi/claude-spill-guard/internal/bash"
)

// The literal-variable propagation of bash-workspace-guard.py (its issue 58),
// ported function for function: literal_assignment_value, substitute_vars,
// apply_assignment_group, poison_vars, printf_assigns, unglue_printf_v and
// clobbers_ifs, with the constants they read. A `$NAME` in a reader's operand
// whose NAME the same command string assigned a literal is what bash and this
// hook can both read off the string; everything else keeps the `$`, and
// resolve records it as it did before.
//
// Fail-closed direction is the port's own. A value that is not a provable
// literal, an assignment that cannot persist, a builtin that might assign, a
// name bash treats specially -- each POISONS the name, which only ever restores
// the unresolved operand. Nothing here guesses.
//
// What is not ported, and why, is at each site: the Windows drive-prefix
// exemption (Q79's class), for-loop binding (a row of its own), and the stable
// subset the upstream recursion starts from (Q147).

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
	m         map[string]string
	propagate bool
}

func newVars() *vars { return &vars{m: map[string]string{}, propagate: true} }

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

// observe folds one segment into the map and reports whether it was
// assignments alone, which leaves no command for the caller to judge. raw is
// the segment's own tokens, which is what decides whether it is an assignment;
// sub is raw with the map substituted, which is what a builtin's arguments
// name. An IFS change stops propagation for the rest of the string: every
// later expansion is re-split by a value this never saw.
func (v *vars) observe(raw, sub []string, persists bool) (assignmentOnly bool) {
	if !v.propagate {
		return false
	}
	if names, ok := applyAssignmentGroup(raw, v.m, persists); ok {
		for _, name := range names {
			if name == "IFS" {
				v.stop()
			}
		}
		return true
	}
	if clobbersIFS(sub) {
		v.stop()
	} else {
		poisonVars(sub, v.m)
	}
	return false
}

func (v *vars) stop() {
	clear(v.m)
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
// Upstream exempts a Windows drive prefix from the `:` rule. Not here: nothing
// in this resolver reads a drive path, and Q79 is where that divergence lives.
func literalAssignmentValue(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		raw = expandTilde(raw)
	}
	if strings.HasPrefix(raw, "~") {
		return "", false
	}
	if strings.ContainsAny(raw, impureValueChars) {
		return "", false
	}
	return raw, true
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
		val, ok := literalAssignmentValue(substituteVars(raw, varmap))
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
func poisonVars(tokens []string, varmap map[string]string) {
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
