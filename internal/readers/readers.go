package readers

import (
	"path"
	"strings"
)

// Files returns the tokens of one simple command that name files it reads, and
// whether the command is one this package knows.
//
// A false second return is not an empty first: an unknown command may read
// anything, and treating "no spec" as "no operands" is the fail-open direction
// this project is built around refusing. The caller decides what to do about a
// command nobody has a table for; this only says it has none.
//
// The order is upstream's -- flag-named files first, then the positionals --
// because firstOutput indexes into the positional run and the two have to line
// up. specs with a firstOutput carry no fileFlags and prog 0, so for those the
// return is exactly the positional operands in order; TestOutputRowsHaveTheShapeFirstOutputAssumes
// pins that.
func Files(tokens []string) ([]string, bool) {
	if len(tokens) == 0 {
		return nil, false
	}
	s, ok := lookup(path.Base(tokens[0]))
	if !ok {
		return nil, false
	}

	files, seen, positionals := splitArgs(tokens, s)

	prog := s.prog
	for _, flag := range s.suppressProg {
		if seen[flag] {
			prog = 0
			break
		}
	}
	if prog > len(positionals) {
		prog = len(positionals)
	}
	operands := positionals[prog:]

	if s.skipAssignments {
		// awk takes `var=value` between file operands. Upstream splits on `/`
		// first so a path containing `=` below a directory is still a path.
		kept := operands[:0:0]
		for _, p := range operands {
			if !strings.Contains(strings.SplitN(p, "/", 2)[0], "=") {
				kept = append(kept, p)
			}
		}
		operands = kept
	}

	// Where the row says the command writes its trailing operands, they carry
	// nothing to the model and are not this package's business. `uniq IN OUT`
	// keeps IN.
	if s.firstOutput >= 0 && s.firstOutput < len(operands) {
		operands = operands[:s.firstOutput]
	}

	return append(files, operands...), true
}

// splitArgs walks one simple command's arguments against its spec, returning
// the files named by flags, the flags it saw, and the positionals.
//
// The three come back together because the caller needs to know where flag
// values ended before it can say which positionals are files, and deriving
// that twice is how the two answers stop agreeing.
func splitArgs(tokens []string, s spec) (files []string, seen map[string]bool, positionals []string) {
	seen = make(map[string]bool)
	endOpts := false
	for i := 1; i < len(tokens); {
		tok := tokens[i]
		if !endOpts && tok == "--" {
			endOpts = true
			i++
			continue
		}
		if !endOpts && strings.HasPrefix(tok, "-") && tok != "-" {
			key, inline, hasInline := splitEq(tok)
			seen[key] = true
			if ff, ok := s.fileFlags[key]; ok {
				if hasInline {
					// `--file=x`: the value is the flag's first token, so it
					// is a file only when index 0 is one.
					for _, at := range ff.files {
						if at == 0 {
							files = append(files, inline)
						}
					}
					i++
					continue
				}
				args := tokens[i+1:]
				if len(args) > ff.consumed {
					args = args[:ff.consumed]
				}
				for at, arg := range args {
					for _, want := range ff.files {
						if at == want {
							files = append(files, arg)
						}
					}
				}
				i += 1 + ff.consumed
				continue
			}
			if n, ok := s.consume[key]; ok {
				if hasInline {
					i++
				} else {
					i += 1 + n
				}
				continue
			}
			// An unknown flag is assumed to take no argument. Guessing the
			// other way would swallow the operand after it.
			i++
			continue
		}
		positionals = append(positionals, tok)
		i++
	}
	return files, seen, positionals
}

// splitEq turns `--opt=val` into its two halves. A short flag is not split:
// `-o=x` is `-o` with the value `=x` to most tools, and upstream splits only
// on the long form.
func splitEq(tok string) (key, value string, ok bool) {
	if strings.HasPrefix(tok, "--") {
		if k, v, found := strings.Cut(tok, "="); found {
			return k, v, true
		}
	}
	return tok, "", false
}
