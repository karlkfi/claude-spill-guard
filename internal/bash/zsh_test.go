package bash

import "testing"

func TestGluedParen(t *testing.T) {
	for text, want := range map[string]bool{
		"cat *(D)":           true,
		`cat *""(D)`:         true,
		"cat *.txt(P:.env:)": true,
		"cat x[1](.)":        true,
		// shlex groups `()` as one run, so a function definition is not a
		// glued `(`.
		"f() { cat *; }":            false,
		"cat *":                     false,
		"echo 'docs(queue): x'":     false,
		`echo "docs(queue): x"`:     false,
		"(cd sub && cat *)":         false,
		"a && (cat *)":              false,
		"if true; then (cat *); fi": false,
		"arr=(a b); cat *":          false,
		"arr+=(c); cat *":           false,
		"diff =(ls) b":              false,
		// `=(` is a process substitution only at the start of a word.
		"cat *=(D)":          true,
		"echo $(cat *)":      false,
		"diff <(cat a) b":    false,
		"echo 'unterminated": true,
	} {
		if got := GluedParen(text); got != want {
			t.Errorf("GluedParen(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestChangesZshOptions(t *testing.T) {
	for text, want := range map[string]bool{
		"setopt globdots; cat *":                   true,
		"builtin setopt globdots; cat *":           true,
		"function f { setopt globdots }; f; cat *": true,
		"'setopt' globdots; cat *":                 true,
		"options[globdots]=on; cat *":              true,
		"options+=(globdots on); cat *":            true,
		"options=(globdots on); cat *":             true,
		"unsetopt nomatch; cat *":                  true,
		"emulate ksh; cat *":                       true,
		"set -4; cat *":                            true,
		"set -o globdots; cat *":                   true,
		"cat *":                                    false,
		"grep -n options *.env":                    false,
		"echo 'run setopt later'; cat *":           false,
		"set -- a b; cat *":                        false,
		"git config --unset x; cat *":              false,
	} {
		if got := ChangesZshOptions(text); got != want {
			t.Errorf("ChangesZshOptions(%q) = %v, want %v", text, got, want)
		}
	}
}
