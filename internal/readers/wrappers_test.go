package readers

import (
	"reflect"
	"strings"
	"testing"
)

// What each wrapper runs, read through its own options. A value missed leaves
// it standing as the command word (`sudo -u root cat`), and a value invented
// swallows the command (`env -i cat`); either way the reader is hidden again.
// The rows are upstream's cases where it has them, driven on bash 5.3.15 for
// the wrappers this machine has.
func TestPeelWrappers(t *testing.T) {
	f := strings.Fields
	for _, tc := range []struct {
		in     []string
		argv   string
		opaque bool
	}{
		{f("cat f"), "cat f", false},
		{f("command cat f"), "cat f", false},
		{f("command -p cat f"), "cat f", false},
		{f("exec cat f"), "cat f", false},
		{f("exec -a name cat f"), "cat f", false},
		{f("exec -cl cat f"), "cat f", false},
		{f("nice cat f"), "cat f", false},
		{f("nice -n 5 cat f"), "cat f", false},
		{f("nice -n5 cat f"), "cat f", false},
		{f("nice --adjustment=5 cat f"), "cat f", false},
		{f("nice --adj 5 cat f"), "cat f", false}, // a unique prefix, as getopt_long takes
		{f("nice -5 cat f"), "cat f", false},
		{f("nice --5 cat f"), "cat f", false},
		{f("nohup cat f"), "cat f", false},
		{f("env cat f"), "cat f", false},
		{f("env -i cat f"), "cat f", false},
		{f("env - cat f"), "cat f", false},
		{f("env A=1 B=2 cat f"), "cat f", false},
		{f("env -u HOME cat f"), "cat f", false},
		{[]string{"env", "-S", "cat f"}, "cat f", false},
		{f("timeout 5 cat f"), "cat f", false},
		{f("timeout -s KILL 5 cat f"), "cat f", false},
		{f("timeout --signal=KILL -k 2 5 cat f"), "cat f", false},
		{f("stdbuf -oL cat f"), "cat f", false},
		{f("stdbuf -o L cat f"), "cat f", false},
		{f("sudo cat f"), "cat f", false},
		{f("sudo -u root cat f"), "cat f", false},
		{f("sudo -uroot -E cat f"), "cat f", false},
		{f("sudo A=1 cat f"), "cat f", false},
		{f("sudo -- cat f"), "cat f", false},
		{f("time -p cat f"), "cat f", false},
		{f("/usr/bin/time -o out cat f"), "cat f", false},
		{f("ionice -c 3 -n7 cat f"), "cat f", false},
		{f("setsid -fw cat f"), "cat f", false},
		{f("chrt -r 5 cat f"), "cat f", false},
		{f("taskset -c 0 cat f"), "cat f", false},
		{f("caffeinate -i cat f"), "cat f", false},
		{f("unbuffer -p cat f"), "cat f", false},
		{f("doas -u root cat f"), "cat f", false},
		{f("builtin cat f"), "cat f", false},
		{f("nice nohup env A=1 timeout 5 cat f"), "cat f", false},
		{f("flock lock cat f"), "cat f", false},
		{[]string{"flock", "lock", "-c", "cat f"}, "sh -c cat f", false},

		// Runs nothing: the operands are names, ids, or files to edit.
		{f("command -v cat f"), "", false},
		{f("command -V cat f"), "", false},
		{f("ionice -p 123"), "", false},
		{f("sudo -l cat f"), "", false},
		{f("sudo -e f"), "", false},
		{f("env --help"), "", false},
		{f("nice"), "", false},
		{f("timeout 5"), "", false},
		{f("flock 9"), "", false},

		// Its operands are not all on the line.
		{f("xargs cat"), "cat", true},
		{f("xargs -0 -n1 cat f"), "cat f", true},
		{f("xargs -I{} cat {}"), "cat {}", true},

		// Grammar lost: an option off the row, or a word the shell rewrites.
		// The command is taken from the first later word naming a reader.
		{f("env -X cat f"), "cat f", true},
		{f("nice -n $N cat f"), "cat f", true},
		{f("nice $FLAGS cat f"), "cat f", true},
		{f("sudo -R /root cat f"), "cat f", true},
		{f("env $A cat f"), "cat f", true},
		{[]string{"env", "-S", `cat "f"`}, `cat "f"`, true},
		{f("env --bogus"), "", true},
	} {
		t.Run(strings.Join(tc.in, " "), func(t *testing.T) {
			p := PeelWrappers(tc.in)
			if got := strings.Join(p.Argv, " "); got != tc.argv {
				t.Errorf("Argv = %q, want %q", got, tc.argv)
			}
			if p.Opaque != tc.opaque {
				t.Errorf("Opaque = %v, want %v", p.Opaque, tc.opaque)
			}
		})
	}
}

// Only `command` and `builtin` run the shell's own cd; everything else is a
// separate program, and a cd it runs moves nothing in the shell.
func TestAWrapperSaysWhetherItIsTheShell(t *testing.T) {
	for in, external := range map[string]bool{
		"command cd sub": false,
		"builtin cd sub": false,
		"env cd sub":     true,
		"nice cd sub":    true,
	} {
		if got := PeelWrappers(strings.Fields(in)).External; got != external {
			t.Errorf("%s: External = %v, want %v", in, got, external)
		}
	}
	for in, want := range map[string]bool{
		"builtin cat f":         true,
		"command builtin cat f": true,
		"builtin command cat f": false,
		"builtin exec cat f":    false,
	} {
		if got := PeelWrappers(strings.Fields(in)).Builtin; got != want {
			t.Errorf("%s: Builtin = %v, want %v", in, got, want)
		}
	}
}

// `env -C` and `sudo -D` move the command; `sudo -i` moves it somewhere this
// cannot know, which is the empty entry.
func TestAWrapperSaysWhereItRunsTheCommand(t *testing.T) {
	for in, want := range map[string][]string{
		"env -C sub cat f":        {"sub"},
		"env --chdir=sub cat f":   {"sub"},
		"sudo -D /srv cat f":      {"/srv"},
		"sudo -i cat f":           {""},
		"env -X cat f":            {""}, // it may have been a -C
		"env -C a env -C b cat f": {"a", "b"},
		"nice cat f":              nil,
	} {
		if got := PeelWrappers(strings.Fields(in)).Chdirs; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Chdirs = %q, want %q", in, got, want)
		}
	}
}

// Every wrapper upstream peels has a row here, and nothing else does. The list
// is upstream's WRAPPER_GRAMMAR keys at 784fc36.
func TestTheWrapperTableIsUpstreams(t *testing.T) {
	want := strings.Fields("env sudo nice nohup timeout stdbuf setsid ionice chrt " +
		"taskset doas caffeinate flock unbuffer time xargs command builtin exec")
	if len(wrappers) != len(want) {
		t.Errorf("%d wrappers, want %d", len(wrappers), len(want))
	}
	for _, name := range want {
		if _, ok := wrappers[name]; !ok {
			t.Errorf("no row for %s", name)
		}
	}
}
