package main

import (
	"strings"
	"testing"
)

// The three shapes a regex reads wrong, and the direction each fails in. The
// first two are what a `uses:` pattern over raw lines invents; the third is
// what a `^  ([A-Za-z0-9_-]+):$` job pattern silently drops, which is the
// failure that lets a gate leave CI while the drift check stays green.
func TestScanOneIgnoresUsesThatIsNotAKey(t *testing.T) {
	const src = `
# uses: actions/evil@v1
on: push
jobs:
  real:
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - name: a comment and a block scalar both spell it
        run: |
          # uses: actions/evil@v1
          echo "uses: actions/evil@v1"
`
	f, err := scanOne("t.yml", []byte(src))
	if err != nil {
		t.Fatalf("scanOne: %v", err)
	}
	if len(f.Uses) != 1 {
		t.Fatalf("uses = %d, want 1: %+v", len(f.Uses), f.Uses)
	}
	if f.Uses[0].Value != "actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("value = %q", f.Uses[0].Value)
	}
	if f.Uses[0].Path != "jobs.real.steps[0].uses" {
		t.Errorf("path = %q", f.Uses[0].Path)
	}
}

func TestScanOneSeesJobNamesARegexWouldMiss(t *testing.T) {
	const src = `
on: push
jobs:
  "quoted-job":
    steps:
      - run: "true"
  plain:
    steps:
      - run: "true"
`
	f, err := scanOne("t.yml", []byte(src))
	if err != nil {
		t.Fatalf("scanOne: %v", err)
	}
	want := []string{"quoted-job", "plain"}
	if len(f.Jobs) != len(want) {
		t.Fatalf("jobs = %v, want %v", f.Jobs, want)
	}
	for i := range want {
		if f.Jobs[i].Name != want[i] {
			t.Errorf("jobs[%d] = %q, want %q", i, f.Jobs[i].Name, want[i])
		}
	}
}

// Every failure is fatal by design: a parse that returns a short list is the
// defect this replaces, so each of these must be an error and not an empty
// result that reads like a clean file.
func TestScanOneRefusesRatherThanReturningNothing(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"empty file", "", "no YAML document"},
		{"no jobs key", "on: push\n", "no `jobs:` key"},
		{"jobs is not a mapping", "jobs: []\n", "not a mapping"},
		{"jobs names none", "jobs: {}\n", "names no jobs"},
		{"top level is a list", "- a\n", "top level is not a mapping"},
		{
			"uses is not a scalar",
			"jobs:\n  a:\n    steps:\n      - uses:\n          - x\n",
			"is not a scalar",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scanOne("t.yml", []byte(tc.src))
			if err == nil {
				t.Fatalf("scanOne returned no error; want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// An anchored step reached through an alias is a step. Following the alias is
// what keeps it checkable; skipping it would drop a real `uses:` from the list
// the pin gate reads, which is the silent direction again.
func TestScanOneFollowsAliases(t *testing.T) {
	const src = `
on: push
jobs:
  a:
    steps:
      - &checkout
        uses: actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  b:
    steps:
      - *checkout
`
	f, err := scanOne("t.yml", []byte(src))
	if err != nil {
		t.Fatalf("scanOne: %v", err)
	}
	if len(f.Uses) != 2 {
		t.Fatalf("uses = %d, want 2: %+v", len(f.Uses), f.Uses)
	}
	if f.Uses[1].Path != "jobs.b.steps[0].uses" {
		t.Errorf("aliased path = %q", f.Uses[1].Path)
	}
}

// The drift check reads these to assert a gate's job invokes `make <gate>`.
// A block scalar is one run, however many lines it spans, and a `run:` under a
// step is reached the same as one under the job.
func TestScanOneCollectsRunsPerJob(t *testing.T) {
	const src = `
on: push
jobs:
  a:
    steps:
      - run: make docs
      - run: |
          echo one
          echo two
  b:
    steps:
      - uses: actions/checkout@cccccccccccccccccccccccccccccccccccccccc
`
	f, err := scanOne("t.yml", []byte(src))
	if err != nil {
		t.Fatalf("scanOne: %v", err)
	}
	if len(f.Jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(f.Jobs))
	}
	if len(f.Jobs[0].Runs) != 2 {
		t.Errorf("a.runs = %q, want 2 entries", f.Jobs[0].Runs)
	}
	if f.Jobs[0].Runs[0] != "make docs" {
		t.Errorf("a.runs[0] = %q", f.Jobs[0].Runs[0])
	}
	if len(f.Jobs[1].Runs) != 0 {
		t.Errorf("b.runs = %q, want none", f.Jobs[1].Runs)
	}
}

func labels(legs []leg) []string {
	out := make([]string, 0, len(legs))
	for _, l := range legs {
		var vals []string
		for _, p := range l {
			vals = append(vals, p.Key+"="+p.Value)
		}
		out = append(out, strings.Join(vals, ","))
	}
	return out
}

func legsOf(t *testing.T, src string) []leg {
	t.Helper()
	f, err := scanOne("t.yml", []byte(src))
	if err != nil {
		t.Fatalf("scanOne: %v", err)
	}
	return f.Jobs[0].Legs
}

func assertLegs(t *testing.T, got []leg, want []string) {
	t.Helper()
	g := labels(got)
	if strings.Join(g, " | ") != strings.Join(want, " | ") {
		t.Errorf("legs =\n  %s\nwant\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

// A job with no matrix has no legs, which is not the same answer as a matrix
// of one: the drift check tells the two apart.
func TestScanOneGivesAJobWithNoMatrixNoLegs(t *testing.T) {
	got := legsOf(t, "jobs:\n  a:\n    strategy:\n      fail-fast: false\n    steps:\n      - run: \"true\"\n")
	if got != nil {
		t.Errorf("legs = %v, want nil", labels(got))
	}
}

// The two shapes this repository's workflows use, with the check run names a
// pull request posted for them: `install-dry-run (macos-latest)` and
// `install-dry-run-mutation-control (windows-latest, install/install.ps1)`.
// The second is the case that holds include to original combinations only: an
// entry appended by include is not one, or the second entry would merge into
// the first and leave one leg.
func TestScanOneExpandsTheShapesThisRepositoryUses(t *testing.T) {
	assertLegs(t, legsOf(t, `
jobs:
  install-dry-run:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
`), []string{"os=ubuntu-latest", "os=macos-latest", "os=windows-latest"})

	assertLegs(t, legsOf(t, `
jobs:
  install-dry-run-mutation-control:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            script: install/install.sh
          - os: windows-latest
            script: install/install.ps1
`), []string{"os=ubuntu-latest,script=install/install.sh", "os=windows-latest,script=install/install.ps1"})
}

// GitHub's own worked examples, with the combinations its documentation says
// they produce: an include entry added everywhere, one overwriting a value an
// earlier include added, one extending a subset, and two that fit no original
// combination; then an exclude matching on every key and one matching on two.
func TestScanOneExpandsGitHubsDocumentedExamples(t *testing.T) {
	assertLegs(t, legsOf(t, `
jobs:
  a:
    strategy:
      matrix:
        fruit: [apple, pear]
        animal: [cat, dog]
        include:
          - color: green
          - color: pink
            animal: cat
          - fruit: apple
            shape: circle
          - fruit: banana
          - fruit: banana
            animal: cat
`), []string{
		"fruit=apple,animal=cat,color=pink,shape=circle",
		"fruit=apple,animal=dog,color=green,shape=circle",
		"fruit=pear,animal=cat,color=pink",
		"fruit=pear,animal=dog,color=green",
		"fruit=banana",
		"fruit=banana,animal=cat",
	})

	got := legsOf(t, `
jobs:
  a:
    strategy:
      matrix:
        os: [macos-latest, windows-latest]
        version: [12, 14, 16]
        environment: [staging, production]
        exclude:
          - os: macos-latest
            version: 12
            environment: production
          - os: windows-latest
            version: 16
`)
	if len(got) != 9 {
		t.Fatalf("legs = %d, want the nine the documentation names: %v", len(got), labels(got))
	}
	for _, l := range labels(got) {
		if l == "os=macos-latest,version=12,environment=production" ||
			strings.HasPrefix(l, "os=windows-latest,version=16,") {
			t.Errorf("an excluded combination survived: %s", l)
		}
	}
}

// Each of these has legs only a run could name. Reporting no legs instead
// would read as a job that runs once, which is the silent direction.
func TestScanOneRefusesAMatrixItCannotExpand(t *testing.T) {
	for _, tc := range []struct{ name, matrix, want string }{
		{"expression matrix", "matrix: ${{ fromJSON(needs.a.outputs.m) }}", "is not a mapping"},
		{"expression list", "matrix:\n        os: ${{ fromJSON(needs.a.outputs.os) }}", "is not a non-empty list"},
		{"expression value", "matrix:\n        os: [\"${{ inputs.os }}\"]", "is an expression"},
		{"empty list", "matrix:\n        os: []", "is not a non-empty list"},
		{"object value", "matrix:\n        os: [{name: a}]", "is not a scalar"},
		{"exclude of an unknown key", "matrix:\n        os: [a]\n        exclude:\n          - arch: x", "does not"},
		{"include that is not a list", "matrix:\n        include: {os: a}", "is not a list"},
		{"excluded down to nothing", "matrix:\n        os: [a]\n        exclude:\n          - os: a", "expands to no legs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "jobs:\n  a:\n    strategy:\n      " + tc.matrix + "\n"
			_, err := scanOne("t.yml", []byte(src))
			if err == nil {
				t.Fatalf("scanOne returned no error; want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
