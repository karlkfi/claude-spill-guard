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
