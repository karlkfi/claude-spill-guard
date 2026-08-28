package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// oracleCase is one row of testdata/prompt-oracle.json. Everything but the
// declared divergence was read out of a transcript rather than written: the
// prompt as the harness received it, and the `filename` of every attachment
// whose `attachment.type` is `file`.
type oracleCase struct {
	Name         string   `json:"name"`
	Prompt       string   `json:"prompt"`
	HarnessFiles []string `json:"harness_files"`
	// The two declared divergences. Both are this side's claims rather than
	// the harness's, and a case leaving them empty asserts exact agreement.
	AlsoScans   []string `json:"resolver_also_scans"`
	AlsoSplices []string `json:"harness_also_splices"`
	Why         string   `json:"why"`
	Note        string   `json:"note"`
}

// The harness resolves an `@` token itself and records the path it landed on,
// so it is an oracle for atTokens and resolveAt together -- and the point of
// keeping the census in a fixture is that the comparison runs on every `go
// test` rather than being taken once by hand and agreed with.
//
// Read what this can and cannot see before trusting a green run. It compares
// the SET of paths, so it says nothing about what is scanned inside one: the
// harness truncated a 5,001-line file to 2,000 lines and this resolver reads
// the whole of it, and both sides still name big.txt. And its subject is
// `attachment.type == "file"`. A raw count of `"type":"attachment"` looks like
// it would do, and separates a blocked turn from an allowed one perfectly,
// which is what lets it survive a spot-check -- but it carries skill listings,
// token reminders, deferred-tool deltas and hook records too, so it answers a
// different question from whether a file crossed. Over the eighteen transcripts behind
// this fixture it ranged 5 to 9, and the ten arms that spliced nothing at all
// still returned 5 or 6 -- so a threshold calibrated on those numbers is
// wrong on the next run, and this compares identities instead.
func TestThePromptResolverAgreesWithTheHarnessOracle(t *testing.T) {
	cases := loadOracle(t)
	root, home := oracleTree(t)

	// The subject has to exist for the agreement to mean anything: a loader
	// that returned no cases, or cases in which the harness spliced nothing,
	// passes every assertion below while testing none of them.
	spliced := 0
	for _, c := range cases {
		spliced += len(c.HarnessFiles)
	}
	if len(cases) < 10 || spliced < 10 {
		t.Fatalf("the oracle carries %d cases and %d spliced files, which is too "+
			"few for agreement to mean anything", len(cases), spliced)
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			prompt := strings.ReplaceAll(c.Prompt, "{{root}}", root)
			got, err := promptTargets(prompt, root)
			if err != nil {
				t.Fatalf("promptTargets: %v", err)
			}
			resolved := relativeTo(t, root, home, got)
			harness := dedup(c.HarnessFiles)

			// Two-sided, and the sides are not worth the same. A path the
			// harness spliced and this did not is a file that reaches the
			// model with nothing having read it, which is the failure this
			// whole package exists to refuse. The other way round is a file
			// scanned that did not have to be.
			if missed := difference(harness, resolved); !equal(missed, c.AlsoSplices) {
				t.Errorf("the harness splices %v that this does not scan, want %v\n"+
					"  harness:  %v\n  resolver: %v",
					missed, c.AlsoSplices, harness, resolved)
			}
			if extra := difference(resolved, harness); !equal(extra, c.AlsoScans) {
				t.Errorf("this scans %v the harness did not splice, want %v (%s)\n"+
					"  harness:  %v\n  resolver: %v",
					extra, c.AlsoScans, c.Why, harness, resolved)
			}
		})
	}
}

// A prompt naming a file this cannot identify blocks, for the reason an
// unresolvable Bash operand does: skipping one reports a clean result for
// content nothing opened, and the token is spliced whatever this decided.
func TestAPromptNamingAFileThisCannotIdentifyBlocks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"a relative token with no cwd to resolve against",
			`{"hook_event_name":"UserPromptSubmit","prompt":"look at @deploy.env"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := drive(t, tc.payload)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, stderr)
			}
			if !strings.Contains(reasonOf(t, stdout), "scan could not be completed") {
				t.Errorf("reason = %q, want it to say the scan did not finish",
					reasonOf(t, stdout))
			}
		})
	}
}

// The `~` prefixes, and the one measurement that decided between blocking a
// `~user` token and passing it through as literal text.
//
// Driven 2026-08-28 against 2.1.238: `@~<the running user>/.zshrc` spliced
// nothing on a run where `@~/.zshrc` in the same prompt spliced that exact
// file, and the harness does not dedup -- the oracle's positives case has two
// records for one path -- so one record there is one splice. `@~` bare
// produced no attachment of any type, not even the directory listing a
// resolved home would have given.
//
// Blocking on `~user` was what this package did until that ran, and it made
// any prompt writing `@~` followed by a name a blocked prompt, for a token
// that carries nothing to the model.
func TestOnlyTheHomePrefixTheHarnessExpandsIsExpanded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := t.TempDir()
	for _, tc := range []struct{ candidate, want string }{
		{"~/deploy.env", filepath.Join(home, "deploy.env")},
		{"~alice/deploy.env", filepath.Join(cwd, "~alice/deploy.env")},
		{"~", filepath.Join(cwd, "~")},
	} {
		got, err := resolveAt(tc.candidate, cwd)
		if err != nil {
			t.Errorf("resolveAt(%q): %v", tc.candidate, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveAt(%q) = %q, want %q", tc.candidate, got, tc.want)
		}
	}
}

// os.ReadFile on a fifo blocks until something writes, which would hang the
// session rather than scan anything, so anything that is not a regular file or
// a directory refuses instead of being opened. /dev/null stands in for the
// class because it needs no mknod: it is a character device on every unix.
func TestAPromptNamingSomethingThatIsNotAFileBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null to stand in for the class")
	}
	code, stdout, stderr := drive(t, `{"hook_event_name":"UserPromptSubmit",`+
		`"cwd":"/tmp","prompt":"read @/dev/null please"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 with a decision object (stderr %q)", code, stderr)
	}
	if !strings.Contains(reasonOf(t, stdout), "neither a file nor a directory") {
		t.Errorf("reason = %q, want it to name what it declined to open", reasonOf(t, stdout))
	}
}

// The end-to-end shape the row is about: the token is in the prompt, the
// secret is in the file, and nothing but this hook is between them and the
// API. Its second job is to be the positive control for
// TestNoPromptRefusalCarriesTheToken -- without it every case there could pass
// against a reason-reader that had stopped seeing values.
func TestASplicedFileIsScannedByOpeningIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.env")
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, `{"hook_event_name":"UserPromptSubmit","cwd":`+
		quote(t, dir)+`,"prompt":"summarise @deploy.env for me"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	reason := reasonOf(t, stdout)
	if !strings.Contains(reason, "aws-access-key-id") {
		t.Errorf("reason does not name the rule: %q", reason)
	}
	if !strings.Contains(reason, path) {
		t.Errorf("reason does not name the file: %q", reason)
	}
	if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
		t.Errorf("the verdict carries the value:\nstdout %q\nstderr %q", stdout, stderr)
	}
}

// A directory token splices the names one level down and no file content, so
// the names are the crossing and a name is where the secret has to be for this
// to fail. The fixture is the value in a filename rather than in a file.
func TestADirectoryTokenScansTheNamesThatCross(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "keys")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, secret+".pem"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, `{"hook_event_name":"UserPromptSubmit","cwd":`+
		quote(t, dir)+`,"prompt":"what is in @keys"}`)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(reasonOf(t, stdout), "aws-access-key-id") {
		t.Errorf("reason = %q, want the rule the filename matches", reasonOf(t, stdout))
	}
	if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
		t.Errorf("the verdict carries the value:\nstdout %q\nstderr %q", stdout, stderr)
	}
}

// Every refusal above is a token this never resolved, so nothing of the prompt
// has been scanned when the reason is written -- and the reason reaches the
// API. Its positive control is TestASplicedFileIsScannedByOpeningIt, which
// asserts a reason DOES carry a path where the design allows one.
func TestNoPromptRefusalCarriesTheToken(t *testing.T) {
	// A symlink named for the secret, pointing at a character device, so the
	// token that reaches the "neither a file nor a directory" refusal is one
	// that would leak if that reason quoted what it declined to open.
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Symlink("/dev/null", filepath.Join(dir, secret)); err != nil {
			t.Fatal(err)
		}
	}
	// A directory nothing can traverse, so the token below reaches the read
	// failure rather than the not-there skip. Its own name is unremarkable and
	// the secret is the leaf, which is where an OS error would carry it.
	shut := filepath.Join(dir, "shut")
	if err := os.Mkdir(shut, 0o000); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, payload string }{
		{"a relative token with no cwd",
			`{"hook_event_name":"UserPromptSubmit","prompt":"see @` + secret + `/x"}`},
		{"a token naming something that is not a file",
			`{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
				`,"prompt":"see @` + secret + `"}`},
		{"a token this cannot read",
			`{"hook_event_name":"UserPromptSubmit","cwd":` + quote(t, dir) +
				`,"prompt":"see @shut/` + secret + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(tc.name, "not a file") {
				t.Skip("no /dev/null to point a symlink at")
			}
			// Root traverses a 0o000 directory, so the read succeeds, the path
			// is simply absent, and the call is allowed -- which is not this
			// case failing but this case never running.
			if strings.Contains(tc.name, "cannot read") && os.Geteuid() == 0 {
				t.Skip("running as root, so the unreadable directory is readable")
			}
			code, stdout, stderr := drive(t, tc.payload)
			if code == 0 && stdout == "" {
				t.Fatalf("the prompt was allowed, so this asserts nothing about a refusal")
			}
			if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
				t.Errorf("a refusal carries the token:\nstdout %q\nstderr %q", stdout, stderr)
			}
		})
	}
}

// The cost of getting the token grammar wrong in the other direction. An
// address and a decorator are `@` in a prompt and neither splices anything, so
// treating either as a token would block ordinary prompts -- and one that
// blocked on a name it could not resolve would block them loudly.
func TestAnAtThatIsNotATokenIsNotJudged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deploy.env"),
		[]byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, prompt := range []string{
		"mail it to someone@deploy.env when you are done",
		"why does the `@deploy.env` in the docs not work",
		"the @property decorator, and @~nobody, and a bare @ sign",
	} {
		code, stdout, stderr := drive(t, `{"hook_event_name":"UserPromptSubmit","cwd":`+
			quote(t, dir)+`,"prompt":`+quote(t, prompt)+`}`)
		if code != 0 || stdout != "" {
			t.Errorf("prompt %q: exit %d, stdout %q, want a silent 0 (stderr %q)",
				prompt, code, stdout, stderr)
		}
	}
}

// loadOracle reads the fixture, failing rather than skipping if it is gone --
// a suite that quietly stops comparing against the harness reads exactly like
// one that agrees with it.
func loadOracle(t *testing.T) []oracleCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "prompt-oracle.json"))
	if err != nil {
		t.Fatalf("the harness census is not readable, so nothing here compares "+
			"against it: %v", err)
	}
	var cases []oracleCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("the harness census does not decode: %v", err)
	}
	return cases
}

// oracleTree rebuilds the directory the probes ran in, and a home directory to
// resolve the one home-relative case against. The root is named `probe`
// because a case reaches out of it and back in by name.
func oracleTree(t *testing.T) (root, home string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "probe")
	home = filepath.Join(base, "home")
	for _, dir := range []string{root, home, filepath.Join(root, "nested", "deep")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{
		filepath.Join(root, "secret.txt"):                 "MARKER_ALPHA\n",
		filepath.Join(root, "plain"):                      "MARKER_EPS\n",
		filepath.Join(root, "big.txt"):                    "MARKER_OMEGA\n",
		filepath.Join(root, "with space.txt"):             "MARKER_DELTA\n",
		filepath.Join(root, "nested", "inner.txt"):        "MARKER_BETA\n",
		filepath.Join(root, "nested", "deep", "deep.txt"): "MARKER_GAMMA\n",
		filepath.Join(home, ".zshrc"):                     "export PATH=$PATH\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// resolveAt reads the home directory through os.UserHomeDir, which is
	// $HOME here, so the recorded ~/ case resolves without naming the machine
	// the probe ran on.
	t.Setenv("HOME", home)
	return root, home
}

// relativeTo maps the paths a run resolved back into the spelling the fixture
// records, so a failure names `nested/inner.txt` rather than a temp path. The
// prompt buffer itself is not a path and is dropped.
func relativeTo(t *testing.T, root, home string, got []target) []string {
	t.Helper()
	var out []string
	for _, target := range got {
		switch {
		case target.label == promptLabel:
		case strings.HasPrefix(target.label, root+string(filepath.Separator)):
			out = append(out, filepath.ToSlash(target.label[len(root)+1:]))
		case strings.HasPrefix(target.label, home+string(filepath.Separator)):
			out = append(out, "~/"+filepath.ToSlash(target.label[len(home)+1:]))
		default:
			t.Errorf("a target resolved outside the fixture tree: %q", target.label)
		}
	}
	return dedup(out)
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// difference is the members of a that b does not carry, sorted.
func difference(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	out := []string{}
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	b = dedup(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
