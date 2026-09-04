package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The class, in both directions, and the second table is the one that took the
// measurement.
//
// A sweep of 24,381 Bash calls and 521 Read calls over the seven days to
// 2026-09-04 found 29 reads of a `.claude/settings*.json` and 0 of every other
// member. So the entries below `settings` are not an oversight to be tidied up
// later: they are what a week of real sessions read, none of it a credential,
// and a build that refuses them is the one guarded.go argues against.
var (
	guardedPaths = []string{
		"/w/app/.env",
		"/w/app/.env.local",
		"/w/app/.env.production",
		"/home/k/.aws/credentials",
		"/home/k/.netrc",
		"/home/k/_netrc",
		"/home/k/.git-credentials",
		"/home/k/.docker/config.json",
		"/home/k/.kube/config",
		"/w/app/kubeconfig",
		"/w/app/staging.kubeconfig",
	}
	openPaths = []string{
		// Measured: 29 of 29 reads of these in a week, not one a credential.
		"/home/k/.claude/settings.json",
		"/w/app/.claude/settings.local.json",
		// Committed to hold placeholders.
		"/w/app/.env.example",
		"/w/app/.env.sample",
		"/w/app/.env.template",
		"/w/app/.env.dist",
		// A suffix is a name somebody chose, not a convention.
		"/w/app/deploy.env",
		// Ordinary basenames that are only credentials under their own parent.
		"/w/app/credentials",
		"/w/app/config",
		"/w/app/config.json",
		"/w/app/notes.txt",
	}
)

func TestTheGuardedClassIsExactlyTheseNames(t *testing.T) {
	for _, path := range guardedPaths {
		if class := guardedClass(path); class == "" {
			t.Errorf("guardedClass(%q) = \"\", want a class -- this path is "+
				"credentials by convention and a read of it is refused", path)
		}
	}
	for _, path := range openPaths {
		if class := guardedClass(path); class != "" {
			t.Errorf("guardedClass(%q) = %q, want \"\" -- refusing this path "+
				"fires on a read somebody meant to make", path, class)
		}
	}
}

// dotenv writes a file in the class holding nothing any rule matches, so a
// block over it can only be the path.
func dotenv(t *testing.T) (dir, name string) {
	t.Helper()
	dir = t.TempDir()
	name = ".env"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("PORT=3000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, name
}

// The refusal, on both surfaces that open a file for themselves.
//
// The fixture holds `PORT=3000`, so nothing in it matches and the block cannot
// be a finding wearing a different hat. Before this the same call exited 0 in
// silence -- driven on a built binary against a fixture holding a real AWS
// secret access key, which no shipped rule matches either.
func TestAReadOfAGuardedPathIsRefusedOnItsShape(t *testing.T) {
	dir, name := dotenv(t)
	t.Run("Bash", func(t *testing.T) {
		code, stdout, stderr := drive(t, bashCall(t, "cat "+name, dir))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		reason := reasonOf(t, stdout)
		if !strings.Contains(reason, "a dotenv file") {
			t.Errorf("the reason does not name the class: %q", reason)
		}
	})
	t.Run("Read", func(t *testing.T) {
		code, stdout, stderr := drive(t,
			`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":`+
				quote(t, filepath.Join(dir, name))+`}}`)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		reason := reasonOf(t, stdout)
		if !strings.Contains(reason, "a dotenv file") {
			t.Errorf("the reason does not name the class: %q", reason)
		}
	})
}

// The bar this had to clear, and the reason it is a pipeline property rather
// than a check on the path alone. A filter with a stage after it sends the
// names, so refusing it would fire on the careful form -- which shape.go
// measures as worse than no rule at all.
func TestAFilteredReadOfAGuardedPathIsNotRefused(t *testing.T) {
	dir, name := dotenv(t)
	code, stdout, stderr := drive(t, bashCall(t, "cat "+name+" | cut -d= -f1", dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("the filtered form was not allowed: %q", stdout)
	}
}

// And what the careful form keeps, which the environment case has nothing to
// keep. `env | cut` leaves the values unexamined because there was never a
// buffer; a filtered read of a file still opens it and still matches every
// rule against it, so the filtered form trades away the shape deny and nothing
// else. verdict.go's reason recommends it on the strength of this.
func TestAFilteredReadIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("AWS_ACCESS_KEY_ID="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := drive(t, bashCall(t, "cat .env | cut -d= -f1", dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if reason := reasonOf(t, stdout); !strings.Contains(reason, "aws-access-key-id") {
		t.Errorf("the filtered form was not scanned: %q", reason)
	}
}

// The reason has to say how far this reaches, because a reader who takes it
// for path protection will trust it further than it goes: internal/readers
// keys on the command, so an interpreter opening the same path is not refused
// and never will be.
func TestTheReasonStatesWhatItDoesNotReach(t *testing.T) {
	dir, name := dotenv(t)
	_, stdout, _ := drive(t, bashCall(t, "cat "+name, dir))
	reason := reasonOf(t, stdout)
	for _, want := range []string{"interpreter", "net for the accident"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not say it stops at the readers it "+
				"knows (missing %q): %q", want, reason)
		}
	}
}

// An interpreter reading the same path, which is the cap stated above driven
// rather than asserted. It is a stated limitation and not a hole to widen
// into: Q87 drove the reader class and no new member landed.
func TestAnInterpreterReadingAGuardedPathIsNotReached(t *testing.T) {
	dir, name := dotenv(t)
	code, stdout, stderr := drive(t,
		bashCall(t, `python3 -c "print(open('`+name+`').read())"`, dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("an interpreter read was refused, so the cap the reason "+
			"states is no longer true: %q", stdout)
	}
}

// The class refuses reads and says nothing about writes. A write to one of
// these changes what some other tool does, which is not a spill and is not
// this tool's goal -- and picking up the write control on the way past is how
// a scanner turns into a permissions system nobody asked it to be.
func TestAWriteToAGuardedPathIsNotRefused(t *testing.T) {
	dir, name := dotenv(t)
	code, stdout, stderr := drive(t, bashCall(t, "echo PORT=3001 > "+name, dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("a write to a guarded path was refused: %q", stdout)
	}
}

// The hatch reaches it like every other block, which is what keeps a refusal
// with no way past it out of the tree. It downgrades to a confirmation rather
// than to an allow, so somebody is still told before the file leaves.
func TestAnOverrideDowngradesAGuardedPathRefusal(t *testing.T) {
	dir, name := dotenv(t)
	code, stdout, stderr := drive(t,
		bashCall(t, "SPILL_GUARD_OVERRIDE='reviewed, holds no credential' cat "+name, dir))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
	got := decision(t, stdout)
	out, ok := got["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("stdout carries no PreToolUse verdict: %q", stdout)
	}
	if out["permissionDecision"] != "ask" {
		t.Errorf("permissionDecision = %v, want ask", out["permissionDecision"])
	}
}
