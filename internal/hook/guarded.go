package hook

import (
	"fmt"
	"path/filepath"
	"strings"
)

// A second class of call refused on its shape, and its argument is not the
// environment's.
//
// shape.go refuses `env` because there is nothing anywhere to open: the values
// live in the tool process and no rule could ever reach them. These paths are
// files. The reader table resolves them, the pipeline opens them, and a value
// in one that matches a shipped rule blocks today with no help from here. So
// this is a smaller claim, and stating it exactly is most of the work: what a
// path refusal adds is the values the ruleset does *not* recognise.
//
// # The gap is measured, not assumed
//
// Driven 2026-09-04 on a binary built from 21f15a6, against a fixture holding
// the `aws-secret-access-key` vector from testdata/corpus/vectors:
//
//	the call                              | today
//	cat matches.env      (an AWS key id)  | blocked, "aws-access-key-id"
//	cat unmatched.env    (a password)     | exit 0, silent
//	cat .aws/credentials (an AWS secret)  | exit 0, silent
//	Read unmatched.env                    | exit 0, silent
//
// The shipped set is 14 high-precision shapes and none of them matches an AWS
// *secret* access key, a netrc password, a base64 registry auth or a
// kubeconfig's client-key-data. Those are the contents of this class, so a
// clean scan of one of these files is a report about the four rules that could
// have fired and not about the file.
//
// # What is in the class, and what is deliberately out
//
// Paths whose contents are credentials by convention, which is why membership
// can be read off the name. `.claude/settings.json` is the member the row that
// filed this named first, and it is out -- measured, below. The `.env.example`
// spelling is out too: that file exists to be committed and to hold
// placeholders. That one is reasoned from the convention rather than measured,
// because the sweep found no `.env` read of any spelling to measure.
//
// `deploy.env` and the rest of the `*.env` family are out. The class is paths
// that are credentials by convention; a suffix is a name somebody chose, and
// widening to it means taking a position on every `example.env` and `test.env`
// in every fixture directory. Under-firing on a spelling is the same trade
// shape.go takes for `env -0`.
//
// # Why `.claude/settings.json` is not here
//
// It was the row's first-named member and it is the one the measurement threw
// out. Swept over 24,381 Bash calls and 521 Read calls in 238 transcript files
// on this machine, the seven days to 2026-09-04, driving internal/bash and
// internal/readers over the real command strings: 29 calls resolve a reader
// operand or a Read path to a `.claude/settings.json` or
// `.claude/settings.local.json`. Not one of them reads a credential. 26 are
// `cat` of the file the session had just written one line into --
// `printf '{"env":{"CLAUDE_CODE_EFFORT_LEVEL":"high"}}' > .claude/settings.local.json
// && cat .claude/settings.local.json` -- which is a worker session confirming
// its own write landed.
//
// So the rule the row proposed would fire 29 times a week, every one of them
// on somebody checking their own config, and most of them on the read-back
// half of a write-then-verify. That is the shape shape.go calls worse than no
// rule: a guard that fires on the careful form teaches the session to stop
// being careful, and here the careful form is verifying a write.
//
// The rest of the class went the other way. Over the same sweep, 0 calls
// resolve to a `.env`, an `~/.aws/credentials`, a `.netrc`, a
// `.git-credentials`, a `~/.docker/config.json` or a kubeconfig. Twelve
// planted calls appended to the same corpus fire 12 times, so the zero is a
// measurement and not a sweep that cannot come back non-empty.
//
// # It refuses the readers it knows, and that is the whole of its reach
//
// Membership is decided on a path internal/readers already resolved, so this
// inherits that table's cap: `python3 -c "print(open('~/.aws/credentials').read())"`
// names no operand this package can see and is not refused. Q87 drove the
// reader class and no new member landed, so the table is not about to grow
// into the hole. The reason says so, because a reader who takes this for a
// guarantee that the path is protected will trust it further than it goes.

// A pathRefusal is a read of a path whose contents are credentials by
// convention, refused before anything opened it.
//
// It travels as an error for shapeRefusal's reason and is separated from a
// failed scan the same way -- failed() says nothing scanned this call, which
// is true here and is not why the call stopped.
type pathRefusal struct{ path, class string }

func (r *pathRefusal) Error() string {
	return fmt.Sprintf("%q is %s, which this refuses to read on its shape", r.path, r.class)
}

func (r *pathRefusal) body() string { return guarded(r.path, r.class) }

// The spellings of a dotenv file that exist to be committed. A closed set of
// four, because every entry is a claim that a file named this way holds
// placeholders, and that is a convention rather than a rule anything enforces.
var dotenvTemplates = map[string]bool{
	".env.example":  true,
	".env.sample":   true,
	".env.template": true,
	".env.dist":     true,
}

// guardedClass names the class this path belongs to, in the words a reason
// uses, or "" for a path outside it.
//
// The parent directory is read for three of them because the basename alone is
// ordinary: `config` and `credentials` and `config.json` are names anything
// might have, and it is `.aws/credentials` rather than `credentials` that is
// credentials by convention.
func guardedClass(path string) string {
	base := filepath.Base(path)
	dir := filepath.Base(filepath.Dir(path))
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		if dotenvTemplates[base] {
			return ""
		}
		return "a dotenv file"
	case dir == ".aws" && base == "credentials":
		return "an AWS credentials file"
	case base == ".netrc" || base == "_netrc":
		return "a netrc file"
	case base == ".git-credentials":
		return "a git credential store"
	case dir == ".docker" && base == "config.json":
		return "a Docker registry auth file"
	case dir == ".kube" && base == "config",
		base == "kubeconfig",
		strings.HasSuffix(base, ".kubeconfig"):
		return "a kubeconfig"
	}
	return ""
}
