// Command workflow reads GitHub Actions workflow files with a real YAML parser
// and prints what the repository's gates need to know about them, as JSON.
//
// It exists because the two consumers were reading the same file with regular
// expressions, and a regex is wrong in the direction nobody notices. A `uses:`
// inside a comment or a `run:` block is not a mapping key and must not be
// checked; a job name the pattern does not match is simply not seen, and a
// drift check then reports agreement over a list with an entry missing. Both
// consumers are Python, and `yaml` is not importable on a machine that
// satisfies `make doctor` -- scripts/check-tools.sh requires go, git, make and
// python3, and nothing on top. Go is required, this module already exists to
// pin tools the gates run, and a real parser is already in its graph. So the
// parse happens here and the policy stays in Python.
//
// It extracts and does not judge. Deciding that a `uses:` ref is unpinned is
// the pin gate's job, and keeping the messages in one style beside the other
// gate scripts is worth more than doing it closer to the parse.
//
// Every failure is fatal. A parse that skips what it cannot understand is the
// defect this replaces, so anything unrecognised is an error with a line
// number rather than a shorter list.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// use is one `uses:` mapping key, wherever it appears in the document.
type use struct {
	// Where it sits, as a reader would name it: jobs.doctor.steps[0].uses.
	// The pin gate prints this, so a finding says which step without the
	// reader counting sequence entries by hand.
	Path  string `json:"path"`
	Line  int    `json:"line"`
	Value string `json:"value"`
}

// job is one entry under the top-level `jobs:` mapping. Runs carries every
// `run:` scalar in it, because the drift check asserts that a gate's job
// invokes `make <gate>` and reading that off the raw block text is the same
// regex mistake one level down -- a `make docs` inside an `echo` would pass.
//
// Legs is nil for a job with no matrix, and otherwise one entry per job the
// matrix expands to. A leg is a check run of its own, so a job key alone
// cannot say that a narrowed matrix took two platforms away.
type job struct {
	Name string   `json:"name"`
	Runs []string `json:"runs"`
	Legs []leg    `json:"legs"`
}

// leg is one matrix combination, in the order its keys are written. Joined
// with ", ", the values are the suffix GitHub renders after the job key in the
// check run's name: `install-dry-run (windows-latest)`.
type leg []pair

type pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type file struct {
	Path string `json:"path"`
	Jobs []job  `json:"jobs"`
	Uses []use  `json:"uses"`
}

type model struct {
	Files []file `json:"files"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: workflow <workflow.yml>...")
		os.Exit(2)
	}
	out, err := scan(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "workflow: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "workflow: %v\n", err)
		os.Exit(1)
	}
}

func scan(paths []string) (model, error) {
	out := model{Files: make([]file, 0, len(paths))}
	for _, path := range paths {
		text, err := os.ReadFile(path)
		if err != nil {
			return model{}, err
		}
		f, err := scanOne(filepath.ToSlash(path), text)
		if err != nil {
			return model{}, fmt.Errorf("%s: %w", path, err)
		}
		out.Files = append(out.Files, f)
	}
	return out, nil
}

func scanOne(path string, text []byte) (file, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(text, &doc); err != nil {
		return file{}, err
	}
	// An empty document decodes without error and yields no content, which
	// would otherwise report a workflow with no jobs and no uses -- a clean
	// answer from a file nothing read.
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return file{}, fmt.Errorf("no YAML document")
	}
	root := resolve(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return file{}, fmt.Errorf("line %d: top level is not a mapping", root.Line)
	}

	jobsNode := value(root, "jobs")
	if jobsNode == nil {
		return file{}, fmt.Errorf("no `jobs:` key")
	}
	if jobsNode.Kind != yaml.MappingNode {
		return file{}, fmt.Errorf("line %d: `jobs:` is not a mapping", jobsNode.Line)
	}
	jobs := make([]job, 0, len(jobsNode.Content)/2)
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		name, body := jobsNode.Content[i].Value, resolve(jobsNode.Content[i+1])
		runs := []string{}
		collectRuns(body, &runs)
		legs, err := matrix(body)
		if err != nil {
			return file{}, fmt.Errorf("job %s: %w", name, err)
		}
		jobs = append(jobs, job{Name: name, Runs: runs, Legs: legs})
	}
	if len(jobs) == 0 {
		return file{}, fmt.Errorf("line %d: `jobs:` names no jobs", jobsNode.Line)
	}

	uses := []use{}
	if err := walk(root, "", &uses); err != nil {
		return file{}, err
	}
	return file{Path: path, Jobs: jobs, Uses: uses}, nil
}

// resolve follows an alias to the node it names, so an anchored step reached
// through `*ref` is read as the step rather than skipped as an alias.
func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// value is the node a mapping maps `key` to, or nil.
func value(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return resolve(mapping.Content[i+1])
		}
	}
	return nil
}

// matrix expands a job's `strategy.matrix` the way GitHub documents it: the
// product of the list-valued keys in the order written, less every `exclude:`
// entry whose pairs all match, and then each `include:` entry merged into every
// original combination it overwrites no original value of -- or appended as a
// combination of its own where it fits none. A value written by an earlier
// include may be overwritten by a later one; an original value may not.
//
// A matrix that only a run can expand -- an expression, a value that is not a
// scalar -- is refused rather than reported as no legs, which would read as a
// job that runs once.
func matrix(body *yaml.Node) ([]leg, error) {
	if body == nil || body.Kind != yaml.MappingNode {
		return nil, nil
	}
	strategy := value(body, "strategy")
	if strategy == nil {
		return nil, nil
	}
	if strategy.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: `strategy:` is not a mapping, so its matrix cannot be read without running it", strategy.Line)
	}
	m := value(strategy, "matrix")
	if m == nil {
		return nil, nil
	}
	if m.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: `strategy.matrix:` is not a mapping, so its legs cannot be read without running it", m.Line)
	}

	var keys []string
	combos := []leg{{}}
	var include, exclude []leg
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], resolve(m.Content[i+1])
		var err error
		switch k.Value {
		case "include":
			include, err = entries(k, v)
		case "exclude":
			exclude, err = entries(k, v)
		default:
			var values []string
			values, err = scalars(k, v)
			keys = append(keys, k.Value)
			next := make([]leg, 0, len(combos)*len(values))
			for _, c := range combos {
				for _, val := range values {
					next = append(next, append(append(leg{}, c...), pair{k.Value, val}))
				}
			}
			combos = next
		}
		if err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		combos = nil
	}

	for _, e := range exclude {
		for _, p := range e {
			if !contains(keys, p.Key) {
				return nil, fmt.Errorf("line %d: `exclude:` names `%s`, which the matrix does not, and what GitHub does with that is unmeasured", m.Line, p.Key)
			}
		}
		kept := combos[:0]
		for _, c := range combos {
			if !matches(c, e) {
				kept = append(kept, c)
			}
		}
		combos = kept
	}

	original := len(combos)
	for _, e := range include {
		extended := false
		for i := 0; i < original; i++ {
			if overwrites(combos[i], e, keys) {
				continue
			}
			for _, p := range e {
				combos[i] = set(combos[i], p)
			}
			extended = true
		}
		if !extended {
			combos = append(combos, append(leg{}, e...))
		}
	}
	if len(combos) == 0 {
		return nil, fmt.Errorf("line %d: `strategy.matrix:` expands to no legs", m.Line)
	}
	return combos, nil
}

// scalars reads one list-valued matrix key.
func scalars(k, v *yaml.Node) ([]string, error) {
	if v == nil || v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
		return nil, fmt.Errorf("line %d: matrix key `%s` is not a non-empty list", k.Line, k.Value)
	}
	out := make([]string, 0, len(v.Content))
	for _, item := range v.Content {
		s, err := scalar(k.Value, resolve(item))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// entries reads `include:` or `exclude:`, a list of flat mappings.
func entries(k, v *yaml.Node) ([]leg, error) {
	if v == nil || v.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("line %d: matrix `%s:` is not a list", k.Line, k.Value)
	}
	out := make([]leg, 0, len(v.Content))
	for _, item := range v.Content {
		item = resolve(item)
		if item == nil || item.Kind != yaml.MappingNode || len(item.Content) == 0 {
			return nil, fmt.Errorf("line %d: a matrix `%s:` entry is not a non-empty mapping", k.Line, k.Value)
		}
		var e leg
		for i := 0; i+1 < len(item.Content); i += 2 {
			s, err := scalar(item.Content[i].Value, resolve(item.Content[i+1]))
			if err != nil {
				return nil, err
			}
			e = append(e, pair{item.Content[i].Value, s})
		}
		out = append(out, e)
	}
	return out, nil
}

func scalar(key string, n *yaml.Node) (string, error) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("matrix value for `%s` is not a scalar, and how GitHub renders one in a check name is unmeasured", key)
	}
	if strings.Contains(n.Value, "${{") {
		return "", fmt.Errorf("line %d: matrix value for `%s` is an expression, so its leg cannot be read without running it", n.Line, key)
	}
	return n.Value, nil
}

func contains(keys []string, k string) bool {
	for _, have := range keys {
		if have == k {
			return true
		}
	}
	return false
}

// matches reports whether every pair of e is in c.
func matches(c, e leg) bool {
	for _, p := range e {
		v, ok := lookup(c, p.Key)
		if !ok || v != p.Value {
			return false
		}
	}
	return true
}

// overwrites reports whether merging e into c would change one of c's
// original values, which are the ones under the matrix's own keys.
func overwrites(c, e leg, keys []string) bool {
	for _, p := range e {
		if !contains(keys, p.Key) {
			continue
		}
		if v, _ := lookup(c, p.Key); v != p.Value {
			return true
		}
	}
	return false
}

func lookup(c leg, key string) (string, bool) {
	for _, p := range c {
		if p.Key == key {
			return p.Value, true
		}
	}
	return "", false
}

// set writes p into c in place where the key is already there, and appends it
// otherwise, so a leg keeps the order its keys were first written in.
func set(c leg, p pair) leg {
	for i := range c {
		if c[i].Key == p.Key {
			c[i].Value = p.Value
			return c
		}
	}
	return append(c, p)
}

// collectRuns appends every `run:` scalar under n, depth first. A non-scalar
// `run:` is not valid in a workflow and is left to actionlint rather than
// duplicated here; what matters for the drift check is that nothing invents a
// command out of prose.
func collectRuns(n *yaml.Node, out *[]string) {
	n = resolve(n)
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "run" {
				if v := resolve(n.Content[i+1]); v != nil && v.Kind == yaml.ScalarNode {
					*out = append(*out, v.Value)
				}
				continue
			}
			collectRuns(n.Content[i+1], out)
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			collectRuns(item, out)
		}
	}
}

// walk appends every `uses:` mapping key under n, depth first, in document
// order. A `uses:` whose value is not a scalar is an error rather than a skip:
// it is the shape a checker would silently pass over.
func walk(n *yaml.Node, path string, out *[]use) error {
	n = resolve(n)
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], resolve(n.Content[i+1])
			child := k.Value
			if path != "" {
				child = path + "." + k.Value
			}
			if k.Value == "uses" {
				if v == nil || v.Kind != yaml.ScalarNode {
					return fmt.Errorf("line %d: `uses:` is not a scalar", k.Line)
				}
				*out = append(*out, use{Path: child, Line: v.Line, Value: v.Value})
				continue
			}
			if err := walk(v, child, out); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			if err := walk(item, fmt.Sprintf("%s[%d]", path, i), out); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		// A block scalar is a string. Whatever `uses:` it spells inside a
		// `run:` block is shell, not a key, and stops here -- which is the
		// whole reason this is a parser.
	default:
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("line %d: unrecognised node", n.Line)
		}
	}
	return nil
}
