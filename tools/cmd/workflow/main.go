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
type job struct {
	Name string   `json:"name"`
	Runs []string `json:"runs"`
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
		runs := []string{}
		collectRuns(jobsNode.Content[i+1], &runs)
		jobs = append(jobs, job{Name: jobsNode.Content[i].Value, Runs: runs})
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
