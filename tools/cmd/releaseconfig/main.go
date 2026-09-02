// Command releaseconfig reads the GoReleaser config with a real YAML parser and
// prints what it declares -- the extra-file globs, and the asset names the
// signing entries produce -- as JSON.
//
// An extra file is a release asset GoReleaser does not build: this repository
// uploads install.sh and install.ps1 that way. Two independent lists decide
// what happens to one, and the pair is the thing worth reading -- `release`
// uploads it and `checksum` puts it in checksums.txt, which is the file cosign
// signs. A name on the first list and not the second ships unverified, which is
// what Q97 was.
//
// The parse lives here for the reason tools/cmd/workflow's does: `yaml` is not
// importable on a machine that satisfies `make doctor`, Go is required, and a
// regex over YAML is wrong in the direction nobody notices. The policy stays in
// scripts/check-release-artifacts.py.
//
// It extracts and does not judge. An absent section or an absent `extra_files`
// is an empty list rather than an error -- that is the state this repository
// was in before Q97, and reporting it is the caller's job. Anything it cannot
// read is fatal with a line number: a `name_template:` renames the file in the
// release, and a caller deriving the published name from the glob would then
// check a name that is not there.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	yaml "go.yaml.in/yaml/v3"
)

type model struct {
	Path string `json:"path"`
	// The `glob:` values, in document order, verbatim. Resolving one against
	// the filesystem is the caller's, which is where a glob matching nothing
	// has to become a finding.
	Release  []string `json:"release_extra_files"`
	Checksum []string `json:"checksum_extra_files"`
	// One entry per `signs:` entry, carrying the asset-name templates it
	// declares. Expanding `${artifact}` is the caller's, which is where a
	// missing asset has to become a finding.
	Signs []sign `json:"signs"`
}

// sign is the asset names one `signs:` entry produces. Both keys are optional
// in GoReleaser and an absent one reads as empty rather than as its default:
// this extracts and does not judge, and a default filled in here would be a
// second copy of GoReleaser's own, wrong on the release where it changed.
type sign struct {
	Signature   string `json:"signature"`
	Certificate string `json:"certificate"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: releaseconfig <.goreleaser.yaml>")
		os.Exit(2)
	}
	path := os.Args[1]
	text, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "releaseconfig: %v\n", err)
		os.Exit(1)
	}
	out, err := scan(path, text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "releaseconfig: %s: %v\n", path, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "releaseconfig: %v\n", err)
		os.Exit(1)
	}
}

func scan(path string, text []byte) (model, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(text, &doc); err != nil {
		return model{}, err
	}
	// An empty document decodes without error and yields no content, which
	// would otherwise report a config that declares no extra file at all --
	// a clean answer from a file nothing read.
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return model{}, fmt.Errorf("no YAML document")
	}
	root := resolve(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return model{}, fmt.Errorf("line %d: top level is not a mapping", root.Line)
	}

	release, err := extraFiles(root, "release")
	if err != nil {
		return model{}, err
	}
	checksum, err := extraFiles(root, "checksum")
	if err != nil {
		return model{}, err
	}
	signs, err := signatures(root)
	if err != nil {
		return model{}, err
	}
	return model{Path: path, Release: release, Checksum: checksum, Signs: signs}, nil
}

// signatures is the `signature:` and `certificate:` of every `signs:` entry.
//
// A caller asserting that a release carries what it signed has to name those
// assets, and naming them anywhere else is a copy that goes stale silently --
// which is what happened when cosign v3 turned one `.sig` plus one `.pem` into
// one `.sigstore.json` and the checker went on requiring the old two.
func signatures(root *yaml.Node) ([]sign, error) {
	found := []sign{}
	list := value(root, "signs")
	if list == nil {
		return found, nil
	}
	if list.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("line %d: `signs:` is not a sequence", list.Line)
	}
	for _, item := range list.Content {
		item = resolve(item)
		if item == nil || item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("line %d: `signs` entry is not a mapping", list.Line)
		}
		var s sign
		for _, key := range []struct {
			name string
			into *string
		}{{"signature", &s.Signature}, {"certificate", &s.Certificate}} {
			n := value(item, key.name)
			if n == nil {
				continue
			}
			if n.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: `signs.%s:` is not a scalar", n.Line, key.name)
			}
			*key.into = n.Value
		}
		found = append(found, s)
	}
	return found, nil
}

// extraFiles is the `glob:` of every entry under `<section>.extra_files`.
func extraFiles(root *yaml.Node, section string) ([]string, error) {
	found := []string{}
	sec := value(root, section)
	if sec == nil {
		return found, nil
	}
	if sec.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: `%s:` is not a mapping", sec.Line, section)
	}
	list := value(sec, "extra_files")
	if list == nil {
		return found, nil
	}
	if list.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("line %d: `%s.extra_files:` is not a sequence", list.Line, section)
	}
	for _, item := range list.Content {
		item = resolve(item)
		if item == nil || item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("line %d: `%s.extra_files` entry is not a mapping", list.Line, section)
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if item.Content[i].Value != "glob" {
				return nil, fmt.Errorf("line %d: `%s.extra_files` entry carries `%s:`, which is not read here -- and a caller that names the asset after the glob would then check a name the release does not carry",
					item.Content[i].Line, section, item.Content[i].Value)
			}
		}
		g := value(item, "glob")
		if g == nil || g.Kind != yaml.ScalarNode || g.Value == "" {
			return nil, fmt.Errorf("line %d: `%s.extra_files` entry has no `glob:` scalar", item.Line, section)
		}
		found = append(found, g.Value)
	}
	return found, nil
}

// resolve follows an alias to the node it names, so an anchored entry reached
// through `*ref` is read as the entry rather than skipped as an alias.
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
