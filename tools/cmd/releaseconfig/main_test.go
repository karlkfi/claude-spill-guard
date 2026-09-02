package main

import (
	"strings"
	"testing"
)

// The state this repository shipped in before Q97, which is the one the caller
// has to be able to report: uploaded by `release`, absent from `checksum`. An
// absent section reads as no globs rather than as an error, or the caller never
// sees the disagreement it exists to find.
func TestScanReadsEachSectionSeparately(t *testing.T) {
	const src = `
version: 2
checksum:
  name_template: checksums.txt
release:
  draft: true
  extra_files:
    - glob: install/install.sh
    - glob: install/install.ps1
`
	m, err := scan("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []string{"install/install.sh", "install/install.ps1"}
	if strings.Join(m.Release, ",") != strings.Join(want, ",") {
		t.Errorf("release = %v, want %v", m.Release, want)
	}
	if len(m.Checksum) != 0 {
		t.Errorf("checksum = %v, want none", m.Checksum)
	}
}

// A glob spelled inside a block scalar is shell, not a key. This is the whole
// reason the parse is here rather than in a regex over lines.
func TestScanIgnoresGlobsThatAreNotKeys(t *testing.T) {
	const src = `
version: 2
before:
  hooks:
    - |
      echo "extra_files:"
      echo "  - glob: smuggled.sh"
checksum:
  extra_files:
    - glob: install/install.sh
`
	m, err := scan("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(m.Checksum) != 1 || m.Checksum[0] != "install/install.sh" {
		t.Errorf("checksum = %v, want [install/install.sh]", m.Checksum)
	}
}

// `name_template:` renames the asset, so a caller naming it after the glob
// would check a name the release does not carry. Refusing is the direction
// that cannot pass over the rename.
func TestScanRefusesAnEntryItWouldReadWrong(t *testing.T) {
	const src = `
version: 2
release:
  extra_files:
    - glob: install/install.sh
      name_template: setup.sh
`
	if _, err := scan("t.yaml", []byte(src)); err == nil {
		t.Fatal("scan accepted a renamed extra file")
	} else if !strings.Contains(err.Error(), "name_template") {
		t.Errorf("err = %v, want it to name the key it could not read", err)
	}
}
