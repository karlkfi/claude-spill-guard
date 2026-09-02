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

// The shape this repository signs with today: one bundle, no certificate. A
// caller reading the asset name from here rather than writing it down is what
// stops a signing-config change leaving the checker requiring an asset the
// release no longer carries.
func TestScanReadsTheSigningAssetNames(t *testing.T) {
	const src = `
version: 2
signs:
  - id: checksums
    cmd: cosign
    artifacts: checksum
    signature: '${artifact}.sigstore.json'
    args:
      - sign-blob
      - '--bundle=${signature}'
`
	m, err := scan("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(m.Signs) != 1 {
		t.Fatalf("signs = %v, want one entry", m.Signs)
	}
	if m.Signs[0].Signature != "${artifact}.sigstore.json" {
		t.Errorf("signature = %q, want the bundle template", m.Signs[0].Signature)
	}
	// Absent rather than defaulted. cosign v3 writes no separate certificate,
	// and a default filled in here would make the caller require an asset that
	// is not produced -- the failure this whole path exists to stop.
	if m.Signs[0].Certificate != "" {
		t.Errorf("certificate = %q, want empty when the key is absent",
			m.Signs[0].Certificate)
	}
}

// The pre-cosign-v3 shape, which has to keep parsing: a caller that only
// handles today's config would report nothing on a tree that rolled back.
func TestScanReadsADetachedSignatureAndCertificate(t *testing.T) {
	const src = `
version: 2
signs:
  - artifacts: checksum
    certificate: '${artifact}.pem'
    signature: '${artifact}.sig'
`
	m, err := scan("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(m.Signs) != 1 {
		t.Fatalf("signs = %v, want one entry", m.Signs)
	}
	if m.Signs[0].Signature != "${artifact}.sig" ||
		m.Signs[0].Certificate != "${artifact}.pem" {
		t.Errorf("signs[0] = %+v, want both templates", m.Signs[0])
	}
}

// No `signs:` at all is a config that signs nothing, which is a finding for
// the caller and not a parse error here.
func TestScanReadsNoSigningSectionAsEmpty(t *testing.T) {
	const src = `
version: 2
release:
  draft: true
`
	m, err := scan("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(m.Signs) != 0 {
		t.Errorf("signs = %v, want none", m.Signs)
	}
}
