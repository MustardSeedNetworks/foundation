// SPDX-License-Identifier: BUSL-1.1

package release

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/v0.27.14 holds stem v0.27.14's real signed release metadata. The
// artifacts are too large to vendor, so these tests supply each artifact's
// digest from checksums.txt; Verify only adds hashing the file on top.
const (
	fixtureTag = "v0.27.14"
	fixtureDeb = "stem_0.27.14_amd64.deb"
	fixtureDir = "testdata/" + fixtureTag
	// The SBOM is signed and listed in checksums.txt, but it is not a
	// provenance subject.
	fixtureSBOM = fixtureDeb + ".sbom.json"
)

func stemPolicy() Policy {
	return Policy{
		Repository:      "MustardSeedNetworks/stem",
		Workflow:        ".github/workflows/release.yml",
		ProvenanceAsset: "stem-slsa-provenance.intoto.jsonl",
	}
}

func mustVerifier(t *testing.T, p Policy) *Verifier {
	t.Helper()
	v, err := NewVerifier(p)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func listedDigest(t *testing.T, asset string) []byte {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join(fixtureDir, ChecksumsAsset))
	if err != nil {
		t.Fatal(err)
	}
	d, err := checksumFor(manifest, asset)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// copyFixture returns a private copy of the fixture release so a case can
// tamper with one file.
func copyFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(fixtureDir)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVerifyDigest(t *testing.T) {
	debDigest := listedDigest(t, fixtureDeb)
	flipped := append([]byte(nil), debDigest...)
	flipped[0] ^= 0xff

	tests := []struct {
		name    string
		policy  func(*Policy)
		tag     string
		asset   string
		digest  []byte
		prepare func(t *testing.T, dir string)
		wantErr string
	}{
		{name: "genuine artifact", tag: fixtureTag, asset: fixtureDeb, digest: debDigest},
		{
			name: "another tag's identity", tag: "v0.27.13", asset: fixtureDeb, digest: debDigest,
			wantErr: "checksums.txt.cosign.bundle",
		},
		{
			name: "tampered artifact", tag: fixtureTag, asset: fixtureDeb, digest: flipped,
			wantErr: "does not match checksums.txt",
		},
		{
			name: "tampered checksums.txt", tag: fixtureTag, asset: fixtureDeb, digest: debDigest,
			prepare: func(t *testing.T, dir string) {
				appendByte(t, filepath.Join(dir, ChecksumsAsset))
			},
			wantErr: "checksums.txt.cosign.bundle",
		},
		{
			name: "another repository", tag: fixtureTag, asset: fixtureDeb, digest: debDigest,
			policy:  func(p *Policy) { p.Repository = "MustardSeedNetworks/seed" },
			wantErr: "checksums.txt.cosign.bundle",
		},
		{
			name: "another workflow", tag: fixtureTag, asset: fixtureDeb, digest: debDigest,
			policy:  func(p *Policy) { p.Workflow = ".github/workflows/ci.yml" },
			wantErr: "checksums.txt.cosign.bundle",
		},
		{
			name: "artifact bundle missing", tag: fixtureTag, asset: fixtureDeb, digest: debDigest,
			prepare: func(t *testing.T, dir string) {
				removeFile(t, filepath.Join(dir, fixtureDeb+bundleSuffix))
			},
			wantErr: fixtureDeb + bundleSuffix,
		},
		{
			name: "artifact bundle is another file's", tag: fixtureTag, asset: fixtureDeb, digest: debDigest,
			prepare: func(t *testing.T, dir string) {
				if err := os.Rename(filepath.Join(dir, fixtureSBOM+bundleSuffix), filepath.Join(dir, fixtureDeb+bundleSuffix)); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: fixtureDeb + bundleSuffix,
		},
		{
			name: "provenance missing", tag: fixtureTag, asset: fixtureDeb, digest: debDigest,
			prepare: func(t *testing.T, dir string) {
				removeFile(t, filepath.Join(dir, stemPolicy().ProvenanceAsset))
			},
			wantErr: stemPolicy().ProvenanceAsset,
		},
		{
			name: "signed but not a provenance subject", tag: fixtureTag, asset: fixtureSBOM,
			digest:  listedDigest(t, fixtureSBOM),
			wantErr: stemPolicy().ProvenanceAsset,
		},
		{
			name: "not in checksums.txt", tag: fixtureTag, asset: "stem_0.27.14_riscv64.deb", digest: debDigest,
			wantErr: "does not list",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := stemPolicy()
			if tt.policy != nil {
				tt.policy(&p)
			}
			dir := fixtureDir
			if tt.prepare != nil {
				dir = copyFixture(t)
				tt.prepare(t, dir)
			}
			err := mustVerifier(t, p).verifyDigest(tt.tag, dir, tt.asset, tt.digest)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyDigest: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrVerification) {
				t.Fatalf("verifyDigest error = %v, want ErrVerification", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("verifyDigest error = %v, want it to name %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyHashesTheFile(t *testing.T) {
	dir := copyFixture(t)
	if err := os.WriteFile(filepath.Join(dir, fixtureDeb), []byte("not the release"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := mustVerifier(t, stemPolicy()).Verify(fixtureTag, dir, fixtureDeb)
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "does not match checksums.txt") {
		t.Fatalf("Verify = %v, want a checksum refusal", err)
	}
	if err := mustVerifier(t, stemPolicy()).Verify(fixtureTag, t.TempDir(), fixtureDeb); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify of a missing artifact = %v, want ErrVerification", err)
	}
}

func TestVerifyRejectsUnsafeNames(t *testing.T) {
	v := mustVerifier(t, stemPolicy())
	for _, tc := range []struct{ tag, asset string }{
		{"0.27.14", fixtureDeb},
		{"v0.27.14-rc1", fixtureDeb},
		{"v0.27", fixtureDeb},
		{"v01.2.3", fixtureDeb},
		{"../v0.27.14", fixtureDeb},
		{fixtureTag, "../" + fixtureDeb},
		{fixtureTag, `dir\` + fixtureDeb},
		{fixtureTag, ".."},
		{fixtureTag, ""},
	} {
		if err := v.Verify(tc.tag, fixtureDir, tc.asset); err == nil {
			t.Errorf("Verify(%q, %q) = nil, want a refusal", tc.tag, tc.asset)
		}
	}
}

func TestNewVerifierPolicy(t *testing.T) {
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.Repository = "" },
		func(p *Policy) { p.Workflow = "" },
		func(p *Policy) { p.ProvenanceAsset = "" },
		func(p *Policy) { p.ProvenanceAsset = "../provenance.jsonl" },
	} {
		p := stemPolicy()
		mutate(&p)
		if _, err := NewVerifier(p); err == nil {
			t.Errorf("NewVerifier(%+v) = nil error, want a refusal", p)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	tests := []struct {
		name     string
		manifest string
		want     string
		wantErr  string
	}{
		{name: "listed", manifest: digest + "  a.deb\n" + strings.Repeat("cd", 32) + "  b.deb\n", want: digest},
		{name: "suffix is not a match", manifest: digest + "  a.deb.sbom.json\n", wantErr: "does not list"},
		{name: "listed twice", manifest: digest + "  a.deb\n" + digest + "  a.deb\n", wantErr: "twice"},
		{name: "short digest", manifest: "abcd  a.deb\n", wantErr: "malformed"},
		{name: "not hex", manifest: strings.Repeat("zz", 32) + "  a.deb\n", wantErr: "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checksumFor([]byte(tt.manifest), "a.deb")
			if tt.wantErr != "" {
				if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("checksumFor error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || hex.EncodeToString(got) != tt.want {
				t.Fatalf("checksumFor = %x, %v; want %s", got, err, tt.want)
			}
		})
	}
}

func TestReadMetadataCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ChecksumsAsset), make([]byte, maxMetadataBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMetadata(dir, ChecksumsAsset); !errors.Is(err, ErrVerification) {
		t.Fatalf("readMetadata of an oversized file = %v, want ErrVerification", err)
	}
}

func appendByte(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
