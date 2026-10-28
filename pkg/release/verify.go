// SPDX-License-Identifier: BUSL-1.1

// Package release verifies a product release artifact before an in-place
// update installs it, and resolves releases from GitHub, an HTTPS mirror or a
// local directory. It is the security core of the fleet's update verb (stem
// ADR-0012); each product supplies only its Policy.
//
// Trust comes from the release's keyless signing identity, never from where
// the bytes came from: every check below must pass, a missing file is a
// failure, and nothing can switch a check off. Verification is offline. The
// Sigstore public-good trusted root is embedded, and each bundle carries its
// certificate, transparency-log inclusion proof and integrated timestamp.
package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// trustedRootJSON is the Sigstore public-good trusted root (Fulcio CAs, Rekor
// and CT log keys, timestamp authority). It changes only when Sigstore rotates
// keys; an operator-supplied root is deliberately not accepted, because it
// would be a switch that turns verification off.
//
//go:embed trusted_root.json
var trustedRootJSON []byte

const (
	// ChecksumsAsset is the release's checksum manifest; it and every artifact
	// carry a sigstore bundle named <asset>.cosign.bundle.
	ChecksumsAsset = "checksums.txt"
	bundleSuffix   = ".cosign.bundle"

	oidcIssuer          = "https://token.actions.githubusercontent.com"
	slsaProvenanceV1    = "https://slsa.dev/provenance/v1"
	maxMetadataBytes    = 1 << 20
	digestAlgorithm     = "sha256"
	checksumFieldsCount = 2
)

// ErrVerification is wrapped by every refusal, so callers can tell a release
// that failed verification from an I/O or network error.
var ErrVerification = errors.New("release verification failed")

var tagPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Policy is a product's release identity.
type Policy struct {
	// Repository is the GitHub owner/name, e.g. "MustardSeedNetworks/stem".
	Repository string
	// Workflow is the repository path of the release workflow whose identity
	// signs every bundle, e.g. ".github/workflows/release.yml".
	Workflow string
	// ProvenanceAsset is the release asset holding the SLSA provenance bundle,
	// e.g. "stem-slsa-provenance.intoto.jsonl".
	ProvenanceAsset string
}

// Verifier checks release artifacts against one product's Policy.
type Verifier struct {
	policy Policy
	sigs   *verify.Verifier
}

// NewVerifier returns a Verifier for p backed by the embedded trusted root.
func NewVerifier(p Policy) (*Verifier, error) {
	if p.Repository == "" || p.Workflow == "" || p.ProvenanceAsset == "" {
		return nil, errors.New("release: policy needs Repository, Workflow and ProvenanceAsset")
	}
	if err := checkAssetName(p.ProvenanceAsset); err != nil {
		return nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("release: load embedded trusted root: %w", err)
	}
	sigs, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("release: build verifier: %w", err)
	}
	return &Verifier{policy: p, sigs: sigs}, nil
}

// Verify checks asset of release tag. dir holds the release's files under
// their release names: the asset, its bundle, checksums.txt and its bundle,
// and the provenance asset. It returns nil only when all of these hold:
//
//  1. the checksums.txt bundle is signed by the release workflow at exactly
//     this tag;
//  2. the asset's SHA-256 equals its line in checksums.txt;
//  3. the asset's own bundle is signed by the same identity;
//  4. the provenance bundle is signed by the same identity, is SLSA v1, lists
//     the asset by exact name and digest, and names this repository, the
//     release workflow and this tag.
func (v *Verifier) Verify(tag, dir, asset string) error {
	if err := checkTag(tag); err != nil {
		return err
	}
	if err := checkAssetName(asset); err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(dir, asset))
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrVerification, asset, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("release: hash %s: %w", asset, err)
	}
	return v.verifyDigest(tag, dir, asset, h.Sum(nil))
}

func (v *Verifier) verifyDigest(tag, dir, asset string, digest []byte) error {
	identity, err := verify.NewShortCertificateIdentity(oidcIssuer, "", v.signerSAN(tag), "")
	if err != nil {
		return fmt.Errorf("release: certificate identity: %w", err)
	}

	checksums, err := readMetadata(dir, ChecksumsAsset)
	if err != nil {
		return err
	}
	if _, err := v.verifyBundle(dir, ChecksumsAsset+bundleSuffix,
		verify.NewPolicy(verify.WithArtifact(bytes.NewReader(checksums)), verify.WithCertificateIdentity(identity))); err != nil {
		return err
	}

	listed, err := checksumFor(checksums, asset)
	if err != nil {
		return err
	}
	if !bytes.Equal(listed, digest) {
		return fmt.Errorf("%w: %s: SHA-256 %x does not match checksums.txt %x", ErrVerification, asset, digest, listed)
	}

	digestPolicy := verify.NewPolicy(verify.WithArtifactDigest(digestAlgorithm, digest), verify.WithCertificateIdentity(identity))
	if _, err := v.verifyBundle(dir, asset+bundleSuffix, digestPolicy); err != nil {
		return err
	}

	result, err := v.verifyBundle(dir, v.policy.ProvenanceAsset, digestPolicy)
	if err != nil {
		return err
	}
	return v.checkProvenance(result, tag, asset, digest)
}

func (v *Verifier) signerSAN(tag string) string {
	return "https://github.com/" + v.policy.Repository + "/" + v.policy.Workflow + "@refs/tags/" + tag
}

func (v *Verifier) verifyBundle(dir, name string, policy verify.PolicyBuilder) (*verify.VerificationResult, error) {
	data, err := readMetadata(dir, name)
	if err != nil {
		return nil, err
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrVerification, name, err)
	}
	result, err := v.sigs.Verify(&b, policy)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrVerification, name, err)
	}
	return result, nil
}

type provenancePredicate struct {
	BuildDefinition struct {
		ExternalParameters struct {
			Workflow struct {
				Ref        string `json:"ref"`
				Repository string `json:"repository"`
				Path       string `json:"path"`
			} `json:"workflow"`
		} `json:"externalParameters"`
	} `json:"buildDefinition"`
}

func (v *Verifier) checkProvenance(result *verify.VerificationResult, tag, asset string, digest []byte) error {
	st := result.Statement
	if st == nil {
		return fmt.Errorf("%w: %s: not an in-toto statement", ErrVerification, v.policy.ProvenanceAsset)
	}
	if st.GetPredicateType() != slsaProvenanceV1 {
		return fmt.Errorf("%w: %s: predicate type %q, want %q", ErrVerification, v.policy.ProvenanceAsset, st.GetPredicateType(), slsaProvenanceV1)
	}
	want := hex.EncodeToString(digest)
	named := false
	for _, s := range st.GetSubject() {
		if s.GetName() == asset && s.GetDigest()[digestAlgorithm] == want {
			named = true
			break
		}
	}
	if !named {
		return fmt.Errorf("%w: %s: no subject %s with SHA-256 %s", ErrVerification, v.policy.ProvenanceAsset, asset, want)
	}
	raw, err := protojson.Marshal(st.GetPredicate())
	if err != nil {
		return fmt.Errorf("release: encode provenance predicate: %w", err)
	}
	var pred provenancePredicate
	if err := json.Unmarshal(raw, &pred); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrVerification, v.policy.ProvenanceAsset, err)
	}
	wf := pred.BuildDefinition.ExternalParameters.Workflow
	if wf.Repository != "https://github.com/"+v.policy.Repository || wf.Path != v.policy.Workflow || wf.Ref != "refs/tags/"+tag {
		return fmt.Errorf("%w: %s: built by %s %s at %s, want %s %s at refs/tags/%s", ErrVerification,
			v.policy.ProvenanceAsset, wf.Repository, wf.Path, wf.Ref, v.policy.Repository, v.policy.Workflow, tag)
	}
	return nil
}

func readMetadata(dir, name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrVerification, name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("release: read %s: %w", name, err)
	}
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrVerification, name, maxMetadataBytes)
	}
	return data, nil
}

// checksumFor returns the digest listed for asset in a sha256sum-format
// manifest. A missing or repeated entry is a refusal.
func checksumFor(manifest []byte, asset string) ([]byte, error) {
	var found []byte
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != checksumFieldsCount || fields[1] != asset {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: checksums.txt lists %s twice", ErrVerification, asset)
		}
		d, err := hex.DecodeString(fields[0])
		if err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("%w: checksums.txt: malformed digest for %s", ErrVerification, asset)
		}
		found = d
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: checksums.txt: %w", ErrVerification, err)
	}
	if found == nil {
		return nil, fmt.Errorf("%w: checksums.txt does not list %s", ErrVerification, asset)
	}
	return found, nil
}

func checkTag(tag string) error {
	if !tagPattern.MatchString(tag) {
		return fmt.Errorf("release: %q is not a release tag (vMAJOR.MINOR.PATCH)", tag)
	}
	return nil
}

func checkAssetName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("release: %q is not an asset name", name)
	}
	return nil
}
