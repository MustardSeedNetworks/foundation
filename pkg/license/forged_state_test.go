// SPDX-License-Identifier: BUSL-1.1

package license_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/license"
)

// forgeState writes an activation state file using only inputs an unprivileged
// local process already has: the device fingerprint it can recompute and the
// encryption salt compiled into the shipped binary. It deliberately lives in
// the external test package and reimplements the sealing rather than calling
// an unexported helper — that is the point of #34. If this function can make
// the product report an entitlement, so can a local user with no private key.
func forgeState(t *testing.T, dir string, policy license.ProductPolicy, state *license.ActivationState) {
	t.Helper()

	plaintext, marshalErr := json.Marshal(state)
	if marshalErr != nil {
		t.Fatalf("marshal forged state: %v", marshalErr)
	}

	fp, fpErr := license.GenerateFingerprint()
	if fpErr != nil {
		t.Fatalf("GenerateFingerprint: %v", fpErr)
	}
	key := sha256.Sum256([]byte(fp.Hash() + policy.EncryptionSalt))

	block, blockErr := aes.NewCipher(key[:])
	if blockErr != nil {
		t.Fatalf("aes.NewCipher: %v", blockErr)
	}
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		t.Fatalf("cipher.NewGCM: %v", gcmErr)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := io.ReadFull(rand.Reader, nonce); nonceErr != nil {
		t.Fatalf("nonce: %v", nonceErr)
	}
	sealed := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil))

	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	path := filepath.Join(dir, policy.LicenseFileName)
	if writeErr := os.WriteFile(path, []byte(sealed), 0o600); writeErr != nil {
		t.Fatalf("write forged state: %v", writeErr)
	}
}

// deviceHash returns this machine's fingerprint hash, which a forged state has
// to carry to clear the device binding.
func deviceHash(t *testing.T) string {
	t.Helper()
	fp, err := license.GenerateFingerprint()
	if err != nil {
		t.Fatalf("GenerateFingerprint: %v", err)
	}
	return fp.Hash()
}

// Token-shaped strings that no key ever signed. They are held in named
// constants rather than written inline so a secret scanner does not have to
// judge a high-entropy literal sitting next to a field called LicenseKey.
const (
	neverSigned   = "MSN1.eyJ2IjoxfQ.bm90YXNpZ25hdHVyZQ"
	obviouslyFake = "MSN1.never-signed"
)

// TestForgedStateGrantsNothing is the #34 acceptance. Everything the manager
// grants after a restart must trace back to the Ed25519 signature or to the
// policy's own trial terms — never to the contents of the state file, which a
// local user can rewrite at will.
func TestForgedStateGrantsNothing(t *testing.T) {
	t.Parallel()

	policy := testPolicy()
	pub, priv := testKeyPair(t)

	tests := []struct {
		name          string
		state         *license.ActivationState
		wantActivated bool
		wantFeatures  []string
		wantNoFeature []string
		// wantStateTier and wantStateFeatures are read straight off GetState,
		// which products render in their licence panel. A stripped state must
		// not still show the tier it claimed.
		wantStateTier     int
		wantStateFeatures []string
	}{
		{
			name: "no token at all",
			state: &license.ActivationState{
				DeviceHash:  deviceHash(t),
				Tier:        2,
				ActivatedAt: time.Now(),
				Features:    []string{"feat_a"},
			},
			wantNoFeature: []string{"feat_a"},
			wantStateTier: -1,
		},
		{
			name: "token that was never signed",
			state: &license.ActivationState{
				LicenseKey:  neverSigned,
				DeviceHash:  deviceHash(t),
				Tier:        2,
				ActivatedAt: time.Now(),
				Features:    []string{"feat_a"},
			},
			wantNoFeature: []string{"feat_a"},
			wantStateTier: -1,
		},
		{
			// A trial with no start date would be measured from the zero time
			// and so is already over, but nothing should have to reason about
			// that: it is not a trial the product issued.
			name: "trial with no start date",
			state: &license.ActivationState{
				DeviceHash:  deviceHash(t),
				Tier:        2,
				IsTrialMode: true,
				Features:    []string{"feat_a"},
			},
			wantNoFeature: []string{"feat_a"},
			wantStateTier: -1,
		},
		{
			name: "trial dated in the future never ends",
			state: &license.ActivationState{
				DeviceHash:     deviceHash(t),
				Tier:           2,
				IsTrialMode:    true,
				TrialStartedAt: time.Now().AddDate(10, 0, 0),
				Features:       []string{"feat_a"},
			},
			wantNoFeature: []string{"feat_a"},
			wantStateTier: -1,
		},
		{
			// #34's headline: a real licence with a bigger tier and extra
			// features written in beside it. The token decides, so the licence
			// keeps working and grants exactly what it was issued.
			name: "genuine licence with a higher tier written in beside it",
			state: &license.ActivationState{
				LicenseKey:  signToken(t, priv, "testprod", "9001", "SERIAL-UPGRADE", 2, 0),
				DeviceHash:  deviceHash(t),
				Tier:        99,
				ActivatedAt: time.Now(),
				Features:    []string{"feat_a", "feat_forged"},
			},
			wantActivated:     true,
			wantFeatures:      []string{"feat_a"},
			wantNoFeature:     []string{"feat_forged"},
			wantStateTier:     2,
			wantStateFeatures: []string{"feat_a"},
		},
		{
			// The token is genuine, so the state stays loaded and keeps the
			// tier it was issued — but the term it runs on must come from the
			// signed payload, not from the expiry written beside it.
			name: "genuine licence whose expiry was rewritten in the file",
			state: &license.ActivationState{
				LicenseKey:  signToken(t, priv, "testprod", "9001", "SERIAL-EXP", 2, time.Now().Add(-24*time.Hour).Unix()),
				DeviceHash:  deviceHash(t),
				Tier:        2,
				ActivatedAt: time.Now().AddDate(-1, 0, 0),
				ExpiresAt:   time.Now().AddDate(1, 0, 0),
				Features:    []string{"feat_a"},
			},
			wantNoFeature:     []string{"feat_a"},
			wantStateTier:     2,
			wantStateFeatures: []string{"feat_a"},
		},
		{
			name: "trial claiming features the trial tier does not grant",
			state: &license.ActivationState{
				DeviceHash:     deviceHash(t),
				Tier:           99,
				IsTrialMode:    true,
				TrialStartedAt: time.Now(),
				Features:       []string{"feat_a", "feat_forged"},
			},
			wantActivated:     true,
			wantFeatures:      []string{"feat_a"},
			wantNoFeature:     []string{"feat_forged"},
			wantStateTier:     2,
			wantStateFeatures: []string{"feat_a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			forgeState(t, dir, policy, tc.state)

			mgr, err := license.NewManagerWithDir(license.NewVerifier(pub, policy), policy, dir)
			if err != nil {
				t.Fatalf("NewManagerWithDir: %v", err)
			}

			if got := mgr.IsActivated(); got != tc.wantActivated {
				t.Errorf("IsActivated() = %v, want %v", got, tc.wantActivated)
			}
			for _, feature := range tc.wantFeatures {
				if !mgr.HasFeature(feature) {
					t.Errorf("HasFeature(%q) = false, want true", feature)
				}
			}
			for _, feature := range tc.wantNoFeature {
				if mgr.HasFeature(feature) {
					t.Errorf("HasFeature(%q) = true — the state file granted it", feature)
				}
			}

			// The state stays in memory so the manager can tell a forgery from
			// a fresh install, but what it reports must be what the signature
			// or the policy allows, never what the file claimed.
			state := mgr.GetState()
			if state == nil {
				t.Fatal("GetState() = nil; the state must be kept so a trial cannot overwrite it")
			}
			if state.Tier != tc.wantStateTier {
				t.Errorf("GetState().Tier = %d, want %d", state.Tier, tc.wantStateTier)
			}
			if !slices.Equal(state.Features, tc.wantStateFeatures) {
				t.Errorf("GetState().Features = %v, want %v", state.Features, tc.wantStateFeatures)
			}
		})
	}
}

// TestGenuineActivationSurvivesReload is the other half of the acceptance: the
// re-verification must not cost a real licence its entitlement across a
// restart. Without this, "grant nothing" would pass by granting nothing ever.
func TestGenuineActivationSurvivesReload(t *testing.T) {
	t.Parallel()

	pub, priv := testKeyPair(t)
	policy := testPolicy()
	v := license.NewVerifier(pub, policy)
	dir := t.TempDir()

	mgr, err := license.NewManagerWithDir(v, policy, dir)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}
	if res := mgr.Activate(signToken(t, priv, "testprod", "9001", "SERIAL-RELOAD", 2, 0)); !res.Success {
		t.Fatalf("Activate: %+v", res)
	}

	reloaded, err := license.NewManagerWithDir(v, policy, dir)
	if err != nil {
		t.Fatalf("reload NewManagerWithDir: %v", err)
	}
	if !reloaded.IsActivated() {
		t.Error("genuine activation is not active after reload")
	}
	if !reloaded.HasFeature("feat_a") {
		t.Error("genuine activation lost its feature after reload")
	}
}

// TestCheckInRefusesAnUnbackedState covers the one exported call that reported
// a tier straight off the state file. A forged state must not be able to get
// "License validated successfully" and its own tier back.
func TestCheckInRefusesAnUnbackedState(t *testing.T) {
	t.Parallel()

	policy := testPolicy()
	pub, _ := testKeyPair(t)
	dir := t.TempDir()

	forgeState(t, dir, policy, &license.ActivationState{
		DeviceHash:  deviceHash(t),
		Tier:        2,
		ActivatedAt: time.Now(),
		Features:    []string{"feat_a"},
	})

	mgr, err := license.NewManagerWithDir(license.NewVerifier(pub, policy), policy, dir)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}

	res := mgr.CheckIn()
	if res.Success {
		t.Errorf("CheckIn() succeeded on a state no signature backs: %+v", res)
	}
	if res.Tier == 2 {
		t.Error("CheckIn() reported the tier the state file claimed")
	}
}

// TestActivateRepairsAnUnverifiedState keeps the operator's way out open.
// Entering a genuine key is how someone recovers a machine whose state file is
// forged, corrupt or signed by a rotated key, so activation must not consult
// the standing it is replacing.
func TestActivateRepairsAnUnverifiedState(t *testing.T) {
	t.Parallel()

	policy := testPolicy()
	pub, priv := testKeyPair(t)
	dir := t.TempDir()

	forgeState(t, dir, policy, &license.ActivationState{
		LicenseKey:  obviouslyFake,
		DeviceHash:  deviceHash(t),
		Tier:        2,
		ActivatedAt: time.Now(),
		Features:    []string{"feat_a"},
	})

	mgr, err := license.NewManagerWithDir(license.NewVerifier(pub, policy), policy, dir)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}
	if mgr.LoadStatus() != license.StatusUnverified {
		t.Fatalf("LoadStatus = %v, want unverified", mgr.LoadStatus())
	}

	if res := mgr.Activate(signToken(t, priv, "testprod", "9001", "SERIAL-REPAIR", 2, 0)); !res.Success {
		t.Fatalf("Activate on an unverified state: %+v", res)
	}
	if !mgr.IsActivated() || !mgr.HasFeature("feat_a") {
		t.Error("a genuine key did not repair the unverified state")
	}
	if got := mgr.LoadStatus(); got != license.StatusLoaded {
		t.Errorf("LoadStatus after repair = %v, want loaded", got)
	}
}
