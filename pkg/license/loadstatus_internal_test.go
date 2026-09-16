// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// internalTestPolicy mirrors license_test.testPolicy for the in-package tests
// that need to build an on-disk state the exported API cannot produce.
func internalTestPolicy() ProductPolicy {
	return ProductPolicy{
		ProductName: "testprod",
		FeaturesForTier: func(tier int) (features []string, expectedCode string, ok bool) {
			if tier == 2 {
				return []string{"feat_a"}, "9001", true
			}
			return nil, "", false
		},
		EncryptionSalt:    "TEST-PRODUCT-SALT",
		ConfigSubdir:      "testprod",
		LicenseFileName:   ".license",
		DefaultMaxDevices: 3,
		TrialDays:         14,
		TrialTier:         2,
	}
}

// internalSignToken mirrors the keygen wire format so an in-package test can
// mint a genuinely signed token. license_test.signToken is in the external
// test package and cannot be reached from here.
func internalSignToken(t *testing.T, priv ed25519.PrivateKey, tier int, exp int64) string {
	t.Helper()
	payload := map[string]any{
		"v":       1,
		"product": "testprod",
		"code":    "9001",
		"serial":  "SERIAL-INTERNAL",
		"tier":    tier,
		"iat":     time.Now().Add(-400 * day).Unix(),
	}
	if exp > 0 {
		payload["exp"] = exp
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, b)
	return "MSN1." + base64.RawURLEncoding.EncodeToString(b) +
		"." + base64.RawURLEncoding.EncodeToString(sig)
}

func internalTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return pub, priv
}

// writeState lays down a real, decryptable state file. Activate cannot produce
// the ones these tests need — an expired term, or a token that was never
// signed — so building the struct and calling saveState is the only honest
// route to them.
func writeState(t *testing.T, dir string, state *ActivationState) {
	t.Helper()
	pub, _ := internalTestKeyPair(t)
	m, err := NewManagerWithDir(NewVerifier(pub, internalTestPolicy()), internalTestPolicy(), dir)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}
	state.DeviceHash = m.fingerprint.Hash()
	m.state = state
	if saveErr := m.saveState(); saveErr != nil {
		t.Fatalf("saveState: %v", saveErr)
	}
}

// TestLoadStatusFailsClosed covers the four states a licence file can be in on
// startup. A file that exists but cannot be used must never be mistaken for a
// fresh install, and must never be overwritten by an automatic trial: that is
// a paid activation destroyed by a disk fault (#33).
func TestLoadStatusFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		fixture       func(t *testing.T, dir string, priv ed25519.PrivateKey)
		wantStatus    LoadStatus
		wantUsable    bool
		wantLoadErr   bool
		wantTrialOK   bool
		wantActivated bool
	}{
		{
			name:          "missing file is a fresh install",
			fixture:       func(_ *testing.T, _ string, _ ed25519.PrivateKey) {},
			wantStatus:    StatusMissing,
			wantUsable:    true,
			wantTrialOK:   true,
			wantActivated: false,
		},
		{
			name: "unreadable file entitles nothing",
			fixture: func(t *testing.T, dir string, _ ed25519.PrivateKey) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, ".license"), 0o700); err != nil {
					t.Fatalf("mkdir fixture: %v", err)
				}
			},
			wantStatus:  StatusUnreadable,
			wantUsable:  false,
			wantLoadErr: true,
		},
		{
			name: "malformed file entitles nothing",
			fixture: func(t *testing.T, dir string, _ ed25519.PrivateKey) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, ".license"), []byte("not encrypted"), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			},
			wantStatus:  StatusMalformed,
			wantUsable:  false,
			wantLoadErr: true,
		},
		{
			// A signed licence whose term has run out is an authentic file,
			// not a forgery: it stays loaded so StartTrial owes its holder
			// "enter a current key" rather than a trial written over it.
			name: "expired activation loads and stays expired",
			fixture: func(t *testing.T, dir string, priv ed25519.PrivateKey) {
				t.Helper()
				writeState(t, dir, &ActivationState{
					LicenseKey:  internalSignToken(t, priv, 2, time.Now().Add(-1*day).Unix()),
					Tier:        2,
					ActivatedAt: time.Now().Add(-400 * day),
					ExpiresAt:   time.Now().Add(-1 * day),
					Features:    []string{"feat_a"},
				})
			},
			wantStatus:    StatusLoaded,
			wantUsable:    true,
			wantActivated: false,
		},
		{
			// Same shape, but the token was never signed by this fleet key:
			// that is #34's forgery and it entitles nothing.
			name: "state whose token is not signed entitles nothing",
			fixture: func(t *testing.T, dir string, _ ed25519.PrivateKey) {
				t.Helper()
				writeState(t, dir, &ActivationState{
					LicenseKey:  "MSN1.paid-token",
					Tier:        2,
					ActivatedAt: time.Now().Add(-1 * day),
					Features:    []string{"feat_a"},
				})
			},
			wantStatus:  StatusUnverified,
			wantUsable:  false,
			wantLoadErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			pub, priv := internalTestKeyPair(t)
			tc.fixture(t, dir, priv)

			m, err := NewManagerWithDir(NewVerifier(pub, internalTestPolicy()), internalTestPolicy(), dir)
			if err != nil {
				t.Fatalf("NewManagerWithDir: %v", err)
			}
			if got := m.LoadStatus(); got != tc.wantStatus {
				t.Errorf("LoadStatus = %v, want %v", got, tc.wantStatus)
			}
			if got := m.LoadStatus().Usable(); got != tc.wantUsable {
				t.Errorf("Usable = %v, want %v", got, tc.wantUsable)
			}
			if gotErr := m.LoadError(); (gotErr != nil) != tc.wantLoadErr {
				t.Errorf("LoadError = %v, want error: %v", gotErr, tc.wantLoadErr)
			}
			if got := m.IsActivated(); got != tc.wantActivated {
				t.Errorf("IsActivated = %v, want %v", got, tc.wantActivated)
			}

			before := readLicenseBytes(t, dir)
			res := m.StartTrial()
			if res.Success != tc.wantTrialOK {
				t.Errorf("StartTrial success = %v (%q), want %v", res.Success, res.Message, tc.wantTrialOK)
			}
			if !tc.wantTrialOK {
				after := readLicenseBytes(t, dir)
				if string(after) != string(before) {
					t.Error("StartTrial overwrote a licence file it must not touch")
				}
			}
		})
	}
}

// readLicenseBytes returns the raw licence file, or nil when it is absent or
// is not a regular file.
func readLicenseBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, ".license")))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrInvalid) {
			return nil
		}
		return nil
	}
	return b
}

// TestLoadStatusString names every status for the operator-facing log line.
func TestLoadStatusString(t *testing.T) {
	t.Parallel()
	want := map[LoadStatus]string{
		StatusLoaded:     "loaded",
		StatusMissing:    "missing",
		StatusUnreadable: "unreadable",
		StatusMalformed:  "malformed",
		StatusUnverified: "unverified",
		LoadStatus(99):   "unknown",
	}
	for status, name := range want {
		if got := status.String(); got != name {
			t.Errorf("LoadStatus(%d).String() = %q, want %q", int(status), got, name)
		}
	}
}
