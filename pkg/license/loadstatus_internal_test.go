// SPDX-License-Identifier: BUSL-1.1

package license

import (
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

// writeExpiredActivation lays down a real, decryptable state file for a paid
// licence whose term has already run out. Activate cannot produce one: the
// verifier rejects an expired token, so the only honest fixture is the state a
// licence that was valid at activation leaves behind once its expiry passes.
func writeExpiredActivation(t *testing.T, dir string) {
	t.Helper()
	m, err := NewManagerWithDir(nil, internalTestPolicy(), dir)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}
	m.state = &ActivationState{
		LicenseKey:  "MSN1.paid-token",
		DeviceHash:  m.fingerprint.Hash(),
		Tier:        2,
		ActivatedAt: time.Now().Add(-400 * day),
		ExpiresAt:   time.Now().Add(-1 * day),
		Features:    []string{"feat_a"},
	}
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
		fixture       func(t *testing.T, dir string)
		wantStatus    LoadStatus
		wantUsable    bool
		wantLoadErr   bool
		wantTrialOK   bool
		wantActivated bool
	}{
		{
			name:          "missing file is a fresh install",
			fixture:       func(_ *testing.T, _ string) {},
			wantStatus:    StatusMissing,
			wantUsable:    true,
			wantTrialOK:   true,
			wantActivated: false,
		},
		{
			name: "unreadable file entitles nothing",
			fixture: func(t *testing.T, dir string) {
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
			fixture: func(t *testing.T, dir string) {
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
			name:          "expired activation loads and stays expired",
			fixture:       func(t *testing.T, dir string) { t.Helper(); writeExpiredActivation(t, dir) },
			wantStatus:    StatusLoaded,
			wantUsable:    true,
			wantActivated: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tc.fixture(t, dir)

			m, err := NewManagerWithDir(nil, internalTestPolicy(), dir)
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
		LoadStatus(99):   "unknown",
	}
	for status, name := range want {
		if got := status.String(); got != name {
			t.Errorf("LoadStatus(%d).String() = %q, want %q", int(status), got, name)
		}
	}
}
