// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"slices"
	"strings"
	"time"
)

const (
	// tierInvalid is the sentinel Info.Tier value before/on validation
	// failure. Not exported: each product names its own tiers.
	tierInvalid = -1

	errProductCodeMismatch = "Product code mismatch for tier"
	// ErrLicenseInvalid is the generic rejection message. Validation failures
	// deliberately do not distinguish "bad signature" from "tampered payload"
	// to a caller — both mean the same thing: not a genuine license.
	ErrLicenseInvalid = "License key is not valid"
)

// Info contains parsed license information.
type Info struct {
	Key         string    `json:"key"`
	Valid       bool      `json:"valid"`
	Tier        int       `json:"tier"`
	ProductCode string    `json:"productCode"`
	Serial      string    `json:"serial"`
	Activated   bool      `json:"activated"`
	ActivatedAt time.Time `json:"activatedAt,omitzero"`
	ExpiresAt   time.Time `json:"expiresAt,omitzero"`
	DeviceHash  string    `json:"deviceHash,omitempty"`
	MaxDevices  int       `json:"maxDevices"`
	Features    []string  `json:"features"`
	ErrorMsg    string    `json:"error,omitempty"`
}

// Validate verifies a signed token and maps it to product feature data via
// the Verifier's ProductPolicy. The signature is checked first (in
// parseAndVerify); only a genuinely signed, current-version payload reaches
// the product-specific interpretation below.
func (v *Verifier) Validate(key string) *Info {
	info := &Info{
		Key:        strings.TrimSpace(key),
		Valid:      false,
		Tier:       tierInvalid,
		MaxDevices: v.policy.DefaultMaxDevices,
	}

	payload, err := v.parseAndVerify(key)
	if err != nil {
		info.ErrorMsg = ErrLicenseInvalid
		return info
	}

	// A correctly signed token for a different product must not validate here.
	if payload.Product != v.policy.ProductName {
		info.ErrorMsg = ErrLicenseInvalid
		return info
	}

	info.ProductCode = payload.Code
	info.Serial = payload.Serial

	// Tier and feature set are authoritative in-policy: the payload's tier is
	// mapped to the feature list the policy defines, so a signed token can
	// only grant what this build knows about. Features are never read from
	// the token.
	features, expectedCode, ok := v.policy.FeaturesForTier(payload.Tier)
	if !ok {
		info.ErrorMsg = "Invalid license tier"
		return info
	}
	info.Tier = payload.Tier
	info.Features = features

	if payload.Code != expectedCode {
		info.ErrorMsg = errProductCodeMismatch
		return info
	}

	if payload.MaxDevices > 0 {
		info.MaxDevices = payload.MaxDevices
	}
	if payload.ExpiresAt > 0 {
		info.ExpiresAt = time.Unix(payload.ExpiresAt, 0).UTC()
		if time.Now().After(info.ExpiresAt) {
			info.ErrorMsg = "License has expired"
			return info
		}
	}

	info.Valid = true
	return info
}

// FormatKey returns a signed token for display. Tokens are already
// display-ready (single line, copy/paste); only surrounding whitespace is
// trimmed. Unlike the old 16-char format, tokens must NOT have characters
// stripped — base64url uses '-' and '_'.
func FormatKey(key string) string {
	return strings.TrimSpace(key)
}

// HasFeature checks if the license includes a specific feature.
func (li *Info) HasFeature(feature string) bool {
	return slices.Contains(li.Features, feature)
}
