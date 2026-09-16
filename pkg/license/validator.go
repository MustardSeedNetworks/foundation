// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"errors"
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

// Reasons a token is not authentic for this product. They are not exported:
// callers get the generic ErrLicenseInvalid message, and only this package
// needs to tell the cases apart.
var (
	errWrongProduct = errors.New("license token names another product")
	errUnknownTier  = errors.New("license tier is not recognized by this product")
	errCodeMismatch = errors.New("product code does not match the token's tier")
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
// the product-specific interpretation below. A token whose term has run out
// is not valid.
func (v *Verifier) Validate(key string) *Info {
	info, err := v.verify(key)
	if err != nil {
		return info
	}
	if !info.ExpiresAt.IsZero() && time.Now().After(info.ExpiresAt) {
		info.ErrorMsg = "License has expired"
		return info
	}
	info.Valid = true
	return info
}

// verify authenticates a token and interprets its payload under the policy,
// stopping short of judging whether the term has run out. Expiry is a runtime
// condition rather than a property of the token, and re-reading persisted
// activation state needs the two apart: an authentic licence that has simply
// run out is a known file with a known meaning, while one that was never
// signed is a forgery. Only the second must fail closed.
//
// A non-nil error means the token is not authentic for this product; info
// carries the operator-facing reason and is safe to return as-is.
func (v *Verifier) verify(key string) (*Info, error) {
	info := &Info{
		Key:        strings.TrimSpace(key),
		Valid:      false,
		Tier:       tierInvalid,
		MaxDevices: v.policy.DefaultMaxDevices,
	}

	payload, err := v.parseAndVerify(key)
	if err != nil {
		info.ErrorMsg = ErrLicenseInvalid
		return info, err
	}

	// A correctly signed token for a different product must not validate here.
	if payload.Product != v.policy.ProductName {
		info.ErrorMsg = ErrLicenseInvalid
		return info, errWrongProduct
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
		return info, errUnknownTier
	}
	info.Tier = payload.Tier
	info.Features = features

	if payload.Code != expectedCode {
		info.ErrorMsg = errProductCodeMismatch
		return info, errCodeMismatch
	}

	if payload.MaxDevices > 0 {
		info.MaxDevices = payload.MaxDevices
	}
	if payload.ExpiresAt > 0 {
		info.ExpiresAt = time.Unix(payload.ExpiresAt, 0).UTC()
	}
	return info, nil
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
