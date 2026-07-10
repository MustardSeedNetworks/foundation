// SPDX-License-Identifier: BUSL-1.1

// Package license provides fleet-shared offline license validation, device
// binding, trial support, and encrypted on-disk activation state for MSN
// products (Seed, Stem, NIAC). Keys are issued by the canonical keygen
// tool; this package only validates and enforces them.
//
// The core (signing format, device fingerprint, activation state machine) is
// fully generic. Everything that differs per product — the product name a
// token must carry, which wire tiers are recognized and what they grant, the
// on-disk state location, and the trial terms — is supplied by the caller as
// a [ProductPolicy].
package license

// ProductPolicy supplies the product-specific configuration the generic
// license core needs but must not hardcode. Each of Seed/Stem/NIAC
// constructs exactly one ProductPolicy at startup and passes it to
// [NewVerifier] / [NewProductionVerifier] and [NewManager].
type ProductPolicy struct {
	// ProductName is matched against Payload.Product; a token issued for
	// another product is rejected even if correctly signed.
	ProductName string

	// FeaturesForTier maps a signed wire-tier value to the features it
	// grants and the product code expected for that tier. ok=false means
	// the tier is not recognized by this product, and the token is
	// rejected. Features are read only from this function, never from
	// the token itself, so a signed token can only grant what the
	// running build knows about.
	FeaturesForTier func(wireTier int) (features []string, expectedCode string, ok bool)

	// EncryptionSalt is mixed into the on-disk state encryption key so a
	// license file from one product can't be reused by renaming it into
	// another product's config directory.
	EncryptionSalt string

	// ConfigSubdir is the directory name under ~/.config/ where license
	// state is persisted (e.g. "niac").
	ConfigSubdir string

	// LicenseFileName is the file name within ConfigSubdir (e.g.
	// ".license").
	LicenseFileName string

	// DefaultMaxDevices is the device cap assumed until a validated
	// token specifies its own MaxDevices.
	DefaultMaxDevices int

	// TrialDays is the length of the no-token trial period.
	TrialDays int

	// TrialTier is the wire-tier value granted during the trial; its
	// features come from FeaturesForTier(TrialTier).
	TrialTier int
}
