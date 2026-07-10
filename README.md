# foundation

Fleet-shared, security-critical plumbing for the MustardSeedNetworks products
(**Seed**, **Stem**, **NIAC**). One implementation, tested once, consumed by all
three — so a fix to license validation or CSRF lands in **one place**, not three.

Source-available under **BUSL-1.1** (same as Seed) so Seed still builds
standalone as open-core; Stem and NIAC (proprietary, MSN-owned) import it freely.

## Packages

| Import | What it is |
|--------|-----------|
| `github.com/MustardSeedNetworks/foundation/pkg/license` | Offline Ed25519 license validation, device fingerprint/binding, trial + encrypted on-disk activation state. Product-agnostic core; per-product policy injected. |
| `github.com/MustardSeedNetworks/foundation/pkg/csrf` | Per-session CSRF token manager, keyed on `sha256(bearer)`, with a `Protect` middleware. The canonical CSRF implementation for the fleet. |

## The product-policy pattern (license)

The crypto core is identical across products; only the product's *identity and
entitlements* differ. Those are injected, never hardcoded:

```go
policy := license.ProductPolicy{
    ProductName:     "niac",
    FeaturesForTier: niacFeaturesForTier, // wire-tier int -> (features, expectedCode, ok)
    EncryptionSalt:  "MSN-NIAC-SIM-2026-LICENSE",
    ConfigSubdir:    "niac",
    LicenseFileName: ".license",
    // TrialDays, TrialTier, DefaultMaxDevices...
}
v := license.NewProductionVerifier(policy) // embedded fleet public key
mgr := license.NewManager(v, policy)
```

Features are resolved **only** from `FeaturesForTier`, never read from the signed
token — a signed token can only grant what the running build knows about. Each
product keeps its own feature catalog; only the crypto lives here.

## Layout note (do not "fix")

Packages live under `pkg/` deliberately. A top-level directory named `license/`
collides with the `LICENSE` file on case-insensitive filesystems (default macOS
APFS, Windows), so a repo-root `license/` package is not portable. `pkg/`
sidesteps it permanently.

## Signing key

The embedded Ed25519 public key verifies production tokens for the whole fleet
(one keypair). The private key lives only in `msn-internal-tools/keygen` and
never ships. **Pre-launch key — rotate via keygen before GA.**
