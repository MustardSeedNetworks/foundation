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
| `github.com/MustardSeedNetworks/foundation/pkg/instance` | Single-instance lock keyed on a daemon's data directory (`flock` on unix, `LockFileEx` on Windows). A second daemon on the same data directory is refused by the holder's PID and port instead of starting beside it on a fallback port. |
| `github.com/MustardSeedNetworks/foundation/pkg/httpserver` | The one HTTPS listener: canonical-port fallback (+1..+9, with the Windows WinNAT case the products had diverged on), TLS 1.3 by default with a TLS 1.2 floor, a self-signed ECDSA default that covers loopback, and a same-port plaintext&#8594;308 redirect so `host:8443` typed without a scheme reaches the https page instead of a connection refused. |
| `github.com/MustardSeedNetworks/foundation/pkg/httpserver/route` | The capability registry: routes declared as data (methods, body cap, auth, CSRF, scope, licence feature, limiter) and composed in one canonical order, with a request ID, access log and panic recovery around the mux, a `/__capabilities` manifest, and `check-route-policy.sh` to keep every route on it. Its `openapi` subpackage renders the product's OpenAPI document from the same table. See [ADR 0004](docs/adr/0004-one-route-registrar-with-one-canonical-order.md). |
| `github.com/MustardSeedNetworks/foundation/pkg/corewlan` | macOS Wi-Fi via Apple's CoreWLAN framework (cgo + Objective-C): scan, associated network, interface list, saved networks, associate/disassociate, radio power. Replaces the `airport` CLI, removed in macOS 26. **darwin-only** — a `!darwin` stub returns `ErrUnsupported`. |

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

## Decisions

Why this module exists and what stays per-product: [`docs/adr/`](docs/adr/README.md).

## Layout note (do not "fix")

Packages live under `pkg/` deliberately. A top-level directory named `license/`
collides with the `LICENSE` file on case-insensitive filesystems (default macOS
APFS, Windows), so a repo-root `license/` package is not portable. `pkg/`
sidesteps it permanently.

## Signing key

The embedded Ed25519 public key verifies production tokens for the whole fleet
(one keypair). The private key lives only in `msn-internal-tools/keygen` and
never ships. **Pre-launch key — rotate via keygen before GA.**
