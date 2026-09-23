# ADR 0001: One shared licence and CSRF core for the fleet

**Status:** Accepted (decided 2026-07-10, recorded 2026-09-14)

## Context

Until July 2026 seed, stem and niac each carried their own Ed25519 licence
verifier and their own per-session CSRF manager. The format was "shared by
convention, each repo owns its own copy, no master module" (stem ADR 0007's
wording at the time). Three copies drifted: seed and stem keyed CSRF tokens on
the raw JWT payload segment while niac keyed on `sha256(bearer)`; a fix to
signature verification or token expiry had to land three times and be
reviewed three times. The licence crypto is the one place a mistake is a
revenue and trust failure for every product at once.

## Decision

The security-critical plumbing lives once, here, and the products import it.

- `pkg/license` — Ed25519 verification of `MSN1.<payload>.<sig>` tokens
  against an embedded fleet public key, device fingerprint and binding,
  trial state, and the AES-GCM activation file keyed from the fingerprint.
  It is product-agnostic: identity and entitlements are injected as a
  `ProductPolicy` (product name, codes, `FeaturesForTier`, encryption salt,
  config paths). Features resolve only from the running build's policy,
  never from the token, so a signed token cannot grant what the build does
  not know about.
- `pkg/csrf` — the per-session token manager keyed on `sha256(bearer)`, with
  a `Protect` middleware that takes the product's error writer. Products keep
  their own exempt list and response format.
- `pkg/corewlan` — added later for the same reason: fleet-shared cgo that
  must be right once (macOS Wi-Fi after the `airport` removal).

Each product keeps a thin layer: `internal/license/policy.go` (codes, tiers,
feature catalog) and its CSRF middleware wrapper. A change to the crypto is a
change here, tagged as a release; Renovate proposes the bump to every
consumer. The module is BUSL-1.1 so seed, itself open-core under BUSL-1.1,
still builds standalone. Seed and Stem import `pkg/license`; NIAC does not
(see Consequences).

## Consequences

- One implementation, one test suite, one review for the licence and CSRF
  paths. The `sha256(bearer)` key is now uniform across seed, stem and niac.
- Consumers' ADRs were written before this move and described the code as
  local; they were amended on 2026-09-14 to point here (seed ADR-0019, stem
  ADR-0006/0007/0009, niac ADR-0004). trellis does not consume `pkg/license`
  (no tier exists for it) and imports only `pkg/corewlan`.
- NIAC stopped runtime licence validation on 2026-08-07 (niac ADR 0005) and
  no longer imports `pkg/license`; it still uses `pkg/csrf`.
- A breaking change to a `pkg/` API is a coordinated bump across the fleet,
  so the packages are kept small and their exported surface changes rarely.
- Nothing here calls out. Validation is offline; the products' opt-in
  auto-upgrade (owner 2026-09-12) is not this module's concern.
- The activation state file's encryption is tamper-evidence and portability
  (a file from one product cannot be renamed into another's config dir), not
  confidentiality against the machine's own user: its key is derived from the
  device fingerprint and a salt compiled into the shipped binary, both of
  which any local process can read. So nothing the file says is an
  entitlement. Every tier and feature the manager reports is re-derived on
  load from the Ed25519 signature that granted it, or from the policy's own
  trial terms (#34). The residual is a user who patches the binary or
  substitutes the embedded public key, which offline validation has always
  accepted; and a trial whose start date is rewritten forward, or a machine
  clock moved backwards past it, is refused rather than honoured, so a legit
  trial can need the operator to clear the file after a clock correction.
- `main` is protected by classic branch protection (`CI Complete` + `Lint PR
  Title`, strict), not by a ruleset; check both endpoints before calling it
  unprotected.
