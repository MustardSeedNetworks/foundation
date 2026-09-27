# Shared authentication interface

This package is under development and cannot yet be published (`private: true`).
Its independent package version is not the Foundation Go module version.
Registry access and release automation must be established before publication.

## Boundary

The shared interface receives semantic outcomes, never access or refresh tokens.
Product adapters own validated HTTP responses, secure cookies, CSRF, refresh,
authorization and publication of the authenticated session. An authenticated
outcome is permitted only after required credential state is durably saved.
TOTP challenges remain in memory and are not successful sign-ins.

Passkey sign-in uses discoverable credentials through the standard browser JSON
API. A cancelled or timed-out browser ceremony is not a server authentication
failure; browsers may report both as `NotAllowedError`. Do not infer which one
occurred from that exception alone. Unsupported browsers require the password
path; do not substitute incomplete credential serialization.

The interface describes the shared target, not current product readiness:

- Seed must replace its username-dependent passkey ceremony and complete its
  fail-closed persistence fix before implementing this adapter.
- Stem must integrate restart-safe credential storage before claiming readiness.
- NIAC must implement human sessions and authentication endpoints first.

Setup, account recovery and account-security screens are subsequent slices.
Their server-enforced ownership and recent-authentication boundaries must exist
before replacing the corresponding product flows. Existing TOTP stays supported.
Sharing this package does not share accounts or introduce cross-product SSO.

## Validation

Use the repository's pinned Node/npm versions, then run from this directory:

```sh
npm ci
npm run lint
npm run typecheck
npm test
npm run test:package
npm audit
```

The package test installs a tarball into a separate temporary consumer and
checks exported types and runtime imports. It is not product adoption or browser
acceptance. Consumers must pin a released registry version, subject to the
existing seven-day release-age policy; no local-file dependency may ship.
