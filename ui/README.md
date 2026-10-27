# Shared authentication interface

This source-available package ships as a tarball attached to each
`auth-ui-vX.Y.Z` GitHub release. It is never published to a registry. Its
independent package version is not the Foundation Go module version.

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
acceptance.

## Installing in a product

Depend on the release asset by exact URL. Never use a local-file dependency, and
never use a git dependency on this repository:

```sh
npm install --save-exact \
  https://github.com/MustardSeedNetworks/foundation/releases/download/auth-ui-v<version>/mustardseednetworks-auth-ui-<version>.tgz
```

The lockfile records the tarball's integrity, so a changed asset fails the
install. To check provenance before adopting a version:

```sh
gh attestation verify mustardseednetworks-auth-ui-<version>.tgz --repo MustardSeedNetworks/foundation
```

npm's seven-day `min-release-age` applies to registry resolution, so it does not
delay this URL dependency, and no exception to the guard is needed. Bumping is
a URL edit; a product that wants Renovate to propose it adds a regex manager
over the URL with the `github-releases` datasource (`extractVersion`
`^auth-ui-v(?<version>.+)$`).

## Releases

Release-please versions `ui` independently and creates `auth-ui-vX.Y.Z` tags.
Foundation's Go releases retain `vX.Y.Z` tags and exclude UI-only changes. Both
components remain in the existing combined release pull request.

When an `auth-ui-v*` release is published, `attach-auth-ui.yml` checks out the
tag, verifies it is on `main`, validates the metadata (`scripts/release-policy.ts`
requires `private: true` and no `publishConfig`), runs lint, typecheck, coverage
and audit, then attests and attaches the exact tarball the isolated consumer
check accepted (`AUTH_UI_ARTIFACT_PATH` tells `npm run test:package` where to
copy it). It never replaces an existing asset: consumers pin its integrity, so a
rerun on an attached release fails closed. To attach to a release published
before this workflow existed, run it with `workflow_dispatch` and the tag.

References: [release-please manifests](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md)
and [artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations).
