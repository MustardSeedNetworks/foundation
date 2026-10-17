# Shared authentication interface

This source-available package is prepared for public npm publication, but
publication is disabled pending operator setup. Its independent package version
is not the Foundation Go module version.

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
acceptance. Consumers must pin a released registry version; no local-file
dependency may ship. The approved release-age exception applies only to this
first-party package and must be configured during consumer adoption, without
lowering the seven-day guard for other dependencies.

## Release preparation and activation

Release-please versions `ui` independently and creates `auth-ui-vX.Y.Z` tags.
Foundation's Go releases retain `vX.Y.Z` tags and exclude UI-only changes. Both
components remain in the existing combined release pull request.

The publication workflow is disabled unless the repository variable
`AUTH_UI_NPM_PUBLISH_ENABLED` is exactly `true`. Before enabling it:

1. Confirm the npm account and `mustardseednetworks` organization exist and the
   owner can publish `@mustardseednetworks/auth-ui` using interactive 2FA.
2. Resolve the root LICENSE's current licensed-work attribution (`The Seed`)
   with the owner. This preparation does not change or approve legal terms.
3. If npm requires the package to exist before configuring trust, the owner
   must bootstrap its first publication from the reviewed release commit,
   using the same validation commands above and the verified tarball. Do not
   introduce a persistent npm token into CI.
4. Configure the GitHub environment `npm-auth-ui` with a required reviewer and
   deployment restrictions allowing only `auth-ui-v*` tags. Naming an
   environment in YAML does not create these protections.
5. Configure npm trusted publishing for GitHub organization
   `MustardSeedNetworks`, repository `foundation`, workflow
   `publish-auth-ui.yml`, and environment `npm-auth-ui`. Verify the repository
   is public so npm can generate provenance for the public package. Explicitly
   allow direct publication for this trusted publisher; a stage-only permission
   does not authorize this workflow's `npm publish` operation.
6. Verify all prerequisites before enabling the repository variable. An absent
   or false variable keeps publication disabled.

The workflow checks out the release's exact SHA, verifies its stable UI tag and
package metadata, runs validation, and publishes the exact tarball tested by the
isolated consumer. `AUTH_UI_ARTIFACT_PATH` tells `npm run test:package` where to
copy that tarball after its checks pass; publication uses `--ignore-scripts` so
it cannot rebuild or repack it. GitHub-hosted runners authenticate through OIDC,
not an npm write key.

After publication, verify the registry version, integrity and provenance against
the reviewed release and tested artifact. Publishing an existing version fails
closed, including on workflow reruns: inspect the existing package instead of
unpublishing, overwriting or automatically incrementing its version.

References: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
and [release-please manifests](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md).
