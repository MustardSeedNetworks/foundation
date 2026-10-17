# Authentication UI capabilities

## Browser passkeys

`src/webauthn.ts` owns native browser JSON conversion and authenticator calls.
Its exports are `supportsPasskeys`, `createPasskeyCredential` and
`getPasskeyCredential`. No HTTP or session policy belongs here.

## Product boundary

`src/contracts.ts` defines `SignInAdapter`, `SignInOutcome` and `AuthFailure`.
Adapters validate wire responses, publish sessions and preserve failed saves.
No token-bearing result is part of the shared interface.

## Package verification

`scripts/test-package.ts` installs the actual packed artifact into an isolated
consumer, checks its license, compiles against its types and imports its runtime.
`scripts/prepare-package.ts` includes the repository license unchanged.

## Release verification

`scripts/release-policy.ts` validates stable UI release tags against package
identity, version and publication destination. `publish-auth-ui.yml` publishes
only the tarball retained by the isolated consumer check, behind the explicit
repository activation gate and protected-environment setup documented in README.
