# Changelog

## [0.6.0](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.21...v0.6.0) (2026-09-25)


### ⚠ BREAKING CHANGES

* **httpserver:** EnsureCertificate takes a *slog.Logger as its first argument.

### Bug Fixes

* **httpserver:** log every self-signed certificate EnsureCertificate writes ([#77](https://github.com/MustardSeedNetworks/foundation/issues/77)) ([532a255](https://github.com/MustardSeedNetworks/foundation/commit/532a25529448f0541fa0be102922fd788b619a91)), closes [#76](https://github.com/MustardSeedNetworks/foundation/issues/76)

## [0.5.21](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.20...v0.5.21) (2026-09-25)


### Bug Fixes

* **httpserver:** advertise h2 and http/1.1 over ALPN in Listen ([#74](https://github.com/MustardSeedNetworks/foundation/issues/74)) ([38f12fc](https://github.com/MustardSeedNetworks/foundation/commit/38f12fc30a36317449e25c495bad50f94ef4ca56)), closes [#69](https://github.com/MustardSeedNetworks/foundation/issues/69)

## [0.5.20](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.19...v0.5.20) (2026-09-25)


### Features

* **csrf:** let a product derive the CSRF session key ([#72](https://github.com/MustardSeedNetworks/foundation/issues/72)) ([5b93580](https://github.com/MustardSeedNetworks/foundation/commit/5b935801bd84a84970e005857c008c146c4c46fb)), closes [#71](https://github.com/MustardSeedNetworks/foundation/issues/71)

## [0.5.19](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.18...v0.5.19) (2026-09-23)


### Documentation

* README and ADR-0001 stop saying NIAC imports pkg/license ([#67](https://github.com/MustardSeedNetworks/foundation/issues/67)) ([c18ddb1](https://github.com/MustardSeedNetworks/foundation/commit/c18ddb1b75a67bf21c84e95451843d3e1906b52d)), closes [#35](https://github.com/MustardSeedNetworks/foundation/issues/35)

## [0.5.18](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.17...v0.5.18) (2026-09-23)


### Continuous Integration

* gate foundation on the fleet license check ([#65](https://github.com/MustardSeedNetworks/foundation/issues/65)) ([d9ba874](https://github.com/MustardSeedNetworks/foundation/commit/d9ba87434d87cf7fcad828d2de411266fff7c131))

## [0.5.17](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.16...v0.5.17) (2026-09-23)


### Features

* **passkey:** preserve complete credential records ([#62](https://github.com/MustardSeedNetworks/foundation/issues/62)) ([7e27aa3](https://github.com/MustardSeedNetworks/foundation/commit/7e27aa3773df72fa63cad9b021c5c32504d22dbc))

## [0.5.16](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.15...v0.5.16) (2026-09-23)


### Features

* **route:** shared route registrar, canonical order and OpenAPI emitter ([#60](https://github.com/MustardSeedNetworks/foundation/issues/60)) ([c50afad](https://github.com/MustardSeedNetworks/foundation/commit/c50afadb03faea9b37a2cb3bd765b7f394e42361))

## [0.5.15](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.14...v0.5.15) (2026-09-23)


### Features

* **password:** share bounded offline hashing ([#57](https://github.com/MustardSeedNetworks/foundation/issues/57)) ([c336f59](https://github.com/MustardSeedNetworks/foundation/commit/c336f59aeb2d4c79c7da309d2f6b1b038e987b91))

## [0.5.14](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.13...v0.5.14) (2026-09-23)


### Features

* **passkey:** bind single-use browser ceremonies ([#56](https://github.com/MustardSeedNetworks/foundation/issues/56)) ([3093c8a](https://github.com/MustardSeedNetworks/foundation/commit/3093c8aa854430d67964877e92a4b0a3da90cd9e))

## [0.5.13](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.12...v0.5.13) (2026-09-23)


### Features

* **passkey:** enforce shared human sign-in policy ([#54](https://github.com/MustardSeedNetworks/foundation/issues/54)) ([d80f00d](https://github.com/MustardSeedNetworks/foundation/commit/d80f00d6e7652f12d3a5f988ec8a1d2c1fa5ab3b))

## [0.5.12](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.11...v0.5.12) (2026-09-18)


### Features

* **httpserver:** one TLS listener, port fallback and same-port plaintext redirect ([#52](https://github.com/MustardSeedNetworks/foundation/issues/52)) ([f15d5dd](https://github.com/MustardSeedNetworks/foundation/commit/f15d5dd7cb9a7cd00d01e5995f72e795a896ccad))

## [0.5.11](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.10...v0.5.11) (2026-09-18)


### Features

* **supervise:** named workers with panic recovery and ordered stop ([#50](https://github.com/MustardSeedNetworks/foundation/issues/50)) ([9ff504c](https://github.com/MustardSeedNetworks/foundation/commit/9ff504cc2c664d9fd2c7c9c844a8f4f5e89a0e5e)), closes [#47](https://github.com/MustardSeedNetworks/foundation/issues/47)

## [0.5.10](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.9...v0.5.10) (2026-09-17)


### Features

* **instance:** single-instance lock keyed on the data directory ([#48](https://github.com/MustardSeedNetworks/foundation/issues/48)) ([0886b50](https://github.com/MustardSeedNetworks/foundation/commit/0886b50e764fa9cfd1415f5f9c2e55bc05a906da)), closes [#46](https://github.com/MustardSeedNetworks/foundation/issues/46)

## [0.5.9](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.8...v0.5.9) (2026-09-16)


### Bug Fixes

* **license:** bind persisted activation state to its signature ([#42](https://github.com/MustardSeedNetworks/foundation/issues/42)) ([c6c8c3b](https://github.com/MustardSeedNetworks/foundation/commit/c6c8c3b401e2aec65780e87e367fb72a74ef1c67)), closes [#34](https://github.com/MustardSeedNetworks/foundation/issues/34)

## [0.5.8](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.7...v0.5.8) (2026-09-16)


### Bug Fixes

* **license:** classify how activation state loaded and fail closed ([#39](https://github.com/MustardSeedNetworks/foundation/issues/39)) ([859038b](https://github.com/MustardSeedNetworks/foundation/commit/859038b392ae88f7de802624f0c9e987900f4ed9)), closes [#33](https://github.com/MustardSeedNetworks/foundation/issues/33)

## [0.5.7](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.6...v0.5.7) (2026-09-16)


### Bug Fixes

* **license:** persist the token's own expiry on activation ([#37](https://github.com/MustardSeedNetworks/foundation/issues/37)) ([ea07e8a](https://github.com/MustardSeedNetworks/foundation/commit/ea07e8a06d8b96b6d5927f6fcad5b7db9fba376f)), closes [#32](https://github.com/MustardSeedNetworks/foundation/issues/32)

## [0.5.6](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.5...v0.5.6) (2026-09-15)


### Documentation

* **adr:** record the decision to hold the fleet's licence and CSRF core here ([#30](https://github.com/MustardSeedNetworks/foundation/issues/30)) ([09969c1](https://github.com/MustardSeedNetworks/foundation/commit/09969c15a8f0384c4a10aeb7d11e6ff1da72a3e4))

## [0.5.5](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.4...v0.5.5) (2026-09-05)


### Continuous Integration

* give release-please's gh calls a repository ([#27](https://github.com/MustardSeedNetworks/foundation/issues/27)) ([844d077](https://github.com/MustardSeedNetworks/foundation/commit/844d07732e7bd66e874bb4eb3c5b6ddbc7f61e99)), closes [#26](https://github.com/MustardSeedNetworks/foundation/issues/26)

## [0.5.4](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.3...v0.5.4) (2026-09-05)


### Continuous Integration

* arm auto-merge on the release PR ([#24](https://github.com/MustardSeedNetworks/foundation/issues/24)) ([6fbcb1b](https://github.com/MustardSeedNetworks/foundation/commit/6fbcb1bc96d03cc003bd05c479d69163658f47eb)), closes [#23](https://github.com/MustardSeedNetworks/foundation/issues/23)

## [0.5.3](https://github.com/MustardSeedNetworks/foundation/compare/v0.5.2...v0.5.3) (2026-09-04)


### Continuous Integration

* add CodeQL analysis and gate on its open alerts ([#21](https://github.com/MustardSeedNetworks/foundation/issues/21)) ([145a1c5](https://github.com/MustardSeedNetworks/foundation/commit/145a1c585dc1736c188a5e0064ce8bf5ceafa090)), closes [#20](https://github.com/MustardSeedNetworks/foundation/issues/20)
* automate releases with release-please ([#19](https://github.com/MustardSeedNetworks/foundation/issues/19)) ([24e88d4](https://github.com/MustardSeedNetworks/foundation/commit/24e88d45c2ad9fd24bbd103db96ac9cd0836b2d6)), closes [#18](https://github.com/MustardSeedNetworks/foundation/issues/18)
* give main pushes their own concurrency group ([#17](https://github.com/MustardSeedNetworks/foundation/issues/17)) ([b2bf510](https://github.com/MustardSeedNetworks/foundation/commit/b2bf510deb3ba2e2630844a01ee3799f0a5da460)), closes [#16](https://github.com/MustardSeedNetworks/foundation/issues/16)
* give the shared security core the gates its consumers already have ([#15](https://github.com/MustardSeedNetworks/foundation/issues/15)) ([4dcf1a9](https://github.com/MustardSeedNetworks/foundation/commit/4dcf1a9a538e5c25819b63d14c5d8f202c661217)), closes [#14](https://github.com/MustardSeedNetworks/foundation/issues/14)
