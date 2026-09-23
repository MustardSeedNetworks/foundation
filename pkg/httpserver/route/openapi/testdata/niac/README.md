# niac OpenAPI golden

Captured from niac-go `178e4c1c` (2026-09-23), where `go run ./cmd/niac-openapi`
reproduces the committed `docs/openapi.yaml` exactly.

- `openapi-source.yaml` and `openapi.yaml` are niac's `docs/` files, verbatim.
- `routes.json` is niac's `api.RouteManifest()` projected onto `route.Policy`:
  every registry route is `auth: true`, `admin` became `scope: "admin"`, the
  `/api/` 404 fallback is `hidden`, and the two unauthenticated introspection
  routes niac registers outside its registry are listed with `auth: false`.
- `error-schema.json` is niac's reflected `api.ErrorResponse` schema.

The test asserts `Generate` reproduces `openapi.yaml` byte for byte. Refresh all
four files together from one niac commit, never one at a time.
