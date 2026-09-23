# ADR 0004 — One route registrar with one canonical order

**Status:** Accepted
**Date:** 2026-09-23

## Context

Seed, stem and niac each declare their API routes as data and compose each
route's middleware in one `register()`, because hand-wrapping at each
registration site is how stem shipped `POST /api/v1/reflector/config` without
authentication (#398). The three registries grew apart:

| Product | Order, outermost first |
| --- | --- |
| niac | recover → auth → limiter → CSRF → admin → method → body |
| stem | limiter → auth → method → body |
| seed | limiter → method → feature → role → body |

niac authenticates every registry route and applies CSRF per route. stem
authenticates per route and applies CSRF globally. seed applies both globally.

Owner decision 10 (2026-09-17, option a) keeps seed, stem and niac on REST
over one shared registrar; the fleet ADR is msn-docs-internal row D-DOC-4.
This ADR records what that registrar decides. `pkg/httpserver/route` is the
registrar and `pkg/httpserver/route/openapi` the emitter.

## Decision

**One order, and the registrar owns it.** Per route, outermost first:

```text
limiter → auth → method gate → CSRF → feature → scope → body cap → handler
```

The cheapest refusal runs first. A flood is refused before a token is parsed.
An unauthenticated caller learns nothing about a route's methods. A wrong method
answers 405 before a CSRF token is demanded, which is the more accurate answer.
The body cap sits nearest the handler so the body is capped before any read.
Products inject what a scope, a licence feature or a limiter *means*
(`Config.Scope`, `Config.Feature`, `Config.Limiters`); they cannot reorder the
layers.

**Every layer is declared per route, and a missing hook panics at
registration.** `Route.Auth` without `Config.Auth`, `Route.CSRF` without a
`csrf.Manager`, or an unknown limiter name stops the daemon at startup, the
way `http.ServeMux` panics on a conflicting pattern. The alternative, skipping
the layer, is the #398 failure again. A product that applied auth or CSRF
globally moves it onto its routes when it adopts, so the manifest and the
OpenAPI document state what is enforced rather than what a global wrapper is
assumed to do.

**The registrar owns the mux and wraps it once.** `Registrar.Handler` puts a
server-assigned request ID, one access-log line and panic recovery around the
whole mux, so an unrouted request and the SPA fallback get them too. A
client-supplied `X-Request-ID` is replaced: trusting it would let a caller
forge the ID that correlates log lines. The access line omits the query
string, which can carry a token. A recovered panic is one error line with the
request ID, and the stack goes to debug, as in `pkg/supervise` (ADR 0003).
`http.ErrAbortHandler` is re-raised.

**The manifest shape is shared.** `Policy` is what `/__capabilities` serves
and what the emitter reads. It keeps the `rateLimited` and `auth` keys that
stem's and niac's contract tests decode. It reports a method-prefixed pattern
(`GET /x`, seed's style) as its bare path and its method.

**The emitter is lifted, not rewritten.** It reproduces niac's committed
`docs/openapi.yaml` byte for byte from niac's registry. That is a CI test over
a fixture captured from niac `178e4c1c`. The two things only a product knows,
its generated-file header and its reflected error schema, are inputs. The
emitter derives "unauthenticated" from `Auth: false` instead of a list of
paths, and it skips `Hidden` catch-alls.

**The route-policy gate ships with the package.** Products run
`check-route-policy.sh` from their pinned module copy (`go list -f '{{.Dir}}'`),
so the gate and the registrar it enforces move on one version. The gate fails
if a product builds its own `ServeMux`, or registers on the default mux,
anywhere in its API tree.

## Consequences

Each adoption row (`S-FDN-1`, `STM-FDN-1`, `N-FDN-1`) changes behaviour. Each
one re-verifies its change on the wire:

- **niac.** Limiters move outside auth, so an unauthenticated request now
  spends the route's write budget before its 401. The budget is per client IP,
  so clients sharing one NAT address share it. niac's `auth.Middleware`
  already had its own per-IP limiter in front of every request, so the new
  exposure is small. The method gate moves outside CSRF. `/__version` and
  `/__capabilities` become `Auth: false` registry routes. The emitter's
  hard-coded public-path list goes away.
- **stem.** CSRF moves from global to per route. Every mutating route must
  declare it, and the registration panics prove none was missed.
- **seed.** Auth and CSRF move from global to per route. `minRole` becomes
  `Scope` and `feature` stays `Feature`. The emitter replaces the hand-kept
  spec, which is what S-FDN-1 asks for.

The manifest keys change as well. niac's `admin: true` becomes
`scope: "admin"`, and seed's `minRole` becomes `scope`. niac's
`TestRoutePolicyManifest` reads `.Admin` from niac's own `RoutePolicy`. It
stays unchanged only if niac keeps that type as a projection of
`route.Policy`. No UI or tool in the three repositories reads
`/__capabilities` (checked 2026-09-23), so the key change affects only each
product's own tests.

Recovery, request IDs and access logging become the registrar's job. Each
product deletes its own copies when it adopts. Two access lines per request, one
from the product and one from the registrar, would be an adoption defect.
