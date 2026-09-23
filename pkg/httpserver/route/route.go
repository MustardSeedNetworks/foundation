// SPDX-License-Identifier: BUSL-1.1

// Package route is the fleet's capability registry: a product declares its
// HTTP routes as data and one [Registrar] composes each route's policy in a
// single canonical order.
//
// Hand-nesting middleware at each registration site is how a mutating route
// ships without its auth or CSRF wrapper — stem's POST /api/v1/reflector/config
// went out unauthenticated that way (#398). Seed, stem and niac each grew a
// registry to stop it, with three different orders and three different field
// sets. This is the one they share.
//
// Per route, outermost first:
//
//	limiter → auth → method gate → CSRF → feature → scope → body cap → handler
//
// The cheapest refusal runs first: a flood is refused before the token is
// parsed, an unauthenticated caller learns nothing about which methods a route
// takes, a wrong method answers 405 before a CSRF token is demanded, and the
// body cap sits closest to the handler so the body is capped before any read.
// Around the whole mux, [Registrar.Handler] adds a request ID, an access log
// line and panic recovery.
//
// Policy that a product interprets — what a scope or a licence feature means,
// how a limiter counts — is injected through [Config]; the order is not.
package route

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/MustardSeedNetworks/foundation/pkg/csrf"
)

// ErrorFunc writes the product's JSON error envelope. It is the same
// signature [csrf.Protect] takes, so one adapter serves both.
type ErrorFunc = csrf.ErrorFunc

// Middleware wraps a handler.
type Middleware = func(http.Handler) http.Handler

// Route declares one route and its policy.
type Route struct {
	// Path is the ServeMux pattern. It may carry a method prefix
	// ("GET /api/v1/x"); the mux then enforces the method itself and Methods
	// must be empty.
	Path string

	// Handler is the terminal handler.
	Handler http.HandlerFunc

	// Methods, when set, restricts the route to these methods; any other
	// answers 405 with an Allow header. Empty leaves method dispatch to the
	// handler.
	Methods []string

	// MaxBodyBytes caps the request body. Zero means Config.MaxBodyBytes.
	MaxBodyBytes int64

	// Auth requires Config.Auth to admit the request.
	Auth bool

	// CSRF requires a valid per-session token on state-changing methods.
	CSRF bool

	// Scope is the minimum role or token scope the route requires, as
	// Config.Scope interprets it. Empty means none.
	Scope string

	// Feature is the licence feature the route requires, as Config.Feature
	// interprets it. Empty means none.
	Feature string

	// Limiter names one of Config.Limiters. Empty means unmetered.
	Limiter string

	// Hidden keeps the route out of the OpenAPI document. It is for catch-all
	// fallbacks, whose every-method pattern would document as operations a
	// client could call. The route is still served and still in the manifest.
	Hidden bool
}

// Config is what a product injects. Error and MaxBodyBytes are required; each
// hook is required only once a route asks for it, and a route that asks for a
// missing one panics at registration rather than serving unprotected.
type Config struct {
	// Error renders refusals (405, recovered panics) and is handed to
	// csrf.Protect.
	Error ErrorFunc

	// MaxBodyBytes is the default body cap.
	MaxBodyBytes int64

	// Logger receives the access log and recovered panics. Nil means
	// [slog.Default].
	Logger *slog.Logger

	// Auth admits authenticated requests. Required by any Route.Auth.
	Auth Middleware

	// CSRF holds the per-session tokens. Required by any Route.CSRF.
	CSRF *csrf.Manager

	// Scope returns the gate for one scope. It is called once per route, at
	// registration. Required by any Route.Scope.
	Scope func(scope string) Middleware

	// Feature returns the gate for one licence feature, called once per route
	// at registration. Required by any Route.Feature.
	Feature func(feature string) Middleware

	// Limiters maps each Route.Limiter name to its middleware.
	Limiters map[string]Middleware
}

// Policy is a registered route's policy without its handler: what
// [Registrar.ServeManifest] serves and what the OpenAPI emitter documents.
type Policy struct {
	// Path is the pattern without any method prefix.
	Path    string   `json:"path"`
	Methods []string `json:"methods,omitempty"`
	// MaxBodyBytes is the effective cap, default applied.
	MaxBodyBytes int64  `json:"maxBodyBytes,omitempty"`
	Auth         bool   `json:"auth"`
	CSRF         bool   `json:"csrf"`
	Scope        string `json:"scope,omitempty"`
	Feature      string `json:"feature,omitempty"`
	RateLimited  bool   `json:"rateLimited"`
	Hidden       bool   `json:"hidden,omitempty"`
}

// Registrar owns a ServeMux and installs every route through the canonical
// order. Register routes during setup, then serve [Registrar.Handler]; it is
// not safe to register while serving.
type Registrar struct {
	cfg      Config
	mux      *http.ServeMux
	policies []Policy
}

// New returns a Registrar. It panics if Error or MaxBodyBytes is missing: both
// are needed by every route, so a registrar without them cannot serve one.
func New(cfg Config) *Registrar {
	if cfg.Error == nil {
		panic("route: Config.Error is required")
	}
	if cfg.MaxBodyBytes <= 0 {
		panic("route: Config.MaxBodyBytes must be positive")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Registrar{cfg: cfg, mux: http.NewServeMux()}
}

var knownMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// Register installs rt. Like [http.ServeMux.Handle] it panics on a route that
// cannot be served as declared — a missing hook, an unknown limiter, a
// malformed method — so the mistake stops the daemon at startup instead of
// shipping a route without its protection.
func (g *Registrar) Register(rt Route) {
	path, methods := g.validate(rt)
	if rt.MaxBodyBytes == 0 {
		rt.MaxBodyBytes = g.cfg.MaxBodyBytes
	}
	g.policies = append(g.policies, Policy{
		Path:         path,
		Methods:      methods,
		MaxBodyBytes: rt.MaxBodyBytes,
		Auth:         rt.Auth,
		CSRF:         rt.CSRF,
		Scope:        rt.Scope,
		Feature:      rt.Feature,
		RateLimited:  rt.Limiter != "",
		Hidden:       rt.Hidden,
	})

	// Built innermost first.
	h := bodyLimited(rt.MaxBodyBytes, rt.Handler)
	if rt.Scope != "" {
		h = g.cfg.Scope(rt.Scope)(h)
	}
	if rt.Feature != "" {
		h = g.cfg.Feature(rt.Feature)(h)
	}
	if rt.CSRF {
		h = csrf.Protect(g.cfg.CSRF, g.cfg.Error, h.ServeHTTP)
	}
	if len(rt.Methods) > 0 {
		h = methodGate(rt.Methods, g.cfg.Error, h)
	}
	if rt.Auth {
		h = g.cfg.Auth(h)
	}
	if rt.Limiter != "" {
		h = g.cfg.Limiters[rt.Limiter](h)
	}
	g.mux.Handle(rt.Path, h)
}

// RegisterAll installs each route in order.
func (g *Registrar) RegisterAll(routes []Route) {
	for _, rt := range routes {
		g.Register(rt)
	}
}

// validate panics on a route the registrar cannot serve as declared, and
// returns its bare path and its effective method set.
func (g *Registrar) validate(rt Route) (path string, methods []string) {
	fail := func(format string, args ...any) {
		panic(fmt.Sprintf("route %q: ", rt.Path) + fmt.Sprintf(format, args...))
	}
	if rt.Handler == nil {
		fail("nil Handler")
	}
	if rt.MaxBodyBytes < 0 {
		fail("negative MaxBodyBytes")
	}
	for _, m := range rt.Methods {
		if !slices.Contains(knownMethods, m) {
			fail("unknown method %q", m)
		}
	}
	switch {
	case rt.Auth && g.cfg.Auth == nil:
		fail("Auth set but Config.Auth is nil")
	case rt.CSRF && g.cfg.CSRF == nil:
		fail("CSRF set but Config.CSRF is nil")
	case rt.Scope != "" && g.cfg.Scope == nil:
		fail("Scope %q set but Config.Scope is nil", rt.Scope)
	case rt.Feature != "" && g.cfg.Feature == nil:
		fail("Feature %q set but Config.Feature is nil", rt.Feature)
	case rt.Limiter != "" && g.cfg.Limiters[rt.Limiter] == nil:
		fail("unknown Limiter %q", rt.Limiter)
	}

	path, methods = rt.Path, rt.Methods
	if m, rest, ok := strings.Cut(rt.Path, " "); ok {
		if !slices.Contains(knownMethods, m) {
			fail("unknown method prefix %q", m)
		}
		if len(rt.Methods) > 0 {
			fail("Methods set on a method-prefixed pattern")
		}
		path, methods = strings.TrimLeft(rest, " "), []string{m}
	}
	if !strings.HasPrefix(path, "/") {
		fail("path must start with /")
	}
	return path, methods
}

// Policies returns every registered route's policy in registration order.
func (g *Registrar) Policies() []Policy {
	return slices.Clone(g.policies)
}

// ServeManifest serves Policies as JSON. Register it as a GET route with Auth
// false: like /__version, the manifest is a deployment and audit surface, and
// it names no secret.
func (g *Registrar) ServeManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(g.policies); err != nil {
		g.cfg.Logger.ErrorContext(r.Context(), "encoding the route manifest", "error", err)
	}
}

// Handler returns the mux wrapped in the request ID, access log and panic
// recovery, outermost first. Every request passes through them, routed or
// not.
func (g *Registrar) Handler() http.Handler {
	return withRequestID(logRequests(g.cfg.Logger, recoverPanics(g.cfg.Logger, g.cfg.Error, g.mux)))
}

// methodGate answers 405 with an Allow header for a method outside allowed.
func methodGate(allowed []string, writeErr ErrorFunc, next http.Handler) http.Handler {
	allow := strings.Join(allowed, ", ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(allowed, r.Method) {
			w.Header().Set("Allow", allow)
			writeErr(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bodyLimited caps the body before the handler reads it. The reader gets
// net/http's own writer: on hitting the cap it type-asserts that writer to
// close the connection after the reply (the rest of the body is still in
// flight), and a wrapper in between would silently disable that. The handler
// still writes through w.
func bodyLimited(limit int64, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(innermost(w), r.Body, limit)
		next(w, r)
	})
}

// innermost follows Unwrap to the writer net/http created.
func innermost(w http.ResponseWriter) http.ResponseWriter {
	for {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = u.Unwrap()
	}
}
