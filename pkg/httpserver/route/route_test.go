// SPDX-License-Identifier: BUSL-1.1

package route_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/csrf"
	"github.com/MustardSeedNetworks/foundation/pkg/httpserver/route"
)

const defaultBody = 1 << 20

// jsonError is a product-shaped envelope, so a test can tell the product's
// renderer answered rather than net/http's text.
func jsonError(w http.ResponseWriter, _ *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

// trace records which layers a request passed through, in order.
type trace struct {
	mu    sync.Mutex
	steps []string
}

func (tr *trace) add(step string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.steps = append(tr.steps, step)
}

func (tr *trace) get() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return slices.Clone(tr.steps)
}

func (tr *trace) layer(name string) route.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr.add(name)
			next.ServeHTTP(w, r)
		})
	}
}

// deny is a layer that refuses, for proving what runs outside it.
func deny(tr *trace, name string, status int) route.Middleware {
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tr.add(name)
			jsonError(w, r, status, name, "denied")
		})
	}
}

func tracedConfig(tr *trace, mgr *csrf.Manager) route.Config {
	return route.Config{
		Error:        jsonError,
		MaxBodyBytes: defaultBody,
		Logger:       slog.New(slog.DiscardHandler),
		Auth:         tr.layer("auth"),
		CSRF:         mgr,
		Scope:        func(s string) route.Middleware { return tr.layer("scope:" + s) },
		Feature:      func(f string) route.Middleware { return tr.layer("feature:" + f) },
		Limiters:     map[string]route.Middleware{"write": tr.layer("limiter:write")},
	}
}

func ok(tr *trace) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		tr.add("handler")
		w.WriteHeader(http.StatusNoContent)
	}
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// csrfRequest returns a request carrying a bearer and, when withToken, the
// session's valid CSRF token.
func csrfRequest(t *testing.T, mgr *csrf.Manager, method, target string, withToken bool) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	req.Header.Set("Authorization", "Bearer test-bearer")
	if withToken {
		token, err := mgr.GetOrCreate(csrf.SessionKeyFromRequest(req))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Csrf-Token", token)
	}
	return req
}

// TestCanonicalOrder pins the one composition every product gets: a
// fully-declared route runs limiter → auth → (method gate) → CSRF → feature →
// scope → handler.
func TestCanonicalOrder(t *testing.T) {
	tr := &trace{}
	mgr := csrf.NewManager()
	t.Cleanup(mgr.Stop)
	g := route.New(tracedConfig(tr, mgr))
	g.Register(route.Route{
		Path: "/api/v1/config/import", Handler: ok(tr), Methods: []string{http.MethodPost},
		Auth: true, CSRF: true, Scope: "admin", Feature: "import", Limiter: "write",
	})

	rec := serve(g.Handler(), csrfRequest(t, mgr, http.MethodPost, "/api/v1/config/import", true))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body %s", rec.Code, rec.Body)
	}
	want := []string{"limiter:write", "auth", "feature:import", "scope:admin", "handler"}
	if got := tr.get(); !slices.Equal(got, want) {
		t.Errorf("layers = %v, want %v", got, want)
	}
}

// TestRefusalPrecedence proves each layer's position by what runs before a
// refusal: the cheapest refusal wins, and nothing inside it runs.
func TestRefusalPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		cfg        func(*route.Config, *trace)
		method     string
		withToken  bool
		wantStatus int
		wantCode   string
		wantSteps  []string
	}{
		{
			name:       "limiter refuses before auth",
			cfg:        func(c *route.Config, tr *trace) { c.Limiters["write"] = deny(tr, "limited", 429) },
			method:     http.MethodPost,
			withToken:  true,
			wantStatus: 429, wantCode: "limited",
			wantSteps: []string{"limited"},
		},
		{
			name:       "auth refuses before the method gate",
			cfg:        func(c *route.Config, tr *trace) { c.Auth = deny(tr, "unauthorized", 401) },
			method:     http.MethodDelete,
			withToken:  true,
			wantStatus: 401, wantCode: "unauthorized",
			wantSteps: []string{"limiter:write", "unauthorized"},
		},
		{
			name:       "wrong method answers 405 before CSRF is demanded",
			method:     http.MethodDelete,
			withToken:  false,
			wantStatus: 405, wantCode: "method_not_allowed",
			wantSteps: []string{"limiter:write", "auth"},
		},
		{
			name:       "missing CSRF token refuses before feature and scope",
			method:     http.MethodPost,
			withToken:  false,
			wantStatus: 403, wantCode: "csrf_token_missing",
			wantSteps: []string{"limiter:write", "auth"},
		},
		{
			name: "feature refuses before scope",
			cfg: func(c *route.Config, tr *trace) {
				c.Feature = func(string) route.Middleware { return deny(tr, "unlicensed", 402) }
			},
			method:     http.MethodPost,
			withToken:  true,
			wantStatus: 402, wantCode: "unlicensed",
			wantSteps: []string{"limiter:write", "auth", "unlicensed"},
		},
		{
			name: "scope refuses before the handler",
			cfg: func(c *route.Config, tr *trace) {
				c.Scope = func(string) route.Middleware { return deny(tr, "forbidden", 403) }
			},
			method:     http.MethodPost,
			withToken:  true,
			wantStatus: 403, wantCode: "forbidden",
			wantSteps: []string{"limiter:write", "auth", "feature:import", "forbidden"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &trace{}
			mgr := csrf.NewManager()
			t.Cleanup(mgr.Stop)
			cfg := tracedConfig(tr, mgr)
			if tt.cfg != nil {
				tt.cfg(&cfg, tr)
			}
			g := route.New(cfg)
			g.Register(route.Route{
				Path: "/api/v1/x", Handler: ok(tr), Methods: []string{http.MethodPost},
				Auth: true, CSRF: true, Scope: "admin", Feature: "import", Limiter: "write",
			})

			rec := serve(g.Handler(), csrfRequest(t, mgr, tt.method, "/api/v1/x", tt.withToken))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body)
			}
			var body struct{ Code string }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != tt.wantCode {
				t.Errorf("body = %s, want the product envelope with code %q", rec.Body, tt.wantCode)
			}
			if got := tr.get(); !slices.Equal(got, tt.wantSteps) {
				t.Errorf("layers = %v, want %v", got, tt.wantSteps)
			}
		})
	}
}

// TestSessionKeyHook proves Config.SessionKey decides which token a CSRF
// route demands. A cookie session carries no Authorization header, so without
// the hook the registrar would validate against the header key and refuse
// every browser mutation.
func TestSessionKeyHook(t *testing.T) {
	tr := &trace{}
	mgr := csrf.NewManager()
	t.Cleanup(mgr.Stop)
	cfg := tracedConfig(tr, mgr)
	cfg.SessionKey = func(r *http.Request) (string, bool) {
		c, err := r.Cookie("session")
		if err != nil {
			return "", false
		}
		return csrf.SessionKey(c.Value), true
	}
	g := route.New(cfg)
	g.Register(route.Route{Path: "/api/v1/x", Handler: ok(tr), Methods: []string{http.MethodPost}, CSRF: true})
	cookieToken, err := mgr.GetOrCreate(csrf.SessionKey("cookie-jwt"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		cookie     bool
		token      string
		wantStatus int
	}{
		{name: "cookie session with its token", cookie: true, token: cookieToken, wantStatus: http.StatusNoContent},
		{name: "cookie session without a token", cookie: true, wantStatus: http.StatusForbidden},
		{name: "no session at all", wantStatus: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/x", nil)
			if tt.cookie {
				req.Header.Set("Cookie", "session=cookie-jwt")
			}
			if tt.token != "" {
				req.Header.Set("X-Csrf-Token", tt.token)
			}
			if rec := serve(g.Handler(), req); rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

// TestMethodGateRejectsWrongMethod is niac's contract: a GET-only route
// answers another method with 405, an Allow header and the product's envelope,
// and the handler never runs.
func TestMethodGateRejectsWrongMethod(t *testing.T) {
	tr := &trace{}
	g := route.New(tracedConfig(tr, nil))
	g.Register(route.Route{
		Path: "/api/v1/topology", Handler: ok(tr), Methods: []string{http.MethodGet}, Auth: true,
	})

	rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/topology", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow = %q, want GET", allow)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want the product's JSON envelope", ct)
	}
	if slices.Contains(tr.get(), "handler") {
		t.Error("handler ran for a refused method")
	}
}

// TestUndeclaredMethodsReachTheHandler: an empty method set leaves dispatch to
// a handler that switches on the method itself.
func TestUndeclaredMethodsReachTheHandler(t *testing.T) {
	tr := &trace{}
	g := route.New(tracedConfig(tr, nil))
	g.Register(route.Route{Path: "/api/v1/devices", Handler: ok(tr)})

	if rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/v1/devices", nil)); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

// TestBodyCap: the default cap applies when a route names none, a route's own
// cap overrides it, and an oversized body fails the handler's read.
func TestBodyCap(t *testing.T) {
	var readErr error
	reader := func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: 8, Logger: slog.New(slog.DiscardHandler)})
	g.Register(route.Route{Path: "/small", Handler: reader})
	g.Register(route.Route{Path: "/large", Handler: reader, MaxBodyBytes: 64})

	tests := []struct {
		path    string
		size    int
		wantErr bool
	}{
		{"/small", 8, false},
		{"/small", 9, true},
		{"/large", 64, false},
		{"/large", 65, true},
	}
	for _, tt := range tests {
		readErr = nil
		serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, tt.path, strings.NewReader(strings.Repeat("x", tt.size))))
		var tooLarge *http.MaxBytesError
		if got := errors.As(readErr, &tooLarge); got != tt.wantErr {
			t.Errorf("%s with %d bytes: read error = %v, want MaxBytesError %v", tt.path, tt.size, readErr, tt.wantErr)
		}
	}
}

// TestManifest is the contract niac's and stem's route_test.go assert through
// /__capabilities: every route is listed with its effective policy, the body
// cap is never zero, and a method-prefixed pattern reports its method and its
// bare path.
func TestManifest(t *testing.T) {
	tr := &trace{}
	mgr := csrf.NewManager()
	t.Cleanup(mgr.Stop)
	g := route.New(tracedConfig(tr, mgr))
	g.RegisterAll([]route.Route{
		{Path: "/__capabilities", Handler: g.ServeManifest, Methods: []string{http.MethodGet}},
		{Path: "/api/v1/auth/login", Handler: ok(tr), Methods: []string{http.MethodPost}, Limiter: "write"},
		{Path: "/api/v1/topology", Handler: ok(tr), Methods: []string{http.MethodGet}, Auth: true},
		{
			Path: "/api/v1/config/import", Handler: ok(tr), Methods: []string{http.MethodPost},
			MaxBodyBytes: 4 << 20, Auth: true, CSRF: true, Scope: "admin", Limiter: "write",
		},
		{Path: "GET /api/v1/reports", Handler: ok(tr), Auth: true, Feature: "reports"},
		{Path: "/api/", Handler: ok(tr), Auth: true, Hidden: true},
	})

	rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/__capabilities", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /__capabilities: status = %d, want 200", rec.Code)
	}
	var got []route.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	want := []route.Policy{
		{Path: "/__capabilities", Methods: []string{"GET"}, MaxBodyBytes: defaultBody},
		{Path: "/api/v1/auth/login", Methods: []string{"POST"}, MaxBodyBytes: defaultBody, RateLimited: true},
		{Path: "/api/v1/topology", Methods: []string{"GET"}, MaxBodyBytes: defaultBody, Auth: true},
		{
			Path: "/api/v1/config/import", Methods: []string{"POST"}, MaxBodyBytes: 4 << 20,
			Auth: true, CSRF: true, Scope: "admin", RateLimited: true,
		},
		{Path: "/api/v1/reports", Methods: []string{"GET"}, MaxBodyBytes: defaultBody, Auth: true, Feature: "reports"},
		{Path: "/api/", MaxBodyBytes: defaultBody, Auth: true, Hidden: true},
	}
	if len(got) != len(want) {
		t.Fatalf("manifest has %d routes, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !policyEqual(got[i], want[i]) {
			t.Errorf("manifest[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if !slices.EqualFunc(got, g.Policies(), policyEqual) {
		t.Error("ServeManifest and Policies disagree")
	}

}

// TestMethodPrefixIsEnforcedByTheMux: a method-prefixed pattern gets no method
// gate of its own; ServeMux answers the other methods with 405. (A catch-all
// such as "/api/" would take them instead, as ServeMux falls through to it.)
func TestMethodPrefixIsEnforcedByTheMux(t *testing.T) {
	tr := &trace{}
	g := route.New(tracedConfig(tr, nil))
	g.Register(route.Route{Path: "GET /api/v1/reports", Handler: ok(tr), Auth: true})

	if rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/reports", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to a GET-prefixed pattern: status = %d, want 405", rec.Code)
	}
	if rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/reports", nil)); rec.Code != http.StatusNoContent {
		t.Errorf("GET: status = %d, want 204", rec.Code)
	}
}

func policyEqual(a, b route.Policy) bool {
	return a.Path == b.Path && slices.Equal(a.Methods, b.Methods) && a.MaxBodyBytes == b.MaxBodyBytes &&
		a.Auth == b.Auth && a.CSRF == b.CSRF && a.Scope == b.Scope && a.Feature == b.Feature &&
		a.RateLimited == b.RateLimited && a.Hidden == b.Hidden
}

// TestRegisterRefusesUnservableRoutes: a route that asks for protection the
// registrar cannot apply stops the daemon at startup rather than serving
// unprotected.
func TestRegisterRefusesUnservableRoutes(t *testing.T) {
	h := func(http.ResponseWriter, *http.Request) {}
	bare := route.Config{Error: jsonError, MaxBodyBytes: defaultBody}
	tests := []struct {
		name string
		rt   route.Route
		want string
	}{
		{"auth without a hook", route.Route{Path: "/a", Handler: h, Auth: true}, "Config.Auth is nil"},
		{"csrf without a manager", route.Route{Path: "/a", Handler: h, CSRF: true}, "Config.CSRF is nil"},
		{"scope without a hook", route.Route{Path: "/a", Handler: h, Scope: "admin"}, "Config.Scope is nil"},
		{"feature without a hook", route.Route{Path: "/a", Handler: h, Feature: "x"}, "Config.Feature is nil"},
		{"unknown limiter", route.Route{Path: "/a", Handler: h, Limiter: "write"}, `unknown Limiter "write"`},
		{"nil handler", route.Route{Path: "/a"}, "nil Handler"},
		{"lower-case method", route.Route{Path: "/a", Handler: h, Methods: []string{"get"}}, `unknown method "get"`},
		{"methods on a prefixed pattern", route.Route{Path: "GET /a", Handler: h, Methods: []string{"GET"}}, "method-prefixed"},
		{"unknown method prefix", route.Route{Path: "FETCH /a", Handler: h}, "unknown method prefix"},
		{"relative path", route.Route{Path: "a", Handler: h}, "must start with /"},
		{"negative body cap", route.Route{Path: "/a", Handler: h, MaxBodyBytes: -1}, "negative MaxBodyBytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				msg, _ := recover().(string)
				if !strings.Contains(msg, tt.want) {
					t.Errorf("panic = %q, want it to name %q", msg, tt.want)
				}
			}()
			route.New(bare).Register(tt.rt)
		})
	}
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	for name, cfg := range map[string]route.Config{
		"no error renderer": {MaxBodyBytes: defaultBody},
		"no body cap":       {Error: jsonError},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("New did not panic")
				}
			}()
			route.New(cfg)
		})
	}
}

// TestRecoverAnswersInTheProductEnvelope: a panicking handler becomes a
// logged 500 in the product's JSON, with the request ID on both.
func TestRecoverAnswersInTheProductEnvelope(t *testing.T) {
	var logs bytes.Buffer
	g := route.New(route.Config{
		Error: jsonError, MaxBodyBytes: defaultBody,
		Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	g.Register(route.Route{Path: "/boom", Handler: func(http.ResponseWriter, *http.Request) { panic(errors.New("kaboom")) }})

	rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var body struct{ Code string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "internal_server_error" {
		t.Errorf("body = %s, want the product envelope", rec.Body)
	}
	id := rec.Header().Get(route.RequestIDHeader)
	var panicLine, stackLine, accessLine map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		switch entry["msg"] {
		case "panic recovered":
			panicLine = entry
		case "panic stack":
			stackLine = entry
		case "http request":
			accessLine = entry
		}
	}
	if panicLine == nil || panicLine["panic"] != "kaboom" || panicLine["request_id"] != id || panicLine["level"] != "ERROR" {
		t.Errorf("panic log = %v, want one error line with the value and request ID %q", panicLine, id)
	}
	if _, inline := panicLine["stack"]; inline {
		t.Error("the stack is on the operator's error line; it belongs at debug")
	}
	stack, _ := stackLine["stack"].(string)
	if stackLine["level"] != "DEBUG" || stackLine["request_id"] != id || !strings.Contains(stack, "route_test.go") {
		t.Errorf("stack log = %v, want a debug line naming the handler", stackLine)
	}
	if accessLine == nil || accessLine["status"] != float64(http.StatusInternalServerError) {
		t.Errorf("access log = %v, want status 500", accessLine)
	}
}

// TestRecoverAfterWriteDoesNotRewrite: once the status line is out a 500
// cannot replace it, so recovery must not append an envelope to the body.
func TestRecoverAfterWriteDoesNotRewrite(t *testing.T) {
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: defaultBody, Logger: slog.New(slog.DiscardHandler)})
	g.Register(route.Route{Path: "/half", Handler: func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("late")
	}})

	rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/half", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "partial" {
		t.Errorf("status %d body %q, want the handler's own 200 and body untouched", rec.Code, rec.Body)
	}
}

// TestRecoverReraisesAbort: http.ErrAbortHandler is how a handler asks net/http
// to cut the response; recovering it would answer the request instead.
func TestRecoverReraisesAbort(t *testing.T) {
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: defaultBody, Logger: slog.New(slog.DiscardHandler)})
	g.Register(route.Route{Path: "/abort", Handler: func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }})

	defer func() {
		v := recover()
		if err, _ := v.(error); !errors.Is(err, http.ErrAbortHandler) {
			t.Errorf("recovered %v, want http.ErrAbortHandler re-raised", v)
		}
	}()
	serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/abort", nil))
}

// TestRequestIDIsServerAssigned: every request gets a fresh ID the handler and
// the client both see; a client-supplied one is not trusted.
func TestRequestIDIsServerAssigned(t *testing.T) {
	var fromCtx, fromHeader string
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: defaultBody, Logger: slog.New(slog.DiscardHandler)})
	g.Register(route.Route{Path: "/id", Handler: func(w http.ResponseWriter, r *http.Request) {
		fromCtx, fromHeader = route.RequestID(r.Context()), r.Header.Get(route.RequestIDHeader)
		w.WriteHeader(http.StatusNoContent)
	}})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/id", nil)
	req.Header.Set(route.RequestIDHeader, "forged\nline")
	rec := serve(g.Handler(), req)

	id := rec.Header().Get(route.RequestIDHeader)
	if id == "" || id == "forged\nline" || fromCtx != id || fromHeader != id {
		t.Errorf("response %q, context %q, request header %q: want one fresh server-assigned ID", id, fromCtx, fromHeader)
	}
	second := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/id", nil)).Header().Get(route.RequestIDHeader)
	if second == id {
		t.Error("two requests got the same ID")
	}
}

// TestAccessLogNamesThePatternNotThePath: the access line carries the matched
// route pattern, never the request's own path or query. Those are user input
// (a token in a query string, a forged log line in an encoded path), and the
// product's slog handler may not escape them.
func TestAccessLogNamesThePatternNotThePath(t *testing.T) {
	tests := []struct {
		target, wantPattern string
		wantStatus          int
	}{
		{"/teapot?token=secret", "/teapot", http.StatusTeapot},
		{"/files/evil%0Aforged=1", "/files/", http.StatusTeapot},
		{"/nowhere/evil", "", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			var logs bytes.Buffer
			g := route.New(route.Config{
				Error: jsonError, MaxBodyBytes: defaultBody,
				Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
			})
			teapot := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }
			g.Register(route.Route{Path: "/teapot", Handler: teapot})
			g.Register(route.Route{Path: "/files/", Handler: teapot})

			rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.target, nil))
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatalf("access log %q: %v", logs.String(), err)
			}
			if entry["method"] != "GET" || entry["pattern"] != tt.wantPattern ||
				entry["status"] != float64(tt.wantStatus) || entry["request_id"] != rec.Header().Get(route.RequestIDHeader) {
				t.Errorf("access log = %v, want pattern %q status %d", entry, tt.wantPattern, tt.wantStatus)
			}
			for _, leaked := range []string{"secret", "evil", "forged"} {
				if strings.Contains(logs.String(), leaked) {
					t.Errorf("access log carries request input %q: %s", leaked, logs.String())
				}
			}
		})
	}
}

// TestStreamingHandlersKeepFlusher: SSE handlers type-assert http.Flusher on
// the writer they are given, so the tracking wrapper must still be one.
func TestStreamingHandlersKeepFlusher(t *testing.T) {
	flushed := false
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: defaultBody, Logger: slog.New(slog.DiscardHandler)})
	g.Register(route.Route{Path: "/events", Handler: func(w http.ResponseWriter, _ *http.Request) {
		f, isFlusher := w.(http.Flusher)
		if !isFlusher {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("data: x\n\n"))
		f.Flush()
		flushed = true
	}})

	rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/events", nil))
	if !flushed || !rec.Flushed {
		t.Errorf("handler flushed %v, recorder flushed %v: want the flush to reach the connection", flushed, rec.Flushed)
	}
}

// TestUnroutedRequestsPassTheGlobalChain: the request ID and recovery wrap the
// whole mux, not only registered routes.
func TestUnroutedRequestsPassTheGlobalChain(t *testing.T) {
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: defaultBody, Logger: slog.New(slog.DiscardHandler)})
	rec := serve(g.Handler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/nowhere", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get(route.RequestIDHeader) == "" {
		t.Errorf("status %d, request ID %q: want 404 with an ID", rec.Code, rec.Header().Get(route.RequestIDHeader))
	}
}

// hijacker is a ResponseWriter that can hand over its connection, as net/http's
// own does for a WebSocket upgrade.
type hijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h hijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

// TestAccessLogStatus: the logged status is the final one the client saw — not
// an informational 1xx, and 101 for a connection handed to a WebSocket.
func TestAccessLogStatus(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    int
	}{
		{"early hints then OK", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusAccepted)
		}, http.StatusAccepted},
		{"hijacked", func(w http.ResponseWriter, _ *http.Request) {
			hj, isHijacker := w.(http.Hijacker)
			if !isHijacker {
				t.Error("the tracking writer hid http.Hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		}, http.StatusSwitchingProtocols},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			g := route.New(route.Config{
				Error: jsonError, MaxBodyBytes: defaultBody,
				Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
			})
			g.Register(route.Route{Path: "/s", Handler: tt.handler})
			server, client := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })
			g.Handler().ServeHTTP(hijacker{httptest.NewRecorder(), server},
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/s", nil))

			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatalf("access log %q: %v", logs.String(), err)
			}
			if entry["status"] != float64(tt.want) {
				t.Errorf("logged status = %v, want %d", entry["status"], tt.want)
			}
		})
	}
}

// TestOversizedBodyClosesTheConnection: net/http closes a connection once a
// handler hits its body cap, since the rest of the body is still in flight.
// It finds out by type-asserting the writer it was handed, so the cap must be
// given net/http's own writer, not the registrar's tracking wrapper.
func TestOversizedBodyClosesTheConnection(t *testing.T) {
	g := route.New(route.Config{Error: jsonError, MaxBodyBytes: 8, Logger: slog.New(slog.DiscardHandler)})
	g.Register(route.Route{Path: "/upload", Handler: func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			jsonError(w, r, http.StatusRequestEntityTooLarge, "too_large", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}})
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/upload", strings.NewReader(strings.Repeat("x", 9)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !resp.Close {
		t.Errorf("status %d, Connection: close %v; want 413 and the connection closed", resp.StatusCode, resp.Close)
	}
}
