// SPDX-License-Identifier: BUSL-1.1

package csrf_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/csrf"
)

func recordError(w http.ResponseWriter, _ *http.Request, status int, code, _ string) {
	w.Header().Set("X-Error-Code", code)
	w.WriteHeader(status)
}

// cookieSession keys a request by its "session" cookie, the way a product
// whose browser session is a cookie would.
func cookieSession(r *http.Request) (string, bool) {
	c, err := r.Cookie("session")
	if err != nil {
		return "", false
	}
	return csrf.SessionKey(c.Value), true
}

// TestProtectKeyed pins that the product's key function decides which token a
// mutation must carry, and that a request with no session is not refused.
func TestProtectKeyed(t *testing.T) {
	mgr := csrf.NewManager()
	t.Cleanup(mgr.Stop)
	cookieToken, err := mgr.GetOrCreate(csrf.SessionKey("cookie-jwt"))
	if err != nil {
		t.Fatal(err)
	}
	// A token minted under the Authorization-header key for a request that
	// carries no header: what the bearer-only Protect would demand.
	headerToken, err := mgr.GetOrCreate(csrf.SessionKeyFromRequest(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		method     string
		cookie     bool
		token      string
		wantStatus int
		wantCode   string
	}{
		{name: "cookie session with its token passes", method: http.MethodPost, cookie: true, token: cookieToken, wantStatus: http.StatusNoContent},
		{name: "cookie session without a token is refused", method: http.MethodPost, cookie: true, wantStatus: http.StatusForbidden, wantCode: "csrf_token_missing"},
		{name: "cookie session with the header key's token is refused", method: http.MethodDelete, cookie: true, token: headerToken, wantStatus: http.StatusForbidden, wantCode: "csrf_token_invalid"},
		{name: "no session passes to the handler", method: http.MethodPost, wantStatus: http.StatusNoContent},
		{name: "safe method passes without a token", method: http.MethodGet, cookie: true, wantStatus: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := csrf.ProtectKeyed(mgr, cookieSession, recordError, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/api/v1/x", nil)
			if tt.cookie {
				req.Header.Set("Cookie", "session=cookie-jwt")
			}
			if tt.token != "" {
				req.Header.Set("X-Csrf-Token", tt.token)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("X-Error-Code"); got != tt.wantCode {
				t.Errorf("code = %q, want %q", got, tt.wantCode)
			}
		})
	}
}

// TestProtectKeyedNilManagerFailsClosed keeps the nil-manager refusal ahead of
// the no-session pass: a misconfigured server must not serve a mutation.
func TestProtectKeyedNilManagerFailsClosed(t *testing.T) {
	h := csrf.ProtectKeyed(nil, cookieSession, recordError, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
