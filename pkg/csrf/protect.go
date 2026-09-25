// SPDX-License-Identifier: BUSL-1.1

package csrf

import (
	"errors"
	"net/http"
)

// ErrorFunc writes a structured error response. CSRF rejections carry no
// structured details, so the signature is intentionally narrower than an
// api package's writeError (which typically takes a slice of error details
// the leaf must not import). The api package adapts writeError to this type.
type ErrorFunc func(w http.ResponseWriter, r *http.Request, status int, code, message string)

// SessionKeyFunc derives the CSRF session key for a request. ok is false when
// the request carries no session credential at all: with nothing ambient for a
// cross-site page to ride, there is nothing to forge, so the request goes on to
// the handler unchecked. Behind an auth layer that is unreachable; on a
// pre-session route it lets a caller without a session through, as it must.
type SessionKeyFunc func(r *http.Request) (key string, ok bool)

// Protect wraps a handler so state-changing methods (POST/PUT/PATCH/DELETE)
// require a valid per-session CSRF token; safe methods pass through. #1257
// sub-4 moved validation from a single global token to per-session tokens
// keyed by sha256(bearer): each authenticated session has its own token, so a
// leaked token from one client cannot unlock another's mutations.
//
// The session is the request's Authorization bearer ([SessionKeyFromRequest]).
// A product whose browser session is a cookie uses [ProtectKeyed] instead.
//
// mgr nil is treated as a server misconfiguration (500) rather than a silent
// bypass. writeErr renders the failure; the distinct error codes let the UI
// react (missing → fetch a token, expired → refetch, invalid → hard 403).
func Protect(mgr *Manager, writeErr ErrorFunc, next http.HandlerFunc) http.HandlerFunc {
	return ProtectKeyed(mgr, func(r *http.Request) (string, bool) {
		return SessionKeyFromRequest(r), true
	}, writeErr, next)
}

// ProtectKeyed is [Protect] with the session key derived by sessionKey rather
// than from the Authorization header. The key must be the one the product's
// token endpoint minted under, or every mutation is refused.
func ProtectKeyed(mgr *Manager, sessionKey SessionKeyFunc, writeErr ErrorFunc, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if mgr == nil {
				writeErr(w, r, http.StatusInternalServerError, "csrf_unavailable",
					"CSRF protection is unavailable, server misconfigured")
				return
			}
			key, hasSession := sessionKey(r)
			if !hasSession {
				next(w, r)
				return
			}
			clientToken := r.Header.Get(csrfHeaderName)
			switch err := mgr.Validate(key, clientToken); {
			case err == nil:
				// passes
			case errors.Is(err, ErrTokenMissing):
				writeErr(w, r, http.StatusForbidden, "csrf_token_missing",
					"CSRF token required for state-changing requests. Include X-CSRF-Token header.")
				return
			case errors.Is(err, ErrTokenExpired):
				writeErr(w, r, http.StatusForbidden, "csrf_token_expired",
					"CSRF token expired; refetch /api/v1/csrf-token")
				return
			default:
				writeErr(w, r, http.StatusForbidden, "csrf_token_invalid",
					"Invalid CSRF token")
				return
			}
		}

		next(w, r)
	}
}
