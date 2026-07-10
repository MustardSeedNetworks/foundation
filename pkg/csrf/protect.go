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

// Protect wraps a handler so state-changing methods (POST/PUT/PATCH/DELETE)
// require a valid per-session CSRF token; safe methods pass through. #1257
// sub-4 moved validation from a single global token to per-session tokens
// keyed by sha256(bearer): each authenticated session has its own token, so a
// leaked token from one client cannot unlock another's mutations.
//
// mgr nil is treated as a server misconfiguration (500) rather than a silent
// bypass. writeErr renders the failure; the distinct error codes let the UI
// react (missing → fetch a token, expired → refetch, invalid → hard 403).
func Protect(mgr *Manager, writeErr ErrorFunc, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if mgr == nil {
				writeErr(w, r, http.StatusInternalServerError, "csrf_unavailable",
					"CSRF protection is unavailable, server misconfigured")
				return
			}
			clientToken := r.Header.Get(csrfHeaderName)
			sessionKey := SessionKeyFromRequest(r)
			switch err := mgr.Validate(sessionKey, clientToken); {
			case err == nil:
				// passes
			case errors.Is(err, errCSRFTokenMissing):
				writeErr(w, r, http.StatusForbidden, "csrf_token_missing",
					"CSRF token required for state-changing requests. Include X-CSRF-Token header.")
				return
			case errors.Is(err, errCSRFTokenExpired):
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
