// SPDX-License-Identifier: BUSL-1.1

package route

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

// RequestIDHeader carries the request ID on the request (for handlers that
// read headers) and on the response (for the client quoting it back).
const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// RequestID returns the ID [Registrar.Handler] assigned to the request, or ""
// outside it.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRequestID assigns every request a fresh ID. A client-supplied header is
// replaced, not trusted: it would otherwise let a caller forge the ID that
// ties log lines together.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		r.Header.Set(RequestIDHeader, id)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// logRequests writes one line per request once it completes. It names the
// ServeMux pattern the request matched ("" when none did), never the request's
// own path or query: those are user input — a token in a query string, a
// forged line in an encoded path — and the product's slog handler may not
// escape them. The mux records the pattern on this same *http.Request, so it
// is readable once the handler returns.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tw := track(w)
		next.ServeHTTP(tw, r)
		logger.InfoContext(r.Context(), "http request",
			"method", r.Method,
			"pattern", r.Pattern,
			"status", tw.statusOrOK(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", RequestID(r.Context()),
		)
	})
}

// recoverPanics turns a handler panic into a logged 500 in the product's
// envelope instead of a dropped connection. [http.ErrAbortHandler] is
// re-raised: it is how a handler asks net/http to abort the response, and
// swallowing it would answer a request the handler meant to cut off.
func recoverPanics(logger *slog.Logger, writeErr ErrorFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := track(w)
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(v)
			}
			// One line for the operator; the stack is a debug field, as in
			// pkg/supervise. Sprint, so the line does not depend on how the
			// product's handler renders a non-string panic value.
			id := RequestID(r.Context())
			logger.ErrorContext(r.Context(), "panic recovered", "panic", fmt.Sprint(v), "request_id", id)
			logger.DebugContext(r.Context(), "panic stack", "stack", string(debug.Stack()), "request_id", id)
			// Once the status line is out, a 500 cannot replace it.
			if tw.status == 0 {
				writeErr(tw, r, http.StatusInternalServerError, "internal_server_error",
					"An internal error occurred. Please try again later.")
			}
		}()
		next.ServeHTTP(tw, r)
	})
}

// trackingWriter records the status the handler wrote. It forwards Flush and
// Hijack explicitly because SSE and WebSocket handlers type-assert for them,
// and Unwrap so [http.ResponseController] reaches everything else.
type trackingWriter struct {
	http.ResponseWriter
	status int
}

// track reuses w if it already tracks, so stacked middlewares share one
// record of what was written.
func track(w http.ResponseWriter) *trackingWriter {
	if tw, ok := w.(*trackingWriter); ok {
		return tw
	}
	return &trackingWriter{ResponseWriter: w}
}

func (tw *trackingWriter) WriteHeader(status int) {
	// A 1xx is informational; the final status is still to come.
	if tw.status == 0 && status >= http.StatusOK {
		tw.status = status
	}
	tw.ResponseWriter.WriteHeader(status)
}

func (tw *trackingWriter) Write(b []byte) (int, error) {
	if tw.status == 0 {
		tw.status = http.StatusOK
	}
	return tw.ResponseWriter.Write(b)
}

func (tw *trackingWriter) Flush() {
	if tw.status == 0 {
		tw.status = http.StatusOK
	}
	_ = http.NewResponseController(tw.ResponseWriter).Flush()
}

func (tw *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(tw.ResponseWriter).Hijack()
	if err == nil && tw.status == 0 {
		tw.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func (tw *trackingWriter) Unwrap() http.ResponseWriter { return tw.ResponseWriter }

// statusOrOK is the status the client saw: net/http sends 200 for a handler
// that wrote nothing.
func (tw *trackingWriter) statusOrOK() int {
	if tw.status == 0 {
		return http.StatusOK
	}
	return tw.status
}
