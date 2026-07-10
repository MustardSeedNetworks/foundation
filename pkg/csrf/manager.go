// SPDX-License-Identifier: BUSL-1.1

// Package csrf provides the fleet-shared per-session CSRF token manager and
// HTTP middleware used by Seed, Stem, and NIAC. It is the canonical
// implementation the three products converge to (ported from NIAC's
// #1257 Wave 5 sub-4 work).
package csrf

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CSRF manager configuration constants. Mirrors stem's Manager
// (#1257 sub-4 port) so the per-session model and the 24h expiry are
// uniform across the fleet.
const (
	csrfPerSessionTokenLength    = 32
	csrfPerSessionTokenExpiry    = 24 * time.Hour
	csrfPerSessionCleanupSeconds = 5 * 60 // 5 minutes between cleanup sweeps
	csrfHeaderName               = "X-Csrf-Token"
	// csrfLoopbackSessionKey is the synthetic session key for the
	// no-token bypass path (loopback / auth-disabled dev mode). All
	// bypass requests share one CSRF token under this key, which
	// preserves the pre-#1257 single-token behavior for that dev path
	// while keeping authenticated requests on per-bearer keys.
	csrfLoopbackSessionKey = "_loopback_bypass"
)

// CSRF errors. Match stem's error vars for cross-repo parity.
var (
	errCSRFTokenMissing = errors.New("CSRF token missing")
	errCSRFTokenInvalid = errors.New("CSRF token invalid")
	errCSRFTokenExpired = errors.New("CSRF token expired")
)

// csrfTokenEntry stores a minted token plus its expiry.
type csrfTokenEntry struct {
	token     string
	expiresAt time.Time
}

// Manager mints, stores, and validates per-session CSRF tokens.
// Keyed by sha256(bearer-token) so the bearer plaintext is never
// retained in memory.
//
// #1257 (Wave 5) sub-4: port of stem's Manager pattern. Pre-port
// niac shared a single global CSRF token across all clients which,
// while functionally protective against cross-site requests, meant
// any client could replay another's value. The per-session model
// pins each token to its issuer.
type Manager struct {
	mu     sync.RWMutex
	tokens map[string]*csrfTokenEntry
	ctx    context.Context
	cancel context.CancelFunc
}

// NewManager constructs a manager and starts its cleanup loop.
// Stop the returned manager via Stop() during server shutdown to
// terminate the background goroutine.
func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		tokens: make(map[string]*csrfTokenEntry),
		ctx:    ctx,
		cancel: cancel,
	}
	go m.cleanupLoop()

	return m
}

// SessionKey derives the Manager's session key from a bearer
// token. Hashing the bearer prevents storing the plaintext in the
// manager's internal map (already-hashed values keep the manager's
// memory profile uniform regardless of bearer length / format).
func SessionKey(bearer string) string {
	if bearer == "" {
		return csrfLoopbackSessionKey
	}
	sum := sha256.Sum256([]byte(bearer))

	return hex.EncodeToString(sum[:])
}

// Generate mints a fresh CSRF token for the given session key,
// replacing any existing one.
func (m *Manager) Generate(sessionKey string) (string, error) {
	buf := make([]byte, csrfPerSessionTokenLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	tok := base64.URLEncoding.EncodeToString(buf)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[sessionKey] = &csrfTokenEntry{
		token:     tok,
		expiresAt: time.Now().Add(csrfPerSessionTokenExpiry),
	}

	return tok, nil
}

// GetOrCreate returns an existing unexpired token or mints a new
// one. Used by the /csrf-token endpoint so a UI that polls for the
// token receives the same value within a session lifetime.
//
// The slow path takes the write lock and re-checks before minting.
// Without the re-check, two concurrent callers for the same session
// could both miss the cache, both call Generate, and the later write
// would overwrite the earlier — leaving the earlier caller holding a
// token that no longer matches the stored entry, which makes its next
// X-Csrf-Token request fail validation with 403. Surfaced as an
// intermittent TestAlertConfig_ConcurrentUpdates failure under -race.
func (m *Manager) GetOrCreate(sessionKey string) (string, error) {
	m.mu.RLock()
	entry, ok := m.tokens[sessionKey]
	m.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.token, nil
	}

	buf := make([]byte, csrfPerSessionTokenLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	tok := base64.URLEncoding.EncodeToString(buf)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check under the write lock: another goroutine may have minted
	// (and stored) a token for this session between our read-lock
	// release above and the write-lock acquisition here.
	if existing, exists := m.tokens[sessionKey]; exists && time.Now().Before(existing.expiresAt) {
		return existing.token, nil
	}
	m.tokens[sessionKey] = &csrfTokenEntry{
		token:     tok,
		expiresAt: time.Now().Add(csrfPerSessionTokenExpiry),
	}

	return tok, nil
}

// Validate constant-time-compares the supplied token against the one
// stored for sessionKey. Returns one of errCSRFTokenMissing /
// errCSRFTokenInvalid / errCSRFTokenExpired so callers can render
// different messages or audit-log differently per failure mode.
func (m *Manager) Validate(sessionKey, token string) error {
	if token == "" {
		return errCSRFTokenMissing
	}
	m.mu.RLock()
	entry, ok := m.tokens[sessionKey]
	m.mu.RUnlock()
	if !ok {
		return errCSRFTokenInvalid
	}
	if time.Now().After(entry.expiresAt) {
		// Re-check under write lock to avoid a TOCTOU racing two
		// expiring sessions into the same delete.
		m.mu.Lock()
		current, stillExists := m.tokens[sessionKey]
		if stillExists && current == entry {
			delete(m.tokens, sessionKey)
		}
		m.mu.Unlock()

		return errCSRFTokenExpired
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(entry.token)) != 1 {
		return errCSRFTokenInvalid
	}

	return nil
}

// Revoke drops the token bound to sessionKey, typically on logout so a
// leaked token can't outlive the session. A no-op if the session holds no
// token. Idempotent.
func (m *Manager) Revoke(sessionKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, sessionKey)
}

// Stop terminates the background cleanup goroutine. Idempotent.
func (m *Manager) Stop() {
	m.cancel()
}

// cleanupLoop sweeps expired tokens from the map at a fixed cadence
// so memory doesn't grow unbounded across long-running sessions.
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(time.Duration(csrfPerSessionCleanupSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for k, entry := range m.tokens {
				if now.After(entry.expiresAt) {
					delete(m.tokens, k)
				}
			}
			m.mu.Unlock()
		}
	}
}

// SessionKeyFromRequest derives the CSRF session key for a request from its
// Authorization header. Mirrors the bearer extraction in the api auth
// middleware so the same token always hashes to the same key.
func SessionKeyFromRequest(r *http.Request) string {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return csrfLoopbackSessionKey
	}

	return SessionKey(strings.TrimPrefix(authz, "Bearer "))
}
