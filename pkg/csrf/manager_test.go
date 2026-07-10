// SPDX-License-Identifier: BUSL-1.1

package csrf

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestCSRFManager_PerSessionIsolation is the load-bearing #1257 test:
// the pre-port single-token model let any client replay another's
// token. Per-session means a token minted for session A must be
// invalid for session B even with identical content.
func TestCSRFManager_PerSessionIsolation(t *testing.T) {
	t.Parallel()
	m := NewManager()
	t.Cleanup(m.Stop)

	tokenA, genErrA := m.Generate(SessionKey("bearer-A"))
	if genErrA != nil {
		t.Fatalf("generate A: %v", genErrA)
	}
	tokenB, genErrB := m.Generate(SessionKey("bearer-B"))
	if genErrB != nil {
		t.Fatalf("generate B: %v", genErrB)
	}
	if tokenA == tokenB {
		t.Fatal("two sessions must not share a CSRF token")
	}

	if vErr := m.Validate(SessionKey("bearer-A"), tokenA); vErr != nil {
		t.Errorf("A's token must validate against A's session: %v", vErr)
	}
	if vErr := m.Validate(SessionKey("bearer-B"), tokenB); vErr != nil {
		t.Errorf("B's token must validate against B's session: %v", vErr)
	}
	// The actual regression guard.
	if vErr := m.Validate(SessionKey("bearer-A"), tokenB); !errors.Is(vErr, errCSRFTokenInvalid) {
		t.Errorf("B's token presented to A's session must be invalid, got %v", vErr)
	}
	if vErr := m.Validate(SessionKey("bearer-B"), tokenA); !errors.Is(vErr, errCSRFTokenInvalid) {
		t.Errorf("A's token presented to B's session must be invalid, got %v", vErr)
	}
}

// TestCSRFManager_LoopbackBypassSharesKey proves that the no-token
// bypass path (loopback or auth-disabled dev mode) maps every request
// to a single key — different empty bearers still share state, which
// preserves the pre-port behavior for that dev-only path.
func TestCSRFManager_LoopbackBypassSharesKey(t *testing.T) {
	t.Parallel()
	if SessionKey("") != csrfLoopbackSessionKey {
		t.Errorf("empty bearer should map to loopback key, got %q", SessionKey(""))
	}
}

// TestCSRFManager_ValidateErrorClassification proves the three failure
// modes are distinguishable so the middleware can render different
// error codes / messages per cause.
func TestCSRFManager_ValidateErrorClassification(t *testing.T) {
	t.Parallel()
	m := NewManager()
	t.Cleanup(m.Stop)

	// Missing.
	if err := m.Validate("session", ""); !errors.Is(err, errCSRFTokenMissing) {
		t.Errorf("empty token => %v, want errCSRFTokenMissing", err)
	}
	// Invalid (no token ever minted for this session).
	if err := m.Validate("session-with-no-mint", "anything"); !errors.Is(err, errCSRFTokenInvalid) {
		t.Errorf("unminted session => %v, want errCSRFTokenInvalid", err)
	}
	// Wrong value for a minted session.
	tok, genErr := m.Generate("session2")
	if genErr != nil {
		t.Fatalf("generate: %v", genErr)
	}
	if vErr := m.Validate("session2", tok+"X"); !errors.Is(vErr, errCSRFTokenInvalid) {
		t.Errorf("wrong token => %v, want errCSRFTokenInvalid", vErr)
	}
}

// TestCSRFManager_GetOrCreateIsIdempotent proves a UI polling
// /api/v1/csrf-token within the expiry window receives the same
// token back — important so the UI can cache and not invalidate
// every in-flight request when it polls.
func TestCSRFManager_GetOrCreateIsIdempotent(t *testing.T) {
	t.Parallel()
	m := NewManager()
	t.Cleanup(m.Stop)

	first, err := m.GetOrCreate("session")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := m.GetOrCreate("session")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Errorf("repeat GetOrCreate must return same token: %q vs %q", first, second)
	}
}

// TestCSRFManager_GetOrCreate_ConcurrentSameSession reproduces the TOCTOU
// race fixed by the double-checked write lock in GetOrCreate. Before the
// fix, two concurrent callers for the same session could each miss the
// read-locked cache check, each Generate a new token, and the later write
// would overwrite the earlier — leaving N-1 of N callers holding a token
// that no longer matched the stored entry. That mismatch is what caused
// TestAlertConfig_ConcurrentUpdates to fail intermittently with HTTP 403
// (csrf_token_invalid) under -race.
//
// The fix makes the mint atomic: every concurrent caller for the same
// session must observe the same token, and a subsequent Validate must
// accept every one of those returned tokens.
func TestCSRFManager_GetOrCreate_ConcurrentSameSession(t *testing.T) {
	t.Parallel()
	m := NewManager()
	t.Cleanup(m.Stop)

	const (
		session = "shared-session-key"
		callers = 32
	)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		tokens = make([]string, 0, callers)
	)

	start := make(chan struct{})
	for range callers {
		wg.Go(func() {
			<-start // align goroutines to maximize contention
			tok, err := m.GetOrCreate(session)
			if err != nil {
				t.Errorf("GetOrCreate: %v", err)
				return
			}
			mu.Lock()
			tokens = append(tokens, tok)
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()

	if len(tokens) != callers {
		t.Fatalf("expected %d tokens, got %d", callers, len(tokens))
	}

	// Invariant 1: every caller observed the same token (idempotence
	// under concurrency).
	for i, tok := range tokens {
		if tok != tokens[0] {
			t.Fatalf("token mismatch at index %d: %q vs %q", i, tok, tokens[0])
		}
	}

	// Invariant 2: every token any caller saw is still acceptable to
	// Validate. Before the fix, the overwrite would have produced a
	// final stored token different from at least one returned value
	// and Validate would have rejected it as invalid.
	for i, tok := range tokens {
		if err := m.Validate(session, tok); err != nil {
			t.Fatalf("token from caller %d rejected by Validate: %v", i, err)
		}
	}
}

// TestSessionKey_HashedNotPlaintext proves the bearer never lands in
// the manager's internal map as plaintext — important so a heap dump
// or debug log of the manager doesn't leak live bearer tokens.
func TestSessionKey_HashedNotPlaintext(t *testing.T) {
	t.Parallel()
	bearer := "extremely-secret-bearer-token"
	key := SessionKey(bearer)
	if strings.Contains(key, bearer) {
		t.Errorf("session key must not embed bearer plaintext (key=%q)", key)
	}
	if len(key) != 64 { // sha256 hex = 64 chars
		t.Errorf("session key length = %d, want 64 (sha256 hex)", len(key))
	}
}
