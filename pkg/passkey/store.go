// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

const maxPending = 1024

// Purpose prevents registration state from being used for sign-in or vice versa.
type Purpose uint8

const (
	Registration Purpose = iota + 1
	Login
)

// Binding comes from server-validated state, not from a submitted account name.
// Browser is a random, at least 32-character HttpOnly/Secure/SameSite cookie.
// AccountID is the stable WebAuthn user handle for enrollment, empty for login.
type Binding struct {
	Browser   string
	AccountID string
	Purpose   Purpose
}

type ceremony struct {
	session Session
	browser [32]byte
	account [32]byte
	purpose Purpose
}

// Store bounds process-local, short-lived ceremonies; a restart discards them.
// Durable credentials belong in the product store, never in this map.
type Store struct {
	mu      sync.Mutex
	pending map[string]ceremony
}

// NewStore creates an empty ceremony store shared by the product's auth routes.
func NewStore() *Store { return &Store{pending: make(map[string]ceremony)} }

// Add retains service-issued state under an unpredictable, independent handle.
func (s *Store) Add(session Session, binding Binding) (string, error) {
	if !validBinding(session, binding) {
		return "", ErrInvalidSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	if len(s.pending) >= maxPending {
		return "", errors.New("passkey: ceremony capacity reached")
	}
	if !session.admitted.CompareAndSwap(false, true) {
		return "", ErrInvalidSession
	}
	id := rand.Text()
	s.pending[id] = ceremony{session: session, browser: sha256.Sum256([]byte(binding.Browser)),
		account: sha256.Sum256([]byte(binding.AccountID)), purpose: binding.Purpose}
	return id, nil
}

// Take consumes a matching ceremony atomically, before verifying the response.
// Failed completion therefore requires a fresh challenge, not a retry/replay.
func (s *Store) Take(id string, binding Binding) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[id]
	if !ok {
		return Session{}, false
	}
	if !time.Now().Before(entry.session.data.Expires) {
		delete(s.pending, id)
		return Session{}, false
	}
	if entry.browser != sha256.Sum256([]byte(binding.Browser)) ||
		entry.account != sha256.Sum256([]byte(binding.AccountID)) || entry.purpose != binding.Purpose {
		return Session{}, false
	}
	delete(s.pending, id)
	return entry.session, true
}

// Clear invalidates all outstanding ceremonies after account recovery/reset.
// Discoverable login has no account identity until completion, so clearing only
// an account's enrollment challenges would leave pre-recovery logins alive.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.pending)
}

func (s *Store) expire() {
	now := time.Now()
	for id, entry := range s.pending {
		if !now.Before(entry.session.data.Expires) {
			delete(s.pending, id)
		}
	}
}

func validBinding(session Session, binding Binding) bool {
	if session.issuer == nil || session.admitted == nil || len(binding.Browser) < 32 || len(binding.Browser) > 512 ||
		!session.valid(session.issuer, session.registration) {
		return false
	}
	if session.registration {
		return binding.Purpose == Registration && binding.AccountID != "" && binding.AccountID == string(session.data.UserID)
	}
	return binding.Purpose == Login && binding.AccountID == ""
}
