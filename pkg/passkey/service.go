// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Service does not expose options that weaken the fleet's verification policy.
// Callers must persist complete credentials and store Sessions server-side.
type Service struct {
	engine *webauthn.WebAuthn
}

// Session is opaque, process-local ceremony state. Never send it to a browser.
// The adapter must bind it to the initiating browser and consume it once.
type Session struct {
	data         webauthn.SessionData
	issuer       *Service
	registration bool
}

// ErrInvalidSession rejects expired, foreign, wrong-purpose and zero sessions.
var ErrInvalidSession = errors.New("passkey: invalid ceremony session")

// BeginRegistration requires a previously authenticated account with a stable,
// opaque user handle. The HTTP adapter must enforce recent authentication.
func (s *Service) BeginRegistration(user webauthn.User) (*protocol.CredentialCreation, *Session, error) {
	options, data, err := s.engine.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	return options, &Session{data: *data, issuer: s, registration: true}, nil
}

// FinishRegistration validates the authenticator response. The adapter must
// atomically consume the browser-bound registration session before calling it.
func (s *Service) FinishRegistration(user webauthn.User, session Session, request *http.Request) (*webauthn.Credential, error) {
	if !session.valid(s, true) {
		return nil, ErrInvalidSession
	}
	return s.engine.FinishRegistration(user, session.data, request)
}

// BeginLogin starts username-free sign-in with a discoverable passkey.
func (s *Service) BeginLogin() (*protocol.CredentialAssertion, *Session, error) {
	options, data, err := s.engine.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, err
	}
	return options, &Session{data: *data, issuer: s}, nil
}

// FinishLogin returns the verified account and full updated credential. Resolve
// must match both credential ID and opaque user handle to the persisted owner.
func (s *Service) FinishLogin(resolve webauthn.DiscoverableUserHandler, session Session, request *http.Request) (webauthn.User, *webauthn.Credential, error) {
	if !session.valid(s, false) {
		return nil, nil, ErrInvalidSession
	}
	return s.engine.FinishPasskeyLogin(resolve, session.data, request)
}

func (session Session) valid(service *Service, registration bool) bool {
	return session.issuer == service && session.registration == registration && time.Now().Before(session.data.Expires)
}
