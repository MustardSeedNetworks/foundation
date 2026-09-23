// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestRegistrationRejectsMalformedCredential(t *testing.T) {
	t.Parallel()
	service := newTestService(t)
	_, session, err := service.BeginRegistration(testUser{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), "POST", "/register/finish", strings.NewReader(`{}`))
	if credential, err := service.FinishRegistration(testUser{}, *session, request); err == nil || credential != nil {
		t.Fatal("malformed registration accepted")
	}
}

func TestLoginRejectsMalformedCredential(t *testing.T) {
	t.Parallel()
	service := newTestService(t)
	_, session, err := service.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), "POST", "/login/finish", strings.NewReader(`{}`))
	resolve := func(_, _ []byte) (webauthn.User, error) {
		t.Fatal("account lookup called before credential parsing")
		return nil, nil
	}
	if user, credential, err := service.FinishLogin(resolve, *session, request); err == nil || user != nil || credential != nil {
		t.Fatal("malformed login accepted")
	}
}

type testUser struct{}

func TestCompletionRejectsInvalidSession(t *testing.T) {
	t.Parallel()
	service := newTestService(t)
	_, foreign, err := newTestService(t).BeginRegistration(testUser{})
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []Session{
		{}, *foreign,
		{issuer: service, registration: false, data: webauthn.SessionData{Expires: time.Now().Add(time.Minute)}},
		{issuer: service, registration: true, data: webauthn.SessionData{Expires: time.Now().Add(-time.Minute)}},
	} {
		assertInvalidSession(t, service, session)
	}
}

func assertInvalidSession(t *testing.T, service *Service, session Session) {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), "POST", "/finish", strings.NewReader(`{}`))
	_, err := service.FinishRegistration(testUser{}, session, request)
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("invalid session reached registration parsing: %v", err)
	}
	if session.registration {
		return
	}
	_, _, err = service.FinishLogin(nil, Session{}, request)
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("zero session reached login parsing: %v", err)
	}
}

func (testUser) WebAuthnID() []byte                         { return []byte("opaque-persisted-account-handle") }
func (testUser) WebAuthnName() string                       { return "operator" }
func (testUser) WebAuthnDisplayName() string                { return "Operator" }
func (testUser) WebAuthnCredentials() []webauthn.Credential { return nil }
