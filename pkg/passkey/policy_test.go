// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestNewRejectsInvalidBoundary(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{
		"", "http://seed.msn.lab", "https://stem.msn.lab", "https://seed.msn.lab/",
		"https://seed.msn.lab/path", "https://seed.msn.lab?query", "https://seed.msn.lab#fragment",
		"https://user@seed.msn.lab", "https://seed.msn.lab:", "https://seed.msn.lab:0",
		"https://seed.msn.lab:65536", "https://seed.msn.lab?", "https://seed.msn.lab#",
		"https://seed.msn.lab:08443",
	} {
		t.Run(origin, func(t *testing.T) {
			if _, err := New(Config{RPID: "seed.msn.lab", Origin: origin, DisplayName: "Seed"}); err == nil {
				t.Fatal("accepted invalid canonical origin")
			}
		})
	}
}

func TestNewRejectsInvalidRPID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"", "127.0.0.1", "[::1]", "seed.msn.lab.", "*.msn.lab", "-seed.msn.lab", "seed..lab"} {
		t.Run(id, func(t *testing.T) {
			if _, err := New(Config{RPID: id, Origin: "https://" + id, DisplayName: "Seed"}); err == nil {
				t.Fatal("accepted invalid relying-party ID")
			}
		})
	}
}

func TestNewRequiresDisplayName(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{RPID: "seed.msn.lab", Origin: "https://seed.msn.lab"}); err == nil {
		t.Fatal("accepted empty display name")
	}
}

func TestRegistrationRequiresDiscoverabilityAndVerification(t *testing.T) {
	t.Parallel()
	service := newTestService(t)
	options, session, err := service.BeginRegistration(testUser{})
	if err != nil {
		t.Fatal(err)
	}
	selection := options.Response.AuthenticatorSelection
	if selection.ResidentKey != protocol.ResidentKeyRequirementRequired || selection.UserVerification != protocol.VerificationRequired {
		t.Fatalf("unsafe authenticator selection: %+v", selection)
	}
	if options.Response.Attestation != protocol.PreferNoAttestation {
		t.Fatal("registration requests identifying attestation")
	}
	assertVerifiedSession(t, session)
}

func TestLoginRequiresVerificationWithoutUsername(t *testing.T) {
	t.Parallel()
	service := newTestService(t)
	options, session, err := service.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	if options.Response.UserVerification != protocol.VerificationRequired || len(options.Response.AllowedCredentials) != 0 {
		t.Fatal("login must discover a credential with user verification")
	}
	assertVerifiedSession(t, session)
}

func TestLocalhostSupportsExplicitHTTPSPort(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{RPID: "localhost", Origin: "https://localhost:8443", DisplayName: "Seed"}); err != nil {
		t.Fatal(err)
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	service, err := New(Config{RPID: "seed.msn.lab", Origin: "https://seed.msn.lab", DisplayName: "Seed"})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func assertVerifiedSession(t *testing.T, session *Session) {
	t.Helper()
	if session.data.UserVerification != protocol.VerificationRequired || session.data.Challenge == "" {
		t.Fatal("missing required verification or random challenge")
	}
	if remaining := time.Until(session.data.Expires); remaining <= 0 || remaining > 5*time.Minute {
		t.Fatalf("invalid ceremony expiry: %s", remaining)
	}
}
