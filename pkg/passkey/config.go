// SPDX-License-Identifier: BUSL-1.1

// Package passkey defines the shared passwordless WebAuthn policy. Products own
// account persistence, ceremony storage, HTTP authorization and browser sessions.
package passkey

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config comes from trusted installation configuration, never request headers.
// An installation uses one canonical HTTPS origin and a host-specific RP ID.
type Config struct {
	RPID        string
	Origin      string
	DisplayName string
}

// New refuses ambiguous origins and does not fall back to localhost.
func New(cfg Config) (*Service, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	engine, err := webauthn.New(libraryConfig(cfg))
	if err != nil {
		return nil, err
	}
	return &Service{engine: engine}, nil
}

func validateConfig(cfg Config) error {
	origin, err := url.Parse(cfg.Origin)
	if err != nil || !validRPID(cfg.RPID) || strings.TrimSpace(cfg.DisplayName) == "" {
		return errors.New("passkey: invalid relying-party configuration")
	}
	if origin.Scheme != "https" || origin.Hostname() != cfg.RPID || origin.User != nil ||
		origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		strings.Contains(cfg.Origin, "#") || !validPort(origin) {
		return errors.New("passkey: require a canonical HTTPS origin matching the relying-party host")
	}
	return nil
}

func validRPID(id string) bool {
	if id == "" || len(id) > 253 || net.ParseIP(id) != nil {
		return false
	}
	for _, label := range strings.Split(id, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	return strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func validPort(origin *url.URL) bool {
	if origin.Host == origin.Hostname() {
		return true
	}
	port, err := strconv.Atoi(origin.Port())
	return err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == origin.Port()
}

func libraryConfig(cfg Config) *webauthn.Config {
	required := true
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute}
	return &webauthn.Config{
		RPID: cfg.RPID, RPDisplayName: cfg.DisplayName, RPOrigins: []string{cfg.Origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: &required,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	}
}
