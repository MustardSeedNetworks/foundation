// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestCredentialEncodingBounds(t *testing.T) {
	t.Parallel()
	large := strings.Repeat("x", MaxCredentialBytes+1)
	for name, mutate := range map[string]func(*webauthn.Credential){
		"id":         func(c *webauthn.Credential) { c.ID = []byte(large) },
		"key":        func(c *webauthn.Credential) { c.PublicKey = []byte(large) },
		"aaguid":     func(c *webauthn.Credential) { c.Authenticator.AAGUID = []byte(large) },
		"clientJSON": func(c *webauthn.Credential) { c.Attestation.ClientDataJSON = []byte(large) },
		"clientHash": func(c *webauthn.Credential) { c.Attestation.ClientDataHash = []byte(large) },
		"authData":   func(c *webauthn.Credential) { c.Attestation.AuthenticatorData = []byte(large) },
		"object":     func(c *webauthn.Credential) { c.Attestation.Object = []byte(large) },
		"type":       func(c *webauthn.Credential) { c.AttestationType = large },
		"format":     func(c *webauthn.Credential) { c.AttestationFormat = large },
		"attachment": func(c *webauthn.Credential) { c.Authenticator.Attachment = protocol.AuthenticatorAttachment(large) },
		"protection": func(c *webauthn.Credential) { c.Extensions.CredProtect = protocol.CredentialProtectionPolicy(large) },
		"transport": func(c *webauthn.Credential) {
			c.Transport = []protocol.AuthenticatorTransport{protocol.AuthenticatorTransport(large)}
		},
		"transportCount": func(c *webauthn.Credential) {
			c.Transport = make([]protocol.AuthenticatorTransport, MaxCredentialBytes/3+1)
		},
		"escapedExpansion": func(c *webauthn.Credential) { c.AttestationType = strings.Repeat("\x00", MaxCredentialBytes/2) },
		"base64Expansion":  func(c *webauthn.Credential) { c.ID = make([]byte, MaxCredentialBytes) },
		"combined": func(c *webauthn.Credential) {
			c.ID = make([]byte, MaxCredentialBytes/2)
			c.PublicKey = make([]byte, MaxCredentialBytes/2+1)
		},
		"invalidUTF8":          func(c *webauthn.Credential) { c.AttestationType = "\xff" },
		"invalidTransportUTF8": func(c *webauthn.Credential) { c.Transport = []protocol.AuthenticatorTransport{"\xff"} },
	} {
		t.Run(name, func(t *testing.T) {
			credential := completeCredential()
			mutate(&credential)
			if _, err := MarshalCredential(credential); !errors.Is(err, ErrCredentialRecord) {
				t.Fatalf("accepted oversized/lossy credential: %v", err)
			}
		})
	}
}

func TestCredentialDecodeExactSizeBound(t *testing.T) {
	t.Parallel()
	record := `{"flags":0}`
	record += strings.Repeat(" ", MaxCredentialBytes-len(record))
	if _, err := UnmarshalCredential([]byte(record)); err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCredential([]byte(record + " ")); !errors.Is(err, ErrCredentialRecord) {
		t.Fatalf("accepted oversized record: %v", err)
	}
}
