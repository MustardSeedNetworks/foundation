// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestCredentialRoundTrip(t *testing.T) {
	t.Parallel()
	for raw := range 256 {
		credential := completeCredential()
		credential.Flags = webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(raw))
		assertCredentialRoundTrip(t, credential)
	}
	credential := completeCredential()
	credential.Flags = webauthn.NewCredentialFlags(protocol.FlagUserVerified).Update(protocol.FlagUserPresent)
	assertCredentialRoundTrip(t, credential)
	assertCredentialRoundTrip(t, webauthn.Credential{})
}

func assertCredentialRoundTrip(t *testing.T, credential webauthn.Credential) {
	t.Helper()
	encoded, err := MarshalCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalCredential(encoded)
	if err != nil || !reflect.DeepEqual(credential, decoded) {
		t.Fatalf("credential changed: %v", err)
	}
}

func completeCredential() webauthn.Credential {
	return webauthn.Credential{
		ID: []byte{1, 2}, PublicKey: []byte{3, 4}, AttestationType: "basic_full", AttestationFormat: "packed",
		Transport: []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal},
		Authenticator: webauthn.Authenticator{
			AAGUID: []byte{5, 6}, SignCount: 42, CloneWarning: true, Attachment: protocol.Platform,
		},
		Attestation: webauthn.CredentialAttestation{
			ClientDataJSON: []byte{7}, ClientDataHash: []byte{8}, AuthenticatorData: []byte{9},
			PublicKeyAlgorithm: -7, Object: []byte{10},
		},
		Extensions: webauthn.CredentialExtensions{
			RK: new(true), CredProtect: "userVerificationRequired", MinPinLength: new(uint(6)),
			PRFEnabled: new(false), LargeBlobSupported: new(true), HMACSecret: new(false), CredBlobSet: new(true),
		},
	}
}

func TestCredentialRejectsMalformedRecord(t *testing.T) {
	t.Parallel()
	for _, record := range []string{
		``, `null`, `[]`, `{}`, `{"flags":null}`, `{"flags":-1}`, `{"flags":256}`,
		`{"flags":1.5}`, `{"flags":"1"}`, `{"flags":0,"unknown":true}`,
		`{"flags":0,"authenticator":{"unknown":true}}`, `{"flags":0} {}`,
		`{"flags":0} trailing`, `{"flags":0,"id":"!"}`, strings.Repeat(" ", MaxCredentialBytes+1),
	} {
		if _, err := UnmarshalCredential([]byte(record)); !errors.Is(err, ErrCredentialRecord) {
			t.Fatalf("accepted malformed record of length %d: %v", len(record), err)
		}
	}
}

func TestCredentialDoesNotMigrateLegacyAttestation(t *testing.T) {
	t.Parallel()
	credential := webauthn.Credential{AttestationType: "packed"}
	assertCredentialRoundTrip(t, credential)
}

func TestCredentialRejectsInconsistentFlags(t *testing.T) {
	t.Parallel()
	credential := completeCredential()
	credential.Flags.UserVerified = true
	if _, err := MarshalCredential(credential); !errors.Is(err, ErrCredentialRecord) {
		t.Fatalf("accepted inconsistent flags: %v", err)
	}
}
