// SPDX-License-Identifier: BUSL-1.1

package passkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// MaxCredentialBytes bounds one encoded credential, not an account envelope.
const MaxCredentialBytes = 1 << 20

// ErrCredentialRecord indicates an invalid or oversized serialization record.
var ErrCredentialRecord = errors.New("passkey: invalid credential record")

// The defined type bypasses Credential.UnmarshalJSON's legacy migration.
type credentialFields webauthn.Credential

type credentialRecord struct {
	credentialFields
	Flags *uint8 `json:"flags"`
}

// MarshalCredential preserves the library record without validating its crypto.
// Product adapters own account policy and protected, atomic persistence.
func MarshalCredential(credential webauthn.Credential) ([]byte, error) {
	raw := uint8(credential.Flags.ProtocolValue())
	if credential.Flags != webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(raw)) || !credentialFits(credential) {
		return nil, ErrCredentialRecord
	}
	record, err := json.Marshal(credentialRecord{credentialFields: credentialFields(credential), Flags: &raw})
	if err != nil || len(record) > MaxCredentialBytes {
		return nil, ErrCredentialRecord
	}
	return record, nil
}

// UnmarshalCredential decodes the current lossless format, never legacy JSON.
// It validates serialization only; possession of a record is not authentication.
func UnmarshalCredential(record []byte) (webauthn.Credential, error) {
	if len(record) > MaxCredentialBytes || !utf8.Valid(record) {
		return webauthn.Credential{}, ErrCredentialRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.DisallowUnknownFields()
	var stored credentialRecord
	if err := decoder.Decode(&stored); err != nil || stored.Flags == nil {
		return webauthn.Credential{}, ErrCredentialRecord
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return webauthn.Credential{}, ErrCredentialRecord
	}
	credential := webauthn.Credential(stored.credentialFields)
	credential.Flags = webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(*stored.Flags))
	return credential, nil
}

func credentialFits(credential webauthn.Credential) bool {
	remaining := MaxCredentialBytes
	for _, field := range [][]byte{
		credential.ID, credential.PublicKey, credential.Authenticator.AAGUID,
		credential.Attestation.ClientDataJSON, credential.Attestation.ClientDataHash,
		credential.Attestation.AuthenticatorData, credential.Attestation.Object,
	} {
		if len(field) > remaining {
			return false
		}
		remaining -= len(field)
	}
	return credentialStringsFit(credential, remaining)
}

func credentialStringsFit(credential webauthn.Credential, remaining int) bool {
	for _, field := range []string{
		credential.AttestationType, credential.AttestationFormat,
		string(credential.Authenticator.Attachment), string(credential.Extensions.CredProtect),
	} {
		if len(field) > remaining || !utf8.ValidString(field) {
			return false
		}
		remaining -= len(field)
	}
	// Even empty transports consume quotes and separators in the output.
	if len(credential.Transport) > remaining/3 {
		return false
	}
	remaining -= len(credential.Transport) * 3
	for _, transport := range credential.Transport {
		if len(transport) > remaining || !utf8.ValidString(string(transport)) {
			return false
		}
		remaining -= len(transport)
	}
	return true
}
