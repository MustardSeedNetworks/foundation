// SPDX-License-Identifier: BUSL-1.1

// Package password supplies the fleet's offline Argon2id password mechanism.
// Callers enforce password strength, request size, rate and concurrency limits.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// MaxBytes bounds input without truncation; product policies may be stricter.
	MaxBytes  = 1024
	saltBytes = 16
	keyBytes  = 32
	// RFC 9106 second recommended profile: 64 MiB, three passes, four lanes.
	memoryKiB  = 64 * 1024
	iterations = 3
	lanes      = 4
	prefix     = "$argon2id$v=19$m=65536,t=3,p=4$"
)

var (
	// ErrInput indicates an empty or oversized password.
	ErrInput = errors.New("password must contain between 1 and 1024 bytes")
	// ErrRecord indicates a malformed or unsupported password record.
	ErrRecord = errors.New("invalid password record")
)

// Hash returns a randomly salted PHC record. It never makes a network request.
func Hash(value string) (string, error) {
	if len(value) == 0 || len(value) > MaxBytes {
		return "", ErrInput
	}
	salt := make([]byte, saltBytes)
	rand.Read(salt)
	key := argon2.IDKey([]byte(value), salt, iterations, memoryKiB, lanes, keyBytes)
	return prefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify returns false without error for a wrong password. Unsupported work
// factors are rejected before derivation; there is no legacy or weak test mode.
func Verify(record, value string) (bool, error) {
	if len(value) == 0 || len(value) > MaxBytes {
		return false, ErrInput
	}
	salt, expected, err := decode(record)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(value), salt, iterations, memoryKiB, lanes, keyBytes)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func decode(record string) ([]byte, []byte, error) {
	encoding := base64.RawStdEncoding.Strict()
	saltLength, keyLength := encoding.EncodedLen(saltBytes), encoding.EncodedLen(keyBytes)
	if len(record) != len(prefix)+saltLength+1+keyLength || !strings.HasPrefix(record, prefix) {
		return nil, nil, ErrRecord
	}
	encodedSalt, encodedKey, ok := strings.Cut(record[len(prefix):], "$")
	if !ok || len(encodedSalt) != saltLength || len(encodedKey) != keyLength {
		return nil, nil, ErrRecord
	}
	salt, saltErr := encoding.DecodeString(encodedSalt)
	key, keyErr := encoding.DecodeString(encodedKey)
	if saltErr != nil || keyErr != nil || len(salt) != saltBytes || len(key) != keyBytes {
		return nil, nil, ErrRecord
	}
	return salt, key, nil
}
