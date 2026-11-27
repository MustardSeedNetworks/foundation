// SPDX-License-Identifier: BUSL-1.1

// Package password supplies the fleet's offline Argon2id password mechanism.
// Callers enforce password strength, request size, rate and concurrency limits.
//
// Production records always use the full work factor. Consumer test suites,
// which cannot afford 64 MiB per hash under the race detector, may call
// UseTestCost to switch to a cheap Argon2id profile. UseTestCost panics unless
// testing.Testing reports true, and that is only the case in a binary built by
// "go test". A production binary therefore cannot enable the cheap profile,
// and while it is disabled Verify rejects every cheap record before deriving a
// key, so a forged low-cost record cannot be used to weaken a login check.
// There is deliberately no environment variable, build tag or exported
// parameter type that could widen that gate.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

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

	testMemoryKiB  = 64
	testIterations = 1
	testLanes      = 1
	testPrefix     = "$argon2id$v=19$m=64,t=1,p=1$"
)

// testCost is set only by UseTestCost, which is unreachable outside go test.
var testCost atomic.Bool

// UseTestCost makes Hash produce, and Verify accept, a cheap Argon2id profile
// (64 KiB, one pass, one lane) for the rest of the process. It panics unless
// the binary was built by "go test". Call it from TestMain.
func UseTestCost() {
	if !testing.Testing() {
		panic("password: UseTestCost is only available under go test")
	}
	testCost.Store(true)
}

// profile describes the Argon2id parameters a record is bound to.
type profile struct {
	prefix     string
	memoryKiB  uint32
	iterations uint32
	lanes      uint8
}

var (
	fullProfile = profile{prefix, memoryKiB, iterations, lanes}
	testProfile = profile{testPrefix, testMemoryKiB, testIterations, testLanes}
)

// active is the profile Hash writes.
func active() profile {
	if testCost.Load() {
		return testProfile
	}
	return fullProfile
}

// accepted is the profile Verify derives with for record. Anything that does
// not carry the full prefix falls through to it and fails decoding, unless the
// test profile is enabled and the record carries the test prefix.
func accepted(record string) profile {
	if testCost.Load() && strings.HasPrefix(record, testPrefix) {
		return testProfile
	}
	return fullProfile
}

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
	p := active()
	key := argon2.IDKey([]byte(value), salt, p.iterations, p.memoryKiB, p.lanes, keyBytes)
	return p.prefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify returns false without error for a wrong password. Unsupported work
// factors are rejected before derivation. The cheap test profile is accepted
// only while UseTestCost is active, which requires go test.
func Verify(record, value string) (bool, error) {
	if len(value) == 0 || len(value) > MaxBytes {
		return false, ErrInput
	}
	p := accepted(record)
	salt, expected, err := decode(record, p.prefix)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(value), salt, p.iterations, p.memoryKiB, p.lanes, keyBytes)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func decode(record, prefix string) ([]byte, []byte, error) {
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
