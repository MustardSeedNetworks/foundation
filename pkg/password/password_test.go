// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, value := range []string{"a long test passphrase", "密碼🔑 passphrase", " spaced password "} {
		t.Run(value, func(t *testing.T) { checkRoundTrip(t, value) })
	}
}

func checkRoundTrip(t *testing.T, value string) {
	t.Helper()
	record, err := Hash(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{value, "!" + value[1:]} {
		matched, err := Verify(record, candidate)
		if err != nil || matched != (candidate == value) {
			t.Fatalf("matched=%v err=%v", matched, err)
		}
	}
}

func TestIndependentSalts(t *testing.T) {
	first, err := Hash("same test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Hash("same test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("reused salt")
	}
}

func TestInputBounds(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("x", MaxBytes+1)} {
		if _, err := Hash(value); !errors.Is(err, ErrInput) {
			t.Fatalf("Hash: %v", err)
		}
		if _, err := Verify("", value); !errors.Is(err, ErrInput) {
			t.Fatalf("Verify: %v", err)
		}
	}
	checkRoundTrip(t, strings.Repeat("x", MaxBytes))
}

func TestMalformedRecords(t *testing.T) {
	record, err := Hash("test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range malformedRecords(record) {
		matched, err := Verify(value, "test passphrase")
		if matched || !errors.Is(err, ErrRecord) {
			t.Fatalf("accepted malformed record: %v", err)
		}
	}
}

func malformedRecords(record string) []string {
	parts := strings.Split(record, "$")
	return []string{
		"", "$2a$10$placeholder", strings.Repeat("x", 2048), record + "$extra",
		strings.Replace(record, "v=19", "v=20", 1),
		strings.Replace(record, "m=65536", "m=4294967295", 1),
		strings.Replace(record, "t=3", "t=0", 1),
		strings.Replace(record, "p=4", "p=0", 1),
		strings.Replace(record, "m=65536", "m=065536", 1),
		strings.Replace(record, parts[4], "AA", 1),
		strings.Replace(record, parts[5], "AA", 1),
		strings.Replace(record, parts[4], strings.Repeat("!", len(parts[4])), 1),
		strings.Replace(record, parts[5], strings.Repeat("!", len(parts[5])), 1),
		record[:len(record)-1] + "=",
	}
}
