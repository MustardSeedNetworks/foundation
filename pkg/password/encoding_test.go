// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"errors"
	"strings"
	"testing"
)

func TestRejectNoncanonicalEncoding(t *testing.T) {
	record, err := Hash("encoding test phrase")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(record, "$")
	for _, index := range []int{4, 5} {
		field := parts[index]
		for _, replacement := range []string{noncanonical(field), field[:len(field)-2] + "\r\n"} {
			candidate := strings.Replace(record, field, replacement, 1)
			if matched, err := Verify(candidate, "encoding test phrase"); matched || !errors.Is(err, ErrRecord) {
				t.Fatalf("accepted noncanonical field %d: %v", index, err)
			}
		}
	}
}

func noncanonical(value string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, value[len(value)-1])
	return value[:len(value)-1] + string(alphabet[last|1])
}
