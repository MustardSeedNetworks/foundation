// SPDX-License-Identifier: BUSL-1.1

package release

import (
	"bytes"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// liveTrustRootEnv opts in to the one test here that reaches the network. The
// scheduled trust-root workflow sets it; ordinary runs stay offline.
const liveTrustRootEnv = "FOUNDATION_LIVE_TRUST_ROOT"

// TestEmbeddedTrustedRootIsCurrent fetches the Sigstore trusted root through
// TUF, which verifies it against the signed root metadata, and fails when it
// differs from the embedded copy. A rotation then surfaces as a red scheduled
// run instead of every product refusing new releases.
func TestEmbeddedTrustedRootIsCurrent(t *testing.T) {
	if os.Getenv(liveTrustRootEnv) == "" {
		t.Skip("set " + liveTrustRootEnv + "=1 to compare against the published root")
	}
	opts := tuf.DefaultOptions()
	opts.CachePath = t.TempDir()
	client, err := tuf.New(opts)
	if err != nil {
		t.Fatalf("TUF client: %v", err)
	}
	published, err := client.GetTarget("trusted_root.json")
	if err != nil {
		t.Fatalf("fetch trusted_root.json: %v", err)
	}
	if !bytes.Equal(published, trustedRootJSON) {
		t.Fatal("the published Sigstore trusted root differs from pkg/release/trusted_root.json: " +
			"replace the embedded copy with the TUF target trusted_root.json and release foundation")
	}
}
