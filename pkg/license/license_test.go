// SPDX-License-Identifier: BUSL-1.1

package license_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/license"
)

// testPolicy is a small ProductPolicy standing in for a real product
// (Seed/Stem/NIAC each supply their own). Tier 2 is the only recognized
// tier, granting "feat_a" and expecting product code "9001".
func testPolicy() license.ProductPolicy {
	return license.ProductPolicy{
		ProductName: "testprod",
		FeaturesForTier: func(tier int) (features []string, expectedCode string, ok bool) {
			if tier == 2 {
				return []string{"feat_a"}, "9001", true
			}
			return nil, "", false
		},
		EncryptionSalt:    "TEST-PRODUCT-SALT",
		ConfigSubdir:      "testprod",
		LicenseFileName:   ".license",
		DefaultMaxDevices: 3,
		TrialDays:         14,
		TrialTier:         2,
	}
}

// signToken builds an MSN1 token signing the given fields with priv. It
// mirrors the keygen/verifier wire format so tests can mint tokens against
// an ephemeral key without a production private key.
func signToken(
	t *testing.T,
	priv ed25519.PrivateKey,
	product, code, serial string,
	tier int,
	exp int64,
) string {
	t.Helper()
	payload := map[string]any{
		"v":          1,
		"product":    product,
		"code":       code,
		"serial":     serial,
		"tier":       tier,
		"maxDevices": 3,
		"iat":        time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC).Unix(),
	}
	if exp > 0 {
		payload["exp"] = exp
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, b)
	return "MSN1." + base64.RawURLEncoding.EncodeToString(b) +
		"." + base64.RawURLEncoding.EncodeToString(sig)
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return pub, priv
}

// TestSignedTokenRoundTrip mints a token with an ephemeral key and verifies it
// through a Verifier built on the matching public key and policy.
func TestSignedTokenRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())

	token := signToken(t, priv, "testprod", "9001", "ABCDEFG", 2, 0)
	info := v.Validate(token)
	if !info.Valid {
		t.Fatalf("Validate: not valid (err=%q)", info.ErrorMsg)
	}
	if info.ProductCode != "9001" {
		t.Errorf("ProductCode = %q, want 9001", info.ProductCode)
	}
	if info.Tier != 2 {
		t.Errorf("Tier = %v, want 2", info.Tier)
	}
	if info.Serial != "ABCDEFG" {
		t.Errorf("Serial = %q, want ABCDEFG", info.Serial)
	}
	if !info.HasFeature("feat_a") || info.HasFeature("nonexistent") {
		t.Errorf("unexpected feature set: %v", info.Features)
	}
}

// TestForgeryRejected is the core security property: a token signed by an
// attacker's own key is rejected by the real verifier. Under the old rotor
// cipher scheme the generator shipped in-binary, so this attack succeeded.
func TestForgeryRejected(t *testing.T) {
	t.Parallel()
	pub, _ := testKeyPair(t)
	_, attacker := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())
	forged := signToken(t, attacker, "testprod", "9001", "FORGEDXX", 2, 0)

	if v.Validate(forged).Valid {
		t.Fatal("forged token (attacker key) validated against production key")
	}
}

// TestTamperRejected mutates a single payload byte of an otherwise valid token
// and confirms the signature check rejects it.
func TestTamperRejected(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())
	token := signToken(t, priv, "testprod", "9001", "ABCDEFG", 2, 0)

	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	raw[len(raw)-2] ^= 0x01 // flip a bit in the payload, keep the old signature
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]

	if v.Validate(tampered).Valid {
		t.Fatal("tampered payload validated")
	}
}

// TestWrongProductRejected confirms a correctly signed token issued for
// another product does not validate against this Verifier's policy.
func TestWrongProductRejected(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())
	token := signToken(t, priv, "otherprod", "9001", "ABCDEFG", 2, 0)
	if v.Validate(token).Valid {
		t.Fatal("otherprod-product token validated against testprod policy")
	}
}

// TestExpiredRejected confirms expiry is enforced even on a validly signed token.
func TestExpiredRejected(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())
	past := time.Now().Add(-time.Hour).Unix()
	token := signToken(t, priv, "testprod", "9001", "ABCDEFG", 2, past)
	info := v.Validate(token)
	if info.Valid {
		t.Fatal("expired token validated")
	}
}

// TestInvalidTierRejected confirms a validly signed token carrying a tier the
// policy does not recognize is rejected.
func TestInvalidTierRejected(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())
	token := signToken(t, priv, "testprod", "9001", "ABCDEFG", 99, 0)
	if v.Validate(token).Valid {
		t.Fatal("token with unrecognized tier validated")
	}
}

func TestValidateRejectsBadInputs(t *testing.T) {
	t.Parallel()
	pub, _ := testKeyPair(t)
	v := license.NewVerifier(pub, testPolicy())
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"garbage", "not-a-token"},
		{"wrong scheme", "MSN9.AAAA.BBBB"},
		{"two parts", "MSN1.AAAA"},
		{"bad base64", "MSN1.!!!.???"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			info := v.Validate(c.key)
			if info.Valid {
				t.Errorf("expected invalid, got valid (key=%q)", c.key)
			}
			if info.ErrorMsg == "" {
				t.Errorf("expected non-empty ErrorMsg")
			}
		})
	}
}

// TestProductBoundary_CrossProductTokenRejected is the product-parameter
// boundary regression guard: a token signed for one product's name must not
// validate against a Verifier configured with a different product's policy,
// even with an otherwise-recognized tier and code.
func TestProductBoundary_CrossProductTokenRejected(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)

	policyA := testPolicy()
	policyA.ProductName = "product-a"
	policyB := testPolicy()
	policyB.ProductName = "product-b"

	tokenForA := signToken(t, priv, "product-a", "9001", "SERIAL1", 2, 0)

	vA := license.NewVerifier(pub, policyA)
	if !vA.Validate(tokenForA).Valid {
		t.Fatal("token for product-a must validate against product-a's policy")
	}

	vB := license.NewVerifier(pub, policyB)
	if vB.Validate(tokenForA).Valid {
		t.Fatal("token signed for product-a validated against product-b's policy")
	}
}

// TestFeaturesComeFromPolicyNotToken confirms features are sourced entirely
// from ProductPolicy.FeaturesForTier and never from anything in the wire
// payload — the payload carries no features field, so a forged/tampered
// feature list is structurally impossible, not merely unvalidated.
func TestFeaturesComeFromPolicyNotToken(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	policy := testPolicy()
	v := license.NewVerifier(pub, policy)

	token := signToken(t, priv, "testprod", "9001", "SERIAL1", 2, 0)
	info := v.Validate(token)
	if !info.Valid {
		t.Fatalf("Validate: not valid (err=%q)", info.ErrorMsg)
	}

	wantFeatures, _, _ := policy.FeaturesForTier(2)
	if len(info.Features) != len(wantFeatures) {
		t.Fatalf("Features = %v, want %v", info.Features, wantFeatures)
	}
	for i, f := range wantFeatures {
		if info.Features[i] != f {
			t.Errorf("Features[%d] = %q, want %q", i, info.Features[i], f)
		}
	}
}

func TestActivationLifecycle(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	policy := testPolicy()
	v := license.NewVerifier(pub, policy)
	token := signToken(t, priv, "testprod", "9001", "SERIAL1", 2, 0)

	tmp := t.TempDir()
	mgr, err := license.NewManagerWithDir(v, policy, tmp)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}

	if mgr.IsActivated() {
		t.Error("expected !IsActivated on fresh manager")
	}

	trial := mgr.StartTrial()
	if !trial.Success || !trial.IsTrialMode || trial.Tier != policy.TrialTier {
		t.Errorf("StartTrial unexpected: %+v", trial)
	}
	if !mgr.IsActivated() || !mgr.IsTrialValid() {
		t.Error("expected trial to be active")
	}

	res := mgr.Activate(token)
	if !res.Success || res.Tier != 2 {
		t.Errorf("Activate unexpected: %+v", res)
	}
	if mgr.GetState().IsTrialMode {
		t.Error("expected non-trial state after Activate")
	}

	mgr2, err := license.NewManagerWithDir(v, policy, tmp)
	if err != nil {
		t.Fatalf("reload NewManagerWithDir: %v", err)
	}
	if !mgr2.IsActivated() {
		t.Error("expected reloaded state to be activated")
	}
	if mgr2.GetState().Tier != 2 {
		t.Errorf("reloaded tier = %v, want 2", mgr2.GetState().Tier)
	}

	if deactErr := mgr2.Deactivate(); deactErr != nil {
		t.Fatalf("Deactivate: %v", deactErr)
	}
	if mgr2.IsActivated() {
		t.Error("expected !IsActivated after Deactivate")
	}
}

// TestManagerConcurrentReadsAndWrites exercises the RWMutex so `go test -race`
// fails loudly if the locking ever regresses.
func TestManagerConcurrentReadsAndWrites(t *testing.T) {
	t.Parallel()
	pub, priv := testKeyPair(t)
	policy := testPolicy()
	v := license.NewVerifier(pub, policy)
	token := signToken(t, priv, "testprod", "9001", "SERIAL1", 2, 0)

	tmp := t.TempDir()
	mgr, err := license.NewManagerWithDir(v, policy, tmp)
	if err != nil {
		t.Fatalf("NewManagerWithDir: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for range 50 {
			mgr.Activate(token)
			_ = mgr.Deactivate()
		}
		close(done)
	}()

	for range 8 {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					_ = mgr.IsActivated()
					_ = mgr.GetState()
					_ = mgr.IsTrialValid()
					_ = mgr.TrialDaysRemaining()
					_ = mgr.NeedsCheckIn()
				}
			}
		}()
	}

	<-done
}
