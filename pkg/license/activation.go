// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// OfflineMaxDays is the number of days allowed offline after activation.
const OfflineMaxDays = 90

// CheckInInterval is the number of days between optional check-ins.
const CheckInInterval = 30

const (
	hoursPerDay = 24
	day         = hoursPerDay * time.Hour
)

// ActivationState represents the current license activation status.
type ActivationState struct {
	LicenseKey      string    `json:"licenseKey"`
	DeviceHash      string    `json:"deviceHash"`
	Tier            int       `json:"tier"`
	ActivatedAt     time.Time `json:"activatedAt"`
	LastValidatedAt time.Time `json:"lastValidatedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	TrialStartedAt  time.Time `json:"trialStartedAt,omitzero"`
	IsTrialMode     bool      `json:"isTrialMode"`
	Features        []string  `json:"features"`
}

// ActivationResult contains the result of an activation attempt.
type ActivationResult struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	Tier          int    `json:"tier,omitempty"`
	DaysRemaining int    `json:"daysRemaining,omitempty"`
	IsTrialMode   bool   `json:"isTrialMode"`
}

// LoadStatus reports the standing of the persisted activation state. Every
// writer maintains it, so it describes the state the manager is acting on and
// not merely how construction went. The differences matter: a missing file is
// a fresh install and may start a trial, while a file that exists but cannot
// be used must not, because starting one overwrites it and a paid activation
// is then unrecoverable.
type LoadStatus int

const (
	// StatusLoaded means a state file was read and parsed. Whether it still
	// entitles anything is the manager's answer, not this one's.
	StatusLoaded LoadStatus = iota
	// StatusMissing means no state file exists.
	StatusMissing
	// StatusUnreadable means a state file exists but could not be read.
	StatusUnreadable
	// StatusMalformed means the bytes were read but did not decrypt or parse.
	StatusMalformed
	// StatusUnverified means the state parsed but nothing vouches for it: no
	// signed token stands behind it, or it could not be written to disk. It
	// is the status a forged state file gets, and it entitles nothing.
	StatusUnverified
)

// String names the status for an operator-facing message.
func (s LoadStatus) String() string {
	switch s {
	case StatusLoaded:
		return "loaded"
	case StatusMissing:
		return "missing"
	case StatusUnreadable:
		return "unreadable"
	case StatusMalformed:
		return "malformed"
	case StatusUnverified:
		return "unverified"
	}
	return "unknown"
}

// Usable reports whether the state on disk can be acted on. An unusable state
// entitles nothing beyond the free grant and must never be replaced by an
// automatic trial: the operator holds a licence file this build cannot read,
// or one nothing vouches for — a key rotation looks exactly like a forgery
// from here — and destroying it is not the product's call.
func (s LoadStatus) Usable() bool {
	return s == StatusLoaded || s == StatusMissing
}

// Manager handles license activation and validation.
//
// Manager is safe for concurrent use. State mutations (Activate,
// Deactivate, StartTrial, CheckIn) take a write lock; reads
// (GetState, IsActivated, HasFeature, etc.) take a read lock.
// Per-feature gates in the HTTP layer call read methods on every
// request, so contention on the write path must stay rare — in
// practice activation happens once at deploy time.
type Manager struct {
	mu          sync.RWMutex
	state       *ActivationState
	fingerprint *DeviceFingerprint
	configDir   string
	verifier    *Verifier
	policy      ProductPolicy
	loadStatus  LoadStatus
	loadErr     error
}

// NewManager creates a new license manager rooted at the default
// per-user config directory (~/.config/<policy.ConfigSubdir>/).
func NewManager(v *Verifier, policy ProductPolicy) (*Manager, error) {
	homeDir, homeErr := os.UserHomeDir()
	if homeErr != nil {
		homeDir = "/tmp"
	}
	return NewManagerWithDir(v, policy, filepath.Join(homeDir, ".config", policy.ConfigSubdir))
}

// NewManagerWithDir creates a license manager that persists state in
// the given directory. Exposed so tests can use a tmpdir without
// poking at the user's real config.
func NewManagerWithDir(v *Verifier, policy ProductPolicy, configDir string) (*Manager, error) {
	if v == nil {
		return nil, errors.New("a verifier is required to re-check persisted activation state")
	}

	fp, fpErr := GenerateFingerprint()
	if fpErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint: %w", fpErr)
	}

	m := &Manager{
		state:       nil,
		fingerprint: fp,
		configDir:   configDir,
		verifier:    v,
		policy:      policy,
	}

	m.loadStatus, m.loadErr = m.loadState()
	return m, nil
}

// GetState returns the current activation state. The returned pointer
// must not be mutated by callers; treat it as read-only.
func (m *Manager) GetState() *ActivationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// GetFingerprint returns a copy of the immutable device fingerprint.
func (m *Manager) GetFingerprint() *DeviceFingerprint {
	fingerprint := *m.fingerprint
	return &fingerprint
}

// LoadStatus reports how the state on disk loaded. Products log it once at
// startup and fail closed to their free tier when it is not Usable.
func (m *Manager) LoadStatus() LoadStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadStatus
}

// LoadError returns why the state on disk could not be used, or nil. It is the
// one reason to log alongside LoadStatus.
func (m *Manager) LoadError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadErr
}

// IsActivated returns true if a valid license is active.
func (m *Manager) IsActivated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isActivatedLocked()
}

// HasFeature reports whether the active license includes the named
// feature. Returns false unless the license is activated AND the
// feature is in the active feature set. Active trials grant the
// trial tier's equivalent features.
//
// Per-feature gates in HTTP handlers call this on every request, so
// the lookup must stay cheap: single slice scan under RLock.
func (m *Manager) HasFeature(feature string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.isActivatedLocked() {
		return false
	}
	return slices.Contains(m.state.Features, feature)
}

// stateTrustedLocked reports whether the state in memory may be acted on. The
// state file is sealed with a key derived from the device fingerprint and a
// salt compiled into the shipped binary, both of which any local process can
// read, so the file is an attacker-controllable input. Nothing it says is an
// entitlement until loadState has traced it back to a signature or to the
// policy's own trial terms (#34).
func (m *Manager) stateTrustedLocked() bool {
	return m.state != nil && m.loadStatus == StatusLoaded
}

func (m *Manager) isActivatedLocked() bool {
	if !m.stateTrustedLocked() {
		return false
	}
	if m.state.IsTrialMode {
		return m.isTrialValidLocked()
	}
	if !m.state.ExpiresAt.IsZero() && time.Now().After(m.state.ExpiresAt) {
		return false
	}
	if m.state.DeviceHash != m.fingerprint.Hash() {
		return false
	}
	return true
}

// IsTrialValid returns true if trial period is still active.
func (m *Manager) IsTrialValid() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isTrialValidLocked()
}

func (m *Manager) isTrialValidLocked() bool {
	if !m.stateTrustedLocked() || !m.state.IsTrialMode {
		return false
	}
	trialEnd := m.state.TrialStartedAt.AddDate(0, 0, m.policy.TrialDays)
	return time.Now().Before(trialEnd)
}

// TrialDaysRemaining returns days left in trial.
func (m *Manager) TrialDaysRemaining() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.trialDaysRemainingLocked()
}

func (m *Manager) trialDaysRemainingLocked() int {
	if !m.stateTrustedLocked() || !m.state.IsTrialMode {
		return 0
	}
	trialEnd := m.state.TrialStartedAt.AddDate(0, 0, m.policy.TrialDays)
	remaining := int(time.Until(trialEnd).Hours() / hoursPerDay)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// StartTrial begins the trial period.
func (m *Manager) StartTrial() *ActivationResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loadStatus.Usable() {
		return &ActivationResult{
			Success: false,
			Message: fmt.Sprintf(
				"License state is %s and will not be replaced; restore or re-enter the license key.",
				m.loadStatus),
			Tier: tierInvalid,
		}
	}

	if m.isActivatedLocked() && !m.state.IsTrialMode {
		return &ActivationResult{
			Success: true,
			Message: "Already activated with full license",
			Tier:    m.state.Tier,
		}
	}

	if m.state != nil && m.state.LicenseKey != "" {
		return &ActivationResult{
			Success: false,
			Message: "This license has expired; enter a current license key rather than starting a trial.",
			Tier:    tierInvalid,
		}
	}

	if m.state != nil && !m.state.TrialStartedAt.IsZero() {
		remaining := m.trialDaysRemainingLocked()
		if remaining <= 0 {
			return &ActivationResult{
				Success:     false,
				Message:     "Trial period has expired. Please enter a license key.",
				Tier:        tierInvalid,
				IsTrialMode: true,
			}
		}
		return &ActivationResult{
			Success:       true,
			Message:       fmt.Sprintf("Trial active: %d days remaining", remaining),
			Tier:          m.policy.TrialTier,
			DaysRemaining: remaining,
			IsTrialMode:   true,
		}
	}

	trialFeatures, _, ok := m.policy.FeaturesForTier(m.policy.TrialTier)
	if !ok {
		trialFeatures = nil
	}

	m.state = &ActivationState{
		LicenseKey:     "",
		DeviceHash:     m.fingerprint.Hash(),
		Tier:           m.policy.TrialTier,
		TrialStartedAt: time.Now(),
		IsTrialMode:    true,
		Features:       trialFeatures,
	}

	if saveErr := m.saveState(); saveErr != nil {
		m.loadStatus, m.loadErr = StatusUnverified, saveErr
		return &ActivationResult{
			Success: false,
			Message: fmt.Sprintf("Failed to save trial state: %v", saveErr),
			Tier:    tierInvalid,
		}
	}
	m.loadStatus, m.loadErr = StatusLoaded, nil

	return &ActivationResult{
		Success:       true,
		Message:       fmt.Sprintf("Trial started! %d days of full access.", m.policy.TrialDays),
		Tier:          m.policy.TrialTier,
		DaysRemaining: m.policy.TrialDays,
		IsTrialMode:   true,
	}
}

// Activate attempts to activate a license key.
func (m *Manager) Activate(licenseKey string) *ActivationResult {
	info := m.verifier.Validate(licenseKey)
	if !info.Valid {
		return &ActivationResult{
			Success: false,
			Message: info.ErrorMsg,
			Tier:    tierInvalid,
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.state = &ActivationState{
		LicenseKey:      info.Key,
		DeviceHash:      m.fingerprint.Hash(),
		Tier:            info.Tier,
		ActivatedAt:     time.Now(),
		LastValidatedAt: time.Now(),
		ExpiresAt:       info.ExpiresAt,
		IsTrialMode:     false,
		Features:        info.Features,
	}

	if saveErr := m.saveState(); saveErr != nil {
		m.loadStatus, m.loadErr = StatusUnverified, saveErr
		return &ActivationResult{
			Success: false,
			Message: fmt.Sprintf("Failed to save activation: %v", saveErr),
			Tier:    tierInvalid,
		}
	}
	m.loadStatus, m.loadErr = StatusLoaded, nil

	return &ActivationResult{
		Success:       true,
		Message:       fmt.Sprintf("License activated successfully! Tier: %d", info.Tier),
		Tier:          info.Tier,
		DaysRemaining: daysUntil(info.ExpiresAt),
	}
}

// daysUntil reports whole days left until t, rounded up so any unexpired
// licence reports at least one day. A zero t is perpetual (matching the
// IsZero() check in isActivatedLocked) and reports 0, which the result's
// omitempty drops from the wire.
func daysUntil(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	remaining := time.Until(t)
	if remaining <= 0 {
		return 0
	}
	return int((remaining + day - time.Nanosecond) / day)
}

// Deactivate removes the current license.
func (m *Manager) Deactivate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	licensePath := filepath.Join(m.configDir, m.policy.LicenseFileName)
	if removeErr := os.Remove(licensePath); removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("failed to remove license file: %w", removeErr)
	}
	m.state = nil
	m.loadStatus, m.loadErr = StatusMissing, nil
	return nil
}

// CheckIn updates the last-validated timestamp on a non-trial license.
func (m *Manager) CheckIn() *ActivationResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isActivatedLocked() {
		return &ActivationResult{
			Success: false,
			Message: "No active license to validate",
			Tier:    tierInvalid,
		}
	}
	m.state.LastValidatedAt = time.Now()
	_ = m.saveState()
	return &ActivationResult{
		Success: true,
		Message: "License validated successfully",
		Tier:    m.state.Tier,
	}
}

// NeedsCheckIn returns true if optional check-in is recommended.
func (m *Manager) NeedsCheckIn() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == nil || m.state.IsTrialMode {
		return false
	}
	daysSinceCheck := int(time.Since(m.state.LastValidatedAt).Hours() / hoursPerDay)
	return daysSinceCheck >= CheckInInterval
}

// loadState reads the persisted activation state and classifies the outcome.
// Only a genuinely absent file is StatusMissing; every other failure leaves the
// manager without state AND says so, so callers never read "no state" as a
// fresh install.
func (m *Manager) loadState() (LoadStatus, error) {
	licensePath := filepath.Clean(filepath.Join(m.configDir, m.policy.LicenseFileName))

	f, openErr := os.Open(licensePath)
	if openErr != nil {
		if os.IsNotExist(openErr) {
			return StatusMissing, nil
		}
		return StatusUnreadable, fmt.Errorf("open license file: %w", openErr)
	}
	defer func() { _ = f.Close() }()

	data, readErr := io.ReadAll(f)
	if readErr != nil {
		return StatusUnreadable, fmt.Errorf("read license file: %w", readErr)
	}

	decrypted, decryptErr := m.decrypt(data)
	if decryptErr != nil {
		return StatusMalformed, fmt.Errorf("failed to decrypt license: %w", decryptErr)
	}

	state := &ActivationState{}
	if unmarshalErr := json.Unmarshal(decrypted, state); unmarshalErr != nil {
		return StatusMalformed, fmt.Errorf("failed to parse license: %w", unmarshalErr)
	}

	m.state = state
	return m.bindStateToItsGrant(state)
}

// bindStateToItsGrant re-derives what a persisted state is allowed to grant
// instead of believing what it claims. A paid activation is re-checked against
// the Ed25519 signature that granted it, and its tier, features and expiry are
// taken from that payload; a trial's tier and features come from the policy.
// Anything left over is a forgery and is reported StatusUnverified with its
// entitlements stripped, so no exported reader — GetState included — can hand
// a caller a tier the signature never issued.
//
// The state itself is kept either way: telling an expired or unverifiable
// licence from a fresh install is what stops StartTrial from writing over one
// (#33).
func (m *Manager) bindStateToItsGrant(state *ActivationState) (LoadStatus, error) {
	if state.IsTrialMode {
		// A trial is bounded by the policy window measured from its start, so
		// a start date in the future would be a trial that never ends.
		if state.TrialStartedAt.IsZero() || state.TrialStartedAt.After(time.Now()) {
			return stripGrant(state, errors.New("trial state has no usable start time"))
		}
		features, _, ok := m.policy.FeaturesForTier(m.policy.TrialTier)
		if !ok {
			features = nil
		}
		state.Tier = m.policy.TrialTier
		state.Features = features
		return StatusLoaded, nil
	}

	// Authentic but expired stays StatusLoaded: it is a known file whose term
	// has run out, isActivatedLocked already refuses it on ExpiresAt, and
	// StartTrial owes its holder the "enter a current key" answer rather than
	// a trial written over the licence.
	info, verifyErr := m.verifier.verify(state.LicenseKey)
	if verifyErr != nil {
		return stripGrant(state, verifyErr)
	}

	state.Tier = info.Tier
	state.Features = info.Features
	state.ExpiresAt = info.ExpiresAt
	return StatusLoaded, nil
}

// stripGrant removes the entitlements a state claimed but cannot justify,
// keeping the token and timestamps that let the manager explain itself.
func stripGrant(state *ActivationState, reason error) (LoadStatus, error) {
	state.Tier = tierInvalid
	state.Features = nil
	return StatusUnverified, fmt.Errorf("license state is not backed by a valid license: %w", reason)
}

func (m *Manager) saveState() error {
	if m.state == nil {
		return nil
	}
	if mkdirErr := os.MkdirAll(m.configDir, 0o700); mkdirErr != nil {
		return fmt.Errorf("failed to create config directory: %w", mkdirErr)
	}

	data, marshalErr := json.Marshal(m.state)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal license state: %w", marshalErr)
	}

	encrypted, encryptErr := m.encrypt(data)
	if encryptErr != nil {
		return encryptErr
	}

	licensePath := filepath.Join(m.configDir, m.policy.LicenseFileName)
	if writeErr := os.WriteFile(licensePath, encrypted, 0o600); writeErr != nil {
		return fmt.Errorf("failed to write license file: %w", writeErr)
	}
	return nil
}

func (m *Manager) encrypt(plaintext []byte) ([]byte, error) {
	key := m.deriveKey()

	block, blockErr := aes.NewCipher(key)
	if blockErr != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", blockErr)
	}
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := io.ReadFull(rand.Reader, nonce); nonceErr != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", nonceErr)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (m *Manager) decrypt(ciphertext []byte) ([]byte, error) {
	data, decodeErr := base64.StdEncoding.DecodeString(string(ciphertext))
	if decodeErr != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", decodeErr)
	}

	key := m.deriveKey()
	block, blockErr := aes.NewCipher(key)
	if blockErr != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", blockErr)
	}
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, openErr := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if openErr != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", openErr)
	}
	return plaintext, nil
}

func (m *Manager) deriveKey() []byte {
	data := m.fingerprint.Hash() + m.policy.EncryptionSalt
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}
