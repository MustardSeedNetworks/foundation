// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Fingerprint constants.
const (
	defaultMAC       = "00:00:00:00:00:00"
	hashLength       = 16 // First 16 hex characters (64 bits of entropy).
	commandTimeout   = 5  // Seconds for external command timeout.
	splitPartsCount  = 2  // Expected parts when splitting on : or =.
	defaultLinuxCPU  = "LINUX-DEFAULT"
	defaultLinuxDisk = "LINUX-DISK"
	unknownSerial    = "UNKNOWN"
)

// DeviceFingerprint contains hardware identifiers for device binding.
type DeviceFingerprint struct {
	MACAddress string `json:"mac"`
	CPUSerial  string `json:"cpu"`
	DiskSerial string `json:"disk"`
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
}

// fingerprintCache keeps the first successful fingerprint. A failed probe is
// not cached, so a later call can still produce the real identity.
type fingerprintCache struct {
	mu          sync.Mutex
	ok          bool
	fingerprint DeviceFingerprint
}

func (c *fingerprintCache) get(generate func() (DeviceFingerprint, error)) (*DeviceFingerprint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok {
		fp, err := generate()
		if err != nil {
			return nil, err
		}
		c.fingerprint, c.ok = fp, true
	}
	result := c.fingerprint
	return &result, nil
}

var processFingerprint fingerprintCache

// GenerateFingerprint creates a unique device fingerprint.
// The result is cached after the first success since hardware IDs don't change.
// It returns an error rather than a substitute identity when a required probe
// fails: a daemon that adopted a different, valid-looking fingerprint would
// silently lose its activation.
func GenerateFingerprint() (*DeviceFingerprint, error) {
	return processFingerprint.get(generateFingerprint)
}

func generateFingerprint() (DeviceFingerprint, error) {
	fp := DeviceFingerprint{
		MACAddress: "",
		CPUSerial:  "",
		DiskSerial: "",
		Hostname:   "",
		Platform:   runtime.GOOS,
	}

	hostname, err := os.Hostname()
	if err == nil {
		fp.Hostname = hostname
	}

	fp.MACAddress = getPrimaryMAC()
	cpu, err := getCPUSerial()
	if err != nil {
		return DeviceFingerprint{}, err
	}
	fp.CPUSerial = cpu
	fp.DiskSerial = getDiskSerial()

	return fp, nil
}

// Hash returns a 16-character hash of the fingerprint.
func (fp *DeviceFingerprint) Hash() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s",
		fp.MACAddress,
		fp.CPUSerial,
		fp.DiskSerial,
		fp.Hostname,
		fp.Platform,
	)

	hash := sha256.Sum256([]byte(data))
	hexHash := hex.EncodeToString(hash[:])

	// Return first 16 characters (64 bits of entropy).
	return strings.ToUpper(hexHash[:hashLength])
}

// String returns a human-readable representation.
func (fp *DeviceFingerprint) String() string {
	const maskShowChars = 8
	const cpuDiskMaskChars = 4
	return fmt.Sprintf("MAC=%s CPU=%s DISK=%s HOST=%s",
		maskString(fp.MACAddress, maskShowChars),
		maskString(fp.CPUSerial, cpuDiskMaskChars),
		maskString(fp.DiskSerial, cpuDiskMaskChars),
		fp.Hostname,
	)
}

// getPrimaryMAC returns the MAC address of the first non-loopback interface.
func getPrimaryMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return defaultMAC
	}

	for _, iface := range interfaces {
		// Skip loopback and interfaces without MAC.
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		// Skip virtual interfaces (common patterns).
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "virbr") {
			continue
		}
		return iface.HardwareAddr.String()
	}

	return defaultMAC
}

// getCPUSerial returns CPU serial number (platform-specific).
func getCPUSerial() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getLinuxCPUSerial(), nil
	case "darwin":
		return getDarwinCPUSerial()
	default:
		return unknownSerial, nil
	}
}

// splitLines returns an iterator over lines in a string.
func splitLines(s string) iter.Seq[string] {
	return strings.SplitSeq(s, "\n")
}

// getLinuxCPUSerial reads CPU serial from /proc/cpuinfo or dmidecode.
func getLinuxCPUSerial() string {
	// Try /proc/cpuinfo first (works on ARM).
	data, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for line := range splitLines(string(data)) {
			if strings.HasPrefix(line, "Serial") {
				parts := strings.Split(line, ":")
				if len(parts) == splitPartsCount {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// Try dmidecode (requires root).
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dmidecode", "-s", "processor-id").Output()
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if serial != "" {
			return serial
		}
	}

	// Try /sys/class/dmi/id/product_serial.
	data, err = os.ReadFile("/sys/class/dmi/id/product_serial")
	if err == nil {
		return strings.TrimSpace(string(data))
	}

	return defaultLinuxCPU
}

// getDarwinCPUSerial reads the hardware UUID on macOS.
func getDarwinCPUSerial() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("read IOPlatformUUID: %w", err)
	}
	return parseIOPlatformUUID(string(out))
}

// parseIOPlatformUUID extracts the IOPlatformUUID value from ioreg output.
func parseIOPlatformUUID(out string) (string, error) {
	for line := range splitLines(out) {
		if !strings.Contains(line, `"IOPlatformUUID"`) {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) == splitPartsCount {
			if uuid := strings.Trim(strings.TrimSpace(parts[1]), `"`); uuid != "" {
				return uuid, nil
			}
		}
	}
	return "", errors.New("read IOPlatformUUID: not in ioreg output")
}

// getDiskSerial returns root disk serial number.
func getDiskSerial() string {
	switch runtime.GOOS {
	case "linux":
		return getLinuxDiskSerial()
	case "darwin":
		// No disk input: system_profiler can pass its timeout under launchd,
		// and the fallback then changed the identity between daemon starts.
		// IOPlatformUUID already identifies the Mac.
		return ""
	default:
		return unknownSerial
	}
}

// getLinuxDiskSerial reads disk serial from /sys or udevadm.
func getLinuxDiskSerial() string {
	// Try common disk paths.
	diskPaths := []string{
		"/sys/block/sda/device/serial",
		"/sys/block/nvme0n1/device/serial",
		"/sys/block/vda/serial",
	}

	for _, path := range diskPaths {
		// Read from known system paths.
		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" {
				return serial
			}
		}
	}

	// Try udevadm.
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "udevadm", "info", "--query=property", "--name=/dev/sda").Output()
	if err == nil {
		for line := range splitLines(string(out)) {
			if serial, found := strings.CutPrefix(line, "ID_SERIAL="); found {
				return serial
			}
		}
	}

	return defaultLinuxDisk
}

// maskString masks a string for display, showing only first N chars.
func maskString(s string, show int) string {
	if len(s) <= show {
		return s
	}
	return s[:show] + "****"
}
