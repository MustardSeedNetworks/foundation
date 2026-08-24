package corewlan_test

import (
	"errors"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/corewlan"
)

func TestDecodeScan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		want    []corewlan.Network
		wantErr error
	}{
		{
			name: "populated scan",
			payload: `{"authorized":true,"networks":[
				{"ssid":"Neuroplasticity","bssid":"24:5a:4c:6b:b5:c9","rssi":-54,"noise":-87,
				 "channel":149,"width":40,"band":5,"phyMode":"802.11ax","security":"wpa3Transition"}]}`,
			want: []corewlan.Network{{
				SSID: "Neuroplasticity", BSSID: "24:5a:4c:6b:b5:c9",
				RSSI: -54, Noise: -87, Channel: 149, ChannelWidth: 40,
				Band: corewlan.Band5GHz, PHYMode: "802.11ax", Security: "wpa3Transition",
			}},
		},
		{
			// A network with a BSSID but no SSID is hidden, not redacted.
			name: "hidden network retains bssid",
			payload: `{"authorized":true,"networks":[
				{"ssid":"","bssid":"26:5a:4c:1b:b5:c9","rssi":-54,"channel":149,"band":5}]}`,
			want: []corewlan.Network{{
				BSSID: "26:5a:4c:1b:b5:c9", RSSI: -54, Channel: 149,
				Band: corewlan.Band5GHz, Hidden: true,
			}},
		},
		{
			// Without the TCC grant CoreWLAN returns results with every identifier
			// stripped and no error. Surfacing that as an empty-but-successful scan
			// is what made this failure mode so hard to diagnose.
			name: "unauthorized scan is an error, not empty results",
			payload: `{"authorized":false,"networks":[
				{"ssid":"","bssid":"","rssi":-54,"channel":149,"band":5}]}`,
			wantErr: corewlan.ErrLocationDenied,
		},
		{
			// The status can report authorized while the data is stripped: a
			// bundled binary launched directly is a different CoreWLAN client
			// from its bundle. A scan that found networks and named none of
			// them was redacted regardless of what the status claims.
			name: "authorized status but every identifier stripped",
			payload: `{"authorized":true,"networks":[
				{"ssid":"","bssid":"","rssi":-47,"channel":40,"band":5},
				{"ssid":"","bssid":"","rssi":-75,"channel":11,"band":2}]}`,
			wantErr: corewlan.ErrLocationDenied,
		},
		{
			// A genuinely empty airspace is not redaction — there is nothing to
			// strip — so it must stay a successful, empty scan.
			name:    "authorized but no networks",
			payload: `{"authorized":true,"networks":[]}`,
			want:    []corewlan.Network{},
		},
		{
			name:    "malformed payload",
			payload: `{"authorized":true,"networks":`,
			wantErr: corewlan.ErrDecode,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := corewlan.DecodeScan([]byte(tc.payload))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("DecodeScan() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeScan() unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("DecodeScan() returned %d networks, want %d", len(got), len(tc.want))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("network[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestNetworkSNR(t *testing.T) {
	t.Parallel()

	n := corewlan.Network{RSSI: -54, Noise: -87}
	if got := n.SNR(); got != 33 {
		t.Errorf("SNR() = %d, want 33", got)
	}
}

// A zero noise floor means CoreWLAN did not report one; SNR is meaningless then.
func TestNetworkSNRWithoutNoise(t *testing.T) {
	t.Parallel()

	n := corewlan.Network{RSSI: -54}
	if got := n.SNR(); got != 0 {
		t.Errorf("SNR() = %d, want 0 when noise is unreported", got)
	}
}

func TestDecodeNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		want    []string
		wantErr error
	}{
		{"two names", `["en0","en1"]`, []string{"en0", "en1"}, nil},
		{"empty array", `[]`, []string{}, nil},
		// A JSON null must not surface as a nil slice callers have to guard.
		{"null becomes empty", `null`, []string{}, nil},
		{"malformed", `["en0"`, nil, corewlan.ErrDecode},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := corewlan.DecodeNames([]byte(tc.payload))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("DecodeNames() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeNames() unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("DecodeNames() = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("name[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestAuthorizationString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		auth corewlan.Authorization
		want string
	}{
		{corewlan.AuthNotDetermined, "not determined"},
		{corewlan.AuthRestricted, "restricted"},
		{corewlan.AuthDenied, "denied"},
		{corewlan.AuthAuthorized, "authorized"},
		{corewlan.Authorization(99), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.auth.String(); got != tc.want {
			t.Errorf("Authorization(%d).String() = %q, want %q", tc.auth, got, tc.want)
		}
	}
}
