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
