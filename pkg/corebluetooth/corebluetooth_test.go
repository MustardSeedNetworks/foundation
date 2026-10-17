package corebluetooth_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/MustardSeedNetworks/foundation/pkg/corebluetooth"
)

func TestDecodeScan(t *testing.T) {
	t.Parallel()

	txPower := -8

	tests := []struct {
		name    string
		payload string
		want    []corebluetooth.Peripheral
		wantErr error
	}{
		{
			// Manufacturer data arrives base64 encoded and begins with the
			// little-endian company identifier (0x004c, Apple).
			name: "populated scan",
			payload: `{"state":5,"peripherals":[
				{"identifier":"6F1C2D3E-0000-4000-8000-00000000A1B2","name":"Thermometer",
				 "rssi":-61,"connectable":true,"txPower":-8,"manufacturerData":"TAAQBQ==",
				 "serviceUuids":["180F","FE9F"]}]}`,
			want: []corebluetooth.Peripheral{{
				Identifier:       "6F1C2D3E-0000-4000-8000-00000000A1B2",
				Name:             "Thermometer",
				RSSI:             -61,
				Connectable:      true,
				TxPower:          &txPower,
				ManufacturerData: []byte{0x4c, 0x00, 0x10, 0x05},
				ServiceUUIDs:     []string{"180F", "FE9F"},
			}},
		},
		{
			// A beacon that advertises nothing but its presence is still a
			// peripheral; absent fields stay absent rather than zero-valued.
			name: "bare advertisement",
			payload: `{"state":5,"peripherals":[
				{"identifier":"0B9E8C7A-0000-4000-8000-0000000000C3","name":"","rssi":-90,
				 "connectable":false,"serviceUuids":[]}]}`,
			want: []corebluetooth.Peripheral{{
				Identifier:   "0B9E8C7A-0000-4000-8000-0000000000C3",
				RSSI:         -90,
				ServiceUUIDs: []string{},
			}},
		},
		{
			// CoreBluetooth reports 127 when it has no RSSI for a packet.
			name: "unavailable rssi reads as unreported",
			payload: `{"state":5,"peripherals":[
				{"identifier":"0B9E8C7A-0000-4000-8000-0000000000C4","rssi":127}]}`,
			want: []corebluetooth.Peripheral{{
				Identifier: "0B9E8C7A-0000-4000-8000-0000000000C4",
			}},
		},
		{
			name:    "quiet room is an empty scan",
			payload: `{"state":5,"peripherals":[]}`,
			want:    []corebluetooth.Peripheral{},
		},
		{
			// A process without the user's grant is refused, never shown an
			// empty airspace.
			name:    "unauthorized",
			payload: `{"state":3,"peripherals":[]}`,
			wantErr: corebluetooth.ErrUnauthorized,
		},
		{
			name:    "powered off",
			payload: `{"state":4,"peripherals":[]}`,
			wantErr: corebluetooth.ErrPoweredOff,
		},
		{
			name:    "unsupported",
			payload: `{"state":2,"peripherals":[]}`,
			wantErr: corebluetooth.ErrUnsupported,
		},
		{
			name:    "still resetting when the wait ran out",
			payload: `{"state":1,"peripherals":[]}`,
			wantErr: corebluetooth.ErrNotReady,
		},
		{
			name:    "malformed payload",
			payload: `{"state":5,"peripherals":`,
			wantErr: corebluetooth.ErrDecode,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := corebluetooth.DecodeScan([]byte(tc.payload))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("DecodeScan() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeScan() unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("DecodeScan() returned nil, want an empty slice")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("DecodeScan() returned %d peripherals, want %d", len(got), len(tc.want))
			}
			for i := range tc.want {
				assertPeripheral(t, i, got[i], tc.want[i])
			}
		})
	}
}

func assertPeripheral(t *testing.T, i int, got, want corebluetooth.Peripheral) {
	t.Helper()

	if got.Identifier != want.Identifier || got.Name != want.Name ||
		got.RSSI != want.RSSI || got.Connectable != want.Connectable {
		t.Errorf("peripheral[%d] = %+v, want %+v", i, got, want)
	}
	switch {
	case (got.TxPower == nil) != (want.TxPower == nil):
		t.Errorf("peripheral[%d].TxPower = %v, want %v", i, got.TxPower, want.TxPower)
	case got.TxPower != nil && *got.TxPower != *want.TxPower:
		t.Errorf("peripheral[%d].TxPower = %d, want %d", i, *got.TxPower, *want.TxPower)
	}
	if !bytes.Equal(got.ManufacturerData, want.ManufacturerData) {
		t.Errorf("peripheral[%d].ManufacturerData = %x, want %x", i, got.ManufacturerData, want.ManufacturerData)
	}
	if !slices.Equal(got.ServiceUUIDs, want.ServiceUUIDs) {
		t.Errorf("peripheral[%d].ServiceUUIDs = %v, want %v", i, got.ServiceUUIDs, want.ServiceUUIDs)
	}
}

func TestAuthorizationString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		auth corebluetooth.Authorization
		want string
	}{
		{corebluetooth.AuthNotDetermined, "not determined"},
		{corebluetooth.AuthRestricted, "restricted"},
		{corebluetooth.AuthDenied, "denied"},
		{corebluetooth.AuthAllowedAlways, "allowed"},
		{corebluetooth.Authorization(99), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.auth.String(); got != tc.want {
			t.Errorf("Authorization(%d).String() = %q, want %q", tc.auth, got, tc.want)
		}
	}
}
