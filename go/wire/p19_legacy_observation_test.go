package wire

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

// Compiled unchanged on the exact baseline and the candidate. Historical
// expected fields are not decoded; only raw bytes, configuration and prior
// binding enter the real generic receiver.
func TestThresholdLegacyTransportReplay(t *testing.T) {
	input, output := os.Getenv("OIP_P19_LEGACY_INPUT"), os.Getenv("OIP_P19_LEGACY_OUTPUT")
	if input == "" || output == "" {
		t.Skip("explicit legacy evidence paths")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	var results bytes.Buffer
	rows := 0
	for scanner.Scan() {
		var row struct {
			ID               string            `json:"id"`
			Packet           string            `json:"packet_hex"`
			Prior            *string           `json:"prior_binding"`
			Profile          operationProfile  `json:"profile"`
			Boundary         operationBoundary `json:"boundary"`
			AttestationValid bool              `json:"attestation_valid"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(row.Packet)
		if err != nil {
			t.Fatal(err)
		}
		b, p := row.Boundary, row.Profile
		public, err := hex.DecodeString(b.PublicKey)
		if err != nil || len(public) != 32 {
			t.Fatal("public key")
		}
		boundary := Boundary{Deployment: b.Deployment, Source: b.Source, Target: b.Target, Principal: b.Principal, KeyID: b.KeyID, Epoch: b.Epoch, RouteScope: b.RouteScope, Now: b.Now, AssetTTLFloor: b.AssetTTLFloor, FutureSkew: b.FutureSkew, VersionFloor: b.VersionFloor, MaxFrame: b.MaxFrame, MaxNesting: b.MaxNesting, CriticalAllowed: b.CriticalAllowed, PublicKey: [32]byte(public)}
		profile := Profile{Version: p.Version, Families: p.Families, Atomicities: p.Atomicities, Schemes: p.Schemes}
		store := TransportBindings{entries: map[TransportKey][]byte{}}
		var key *TransportKey
		if packet, err := DecodePacket(raw, len(raw)); err == nil {
			if k, err := Key(packet.Core()); err == nil {
				key = &k
			}
		}
		if key != nil && row.Prior != nil {
			prior, err := hex.DecodeString(*row.Prior)
			if err != nil {
				t.Fatal(err)
			}
			store.entries[*key] = prior
		}
		before := map[TransportKey][]byte{}
		for k, v := range store.entries {
			before[k] = slices.Clone(v)
		}
		arrival, packet, err := store.Receive(raw, profile, boundary, func(*wirepb.Core) bool { return row.AttestationValid })
		result := operationResult{ID: row.ID, Verdict: "accept:first"}
		if err != nil {
			result.Verdict = operationError(err)
			if !reflect.DeepEqual(before, store.entries) {
				t.Fatalf("%s: refusal changed binding", row.ID)
			}
		} else {
			if arrival == Identical {
				result.Verdict = "accept:identical"
			}
			if packet == nil || packet.decodedOperands == nil || key == nil {
				t.Fatal("missing accepted data")
			}
			encoded, err := EncodeCore(packet.Core())
			if err != nil {
				t.Fatal(err)
			}
			preimage, err := packet.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			coreHex, preimageHex := hex.EncodeToString(encoded), hex.EncodeToString(preimage)
			result.Reencoded, result.Signing = &coreHex, &preimageHex
			result.TransportKey = TypedIRDecimal(TransportKeyIR(*key))
			result.TypedOperand = TypedIRDecimal(packet.decodedOperands.TypedIR)
		}
		if key != nil {
			if retained, ok := store.entries[*key]; ok {
				v := hex.EncodeToString(retained)
				result.Retained = &v
			}
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		results.Write(encoded)
		results.WriteByte('\n')
		rows++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if rows != 675 {
		t.Fatalf("legacy count %d", rows)
	}
	if err := os.WriteFile(output, results.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}
