package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

type operationProfile struct {
	Version     uint64   `json:"version"`
	Families    []uint64 `json:"families"`
	Atomicities []uint64 `json:"atomicities"`
	Schemes     []uint64 `json:"schemes"`
}
type operationBoundary struct {
	Deployment      uint64 `json:"deployment"`
	Source          uint64 `json:"source"`
	Target          uint64 `json:"target"`
	Principal       uint64 `json:"principal"`
	KeyID           uint64 `json:"key_id"`
	Epoch           uint64 `json:"epoch"`
	RouteScope      uint64 `json:"route_scope"`
	Now             uint64 `json:"now"`
	AssetTTLFloor   uint64 `json:"asset_ttl_floor"`
	FutureSkew      uint64 `json:"future_skew"`
	VersionFloor    uint64 `json:"version_floor"`
	MaxFrame        int    `json:"max_frame"`
	MaxNesting      int    `json:"max_nesting"`
	CriticalAllowed bool   `json:"critical_allowed"`
	PublicKey       string `json:"public_key"`
}
type operationExpected struct {
	Verdict  any     `json:"verdict"`
	Retained *string `json:"retained_binding"`
}
type operationCase struct {
	Schema             int                `json:"schema"`
	Layer              string             `json:"layer"`
	ThresholdSupported bool               `json:"threshold_supported"`
	ID                 string             `json:"id"`
	Packet             string             `json:"packet_hex"`
	Prior              *string            `json:"prior_binding"`
	Profile            operationProfile   `json:"profile"`
	Boundary           operationBoundary  `json:"boundary"`
	AttestationValid   bool               `json:"attestation_valid"`
	ReferenceAccepts   bool               `json:"reference_accepts"`
	Expected           *operationExpected `json:"expected"`
}
type operationResult struct {
    Reencoded *string `json:"reencoded_core_hex"`
    Signing *string `json:"signing_preimage_hex"`
    TransportKey []string `json:"transport_key_ir"`
    TypedOperand []string `json:"typed_operand_ir"`
	ID       string  `json:"id"`
	Verdict  any     `json:"verdict"`
	Retained *string `json:"retained_binding"`
}

func operationError(err error) int {
	switch err {
	case ErrFormat:
		return 70
	case ErrVersion:
		return 71
	case ErrSource:
		return 72
	case ErrSignature:
		return 73
	case ErrThreshold:
		return 74
	case ErrTTL:
		return 75
	case ErrReplay:
		return 76
	case ErrExpired:
		return 54
	default:
		panic(err)
	}
}
func TestOperationVectorsFollowTheRealTransportReceiver(t *testing.T) {
	path := os.Getenv("OIP_WIRE_OPERATIONS_INPUT")
	if path == "" {
		path = filepath.Join("..", "..", "tests", "vectors", "wire-operations.jsonl")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	rows := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var row operationCase
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Schema != 1 || row.Layer != "transport" || row.ThresholdSupported {
			t.Fatal("unsupported operation test schema or layer")
		}
		packet, err := hex.DecodeString(row.Packet)
		if err != nil {
			t.Fatal(err)
		}
		b := row.Boundary
		public, err := hex.DecodeString(b.PublicKey)
		if err != nil || len(public) != 32 {
			t.Fatal("public key")
		}
		boundary := Boundary{Deployment: b.Deployment, Source: b.Source, Target: b.Target, Principal: b.Principal,
			KeyID: b.KeyID, Epoch: b.Epoch, RouteScope: b.RouteScope, Now: b.Now, AssetTTLFloor: b.AssetTTLFloor,
			FutureSkew: b.FutureSkew, VersionFloor: b.VersionFloor, MaxFrame: b.MaxFrame, MaxNesting: b.MaxNesting,
			CriticalAllowed: b.CriticalAllowed, PublicKey: [32]byte(public)}
		profile := Profile{Version: row.Profile.Version, Families: row.Profile.Families, Atomicities: row.Profile.Atomicities, Schemes: row.Profile.Schemes}
		store := TransportBindings{entries: map[TransportKey][]byte{}}
		var key *TransportKey
		if decoded, err := DecodePacket(packet, int(^uint(0)>>1)); err == nil {
			if value, err := Key(decoded.Core()); err == nil {
				key = &value
			}
			if strings.HasSuffix(row.ID, "/valid") && ReferenceAccepts(decoded.Core()) != row.ReferenceAccepts {
				t.Fatalf("%s: reference operation set differs from the table", row.ID)
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
			before[k] = append([]byte(nil), v...)
		}
		arrival, typedValue, err := store.Receive(packet, profile, boundary, func(*wirepb.Core) bool { return row.AttestationValid })
		result := operationResult{ID: row.ID, Verdict: "accept:first"}
		if err != nil {
			result.Verdict = operationError(err)
			if !reflect.DeepEqual(before, store.entries) {
				t.Fatalf("%s: refusal changed bindings", row.ID)
			}
        } else {
            if arrival==Identical {result.Verdict="accept:identical"}
            decoded:=typedValue
            if decoded==nil || decoded.decodedOperands==nil {t.Fatal("accepted receiver lost its actual typed operand")}
            encoded,encodeErr:=EncodeCore(decoded.Core());if encodeErr!=nil {t.Fatal(encodeErr)}
            preimage,signErr:=decoded.SigningBytes();if signErr!=nil {t.Fatal(signErr)}
            encodedHex,preimageHex:=hex.EncodeToString(encoded),hex.EncodeToString(preimage)
            result.Reencoded,result.Signing=&encodedHex,&preimageHex
            if key==nil {t.Fatal("accepted packet has no actual transport key")}
            result.TransportKey=TypedIRDecimal(TransportKeyIR(*key))
            result.TypedOperand=TypedIRDecimal(decoded.decodedOperands.TypedIR)
        }
		if key != nil {
			if value, ok := store.entries[*key]; ok {
				text := hex.EncodeToString(value)
				result.Retained = &text
			}
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(encoded)
		output.WriteByte('\n')
		if row.Expected != nil {
			var normalized operationExpected
			if err := json.Unmarshal(encoded, &normalized); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(row.Expected, &normalized) {
				t.Fatalf("%s: got %s", row.ID, encoded)
			}
		}
		rows++
	}
	if rows < 31 {
		t.Fatal("operation corpus is missing")
	}
	if path := os.Getenv("OIP_WIRE_OPERATIONS_OUTPUT"); path != "" {
		if err := os.WriteFile(path, []byte(output.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
