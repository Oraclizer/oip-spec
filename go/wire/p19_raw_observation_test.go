package wire

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

// This adapter consumes only raw packet/configuration inputs. It has no
// expected-verdict field and never reads the model or generated model inputs.
type p19Input struct {
	ID        string `json:"id"`
	PacketHex string `json:"packet_hex"`
	Profile   struct {
		Version     uint64   `json:"version"`
		Families    []uint64 `json:"families"`
		Atomicities []uint64 `json:"atomicities"`
		Schemes     []uint64 `json:"schemes"`
	} `json:"profile"`
	Boundary struct {
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
	} `json:"boundary"`
	Roster *struct {
		Deployment uint64               `json:"deployment"`
		Source     uint64               `json:"source"`
		Principal  uint64               `json:"principal"`
		KeyID      uint64               `json:"key_id"`
		Epoch      uint64               `json:"epoch"`
		Quorum     uint64               `json:"quorum"`
		Members    [][2]json.RawMessage `json:"members"`
	} `json:"roster"`
	AttestationValid bool    `json:"attestation_valid"`
	PriorBinding     *string `json:"prior_binding"`
}

type p19Observation struct {
	ID              string     `json:"id"`
	PacketHex       string     `json:"packet_hex"`
	PacketSHA256    string     `json:"packet_sha256"`
	CoreHex         *string    `json:"core_hex"`
	PreimageHex     *string    `json:"signing_preimage_hex"`
	SelectedGroup   *[5]uint64 `json:"selected_group_deployment_source_principal_key_epoch"`
	SignatureStep   any        `json:"signature_step"`
	AdmissionStop   string     `json:"admission_stop"`
	ActualCallbacks []string   `json:"actual_callbacks"`
	Verdict         any        `json:"verdict"`
	Error           string     `json:"error"`
	Before          *string    `json:"binding_before"`
	After           *string    `json:"retained_binding"`
	BeforeCount     int        `json:"binding_count_before"`
	AfterCount      int        `json:"binding_count_after"`
	TypedOperand    []string   `json:"typed_operand_ir"`
}

func p19Error(err error) int {
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

func p19Hex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func p19Configuration(t *testing.T, row p19Input) (Profile, Boundary, []ThresholdRoster) {
	t.Helper()
	p, b := row.Profile, row.Boundary
	profile := Profile{Version: p.Version, Families: p.Families, Atomicities: p.Atomicities, Schemes: p.Schemes}
	key := p19Hex(t, b.PublicKey)
	if len(key) != 32 {
		t.Fatal("boundary public key length")
	}
	boundary := Boundary{Deployment: b.Deployment, Source: b.Source, Target: b.Target, Principal: b.Principal,
		KeyID: b.KeyID, Epoch: b.Epoch, RouteScope: b.RouteScope, Now: b.Now, AssetTTLFloor: b.AssetTTLFloor,
		FutureSkew: b.FutureSkew, VersionFloor: b.VersionFloor, MaxFrame: b.MaxFrame, MaxNesting: b.MaxNesting,
		CriticalAllowed: b.CriticalAllowed, PublicKey: [32]byte(key)}
	var rosters []ThresholdRoster
	if r := row.Roster; r != nil {
		roster := ThresholdRoster{Deployment: r.Deployment, Source: r.Source, Principal: r.Principal, KeyID: r.KeyID, Epoch: r.Epoch, Quorum: r.Quorum}
		for _, entry := range r.Members {
			var id uint64
			var keyText string
			if err := json.Unmarshal(entry[0], &id); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(entry[1], &keyText); err != nil {
				t.Fatal(err)
			}
			key := p19Hex(t, keyText)
			if len(key) != 32 {
				t.Fatal("roster public key length")
			}
			roster.Members = append(roster.Members, ThresholdMember{ID: id, PublicKey: [32]byte(key)})
		}
		rosters = []ThresholdRoster{roster}
	}
	return profile, boundary, rosters
}

// Use the real negotiation API with independent local and peer test keys.
// Roster members are never used to authenticate either channel peer.
func p19Channel(t *testing.T, profile Profile, boundary Boundary) Channel {
	t.Helper()
	localKey := ed25519.NewKeyFromSeed(slices.Repeat([]byte{6}, 32))
	remoteKey := ed25519.NewKeyFromSeed(slices.Repeat([]byte{7}, 32))
	if [32]byte(remoteKey.Public().(ed25519.PublicKey)) != boundary.PublicKey {
		t.Fatal("input boundary is not authenticated by the synthetic peer key")
	}
	context := Negotiation{Deployment: boundary.Deployment, Local: boundary.Target, Remote: boundary.Source,
		Challenge: 91, Now: boundary.Now, Floor: profile.Version,
		LocalKey: [32]byte(localKey.Public().(ed25519.PublicKey)), RemoteKey: [32]byte(remoteKey.Public().(ed25519.PublicKey))}
	local := Offer{Deployment: boundary.Deployment, Sender: boundary.Target, Receiver: boundary.Source,
		Challenge: 91, Expires: 1000, Versions: []uint64{profile.Version}, Families: profile.Families,
		Atomicities: profile.Atomicities, Schemes: profile.Schemes}
	remote := local
	remote.Sender, remote.Receiver = boundary.Source, boundary.Target
	channel, err := Negotiate(context, SignedOffers{Local: local, Remote: remote,
		LocalSignature: ed25519.Sign(localKey, OfferBytes(local)), RemoteSignature: ed25519.Sign(remoteKey, OfferBytes(remote)),
		Confirmation: ed25519.Sign(remoteKey, ConfirmationBytes(local, remote, profile))})
	if err != nil {
		t.Fatal(err)
	}
	return channel
}

func p19AdmissionObservation(raw []byte, profile Profile, boundary Boundary, rosters []ThresholdRoster) (any, string) {
	if profile.Version != 6 {
		return "not-reached", "profile"
	}
	if err := CheckDeclaredVersion(raw, boundary.MaxFrame); err != nil {
		return "not-reached", "frame/version"
	}
	packet, err := DecodePacket(raw, boundary.MaxFrame)
	if err != nil {
		return "not-reached", "canonical"
	}
	if !ReferenceAccepts(packet.Core()) {
		return "not-reached", "configured-operation"
	}
	if err := checkScope(packet.Core(), profile, boundary, 6); err != nil {
		if err == ErrTTL || err == ErrExpired {
			return "not-reached", "ttl"
		}
		return "not-reached", "scope"
	}
	if err := admitPacket(packet, profile, boundary, rosters); err != nil {
		return p19Error(err), "scheme/roster/signature"
	}
	return "accept", "passed-signature"
}

func TestThresholdTransportReplaysRawPackets(t *testing.T) {
	input, output := os.Getenv("OIP_P19_INPUT"), os.Getenv("OIP_P19_OUTPUT")
	if input == "" || output == "" {
		t.Skip("raw evidence paths are explicit")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	rows := 0
	for scanner.Scan() {
		var row p19Input
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		profile, boundary, rosters := p19Configuration(t, row)
		raw := p19Hex(t, row.PacketHex)
		digest := sha256.Sum256(raw)
		observation := p19Observation{ID: row.ID, PacketHex: row.PacketHex, PacketSHA256: hex.EncodeToString(digest[:]), ActualCallbacks: []string{}}
		store := TransportBindings{entries: map[TransportKey][]byte{}}
		var key *TransportKey
		// The full-size canonical read supplies exact evidence even when the
		// receiver subsequently refuses this frame's configured size limit.
		if packet, err := DecodePacket(raw, len(raw)); err == nil {
			coreHex := hex.EncodeToString(packet.CoreBytes())
			preimage, err := packet.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			preimageHex := hex.EncodeToString(preimage)
			observation.CoreHex, observation.PreimageHex = &coreHex, &preimageHex
			k, err := Key(packet.Core())
			if err != nil {
				t.Fatal(err)
			}
			key = &k
		}
		if key != nil && row.PriorBinding != nil {
			store.entries[*key] = p19Hex(t, *row.PriorBinding)
		}
		before := map[TransportKey][]byte{}
		for k, v := range store.entries {
			before[k] = slices.Clone(v)
		}
		observation.Before = row.PriorBinding
		observation.BeforeCount = store.Len()
		if selected := selectThresholdRoster(boundary, rosters); selected != nil {
			observation.SelectedGroup = &[5]uint64{selected.Deployment, selected.Source, selected.Principal, selected.KeyID, selected.Epoch}
		}
		observation.SignatureStep, observation.AdmissionStop = p19AdmissionObservation(raw, profile, boundary, rosters)
		channel := p19Channel(t, profile, boundary)
		arrival, packet, err := store.ReceiveConfigured(raw, channel, boundary, rosters,
			func(core *wirepb.Core) bool {
				observation.ActualCallbacks = append(observation.ActualCallbacks, "configured-operation")
				return ReferenceAccepts(core)
			},
			func(*wirepb.Core) bool {
				observation.ActualCallbacks = append(observation.ActualCallbacks, "attestation")
				return row.AttestationValid
			})
		observation.Verdict = "accept:first"
		if err != nil {
			observation.Verdict = p19Error(err)
			observation.Error = err.Error()
			if !reflect.DeepEqual(before, store.entries) {
				t.Fatalf("%s: refusal changed bindings", row.ID)
			}
		} else {
			if arrival == Identical {
				observation.Verdict = "accept:identical"
			}
			if packet == nil || packet.decodedOperands == nil || key == nil {
				t.Fatal("accepted packet missing actual operand or key")
			}
			observation.TypedOperand = TypedIRDecimal(packet.decodedOperands.TypedIR)
			if !bytes.Equal(store.entries[*key], packet.CoreBytes()) {
				t.Fatal("stored binding is not exact accepted Core")
			}
		}
		observation.AfterCount = store.Len()
		if key != nil {
			if retained, ok := store.entries[*key]; ok {
				value := hex.EncodeToString(retained)
				observation.After = &value
			}
		}
		encoded, err := json.Marshal(observation)
		if err != nil {
			t.Fatal(err)
		}
		result.Write(encoded)
		result.WriteByte('\n')
		t.Logf("%s signature=%v receive=%v binding=%d->%d", row.ID, observation.SignatureStep, observation.Verdict, observation.BeforeCount, observation.AfterCount)
		rows++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if rows != 22 {
		t.Fatal(fmt.Sprintf("raw input count %d", rows))
	}
	if err := os.WriteFile(output, result.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}
