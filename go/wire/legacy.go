package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

type LegacyCore struct {
	Version    uint64   `json:"version"`
	Deployment uint64   `json:"deployment"`
	Source     uint64   `json:"source"`
	Target     uint64   `json:"target"`
	Principal  uint64   `json:"principal"`
	Key        uint64   `json:"key"`
	Epoch      uint64   `json:"epoch"`
	Sent       uint64   `json:"sent"`
	TTL        uint64   `json:"ttl"`
	UUID       string   `json:"uuid"`
	Family     uint64   `json:"family"`
	Opcode     uint64   `json:"opcode"`
	Words      []uint64 `json:"words"`
	Atomicity  uint64   `json:"atomicity"`
	Scope      uint64   `json:"scope"`
}

type LegacyPacket struct {
	Core      LegacyCore `json:"core"`
	Signature string     `json:"signature"`
}

func (core LegacyCore) SigningBytes() ([]byte, error) {
	body, err := json.Marshal(core)
	if err != nil {
		return nil, ErrFormat
	}
	return append([]byte("OIP\x00LEGACY\x00"), body...), nil
}

func (core LegacyCore) typed() (*wirepb.Core, error) {
	// The compatibility record carries only the Query and Heartbeat subset.
	if (core.Family != 4 && core.Family != 6) || core.Opcode < 1 || core.Opcode > 2 {
		return nil, ErrVersion
	}
	uuid, err := hex.DecodeString(core.UUID)
	if err != nil || hex.EncodeToString(uuid) != core.UUID {
		return nil, ErrFormat
	}
	op := &wirepb.Operation{Opcode: proto.Uint64(core.Opcode), Words: slices.Clone(core.Words)}
	typed := &wirepb.Core{
		Version: proto.Uint64(core.Version), Purpose: proto.Uint64(1),
		Deployment: proto.Uint64(core.Deployment), SourceDomain: proto.Uint64(core.Source),
		TargetDomain: proto.Uint64(core.Target), Principal: proto.Uint64(core.Principal),
		KeyId: proto.Uint64(core.Key), AuthorityEpoch: proto.Uint64(core.Epoch),
		IssuedSeconds: proto.Uint64(core.Sent), TtlSeconds: proto.Uint64(core.TTL),
		Uuid: uuid, Family: proto.Uint64(core.Family), Primary: proto.Uint64(1),
		SignatureScheme: proto.Uint64(1), Atomicity: proto.Uint64(core.Atomicity),
		Priority: proto.Uint64(3), RouteScope: proto.Uint64(core.Scope),
	}
	if core.Family == 4 {
		typed.Body = &wirepb.Core_Query{Query: op}
	} else {
		typed.Body = &wirepb.Core_Heartbeat{Heartbeat: op}
	}
	if _, err := EncodeCore(typed); err != nil {
		return nil, err
	}
	return typed, nil
}

func DecodeLegacy(raw []byte, profile Profile, boundary Boundary) (*wirepb.Core, []byte, error) {
	if profile.Version != 5 {
		return nil, nil, ErrVersion
	}
	if len(raw) > boundary.MaxFrame {
		return nil, nil, ErrFormat
	}
	var packet LegacyPacket
	if !canonicalJSON(raw, &packet) {
		return nil, nil, ErrFormat
	}
	core, err := packet.Core.typed()
	if err != nil {
		return nil, nil, err
	}
	if err := checkScope(core, profile, boundary, 5); err != nil {
		return nil, nil, err
	}
	// The scheme check comes first, then the signature encoding, then the
	// signature itself, as in the reference decoder.
	if !slices.Contains(profile.Schemes, uint64(1)) {
		return nil, nil, ErrSignature
	}
	preimage, err := packet.Core.SigningBytes()
	if err != nil {
		return nil, nil, ErrFormat
	}
	signature, err := hex.DecodeString(packet.Signature)
	if err != nil || hex.EncodeToString(signature) != packet.Signature {
		return nil, nil, ErrFormat
	}
	if !verify(boundary.PublicKey, preimage, signature) {
		return nil, nil, ErrSignature
	}
	if _, err := DecodeOperands(core, boundary.MaxNesting); err != nil {
		return nil, nil, err
	}
	exact, err := json.Marshal(packet.Core)
	if err != nil {
		return nil, nil, ErrFormat
	}
	return core, exact, nil
}

// ReceiveVersioned uses the negotiated codec once. A modern failure cannot
// enter the configured legacy adapter.
func (store *TransportBindings) ReceiveVersioned(raw []byte, channel Channel, boundary Boundary,
	legacyConfigured bool, attest func(*wirepb.Core) bool) (Arrival, *wirepb.Core, error) {
	if channel.deployment != boundary.Deployment || channel.local != boundary.Target ||
		channel.remote != boundary.Source || channel.expires < boundary.Now {
		return First, nil, ErrSource
	}
	switch channel.profile.Version {
	case 6:
		if channel.keys[1] != boundary.PublicKey {
			return First, nil, ErrSource
		}
		arrival, packet, err := store.Receive(raw, channel.profile, boundary, attest)
		if err != nil {
			return First, nil, err
		}
		return arrival, packet.Core(), nil
	case 5:
		if !legacyConfigured {
			return First, nil, ErrVersion
		}
		// DecodeLegacy has already decoded the operands of the admitted Core.
		core, exact, err := DecodeLegacy(raw, channel.profile, boundary)
		if err != nil {
			return First, nil, err
		}
		// Keep attestation mutations separate from the admitted Core and key.
		if !attest(proto.Clone(core).(*wirepb.Core)) {
			return First, nil, ErrSource
		}
		key, err := Key(core)
		if err != nil {
			return First, nil, err
		}
		arrival, err := store.bind(key, exact)
		if err != nil {
			return First, nil, err
		}
		return arrival, core, nil
	default:
		return First, nil, ErrVersion
	}
}

func EqualCore(a, b *wirepb.Core) bool {
	left, err := EncodeCore(a)
	if err != nil {
		return false
	}
	right, err := EncodeCore(b)
	return err == nil && bytes.Equal(left, right)
}

var ErrCancelled = errors.New("CANCELLED")
var ErrDeadline = errors.New("DEADLINE_EXPIRED")

func (store *TransportBindings) ReceiveBeforeCommit(raw []byte, channel Channel, boundary Boundary,
	legacyConfigured bool, cancelled bool, deadline *uint64,
	attest func(*wirepb.Core) bool) (Arrival, *wirepb.Core, error) {
	if cancelled {
		return First, nil, ErrCancelled
	}
	if deadline != nil && boundary.Now > *deadline {
		return First, nil, ErrDeadline
	}
	return store.ReceiveVersioned(raw, channel, boundary, legacyConfigured, attest)
}
