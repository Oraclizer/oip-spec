// Package wire checks original OIP bytes before generated protobuf decoding.
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var (
	ErrFormat    = errors.New("INVALID_FORMAT")
	ErrVersion   = errors.New("UNSUPPORTED_VERSION")
	ErrSource    = errors.New("INVALID_SOURCE")
	ErrSignature = errors.New("INVALID_SIGNATURE")
	ErrThreshold = errors.New("INVALID_THRESHOLD_SIGNATURE")
	ErrExpired   = errors.New("TTL_EXPIRED")
	ErrTTL       = errors.New("TTL_INVALID")
	ErrReplay    = errors.New("REPLAY_CONFLICT")
)

type field struct {
	tag  uint32
	kind uint64
	word uint64
	data []byte
}

func rawVarint(data []byte) (uint64, int) {
	value, n := protowire.ConsumeVarint(data)
	if n < 0 || n != protowire.SizeVarint(value) {
		return 0, -1
	}
	return value, n
}

func fields(data []byte) ([]field, error) {
	var result []field
	for len(data) > 0 {
		key, n := rawVarint(data)
		if n < 0 || key>>3 == 0 || key>>3 > (1<<29)-1 {
			return nil, ErrFormat
		}
		data = data[n:]
		f := field{tag: uint32(key >> 3), kind: key & 7}
		switch f.kind {
		case 0:
			value, n := rawVarint(data)
			if n < 0 {
				return nil, ErrFormat
			}
			f.word = value
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return nil, ErrFormat
			}
			f.word = binary.LittleEndian.Uint64(data[:8])
			data = data[8:]
		case 2:
			size, n := rawVarint(data)
			if n < 0 || size > uint64(len(data)-n) {
				return nil, ErrFormat
			}
			f.data = data[n : n+int(size)]
			data = data[n+int(size):]
		default:
			return nil, ErrFormat
		}
		result = append(result, f)
	}
	return result, nil
}

func is(f field, tag uint32, kind uint64) bool { return f.tag == tag && f.kind == kind }

func verifyOperation(data []byte) error {
	values, err := fields(data)
	if err != nil || len(values) == 0 || !is(values[0], 1, 0) {
		return ErrFormat
	}
	i := 1
	for i < len(values) && is(values[i], 2, 1) {
		i++
	}
	for i < len(values) && is(values[i], 3, 2) {
		i++
	}
	if i == len(values) {
		return nil
	}
	if i+1 == len(values) && ((is(values[i], 4, 0) && values[i].word == 1) || is(values[i], 5, 1)) {
		return nil
	}
	return ErrFormat
}

func verifyCore(data []byte) error {
	values, err := fields(data)
	if err != nil || len(values) < 18 {
		return ErrFormat
	}
	for i, kind := range []uint64{0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0} {
		if !is(values[i], uint32(i+1), kind) {
			return ErrFormat
		}
	}
	family := values[11].word
	if family < 1 || family > 7 {
		return ErrFormat
	}
	tail := values[13:]
	if is(tail[0], 14, 0) {
		tail = tail[1:]
	}
	if len(tail) != 5 || !is(tail[0], 15, 0) || !is(tail[1], uint32(15+family), 2) ||
		!is(tail[2], 23, 0) || !is(tail[3], 24, 0) || !is(tail[4], 25, 1) {
		return ErrFormat
	}
	return verifyOperation(tail[1].data)
}

func appendVarint(out []byte, tag protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(out, tag, protowire.VarintType), value)
}
func appendFixed64(out []byte, tag protowire.Number, value uint64) []byte {
	return protowire.AppendFixed64(protowire.AppendTag(out, tag, protowire.Fixed64Type), value)
}
func appendBytes(out []byte, tag protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(out, tag, protowire.BytesType), value)
}

func Body(core *wirepb.Core) (uint64, *wirepb.Operation) {
	switch body := core.GetBody().(type) {
	case *wirepb.Core_StateSync:
		return 1, body.StateSync
	case *wirepb.Core_RegulatoryAction:
		return 2, body.RegulatoryAction
	case *wirepb.Core_LockManagement:
		return 3, body.LockManagement
	case *wirepb.Core_Query:
		return 4, body.Query
	case *wirepb.Core_Ack:
		return 5, body.Ack
	case *wirepb.Core_Heartbeat:
		return 6, body.Heartbeat
	case *wirepb.Core_Governance:
		return 7, body.Governance
	default:
		return 0, nil
	}
}

func encodeOperation(op *wirepb.Operation) ([]byte, error) {
	if op == nil || op.Opcode == nil {
		return nil, ErrFormat
	}
	out := appendVarint(nil, 1, *op.Opcode)
	for _, word := range op.Words {
		out = appendFixed64(out, 2, word)
	}
	for _, blob := range op.Blobs {
		out = appendBytes(out, 3, blob)
	}
	switch deadline := op.GetAppealDeadline().(type) {
	case nil:
	case *wirepb.Operation_AppealDeadlineIndefinite:
		if !deadline.AppealDeadlineIndefinite {
			return nil, ErrFormat
		}
		out = appendVarint(out, 4, 1)
	case *wirepb.Operation_AppealDeadlineUtcSeconds:
		out = appendFixed64(out, 5, deadline.AppealDeadlineUtcSeconds)
	default:
		return nil, ErrFormat
	}
	return out, nil
}

func EncodeCore(core *wirepb.Core) ([]byte, error) {
	if core == nil {
		return nil, ErrFormat
	}
	family, op := Body(core)
	if family == 0 || op == nil || core.Family == nil || core.GetFamily() != family ||
		core.Version == nil || core.Purpose == nil || core.Primary == nil || core.SignatureScheme == nil ||
		core.Atomicity == nil || core.Priority == nil || core.RouteScope == nil ||
		len(core.Uuid) != 16 || core.Uuid[6]>>4 != 4 || core.Uuid[8]>>6 != 2 {
		return nil, ErrFormat
	}
	primary, scheme, atomicity, priority := core.GetPrimary(), core.GetSignatureScheme(), core.GetAtomicity(), core.GetPriority()
	last := [...]uint64{7, 3, 8, 9, 2, 2, 2}
	if primary < 1 || primary > 5 || (scheme != 1 && scheme != 2) || atomicity < 1 || atomicity > 3 ||
		priority > 4 || (priority == 0 && atomicity != 3) || op.GetOpcode() < 1 || op.GetOpcode() > last[family-1] {
		return nil, ErrFormat
	}
	encoded, err := encodeOperation(op)
	if err != nil {
		return nil, err
	}
	out := appendVarint(nil, 1, core.GetVersion())
	out = appendVarint(out, 2, core.GetPurpose())
	for i, v := range []*uint64{core.Deployment, core.SourceDomain, core.TargetDomain, core.Principal, core.KeyId,
		core.AuthorityEpoch, core.IssuedSeconds, core.TtlSeconds} {
		if v == nil {
			return nil, ErrFormat
		}
		out = appendFixed64(out, protowire.Number(i+3), *v)
	}
	out = appendBytes(out, 11, core.Uuid)
	out = appendVarint(out, 12, family)
	out = appendVarint(out, 13, primary)
	if core.Secondary != nil {
		out = appendVarint(out, 14, *core.Secondary)
	}
	out = appendVarint(out, 15, scheme)
	out = appendBytes(out, protowire.Number(15+family), encoded)
	out = appendVarint(out, 23, atomicity)
	out = appendVarint(out, 24, priority)
	out = appendFixed64(out, 25, core.GetRouteScope())
	return out, nil
}

func DecodeCore(raw []byte) (*wirepb.Core, error) {
	if err := verifyCore(raw); err != nil {
		return nil, err
	}
	core := new(wirepb.Core)
	if err := proto.Unmarshal(raw, core); err != nil {
		return nil, ErrFormat
	}
	exact, err := EncodeCore(core)
	if err != nil || !bytes.Equal(exact, raw) {
		return nil, ErrFormat
	}
	return core, nil
}

func EncodePacket(packet *wirepb.Packet) ([]byte, error) {
	if packet == nil || packet.Core == nil {
		return nil, ErrFormat
	}
	scheme := packet.Core.GetSignatureScheme()
	if (scheme == 1 && len(packet.Signature) != 64) || (scheme == 2 && len(packet.Signature) == 0) {
		return nil, ErrFormat
	}
	core, err := EncodeCore(packet.Core)
	if err != nil || uint64(len(core)) > math.MaxUint32 {
		return nil, ErrFormat
	}
	return appendBytes(appendBytes(nil, 1, core), 2, packet.Signature), nil
}

// CanonicalPacket cannot be constructed with caller-supplied typed fields.
type CanonicalPacket struct {
	// Exact typed result from this packet's successful Receive path.
	decodedOperands *Operands
	packet *wirepb.Packet
	exact  []byte
}

func (packet *CanonicalPacket) Core() *wirepb.Core {
	return proto.Clone(packet.packet.Core).(*wirepb.Core)
}
func (packet *CanonicalPacket) CoreBytes() []byte             { return bytes.Clone(packet.exact) }
func (packet *CanonicalPacket) Encode() ([]byte, error)       { return EncodePacket(packet.packet) }
func (packet *CanonicalPacket) SigningBytes() ([]byte, error) { return SigningBytes(packet.exact) }

func DecodePacket(raw []byte, maxFrame int) (*CanonicalPacket, error) {
	if maxFrame < 0 || len(raw) > maxFrame {
		return nil, ErrFormat
	}
	values, err := fields(raw)
	if err != nil || len(values) != 2 || !is(values[0], 1, 2) || !is(values[1], 2, 2) {
		return nil, ErrFormat
	}
	core, err := DecodeCore(values[0].data)
	if err != nil {
		return nil, err
	}
	packet := new(wirepb.Packet)
	if err := proto.Unmarshal(raw, packet); err != nil || !proto.Equal(core, packet.Core) {
		return nil, ErrFormat
	}
	exact, err := EncodePacket(packet)
	if err != nil || !bytes.Equal(exact, raw) {
		return nil, ErrFormat
	}
	return &CanonicalPacket{packet: packet, exact: bytes.Clone(values[0].data)}, nil
}

// DeclaredVersion returns the varint of core field 1 when the frame starts
// with packet field 1 and the core it carries starts with field 1. Nothing
// else in the frame is read, so the answer does not depend on fields that a
// later version may add. A frame that does not start this way declares no
// version, and the canonical decoder reports it.
func DeclaredVersion(raw []byte) (uint64, bool) {
	key, n := rawVarint(raw)
	if n < 0 || key != 1<<3|2 {
		return 0, false
	}
	raw = raw[n:]
	size, n := rawVarint(raw)
	if n < 0 || size > uint64(len(raw)-n) {
		return 0, false
	}
	core := raw[n : n+int(size)]
	key, n = rawVarint(core)
	if n < 0 || key != 1<<3 {
		return 0, false
	}
	version, n := rawVarint(core[n:])
	return version, n >= 0
}

// CheckDeclaredVersion is the version check that runs in front of the
// canonical decoder and the admission gate. A frame within the size limit
// that declares a version other than 6 receives ErrVersion, whatever fields
// follow. Every other frame continues to the canonical checks unchanged.
func CheckDeclaredVersion(raw []byte, maxFrame int) error {
	if maxFrame < 0 || len(raw) > maxFrame {
		return ErrFormat
	}
	if version, ok := DeclaredVersion(raw); ok && version != 6 {
		return ErrVersion
	}
	return nil
}

func SigningBytes(core []byte) ([]byte, error) {
	if uint64(len(core)) > math.MaxUint32 {
		return nil, ErrFormat
	}
	out := []byte("OIP\x00ENVELOPE\x00")
	out = binary.BigEndian.AppendUint32(out, uint32(len(core)))
	return append(out, core...), nil
}

type Unsigned256 [32]byte

func DecodeAmount(raw []byte) (Unsigned256, error) {
	if len(raw) != 32 {
		return Unsigned256{}, ErrFormat
	}
	return Unsigned256(raw), nil
}
func (amount Unsigned256) ProductAmount() (uint64, error) {
	for _, byte := range amount[:24] {
		if byte != 0 {
			return 0, ErrFormat
		}
	}
	return binary.BigEndian.Uint64(amount[24:]), nil
}
