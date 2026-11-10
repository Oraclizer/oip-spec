package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var referenceRefused = [][2]uint64{{3, 8}, {5, 2}, {6, 1}, {6, 2}, {7, 2}}

func withBody(core *wirepb.Core, family uint64, op *wirepb.Operation) *wirepb.Core {
	switch family {
	case 1:
		core.Body = &wirepb.Core_StateSync{StateSync: op}
	case 2:
		core.Body = &wirepb.Core_RegulatoryAction{RegulatoryAction: op}
	case 3:
		core.Body = &wirepb.Core_LockManagement{LockManagement: op}
	case 4:
		core.Body = &wirepb.Core_Query{Query: op}
	case 5:
		core.Body = &wirepb.Core_Ack{Ack: op}
	case 6:
		core.Body = &wirepb.Core_Heartbeat{Heartbeat: op}
	case 7:
		core.Body = &wirepb.Core_Governance{Governance: op}
	}
	return core
}

// rawFrame wraps exact Core bytes, which need not be canonical, in a packet
// signed with the fixture key.
func rawFrame(t *testing.T, core []byte) []byte {
	t.Helper()
	preimage, err := SigningBytes(core)
	if err != nil {
		t.Fatal(err)
	}
	frame := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), core)
	return protowire.AppendBytes(protowire.AppendTag(frame, 2, protowire.BytesType), ed25519.Sign(remoteKey, preimage))
}

func TestReferenceProfileAcceptsTheOperationsItExecutes(t *testing.T) {
	accepted := 0
	for family, count := range []uint64{7, 3, 8, 9, 2, 2, 2} {
		for opcode := uint64(1); opcode <= count; opcode++ {
			core := withBody(coreFixture(2, uint64(family+1), 1), uint64(family+1), &wirepb.Operation{Opcode: proto.Uint64(opcode)})
			refused := false
			for _, operation := range referenceRefused {
				refused = refused || operation == [2]uint64{uint64(family + 1), opcode}
			}
			if ReferenceAccepts(core) == refused {
				t.Fatalf("%d/%d: accepted %v", family+1, opcode, !refused)
			}
			if !refused {
				accepted++
			}
		}
	}
	if accepted != 28 {
		t.Fatalf("accepted %d operations", accepted)
	}
}

func TestUnsupportedOperationsAreRefusedBeforeAnySignatureCheck(t *testing.T) {
	var store TransportBindings
	for index, operation := range referenceRefused {
		core := withBody(coreFixture(2, operation[0], byte(30+index)), operation[0],
			&wirepb.Operation{Opcode: proto.Uint64(operation[1]), Words: []uint64{1, 2}})
		frame := signFixture(t, core)
		tampered := append([]byte(nil), frame...)
		tampered[len(tampered)-1] ^= 1
		for _, raw := range [][]byte{frame, tampered} {
			_, _, err := store.ReceiveAccepting(raw, fixtureProfile(), fixtureBoundary(), ReferenceAccepts, attest)
			if !errors.Is(err, ErrVersion) {
				t.Fatalf("%v: got %v", operation, err)
			}
		}
		// The same frame with a bad signature reaches the signature check when
		// the configuration accepts the operation.
		if _, _, err := store.Receive(tampered, fixtureProfile(), fixtureBoundary(), attest); !errors.Is(err, ErrSignature) {
			t.Fatalf("%v accepted: got %v", operation, err)
		}
	}
	if store.Len() != 0 {
		t.Fatalf("a refused frame was bound: %d", store.Len())
	}
	if arrival, _, err := store.ReceiveAccepting(signFixture(t, canonicalFixture()), fixtureProfile(), fixtureBoundary(),
		ReferenceAccepts, attest); err != nil || arrival != First {
		t.Fatalf("accepted operation: %v %v", arrival, err)
	}
}

func TestDeclaredVersionIsReadBeforeDecoding(t *testing.T) {
	core, err := EncodeCore(canonicalFixture())
	if err != nil {
		t.Fatal(err)
	}
	if string(rawFrame(t, core)) != string(signFixture(t, canonicalFixture())) {
		t.Fatal("raw frame differs from the canonical encoding")
	}
	declared := func(version byte, extension ...byte) []byte {
		if core[0] != 0x08 || core[1] != 6 {
			t.Fatal("the fixture does not start with the version")
		}
		bytes := append([]byte{core[0], version}, core[2:]...)
		return rawFrame(t, append(bytes, extension...))
	}
	// Core field 26 is not defined by version 6.
	field26 := []byte{0xd0, 0x01, 0x01}
	for _, test := range []struct {
		name  string
		frame []byte
		want  error
	}{
		{"current", declared(6), nil},
		{"earlier", declared(5), ErrVersion},
		{"later", declared(7), ErrVersion},
		{"later with a new field", declared(7, field26...), ErrVersion},
		{"current with an unknown field", declared(6, field26...), ErrFormat},
	} {
		var store TransportBindings
		_, _, err := store.Receive(test.frame, fixtureProfile(), fixtureBoundary(), attest)
		if !errors.Is(err, test.want) && !(err == nil && test.want == nil) {
			t.Fatalf("%s: got %v, want %v", test.name, err, test.want)
		}
	}
	later := declared(7, field26...)
	if version, ok := DeclaredVersion(later); !ok || version != 7 {
		t.Fatalf("declared version %d %v", version, ok)
	}
	if err := CheckDeclaredVersion(later, len(later)-1); !errors.Is(err, ErrFormat) {
		t.Fatalf("size limit first: %v", err)
	}
	for _, frame := range [][]byte{{}, {0x0a, 0x02, 0x10, 0x01}, {0x0a, 0x05, 0x08, 0x07}} {
		if _, ok := DeclaredVersion(frame); ok {
			t.Fatalf("%x declares a version", frame)
		}
		if err := CheckDeclaredVersion(frame, 16); err != nil {
			t.Fatalf("%x: %v", frame, err)
		}
	}
}

func TestLegacyChecksFollowTheReferenceOrder(t *testing.T) {
	legacy := LegacyCore{Version: 5, Deployment: 7, Source: 0, Target: 2, Principal: 7, Key: 9, Epoch: 9, Sent: 100,
		TTL: 5, UUID: "not hex", Family: 1, Opcode: 1, Words: []uint64{1}, Atomicity: 3, Scope: 1}
	encode := func(packet LegacyPacket) []byte {
		raw, err := json.Marshal(packet)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	profile := Profile{Version: 5, Families: []uint64{4, 6}, Atomicities: []uint64{1, 2, 3}, Schemes: []uint64{1}}
	// An operation outside the compatibility subset is refused before its UUID is read.
	if _, _, err := DecodeLegacy(encode(LegacyPacket{Core: legacy, Signature: "00"}), profile, fixtureBoundary()); !errors.Is(err, ErrVersion) {
		t.Fatalf("subset first: %v", err)
	}
	legacy.Family, legacy.Opcode, legacy.UUID, legacy.Words = 4, 1, hex.EncodeToString(canonicalUUID), []uint64{1, 0, 1, 17}
	// A profile without the legacy scheme refuses the signature before its encoding is read.
	noScheme := profile
	noScheme.Schemes = nil
	if _, _, err := DecodeLegacy(encode(LegacyPacket{Core: legacy, Signature: "zz"}), noScheme, fixtureBoundary()); !errors.Is(err, ErrSignature) {
		t.Fatalf("scheme first: %v", err)
	}
	if _, _, err := DecodeLegacy(encode(LegacyPacket{Core: legacy, Signature: "zz"}), profile, fixtureBoundary()); !errors.Is(err, ErrFormat) {
		t.Fatalf("signature encoding: %v", err)
	}
}
