package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

func mutateCallbackCore(core *wirepb.Core) {
	*core.Principal = 999
	core.Uuid[0] ^= 1
	_, operation := Body(core)
	operation.Words[len(operation.Words)-1]++
	for _, blob := range operation.Blobs {
		if len(blob) != 0 {
			blob[len(blob)-1]++
		}
	}
}

func TestReceiveAcceptingIsolatesCallbackMutations(t *testing.T) {
	fixtures := []struct {
		name string
		core func() *wirepb.Core
	}{
		{"query", canonicalFixture},
		{"debit_with_blob", debitFixture},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			for _, phase := range []string{"accepts", "attest", "both"} {
				t.Run(phase, func(t *testing.T) {
					original := fixture.core()
					boundary := fixtureBoundary()
					boundary.Target = original.GetTargetDomain()
					raw := signFixture(t, original)
					coreBytes, err := EncodeCore(original)
					if err != nil {
						t.Fatal(err)
					}
					wantOperands, err := DecodeOperands(original, boundary.MaxNesting)
					if err != nil {
						t.Fatal(err)
					}
					wantKey, err := Key(original)
					if err != nil {
						t.Fatal(err)
					}
					var store TransportBindings
					var calls []string
					var callbackInputs []*wirepb.Core
					callback := func(name string, mutate bool) func(*wirepb.Core) bool {
						return func(core *wirepb.Core) bool {
							calls = append(calls, name)
							callbackInputs = append(callbackInputs, core)
							if !proto.Equal(core, original) {
								t.Errorf("%s did not receive the signed original", name)
							}
							if mutate {
								mutateCallbackCore(core)
							}
							return true
						}
					}
					checkPacket := func(packet *CanonicalPacket) {
						t.Helper()
						if packet == nil || packet.decodedOperands == nil {
							t.Fatal("accepted packet lost its decoded operands")
						}
						if !proto.Equal(packet.Core(), original) || !bytes.Equal(packet.CoreBytes(), coreBytes) {
							t.Error("returned Core differs from the signed original")
						}
						encoded, err := packet.Encode()
						if err != nil || !bytes.Equal(encoded, raw) {
							t.Errorf("signed packet changed: %v", err)
						}
						if !reflect.DeepEqual(packet.decodedOperands.TypedIR, wantOperands.TypedIR) ||
							!reflect.DeepEqual(packet.decodedOperands.Words, wantOperands.Words) ||
							!reflect.DeepEqual(packet.decodedOperands.Blobs, wantOperands.Blobs) {
							t.Error("returned operands differ from the signed original")
						}
						if store.Len() != 1 || !bytes.Equal(store.entries[wantKey], coreBytes) {
							t.Errorf("binding differs from the original transport key: %d keys", store.Len())
						}
					}
					arrival, packet, err := store.ReceiveAccepting(raw, fixtureProfile(), boundary,
						callback("accepts", phase == "accepts" || phase == "both"),
						callback("attest", phase == "attest" || phase == "both"))
					if err != nil || arrival != First {
						t.Fatalf("first receive: %v %v", arrival, err)
					}
					if !reflect.DeepEqual(calls, []string{"accepts", "attest"}) {
						t.Fatalf("callback order changed: %v", calls)
					}
					checkPacket(packet)
					// Retained callback arguments cannot change returned operand slices.
					for _, core := range callbackInputs {
						mutateCallbackCore(core)
					}
					checkPacket(packet)
					calls = nil
					arrival, packet, err = store.ReceiveAccepting(raw, fixtureProfile(), boundary,
						callback("accepts", false), callback("attest", false))
					if err != nil || arrival != Identical {
						t.Fatalf("same signed original must be identical: %v %v", arrival, err)
					}
					if !reflect.DeepEqual(calls, []string{"accepts", "attest"}) {
						t.Fatalf("repeat callback order changed: %v", calls)
					}
					checkPacket(packet)
				})
			}
		})
	}
}

func TestReceiveVersionedIsolatesLegacyAttestationMutation(t *testing.T) {
	channel, err := fixtureNegotiation([]uint64{5, 6}, []uint64{5}, 5, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	boundary := fixtureBoundary()
	raw := legacyFixture(t, 4, 1, 201, []uint64{1, 0, 1, 17})
	original, exact, err := DecodeLegacy(raw, channel.Profile(), boundary)
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := Key(original)
	if err != nil {
		t.Fatal(err)
	}
	wantOperands, err := DecodeOperands(original, boundary.MaxNesting)
	if err != nil {
		t.Fatal(err)
	}
	var store TransportBindings
	var callbackInput *wirepb.Core
	arrival, returned, err := store.ReceiveVersioned(raw, channel, boundary, true, func(core *wirepb.Core) bool {
		if !proto.Equal(core, original) {
			t.Error("legacy attestation did not receive the signed original")
		}
		callbackInput = core
		mutateCallbackCore(core)
		return true
	})
	if err != nil || arrival != First {
		t.Fatalf("first legacy receive: %v %v", arrival, err)
	}
	checkCore := func(core *wirepb.Core) {
		t.Helper()
		if !proto.Equal(core, original) {
			t.Error("legacy returned Core differs from its signed original")
		}
		operands, err := DecodeOperands(core, boundary.MaxNesting)
		if err != nil || !reflect.DeepEqual(operands.TypedIR, wantOperands.TypedIR) {
			t.Errorf("legacy operands differ from the original: %v", err)
		}
		if store.Len() != 1 || !bytes.Equal(store.entries[wantKey], exact) {
			t.Errorf("legacy binding differs from the original transport key: %d keys", store.Len())
		}
	}
	checkCore(returned)
	mutateCallbackCore(callbackInput)
	checkCore(returned)
	arrival, returned, err = store.ReceiveVersioned(raw, channel, boundary, true, func(core *wirepb.Core) bool {
		if !proto.Equal(core, original) {
			t.Error("repeated legacy attestation did not receive the signed original")
		}
		return true
	})
	if err != nil || arrival != Identical {
		t.Fatalf("same signed legacy original must be identical: %v %v", arrival, err)
	}
	checkCore(returned)
}
