package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestWriteModelCoreUsesConfiguredSignedReceiver(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "write-core-vectors.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(string(fixture)), "\t")
	if len(fields) != 3 || fields[0] != "I" || fields[1] != "write-core" {
		t.Fatal("unexpected Write fixture")
	}
	exact, err := hex.DecodeString(fields[2])
	if err != nil || len(exact) != 363 {
		t.Fatalf("Write Core length %d, decode error %v", len(exact), err)
	}
	packet := rawFrame(t, exact)
	boundary := fixtureBoundary()
	boundary.Target = 0
	var store TransportBindings
	tampered := bytes.Clone(packet)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := store.ReceiveAccepting(tampered, fixtureProfile(), boundary, ReferenceAccepts, attest); err != ErrSignature || store.Len() != 0 {
		t.Fatalf("changed signature returned %v with %d bindings", err, store.Len())
	}
	arrival, accepted, err := store.ReceiveAccepting(packet, fixtureProfile(), boundary, ReferenceAccepts, attest)
	if err != nil || arrival != First || !bytes.Equal(accepted.CoreBytes(), exact) {
		t.Fatalf("Write fixture admission returned %v, %v", arrival, err)
	}
	operand := accepted.decodedOperands
	origin := Origin{Domain: 0, Event: 17}
	expected := Native{
		Namespace: 7, Endpoint: 0, Caller: 7, Reference: 1, Sequence: 1,
		Session: 1, Revision: 0, OriginEpoch: 9,
		Binding:    Binding{Origin: origin, Asset: 17, Owner: 3, Destination: 2, Recipient: 3, Amount: 5},
		Credential: &Credential{Asset: 17, Origin: origin, Holder: 7, Generation: 0, Epoch: 9},
		Versions:   [][2]uint64{{17, 0}},
	}
	expected.Summary = valueNode(10, valueNative(&expected, 9),
		valueCredential(expected.Credential), valueVersions(expected.Versions),
		valueNode(121, valueScalar(0), valueScalar(9)), valueProofs(nil))
	if operand == nil || operand.Family != 3 || operand.Opcode != 7 || operand.Session != 1 ||
		!reflect.DeepEqual(operand.Native, &expected) || !reflect.DeepEqual(operand.TypedIR, expected.Summary) {
		t.Fatalf("unexpected typed Write operand %#v", operand)
	}
	if arrival, _, err := store.ReceiveAccepting(packet, fixtureProfile(), boundary, ReferenceAccepts, attest); err != nil || arrival != Identical || store.Len() != 1 {
		t.Fatalf("exact Write retry returned %v, %v with %d bindings", arrival, err, store.Len())
	}
	timeout := accepted.Core()
	_, operation := Body(timeout)
	operation.Opcode = proto.Uint64(8)
	operation.Words = operation.Words[:len(operation.Words)-1]
	operation.Words[len(operation.Words)-1] = 1
	if _, err := DecodeOperands(timeout, boundary.MaxNesting); err != nil {
		t.Fatalf("Timeout fixture has invalid operands: %v", err)
	}
	if _, _, err := store.ReceiveAccepting(signFixture(t, timeout), fixtureProfile(), boundary, ReferenceAccepts, attest); err != ErrVersion || store.Len() != 1 {
		t.Fatalf("Timeout returned %v with %d bindings", err, store.Len())
	}
	t.Logf("write-go-input\t%x\t%x", sha256.Sum256(exact), sha256.Sum256(packet))
}
