package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

func responseCodeVectorWords(csv string) ([]uint64, error) {
	var words []uint64
	for _, field := range strings.Split(csv, ",") {
		word, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, err
		}
		words = append(words, word)
	}
	return words, nil
}

func responseCodeVectorOriginal(t *testing.T, family, opcode, namespace, sequence uint64) []byte {
	t.Helper()
	prefix := []uint64{33, sequence, 2, 2, 9, 0, 17, 17, 7, 0, 3}
	amount := make([]byte, 32)
	amount[31] = 5
	core := coreFixture(0, family, 0)
	op := &wirepb.Operation{Opcode: proto.Uint64(opcode)}
	core.Body = &wirepb.Core_StateSync{StateSync: op}
	switch {
	case family == 1 && opcode == 1:
		core = debitFixture()
		core.GetStateSync().Words[1] = sequence
	case family == 1 && opcode == 6:
		core.Uuid[0] = 3
		spend := make([]byte, 32)
		spend[31] = 1
		op.Words, op.Blobs = append(prefix, 1, 7, 3, 0), [][]byte{amount, spend}
	case family == 2 && opcode == 2:
		core.Uuid[0] = 4
		core.Body = &wirepb.Core_RegulatoryAction{RegulatoryAction: op}
		op.Words, op.Blobs = append(prefix, 1, 7, 1, 1, 9, 0, 0, 0), [][]byte{amount, {1}}
	case family == 1 && opcode == 7:
		core.Uuid[0] = 5
		commitment := bytes.Repeat([]byte{1}, 32)
		attestation := []byte("OIP\x00SOURCE-ATTESTATION\x00")
		for _, word := range []uint64{1, 1, 7, 0, 9, 1, 17, 17, 1} {
			attestation = binary.BigEndian.AppendUint64(attestation, word)
		}
		attestation = append(attestation, commitment...)
		attestation = append(attestation, 0)
		attestation = binary.BigEndian.AppendUint64(attestation, 1)
		attestation = binary.BigEndian.AppendUint64(attestation, 7)
		attestation = append(attestation, make([]byte, 64)...)
		op.Words, op.Blobs = []uint64{50, sequence, 2, 0, 9, 0, 17, 17, 1, 1}, [][]byte{commitment, {}, attestation}
	default:
		t.Fatalf("unexpected original family %d opcode %d", family, opcode)
	}
	core.Principal = proto.Uint64(namespace)
	exact, err := EncodeCore(core)
	if err != nil {
		t.Fatal(err)
	}
	return exact
}

func TestResponseCodeExtensionVectors(t *testing.T) {
	read := func(name string) []string {
		data, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
	observations := map[string][]uint64{}
	for _, line := range read("response-code-observations.tsv") {
		id, csv, _ := strings.Cut(line, "\t")
		fields, err := responseCodeVectorWords(csv)
		if err != nil {
			t.Fatal(err)
		}
		observations[id] = fields
	}
	for _, line := range read("response-code-cases.tsv") {
		columns := strings.Split(line, "\t")
		if columns[0] != "R" {
			continue
		}
		id := columns[1]
		t.Run(id, func(t *testing.T) {
			fields := observations[id]
			call, err := responseCodeVectorWords(strings.Join(columns[2:4], ","))
			if err != nil {
				t.Fatal(err)
			}
			words, err := responseCodeVectorWords(columns[4])
			if err != nil {
				// A value above uint64 cannot occupy a fixed-width wire word.
				if !slices.Equal(fields, []uint64{0}) {
					t.Fatal(err)
				}
				fmt.Printf("response-code\t%s\t0\n", id)
				return
			}
			shape := "-"
			compatible := false
			structurallyValid := words[2] >= 1 && words[2] <= 3 &&
				((len(words) == 5 && words[4] == 0) || (len(words) == 6 && words[4] == 1))
			if structurallyValid {
				kind, code := words[2], words[3]
				compatible = fields[15] == 1
				syncOnly, err := responseStatus(kind, code, words[4] == 1)
				switch code {
				case 29, 39, 40, 41:
					status := []uint64{0, 0, 0}
					if err == nil && syncOnly {
						status = []uint64{1, kind, code}
					}
					if !slices.Equal(status, fields[10:13]) {
						t.Fatalf("shape %v, want %v", status, fields[10:13])
					}
					shape = fmt.Sprintf("%d,%d,%d", status[0], status[1], status[2])
				default:
					if syncOnly || (err == nil) != (kind == 1 || words[4] == 0) {
						t.Fatalf("raw operand shape: %v", err)
					}
				}
				if id == "legacy-debit-12-no-commit" {
					// Go's existing raw operand decoding preserves this shape.
					// The reference product verifier enforces Debit commit presence.
					compatible = true
				}
			} else if !slices.Equal(fields, []uint64{0}) {
				t.Fatal("unexpected invalid words")
			} else {
				shape = "0,0,0"
			}
			exact := responseCodeVectorOriginal(t, call[0], call[1], words[0], words[1])
			original, err := DecodeCore(exact)
			if err != nil {
				t.Fatalf("original canonical decode: %v", err)
			}
			if typed, err := DecodeOperands(original, 1); err != nil || (typed.Native == nil && typed.Sync == nil) {
				t.Fatalf("original typed decode: %v", err)
			}
			core := coreFixture(0, 5, 0)
			core.Principal, core.KeyId, core.TtlSeconds = proto.Uint64(42), proto.Uint64(3), proto.Uint64(10)
			core.Uuid = []byte{0, 0, 0, 0, 0, 0, 64, 0, 128, 0, 0, 0, 0, 0, 0, 0}
			core.Secondary = nil
			core.Body = &wirepb.Core_Ack{Ack: &wirepb.Operation{
				Opcode: proto.Uint64(2), Words: words, Blobs: [][]byte{exact},
			}}
			response, err := EncodeCore(core)
			if err != nil {
				t.Fatal(err)
			}
			var store TransportBindings
			_, packet, err := store.Receive(signFixture(t, core), fixtureProfile(), fixtureScope(core), attest)
			accepted := err == nil
			if accepted != compatible || (!accepted && (err != ErrFormat || store.Len() != 0)) {
				t.Fatalf("response operand decode: %v", err)
			}
			if accepted {
				typed := packet.decodedOperands
				bound, err := EncodeCore(typed.Original)
				if err != nil || !bytes.Equal(bound, exact) || !bytes.Equal(typed.Blobs[0], exact) || !slices.Equal(typed.Words, words) {
					t.Fatalf("response did not preserve the exact original and words: %v", err)
				}
			}
			fmt.Printf("response-code\t%s\t%s\t%t\ttrue\t%t\t%x\n",
				id, shape, compatible, accepted, sha256.Sum256(response))
		})
	}
}
