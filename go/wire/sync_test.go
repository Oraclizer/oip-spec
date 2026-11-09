package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

func syncVectorRows(t *testing.T, name string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(string(data), "\r\n"), "\n") {
		rows = append(rows, strings.Split(strings.TrimSuffix(line, "\r"), "\t"))
	}
	return rows
}

func syncVectorInputs(t *testing.T) map[string][]byte {
	t.Helper()
	inputs := map[string][]byte{}
	for _, row := range syncVectorRows(t, "sync-structure-vectors.tsv") {
		if len(row) != 3 || row[0] != "I" || inputs[row[1]] != nil {
			t.Fatalf("invalid structure input row %q", row)
		}
		raw, err := hex.DecodeString(row[2])
		if err != nil {
			t.Fatal(err)
		}
		inputs[row[1]] = raw
	}
	if len(inputs) != 8 {
		t.Fatalf("got %d structure inputs, want 8", len(inputs))
	}
	return inputs
}

func syncVectorNumbers(values ...uint64) string {
	return strings.Join(TypedIRDecimal(values), ",")
}

func syncVectorBlobs(blobs ...[]byte) string {
	values := make([]string, len(blobs))
	for i, blob := range blobs {
		values[i] = hex.EncodeToString(blob)
	}
	return strings.Join(values, ",")
}

func TestSyncStructureVectors(t *testing.T) {
	inputs := syncVectorInputs(t)
	rows := syncVectorRows(t, "sync-structure-observations.tsv")
	if len(rows) != 5 {
		t.Fatalf("got %d observation rows, want 5", len(rows))
	}
	for _, row := range rows {
		t.Run(row[1], func(t *testing.T) {
			input := inputs[row[1]]
			if input == nil {
				t.Fatal("observation has no input")
			}
			var observed []string
			switch row[0] {
			case "P":
				packet, err := DecodePacket(input, len(input))
				if err != nil {
					t.Fatal(err)
				}
				if encoded, err := packet.Encode(); err != nil || !bytes.Equal(encoded, input) {
					t.Fatalf("packet re-encoding: %v", err)
				}
				coreInput := inputs[strings.TrimSuffix(row[1], "packet")+"core"]
				core, err := DecodeCore(coreInput)
				if err != nil || !proto.Equal(core, packet.Core()) {
					t.Fatalf("exact Core differs from decoded packet: %v", err)
				}
				exact, err := EncodeCore(core)
				if err != nil || !bytes.Equal(exact, coreInput) || !bytes.Equal(exact, packet.CoreBytes()) {
					t.Fatalf("Core re-encoding: %v", err)
				}
				preimage, err := packet.SigningBytes()
				if err != nil {
					t.Fatal(err)
				}
				typed, err := DecodeOperands(core, 1)
				if err != nil {
					t.Fatal(err)
				}
				header := syncVectorNumbers(core.GetVersion(), core.GetDeployment(), core.GetSourceDomain(), core.GetTargetDomain(),
					core.GetPrincipal(), core.GetAuthorityEpoch(), typed.Family, typed.Opcode)
				var words, blobs string
				switch row[1] {
				case "sync-packet":
					value := typed.Sync
					if value == nil || value.Predecessor == nil || typed.Session != value.Session {
						t.Fatal("expected typed incremental synchronization")
					}
					words = syncVectorNumbers(1, value.Reference, value.Sequence, value.Session, value.Revision, value.OriginEpoch,
						value.Origin.Domain, value.Origin.Event, value.Asset, value.SourcePosition, uint64(value.Mode))
					blobs = syncVectorBlobs(value.Commitment[:], value.Predecessor[:], value.SourceAttestation)
				case "query-packet":
					value := typed.CommitmentQuery
					if value == nil || typed.Session != value.Session {
						t.Fatal("expected typed current commitment query")
					}
					words = syncVectorNumbers(2, value.Session, value.Revision, value.Asset, value.OriginDomain)
				default:
					t.Fatalf("unknown packet input %q", row[1])
				}
				observed = []string{header, hex.EncodeToString(exact), hex.EncodeToString(preimage), hex.EncodeToString(core.Uuid), words, blobs}
			case "A":
				proof, err := DecodeSourceAttestation(input)
				if err != nil || proof.Predecessor == nil || !bytes.Equal(proof.SignedStatement, inputs["source-statement"]) {
					t.Fatalf("source statement differs from the exact signing input: %v", err)
				}
				values := []uint64{proof.FormatVersion, proof.ClaimKind, proof.Deployment, proof.OriginDomain, proof.OriginEpoch,
					proof.RosterID, proof.Asset, proof.OriginEvent, proof.SourcePosition, 1, uint64(len(proof.Signatures))}
				blobs := [][]byte{proof.SignedStatement, proof.Commitment[:], proof.Predecessor[:]}
				for _, vote := range proof.Signatures {
					values = append(values, vote.SignerID)
					blobs = append(blobs, vote.Signature[:])
				}
				observed = []string{syncVectorNumbers(values...), syncVectorBlobs(blobs...)}
			case "R":
				if _, err := DecodeSourceAttestation(input); err != ErrFormat {
					t.Fatalf("invalid source attestation: %v", err)
				}
				observed = []string{"rejected"}
			default:
				t.Fatalf("unknown observation type %q", row[0])
			}
			if !slices.Equal(observed, row[2:]) {
				t.Fatalf("observed %q, want %q", observed, row[2:])
			}
		})
	}
}

func TestSourceAttestationSigningInputAndMalformedLists(t *testing.T) {
	inputs := syncVectorInputs(t)
	statement := inputs["source-statement"]
	snapshot := bytes.Clone(statement[:len(statement)-32])
	snapshot[len(snapshot)-1] = 0
	proof := binary.BigEndian.AppendUint64(bytes.Clone(snapshot), 1)
	proof = binary.BigEndian.AppendUint64(proof, 101)
	proof = append(proof, ed25519.Sign(remoteKey, snapshot)...)
	decoded, err := DecodeSourceAttestation(proof)
	if err != nil || decoded.Predecessor != nil || !bytes.Equal(decoded.SignedStatement, snapshot) || len(decoded.Signatures) != 1 {
		t.Fatalf("source snapshot decode: %v", err)
	}
	vote := decoded.Signatures[0]
	if vote.SignerID != 101 || !verify(fixtureBoundary().PublicKey, decoded.SignedStatement, vote.Signature[:]) {
		t.Fatal("signature did not cover the exact source snapshot")
	}
	proof[0] ^= 1
	if !bytes.Equal(decoded.SignedStatement, snapshot) {
		t.Fatal("mutating the input changed the retained signing bytes")
	}
	for _, test := range []struct {
		name string
		edit func([]byte)
	}{
		{"domain", func(raw []byte) { raw[0] ^= 1 }},
		{"format", func(raw []byte) { raw[len(sourceAttestationDomain)+7] = 2 }},
		{"claim", func(raw []byte) { raw[len(sourceAttestationDomain)+15] = 2 }},
		{"predecessor presence", func(raw []byte) { raw[len(statement)-33] = 2 }},
		{"overflowing count", func(raw []byte) { binary.BigEndian.PutUint64(raw[len(statement):], math.MaxUint64) }},
		{"duplicate signer", func(raw []byte) { binary.BigEndian.PutUint64(raw[len(statement)+80:], 101) }},
		{"out of order signer", func(raw []byte) { binary.BigEndian.PutUint64(raw[len(statement)+80:], 100) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := bytes.Clone(inputs["source-proof"])
			test.edit(invalid)
			if _, err := DecodeSourceAttestation(invalid); err != ErrFormat {
				t.Fatalf("malformed proof: %v", err)
			}
		})
	}
}

func syncFixture() *wirepb.Core {
	return withBody(coreFixture(2, 1, 90), 1, &wirepb.Operation{
		Opcode: proto.Uint64(7), Words: []uint64{52, 53, 60, 0, 6, 30, 91, 20, math.MaxUint64, uint64(SyncInitial)},
		Blobs: [][]byte{bytes.Repeat([]byte{0xa5}, 32), {}, {1}},
	})
}

func commitmentQueryFixture() *wirepb.Core {
	return withBody(coreFixture(2, 4, 91), 4, &wirepb.Operation{Opcode: proto.Uint64(9), Words: []uint64{60, 0, 20, 30}})
}

func fixtureScope(core *wirepb.Core) Boundary {
	boundary := fixtureBoundary()
	boundary.Deployment, boundary.Source, boundary.Target = core.GetDeployment(), core.GetSourceDomain(), core.GetTargetDomain()
	boundary.Principal, boundary.KeyID, boundary.Epoch = core.GetPrincipal(), core.GetKeyId(), core.GetAuthorityEpoch()
	boundary.RouteScope, boundary.Now = core.GetRouteScope(), core.GetIssuedSeconds()
	return boundary
}

func TestSyncExtensionsUseTheConfiguredAdmissionPath(t *testing.T) {
	for _, core := range []*wirepb.Core{syncFixture(), commitmentQueryFixture()} {
		family, op := Body(core)
		t.Run(syncVectorNumbers(family, op.GetOpcode()), func(t *testing.T) {
			var store TransportBindings
			boundary := fixtureScope(core)
			raw := signFixture(t, core)
			badSignature := bytes.Clone(raw)
			badSignature[len(badSignature)-1] ^= 1
			wrongScope := boundary
			wrongScope.Principal++
			excluded := func(candidate *wirepb.Core) bool { return candidate.GetFamily() != family }
			unreachableAttest := func(*wirepb.Core) bool { t.Fatal("refusal reached the authority callback"); return false }
			if _, _, err := store.ReceiveAccepting(badSignature, fixtureProfile(), wrongScope, excluded, unreachableAttest); err != ErrVersion {
				t.Fatalf("known excluded opcode: %v", err)
			}
			if _, _, err := store.ReceiveAccepting(badSignature, fixtureProfile(), boundary, ReferenceAccepts, unreachableAttest); err != ErrSignature {
				t.Fatalf("known included opcode with bad signature: %v", err)
			}
			exact, err := EncodeCore(core)
			if err != nil {
				t.Fatal(err)
			}
			operation, err := encodeOperation(op)
			if err != nil || bytes.Count(exact, operation) != 1 {
				t.Fatal("unexpected operation fixture encoding")
			}
			unknown := bytes.Clone(operation)
			unknown[1]++
			unknownFrame := rawFrame(t, bytes.Replace(exact, operation, unknown, 1))
			if _, _, err := store.ReceiveAccepting(unknownFrame, fixtureProfile(), wrongScope, unreachableAttest, unreachableAttest); err != ErrFormat {
				t.Fatalf("unknown opcode: %v", err)
			}
			if store.Len() != 0 {
				t.Fatal("refused input changed the transport bindings")
			}
			for _, want := range []Arrival{First, Identical} {
				arrival, packet, err := store.ReceiveAccepting(raw, fixtureProfile(), boundary, ReferenceAccepts, attest)
				if err != nil || arrival != want || !bytes.Equal(packet.CoreBytes(), exact) || store.Len() != 1 {
					t.Fatalf("signed extension receive: %v, %v", arrival, err)
				}
				if family == 1 {
					typed := packet.decodedOperands.Sync
					if typed == nil || typed.Origin.Domain == core.GetSourceDomain() || typed.SourcePosition != math.MaxUint64 ||
						!bytes.Equal(typed.SourceAttestation, op.Blobs[2]) {
						t.Fatal("synchronization did not preserve its typed values")
					}
					if _, err := DecodeSourceAttestation(typed.SourceAttestation); err != ErrFormat {
						t.Fatal("admitted opaque malformed proof as an attestation")
					}
				} else if packet.decodedOperands.CommitmentQuery == nil {
					t.Fatal("current commitment query lost its typed operand")
				}
			}
		})
	}
}

func TestSyncExtensionOperandLayouts(t *testing.T) {
	for _, test := range []struct {
		name string
		core func() *wirepb.Core
		edit func(*wirepb.Operation)
		want error
	}{
		{"incremental with zero predecessor", syncFixture, func(op *wirepb.Operation) {
			op.Words[9] = uint64(SyncIncremental)
			op.Blobs[1] = make([]byte, 32)
		}, nil},
		{"full resync", syncFixture, func(op *wirepb.Operation) { op.Words[9] = uint64(SyncFullResync) }, nil},
		{"empty attestation blob", syncFixture, func(op *wirepb.Operation) { op.Blobs[2] = nil }, nil},
		{"missing attestation blob", syncFixture, func(op *wirepb.Operation) { op.Blobs = op.Blobs[:2] }, ErrFormat},
		{"extra blob", syncFixture, func(op *wirepb.Operation) { op.Blobs = append(op.Blobs, nil) }, ErrFormat},
		{"short commitment", syncFixture, func(op *wirepb.Operation) { op.Blobs[0] = op.Blobs[0][:31] }, ErrFormat},
		{"long commitment", syncFixture, func(op *wirepb.Operation) { op.Blobs[0] = append(op.Blobs[0], 0) }, ErrFormat},
		{"snapshot predecessor", syncFixture, func(op *wirepb.Operation) { op.Blobs[1] = make([]byte, 32) }, ErrFormat},
		{"incremental without predecessor", syncFixture, func(op *wirepb.Operation) { op.Words[9] = uint64(SyncIncremental) }, ErrFormat},
		{"unknown mode", syncFixture, func(op *wirepb.Operation) { op.Words[9] = 4 }, ErrFormat},
		{"missing mode", syncFixture, func(op *wirepb.Operation) { op.Words = op.Words[:9] }, ErrFormat},
		{"extra sync word", syncFixture, func(op *wirepb.Operation) { op.Words = append(op.Words, 0) }, ErrFormat},
		{"sync deadline", syncFixture, func(op *wirepb.Operation) {
			op.AppealDeadline = &wirepb.Operation_AppealDeadlineIndefinite{AppealDeadlineIndefinite: true}
		}, ErrFormat},
		{"missing query word", commitmentQueryFixture, func(op *wirepb.Operation) { op.Words = op.Words[:3] }, ErrFormat},
		{"extra query word", commitmentQueryFixture, func(op *wirepb.Operation) { op.Words = append(op.Words, 0) }, ErrFormat},
		{"query blob", commitmentQueryFixture, func(op *wirepb.Operation) { op.Blobs = [][]byte{nil} }, ErrFormat},
		{"query deadline", commitmentQueryFixture, func(op *wirepb.Operation) {
			op.AppealDeadline = &wirepb.Operation_AppealDeadlineUtcSeconds{AppealDeadlineUtcSeconds: 0}
		}, ErrFormat},
	} {
		t.Run(test.name, func(t *testing.T) {
			core := test.core()
			_, op := Body(core)
			test.edit(op)
			var store TransportBindings
			_, packet, err := store.ReceiveAccepting(signFixture(t, core), fixtureProfile(), fixtureScope(core), ReferenceAccepts, attest)
			if err != test.want || (err != nil && store.Len() != 0) {
				t.Fatalf("operand receive: %v, want %v", err, test.want)
			}
			if test.name == "empty attestation blob" {
				typed := packet.decodedOperands
				if len(typed.Blobs) != 3 || len(typed.Sync.SourceAttestation) != 0 {
					t.Fatal("empty proof field did not preserve its position")
				}
				if _, err := DecodeSourceAttestation(typed.Sync.SourceAttestation); err != ErrFormat {
					t.Fatalf("empty source attestation: %v", err)
				}
			}
		})
	}
}

func exactFixtureCore(t *testing.T, core *wirepb.Core) []byte {
	t.Helper()
	exact, err := EncodeCore(core)
	if err != nil {
		t.Fatal(err)
	}
	return exact
}

func syncResponseFixture(exact []byte, words []uint64) *wirepb.Core {
	core := coreFixture(0, 5, 93)
	core.SourceDomain, core.Principal = proto.Uint64(2), proto.Uint64(42)
	return withBody(core, 5, &wirepb.Operation{Opcode: proto.Uint64(2), Words: words, Blobs: [][]byte{exact}})
}

func TestSyncResponsesCorrelateExactOriginalAndReceipt(t *testing.T) {
	original := syncFixture()
	boundOriginal := exactFixtureCore(t, original)
	receipt := withBody(coreFixture(2, 4, 92), 4, &wirepb.Operation{
		Opcode: proto.Uint64(8), Words: []uint64{60}, Blobs: [][]byte{boundOriginal},
	})
	var receiptBindings TransportBindings
	_, packet, err := receiptBindings.ReceiveAccepting(signFixture(t, receipt), fixtureProfile(), fixtureScope(receipt), ReferenceAccepts, attest)
	if err != nil || !bytes.Equal(packet.decodedOperands.Blobs[0], boundOriginal) ||
		!bytes.Equal(exactFixtureCore(t, packet.decodedOperands.Original), boundOriginal) {
		t.Fatalf("receipt did not carry the exact synchronization call: %v", err)
	}
	for _, input := range []struct {
		name string
		core *wirepb.Core
	}{
		{"original", original},
		{"receipt", receipt},
	} {
		t.Run(input.name, func(t *testing.T) {
			exact := exactFixtureCore(t, input.core)
			for _, test := range []struct {
				name  string
				words []uint64
				want  error
			}{
				{"synced", []uint64{7, 53, 1, 29, 1, 17}, nil},
				{"attestation rejected", []uint64{7, 53, 1, 41, 0}, nil},
				{"wrong sequence", []uint64{7, 54, 1, 29, 1, 17}, ErrFormat},
				{"wrong namespace", []uint64{8, 53, 1, 29, 1, 17}, ErrSource},
				{"unknown recorded absent", []uint64{7, 53, 1, 999, 0}, nil},
				{"unknown recorded present", []uint64{7, 53, 1, 999, 1, 17}, nil},
				{"unknown delivery absent", []uint64{7, 53, 2, 5, 0}, nil},
				{"unknown delivery present", []uint64{7, 53, 2, 5, 1, 17}, ErrFormat},
				{"unknown refusal absent", []uint64{7, 53, 3, 78, 0}, nil},
				{"known wrong kind", []uint64{7, 53, 2, 1, 0}, ErrFormat},
				{"known wrong commit", []uint64{7, 53, 1, 2, 1, 17}, ErrFormat},
				{"delivery code with recorded kind", []uint64{7, 53, 1, 50, 0}, ErrFormat},
				{"refusal code with delivery kind", []uint64{7, 53, 2, 70, 0}, ErrFormat},
				{"incompatible debit code", []uint64{7, 53, 1, 12, 1, 17}, ErrFormat},
			} {
				t.Run(test.name, func(t *testing.T) {
					core := syncResponseFixture(exact, test.words)
					var store TransportBindings
					_, packet, err := store.Receive(signFixture(t, core), fixtureProfile(), fixtureScope(core), attest)
					if err != test.want || (err != nil && store.Len() != 0) {
						t.Fatalf("response receive: %v, want %v", err, test.want)
					}
					if err == nil {
						typed := packet.decodedOperands
						if !bytes.Equal(typed.Blobs[0], exact) || !bytes.Equal(exactFixtureCore(t, typed.Original), exact) ||
							!slices.Equal(typed.Words, test.words) {
							t.Fatal("response changed the original Core or status words")
						}
					}
				})
			}
		})
	}
}

func TestSyncNestedOperandRefusals(t *testing.T) {
	query := commitmentQueryFixture()
	receipt := func(original []byte) *wirepb.Core {
		return withBody(coreFixture(2, 4, 92), 4, &wirepb.Operation{
			Opcode: proto.Uint64(8), Words: []uint64{60}, Blobs: [][]byte{original},
		})
	}
	wrongEpoch := syncFixture()
	wrongEpoch.AuthorityEpoch = proto.Uint64(wrongEpoch.GetAuthorityEpoch() + 1)
	validReceipt := exactFixtureCore(t, receipt(exactFixtureCore(t, syncFixture())))
	wrongEpochReceipt := exactFixtureCore(t, receipt(exactFixtureCore(t, wrongEpoch)))
	words := []uint64{7, 53, 1, 29, 1, 17}
	for _, test := range []struct {
		name  string
		core  *wirepb.Core
		depth int
		want  error
	}{
		{"response to current commitment", syncResponseFixture(exactFixtureCore(t, query), []uint64{7, 53, 1, 999, 0}), 2, ErrFormat},
		{"receipt for current commitment", receipt(exactFixtureCore(t, query)), 2, ErrFormat},
		{"response to receipt with wrong epoch", syncResponseFixture(wrongEpochReceipt, words), 3, ErrSource},
		{"response to receipt exceeds nesting", syncResponseFixture(validReceipt, words), 2, ErrFormat},
	} {
		t.Run(test.name, func(t *testing.T) {
			boundary := fixtureScope(test.core)
			boundary.MaxNesting = test.depth
			var store TransportBindings
			if _, _, err := store.Receive(signFixture(t, test.core), fixtureProfile(), boundary, attest); err != test.want || store.Len() != 0 {
				t.Fatalf("nested operand receive: %v, want %v", err, test.want)
			}
		})
	}
}
