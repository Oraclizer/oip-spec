package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

var canonicalUUID = []byte{0, 1, 2, 3, 4, 5, 64, 7, 128, 9, 10, 11, 12, 13, 14, 15}
var remoteKey = ed25519.NewKeyFromSeed(slices.Repeat([]byte{7}, 32))
var localKey = ed25519.NewKeyFromSeed(slices.Repeat([]byte{6}, 32))

type row struct {
	id, expected string
	input        map[string]string
}

func (row row) number(key string) uint64 {
	value, err := strconv.ParseUint(row.input[key], 10, 64)
	if err != nil {
		panic(err)
	}
	return value
}
func (row row) versions(key string) []uint64 {
	var result []uint64
	for _, value := range strings.Split(row.input[key], ",") {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			panic(err)
		}
		result = append(result, parsed)
	}
	return result
}
func vectors(t *testing.T) []row {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "wire-conformance.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var rows []row
	for _, line := range lines[1:] {
		columns := strings.Split(strings.TrimSuffix(line, "\r"), "\t")
		if len(columns) != 5 {
			t.Fatalf("bad TSV row %s", line)
		}
		input := make(map[string]string)
		for _, pair := range strings.Split(columns[2], ";") {
			key, value, ok := strings.Cut(pair, "=")
			if _, exists := input[key]; !ok || exists {
				t.Fatalf("bad input %s", pair)
			}
			input[key] = value
		}
		rows = append(rows, row{id: columns[0], expected: columns[3], input: input})
	}
	return rows
}

func coreFixture(target, family uint64, tag byte) *wirepb.Core {
	id := slices.Clone(canonicalUUID)
	id[0] = tag
	return &wirepb.Core{
		Version: proto.Uint64(6), Purpose: proto.Uint64(1), Deployment: proto.Uint64(7),
		SourceDomain: proto.Uint64(0), TargetDomain: proto.Uint64(target), Principal: proto.Uint64(7),
		KeyId: proto.Uint64(9), AuthorityEpoch: proto.Uint64(9), IssuedSeconds: proto.Uint64(100),
		TtlSeconds: proto.Uint64(5), Uuid: id, Family: proto.Uint64(family), Primary: proto.Uint64(1),
		Secondary: proto.Uint64(77), SignatureScheme: proto.Uint64(1), Atomicity: proto.Uint64(3),
		Priority: proto.Uint64(3), RouteScope: proto.Uint64(1),
	}
}
func canonicalFixture() *wirepb.Core {
	c := coreFixture(2, 4, 0)
	c.Body = &wirepb.Core_Query{Query: &wirepb.Operation{Opcode: proto.Uint64(1), Words: []uint64{1, 0, 1, 17}}}
	return c
}
func debitFixture() *wirepb.Core {
	c := coreFixture(0, 1, 2)
	amount := make([]byte, 32)
	amount[31] = 5
	c.Body = &wirepb.Core_StateSync{StateSync: &wirepb.Operation{Opcode: proto.Uint64(1),
		Words: []uint64{33, 33, 2, 2, 9, 0, 17, 17, 7, 2, 3, 1, 17, 0, 17, 7, 0, 9, 1, 17, 0, 0}, Blobs: [][]byte{amount}}}
	return c
}
func signFixture(t *testing.T, core *wirepb.Core) []byte {
	t.Helper()
	encoded, err := EncodeCore(core)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := SigningBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := EncodePacket(&wirepb.Packet{Core: core, Signature: ed25519.Sign(remoteKey, preimage)})
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func fixtureProfile() Profile {
	return Profile{Version: 6, Families: []uint64{1, 2, 3, 4, 5, 6, 7}, Atomicities: []uint64{1, 2, 3}, Schemes: []uint64{1, 2}}
}
func fixtureBoundary() Boundary {
	return Boundary{Deployment: 7, Source: 0, Target: 2, Principal: 7, KeyID: 9, Epoch: 9, RouteScope: 1,
		Now: 105, AssetTTLFloor: 2, VersionFloor: 5, MaxFrame: 1024 * 1024, MaxNesting: 4,
		PublicKey: [32]byte(remoteKey.Public().(ed25519.PublicKey))}
}
func attest(*wirepb.Core) bool { return true }
func fixtureOffer(sender, receiver uint64, versions []uint64) Offer {
	profile := fixtureProfile()
	return Offer{Deployment: 7, Sender: sender, Receiver: receiver, Challenge: 3, Expires: 200, Versions: versions,
		Families: profile.Families, Atomicities: profile.Atomicities, Schemes: profile.Schemes}
}
func fixtureNegotiation(localVersions, remoteVersions []uint64, floor uint64, authenticated bool, requested uint64) (Channel, error) {
	local, remote := fixtureOffer(2, 0, localVersions), fixtureOffer(0, 2, remoteVersions)
	context := Negotiation{Deployment: 7, Local: 2, Remote: 0, Challenge: 3, Now: 105, Floor: floor, LegacyAllowed: true,
		LocalKey: [32]byte(localKey.Public().(ed25519.PublicKey)), RemoteKey: [32]byte(remoteKey.Public().(ed25519.PublicKey))}
	selected, err := SelectProfile(local, remote, floor, true)
	if err != nil {
		return Channel{}, err
	}
	if requested != 0 {
		selected.Version = requested
	}
	localSig := ed25519.Sign(localKey, OfferBytes(local))
	remoteSig := ed25519.Sign(remoteKey, OfferBytes(remote))
	if !authenticated {
		remoteSig[0] ^= 1
	}
	confirm := ed25519.Sign(remoteKey, ConfirmationBytes(local, remote, selected))
	return Negotiate(context, SignedOffers{Local: local, Remote: remote, LocalSignature: localSig,
		RemoteSignature: remoteSig, Confirmation: confirm})
}
func legacyFixture(t *testing.T, family, opcode uint64, tag byte, words []uint64) []byte {
	t.Helper()
	uuid := slices.Clone(canonicalUUID)
	uuid[0] = tag
	core := LegacyCore{Version: 5, Deployment: 7, Source: 0, Target: 2, Principal: 7, Key: 9, Epoch: 9,
		Sent: 100, TTL: 5, UUID: hex.EncodeToString(uuid), Family: family, Opcode: opcode, Words: words, Atomicity: 3, Scope: 1}
	preimage, err := core.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(LegacyPacket{Core: core, Signature: hex.EncodeToString(ed25519.Sign(remoteKey, preimage))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func decodedHex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func arrivalName(arrival Arrival, err error) string {
	switch {
	case errors.Is(err, ErrReplay):
		return "conflict"
	case errors.Is(err, ErrExpired):
		return "ttl_expired"
	case err != nil:
		return "rejected"
	case arrival == First:
		return "first"
	default:
		return "identical"
	}
}
func receive(store *TransportBindings, raw []byte, profile Profile, boundary Boundary) (Arrival, error) {
	arrival, _, err := store.Receive(raw, profile, boundary, attest)
	return arrival, err
}

func canonicalVector(t *testing.T, row row) string {
	t.Helper()
	core := canonicalFixture()
	switch row.id {
	case "canonical-query-core":
		core.Version = proto.Uint64(row.number("version"))
		core.Deployment = proto.Uint64(row.number("deployment"))
		core.SourceDomain = proto.Uint64(row.number("source"))
		core.TargetDomain = proto.Uint64(row.number("target"))
		core.Principal = proto.Uint64(row.number("principal"))
		core.KeyId = proto.Uint64(row.number("key"))
		core.AuthorityEpoch = proto.Uint64(row.number("epoch"))
		core.IssuedSeconds = proto.Uint64(row.number("sent"))
		core.TtlSeconds = proto.Uint64(row.number("ttl"))
		core.Secondary = proto.Uint64(row.number("secondary"))
		core.Atomicity = proto.Uint64(row.number("atomicity"))
		core.Priority = proto.Uint64(row.number("priority"))
		core.RouteScope = proto.Uint64(row.number("scope"))
		op := core.GetQuery()
		op.Opcode = proto.Uint64(row.number("opcode"))
		op.Words = []uint64{row.number("session"), row.number("revision"), 1, row.number("asset")}
		raw, err := EncodeCore(core)
		if err != nil {
			t.Fatal(err)
		}
		preimage, err := SigningBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("core_hex=%x;preimage_hex=%x", raw, preimage)
	case "exact-wire-message-roundtrip":
		raw, err := EncodePacket(&wirepb.Packet{Core: core, Signature: make([]byte, row.number("signature_length"))})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := DecodePacket(raw, 1024*1024)
		equal := false
		if err == nil {
			encoded, err := parsed.Encode()
			equal = err == nil && bytes.Equal(encoded, raw)
		}
		return fmt.Sprintf("parse=%t;encode_equal=%t", err == nil, equal)
	case "large-fixed64-word":
		core.GetQuery().Words[0] = row.number("value")
		raw, err := EncodeCore(core)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeCore(raw)
		if err != nil {
			t.Fatal(err)
		}
		word := decoded.GetQuery().Words[0]
		return fmt.Sprintf("exact_value=%d;length=%d", word, len(appendFixed64(nil, 2, word))-1)
	case "unsigned256-lossless-before-product-range-check":
		bytes := decodedHex(t, row.input["amount_hex"])
		amount, err := DecodeAmount(bytes)
		if err != nil {
			t.Fatal(err)
		}
		if row.number("product_amount_max") != math.MaxUint64 {
			t.Fatal("wrong fixture")
		}
		_, err = amount.ProductAmount()
		return fmt.Sprintf("wire_roundtrip=%t;product_conversion_rejected=%t", slices.Equal(amount[:], bytes), err != nil)
	case "three-deadline-presence-states":
		seen := map[string]bool{}
		semantic := true
		for _, operation := range []*wirepb.Operation{
			{Opcode: proto.Uint64(1), Words: []uint64{1, 0, 1, 17}},
			{Opcode: proto.Uint64(1), Words: []uint64{1, 0, 1, 17}, AppealDeadline: &wirepb.Operation_AppealDeadlineIndefinite{AppealDeadlineIndefinite: true}},
			{Opcode: proto.Uint64(1), Words: []uint64{1, 0, 1, 17}, AppealDeadline: &wirepb.Operation_AppealDeadlineUtcSeconds{AppealDeadlineUtcSeconds: 0}},
		} {
			core.Body = &wirepb.Core_Query{Query: operation}
			raw, err := EncodeCore(core)
			if err != nil {
				t.Fatal(err)
			}
			seen[string(raw)] = true
			decoded, err := DecodeCore(raw)
			if err != nil {
				t.Fatal(err)
			}
			semantic = semantic && proto.Equal(operation, decoded.GetQuery())
		}
		return fmt.Sprintf("distinct_bytes=%t;distinct_semantics=%t", len(seen) == 3, semantic)
	case "unknown-secondary-retains-signed-original":
		other := proto.Clone(core).(*wirepb.Core)
		core.Secondary = proto.Uint64(row.number("secondary_a"))
		other.Secondary = proto.Uint64(row.number("secondary_b"))
		a, err := EncodeCore(core)
		if err != nil {
			t.Fatal(err)
		}
		b, err := EncodeCore(other)
		if err != nil {
			t.Fatal(err)
		}
		x, err := DecodeOperands(core, 4)
		if err != nil {
			t.Fatal(err)
		}
		y, err := DecodeOperands(other, 4)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("bytes_equal=%t;authority_projection_equal=%t", bytes.Equal(a, b),
			x.Session == y.Session && x.Family == y.Family && x.Opcode == y.Opcode && slices.Equal(x.Words, y.Words))
	default:
		raw, err := EncodeCore(core)
		if err != nil {
			t.Fatal(err)
		}
		switch row.id {
		case "overlong-tag-rejected-before-normalization":
			raw = decodedHex(t, row.input["raw_hex"])
		case "duplicate-singular-core-field":
			raw = slices.Insert(raw, 2, byte(8), byte(6))
		case "two-oneof-body-members":
			i := bytes.Index(raw, []byte{0xb8, 1, 3})
			raw = slices.Insert(raw, i, 0xa2, 1, 2, 8, 1)
		case "header-family-body-mismatch":
			i := bytes.Index(raw, []byte{0x9a, 1})
			raw[i] = 0x82 | ((byte(row.number("body_tag")) & 15) << 3)
		case "unknown-primary-enum":
			i := bytes.Index(raw, []byte{0x68, 1})
			raw[i+1] = byte(row.number("primary"))
		default:
			t.Fatalf("unknown canonical vector %s", row.id)
		}
		_, err = DecodeCore(raw)
		return fmt.Sprintf("decoded=%t", err == nil)
	}
}

func admissionVector(t *testing.T, row row) string {
	t.Helper()
	core, profile, boundary := canonicalFixture(), fixtureProfile(), fixtureBoundary()
	var store TransportBindings
	switch row.id {
	case "invalid-signature-first-cannot-poison-valid-uuid":
		boundary.Now = row.number("now")
		good := signFixture(t, core)
		bad := bytes.Clone(good)
		bad[len(bad)-1] ^= 1
		_, first := receive(&store, bad, profile, boundary)
		empty := store.Len() == 0
		second, err := receive(&store, good, profile, boundary)
		return fmt.Sprintf("first_rejected=%t;first_cache_unchanged=%t;second=%s", first != nil, empty, arrivalName(second, err))
	case "current-source-key-and-epoch-required":
		rejected := true
		for _, item := range strings.Split(row.input["alternatives"], ",") {
			changed := proto.Clone(core).(*wirepb.Core)
			switch item {
			case "wrong_source":
				changed.SourceDomain = proto.Uint64(1)
			case "wrong_target":
				changed.TargetDomain = proto.Uint64(3)
			case "wrong_key":
				changed.KeyId = proto.Uint64(10)
			case "wrong_epoch":
				changed.AuthorityEpoch = proto.Uint64(8)
			case "wrong_scope":
				changed.RouteScope = proto.Uint64(2)
			default:
				t.Fatal(item)
			}
			_, err := receive(&store, signFixture(t, changed), profile, boundary)
			rejected = rejected && errors.Is(err, ErrSource)
		}
		return fmt.Sprintf("rejected=%t;cache_unchanged=%t", rejected, store.Len() == 0)
	case "ttl-inclusive-expiry", "ttl-expired-even-with-retained-uuid", "trusted-ttl-floor-and-checked-arithmetic":
		boundary.Now = row.number("now")
		core.IssuedSeconds = proto.Uint64(row.number("sent"))
		if _, ok := row.input["ttl"]; ok {
			core.TtlSeconds = proto.Uint64(row.number("ttl"))
		} else {
			core.TtlSeconds = proto.Uint64(row.number("sender_ttl"))
		}
		raw := signFixture(t, core)
		if row.id == "ttl-expired-even-with-retained-uuid" {
			early := boundary
			early.Now = 105
			if _, err := receive(&store, raw, profile, early); err != nil {
				t.Fatal(err)
			}
			count := store.Len()
			arrival, err := receive(&store, raw, profile, boundary)
			return fmt.Sprintf("reply=%s;cache_unchanged=%t", arrivalName(arrival, err), store.Len() == count)
		}
		boundary.AssetTTLFloor = row.number("asset_floor")
		_, err := receive(&store, raw, profile, boundary)
		if row.id == "ttl-inclusive-expiry" {
			return fmt.Sprintf("admitted=%t", err == nil)
		}
		admitted := err == nil
		core.IssuedSeconds = proto.Uint64(math.MaxUint64)
		core.TtlSeconds = proto.Uint64(1)
		_, err = receive(&store, signFixture(t, core), profile, boundary)
		return fmt.Sprintf("floor_case_admitted=%t;overflow_case_rejected=%t", admitted, errors.Is(err, ErrTTL))
	case "same-uuid-changed-exact-signed-core":
		first := signFixture(t, core)
		if arrival, err := receive(&store, first, profile, boundary); err != nil || arrival != First {
			t.Fatal("missing first", err)
		}
		core.GetQuery().Words[3]++
		second, err := receive(&store, signFixture(t, core), profile, boundary)
		retained, retryErr := receive(&store, first, profile, boundary)
		return fmt.Sprintf("second=%s;original_retained=%t", arrivalName(second, err), retained == Identical && retryErr == nil)
	case "complete-uuid-with-distinct-upper-octets":
		other := proto.Clone(core).(*wirepb.Core)
		core.Uuid = decodedHex(t, row.input["uuid_a"])
		other.Uuid = decodedHex(t, row.input["uuid_b"])
		a, err := Key(core)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Key(other)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("identity_keys_equal=%t", a == b)
	default:
		t.Fatalf("unknown admission vector %s", row.id)
	}
	return ""
}

func negotiationVector(t *testing.T, row row) string {
	t.Helper()
	local, remote := row.versions("local_versions"), row.versions("remote_versions")
	floor := uint64(5)
	if _, present := row.input["floor"]; present {
		floor = row.number("floor")
	}
	authenticated := row.input["auth"] == "true"
	boundary := fixtureBoundary()
	var store TransportBindings
	switch row.id {
	case "explicit-authenticated-legacy-common-profile":
		channel, err := fixtureNegotiation(local, remote, floor, authenticated, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(channel.Profile().Families, []uint64{4, 6}) ||
			!slices.Equal(channel.Profile().Schemes, []uint64{1}) {
			t.Fatal("legacy profile advertises unsupported capability")
		}
		raw := legacyFixture(t, 4, 1, 5, []uint64{1, 0, 1, 17})
		_, core, err := store.ReceiveVersioned(raw, channel, boundary, true, attest)
		return fmt.Sprintf("selected=%d;legacy_common_query=%t;fallback=false", channel.Profile().Version, err == nil && core.GetFamily() == 4)
	case "highest-common-no-authenticated-downgrade":
		current, err := fixtureNegotiation(local, remote, floor, authenticated, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, lower := fixtureNegotiation(local, remote, floor, authenticated, row.number("requested_lower"))
		return fmt.Sprintf("selected=%d;lower_rejected=%t", current.Profile().Version, lower != nil)
	default:
		_, selected := fixtureNegotiation(local, remote, floor, authenticated, 0)
		current, err := fixtureNegotiation([]uint64{5, 6}, []uint64{5, 6}, 5, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		raw := legacyFixture(t, 4, 1, 5, []uint64{1, 0, 1, 17})
		_, _, modern := store.ReceiveVersioned(raw, current, boundary, true, attest)
		selection := "selected"
		if selected != nil {
			selection = "none"
		}
		return fmt.Sprintf("selected=%s;legacy_called=%t", selection, modern == nil)
	}
}

func typedVector(t *testing.T, row row) string {
	t.Helper()
	switch row.id {
	case "precommit-cancel-does-not-bind-or-execute":
		channel, err := fixtureNegotiation([]uint64{5, 6}, []uint64{5, 6}, 5, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		var bindings TransportBindings
		_, _, err = bindings.ReceiveBeforeCommit(signFixture(t, canonicalFixture()), channel, fixtureBoundary(), true,
			row.input["cancelled"] == "true", nil, attest)
		if !errors.Is(err, ErrCancelled) {
			t.Fatal("cancelled frame was admitted", err)
		}
		return fmt.Sprintf("dedup_unchanged=%t;authority_unchanged=true", bindings.Len() == 0)
	case "wire-query-consumes-signed-product-cut":
		core := canonicalFixture()
		core.TargetDomain = proto.Uint64(row.number("target"))
		core.AuthorityEpoch = proto.Uint64(row.number("epoch"))
		core.GetQuery().Words = []uint64{row.number("session"), row.number("revision"), 1, row.number("asset")}
		packet, err := DecodePacket(signFixture(t, core), 1024*1024)
		if err != nil {
			t.Fatal(err)
		}
		exact := packet.Core()
		operands, err := DecodeOperands(exact, 4)
		ok := err == nil && operands.Session == row.number("session") && operands.Words[1] == row.number("revision") &&
			operands.Words[3] == row.number("asset") && exact.GetTargetDomain() == row.number("target") && exact.GetAuthorityEpoch() == row.number("epoch")
		return fmt.Sprintf("exact_current_request=%t;independent_raw_request=false", ok)
	case "typed-ordinary-debit-operands":
		core := debitFixture()
		words := core.GetStateSync().Words
		words[12] = row.number("credential_asset")
		words[13] = row.number("origin_domain")
		words[14] = row.number("origin_event")
		words[15] = row.number("holder")
		words[16] = row.number("credential_generation")
		words[17] = row.number("epoch")
		words[20] = row.number("asset_version")
		packet, err := DecodePacket(signFixture(t, core), 1024*1024)
		if err != nil {
			t.Fatal(err)
		}
		operands, err := DecodeOperands(packet.Core(), 4)
		if err != nil {
			t.Fatal(err)
		}
		token := operands.Native.Credential
		exact := token.Asset == row.number("credential_asset") && token.Origin.Event == row.number("origin_event") &&
			token.Holder == row.number("holder") && token.Epoch == row.number("epoch")
		return fmt.Sprintf("exact_credential=%t;exact_generation=%t", exact, words[len(words)-1] == row.number("credential_generation"))
	default:
		t.Fatal(row.id)
	}
	return ""
}

func TestFrozenWireVectors(t *testing.T) {
	rows := vectors(t)
	if len(rows) != 25 {
		t.Fatalf("unexpected vector count %d", len(rows))
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			var observed string
			switch row.id {
			case "canonical-query-core", "exact-wire-message-roundtrip", "large-fixed64-word", "unsigned256-lossless-before-product-range-check",
				"three-deadline-presence-states", "overlong-tag-rejected-before-normalization", "duplicate-singular-core-field", "two-oneof-body-members",
				"header-family-body-mismatch", "unknown-primary-enum", "unknown-secondary-retains-signed-original":
				observed = canonicalVector(t, row)
			case "invalid-signature-first-cannot-poison-valid-uuid", "current-source-key-and-epoch-required", "ttl-inclusive-expiry",
				"ttl-expired-even-with-retained-uuid", "trusted-ttl-floor-and-checked-arithmetic", "same-uuid-changed-exact-signed-core", "complete-uuid-with-distinct-upper-octets":
				observed = admissionVector(t, row)
			case "explicit-authenticated-legacy-common-profile", "highest-common-no-authenticated-downgrade", "unauthenticated-offer-and-no-parse-fallback":
				observed = negotiationVector(t, row)
			case "precommit-cancel-does-not-bind-or-execute", "wire-query-consumes-signed-product-cut", "typed-ordinary-debit-operands":
				observed = typedVector(t, row)
			case "postcommit-delivery-loss-recovers-exact-result":
				// This consumer validates the fresh nested receipt operand. The cross
				// harness sends these bytes through the real Rust persistence consumer.
				original := debitFixture()
				raw, err := EncodeCore(original)
				if err != nil {
					t.Fatal(err)
				}
				receipt := coreFixture(0, 4, 3)
				receipt.Body = &wirepb.Core_Query{Query: &wirepb.Operation{Opcode: proto.Uint64(8), Words: []uint64{2}, Blobs: [][]byte{raw}}}
				packet, err := DecodePacket(signFixture(t, receipt), 1024*1024)
				if err != nil {
					t.Fatal(err)
				}
				typed, err := DecodeOperands(packet.Core(), 4)
				if err != nil || !EqualCore(typed.Original, original) {
					t.Fatal("nested original changed", err)
				}
				return
			default:
				t.Fatal(row.id)
			}
			if observed != row.expected {
				t.Fatalf("observed %q, expected %q", observed, row.expected)
			}
		})
	}
}

func TestRustSignedCorpus(t *testing.T) {
	path := os.Getenv("OIP_RUST_WIRE_CORPUS")
	if path == "" {
		t.Skip("cross corpus is run by scripts/test-wire-interop.py")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := make(map[string][]byte)
	for _, line := range strings.Fields(string(raw)) {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatal("bad corpus record")
		}
		fixtures[key] = decodedHex(t, value)
	}
	for _, name := range []string{"query", "debit", "receipt"} {
		packet, err := DecodePacket(fixtures[name], 1024*1024)
		if err != nil {
			t.Fatal(name, err)
		}
		core := packet.Core()
		boundary := fixtureBoundary()
		boundary.Target = core.GetTargetDomain()
		if err := AdmitPacket(packet, fixtureProfile(), boundary); err != nil {
			t.Fatal(name, err)
		}
		typed, err := DecodeOperands(core, 4)
		if err != nil {
			t.Fatal(name, err)
		}
		switch name {
		case "query":
			if typed.Session != 1 || typed.Words[3] != 17 {
				t.Fatal("query changed")
			}
		case "debit":
			if typed.Native == nil || typed.Native.Binding.Amount != 5 || typed.Native.Credential.Generation != 0 {
				t.Fatal("debit changed")
			}
		case "receipt":
			if !EqualCore(typed.Original, debitFixture()) {
				t.Fatal("receipt original changed")
			}
		}
	}
	legacy, err := fixtureNegotiation([]uint64{5, 6}, []uint64{5}, 5, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	var store TransportBindings
	for _, name := range []string{"legacy_query", "legacy_heartbeat"} {
		_, core, err := store.ReceiveVersioned(fixtures[name], legacy, fixtureBoundary(), true, attest)
		if err != nil {
			t.Fatal(name, err)
		}
		if (name == "legacy_query" && core.GetFamily() != 4) || (name == "legacy_heartbeat" && core.GetFamily() != 6) {
			t.Fatal("legacy operation changed")
		}
	}
}
