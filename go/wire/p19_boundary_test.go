package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

// Supplemental tests use independent deterministic synthetic keys. They do
// not regenerate or replace the separately frozen 22 raw input observations.
func p19Synthetic(t *testing.T, core *wirepb.Core) ([]byte, Boundary, []ThresholdRoster) {
	t.Helper()
	core = proto.Clone(core).(*wirepb.Core)
	core.SignatureScheme, core.KeyId = proto.Uint64(2), proto.Uint64(40)
	boundary := fixtureScope(core)
	encoded, err := EncodeCore(core)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := SigningBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	roster := ThresholdRoster{Deployment: boundary.Deployment, Source: boundary.Source, Principal: boundary.Principal,
		KeyID: boundary.KeyID, Epoch: boundary.Epoch, Quorum: 2}
	payload := binary.BigEndian.AppendUint64(nil, 2)
	for i, id := range []uint64{2, 7, 11} {
		key := ed25519.NewKeyFromSeed(slices.Repeat([]byte{byte(31 + i)}, 32))
		roster.Members = append(roster.Members, ThresholdMember{ID: id, PublicKey: [32]byte(key.Public().(ed25519.PublicKey))})
		if i < 2 {
			payload = binary.BigEndian.AppendUint64(payload, id)
			payload = append(payload, ed25519.Sign(key, preimage)...)
		}
	}
	raw, err := EncodePacket(&wirepb.Packet{Core: core, Signature: payload})
	if err != nil {
		t.Fatal(err)
	}
	return raw, boundary, []ThresholdRoster{roster}
}

func p19CopyRosters(rosters []ThresholdRoster) []ThresholdRoster {
	copy := slices.Clone(rosters)
	for i := range copy {
		copy[i].Members = slices.Clone(copy[i].Members)
	}
	return copy
}

func TestThresholdRosterAndStrictSignatureBoundaries(t *testing.T) {
	raw, boundary, rosters := p19Synthetic(t, canonicalFixture())
	profile := fixtureProfile()
	channel := p19Channel(t, profile, boundary)
	// Every roster entry must be a valid unique canonical key, even if unused.
	nonpoint := [32]byte{2}
	if validThresholdPublicKey(nonpoint) {
		t.Fatal("the nonpoint fixture unexpectedly decoded")
	}
	for _, test := range []struct {
		name   string
		change func([]ThresholdRoster)
	}{
		{"deployment", func(r []ThresholdRoster) { r[0].Deployment++ }},
		{"source", func(r []ThresholdRoster) { r[0].Source++ }},
		{"principal", func(r []ThresholdRoster) { r[0].Principal++ }},
		{"unknown-group", func(r []ThresholdRoster) { r[0].KeyID++ }},
		{"previous-epoch", func(r []ThresholdRoster) { r[0].Epoch-- }},
		{"zero-quorum", func(r []ThresholdRoster) { r[0].Quorum = 0 }},
		{"quorum-above-roster", func(r []ThresholdRoster) { r[0].Quorum = 4 }},
		{"duplicate-unused-id", func(r []ThresholdRoster) { r[0].Members[2].ID = 2 }},
		{"alias-unused-key", func(r []ThresholdRoster) { r[0].Members[2].PublicKey = r[0].Members[0].PublicKey }},
		{"unused-small-order-key", func(r []ThresholdRoster) { r[0].Members[2].PublicKey = [32]byte{1} }},
		{"unused-invalid-point", func(r []ThresholdRoster) { r[0].Members[2].PublicKey = nonpoint }},
		{"unused-noncanonical-key", func(r []ThresholdRoster) {
			r[0].Members[2].PublicKey = [32]byte(p19Hex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := p19CopyRosters(rosters)
			test.change(current)
			var store TransportBindings
			if _, _, err := store.ReceiveConfigured(raw, channel, boundary, current, ReferenceAccepts, attest); err != ErrThreshold || store.Len() != 0 {
				t.Fatalf("got %v bindings %d", err, store.Len())
			}
		})
	}
	t.Run("ambiguous-group", func(t *testing.T) {
		var store TransportBindings
		if _, _, err := store.ReceiveConfigured(raw, channel, boundary, append(rosters, rosters[0]), ReferenceAccepts, attest); err != ErrThreshold || store.Len() != 0 {
			t.Fatal(err)
		}
	})
	for _, test := range []struct {
		name   string
		change func([]byte)
	}{
		{"small-order-R", func(s []byte) { clear(s[16:48]); s[16] = 1 }},
		{"noncanonical-R", func(s []byte) {
			copy(s[16:48], p19Hex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
		}},
		{"S-equal-group-order", func(s []byte) {
			clear(s[48:80])
			copy(s[48:64], p19Hex(t, "edd3f55c1a631258d69cf7a2def9de14"))
			s[79] = 0x10
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet, err := DecodePacket(raw, len(raw))
			if err != nil {
				t.Fatal(err)
			}
			test.change(packet.packet.Signature)
			bad, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			var store TransportBindings
			if _, _, err := store.ReceiveConfigured(bad, channel, boundary, rosters, ReferenceAccepts, attest); err != ErrThreshold || store.Len() != 0 {
				t.Fatal(err)
			}
		})
	}
}

func TestThresholdCurrentRosterReopenAndCallbackIsolation(t *testing.T) {
	raw, boundary, rosters := p19Synthetic(t, canonicalFixture())
	channel := p19Channel(t, fixtureProfile(), boundary)
	var store TransportBindings
	if arrival, _, err := store.ReceiveConfigured(raw, channel, boundary, rosters, ReferenceAccepts, attest); err != nil || arrival != First {
		t.Fatal(arrival, err)
	}
	// Reconstruct only transport state; current authority stays a fresh input.
	reopened := TransportBindings{entries: map[TransportKey][]byte{}}
	for k, v := range store.entries {
		reopened.entries[k] = slices.Clone(v)
	}
	changed := p19CopyRosters(rosters)
	changed[0].Members[0].PublicKey = [32]byte(ed25519.NewKeyFromSeed(slices.Repeat([]byte{70}, 32)).Public().(ed25519.PublicKey))
	before := map[TransportKey][]byte{}
	for k, v := range reopened.entries {
		before[k] = slices.Clone(v)
	}
	if _, _, err := reopened.ReceiveConfigured(raw, channel, boundary, changed, ReferenceAccepts, attest); err != ErrThreshold || !reflect.DeepEqual(before, reopened.entries) {
		t.Fatal("old signature after roster replacement", err)
	}
	if arrival, _, err := reopened.ReceiveConfigured(raw, channel, boundary, rosters, ReferenceAccepts, attest); err != nil || arrival != Identical {
		t.Fatal("exact retry after reopen", arrival, err)
	}
	wrongPeer := boundary
	wrongPeer.PublicKey[0] ^= 1
	if _, _, err := reopened.ReceiveConfigured(raw, channel, wrongPeer, rosters, ReferenceAccepts, attest); err != ErrSource || !reflect.DeepEqual(before, reopened.entries) {
		t.Fatal("peer key mismatch on retained retry", err)
	}
	boundary.Epoch++
	if _, _, err := reopened.ReceiveConfigured(raw, channel, boundary, rosters, ReferenceAccepts, attest); err != ErrSource || reopened.Len() != 1 {
		t.Fatal("old packet epoch after handover", err)
	}
	boundary.Epoch--
	var isolated TransportBindings
	mutable := p19CopyRosters(rosters)
	if arrival, _, err := isolated.ReceiveConfigured(raw, channel, boundary, mutable, func(core *wirepb.Core) bool {
		mutable[0].Members[0].PublicKey = [32]byte{1}
		return ReferenceAccepts(core)
	}, attest); err != nil || arrival != First {
		t.Fatal("active cut changed by callback", arrival, err)
	}
	if _, _, err := isolated.ReceiveConfigured(raw, channel, boundary, mutable, ReferenceAccepts, attest); err != ErrThreshold || isolated.Len() != 1 {
		t.Fatal("next cut not refreshed", err)
	}
}

func TestThresholdScopeTTLOperationAndChannelPrecedence(t *testing.T) {
	raw, boundary, rosters := p19Synthetic(t, canonicalFixture())
	channel := p19Channel(t, fixtureProfile(), boundary)
	bad := slices.Clone(raw)
	bad[len(bad)-1] ^= 1
	for _, test := range []struct {
		name   string
		change func(*Boundary)
		want   error
	}{
		{"scope-before-signature", func(b *Boundary) { b.Principal++ }, ErrSource},
		{"expired-before-signature", func(b *Boundary) { b.Now = 200 }, ErrExpired},
		{"future-before-signature", func(b *Boundary) { b.Now = 99 }, ErrTTL},
		{"frame-before-signature", func(b *Boundary) { b.MaxFrame = len(raw) - 1 }, ErrFormat},
		{"channel-deployment", func(b *Boundary) { b.Deployment++ }, ErrSource},
		{"channel-local", func(b *Boundary) { b.Target++ }, ErrSource},
		{"channel-peer", func(b *Boundary) { b.Source++ }, ErrSource},
		{"channel-peer-key-before-signature", func(b *Boundary) { b.PublicKey[0] ^= 1 }, ErrSource},
		{"channel-expiry", func(b *Boundary) { b.Now = 1001 }, ErrSource},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := boundary
			test.change(&b)
			var store TransportBindings
			if _, _, err := store.ReceiveConfigured(bad, channel, b, rosters, ReferenceAccepts, attest); err != test.want || store.Len() != 0 {
				t.Fatal(err)
			}
		})
	}
	var store TransportBindings
	if _, _, err := store.ReceiveConfigured(bad, channel, boundary, rosters, func(*wirepb.Core) bool { return false }, attest); err != ErrVersion || store.Len() != 0 {
		t.Fatal("operation precedence", err)
	}
	// The original Go order is signature, attestation, operands, binding.
	malformed := canonicalFixture()
	malformed.GetQuery().Words = nil
	malformedRaw, malformedBoundary, malformedRosters := p19Synthetic(t, malformed)
	malformedChannel := p19Channel(t, fixtureProfile(), malformedBoundary)
	if _, _, err := store.ReceiveConfigured(malformedRaw, malformedChannel, malformedBoundary, malformedRosters, ReferenceAccepts, func(*wirepb.Core) bool { return false }); err != ErrSource || store.Len() != 0 {
		t.Fatal("attestation before operands", err)
	}
	if _, _, err := store.ReceiveConfigured(malformedRaw, malformedChannel, malformedBoundary, malformedRosters, ReferenceAccepts, attest); err != ErrFormat || store.Len() != 0 {
		t.Fatal("operand no-effect", err)
	}
}

func TestThresholdPreservesSingleAPIsAndInstalledChannelIdentity(t *testing.T) {
	// An unkeyed literal checks that Boundary's public struct shape is unchanged.
	boundary := Boundary{7, 0, 2, 7, 9, 9, 1, 105, 2, 0, 5, 1024 * 1024, 4, false, [32]byte(remoteKey.Public().(ed25519.PublicKey))}
	raw := signFixture(t, canonicalFixture())
	channel := p19Channel(t, fixtureProfile(), boundary)
	if channel.keys != [2][32]byte{[32]byte(localKey.Public().(ed25519.PublicKey)), boundary.PublicKey} {
		t.Fatal("roster replaced channel peer identity")
	}
	malformedRosters := []ThresholdRoster{{Quorum: 0}}
	for _, kind := range []string{"Receive", "ReceiveAccepting", "ReceiveConfigured", "ReceiveVersioned", "ReceiveBeforeCommit"} {
		t.Run(kind, func(t *testing.T) {
			var store TransportBindings
			var arrival Arrival
			var err error
			switch kind {
			case "Receive":
				arrival, _, err = store.Receive(raw, fixtureProfile(), boundary, attest)
			case "ReceiveAccepting":
				arrival, _, err = store.ReceiveAccepting(raw, fixtureProfile(), boundary, ReferenceAccepts, attest)
			case "ReceiveConfigured":
				arrival, _, err = store.ReceiveConfigured(raw, channel, boundary, malformedRosters, ReferenceAccepts, attest)
			case "ReceiveVersioned":
				arrival, _, err = store.ReceiveVersioned(raw, channel, boundary, true, attest)
			case "ReceiveBeforeCommit":
				arrival, _, err = store.ReceiveBeforeCommit(raw, channel, boundary, true, false, nil, attest)
			}
			if err != nil || arrival != First || store.Len() != 1 {
				t.Fatal(arrival, err)
			}
		})
	}
	threshold, b, rosters := p19Synthetic(t, canonicalFixture())
	_ = rosters
	var old TransportBindings
	if _, _, err := old.Receive(threshold, fixtureProfile(), b, attest); err != ErrThreshold {
		t.Fatal("default threshold must stay refused", err)
	}
	if _, _, err := old.ReceiveAccepting(threshold, fixtureProfile(), b, ReferenceAccepts, attest); err != ErrThreshold {
		t.Fatal("default configured threshold must stay refused", err)
	}
}

func TestThresholdConfiguredOperandConsumers(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "wire-operations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, refused := 0, 0
	var evidence bytes.Buffer
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var row struct {
			ID        string `json:"id"`
			PacketHex string `json:"packet_hex"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(row.ID, "/valid") {
			continue
		}
		original, err := hex.DecodeString(row.PacketHex)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := DecodePacket(original, len(original))
		if err != nil {
			t.Fatal(err)
		}
		raw, boundary, rosters := p19Synthetic(t, packet.Core())
		channel := p19Channel(t, fixtureProfile(), boundary)
		var store TransportBindings
		arrival, received, err := store.ReceiveConfigured(raw, channel, boundary, rosters, ReferenceAccepts, attest)
		var verdict any = "accept:first"
		if ReferenceAccepts(packet.Core()) {
			if err != nil || arrival != First || received == nil || received.decodedOperands == nil || store.Len() != 1 {
				t.Fatalf("%s: %v", row.ID, err)
			}
			accepted++
			if retry, _, err := store.ReceiveConfigured(raw, channel, boundary, rosters, ReferenceAccepts, attest); err != nil || retry != Identical {
				t.Fatalf("%s retry: %v", row.ID, err)
			}
		} else {
			if err != ErrVersion || store.Len() != 0 {
				t.Fatalf("%s not excluded: %v", row.ID, err)
			}
			refused++
			verdict = p19Error(err)
		}
		encoded, err := json.Marshal(struct {
			ID        string `json:"id"`
			PacketHex string `json:"packet_hex"`
			Verdict   any    `json:"verdict"`
		}{row.ID, hex.EncodeToString(raw), verdict})
		if err != nil {
			t.Fatal(err)
		}
		evidence.Write(encoded)
		evidence.WriteByte('\n')
	}
	if accepted != 28 || refused != 5 {
		t.Fatalf("configured consumers accepted %d refused %d", accepted, refused)
	}
	if path := os.Getenv("OIP_P19_CONSUMER_OUTPUT"); path != "" {
		if err := os.WriteFile(path, evidence.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d actual configured operands and exact retries accepted; %d configured operations refused", accepted, refused)
}
