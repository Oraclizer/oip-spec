package wire

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

// Install a genuinely authenticated channel for a different synthetic peer.
func fixtureOtherPeerChannel(t *testing.T) Channel {
	t.Helper()
	peer := ed25519.NewKeyFromSeed(slices.Repeat([]byte{8}, 32))
	local, remote := fixtureOffer(2, 0, []uint64{6}), fixtureOffer(0, 2, []uint64{6})
	context := Negotiation{Deployment: 7, Local: 2, Remote: 0, Challenge: 3, Now: 105, Floor: 6,
		LocalKey: [32]byte(localKey.Public().(ed25519.PublicKey)), RemoteKey: [32]byte(peer.Public().(ed25519.PublicKey))}
	profile, err := SelectProfile(local, remote, context.Floor, context.LegacyAllowed)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := Negotiate(context, SignedOffers{Local: local, Remote: remote,
		LocalSignature: ed25519.Sign(localKey, OfferBytes(local)), RemoteSignature: ed25519.Sign(peer, OfferBytes(remote)),
		Confirmation: ed25519.Sign(peer, ConfirmationBytes(local, remote, profile))})
	if err != nil {
		t.Fatal(err)
	}
	return channel
}

func TestVersionSixChannelBindsPeerKeyBeforeReceive(t *testing.T) {
	boundary := fixtureBoundary()
	raw := signFixture(t, canonicalFixture())
	matching, err := fixtureNegotiation([]uint64{6}, []uint64{6}, 6, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	other := fixtureOtherPeerChannel(t)
	if other.keys[1] == boundary.PublicKey {
		t.Fatal("the other peer must differ from the envelope verification key")
	}
	key, err := Key(canonicalFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"ReceiveVersioned", "ReceiveBeforeCommit"} {
		t.Run(entry, func(t *testing.T) {
			var store TransportBindings
			callbacks := 0
			attest := func(*wirepb.Core) bool { callbacks++; return true }
			receive := func(channel Channel) (Arrival, *wirepb.Core, error) {
				if entry == "ReceiveVersioned" {
					return store.ReceiveVersioned(raw, channel, boundary, true, attest)
				}
				return store.ReceiveBeforeCommit(raw, channel, boundary, true, false, nil, attest)
			}
			if _, core, err := receive(other); err != ErrSource || core != nil || callbacks != 0 || store.Len() != 0 {
				t.Fatalf("wrong peer before first receive: error=%v callbacks=%d bindings=%d", err, callbacks, store.Len())
			}
			if arrival, core, err := receive(matching); err != nil || arrival != First || core == nil || callbacks != 1 || store.Len() != 1 {
				t.Fatalf("matching peer: arrival=%v error=%v callbacks=%d bindings=%d", arrival, err, callbacks, store.Len())
			}
			retained := bytes.Clone(store.entries[key])
			if _, core, err := receive(other); err != ErrSource || core != nil || callbacks != 1 || store.Len() != 1 || !bytes.Equal(retained, store.entries[key]) {
				t.Fatalf("wrong peer with retained binding: error=%v callbacks=%d bindings=%d", err, callbacks, store.Len())
			}
			if arrival, _, err := receive(matching); err != nil || arrival != Identical || callbacks != 2 || !bytes.Equal(retained, store.entries[key]) {
				t.Fatalf("matching exact retry: arrival=%v error=%v callbacks=%d", arrival, err, callbacks)
			}
		})
	}
}

func TestVersionSixBeforeCommitChecksCancellationThenDeadlineThenPeer(t *testing.T) {
	boundary := fixtureBoundary()
	raw := signFixture(t, canonicalFixture())
	other := fixtureOtherPeerChannel(t)
	matching, err := fixtureNegotiation([]uint64{6}, []uint64{6}, 6, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	expired, inclusive := boundary.Now-1, boundary.Now
	for _, test := range []struct {
		name      string
		channel   Channel
		cancelled bool
		deadline  *uint64
		want      error
	}{
		{"cancelled before deadline and peer", other, true, &expired, ErrCancelled},
		{"deadline before peer", other, false, &expired, ErrDeadline},
		{"equal deadline reaches peer", other, false, &inclusive, ErrSource},
		{"absent deadline reaches peer", other, false, nil, ErrSource},
		{"equal deadline with matching peer", matching, false, &inclusive, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var store TransportBindings
			callbacks := 0
			arrival, core, err := store.ReceiveBeforeCommit(raw, test.channel, boundary, true, test.cancelled, test.deadline,
				func(*wirepb.Core) bool { callbacks++; return true })
			if err != test.want {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if test.want != nil {
				if core != nil || callbacks != 0 || store.Len() != 0 {
					t.Fatalf("refusal reached callback or binding: callbacks=%d bindings=%d", callbacks, store.Len())
				}
			} else if arrival != First || core == nil || callbacks != 1 || store.Len() != 1 {
				t.Fatalf("inclusive deadline: arrival=%v callbacks=%d bindings=%d", arrival, callbacks, store.Len())
			}
		})
	}
}
