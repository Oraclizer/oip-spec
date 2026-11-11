package wire

import (
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

// ThresholdMember binds one member identifier to its Ed25519 public key.
type ThresholdMember struct {
	ID        uint64
	PublicKey [32]byte
}

// ThresholdRoster is trusted current configuration, never packet-supplied
// authority. KeyID names the group, not a member or a channel negotiation key.
// A host must supply the roster for its current cut on every receive, including
// after reopening or handing over a retained transport binding store.
type ThresholdRoster struct {
	Deployment, Source, Principal, KeyID, Epoch, Quorum uint64
	Members                                             []ThresholdMember
}

// ReceiveConfigured receives a version 6 envelope on an authenticated channel,
// with the host's current threshold rosters and operation predicate. It uses
// the same admission, attestation, operand and exact binding path as Receive.
// Channel peer keys retain their negotiation role. SINGLE still uses
// boundary.PublicKey; configuring a group does not replace any peer key.
// Roster data is copied before callbacks so a callback cannot alter this cut.
func (store *TransportBindings) ReceiveConfigured(raw []byte, channel Channel, boundary Boundary,
	rosters []ThresholdRoster, accepts func(*wirepb.Core) bool, attest func(*wirepb.Core) bool) (Arrival, *CanonicalPacket, error) {
	if channel.deployment != boundary.Deployment || channel.local != boundary.Target ||
		channel.remote != boundary.Source || channel.expires < boundary.Now || channel.keys[1] != boundary.PublicKey {
		return First, nil, ErrSource
	}
	current := slices.Clone(rosters)
	for i := range current {
		current[i].Members = slices.Clone(current[i].Members)
	}
	return store.receiveAccepting(raw, channel.profile, boundary, current, accepts, attest)
}

func selectThresholdRoster(boundary Boundary, rosters []ThresholdRoster) *ThresholdRoster {
	var selected *ThresholdRoster
	for i := range rosters {
		roster := &rosters[i]
		if roster.Deployment == boundary.Deployment && roster.Source == boundary.Source &&
			roster.Principal == boundary.Principal && roster.KeyID == boundary.KeyID && roster.Epoch == boundary.Epoch {
			if selected != nil {
				return nil // Ambiguous trusted registration is not a choice for the sender.
			}
			selected = roster
		}
	}
	return selected
}

// strictPoint supplies the existing SINGLE canonical and small-order checks.
// The square-root check also rejects invalid points in unused roster entries:
// those entries do not reach ed25519.Verify's point decoder during this packet.
func validThresholdPublicKey(key [32]byte) bool {
	if !strictPoint(key[:]) {
		return false
	}
	var reversed [32]byte
	for i := range reversed {
		reversed[31-i] = key[i]
	}
	reversed[0] &= 127
	y := new(big.Int).SetBytes(reversed[:])
	yy := new(big.Int).Mod(new(big.Int).Mul(y, y), edwardsPrime)
	denominator := new(big.Int).Add(new(big.Int).Mul(edwardsD, yy), big.NewInt(1))
	inverse := new(big.Int).ModInverse(denominator, edwardsPrime)
	if inverse == nil {
		return false
	}
	xx := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(yy, big.NewInt(1)), inverse), edwardsPrime)
	return new(big.Int).ModSqrt(xx, edwardsPrime) != nil
}

// The caller has already enforced the complete Packet bound and scope/TTL.
// Payload length, declared u64 count and roster capacity are checked before
// allocating a lookup table or verifying any supplied record. No count-sized
// multiplication or conversion to a native integer is used.
func verifyThreshold(packet *CanonicalPacket, boundary Boundary, rosters []ThresholdRoster) bool {
	roster := selectThresholdRoster(boundary, rosters)
	if roster == nil || roster.Quorum == 0 || roster.Quorum > uint64(len(roster.Members)) {
		return false
	}
	payload := packet.packet.Signature
	const recordSize = 8 + 64
	if len(payload) < 8 || (len(payload)-8)%recordSize != 0 {
		return false
	}
	available := (len(payload) - 8) / recordSize
	count := binary.BigEndian.Uint64(payload[:8])
	if count != uint64(available) || count > uint64(len(roster.Members)) || count < roster.Quorum {
		return false
	}
	members := make(map[uint64][32]byte, len(roster.Members))
	keys := make(map[[32]byte]struct{}, len(roster.Members))
	for _, member := range roster.Members {
		if _, exists := members[member.ID]; exists {
			return false
		}
		if _, exists := keys[member.PublicKey]; exists || !validThresholdPublicKey(member.PublicKey) {
			return false
		}
		members[member.ID] = member.PublicKey
		keys[member.PublicKey] = struct{}{}
	}
	preimage, err := packet.SigningBytes()
	if err != nil {
		return false
	}
	var previous uint64
	for i, records := 0, payload[8:]; i < available; i, records = i+1, records[recordSize:] {
		id := binary.BigEndian.Uint64(records[:8])
		key, registered := members[id]
		if (i != 0 && id <= previous) || !registered || !verify(key, preimage, records[8:recordSize]) {
			return false
		}
		previous = id
	}
	return true
}
