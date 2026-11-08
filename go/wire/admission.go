package wire

import (
	"crypto/ed25519"
	"encoding/binary"
	"math"
	"math/big"
	"slices"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

type Offer struct {
	Deployment, Sender, Receiver, Challenge, Expires uint64
	Versions, Families, Atomicities, Schemes         []uint64
}

type Profile struct {
	Version                        uint64
	Families, Atomicities, Schemes []uint64
}

type Negotiation struct {
	Deployment, Local, Remote, Challenge, Now, Floor uint64
	LegacyAllowed                                    bool
	LocalKey, RemoteKey                              [32]byte
}
type SignedOffers struct {
	Local, Remote                                 Offer
	LocalSignature, RemoteSignature, Confirmation []byte
}
type Channel struct {
	profile                                       Profile
	deployment, local, remote, challenge, expires uint64
	keys                                          [2][32]byte
}

func (channel Channel) Profile() Profile {
	p := channel.profile
	p.Families = slices.Clone(p.Families)
	p.Atomicities = slices.Clone(p.Atomicities)
	p.Schemes = slices.Clone(p.Schemes)
	return p
}

func strictlySorted(values []uint64) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}
func appendSet(out []byte, values []uint64) []byte {
	out = binary.BigEndian.AppendUint64(out, uint64(len(values)))
	for _, v := range values {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	return out
}
func OfferBytes(offer Offer) []byte {
	out := []byte("OIP\x00HEARTBEAT-OFFER\x00")
	for _, v := range []uint64{offer.Deployment, offer.Sender, offer.Receiver, offer.Challenge, offer.Expires} {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	for _, set := range [][]uint64{offer.Versions, offer.Families, offer.Atomicities, offer.Schemes} {
		out = appendSet(out, set)
	}
	return out
}
func ConfirmationBytes(local, remote Offer, profile Profile) []byte {
	out := []byte("OIP\x00HEARTBEAT-PROFILE\x00")
	for _, offer := range []Offer{local, remote} {
		bytes := OfferBytes(offer)
		out = binary.BigEndian.AppendUint64(out, uint64(len(bytes)))
		out = append(out, bytes...)
	}
	out = binary.BigEndian.AppendUint64(out, profile.Version)
	for _, set := range [][]uint64{profile.Families, profile.Atomicities, profile.Schemes} {
		out = appendSet(out, set)
	}
	return out
}

func intersect(a, b []uint64) []uint64 {
	out := make([]uint64, 0)
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}
func SelectProfile(local, remote Offer, floor uint64, legacyAllowed bool) (Profile, error) {
	for _, s := range [][]uint64{local.Versions, local.Families, local.Atomicities, local.Schemes,
		remote.Versions, remote.Families, remote.Atomicities, remote.Schemes} {
		if !strictlySorted(s) {
			return Profile{}, ErrFormat
		}
	}
	for _, v := range []uint64{6, 5} {
		if v >= floor && (v != 5 || legacyAllowed) && slices.Contains(local.Versions, v) && slices.Contains(remote.Versions, v) {
			families := intersect(local.Families, remote.Families)
			schemes := intersect(local.Schemes, remote.Schemes)
			if v == 5 {
				families = intersect(families, []uint64{4, 6})
				schemes = intersect(schemes, []uint64{1})
			}
			return Profile{Version: v, Families: families, Atomicities: intersect(local.Atomicities, remote.Atomicities), Schemes: schemes}, nil
		}
	}
	return Profile{}, ErrVersion
}

var edwardsPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
var edwardsD = func() *big.Int {
	inverse := new(big.Int).ModInverse(big.NewInt(121666), edwardsPrime)
	return new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), inverse), edwardsPrime)
}()

// Reject noncanonical and small-order public encodings before Go's Ed25519
// verification. These are public point checks, not a signing implementation.
func strictPoint(compressed []byte) bool {
	if len(compressed) != 32 {
		return false
	}
	var reversed [32]byte
	for i := range reversed {
		reversed[31-i] = compressed[i]
	}
	reversed[0] &= 127
	y := new(big.Int).SetBytes(reversed[:])
	if y.Cmp(edwardsPrime) >= 0 {
		return false
	}
	one := big.NewInt(1)
	for range 3 {
		yy := new(big.Int).Mod(new(big.Int).Mul(y, y), edwardsPrime)
		dyy := new(big.Int).Mul(edwardsD, yy)
		inverse := new(big.Int).ModInverse(new(big.Int).Add(dyy, one), edwardsPrime)
		if inverse == nil {
			return false
		}
		xx := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(yy, one), inverse), edwardsPrime)
		denominator := new(big.Int).Sub(one, new(big.Int).Mul(dyy, xx))
		inverse = denominator.ModInverse(denominator, edwardsPrime)
		if inverse == nil {
			return false
		}
		y.Mod(new(big.Int).Mul(new(big.Int).Add(yy, xx), inverse), edwardsPrime)
	}
	return y.Cmp(one) != 0
}

func verify(key [32]byte, message, signature []byte) bool {
	return len(signature) == ed25519.SignatureSize && strictPoint(key[:]) && strictPoint(signature[:32]) &&
		ed25519.Verify(ed25519.PublicKey(key[:]), message, signature)
}

func Negotiate(context Negotiation, signed SignedOffers) (Channel, error) {
	l, r := signed.Local, signed.Remote
	if l.Deployment != context.Deployment || r.Deployment != context.Deployment ||
		l.Sender != context.Local || l.Receiver != context.Remote || r.Sender != context.Remote || r.Receiver != context.Local ||
		l.Challenge != context.Challenge || r.Challenge != context.Challenge || l.Expires < context.Now || r.Expires < context.Now {
		return Channel{}, ErrSource
	}
	if !verify(context.LocalKey, OfferBytes(l), signed.LocalSignature) ||
		!verify(context.RemoteKey, OfferBytes(r), signed.RemoteSignature) {
		return Channel{}, ErrSignature
	}
	profile, err := SelectProfile(l, r, context.Floor, context.LegacyAllowed)
	if err != nil {
		return Channel{}, err
	}
	if !verify(context.RemoteKey, ConfirmationBytes(l, r, profile), signed.Confirmation) {
		return Channel{}, ErrSignature
	}
	return Channel{profile: profile, deployment: context.Deployment, local: context.Local, remote: context.Remote,
		challenge: context.Challenge, expires: min(l.Expires, r.Expires), keys: [2][32]byte{context.LocalKey, context.RemoteKey}}, nil
}

type Boundary struct {
	Deployment, Source, Target, Principal, KeyID, Epoch, RouteScope uint64
	Now, AssetTTLFloor, FutureSkew, VersionFloor                    uint64
	MaxFrame, MaxNesting                                            int
	CriticalAllowed                                                 bool
	PublicKey                                                       [32]byte
}

func checkScope(core *wirepb.Core, profile Profile, boundary Boundary, version uint64) error {
	family, op := Body(core)
	if profile.Version != version || core.GetVersion() != version || boundary.VersionFloor > version ||
		!slices.Contains(profile.Families, family) || !slices.Contains(profile.Atomicities, core.GetAtomicity()) ||
		(version == 5 && (op.GetOpcode() < 1 || op.GetOpcode() > 2 || (family != 4 && family != 6))) {
		return ErrVersion
	}
	if core.GetPurpose() != 1 || core.GetDeployment() != boundary.Deployment || core.GetSourceDomain() != boundary.Source ||
		core.GetTargetDomain() != boundary.Target || core.GetPrincipal() != boundary.Principal || core.GetKeyId() != boundary.KeyID ||
		core.GetAuthorityEpoch() != boundary.Epoch || core.GetRouteScope() != boundary.RouteScope ||
		(core.GetPriority() == 0 && !boundary.CriticalAllowed) {
		return ErrSource
	}
	sent, ttl := core.GetIssuedSeconds(), max(core.GetTtlSeconds(), boundary.AssetTTLFloor)
	if ttl > math.MaxUint64-sent || boundary.FutureSkew > math.MaxUint64-boundary.Now ||
		sent > boundary.Now+boundary.FutureSkew {
		return ErrTTL
	}
	if sent+ttl < boundary.Now {
		return ErrExpired
	}
	return nil
}

func AdmitPacket(packet *CanonicalPacket, profile Profile, boundary Boundary) error {
	core := packet.packet.Core
	if err := checkScope(core, profile, boundary, 6); err != nil {
		return err
	}
	if core.GetSignatureScheme() == 2 {
		return ErrThreshold
	}
	preimage, err := packet.SigningBytes()
	if err != nil || !slices.Contains(profile.Schemes, core.GetSignatureScheme()) ||
		!verify(boundary.PublicKey, preimage, packet.packet.Signature) {
		return ErrSignature
	}
	return nil
}

type TransportKey struct {
	Deployment, Source, Principal uint64
	UUID                          [16]byte
}

func Key(core *wirepb.Core) (TransportKey, error) {
	if core.Deployment == nil || core.SourceDomain == nil || core.Principal == nil || len(core.Uuid) != 16 {
		return TransportKey{}, ErrFormat
	}
	return TransportKey{Deployment: core.GetDeployment(), Source: core.GetSourceDomain(), Principal: core.GetPrincipal(), UUID: [16]byte(core.Uuid)}, nil
}
