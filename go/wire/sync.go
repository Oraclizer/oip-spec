package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

type SyncMode uint64

const (
	SyncInitial SyncMode = iota + 1
	SyncIncremental
	SyncFullResync
)

// SyncCommitment is the decoded STATE_SYNC/7 operand. SourceAttestation is
// carried as opaque bytes by transport admission.
type SyncCommitment struct {
	Reference, Sequence, Session, Revision, OriginEpoch uint64
	Origin                                              Origin
	Asset, SourcePosition                               uint64
	Mode                                                SyncMode
	Commitment                                          [32]byte
	Predecessor                                         *[32]byte
	SourceAttestation                                   []byte
}

// CurrentCommitment is the decoded QUERY/9 operand.
type CurrentCommitment struct {
	Session, Revision, Asset, OriginDomain uint64
}

func decodeSyncCommitment(core *wirepb.Core, op *wirepb.Operation) (*SyncCommitment, []uint64, error) {
	if op.AppealDeadline != nil || len(op.Blobs) != 3 || len(op.Blobs[0]) != 32 {
		return nil, nil, ErrFormat
	}
	w := words{items: op.Words}
	sync := new(SyncCommitment)
	var mode uint64
	if err := w.read(&sync.Reference, &sync.Sequence, &sync.Session, &sync.Revision, &sync.OriginEpoch,
		&sync.Origin.Domain, &sync.Origin.Event, &sync.Asset, &sync.SourcePosition, &mode); err != nil || w.end() != nil {
		return nil, nil, ErrFormat
	}
	sync.Mode = SyncMode(mode)
	predecessor := valueNone()
	switch sync.Mode {
	case SyncInitial, SyncFullResync:
		if len(op.Blobs[1]) != 0 {
			return nil, nil, ErrFormat
		}
	case SyncIncremental:
		if len(op.Blobs[1]) != 32 {
			return nil, nil, ErrFormat
		}
		value := [32]byte(op.Blobs[1])
		sync.Predecessor = &value
		predecessor = valueSome(valueBytes(value[:]))
	default:
		return nil, nil, ErrFormat
	}
	sync.Commitment = [32]byte(op.Blobs[0])
	sync.SourceAttestation = bytes.Clone(op.Blobs[2])
	summary := valueNode(22, valueScalar(sync.Reference), valuePair(core.GetPrincipal(), sync.Sequence),
		valueScalar(sync.Session), valuePair(core.GetAuthorityEpoch(), sync.Revision), valueScalar(sync.OriginEpoch),
		valuePair(sync.Origin.Domain, sync.Origin.Event), valueScalar(sync.Asset), valueScalar(sync.SourcePosition),
		valueScalar(mode), valueBytes(sync.Commitment[:]), predecessor, valueBytes(sync.SourceAttestation))
	return sync, summary, nil
}

func decodeCurrentCommitment(core *wirepb.Core, op *wirepb.Operation) (*CurrentCommitment, []uint64, error) {
	if op.AppealDeadline != nil || len(op.Blobs) != 0 {
		return nil, nil, ErrFormat
	}
	w := words{items: op.Words}
	query := new(CurrentCommitment)
	if err := w.read(&query.Session, &query.Revision, &query.Asset, &query.OriginDomain); err != nil || w.end() != nil {
		return nil, nil, ErrFormat
	}
	epoch := core.GetAuthorityEpoch()
	proof := valueNode(104, valueScalar(query.Session), valueScalar(epoch))
	request := valueNode(156, valuePair(epoch, query.Revision), valueScalar(query.Asset), valueScalar(query.OriginDomain))
	return query, valueNode(13, proof, request), nil
}

type SourceAttestationSignature struct {
	SignerID  uint64
	Signature [ed25519.SignatureSize]byte
}

// SourceAttestation contains the exact signed statement and the signatures
// following it. A nil predecessor identifies a source snapshot.
type SourceAttestation struct {
	FormatVersion, ClaimKind, Deployment, OriginDomain, OriginEpoch uint64
	RosterID, Asset, OriginEvent, SourcePosition                    uint64
	Commitment                                                      [32]byte
	Predecessor                                                     *[32]byte
	SignedStatement                                                 []byte
	Signatures                                                      []SourceAttestationSignature
}

const sourceAttestationDomain = "OIP\x00SOURCE-ATTESTATION\x00"

// DecodeSourceAttestation checks the format-1, claim-kind-1 binary layout.
// Roster, quorum, signature and request checks are separate from this decoder.
func DecodeSourceAttestation(proof []byte) (SourceAttestation, error) {
	const (
		statementSize = len(sourceAttestationDomain) + 9*8 + 32 + 1
		signatureSize = 8 + ed25519.SignatureSize
	)
	if len(proof) < statementSize+8 || !bytes.HasPrefix(proof, []byte(sourceAttestationDomain)) {
		return SourceAttestation{}, ErrFormat
	}
	var attestation SourceAttestation
	fields := []*uint64{&attestation.FormatVersion, &attestation.ClaimKind, &attestation.Deployment,
		&attestation.OriginDomain, &attestation.OriginEpoch, &attestation.RosterID, &attestation.Asset,
		&attestation.OriginEvent, &attestation.SourcePosition}
	remaining := proof[len(sourceAttestationDomain):]
	for _, field := range fields {
		*field = binary.BigEndian.Uint64(remaining)
		remaining = remaining[8:]
	}
	if attestation.FormatVersion != 1 || attestation.ClaimKind != 1 {
		return SourceAttestation{}, ErrFormat
	}
	attestation.Commitment = [32]byte(remaining[:32])
	end := statementSize
	switch remaining[32] {
	case 0:
	case 1:
		end += 32
		if len(proof) < end+8 {
			return SourceAttestation{}, ErrFormat
		}
		predecessor := [32]byte(proof[statementSize:end])
		attestation.Predecessor = &predecessor
	default:
		return SourceAttestation{}, ErrFormat
	}
	count := binary.BigEndian.Uint64(proof[end:])
	votes := proof[end+8:]
	if len(votes)%signatureSize != 0 || count != uint64(len(votes)/signatureSize) {
		return SourceAttestation{}, ErrFormat
	}
	attestation.SignedStatement = bytes.Clone(proof[:end])
	attestation.Signatures = make([]SourceAttestationSignature, int(count))
	for i := range attestation.Signatures {
		id := binary.BigEndian.Uint64(votes)
		if i > 0 && attestation.Signatures[i-1].SignerID >= id {
			return SourceAttestation{}, ErrFormat
		}
		attestation.Signatures[i] = SourceAttestationSignature{SignerID: id, Signature: [ed25519.SignatureSize]byte(votes[8:signatureSize])}
		votes = votes[signatureSize:]
	}
	return attestation, nil
}
