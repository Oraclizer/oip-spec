//! Current owner endorsement and exact terminal proof matching.

use super::{
    Ed25519Profile, preimage,
    source::{SourceStatement, verify_certificate},
};
use crate::authority::CallPayload;
use crate::authority::identity::{Identity, SessionProof};
use crate::authority::recovery::RecoveryProfile;
use crate::lock_finality::{Command, TerminalEvidence, TerminalKind};
use crate::wire::codec::WireError;
use crate::{CallId, OriginKey};

/// Build the owner endorsement for exactly the current product action.
pub fn claim_recovery_signing_bytes(
    profile: RecoveryProfile,
    identity: Identity,
    proof: SessionProof,
    target: u64,
    origin: OriginKey,
    id: CallId,
    payload: &CallPayload,
) -> Result<Vec<u8>, WireError> {
    preimage(
        b"oip/reference-claim-recovery/v1\0",
        &(
            profile,
            identity,
            proof.session,
            proof.epoch,
            target,
            origin,
            id,
            payload,
        ),
    )
}

pub(super) fn lock_recovery(command: Command) -> bool {
    matches!(
        command,
        Command::Cancel { .. } | Command::Fence { .. } | Command::Preempt { .. }
    )
}

pub(super) fn terminal_proof(
    config: &Ed25519Profile,
    payload: &CallPayload,
    proofs: &[Vec<u8>],
) -> bool {
    let evidence = match payload.command {
        Command::RecordTerminal(evidence) => evidence,
        Command::Refund { reference, .. } => TerminalEvidence {
            binding: payload.binding,
            kind: TerminalKind::Reversed,
            reference,
        },
        Command::Reconcile { reference, .. } => TerminalEvidence {
            binding: payload.binding,
            kind: TerminalKind::Confirmed,
            reference,
        },
        command if lock_recovery(command) => {
            return matches!(proofs, [proof] if ed25519_dalek::Signature::from_slice(proof).is_ok());
        }
        _ => return proofs.is_empty(),
    };
    let [proof] = proofs else {
        return false;
    };
    evidence.binding == payload.binding
        && verify_certificate(
            &config.sources,
            SourceStatement {
                profile: config.profile,
                origin_epoch: payload.origin_epoch,
                evidence,
            },
            proof,
        )
}
