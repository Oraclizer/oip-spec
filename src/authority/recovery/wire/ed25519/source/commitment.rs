//! Commitment observations selected by the independent source journal.

use super::{Mark, SourceAuthority, SourceReader, SourceSigner, SourceStores, verify_strict};
use crate::OriginKey;
use crate::authority::recovery::HeadError;
use crate::authority::sync::{Call, Stream};
use crate::wire::source_attestation::{self, SourceSignature, SourceStatement};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Historical producer registration indexed by origin, epoch and roster.
/// The receiving policy independently names the one current roster.
pub type CommitmentAuthorities = BTreeMap<u64, BTreeMap<u64, BTreeMap<u64, SourceAuthority>>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncRoster {
    pub origin_epoch: u64,
    pub roster_id: u64,
    pub quorum: usize,
    pub signers: BTreeMap<u64, [u8; 32]>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncPolicy {
    pub accept_sync: bool,
    pub accept_current: bool,
    pub rosters: BTreeMap<u64, SyncRoster>,
}

impl SyncPolicy {
    pub(crate) fn is_empty(&self) -> bool {
        !self.accept_sync && !self.accept_current && self.rosters.is_empty()
    }

    pub(crate) fn valid(&self, unavailable_keys: &BTreeSet<[u8; 32]>) -> bool {
        self.rosters.values().all(|roster| {
            super::valid_signers(roster.quorum, &roster.signers)
                && roster
                    .signers
                    .values()
                    .all(|key| !unavailable_keys.contains(key))
        })
    }

    pub(crate) fn verifies(&self, call: &Call<'_>) -> bool {
        let Some(roster) = self.rosters.get(&call.stream.origin_domain) else {
            return false;
        };
        let Ok(proof) = source_attestation::decode(call.source_attestation) else {
            return false;
        };
        let expected = SourceStatement {
            deployment: call.deployment,
            origin_domain: call.stream.origin_domain,
            origin_epoch: call.entry.origin_epoch,
            roster_id: roster.roster_id,
            asset: call.stream.asset,
            origin_event: call.entry.origin_event,
            source_position: call.entry.source_position,
            commitment: call.entry.commitment,
            predecessor: call.predecessor,
        };
        proof.statement == expected
            && roster.origin_epoch == expected.origin_epoch
            && proof.signatures.len() >= roster.quorum
            && proof.signatures.iter().all(|vote| {
                roster
                    .signers
                    .get(&vote.signer_id)
                    .is_some_and(|key| verify_strict(key, proof.signed_bytes, &vote.signature))
            })
    }
}

/// One authenticated external observation for insertion by the source writer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedCommitment {
    statement: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedCommitment {
    pub fn new(statement: SourceStatement, signature: [u8; 64]) -> Self {
        Self {
            statement: statement.signing_bytes(),
            signature: signature.to_vec(),
        }
    }

    pub fn record_signing_bytes(statement: &SourceStatement) -> Vec<u8> {
        let mut bytes = b"oip/source-commitment-record/v1\0".to_vec();
        bytes.extend(statement.signing_bytes());
        bytes
    }

    pub(super) fn statement(&self) -> Result<SourceStatement, HeadError> {
        source_attestation::decode_statement(&self.statement).map_err(|_| HeadError)
    }
}

pub(super) fn stream_of(statement: SourceStatement) -> Stream {
    Stream {
        asset: statement.asset,
        origin_domain: statement.origin_domain,
    }
}

/// Opaque identity of the journal revision selected by the independent mark.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentSelection {
    stores: SourceStores,
    mark: Mark,
    statement: SourceStatement,
    quorum: usize,
}

impl CommitmentSelection {
    pub fn statement(&self) -> SourceStatement {
        self.statement
    }

    /// Assemble votes obtained from this exact selected record.
    pub fn proof(&self, votes: &[CommitmentVote]) -> Result<Vec<u8>, HeadError> {
        if votes.len() < self.quorum || !votes.iter().all(|vote| &vote.selection == self) {
            return Err(HeadError);
        }
        let mut signatures: Vec<_> = votes.iter().map(|vote| vote.signature).collect();
        signatures.sort_unstable_by_key(|vote| vote.signer_id);
        source_attestation::encode(&self.statement, &signatures).map_err(|_| HeadError)
    }
}

pub struct CommitmentVote {
    selection: CommitmentSelection,
    signature: SourceSignature,
}

impl SourceReader {
    pub(super) fn commitment_rule(&self, statement: SourceStatement) -> Option<&SourceAuthority> {
        self.commitment_authorities
            .get(&statement.origin_domain)?
            .get(&statement.origin_epoch)?
            .get(&statement.roster_id)
    }

    pub(super) fn authenticated_commitment(
        &self,
        record: &SignedCommitment,
    ) -> Option<SourceStatement> {
        let statement = record.statement().ok()?;
        let rule = self.commitment_rule(statement)?;
        (statement.deployment == self.profile.deployment
            && verify_strict(
                &rule.issuer,
                &SignedCommitment::record_signing_bytes(&statement),
                &record.signature,
            ))
        .then_some(statement)
    }

    pub(super) fn valid_commitments(&self, records: &[SignedCommitment]) -> bool {
        let mut entries = BTreeMap::<Stream, SourceStatement>::new();
        let mut events = BTreeSet::new();
        for record in records {
            let Some(statement) = self.authenticated_commitment(record) else {
                return false;
            };
            let stream = stream_of(statement);
            if !events.insert(OriginKey {
                domain: stream.origin_domain,
                event: statement.origin_event,
            }) || entries
                .get(&stream)
                .is_some_and(|before| statement.source_position <= before.source_position)
                || statement.predecessor.is_some_and(|predecessor| {
                    entries.get(&stream).map(|before| before.commitment) != Some(predecessor)
                })
            {
                return false;
            }
            entries.insert(stream, statement);
        }
        true
    }

    pub fn selected_commitment(&self, stream: Stream) -> Result<CommitmentSelection, HeadError> {
        let journal = self.journal.current()?;
        let state = self.decode_state(&journal.bytes)?;
        let selected = self.confirm_selected(&journal, &state)?;
        let statement = state.current_commitment(stream)?.statement()?;
        let quorum = self.commitment_rule(statement).ok_or(HeadError)?.quorum;
        Ok(CommitmentSelection {
            stores: self.binding,
            mark: selected.journal,
            statement,
            quorum,
        })
    }
}

impl SourceSigner {
    /// Independently read the current selected record before signing its statement.
    pub fn issue_commitment(
        &self,
        journal: &SourceReader,
        selected: &CommitmentSelection,
    ) -> Result<CommitmentVote, HeadError> {
        let current = journal.selected_commitment(stream_of(selected.statement))?;
        let rule = journal
            .commitment_rule(current.statement)
            .ok_or(HeadError)?;
        if current != *selected
            || rule.signers.get(&self.id) != Some(&self.key.verifying_key().to_bytes())
        {
            return Err(HeadError);
        }
        Ok(CommitmentVote {
            signature: SourceSignature {
                signer_id: self.id,
                signature: self.key.sign(&current.statement.signing_bytes()).to_bytes(),
            },
            selection: current,
        })
    }
}
