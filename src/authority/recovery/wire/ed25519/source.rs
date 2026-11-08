//! Durable external source decisions and purpose-bound terminal attestations.

use super::{INVALID, preimage, verify_strict, verifying_key};
use crate::OriginKey;
use crate::authority::recovery::ordered::ControlValue;
use crate::authority::recovery::ordered::etcd::EtcdTransport;
use crate::authority::recovery::{HeadError, RecoveryProfile};
use crate::lock_finality::TerminalEvidence;
use crate::wire::codec::WireError;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type SourceAuthorities = BTreeMap<u64, BTreeMap<u64, SourceAuthority>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceAuthority {
    pub issuer: [u8; 32],
    pub quorum: usize,
    pub signers: BTreeMap<u64, [u8; 32]>,
}

impl SourceAuthority {
    fn valid(&self) -> bool {
        let distinct: BTreeSet<_> = self.signers.values().copied().collect();
        self.quorum > 0
            && self.quorum <= self.signers.len()
            && distinct.len() == self.signers.len()
            && !distinct.contains(&self.issuer)
            && verifying_key(&self.issuer).is_some()
            && distinct.iter().all(|key| verifying_key(key).is_some())
    }
}

pub(super) fn valid_authorities(
    authorities: &SourceAuthorities,
    unavailable_keys: &BTreeSet<[u8; 32]>,
) -> bool {
    authorities.values().all(|epochs| {
        !epochs.is_empty()
            && epochs.values().all(|authority| {
                authority.valid()
                    && !unavailable_keys.contains(&authority.issuer)
                    && authority
                        .signers
                        .values()
                        .all(|key| !unavailable_keys.contains(key))
            })
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStatement {
    pub profile: RecoveryProfile,
    pub origin_epoch: u64,
    pub evidence: TerminalEvidence,
}

impl SourceStatement {
    /// The configured external source authority signs the durable decision
    /// before it can enter the independent source journal.
    pub fn record_signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        preimage(b"oip/source-terminal-record/v1\0", self)
    }

    fn quorum_signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        preimage(b"oip/source-terminal-quorum/v1\0", self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedSourceDecision {
    pub statement: SourceStatement,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceVote {
    pub signer: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceCertificate {
    pub statement: SourceStatement,
    pub votes: Vec<SourceVote>,
}

impl SourceCertificate {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WireError> {
        serde_json::to_vec(self).map_err(|_| WireError::InvalidFormat)
    }
}

fn rule_for<'a>(
    rules: &'a SourceAuthorities,
    statement: &SourceStatement,
) -> Option<&'a SourceAuthority> {
    rules
        .get(&statement.evidence.binding.origin.domain)?
        .get(&statement.origin_epoch)
}

pub(super) fn verify_certificate(
    rules: &SourceAuthorities,
    expected: SourceStatement,
    proof: &[u8],
) -> bool {
    let Ok(certificate) = canonical::<SourceCertificate>(proof) else {
        return false;
    };
    if certificate.statement != expected {
        return false;
    }
    let Some(rule) = rule_for(rules, &certificate.statement).filter(|rule| rule.valid()) else {
        return false;
    };
    let Ok(message) = expected.quorum_signing_bytes() else {
        return false;
    };
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    certificate.votes.iter().all(|vote| {
        rule.signers.get(&vote.signer).is_some_and(|key| {
            ids.insert(vote.signer)
                && keys.insert(*key)
                && verify_strict(key, &message, &vote.signature)
        })
    }) && keys.len() >= rule.quorum
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourceStores {
    journal: [u8; 32],
    witness: [u8; 32],
    authorities: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Mark {
    revision: u64,
    sha256: [u8; 32],
}

impl Mark {
    // Upper bound on the canonical JSON length before the CAS assigns its MOD.
    const ENCODING_BOUND: Self = Self {
        revision: u64::MAX,
        sha256: [u8::MAX; 32],
    };

    fn of(raw: &ControlValue) -> Self {
        Self {
            revision: raw.revision,
            sha256: Sha256::digest(&raw.bytes).into(),
        }
    }

    fn valid_for(self, bytes: &[u8]) -> bool {
        self.revision != 0 && self.sha256 == <[u8; 32]>::from(Sha256::digest(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourceState {
    profile: RecoveryProfile,
    stores: SourceStores,
    preparation: Option<Mark>,
    decisions: Vec<SignedSourceDecision>,
}

impl SourceState {
    fn decision(&self, origin: OriginKey) -> Result<&SignedSourceDecision, usize> {
        self.decisions
            .binary_search_by_key(&origin, origin_of)
            .map(|index| &self.decisions[index])
    }

    fn appended(
        mut self,
        preparation: Mark,
        decision: SignedSourceDecision,
    ) -> Result<Self, HeadError> {
        let index = self.decision(origin_of(&decision)).err().ok_or(HeadError)?;
        self.preparation = Some(preparation);
        self.decisions.insert(index, decision);
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SelectedSource {
    state: SourceState,
    journal: Mark,
}

impl SelectedSource {
    fn matches(&self, raw: &ControlValue, state: &SourceState) -> bool {
        self.journal == Mark::of(raw) && self.state == *state
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum WitnessSelection {
    Initializing {
        state: SourceState,
        empty_journal: Mark,
    },
    Selected(SelectedSource),
    Appending {
        before: SelectedSource,
        decision: SignedSourceDecision,
    },
    Repairing {
        selected: SelectedSource,
        observed_journal: Mark,
    },
}

/// Trusted source writer. Both stores require their own write credentials.
pub struct SourceJournal {
    stores: SourceReader,
}

/// Read-only handle for an attester. Each store supplies its own reader
/// credential. An independently selected state is mandatory.
pub struct SourceReader {
    journal: EtcdTransport,
    witness: EtcdTransport,
    profile: RecoveryProfile,
    binding: SourceStores,
    authorities: SourceAuthorities,
}

impl SourceJournal {
    pub fn new(
        journal: EtcdTransport,
        witness: EtcdTransport,
        profile: RecoveryProfile,
        authorities: SourceAuthorities,
    ) -> Result<Self, HeadError> {
        Ok(Self {
            stores: SourceReader::new(journal, witness, profile, authorities)?,
        })
    }

    /// Explicitly initialize two pre-provisioned empty keys. An interrupted
    /// initialization can resume only with the same journal and witness.
    pub fn initialize(&self) -> Result<bool, HeadError> {
        let journal = self.stores.journal.current()?;
        let (observed, selection) = self.stores.selection()?;
        let (reservation, state, empty_journal) = match selection {
            None if journal.bytes.is_empty() => {
                let empty_journal = Mark::of(&journal);
                let state = self.stores.empty();
                self.require_capacity(&state)?;
                let proposed = WitnessSelection::Initializing {
                    state: state.clone(),
                    empty_journal,
                };
                (self.reserve(&observed, &proposed)?, state, empty_journal)
            }
            Some(WitnessSelection::Initializing {
                state,
                empty_journal,
            }) => (observed, state, empty_journal),
            Some(WitnessSelection::Selected(selected)) => {
                let state = self.stores.decode_state(&journal.bytes)?;
                return selected
                    .matches(&journal, &state)
                    .then_some(false)
                    .ok_or(HeadError);
            }
            _ => return Err(HeadError),
        };
        let prepared = self.prepare(empty_journal, &state)?;
        self.publish(&reservation, state, prepared)
    }

    /// Confirm one exact signed addition. If any write response is ambiguous,
    /// only the exact current independent selection can acknowledge success.
    pub fn record(&self, decision: &SignedSourceDecision) -> Result<bool, HeadError> {
        if !self.stores.valid_decision(decision) {
            return Err(HeadError);
        }
        self.append(decision).or_else(|_| {
            if self.stores.decision(origin_of(decision))? == *decision {
                Ok(false)
            } else {
                Err(HeadError)
            }
        })
    }

    fn append(&self, decision: &SignedSourceDecision) -> Result<bool, HeadError> {
        let (reserved, before) = self.reserve_append(decision)?;
        let state = before
            .state
            .appended(Mark::of(&reserved), decision.clone())?;
        let prepared = self.prepare(before.journal, &state)?;
        self.publish(&reserved, state, prepared)
    }

    fn reserve_append(
        &self,
        decision: &SignedSourceDecision,
    ) -> Result<(ControlValue, SelectedSource), HeadError> {
        let journal = self.stores.journal.current()?;
        let (observed, selection) = self.stores.selection()?;
        match selection {
            Some(WitnessSelection::Selected(before)) => {
                let state = self.stores.decode_state(&journal.bytes)?;
                if !before.matches(&journal, &state) || state.decision(origin_of(decision)).is_ok()
                {
                    return Err(HeadError);
                }
                let bounded = before
                    .state
                    .clone()
                    .appended(Mark::ENCODING_BOUND, decision.clone())?;
                self.require_capacity(&bounded)?;
                let proposed = WitnessSelection::Appending {
                    before: before.clone(),
                    decision: decision.clone(),
                };
                Ok((self.reserve(&observed, &proposed)?, before))
            }
            Some(WitnessSelection::Appending {
                before,
                decision: reserved,
            }) if reserved == *decision => Ok((observed, before)),
            _ => Err(HeadError),
        }
    }

    /// Restore exactly the independently selected decision list with the
    /// trusted two-store writer. An unresolved addition remains reserved.
    pub fn repair_selected(&self) -> Result<bool, HeadError> {
        let journal = self.stores.journal.current()?;
        let (observed, selection) = self.stores.selection()?;
        let (reservation, selected, observed_journal) = match selection {
            Some(WitnessSelection::Selected(selected)) => {
                if selected.journal == Mark::of(&journal) {
                    return Ok(false);
                }
                let observed_journal = Mark::of(&journal);
                let proposed = WitnessSelection::Repairing {
                    selected: selected.clone(),
                    observed_journal,
                };
                (
                    self.reserve(&observed, &proposed)?,
                    selected,
                    observed_journal,
                )
            }
            Some(WitnessSelection::Repairing {
                selected,
                observed_journal,
            }) => (observed, selected, observed_journal),
            _ => return Err(HeadError),
        };
        let prepared = self.prepare(observed_journal, &selected.state)?;
        self.publish(&reservation, selected.state, prepared)
    }

    // A source reservation must fit its later journal write, independent
    // selection and same-state repair before it can exclude other additions.
    fn require_capacity(&self, state: &SourceState) -> Result<(), HeadError> {
        let selected = SelectedSource {
            state: state.clone(),
            journal: Mark::ENCODING_BOUND,
        };
        let repaired = WitnessSelection::Repairing {
            selected: selected.clone(),
            observed_journal: Mark::ENCODING_BOUND,
        };
        if !self
            .stores
            .journal
            .supports_source_value(encode(state)?.len())
            || !self
                .stores
                .witness
                .supports_source_value(encode(&WitnessSelection::Selected(selected))?.len())
            || !self
                .stores
                .witness
                .supports_source_value(encode(&repaired)?.len())
        {
            return Err(HeadError);
        }
        Ok(())
    }

    fn reserve(
        &self,
        observed: &ControlValue,
        proposed: &WitnessSelection,
    ) -> Result<ControlValue, HeadError> {
        let bytes = encode(proposed)?;
        let _ = self.stores.witness.replace(observed, &bytes);
        let current = self.stores.witness.current()?;
        (current.bytes == bytes).then_some(current).ok_or(HeadError)
    }

    fn prepare(&self, expected: Mark, state: &SourceState) -> Result<ControlValue, HeadError> {
        let bytes = encode(state)?;
        let observed = self.stores.journal.current()?;
        if observed.bytes == bytes {
            return Ok(observed);
        }
        if expected != Mark::of(&observed) {
            return Err(HeadError);
        }
        let _ = self.stores.journal.replace(&observed, &bytes);
        let current = self.stores.journal.current()?;
        (current.bytes == bytes).then_some(current).ok_or(HeadError)
    }

    fn publish(
        &self,
        reservation: &ControlValue,
        state: SourceState,
        prepared: ControlValue,
    ) -> Result<bool, HeadError> {
        let selected = SelectedSource {
            state,
            journal: Mark::of(&prepared),
        };
        let published = self.stores.witness.replace(
            reservation,
            &encode(&WitnessSelection::Selected(selected.clone()))?,
        );
        let journal = self.stores.journal.current()?;
        let state = self.stores.decode_state(&journal.bytes)?;
        if self.stores.confirm_selected(&journal, &state)? != selected {
            return Err(HeadError);
        }
        Ok(published == Ok(true))
    }
}

impl SourceReader {
    pub fn new(
        journal: EtcdTransport,
        witness: EtcdTransport,
        profile: RecoveryProfile,
        authorities: SourceAuthorities,
    ) -> Result<Self, HeadError> {
        if !journal.distinct_source_stores(&witness)
            || authorities.is_empty()
            || !valid_authorities(&authorities, &BTreeSet::new())
        {
            return Err(HeadError);
        }
        let binding = SourceStores {
            journal: journal.source_store_binding(),
            witness: witness.source_store_binding(),
            authorities: Sha256::digest(encode(&authorities)?).into(),
        };
        Ok(Self {
            journal,
            witness,
            profile,
            binding,
            authorities,
        })
    }

    fn decision(&self, origin: OriginKey) -> Result<SignedSourceDecision, HeadError> {
        let journal = self.journal.current()?;
        let state = self.decode_state(&journal.bytes)?;
        self.confirm_selected(&journal, &state)?;
        state.decision(origin).cloned().map_err(|_| HeadError)
    }

    fn confirm_selected(
        &self,
        journal: &ControlValue,
        state: &SourceState,
    ) -> Result<SelectedSource, HeadError> {
        let (_, Some(WitnessSelection::Selected(selected))) = self.selection()? else {
            return Err(HeadError);
        };
        selected
            .matches(journal, state)
            .then_some(selected)
            .ok_or(HeadError)
    }

    fn empty(&self) -> SourceState {
        SourceState {
            profile: self.profile,
            stores: self.binding,
            preparation: None,
            decisions: Vec::new(),
        }
    }

    fn decode_state(&self, bytes: &[u8]) -> Result<SourceState, HeadError> {
        let state: SourceState = canonical(bytes)?;
        self.valid_state(&state).then_some(state).ok_or(HeadError)
    }

    fn valid_state(&self, state: &SourceState) -> bool {
        state.profile == self.profile
            && state.stores == self.binding
            && state.decisions.is_empty() == state.preparation.is_none()
            && state.preparation.is_none_or(|mark| mark.revision != 0)
            && state
                .decisions
                .windows(2)
                .all(|pair| origin_of(&pair[0]) < origin_of(&pair[1]))
            && state
                .decisions
                .iter()
                .all(|decision| self.valid_decision(decision))
    }

    fn selection(&self) -> Result<(ControlValue, Option<WitnessSelection>), HeadError> {
        let raw = self.witness.current()?;
        if raw.bytes.is_empty() {
            return Ok((raw, None));
        }
        let selection = canonical(&raw.bytes)?;
        let valid_selected = |selected: &SelectedSource| {
            self.valid_state(&selected.state)
                && encode(&selected.state).is_ok_and(|bytes| selected.journal.valid_for(&bytes))
        };
        let valid = match &selection {
            WitnessSelection::Initializing {
                state,
                empty_journal,
            } => *state == self.empty() && empty_journal.valid_for(&[]),
            WitnessSelection::Selected(selected) => valid_selected(selected),
            WitnessSelection::Repairing {
                selected,
                observed_journal,
            } => valid_selected(selected) && observed_journal.revision != 0,
            WitnessSelection::Appending { before, decision } => {
                valid_selected(before)
                    && self.valid_decision(decision)
                    && before.state.decision(origin_of(decision)).is_err()
            }
        };
        valid.then_some((raw, Some(selection))).ok_or(HeadError)
    }

    fn valid_decision(&self, decision: &SignedSourceDecision) -> bool {
        decision.statement.profile == self.profile
            && decision.statement.evidence.binding.amount > 0
            && rule_for(&self.authorities, &decision.statement).is_some_and(|rule| {
                decision
                    .statement
                    .record_signing_bytes()
                    .is_ok_and(|message| verify_strict(&rule.issuer, &message, &decision.signature))
            })
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, HeadError> {
    serde_json::to_vec(value).map_err(|_| HeadError)
}

fn origin_of(decision: &SignedSourceDecision) -> OriginKey {
    decision.statement.evidence.binding.origin
}

fn canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, HeadError> {
    let value = serde_json::from_slice(bytes).map_err(|_| HeadError)?;
    if encode(&value)? != bytes {
        return Err(HeadError);
    }
    Ok(value)
}

/// Held by one registered source attester. The only signing entry consumes
/// the authoritative journal and an origin identifier.
pub struct SourceSigner {
    id: u64,
    key: SigningKey,
}

impl SourceSigner {
    pub fn new(id: u64, key: SigningKey) -> Self {
        Self { id, key }
    }

    pub fn issue(
        &self,
        journal: &SourceReader,
        origin: OriginKey,
    ) -> Result<(SourceStatement, SourceVote), WireError> {
        let decision = journal.decision(origin).map_err(|_| INVALID)?;
        let rule = rule_for(&journal.authorities, &decision.statement).ok_or(INVALID)?;
        if rule.signers.get(&self.id) != Some(&self.key.verifying_key().to_bytes()) {
            return Err(INVALID);
        }
        let signature = self
            .key
            .sign(&decision.statement.quorum_signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok((
            decision.statement,
            SourceVote {
                signer: self.id,
                signature,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::recovery::vector_tests::{DEFAULT_PROFILE, binding};
    use crate::lock_finality::TerminalKind;

    #[test]
    fn terminal_quorum_rejects_zero_duplicate_key_and_wrong_origin_epoch() {
        let root = SigningKey::from_bytes(&[20; 32]);
        let a = SigningKey::from_bytes(&[21; 32]);
        let b = SigningKey::from_bytes(&[22; 32]);
        let authority = SourceAuthority {
            issuer: root.verifying_key().to_bytes(),
            quorum: 2,
            signers: BTreeMap::from([
                (1, a.verifying_key().to_bytes()),
                (2, b.verifying_key().to_bytes()),
            ]),
        };
        let statement = SourceStatement {
            profile: DEFAULT_PROFILE,
            origin_epoch: 8,
            evidence: TerminalEvidence {
                binding: binding(),
                kind: TerminalKind::Confirmed,
                reference: 41,
            },
        };
        let message = statement.quorum_signing_bytes().unwrap();
        let certificate = SourceCertificate {
            statement,
            votes: vec![
                SourceVote {
                    signer: 1,
                    signature: a.sign(&message).to_bytes().to_vec(),
                },
                SourceVote {
                    signer: 2,
                    signature: b.sign(&message).to_bytes().to_vec(),
                },
            ],
        };
        let bytes = certificate.canonical_bytes().unwrap();
        let mut rules =
            BTreeMap::from([(0, BTreeMap::from([(8, authority.clone()), (9, authority)]))]);
        assert!(verify_certificate(&rules, statement, &bytes));
        assert!(!verify_certificate(
            &rules,
            SourceStatement {
                origin_epoch: 9,
                ..statement
            },
            &bytes
        ));
        let active = rules.get_mut(&0).unwrap().get_mut(&8).unwrap();
        active.quorum = 0;
        assert!(!verify_certificate(&rules, statement, &bytes));
        let active = rules.get_mut(&0).unwrap().get_mut(&8).unwrap();
        active.quorum = 2;
        active.signers.insert(2, a.verifying_key().to_bytes());
        assert!(!valid_authorities(&rules, &BTreeSet::new()));
        assert!(!verify_certificate(&rules, statement, &bytes));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod freshness_tests;
