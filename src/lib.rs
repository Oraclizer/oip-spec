//! Reference implementation of the OIP product boundary.
//!
//! The crate root is an in-memory model of the common product boundary. Its
//! caller identity, envelope verification and snapshot provenance come from
//! trusted adapters, and its state change models one commit under exclusive
//! access. The [wire] module holds the canonical wire codec and admission
//! gate, and the [authority] module holds the persistent authority, its
//! recovery journal and the reference Ed25519 configuration.

// Wire revisions, commit positions and counts are 64-bit integers that the
// reference decodes into usize. A narrower target would refuse large values
// that a 64-bit target accepts, so the reference builds only for 64-bit
// targets and keeps one verdict for every frame.
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "oip-spec requires a 64-bit target: wire revisions, commit positions and counts decode into usize"
);

use std::collections::BTreeMap;

pub mod authority;
pub mod interleaving;
pub mod lock_finality;
pub mod wire;

pub type Principal = u64;
pub type AssetId = u64;
pub type SessionId = u64;

/// Identity already authenticated by the entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedCaller(pub Principal);

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct CallId {
    pub namespace: Principal,
    pub sequence: u64,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct OriginKey {
    pub domain: u64,
    pub event: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitCut {
    pub authority_epoch: u64,
    pub revision: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionBinding {
    pub principal: Principal,
    pub authority_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockToken {
    pub asset: AssetId,
    pub owner: Principal,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveLock {
    pub holder: Principal,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asset {
    pub owner: Principal,
    pub active_lock: Option<ActiveLock>,
    pub credits: u64,
}

impl Asset {
    fn lock_token(&self, asset: AssetId) -> Option<LockToken> {
        self.active_lock.map(|lock| LockToken {
            asset,
            owner: lock.holder,
            generation: lock.generation,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credit {
    pub caller: Principal,
    pub amount: u64,
    pub lock: Option<LockToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub message_id: u64,
    pub origin: OriginKey,
    pub asset: AssetId,
    pub caller: Principal,
    pub session: SessionId,
    pub cut: CommitCut,
    pub command: Credit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receipt {
    Executed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    Dispatched,
    Rejected,
    Waiting,
    Completed(Receipt),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CallRecord {
    envelope: Envelope,
    outcome: Option<Receipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableSnapshot {
    authority_epoch: u64,
    sessions: BTreeMap<SessionId, SessionBinding>,
    assets: BTreeMap<AssetId, Asset>,
    calls: BTreeMap<CallId, CallRecord>,
    authority_log: Vec<CallId>,
    completions: BTreeMap<CallId, Receipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Up,
    Down,
}

/// Common product boundary fixture. Its credits do not belong to the
/// authoritative transfer ledger in [lock_finality].
pub struct Product {
    durable: DurableSnapshot,
    endpoint: Endpoint,
    connected: bool,
    response_cache: BTreeMap<CallId, Receipt>,
}

impl Product {
    #[cfg(test)]
    pub(crate) fn new(
        authority_epoch: u64,
        sessions: BTreeMap<SessionId, SessionBinding>,
        assets: BTreeMap<AssetId, Asset>,
    ) -> Self {
        Self {
            durable: DurableSnapshot {
                authority_epoch,
                sessions,
                assets,
                calls: BTreeMap::new(),
                authority_log: Vec::new(),
                completions: BTreeMap::new(),
            },
            endpoint: Endpoint::Up,
            connected: true,
            response_cache: BTreeMap::new(),
        }
    }

    pub fn current_cut(&self) -> CommitCut {
        CommitCut {
            authority_epoch: self.durable.authority_epoch,
            revision: self.durable.authority_log.len(),
        }
    }

    pub fn snapshot(&self) -> DurableSnapshot {
        self.durable.clone()
    }

    pub fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub fn set_authority_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    pub fn crash(&mut self) {
        self.response_cache.clear();
        self.endpoint = Endpoint::Down;
    }

    /// Re-enable a crashed endpoint after its adapter supplies a checked
    /// snapshot. Compare the full durable image, including recorded outcomes.
    pub fn restart(&mut self, checked_snapshot: Option<&DurableSnapshot>) {
        if self.endpoint == Endpoint::Down
            && self.connected
            && checked_snapshot == Some(&self.durable)
        {
            self.endpoint = Endpoint::Up;
        }
    }

    pub fn credits(&self, asset: AssetId) -> Option<u64> {
        self.durable.assets.get(&asset).map(|asset| asset.credits)
    }

    pub fn cached_reply(&self, id: CallId) -> Option<Receipt> {
        self.response_cache.get(&id).copied()
    }

    pub fn current_lock_token(&self, token: LockToken) -> bool {
        self.durable
            .assets
            .get(&token.asset)
            .and_then(|asset| asset.lock_token(token.asset))
            == Some(token)
    }

    fn identity_bound(&self, caller: AuthenticatedCaller, id: CallId, envelope: &Envelope) -> bool {
        id.namespace == caller.0
            && envelope.caller == caller.0
            && envelope.command.caller == caller.0
            && self.durable.sessions.get(&envelope.session)
                == Some(&SessionBinding {
                    principal: caller.0,
                    authority_epoch: self.durable.authority_epoch,
                })
    }

    /// Check the complete envelope and call ID at entry. A fresh dispatch checks
    /// the current cut. An exact prior request can only collect its durable result.
    pub fn submit(
        &mut self,
        caller: AuthenticatedCaller,
        id: CallId,
        envelope: Envelope,
        verify: impl FnOnce(AuthenticatedCaller, CallId, &Envelope) -> bool,
    ) -> Submission {
        if !verify(caller, id, &envelope) || !self.identity_bound(caller, id, &envelope) {
            return Submission::Rejected;
        }
        if self.endpoint != Endpoint::Up || !self.connected {
            return Submission::Waiting;
        }
        if let Some(prior) = self.durable.calls.get(&id) {
            if prior.envelope != envelope {
                return Submission::Rejected;
            }
            if let Some(receipt) = prior.outcome {
                self.response_cache.insert(id, receipt);
                self.durable.completions.insert(id, receipt);
                return Submission::Completed(receipt);
            }
            return Submission::Waiting;
        }
        if envelope.cut != self.current_cut() {
            return Submission::Rejected;
        }

        let Some(asset) = self.durable.assets.get_mut(&envelope.asset) else {
            return Submission::Rejected;
        };
        let expected_lock = asset.lock_token(envelope.asset);
        if envelope.command.lock != expected_lock
            || expected_lock.is_some_and(|token| token.owner != caller.0)
        {
            return Submission::Rejected;
        }
        let Some(credits) = asset.credits.checked_add(envelope.command.amount) else {
            return Submission::Rejected;
        };

        // The exclusive borrow keeps effect, outcome and revision in one
        // in-memory transition after all rejecting checks have passed.
        asset.credits = credits;
        self.durable.calls.insert(
            id,
            CallRecord {
                envelope,
                outcome: Some(Receipt::Executed),
            },
        );
        self.durable.authority_log.push(id);
        Submission::Dispatched
    }
}

#[cfg(test)]
mod vector_tests;
