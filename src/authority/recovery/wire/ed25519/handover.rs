//! Consent to a retained transition between exact registered authority policies.

use super::{
    AuthorityClock, Ed25519Profile, Ed25519Security, Handover, INVALID, Identity, Operation, Scope,
    SessionId, authority_policy_binding, preimage, verify_strict,
};
use crate::SessionBinding;
use crate::lock_finality::EndpointContext;
use crate::wire::codec::WireError;
use std::collections::BTreeMap;

pub(super) struct SuccessorPolicy {
    config: Ed25519Profile,
    binding: [u8; 32],
    contexts: Vec<EndpointContext>,
}

impl SuccessorPolicy {
    pub(super) fn epoch(&self) -> u64 {
        self.config.authority_epoch
    }

    pub(super) fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub(super) fn bind_sessions(
        &self,
        sessions: &BTreeMap<SessionId, SessionBinding>,
    ) -> Option<[u8; 32]> {
        // Read-only login and ACK identities may have no native ledger session.
        // Every actual ledger session must have one unambiguous new registration.
        for (&session, binding) in sessions {
            let mut registered = self
                .config
                .peers
                .iter()
                .filter(|(_, peer)| peer.sessions.contains_key(&session))
                .map(|(&principal, _)| principal);
            if binding.authority_epoch != self.epoch()
                || registered.next() != Some(binding.principal)
                || registered.next().is_some()
            {
                return None;
            }
        }
        Some(self.binding)
    }
}

impl<C: AuthorityClock> Ed25519Security<C> {
    /// Register a host-approved prospective policy. Its keys and grants never
    /// authenticate ordinary ingress through this current-epoch handle.
    pub fn with_successor(
        mut self,
        config: Ed25519Profile,
        contexts: Vec<EndpointContext>,
        next_signer_ready: &[u8; 64],
    ) -> Result<Self, WireError> {
        let binding = authority_policy_binding(&config)?;
        if config.profile != self.config.profile
            || config.authority_epoch <= self.config.authority_epoch
            || config.sources != self.config.sources
            || contexts.is_empty()
            || contexts
                .iter()
                .any(|context| context.epoch != config.authority_epoch)
            || contexts
                .windows(2)
                .any(|pair| pair[0].endpoint >= pair[1].endpoint)
            || config.peers.iter().any(|(principal, peer)| {
                self.config
                    .peers
                    .get(principal)
                    .map(|current| current.identity)
                    != Some(peer.identity)
            })
        {
            return Err(INVALID);
        }
        let readiness = self.successor_readiness_signing_bytes(&config, &contexts)?;
        if !verify_strict(&config.response_key, &readiness, next_signer_ready) {
            return Err(INVALID);
        }
        self.next = Some(SuccessorPolicy {
            config,
            binding,
            contexts,
        });
        Ok(self)
    }

    /// Signed by the separately prepared next response key before it can
    /// be selected. The current process does not need the next private key.
    pub fn successor_readiness_signing_bytes(
        &self,
        config: &Ed25519Profile,
        contexts: &[EndpointContext],
    ) -> Result<Vec<u8>, WireError> {
        preimage(
            b"oip/reference-successor-ready/v1\0",
            &(
                self.config.profile,
                self.binding,
                authority_policy_binding(config)?,
                contexts,
            ),
        )
    }

    pub(super) fn handover_policy(&self, proposal: &Handover) -> Option<&SuccessorPolicy> {
        let next = self.next.as_ref()?;
        if proposal.expected.authority_epoch != self.config.authority_epoch
            || proposal.epoch != next.epoch()
            || proposal.contexts != next.contexts
            || proposal.previous == proposal.successor
            || !next
                .config
                .peers
                .get(&proposal.successor)?
                .sessions
                .contains_key(&proposal.new_session)
            || next
                .config
                .peers
                .get(&proposal.previous)
                .is_some_and(|peer| peer.sessions.contains_key(&proposal.old_session))
        {
            return None;
        }
        Some(next)
    }

    /// Exact bytes signed independently by each registered participant.
    /// The typed proposal includes its previous cut and all endpoint contexts.
    pub fn handover_consent_signing_bytes(
        &self,
        identity: Identity,
        proposal: &Handover,
    ) -> Result<Vec<u8>, WireError> {
        let next = self.handover_policy(proposal).ok_or(INVALID)?;
        let role = if identity.principal == proposal.previous {
            1_u8
        } else if identity.principal == proposal.successor {
            2_u8
        } else {
            return Err(INVALID);
        };
        if self
            .config
            .peers
            .get(&identity.principal)
            .map(|peer| peer.identity)
            != Some(identity)
        {
            return Err(INVALID);
        }
        preimage(
            b"oip/reference-handover-consent/v1\0",
            &(
                self.config.profile,
                self.binding,
                next.binding,
                role,
                identity,
                proposal,
            ),
        )
    }

    pub(super) fn verify_consent(
        &self,
        identity: Identity,
        proposal: &Handover,
        signature: &[u8],
    ) -> bool {
        let Some(peer) = self.config.peers.get(&identity.principal) else {
            return false;
        };
        if identity.principal == proposal.previous
            && !self.grant(
                identity,
                proposal.old_session,
                identity.domain,
                Operation::TransferOwner,
                Scope::Asset(proposal.asset),
            )
        {
            return false;
        }
        self.handover_consent_signing_bytes(identity, proposal)
            .is_ok_and(|bytes| verify_strict(&peer.public_key, &bytes, signature))
    }
}
