//! Independent Ed25519 keys for attachment, genesis, and repair.

use super::{
    HeadError, RecoveryProfile, WitnessAttachmentVerifier, WitnessGenesis, WitnessRepair,
    WitnessWriter, encode,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WitnessAttachmentContext {
    pub profile: RecoveryProfile,
    pub authority: [u8; 32],
    pub witness: [u8; 32],
    pub writer: WitnessWriter,
    pub connected: bool,
}

impl WitnessAttachmentContext {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, HeadError> {
        let mut message = b"oip/independent-attachment/v1\0".to_vec();
        message.extend(encode(self)?);
        Ok(message)
    }
}

/// Trusted host attachment issuer. It signs the actual witness head's
/// configured context and has no genesis or repair signing method.
pub struct WitnessAttachmentIssuer(SigningKey);

impl WitnessAttachmentIssuer {
    pub fn new(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn issue(
        &self,
        head: &super::WitnessHead<Ed25519WitnessAuthority>,
        connected: bool,
    ) -> Result<[u8; 64], HeadError> {
        if self.0.verifying_key() != head.ordered.store.attachment.attachment {
            return Err(HeadError);
        }
        let message = head.attachment_context(connected).signing_bytes()?;
        Ok(self.0.sign(&message).to_bytes())
    }
}

pub struct Ed25519WitnessAuthority {
    attachment: VerifyingKey,
    genesis: VerifyingKey,
    repair: VerifyingKey,
}

impl Ed25519WitnessAuthority {
    pub fn new(
        attachment: [u8; 32],
        genesis: [u8; 32],
        repair: [u8; 32],
    ) -> Result<Self, HeadError> {
        if attachment == genesis || attachment == repair || genesis == repair {
            return Err(HeadError);
        }
        Ok(Self {
            attachment: key(&attachment)?,
            genesis: key(&genesis)?,
            repair: key(&repair)?,
        })
    }
}

impl WitnessAttachmentVerifier for Ed25519WitnessAuthority {
    type Proof = [u8; 64];

    fn verify_attachment(
        &self,
        profile: RecoveryProfile,
        authority: [u8; 32],
        witness: [u8; 32],
        writer: WitnessWriter,
        connected: bool,
        proof: &Self::Proof,
    ) -> bool {
        let context = WitnessAttachmentContext {
            profile,
            authority,
            witness,
            writer,
            connected,
        };
        verified(&self.attachment, context.signing_bytes(), proof)
    }

    fn verify_genesis(&self, cut: &WitnessGenesis, _: &Self::Proof, signature: &[u8]) -> bool {
        verified(&self.genesis, cut.authorization_message(), signature)
    }

    fn verify_repair(&self, cut: &WitnessRepair, _: &Self::Proof, signature: &[u8]) -> bool {
        verified(&self.repair, cut.authorization_message(), signature)
    }
}

fn key(raw: &[u8; 32]) -> Result<VerifyingKey, HeadError> {
    let key = VerifyingKey::from_bytes(raw).map_err(|_| HeadError)?;
    if key.is_weak() {
        return Err(HeadError);
    }
    Ok(key)
}

fn verified(key: &VerifyingKey, bytes: Result<Vec<u8>, HeadError>, signature: &[u8]) -> bool {
    bytes
        .ok()
        .zip(Signature::from_slice(signature).ok())
        .is_some_and(|(bytes, signature)| key.verify_strict(&bytes, &signature).is_ok())
}
