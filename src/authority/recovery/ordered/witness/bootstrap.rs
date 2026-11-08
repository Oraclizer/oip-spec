//! Explicit signed provisioning from an independently retained genesis image.

use super::*;
use crate::authority::identity::{Bootstrap, ProductAuthority, Security};
use crate::authority::recovery::{
    CommitRecord, LockedFile, RetainedImage, append_record, encode as encode_record,
    validate_retained_transition,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WitnessGenesis {
    profile: RecoveryProfile,
    authority: [u8; 32],
    witness: [u8; 32],
    authority_empty: Mark,
    witness_empty: Mark,
    archive: ArchiveRef,
    writer: WitnessWriter,
    connected: bool,
}

impl WitnessGenesis {
    pub fn authorization_message(&self) -> Result<Vec<u8>, HeadError> {
        let mut bytes = b"oip/independent-genesis/v1\0".to_vec();
        bytes.extend(encode(self)?);
        Ok(bytes)
    }
}

impl<A: WitnessAttachmentVerifier> WitnessHead<A> {
    /// Prepare an exact genesis without exposing an authority head. The two
    /// configured keys must have been provisioned as empty by the operator.
    pub fn prepare_genesis<S: Security>(
        &self,
        journal: &mut File,
        initial: Bootstrap,
        security: S,
        connected: bool,
        proof: &A::Proof,
    ) -> Result<WitnessGenesis, RecoveryError> {
        let store = &self.ordered.store;
        if !store.verify_attachment(store.profile, connected, proof) {
            return Err(RecoveryError::AttachmentRejected);
        }
        let authority = store.authority.current().map_err(hold)?;
        let witness = store.witness.current().map_err(hold)?;
        if !authority.bytes.is_empty() || !witness.bytes.is_empty() {
            return Err(RecoveryError::AlreadyInitialized);
        }
        let product = ProductAuthority::bootstrap(initial, security)
            .ok_or(RecoveryError::InvalidBootstrap)?;
        let record = CommitRecord {
            profile: store.profile,
            sequence: 0,
            previous: None,
            image: RetainedImage::capture(&product),
        };
        if !record.image.accepts_security(product.security.as_ref()) {
            return Err(RecoveryError::InvalidBootstrap);
        }
        validate_retained_transition(&record, None)?;
        let bytes = encode_record(&record)?;
        let expected = AnchorHead {
            profile: store.profile,
            sequence: 0,
            offset: 0,
            length: u64::try_from(bytes.len()).map_err(|_| RecoveryError::InvalidImage)?,
            digest: Sha256::digest(&bytes).into(),
        };
        let locked = LockedFile::acquire(journal)?;
        let length = locked.0.metadata().map_err(|_| RecoveryError::Io)?.len();
        if length == 0 {
            let written = append_record(locked.0, &record, File::sync_all)?;
            if written != expected {
                return Err(RecoveryError::Hold);
            }
        } else if length != expected.length || exact_image(locked.0, expected)? != record {
            return Err(RecoveryError::AlreadyInitialized);
        }
        let archive = store.archive.retain(locked.0, expected)?;
        Ok(WitnessGenesis {
            profile: store.profile,
            authority: store.authority.attachment_binding(),
            witness: store.witness.attachment_binding(),
            authority_empty: Mark::of(&authority),
            witness_empty: Mark::of(&witness),
            archive,
            writer: store.writer,
            connected,
        })
    }

    /// Select one exact prepared genesis. A repeated signature for the
    /// already selected genesis confirms that selection without another write.
    pub fn provision_genesis(
        &self,
        cut: &WitnessGenesis,
        proof: &A::Proof,
        signature: &[u8],
    ) -> Result<(), RecoveryError> {
        let store = &self.ordered.store;
        if cut.profile != store.profile
            || cut.authority != store.authority.attachment_binding()
            || cut.witness != store.witness.attachment_binding()
            || cut.writer != store.writer
            || cut.archive.head.sequence != 0
            || !store.verify_attachment(store.profile, cut.connected, proof)
            || !store.attachment.verify_genesis(cut, proof, signature)
        {
            return Err(RecoveryError::AttachmentRejected);
        }
        store.archive.open_verified(cut.archive)?;
        let authorization: [u8; 32] =
            Sha256::digest(cut.authorization_message().map_err(hold)?).into();
        let mut nonce = Sha256::new();
        nonce.update(b"oip/witness-genesis-nonce/v1\0");
        nonce.update(authorization);
        let control = OrderedHead::<WitnessStore<A>>::initial_value(
            store.profile,
            Some(cut.archive.head),
            cut.writer.generation,
        )
        .map_err(hold)?;
        let selected = Selection {
            profile: store.profile,
            authority: cut.authority,
            witness: cut.witness,
            control,
            archive: cut.archive,
            floor: cut.archive.head,
            writer: cut.writer,
            previous: Some(cut.witness_empty),
            repair_nonce: nonce.finalize().into(),
            authorization: Some(authorization),
        };
        let bytes = encode(&selected).map_err(hold)?;
        let current = store.witness.current().map_err(hold)?;
        if current.bytes == bytes {
            return store.read_witness().map(|_| ()).map_err(hold);
        }
        if !current.bytes.is_empty() || Mark::of(&current) != cut.witness_empty {
            return Err(RecoveryError::AlreadyInitialized);
        }
        let authority = store.authority.current().map_err(hold)?;
        let prepare = AuthorityPrepare {
            profile: store.profile,
            base: cut.witness_empty,
            preparations: vec![bytes.clone()],
        };
        store
            .install_exact_prepare(&authority, cut.authority_empty, &prepare)
            .map_err(hold)?;
        let _ = store.witness.replace(&current, &bytes);
        if store.read_witness().map_err(hold)?.raw.bytes != bytes {
            return Err(RecoveryError::Hold);
        }
        Ok(())
    }
}
