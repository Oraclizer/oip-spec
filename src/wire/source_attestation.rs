//! Exact source attestation statements and proof framing for SyncCommitment.

const DOMAIN: &[u8] = b"OIP\0SOURCE-ATTESTATION\0";
const FORMAT_VERSION: u64 = 1;
const CLAIM_KIND: u64 = 1;
const SIGNATURE_RECORD_LEN: usize = 8 + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSourceAttestation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStatement {
    pub deployment: u64,
    pub origin_domain: u64,
    pub origin_epoch: u64,
    pub roster_id: u64,
    pub asset: u64,
    pub origin_event: u64,
    pub source_position: u64,
    pub commitment: [u8; 32],
    pub predecessor: Option<[u8; 32]>,
}

impl SourceStatement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        for word in [
            FORMAT_VERSION,
            CLAIM_KIND,
            self.deployment,
            self.origin_domain,
            self.origin_epoch,
            self.roster_id,
            self.asset,
            self.origin_event,
            self.source_position,
        ] {
            bytes.extend(word.to_be_bytes());
        }
        bytes.extend(self.commitment);
        bytes.push(u8::from(self.predecessor.is_some()));
        if let Some(predecessor) = self.predecessor {
            bytes.extend(predecessor);
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSignature {
    pub signer_id: u64,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAttestation<'a> {
    pub statement: SourceStatement,
    pub signed_bytes: &'a [u8],
    pub signatures: Vec<SourceSignature>,
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], InvalidSourceAttestation> {
    let (value, tail) = input.split_first_chunk().ok_or(InvalidSourceAttestation)?;
    *input = tail;
    Ok(*value)
}

fn word(input: &mut &[u8]) -> Result<u64, InvalidSourceAttestation> {
    Ok(u64::from_be_bytes(take(input)?))
}

fn take_statement(input: &mut &[u8]) -> Result<SourceStatement, InvalidSourceAttestation> {
    *input = input.strip_prefix(DOMAIN).ok_or(InvalidSourceAttestation)?;
    if word(input)? != FORMAT_VERSION || word(input)? != CLAIM_KIND {
        return Err(InvalidSourceAttestation);
    }
    Ok(SourceStatement {
        deployment: word(input)?,
        origin_domain: word(input)?,
        origin_epoch: word(input)?,
        roster_id: word(input)?,
        asset: word(input)?,
        origin_event: word(input)?,
        source_position: word(input)?,
        commitment: take(input)?,
        predecessor: match take::<1>(input)?[0] {
            0 => None,
            1 => Some(take(input)?),
            _ => return Err(InvalidSourceAttestation),
        },
    })
}

pub fn decode_statement(mut bytes: &[u8]) -> Result<SourceStatement, InvalidSourceAttestation> {
    let statement = take_statement(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(InvalidSourceAttestation);
    }
    Ok(statement)
}

fn check_signer_order(signatures: &[SourceSignature]) -> Result<(), InvalidSourceAttestation> {
    if signatures
        .windows(2)
        .any(|pair| pair[0].signer_id >= pair[1].signer_id)
    {
        return Err(InvalidSourceAttestation);
    }
    Ok(())
}

/// Parse the exact signed statement and ordered signature list. The caller checks
/// the roster, quorum, signatures and binding to the request.
pub fn decode(bytes: &[u8]) -> Result<SourceAttestation<'_>, InvalidSourceAttestation> {
    let mut tail = bytes;
    let statement = take_statement(&mut tail)?;
    let signed_bytes = &bytes[..bytes.len() - tail.len()];
    let count = usize::try_from(word(&mut tail)?).map_err(|_| InvalidSourceAttestation)?;
    if count.checked_mul(SIGNATURE_RECORD_LEN) != Some(tail.len()) {
        return Err(InvalidSourceAttestation);
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(SourceSignature {
            signer_id: word(&mut tail)?,
            signature: take(&mut tail)?,
        });
    }
    check_signer_order(&signatures)?;
    Ok(SourceAttestation {
        statement,
        signed_bytes,
        signatures,
    })
}

pub fn encode(
    statement: &SourceStatement,
    signatures: &[SourceSignature],
) -> Result<Vec<u8>, InvalidSourceAttestation> {
    check_signer_order(signatures)?;
    let mut bytes = statement.signing_bytes();
    let count = u64::try_from(signatures.len()).map_err(|_| InvalidSourceAttestation)?;
    bytes.extend(count.to_be_bytes());
    for signature in signatures {
        bytes.extend(signature.signer_id.to_be_bytes());
        bytes.extend(signature.signature);
    }
    Ok(bytes)
}
