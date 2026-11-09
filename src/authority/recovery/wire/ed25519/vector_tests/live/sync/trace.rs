use super::*;
use crate::authority::recovery::exact_image;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn selected(service: &mut Service) -> Value {
    let head = service.anchor.current().unwrap().unwrap();
    let record = exact_image(&mut service.file, head).unwrap();
    let primary = &record.image.authority.primary;
    json!({
        "cut": primary.ledger.current_cut(),
        "entry": primary.sync.entries.get(&STREAM),
        "selected_sequence": head.sequence,
        "selected_digest": hex(&head.digest),
    })
}

fn source_evidence(core: &Core) -> Option<Value> {
    let Operands::SyncCommitment {
        source_attestation: proof,
        ..
    } = decode(core, 1).ok()?
    else {
        return None;
    };
    let mut evidence = json!({"proof_hex": hex(&proof)});
    if let Ok(decoded) = source_attestation::decode(&proof) {
        let statement = decoded.statement;
        let rules = authorities();
        let rule = &rules[&statement.origin_domain][&statement.origin_epoch][&statement.roster_id];
        let votes: Vec<_> = decoded.signatures.iter().map(|vote| {
            let key = rule.signers[&vote.signer_id];
            json!({
                "signer_id": vote.signer_id,
                "public_key_hex": hex(&key),
                "preimage_hex": hex(decoded.signed_bytes),
                "signature_hex": hex(&vote.signature),
                "strict_ed25519_verified": verify_strict(&key, decoded.signed_bytes, &vote.signature),
            })
        }).collect();
        evidence["verification_facts"] = json!(votes);
    }
    Some(evidence)
}

pub(super) struct Trace {
    directory: Option<PathBuf>,
    context: Value,
    inputs: Vec<Value>,
    observed: Vec<Value>,
}

impl Trace {
    pub(super) fn new(service: &Service, channel: &Channel) -> Self {
        Self {
            directory: std::env::var_os("OIP_SYNC_PRODUCT_TRACE_DIR").map(PathBuf::from),
            context: json!({
                "specification_version": "0.6.1",
                "receiver_policy": service.security.config,
                "source_registrations": authorities(),
                "active_sessions": initial().sessions,
                "channel": {
                    "deployment": channel.deployment(),
                    "local": channel.local(),
                    "remote": channel.remote(),
                    "expires": channel.expires(),
                    "wire_version": channel.profile().version,
                    "families": channel.profile().families,
                    "atomicities": channel.profile().atomicities,
                    "schemes": channel.profile().schemes,
                    "public_keys": channel.peer_keys().iter().map(|key| hex(key)).collect::<Vec<_>>(),
                },
            }),
            inputs: Vec::new(),
            observed: Vec::new(),
        }
    }

    pub(super) fn input(
        &mut self,
        service: &mut Service,
        case: &str,
        bytes: &[u8],
        client: &SessionToken,
    ) {
        if self.directory.is_none() {
            return;
        }
        let packet = decode_packet(bytes, bytes.len()).unwrap();
        let before = selected(service);
        self.inputs.push(json!({
            "case": case,
            "packet_hex": hex(bytes),
            "canonical_core_hex": hex(packet.core_bytes()),
            "envelope_preimage_hex": hex(&packet.signing_bytes().unwrap()),
            "source_evidence": source_evidence(packet.core()),
            "session_claims": client.claims,
            "session_token_signature_hex": hex(&client.signature),
            "clock_seconds": service.security.clock.unix_seconds().unwrap(),
            "source_connected": service.source_connected,
            "delivery": {"response_lost": case == "response-lost", "cancelled": false, "deadline": null},
            "before": before,
        }));
    }

    pub(super) fn observed(&mut self, service: &mut Service, case: &str, actual: Value) {
        if self.directory.is_some() {
            self.observed
                .push(json!({"case": case, "actual": actual, "after": selected(service)}));
        }
    }

    pub(super) fn write(self) {
        let Some(directory) = self.directory else {
            return;
        };
        for (name, value) in [
            (
                "sync-live-inputs.json",
                json!({"context": self.context, "cases": self.inputs}),
            ),
            ("sync-live-observations.json", json!(self.observed)),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .unwrap();
            serde_json::to_writer_pretty(&mut file, &value).unwrap();
            file.write_all(b"\n").unwrap();
            file.sync_all().unwrap();
        }
    }
}
