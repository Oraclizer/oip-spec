use ed25519_dalek::{Signer, SigningKey};
use oip_spec::wire::{
    codec::{encode_core, encode_packet, signing_bytes},
    generated::{Core, Operation, Packet, core::Body},
    legacy::{LegacyCore, LegacyPacket, hex},
};

const UUID: [u8; 16] = [0, 1, 2, 3, 4, 5, 64, 7, 128, 9, 10, 11, 12, 13, 14, 15];

fn core(target: u64, family: u64, tag: u8, body: Body) -> Core {
    let mut uuid = UUID;
    uuid[0] = tag;
    Core {
        version: Some(6),
        purpose: Some(1),
        deployment: Some(7),
        source_domain: Some(0),
        target_domain: Some(target),
        principal: Some(7),
        key_id: Some(9),
        authority_epoch: Some(9),
        issued_seconds: Some(100),
        ttl_seconds: Some(5),
        uuid: Some(uuid.to_vec()),
        family: Some(family),
        primary: Some(1),
        secondary: Some(77),
        signature_scheme: Some(1),
        atomicity: Some(3),
        priority: Some(3),
        route_scope: Some(1),
        body: Some(body),
    }
}

fn sign(key: &SigningKey, core: Core) -> Vec<u8> {
    let preimage = signing_bytes(&encode_core(&core).unwrap()).unwrap();
    let signature = key.sign(&preimage).to_bytes().to_vec();
    encode_packet(&Packet {
        core: Some(core),
        signature: Some(signature),
    })
    .unwrap()
}

fn legacy(key: &SigningKey, family: u64, opcode: u64, tag: u8, words: Vec<u64>) -> Vec<u8> {
    let mut uuid = UUID;
    uuid[0] = tag;
    let core = LegacyCore {
        version: 5,
        deployment: 7,
        source: 0,
        target: 2,
        principal: 7,
        key: 9,
        epoch: 9,
        sent: 100,
        ttl: 5,
        uuid: hex(&uuid),
        family,
        opcode,
        words,
        atomicity: 3,
        scope: 1,
    };
    let signature = key.sign(&core.signing_bytes().unwrap());
    LegacyPacket {
        core,
        signature: hex(&signature.to_bytes()),
    }
    .encode()
    .unwrap()
}

fn main() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let query = core(
        2,
        4,
        0,
        Body::Query(Operation {
            opcode: Some(1),
            words: vec![1, 0, 1, 17],
            blobs: vec![],
            appeal_deadline: None,
        }),
    );
    let mut amount = vec![0; 32];
    amount[31] = 5;
    let debit = core(
        0,
        1,
        2,
        Body::StateSync(Operation {
            opcode: Some(1),
            words: vec![
                33, 33, 2, 2, 9, 0, 17, 17, 7, 2, 3, 1, 17, 0, 17, 7, 0, 9, 1, 17, 0, 0,
            ],
            blobs: vec![amount],
            appeal_deadline: None,
        }),
    );
    let original = encode_core(&debit).unwrap();
    let receipt = core(
        0,
        4,
        3,
        Body::Query(Operation {
            opcode: Some(8),
            words: vec![2],
            blobs: vec![original],
            appeal_deadline: None,
        }),
    );
    println!(
        "query={}\ndebit={}\nreceipt={}\nlegacy_query={}\nlegacy_heartbeat={}",
        hex(&sign(&key, query)),
        hex(&sign(&key, debit)),
        hex(&sign(&key, receipt)),
        hex(&legacy(&key, 4, 1, 5, vec![1, 0, 1, 17])),
        hex(&legacy(&key, 6, 2, 7, vec![3, 190]))
    );
}
