use super::*;
use crate::authority::recovery::wire::vector_tests::{
    channel, core_with, debit_core, operation, raw_frame, signed, uint256,
};
use prost::Message;
use std::collections::BTreeMap;

const CASES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/response-code-cases.tsv"
));
const OBSERVATIONS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/response-code-observations.tsv"
));

fn original(family: u64, opcode: u64, namespace: u64, sequence: u64) -> Core {
    let prefix = [33, sequence, 2, 2, 9, 0, 17, 17, 7, 0, 3];
    let mut core = match (family, opcode) {
        (1, 1) => {
            let mut core = debit_core(2);
            operation(&mut core).words[1] = sequence;
            core
        }
        (1, 6) => core_with(
            family,
            opcode,
            0,
            3,
            [prefix.as_slice(), &[1, 7, 3, 0]].concat(),
            vec![uint256(5), uint256(1)],
        ),
        (2, 2) => core_with(
            family,
            opcode,
            0,
            4,
            [prefix.as_slice(), &[1, 7, 1, 1, 9, 0, 0, 0]].concat(),
            vec![uint256(5), vec![1]],
        ),
        (1, 7) => core_with(
            family,
            opcode,
            0,
            5,
            vec![50, sequence, 2, 0, 9, 0, 17, 17, 1, 1],
            vec![vec![1; 32], vec![], source_attestation()],
        ),
        _ => panic!("unexpected original family {family}, opcode {opcode}"),
    };
    core.principal = Some(namespace);
    core
}

fn source_attestation() -> Vec<u8> {
    let mut bytes = b"OIP\0SOURCE-ATTESTATION\0".to_vec();
    for word in [1u64, 1, 7, 0, 9, 1, 17, 17, 1] {
        bytes.extend(word.to_be_bytes());
    }
    bytes.extend([1; 32]);
    bytes.push(0);
    bytes.extend(1u64.to_be_bytes());
    bytes.extend(7u64.to_be_bytes());
    bytes.extend([0; 64]);
    bytes
}

fn original_bytes(core: &Core) -> Vec<u8> {
    if let Ok(bytes) = encode_core(core) {
        return bytes;
    }
    // Preserve the exact SyncCommitment layout when the original opcode is
    // outside the canonical codec's supported operation set.
    let mut placeholder = core.clone();
    let op = operation(&mut placeholder);
    assert_eq!(op.opcode.replace(1), Some(7));
    let needle = op.encode_to_vec();
    let mut bytes = encode_core(&placeholder).unwrap();
    let start = bytes
        .windows(needle.len())
        .position(|candidate| candidate == needle)
        .unwrap();
    assert_eq!(bytes[start..start + 2], [8, 1]);
    bytes[start + 1] = 7;
    bytes
}

fn status_fields(status: Result<ResponseStatus, WireError>) -> [u64; 3] {
    match status {
        Ok(ResponseStatus::Known(code)) => [1, code.descriptor().0, code as u64],
        Ok(ResponseStatus::Unknown { kind, code }) => [2, kind as u64, code],
        Err(WireError::InvalidFormat) => [0, 0, 0],
        other => panic!("unexpected response status {other:?}"),
    }
}

#[test]
fn response_code_extension_vectors_follow_the_status_and_client_paths() {
    let observations = OBSERVATIONS
        .lines()
        .map(|line| line.split_once('\t').unwrap())
        .collect::<BTreeMap<_, _>>();
    let channel = channel(0);
    let params = ResponseParameters {
        principal: 42,
        key_id: 3,
        authority_epoch: 9,
        issued_seconds: 100,
        ttl_seconds: 10,
        uuid: [0, 0, 0, 0, 0, 0, 64, 0, 128, 0, 0, 0, 0, 0, 0, 0],
        route_scope: 1,
    };
    let boundary = Boundary {
        deployment: 7,
        source: 0,
        target: 0,
        principal: params.principal,
        key_id: params.key_id,
        epoch: params.authority_epoch,
        route_scope: params.route_scope,
        now: 105,
        asset_ttl_floor: 2,
        future_skew: 0,
        max_frame: 1024 * 1024,
        max_nesting: 4,
        version_floor: 6,
        critical_allowed: false,
        public_key: channel.peer_keys()[1],
    };
    for line in CASES.lines().filter(|line| line.starts_with("R\t")) {
        let columns = line.split('\t').collect::<Vec<_>>();
        let id = columns[1];
        let family = columns[2].parse().unwrap();
        let opcode = columns[3].parse().unwrap();
        let fields = observations[id]
            .split(',')
            .map(|field| field.parse::<u64>().unwrap())
            .collect::<Vec<_>>();
        let Ok(words) = columns[4]
            .split(',')
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
        else {
            // A value above u64 cannot occupy a fixed-width wire word.
            assert_eq!(fields, [0], "{id}");
            println!("response-code\t{id}\t0");
            continue;
        };
        let core = original(family, opcode, words[0], words[1]);
        let original = original_bytes(&core);
        let request = raw_frame(&original);
        let expected = decode_packet(&request, boundary.max_frame);
        let response = signed(response_core(
            &channel,
            &params,
            3,
            words.clone(),
            &original,
        ));
        let decoded = expected
            .as_ref()
            .ok()
            .map(|packet| decode(packet.core(), 1).unwrap());
        let structurally_valid = matches!(
            words.as_slice(),
            [_, _, 1..=3, _, 0] | [_, _, 1..=3, _, 1, _]
        );
        let (shape, compatible) = if structurally_valid {
            assert_eq!(
                &fields[..6],
                &[1, words[0], words[1], words[2], words[3], words[4]],
                "{id}"
            );
            assert_eq!(fields[6], words.get(5).copied().unwrap_or(0), "{id}");
            let status = ResponseStatus::decode(words[2], words[3], words[4] == 1);
            let compatible = match status {
                Ok(ResponseStatus::Known(code)) => match &decoded {
                    Some(operands) => code.matches_call(operands, &core),
                    None => code.matches_sync_commitment(),
                },
                Ok(ResponseStatus::Unknown { .. }) => true,
                Err(_) => false,
            };
            let shape = status_fields(status);
            assert_eq!(shape, fields[10..13], "{id}");
            assert_eq!(u64::from(compatible), fields[15], "{id}");
            (shape, compatible)
        } else {
            assert_eq!(fields, [0], "{id}");
            ([0; 3], false)
        };

        let packet = decode_packet(&response, boundary.max_frame).unwrap();
        let raw = decode(packet.core(), boundary.max_nesting);
        let accepted = if let Ok(expected) = expected {
            let result = admit_response(&channel, &boundary, &expected, &response);
            assert_eq!(result.is_ok(), compatible, "{id}: {result:?}");
            if let Ok(result) = result {
                assert_eq!(
                    result.id,
                    CallId {
                        namespace: words[0],
                        sequence: words[1]
                    },
                    "{id}"
                );
                assert_eq!(status_fields(Ok(result.code)), shape, "{id}");
                assert_eq!(
                    result.commit.map(|commit| commit.position as u64),
                    words.get(5).copied(),
                    "{id}"
                );
            } else {
                assert_eq!(result, Err(BAD), "{id}");
            }
            result.is_ok()
        } else {
            assert_eq!((family, opcode), (1, 7), "{id}");
            assert_eq!(expected.err(), Some(BAD), "{id}");
            assert!(matches!(raw, Err(WireError::InvalidFormat)), "{id}");
            false
        };
        println!(
            "response-code\t{id}\t{},{},{}\t{}\t{}\t{}\t{}\t{:x}",
            shape[0],
            shape[1],
            shape[2],
            u8::from(compatible),
            u8::from(decoded.is_some()),
            u8::from(accepted),
            u8::from(raw.is_ok()),
            Sha256::digest(packet.core_bytes()),
        );
    }
}
