//! Exercise the real transport receiver against generated fixed and random cases.
use super::*;
use serde_json::{Value, json};
#[path = "typed_value_tests.rs"]
mod typed_values;

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}
fn number(row: &Value, name: &str) -> u64 {
    row[name].as_u64().unwrap()
}
fn list(row: &Value, name: &str) -> Vec<u64> {
    row[name]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_u64().unwrap())
        .collect()
}
fn error_number(error: WireError) -> u64 {
    match error {
        WireError::InvalidFormat => 70,
        WireError::UnsupportedVersion => 71,
        WireError::InvalidSource => 72,
        WireError::InvalidSignature => 73,
        WireError::InvalidThresholdSignature => 74,
        WireError::TtlInvalid => 75,
        WireError::ReplayConflict => 76,
        WireError::ProductRejected => 77,
        WireError::TtlExpired => 54,
        other => panic!("unexpected transport error: {other:?}"),
    }
}
fn evaluate(row: &Value) -> Value {
    assert_eq!(row["schema"].as_u64(), Some(1));
    assert_eq!(row["layer"].as_str(), Some("transport"));
    assert_eq!(row["threshold_supported"].as_bool(), Some(false));
    let p = &row["profile"];
    let profile = Profile {
        version: number(p, "version"),
        families: list(p, "families").into_iter().collect(),
        atomicities: list(p, "atomicities").into_iter().collect(),
        schemes: list(p, "schemes").into_iter().collect(),
    };
    let b = &row["boundary"];
    let boundary = Boundary {
        deployment: number(b, "deployment"),
        source: number(b, "source"),
        target: number(b, "target"),
        principal: number(b, "principal"),
        key_id: number(b, "key_id"),
        epoch: number(b, "epoch"),
        route_scope: number(b, "route_scope"),
        now: number(b, "now"),
        asset_ttl_floor: number(b, "asset_ttl_floor"),
        future_skew: number(b, "future_skew"),
        max_frame: number(b, "max_frame") as usize,
        max_nesting: number(b, "max_nesting") as usize,
        version_floor: number(b, "version_floor"),
        critical_allowed: b["critical_allowed"].as_bool().unwrap(),
        public_key: unhex(b["public_key"].as_str().unwrap()).try_into().unwrap(),
    };
    let packet = unhex(row["packet_hex"].as_str().unwrap());
    let mut store = TransportBindings::default();
    // A retained core is the value already stored for this packet's exact key.
    // Inserting it here avoids re-admitting historical bytes under today's clock.
    let key = decode_packet(&packet, usize::MAX)
        .ok()
        .and_then(|p| TransportKey::for_core(p.core()).ok());
    if let (Some(key), Some(prior)) = (key, row["prior_binding"].as_str()) {
        store.0.insert(key, unhex(prior));
    }
    let before = store.0.clone();
    let attest = row["attestation_valid"].as_bool().unwrap();
    let result = store.receive(&packet, &profile, &boundary, |_| attest);
    let mut core_bytes=None;
    let mut signing_preimage=None;
    let mut transport_key=None;
    let mut operand_value=None;
    let verdict = match result {
        Ok((arrival, received)) => {
            let typed=crate::wire::operands::decode(received.core(),boundary.max_nesting).expect("same actual decoder on accepted returned Core");
            core_bytes=Some(hex(&crate::wire::codec::encode_core(received.core()).expect("source reencoding")));
            signing_preimage=Some(hex(&received.signing_bytes().expect("source signing bytes")));
            transport_key=Some(typed_values::decimal(typed_values::key_ir(key.expect("accepted source key"))));
            operand_value=Some(typed_values::decimal(typed_values::operand_ir(received.core(),&typed,boundary.max_nesting)));
            match arrival {Arrival::First=>json!("accept:first"),Arrival::Identical=>json!("accept:identical")}
        },
        Err(error) => {
            assert_eq!(
                store.0, before,
                "{}: refusal changed retained state",
                row["id"]
            );
            json!(error_number(error))
        }
    };
    let retained = key
        .and_then(|key| store.0.get(&key))
        .map(|bytes| hex(bytes));
    json!({"id":row["id"],"verdict":verdict,"retained_binding":retained,"reencoded_core_hex":core_bytes,
        "signing_preimage_hex":signing_preimage,"transport_key_ir":transport_key,"typed_operand_ir":operand_value})
}

#[test]
fn operation_vectors_follow_the_real_transport_receiver() {
    let data = std::env::var_os("OIP_WIRE_OPERATIONS_INPUT")
        .map(|path| std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|| include_str!("../../tests/vectors/wire-operations.jsonl").into());
    let mut outputs = String::new();
    let mut rows = 0;
    for line in data.lines().filter(|line| !line.is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        let got = evaluate(&row);
        if let Some(expected) = row.get("expected") {
            assert_eq!(&got["verdict"], &expected["verdict"], "{}", row["id"]);
            assert_eq!(
                &got["retained_binding"], &expected["retained_binding"],
                "{}",
                row["id"]
            );
        }
        outputs.push_str(&got.to_string());
        outputs.push('\n');
        rows += 1;
    }
    assert!(rows >= 31, "operation corpus is missing");
    if let Some(path) = std::env::var_os("OIP_WIRE_OPERATIONS_OUTPUT") {
        std::fs::write(path, outputs).unwrap();
    }
}
