//! Deterministic test signatures for the operation conformance corpus.
use ed25519_dalek::{Signer, SigningKey};
use oip_spec::wire::codec::signing_bytes;
use serde_json::{Value, json};
use std::io::{self, BufRead};

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
fn varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn main() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for line in io::stdin().lock().lines() {
        let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let core = unhex(row["core_hex"].as_str().unwrap());
        let mut signature = key.sign(&signing_bytes(&core).unwrap()).to_bytes().to_vec();
        let mode = row["signature_mode"].as_str().unwrap_or("valid");
        match mode {
            "valid" => (),
            "invalid" => signature[63] ^= 1,
            "short" => {
                signature.pop();
            }
            "small-order" => {
                signature.fill(0);
                signature[0] = 1;
            }
            "noncanonical-point" => {
                signature[..32].fill(255);
                signature[32..].fill(0);
            }
            _ => panic!("unknown signature mode"),
        }
        let mut packet = vec![10];
        varint(core.len(), &mut packet);
        packet.extend(&core);
        packet.push(18);
        varint(signature.len(), &mut packet);
        packet.extend(signature);
        println!(
            "{}",
            json!({"id": row["id"], "packet_hex": hex(&packet),
            "public_key": hex(&key.verifying_key().to_bytes()), "signature_valid": mode == "valid"})
        );
    }
}
