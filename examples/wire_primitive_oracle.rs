//! Deterministic test-only primitive provider for model-issued exact requests.
//! No observed source response, digest, UUID or signature is an answer supplier.
use ed25519_dalek::{Signer,SigningKey,Signature,VerifyingKey};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::io::{self,BufRead,Write};
fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn canonical_point(point:&[u8])->bool {
    let Ok(mut y)=<[u8;32]>::try_from(point) else {return false};
    y[31]&=127;let mut prime=[255u8;32];prime[0]=237;prime[31]=127;
    y.iter().rev().cmp(prime.iter().rev()).is_lt()
}
fn octets(value:&Value)->Vec<u8> {
    let text=value.as_str().expect("hex primitive field");
    assert!(text.len()%2==0 && text.len()<=2*1024*1024 && text.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    text.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()
}
fn main() {
    let stdin=io::stdin();let mut stdout=io::stdout().lock();
    for line in stdin.lock().lines() {
        let request:Value=serde_json::from_str(&line.unwrap()).unwrap();
        assert_eq!(request["schema"],"oip-wire-primitive-request-v1");
        let answer=match request["primitive"].as_str().unwrap() {
            "sha256"=>json!({"digest_hex":hex(&Sha256::digest(octets(&request["preimage_hex"])))}),
            "ed25519-sign"=>{
                let seed=u8::try_from(request["test_seed_byte"].as_u64().unwrap()).unwrap();
                assert!([6,7,8,10].contains(&seed),"Only declared public fixture keys are available");
                let key=SigningKey::from_bytes(&[seed;32]);
                assert_eq!(hex(&key.verifying_key().to_bytes()),request["public_key_hex"].as_str().unwrap());
                json!({"signature_hex":hex(&key.sign(&octets(&request["preimage_hex"])).to_bytes())})
            },
            "ed25519-verify"=>{
                let key:[u8;32]=octets(&request["public_key_hex"]).try_into().unwrap();
                let signature=octets(&request["signature_hex"]);
                // Preserve the source negotiation::verify canonical point checks.
                let valid=canonical_point(&key) && signature.get(..32).is_some_and(canonical_point) &&
                    Signature::from_slice(&signature).is_ok_and(|signature|VerifyingKey::from_bytes(&key).is_ok_and(|key|key.verify_strict(&octets(&request["preimage_hex"]),&signature).is_ok()));
                json!({"valid":valid})
            },
            _=>panic!("Unknown named primitive request"),
        };
        serde_json::to_writer(&mut stdout,&json!({"schema":"oip-wire-primitive-reply-v1","id":request["id"],"request":request,"answer":answer})).unwrap();
        stdout.write_all(b"\n").unwrap();stdout.flush().unwrap();
    }
}
