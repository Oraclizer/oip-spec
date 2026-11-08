//! Cross-language decode corpus.
//!
//! The corpus holds one valid Core for each operation of version 6 and
//! deterministic mutations of it: changed, dropped and added operand words,
//! changed blobs and nested originals, appeal deadlines, target domains,
//! principals and raw bytes, alone or two and three at a time. This test
//! regenerates every mutation from its valid Core and checks the reference
//! verdict of every row. The Go tests check the same rows, so both decoders
//! return the same verdict, including which error a frame with several
//! defects receives.
//!
//! Set OIP_WRITE_DECODE_CORPUS=1 to rewrite the corpus after a deliberate
//! change to the valid Cores or to the mutation rules.

use super::codec::{WireError, decode_core, encode_core};
use super::generated::{Core, Operation, core::Body, operation::AppealDeadline};
use super::operands::decode;
use std::fmt::Write as _;

const CORPUS: &str = include_str!("../../tests/interop/wire-decode-mutations.tsv");
const HEADER: &str = "id\tnesting\tcore\texpect";
const MUTANTS: usize = 24;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// The error names that the Go decoder reports.
fn name(error: WireError) -> String {
    match error {
        WireError::InvalidFormat => "INVALID_FORMAT".into(),
        WireError::UnsupportedVersion => "UNSUPPORTED_VERSION".into(),
        WireError::InvalidSource => "INVALID_SOURCE".into(),
        WireError::InvalidSignature => "INVALID_SIGNATURE".into(),
        WireError::InvalidThresholdSignature => "INVALID_THRESHOLD_SIGNATURE".into(),
        WireError::TtlExpired => "TTL_EXPIRED".into(),
        WireError::TtlInvalid => "TTL_INVALID".into(),
        WireError::ReplayConflict => "REPLAY_CONFLICT".into(),
        other => format!("{other:?}"),
    }
}

fn verdict(core: &[u8], nesting: usize) -> String {
    match decode_core(core).and_then(|core| decode(&core, nesting).map(|_| ())) {
        Ok(()) => "OK".into(),
        Err(error) => name(error),
    }
}

/// SplitMix64, so that the mutations are fixed by the corpus alone.
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }
}

fn operation(core: &mut Core) -> &mut Operation {
    match core.body.as_mut().unwrap() {
        Body::StateSync(op)
        | Body::RegulatoryAction(op)
        | Body::LockManagement(op)
        | Body::Query(op)
        | Body::Ack(op)
        | Body::Heartbeat(op)
        | Body::Governance(op) => op,
    }
}

fn mutate_words(words: &mut Vec<u64>, mix: &mut Mix) {
    let at = mix.below(words.len() + 1);
    match mix.below(3) {
        0 if !words.is_empty() => {
            let at = at.min(words.len() - 1);
            let values = [0, 1, 2, 3, 5, 7, 9, 17, 33, u64::MAX, words[at].wrapping_add(1), words[at].wrapping_sub(1)];
            words[at] = values[mix.below(values.len())];
        }
        1 if !words.is_empty() => {
            words.remove(at.min(words.len() - 1));
        }
        _ => words.insert(at, [0, 1, 2, 7, 17][mix.below(5)]),
    }
}

/// One structural change. The result may violate the operand rules but must
/// stay a canonical Core, so that the change reaches the operand decoder.
fn mutate(core: &mut Core, mix: &mut Mix) {
    match mix.below(8) {
        0..=2 => mutate_words(&mut operation(core).words, mix),
        3 => core.target_domain = Some([0, 1, 2, 3][mix.below(4)]),
        4 => core.principal = Some([7, 8][mix.below(2)]),
        5 => {
            operation(core).appeal_deadline = match mix.below(3) {
                0 => None,
                1 => Some(AppealDeadline::AppealDeadlineIndefinite(true)),
                _ => Some(AppealDeadline::AppealDeadlineUtcSeconds(5)),
            }
        }
        _ => {
            let blobs = &mut operation(core).blobs;
            if blobs.is_empty() || mix.below(6) == 0 {
                blobs.push(vec![1]);
                return;
            }
            let at = mix.below(blobs.len());
            match mix.below(5) {
                0 => blobs[at].clear(),
                1 => {
                    blobs[at].pop();
                }
                2 => {
                    blobs.remove(at);
                }
                _ => {
                    // A change inside a nested original when the blob holds one.
                    if let Ok(mut nested) = decode_core(&blobs[at]) {
                        mutate(&mut nested, mix);
                        if let Ok(bytes) = encode_core(&nested) {
                            blobs[at] = bytes;
                            return;
                        }
                    }
                    let index = mix.below(blobs[at].len());
                    if let Some(byte) = blobs[at].get_mut(index) {
                        *byte ^= 1 << mix.below(8);
                    }
                }
            }
        }
    }
}

fn mutants(base: &[u8], seed: u64) -> Vec<Vec<u8>> {
    let mut mix = Mix(seed);
    let original = decode_core(base).unwrap();
    let mut out = Vec::new();
    while out.len() < MUTANTS {
        let bytes = if out.len() % 8 == 7 {
            // Raw byte changes reach the canonical decoder itself.
            let mut bytes = base.to_vec();
            let at = mix.below(bytes.len());
            bytes[at] ^= 1 << mix.below(8);
            bytes
        } else {
            let mut core = original.clone();
            for _ in 0..1 + mix.below(3) {
                mutate(&mut core, &mut mix);
            }
            match encode_core(&core) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            }
        };
        if bytes != base && !out.contains(&bytes) {
            out.push(bytes);
        }
    }
    out
}

struct Row<'a> {
    id: &'a str,
    nesting: usize,
    core: Vec<u8>,
    expect: &'a str,
}

fn rows(text: &str) -> Vec<Row<'_>> {
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(HEADER));
    lines
        .map(|line| {
            let [id, nesting, core, expect] = line.split('\t').collect::<Vec<_>>()[..] else {
                panic!("corpus row {line}");
            };
            Row { id, nesting: nesting.parse().unwrap(), core: unhex(core), expect }
        })
        .collect()
}

fn render(bases: &[Row<'_>]) -> String {
    let mut out = format!("{HEADER}\n");
    for (index, base) in bases.iter().enumerate() {
        let operation = base.id.strip_suffix("/valid").unwrap();
        let seed = u64::try_from(index).unwrap() + 1;
        writeln!(out, "{}\t{}\t{}\t{}", base.id, base.nesting, hex(&base.core), verdict(&base.core, base.nesting)).unwrap();
        for (number, bytes) in mutants(&base.core, seed).iter().enumerate() {
            writeln!(out, "{operation}/mutant-{number:02}\t{}\t{}\t{}", base.nesting, hex(bytes), verdict(bytes, base.nesting)).unwrap();
        }
    }
    out
}

#[test]
fn reference_decode_corpus_is_reproducible_and_holds_its_verdicts() {
    let rows = rows(CORPUS);
    let bases: Vec<_> = rows.into_iter().filter(|row| row.id.ends_with("/valid")).collect();
    assert_eq!(bases.len(), 31);
    assert!(bases.iter().all(|base| base.expect == "OK"), "every valid Core decodes");
    let rendered = render(&bases);
    if std::env::var_os("OIP_WRITE_DECODE_CORPUS").is_some() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/wire-decode-mutations.tsv");
        std::fs::write(path, &rendered).unwrap();
        return;
    }
    assert_eq!(rendered, CORPUS.replace("\r\n", "\n"));
    let counts = rendered.lines().skip(1).fold(std::collections::BTreeMap::new(), |mut counts, line| {
        *counts.entry(line.rsplit('\t').next().unwrap().to_string()).or_insert(0) += 1;
        counts
    });
    // The corpus must reach the operand decoder, not only the canonical one.
    assert!(counts.get("INVALID_SOURCE").copied().unwrap_or(0) > 0, "{counts:?}");
    assert!(counts.get("OK").copied().unwrap_or(0) > 31, "{counts:?}");
}
