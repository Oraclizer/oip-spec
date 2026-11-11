//! Test-only observations of actual consumers; never supplies a decision.
use super::*;
use serde_json::{Value, json};
use std::cell::RefCell;
thread_local! { static TRACE: RefCell<Option<Vec<Value>>> = const { RefCell::new(None) }; }
pub(crate) fn begin() { TRACE.with(|t| *t.borrow_mut() = Some(Vec::new())); }
pub(crate) fn take() -> Vec<Value> { TRACE.with(|t| t.borrow_mut().take().unwrap_or_default()) }
pub(crate) fn record(stage: &str, packet: &CanonicalPacket, rosters: &[ThresholdRoster], result: &Result<()>) {
    TRACE.with(|t| {
        if let Some(trace) = &mut *t.borrow_mut() {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            trace.push(json!({"stage":stage,"packet_hex":packet.encode().ok().map(|b|hex(&b)),
                "preimage_hex":packet.signing_bytes().ok().map(|b|hex(&b)),
                "selected_roster":select(rosters,packet.core()),"result_debug":format!("{result:?}")}));
        }
    });
}
