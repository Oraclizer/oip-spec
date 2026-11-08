#[cfg(creusot)]
use creusot_std::prelude::*;

#[cfg_attr(creusot, ensures(match result {
    Some(end) => end@ == offset@ + length@,
    None => offset@ + length@ > u64::MAX@,
}))]
pub fn checked_end(offset: u64, length: u64) -> Option<u64> {
    offset.checked_add(length)
}

/// The same half-open span relation is used for file and predecessor bounds.
#[cfg_attr(creusot, ensures(result == (offset@ + length@ <= upper@)))]
pub fn ends_by(offset: u64, length: u64, upper: u64) -> bool {
    match checked_end(offset, length) {
        Some(end) => end <= upper,
        None => false,
    }
}

#[cfg_attr(creusot, ensures(result == (
    same_profile && parent_sequence@ + 1 == sequence@
        && parent_offset@ + parent_length@ <= offset@
)))]
pub fn valid_predecessor(
    same_profile: bool,
    parent_sequence: u64,
    parent_offset: u64,
    parent_length: u64,
    sequence: u64,
    offset: u64,
) -> bool {
    same_profile
        && parent_sequence.checked_add(1) == Some(sequence)
        && ends_by(parent_offset, parent_length, offset)
}
