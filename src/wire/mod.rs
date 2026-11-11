//! OIP wire codecs and authority admission.

pub mod codec;
pub mod generated;

pub mod admission;
pub mod legacy;
pub mod negotiation;
pub mod operands;
pub mod source_attestation;
pub mod threshold;

#[cfg(test)]
mod interop_tests;
#[cfg(test)]
mod sync_structure_tests;
