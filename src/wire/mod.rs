//! OIP wire codecs and authority admission.

pub mod codec;
pub mod generated;

pub mod admission;
pub mod legacy;
pub mod negotiation;
pub mod operands;

#[cfg(test)]
mod interop_tests;
