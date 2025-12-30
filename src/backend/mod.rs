//! Proof backend abstraction and implementations
//!
//! This module provides a clean interface for proof generation and verification,
//! along with concrete implementations using different STARK backends.

pub mod proof;
pub mod r#trait;
pub mod plonky3;

pub use proof::{Proof, VerifyingKey};
pub use r#trait::ProverBackend;
