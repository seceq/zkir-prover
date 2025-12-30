//! Plonky3 backend implementation
//!
//! This module implements the STARK proof backend using Plonky3, a high-performance
//! STARK framework developed by Polygon Zero.

pub mod config;
pub mod air;
pub mod pcs;
pub mod prover;
pub mod verifier;
pub mod backend_impl;

pub use config::StarkConfiguration;
pub use air::{ZkIrAirAdapter, main_witness_to_trace, aux_witness_to_trace};
pub use prover::Plonky3Prover;
pub use verifier::Plonky3Verifier;
pub use backend_impl::Plonky3Backend;
