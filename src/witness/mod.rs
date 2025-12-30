//! Witness generation for ZKIR v3.4
//!
//! This module handles collection of execution traces and auxiliary data
//! needed for proof generation.
//!
//! ## RAP Pattern Support
//!
//! The witness generation now supports the RAP (Randomized AIR with Preprocessing)
//! pattern for proper Fiat-Shamir security:
//!
//! - `MainWitness`: Execution data without auxiliary columns
//! - `AuxWitness`: Auxiliary columns (LogUp sums, permutation products)
//! - `compute_auxiliary()`: Computes auxiliary with real Fiat-Shamir challenge

pub mod trace;
pub mod collector;
pub mod verify;
pub mod multiplicity;
pub mod table_sums;
pub mod auxiliary;

// Core trace exports
pub use trace::{
    MemoryOp, RangeCheckWitness, CryptoWitness, PublicIO,
    ProgramConfig, ValueBound, CryptoType,
    MainWitness, MainTraceRow, MainWitnessBuilder,
};
pub use auxiliary::{AuxWitness, compute_auxiliary, compute_auxiliary_with_challenges};

// Other exports
pub use collector::{WitnessCollector, TraceCollector};
pub use verify::verify_witness;
pub use multiplicity::{LogUpMultiplicities, MultiplicityTracker, encode_bitwise_triple, decode_bitwise_triple};
pub use table_sums::{TableSums, compute_table_sum};
