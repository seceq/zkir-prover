//! Constraint system for ZKIR v3.4
//!
//! This module defines the Algebraic Intermediate Representation (AIR) constraints
//! for proving correct execution of ZKIR v3.4 programs.
//!
//! # Architecture
//!
//! The constraint system is organized into several categories:
//! - **Execution constraints**: Verify correct instruction execution
//! - **Memory constraints**: Enforce read-write consistency
//! - **Range check constraints**: Validate limb values via lookup arguments
//! - **Crypto constraints**: Special constraints for cryptographic syscalls
//!
//! # AIR Framework
//!
//! We use Plonky3's AIR framework to define polynomial constraints over trace columns.
//! Each constraint is a polynomial equation that must equal zero for a valid execution.

pub mod air;
pub mod execution;
pub mod memory;
pub mod range_check;
pub mod crypto;
pub mod instruction_decode;
pub mod bitwise;
pub mod logup;
pub mod challenges;
pub mod hierarchical;

pub use air::{ZkIrAir, ConstraintBuilder};
pub use instruction_decode::InstructionDecoder;
pub use bitwise::BitwiseLookupTable;
pub use logup::{LogUpAccumulator, LogUpConstraintBuilder, BitwiseLookupEntry, MultiplicityTracker};
pub use challenges::RapChallenges;
pub use hierarchical::{
    hierarchical_decomposition, decomposition_column_count, decomposition_sizes,
    decompose_value, verify_decomposition, HierarchicalDecomposition, ChunkInfo,
    TABLE_SIZES, table_index_for_bits,
};
