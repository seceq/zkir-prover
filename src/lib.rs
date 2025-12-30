//! ZK IR Prover v3.4
//!
//! STARK prover for ZK IR v3.4 using Plonky3 with Mersenne 31 field.
//!
//! # Architecture
//!
//! The prover uses a multi-chip design:
//! - CPU Chip: Executes ZKIR v3.4 instructions with variable limb arithmetic
//! - Memory Chip: Enforces memory consistency with timestamp ordering
//! - Range Check Chip: Validates limb values using chunk decomposition
//! - Syscall Chips: Dedicated chips for cryptographic operations
//!
//! # ZKIR v3.4 Features
//!
//! - **Variable limb architecture**: Configurable 16-30 bit limbs (default: 20-bit)
//! - **40-bit values**: Default configuration uses 2×20-bit limbs
//! - **47 instructions**: Complete RISC-style instruction set
//! - **Bound tracking**: Optimizes constraint generation by tracking value bounds
//! - **Adaptive crypto**: Cryptographic syscalls use adaptive internal representation
//! - **Deferred range checking**: Leverages headroom for batched range checks
//!
//! # Implementation Status
//!
//! - Phase 1: Witness Generation (Core - Complete, VM Integration - Pending)
//! - Phase 2: Constraint System (Framework - In Progress)
//! - Phase 3: Proof Backend (Not Started)
//! - Phase 4: Optimization (Not Started)
//! - Phase 5: GPU Acceleration (Not Started)
//! - Phase 6: Advanced Features (Not Started)
//!
//! # Type System
//!
//! Types are imported from `zkir-spec` as the single source of truth.
//! Use `zkir_prover::types::*` for access to all shared types.
//!
//! # Legacy Code
//!
//! The v2.1 implementation (32-bit only) has been moved to `src_backup/` for reference.

pub mod types;
pub mod columns;
pub mod witness;
pub mod constraints;
pub mod backend;
pub mod vm_integration;

// Re-export main witness types for convenience
pub use witness::{
    MemoryOp, WitnessCollector,
    ProgramConfig, ValueBound, CryptoType, CryptoWitness,
    RangeCheckWitness, PublicIO, TraceCollector,
    verify_witness,
    MainWitness, MainTraceRow, MainWitnessBuilder,
};

// Re-export key types from types module
pub use types::{
    Config, Opcode, InstructionFamily,
    NUM_REGISTERS, MERSENNE31_PRIME,
};

// Re-export high-level API from vm_integration
pub use vm_integration::{VMProver, prove, prove_test, verify};

use p3_mersenne_31::Mersenne31;

/// The field type used throughout the prover (Mersenne 31: p = 2^31 - 1)
pub type F = Mersenne31;

// Default configuration values (for backward compatibility)
// New code should use types::Config::DEFAULT

/// Default limb size in bits
pub const DEFAULT_LIMB_BITS: u8 = 20;

/// Default number of data limbs
pub const DEFAULT_DATA_LIMBS: u8 = 2;

/// Default number of address limbs
pub const DEFAULT_ADDR_LIMBS: u8 = 2;
