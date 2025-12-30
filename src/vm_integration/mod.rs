//! VM Integration Module
//!
//! This module bridges the ZKIR VM execution with the prover's witness generation.
//! It converts VM execution results into the witness format required by the prover.
//!
//! The module uses the RAP (Randomized AIR with Preprocessing) pattern:
//! - `vm_result_to_main_witness()` - Converts VM result to main witness (execution data only)
//! - Auxiliary columns are computed later using the Fiat-Shamir challenge
//!
//! # High-Level API
//!
//! The simplest way to prove a ZKIR program:
//!
//! ```ignore
//! use zkir_prover::vm_integration::prove_test;
//! use zkir_spec::Program;
//!
//! let program = Program::new();
//! let inputs = vec![42];
//!
//! let (proof, vk) = prove_test(&program, &inputs).unwrap();
//! ```
//!
//! For more control, use the `VMProver` struct:
//!
//! ```ignore
//! use zkir_prover::vm_integration::VMProver;
//!
//! let prover = VMProver::default_config();
//! let (proof, vk) = prover.prove_program(&program, &inputs).unwrap();
//! let verified = prover.verify(&proof, &vk).unwrap();
//! ```

mod converter;
mod prover;

pub use converter::VMWitnessConverter;
pub use prover::{VMProver, prove, prove_test, verify};

use crate::backend::r#trait::ProofResult;
use crate::witness::MainWitness;

/// Convert VM execution result to main witness (RAP pattern)
///
/// This is the **recommended** conversion function for production use.
/// It produces a `MainWitness` containing only execution data (no auxiliary columns).
/// Auxiliary columns are computed separately using the Fiat-Shamir challenge
/// derived from the committed main trace.
///
/// Use with `backend.prove_rap()` for cryptographically secure proofs.
///
/// # Example
///
/// ```ignore
/// use zkir_runtime::{VM, VMConfig};
/// use zkir_spec::Program;
/// use zkir_prover::vm_integration::vm_result_to_main_witness;
/// use zkir_prover::backend::plonky3::Plonky3Backend;
///
/// // Run VM
/// let program = Program::new();
/// let inputs = vec![42, 100];
/// let mut config = VMConfig::default();
/// config.enable_execution_trace = true;
///
/// let vm = VM::new(program.clone(), inputs.clone(), config);
/// let result = vm.run().unwrap();
///
/// // Convert to main witness (RAP pattern)
/// let main_witness = vm_result_to_main_witness(&program, &inputs, result).unwrap();
///
/// // Prove with RAP (proper Fiat-Shamir)
/// let backend = Plonky3Backend::default_config();
/// let proof = backend.prove_rap(&main_witness).unwrap();
/// ```
pub fn vm_result_to_main_witness(
    program: &zkir_spec::Program,
    inputs: &[u64],
    result: zkir_runtime::ExecutionResult,
) -> ProofResult<MainWitness> {
    let converter = VMWitnessConverter::new(program, inputs);
    converter.convert_to_main_witness(result)
}

/// Alias for `vm_result_to_main_witness` for backward compatibility
///
/// This is the same as `vm_result_to_main_witness`. The name "witness" refers
/// to the main witness in the RAP (Randomized AIR with Preprocessing) pattern.
pub fn vm_result_to_witness(
    program: &zkir_spec::Program,
    inputs: &[u64],
    result: zkir_runtime::ExecutionResult,
) -> ProofResult<MainWitness> {
    vm_result_to_main_witness(program, inputs, result)
}
