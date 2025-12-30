// ! High-level end-to-end proving API
//!
//! This module provides a convenient API for proving ZKIR programs directly from VM execution.
//! It handles the full pipeline: VM execution → witness conversion → proof generation.

use crate::backend::plonky3::Plonky3Backend;
use crate::backend::proof::{Proof, VerifyingKey};
use crate::backend::r#trait::{ProofError, ProofResult, ProverBackend};
use crate::vm_integration::vm_result_to_main_witness;
use zkir_runtime::{ExecutionResult, VM, VMConfig};
use zkir_spec::Program;

/// High-level prover that integrates VM execution and proof generation
///
/// This provides a convenient API for end-to-end proving:
/// 1. Execute program in VM with witness collection
/// 2. Convert execution result to witness
/// 3. Generate cryptographic proof
///
/// # Example
///
/// ```ignore
/// use zkir_prover::vm_integration::VMProver;
/// use zkir_spec::Program;
///
/// let program = Program::new();
/// let inputs = vec![42, 100];
///
/// let prover = VMProver::default_config();
/// let (proof, vk) = prover.prove_program(&program, &inputs).unwrap();
///
/// // Verify the proof
/// let verified = prover.verify(&proof, &vk).unwrap();
/// assert!(verified);
/// ```
pub struct VMProver {
    backend: Plonky3Backend,
}

impl VMProver {
    /// Create a new VM prover with the given backend
    pub fn new(backend: Plonky3Backend) -> Self {
        Self { backend }
    }

    /// Create a VM prover with default configuration (production settings)
    pub fn default_config() -> Self {
        Self::new(Plonky3Backend::default_config())
    }

    /// Create a VM prover with test configuration (faster, lower security)
    pub fn test_config() -> Self {
        Self::new(Plonky3Backend::test_config())
    }

    /// Create a VM prover with fast test configuration (minimal security, very fast)
    pub fn fast_test_config() -> Self {
        Self::new(Plonky3Backend::fast_test_config())
    }

    /// Prove a program's execution end-to-end
    ///
    /// This is the main entry point for proving ZKIR programs. It:
    /// 1. Executes the program in the VM with witness collection enabled
    /// 2. Converts the execution result to a witness
    /// 3. Generates a cryptographic proof using RAP (proper Fiat-Shamir)
    /// 4. Generates a verifying key for the program
    ///
    /// # Arguments
    ///
    /// * `program` - The ZKIR program to prove
    /// * `inputs` - Input values for the program
    ///
    /// # Returns
    ///
    /// Returns `(proof, verifying_key)` on success
    ///
    /// # Errors
    ///
    /// Returns `ProofError` if:
    /// - VM execution fails
    /// - Witness conversion fails
    /// - Proof generation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let prover = VMProver::default_config();
    /// let (proof, vk) = prover.prove_program(&program, &[42]).unwrap();
    /// ```
    pub fn prove_program(
        &self,
        program: &Program,
        inputs: &[u64],
    ) -> ProofResult<(Proof, VerifyingKey)> {
        // Execute program with witness collection
        let execution_result = self.execute_with_witness(program, inputs)?;

        // Convert to witness
        let main_witness = vm_result_to_main_witness(program, inputs, execution_result)?;

        // Generate proof using RAP pattern (proper Fiat-Shamir)
        // Note: The proof contains the verifying key
        let proof = self.backend.prove(&main_witness)?;

        // Extract verifying key from proof
        let vk = proof.verifying_key.clone();

        Ok((proof, vk))
    }

    /// Execute a program in the VM with witness collection enabled
    ///
    /// This is a convenience method that configures the VM for witness collection
    /// and runs the program.
    ///
    /// # Arguments
    ///
    /// * `program` - The ZKIR program to execute
    /// * `inputs` - Input values for the program
    ///
    /// # Returns
    ///
    /// Returns the execution result with full trace and witness data
    ///
    /// # Errors
    ///
    /// Returns `ProofError` if VM execution fails
    pub fn execute_with_witness(
        &self,
        program: &Program,
        inputs: &[u64],
    ) -> ProofResult<ExecutionResult> {
        // Create VM config with witness collection enabled
        let mut config = VMConfig::default();
        config.enable_execution_trace = true;
        config.enable_range_checking = true;

        // Run VM
        let vm = VM::new(program.clone(), inputs.to_vec(), config);
        vm.run().map_err(|e| {
            ProofError::InvalidWitness(format!("VM execution failed: {}", e))
        })
    }

    /// Verify a proof
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `vk` - The verifying key for the program
    ///
    /// # Returns
    ///
    /// Returns `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, proof: &Proof, vk: &VerifyingKey) -> ProofResult<bool> {
        self.backend.verify(proof, vk).map(|_| true)
    }

    /// Get reference to the underlying backend
    pub fn backend(&self) -> &Plonky3Backend {
        &self.backend
    }
}

/// Execute a program and generate a proof in one call (convenience function)
///
/// This is the simplest way to prove a ZKIR program. It uses default configuration.
///
/// # Example
///
/// ```ignore
/// use zkir_prover::vm_integration::prove;
/// use zkir_spec::Program;
///
/// let program = Program::new();
/// let inputs = vec![42];
///
/// let (proof, vk) = prove(&program, &inputs).unwrap();
/// ```
pub fn prove(program: &Program, inputs: &[u64]) -> ProofResult<(Proof, VerifyingKey)> {
    let prover = VMProver::default_config();
    prover.prove_program(program, inputs)
}

/// Execute a program and generate a proof with test configuration (faster)
///
/// Use this for testing. It's faster but has lower security parameters.
///
/// # Example
///
/// ```ignore
/// use zkir_prover::vm_integration::prove_test;
///
/// let (proof, vk) = prove_test(&program, &inputs).unwrap();
/// ```
pub fn prove_test(program: &Program, inputs: &[u64]) -> ProofResult<(Proof, VerifyingKey)> {
    let prover = VMProver::test_config();
    prover.prove_program(program, inputs)
}

/// Verify a proof (convenience function)
///
/// # Example
///
/// ```ignore
/// use zkir_prover::vm_integration::{prove, verify};
///
/// let (proof, vk) = prove(&program, &inputs).unwrap();
/// assert!(verify(&proof, &vk).unwrap());
/// ```
pub fn verify(proof: &Proof, vk: &VerifyingKey) -> ProofResult<bool> {
    let prover = VMProver::default_config();
    prover.verify(proof, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkir_spec::{Instruction, Register};

    fn create_simple_program() -> Program {
        // Program: R1 = 10, R2 = 20, R3 = R1 + R2, ebreak
        let instructions = vec![
            Instruction::Addi {
                rd: Register::R1,
                rs1: Register::R0,
                imm: 10,
            },
            Instruction::Addi {
                rd: Register::R2,
                rs1: Register::R0,
                imm: 20,
            },
            Instruction::Add {
                rd: Register::R3,
                rs1: Register::R1,
                rs2: Register::R2,
            },
            Instruction::Ebreak,
        ];

        let mut program = Program::new();
        program.code = instructions
            .iter()
            .map(|inst| zkir_assembler::encode(inst))
            .collect();
        program.header.code_size = (program.code.len() * 4) as u32;
        program
    }

    #[test]
    fn test_vm_prover_execution() {
        let program = create_simple_program();
        let prover = VMProver::fast_test_config();

        let result = prover.execute_with_witness(&program, &[]).unwrap();

        assert_eq!(result.cycles, 4);
        assert!(!result.execution_trace.is_empty());
    }

    #[test]
    fn test_vm_prover_end_to_end() {
        let program = create_simple_program();
        let prover = VMProver::fast_test_config();

        let (proof, vk) = prover.prove_program(&program, &[]).unwrap();

        // Verify proof
        let verified = prover.verify(&proof, &vk).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_prove_convenience_function() {
        let program = create_simple_program();

        // Use fast test config for speed (prove and verify must use same config)
        let prover = VMProver::fast_test_config();
        let (proof, vk) = prover.prove_program(&program, &[]).unwrap();

        // Verify with same config
        assert!(prover.verify(&proof, &vk).unwrap());
    }

    #[test]
    fn test_vm_prover_with_inputs() {
        // Program that reads input and writes output
        let instructions = vec![
            // Read syscall (a0 = syscall num)
            Instruction::Addi {
                rd: Register::R10,
                rs1: Register::R0,
                imm: 1, // SYSCALL_READ
            },
            Instruction::Ecall,
            // Write syscall - output the value read
            Instruction::Addi {
                rd: Register::R11,
                rs1: Register::R10,
                imm: 0,
            },
            Instruction::Addi {
                rd: Register::R10,
                rs1: Register::R0,
                imm: 2, // SYSCALL_WRITE
            },
            Instruction::Ecall,
            // Exit
            Instruction::Addi {
                rd: Register::R10,
                rs1: Register::R0,
                imm: 0, // SYSCALL_EXIT
            },
            Instruction::Addi {
                rd: Register::R11,
                rs1: Register::R0,
                imm: 0,
            },
            Instruction::Ecall,
        ];

        let mut program = Program::new();
        program.code = instructions
            .iter()
            .map(|inst| zkir_assembler::encode(inst))
            .collect();
        program.header.code_size = (program.code.len() * 4) as u32;

        let prover = VMProver::fast_test_config();
        let inputs = vec![42];

        let (proof, vk) = prover.prove_program(&program, &inputs).unwrap();
        assert!(prover.verify(&proof, &vk).unwrap());
    }

    #[test]
    fn test_vm_prover_different_configs() {
        let program = create_simple_program();

        // Test with fast config
        let prover_fast = VMProver::fast_test_config();
        let (proof_fast, vk_fast) = prover_fast.prove_program(&program, &[]).unwrap();
        assert!(prover_fast.verify(&proof_fast, &vk_fast).unwrap());

        // Test with test config
        let prover_test = VMProver::test_config();
        let (proof_test, vk_test) = prover_test.prove_program(&program, &[]).unwrap();
        assert!(prover_test.verify(&proof_test, &vk_test).unwrap());
    }

    #[test]
    fn test_vm_prover_memory_operations() {
        // Program with memory operations
        let instructions = vec![
            // R1 = 0x1000 (address)
            Instruction::Addi {
                rd: Register::R1,
                rs1: Register::R0,
                imm: 0x1000,
            },
            // R2 = 42 (value)
            Instruction::Addi {
                rd: Register::R2,
                rs1: Register::R0,
                imm: 42,
            },
            // Store R2 to [R1]
            Instruction::Sw {
                rs1: Register::R1,
                rs2: Register::R2,
                imm: 0,
            },
            // Load from [R1] to R3
            Instruction::Lw {
                rd: Register::R3,
                rs1: Register::R1,
                imm: 0,
            },
            Instruction::Ebreak,
        ];

        let mut program = Program::new();
        program.code = instructions
            .iter()
            .map(|inst| zkir_assembler::encode(inst))
            .collect();
        program.header.code_size = (program.code.len() * 4) as u32;

        let prover = VMProver::fast_test_config();
        let (proof, vk) = prover.prove_program(&program, &[]).unwrap();
        assert!(prover.verify(&proof, &vk).unwrap());
    }

    #[test]
    fn test_vm_prover_branches() {
        // Program with branch
        let instructions = vec![
            // R1 = 10
            Instruction::Addi {
                rd: Register::R1,
                rs1: Register::R0,
                imm: 10,
            },
            // R2 = 10
            Instruction::Addi {
                rd: Register::R2,
                rs1: Register::R0,
                imm: 10,
            },
            // BEQ R1, R2, +8 (skip next instruction)
            Instruction::Beq {
                rs1: Register::R1,
                rs2: Register::R2,
                offset: 8,
            },
            // This should be skipped
            Instruction::Addi {
                rd: Register::R3,
                rs1: Register::R0,
                imm: 99,
            },
            // Jump target
            Instruction::Ebreak,
        ];

        let mut program = Program::new();
        program.code = instructions
            .iter()
            .map(|inst| zkir_assembler::encode(inst))
            .collect();
        program.header.code_size = (program.code.len() * 4) as u32;

        let prover = VMProver::fast_test_config();
        let (proof, vk) = prover.prove_program(&program, &[]).unwrap();
        assert!(prover.verify(&proof, &vk).unwrap());
    }

    #[test]
    fn test_vm_prover_stack_frame() {
        // Test program that mimics C-compiled code with stack frame
        // This tests the pattern that causes OodEvaluationMismatch
        //
        // NOTE: 17-bit signed immediates have range [-65536, 65535].
        // To initialize SP to 0x10000 (65536), we need two ADDIs since
        // 65536 would have bit 16 set and be treated as negative.
        let instructions = vec![
            // Initialize stack pointer: R2 = 0x8000 (32768) - first half
            Instruction::Addi {
                rd: Register::R2,
                rs1: Register::R0,
                imm: 0x8000,
            },
            // R2 = R2 + 0x8000 = 0x10000 (65536) - second half
            Instruction::Addi {
                rd: Register::R2,
                rs1: Register::R2,
                imm: 0x8000,
            },
            // Allocate stack frame: R2 = R2 - 16
            Instruction::Addi {
                rd: Register::R2,
                rs1: Register::R2,
                imm: -16,
            },
            // Save return address (R1) to stack: mem[R2 + 12] = R1
            Instruction::Sw {
                rs1: Register::R2,
                rs2: Register::R1,
                imm: 12,
            },
            // Compute result: R15 = 42
            Instruction::Addi {
                rd: Register::R15,
                rs1: Register::R0,
                imm: 42,
            },
            Instruction::Ebreak,
        ];

        let mut program = Program::new();
        program.code = instructions
            .iter()
            .map(|inst| zkir_assembler::encode(inst))
            .collect();
        program.header.code_size = (program.code.len() * 4) as u32;

        let prover = VMProver::fast_test_config();
        let (proof, vk) = prover.prove_program(&program, &[]).unwrap();
        assert!(prover.verify(&proof, &vk).unwrap());
    }
}
