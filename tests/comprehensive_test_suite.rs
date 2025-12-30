//! Comprehensive Test Suite for zkir-prover
//!
//! This module provides extensive testing coverage including:
//! - Integration tests with complex multi-instruction programs
//! - Edge case tests (boundary values, register limits, etc.)
//! - Adversarial input tests (malformed witnesses, invalid proofs)
//! - Stress tests with large programs
//!
//! Run with: cargo test --test comprehensive_test_suite

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_main_witness;
use zkir_prover::witness::{
    MainWitness, MainWitnessBuilder, MainTraceRow, ProgramConfig, ValueBound, MemoryOp,
};
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Run a program through the VM and return a witness
fn run_program_and_get_witness(instructions: Vec<Instruction>) -> MainWitness {
    let header = ProgramHeader::new();
    let code: Vec<u32> = instructions.iter().map(|inst| encode(inst)).collect();
    let program = Program {
        header,
        code,
        data: Vec::new(),
    };

    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], vm_config);
    let result = vm.run().expect("VM execution failed");

    vm_result_to_main_witness(&program, &[], result)
        .expect("Witness conversion failed")
}

/// Create a simple trace row with given values (for adversarial tests only)
fn create_trace_row(
    cycle: u64,
    pc: u64,
    instruction: u32,
    reg_values: &[u32],
    config: &ProgramConfig,
) -> MainTraceRow {
    let data_limbs = config.data_limbs as usize;
    let mut registers = vec![vec![0u32; data_limbs]; 16];

    // Set register values (only low limb for simplicity)
    for (i, &val) in reg_values.iter().enumerate().take(16) {
        registers[i][0] = val;
    }

    let bounds = vec![ValueBound::zero(); 16];
    MainTraceRow::new(cycle, pc, instruction, registers, bounds)
}

/// Create a witness with specified trace rows (for adversarial tests only)
fn create_witness(rows: Vec<MainTraceRow>, config: ProgramConfig) -> MainWitness {
    let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);
    for row in rows {
        builder.add_trace_row(row);
    }
    builder.build()
}

// Constants for manual witness construction (adversarial tests)
const OPCODE_NOP: u32 = 0x71;   // EBREAK
#[allow(dead_code)]
const OPCODE_ADDI: u32 = 0x05;  // ADDI (kept for reference)

// ============================================================================
// INTEGRATION TESTS - COMPLEX PROGRAMS
// ============================================================================

mod integration_tests {
    use super::*;

    /// Test a program that uses multiple registers
    #[test]
    fn test_multiple_registers() {
        let instructions = vec![
            // Initialize registers with distinct values
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 30 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 40 },
            Instruction::Addi { rd: Register::R5, rs1: Register::R0, imm: 50 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Proof generation failed: {:?}", result.err());

        let proof = result.unwrap();
        let verify_result = backend.verify(&proof, &proof.verifying_key);
        assert!(verify_result.is_ok(), "Verification failed: {:?}", verify_result.err());
    }

    /// Test a program with mixed arithmetic operations
    #[test]
    fn test_mixed_arithmetic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 150
            Instruction::Sub { rd: Register::R4, rs1: Register::R3, rs2: Register::R2 }, // 100
            Instruction::Mul { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 }, // 5000
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Mixed arithmetic proof failed: {:?}", result.err());
    }

    /// Test a program that chains multiple operations
    #[test]
    fn test_chained_operations() {
        let instructions = vec![
            // R1 = 5
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            // R2 = R1 + R1 = 10
            Instruction::Add { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 },
            // R3 = R2 + R2 = 20
            Instruction::Add { rd: Register::R3, rs1: Register::R2, rs2: Register::R2 },
            // R4 = R3 + R3 = 40
            Instruction::Add { rd: Register::R4, rs1: Register::R3, rs2: Register::R3 },
            // R5 = R4 + R4 = 80
            Instruction::Add { rd: Register::R5, rs1: Register::R4, rs2: Register::R4 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Chained operations proof failed: {:?}", result.err());
    }
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

mod edge_case_tests {
    use super::*;

    /// Test with minimum trace size (single instruction)
    #[test]
    fn test_minimum_trace_size() {
        let instructions = vec![
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Minimum trace proof failed: {:?}", result.err());
    }

    /// Test with small programs of various sizes
    #[test]
    fn test_small_programs() {
        // Test 4 instruction program
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 2 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 3 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Small program proof failed: {:?}", result.err());
    }

    /// Test R0 hardwired to zero (attempts to write to R0 are ignored)
    #[test]
    fn test_r0_always_zero() {
        // R0 is hardwired to zero - the VM enforces this
        let instructions = vec![
            Instruction::Addi { rd: Register::R0, rs1: Register::R0, imm: 100 }, // R0 stays 0
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 50 },  // R1 = 50
            Instruction::Add { rd: Register::R2, rs1: Register::R0, rs2: Register::R1 }, // R2 = 0 + 50 = 50
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "R0 zero constraint proof failed: {:?}", result.err());
    }

    /// Test with zero values in operations
    #[test]
    fn test_zero_values() {
        let instructions = vec![
            // ADD R1, R0, R0 (0 + 0 = 0)
            Instruction::Add { rd: Register::R1, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Zero values proof failed: {:?}", result.err());
    }
}

// ============================================================================
// ADVERSARIAL INPUT TESTS
// ============================================================================

mod adversarial_tests {
    use super::*;
    use zkir_prover::witness::verify::verify_witness;

    /// Test that empty trace is rejected
    #[test]
    fn test_empty_trace_rejected() {
        let config = ProgramConfig::DEFAULT;
        let witness = MainWitnessBuilder::new(config, [0u8; 32]).build();

        let verify_result = verify_witness(&witness);
        assert!(verify_result.is_err(), "Empty trace should be rejected");
    }

    /// Test that out-of-order cycles are detected
    #[test]
    fn test_out_of_order_cycles_rejected() {
        let config = ProgramConfig::DEFAULT;

        // Create rows with out-of-order cycles
        let rows = vec![
            create_trace_row(0, 0, OPCODE_NOP, &[0; 16], &config),
            create_trace_row(2, 8, OPCODE_NOP, &[0; 16], &config), // Skip cycle 1
            create_trace_row(1, 4, OPCODE_NOP, &[0; 16], &config), // Out of order!
        ];

        let witness = create_witness(rows, config);
        let verify_result = verify_witness(&witness);

        assert!(verify_result.is_err(), "Out-of-order cycles should be rejected");
    }

    /// Test that wrong register count is detected
    #[test]
    fn test_wrong_register_count_rejected() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        // Create a row with wrong number of registers
        let wrong_registers = vec![vec![0u32, 0u32]; 10]; // 10 instead of 16
        let bounds = vec![ValueBound::zero(); 16];
        let row = MainTraceRow::new(0, 0, OPCODE_NOP, wrong_registers, bounds);
        builder.add_trace_row(row);

        let witness = builder.build();
        let verify_result = verify_witness(&witness);

        assert!(verify_result.is_err(), "Wrong register count should be rejected");
    }

    /// Test that proof verification fails with tampered proof data
    #[test]
    fn test_tampered_proof_rejected() {
        // Generate a valid proof using VM-based witness
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 100 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let mut proof = backend.prove(&witness).expect("Proof generation should succeed");

        // Tamper with the proof by modifying proof bytes
        if proof.proof_bytes.len() > 10 {
            proof.proof_bytes[5] ^= 0xFF;  // Flip bits in the proof data
            proof.proof_bytes[10] ^= 0xAA;
        }

        // Verification should fail with tampered proof
        let verify_result = backend.verify(&proof, &proof.verifying_key);
        assert!(verify_result.is_err(), "Tampered proof should be rejected");
        println!("Tampered proof verification correctly failed: {:?}", verify_result.err());
    }
}

// ============================================================================
// STRESS TESTS
// ============================================================================

mod stress_tests {
    use super::*;

    /// Test with a longer trace (16 instructions)
    #[test]
    fn test_longer_trace() {
        let mut instructions = Vec::new();

        // Build a longer program with various operations
        for i in 1..=15i64 {
            let rd = match i % 15 {
                1 => Register::R1,
                2 => Register::R2,
                3 => Register::R3,
                4 => Register::R4,
                5 => Register::R5,
                6 => Register::R6,
                7 => Register::R7,
                8 => Register::R8,
                9 => Register::R9,
                10 => Register::R10,
                11 => Register::R11,
                12 => Register::R12,
                13 => Register::R13,
                14 => Register::R14,
                _ => Register::R15,
            };
            instructions.push(Instruction::Addi { rd, rs1: Register::R0, imm: i as i32 });
        }
        instructions.push(Instruction::Ebreak);

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Longer trace proof failed: {:?}", result.err());
    }

    /// Test with many arithmetic operations
    #[test]
    fn test_many_arithmetic_ops() {
        let mut instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
        ];

        // Many ADD operations
        for _ in 0..10 {
            instructions.push(Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 });
            instructions.push(Instruction::Add { rd: Register::R4, rs1: Register::R3, rs2: Register::R1 });
        }
        instructions.push(Instruction::Ebreak);

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Many arithmetic ops proof failed: {:?}", result.err());
    }
}

// ============================================================================
// CONFIGURATION TESTS
// ============================================================================

mod config_tests {
    use super::*;

    /// Test with default configuration
    #[test]
    fn test_default_config() {
        // Verify default config values
        let config = ProgramConfig::DEFAULT;
        assert_eq!(config.limb_bits, 20);
        assert_eq!(config.data_limbs, 2);

        // Simple program should work with default config
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Default config proof failed: {:?}", result.err());
    }

    /// Test chunk bits calculation
    #[test]
    fn test_chunk_bits_calculation() {
        let config = ProgramConfig::DEFAULT;
        let chunk_bits = config.chunk_bits();

        assert_eq!(chunk_bits, 10, "Chunk bits should be half of limb_bits");
        assert_eq!(config.limb_bits / 2, chunk_bits as u8);
    }
}

// ============================================================================
// MEMORY OPERATION TESTS
// ============================================================================

mod memory_tests {
    use super::*;

    /// Test program with memory operations (store + load)
    #[test]
    fn test_memory_operations() {
        let instructions = vec![
            // Store 42 to address 0x1000
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
            Instruction::Sw { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            // Load it back into R3
            Instruction::Lw { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let result = backend.prove(&witness);

        assert!(result.is_ok(), "Memory operations proof failed: {:?}", result.err());
    }

    /// Test memory consistency verification
    #[test]
    fn test_memory_consistency_check() {
        use zkir_prover::witness::verify::verify_witness;

        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];
        builder.add_trace_row(MainTraceRow::new(0, 0, OPCODE_NOP, registers.clone(), bounds.clone()));

        // Write value 42
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![42, 0],
            0,
            true,
            ValueBound::tight(32),
        ));

        // Read same value 42 (consistent)
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![42, 0],
            1,
            false,
            ValueBound::tight(32),
        ));

        let witness = builder.build();
        let verify_result = verify_witness(&witness);

        assert!(verify_result.is_ok(), "Memory consistency check should pass");
    }

    /// Test memory inconsistency is detected
    #[test]
    fn test_memory_inconsistency_detected() {
        use zkir_prover::witness::verify::verify_witness;

        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];
        builder.add_trace_row(MainTraceRow::new(0, 0, OPCODE_NOP, registers.clone(), bounds.clone()));

        // Write value 42
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![42, 0],
            0,
            true,
            ValueBound::tight(32),
        ));

        // Read different value 99 (inconsistent!)
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![99, 0], // Wrong value!
            1,
            false,
            ValueBound::tight(32),
        ));

        let witness = builder.build();
        let verify_result = verify_witness(&witness);

        assert!(verify_result.is_err(), "Memory inconsistency should be detected");
    }
}

// ============================================================================
// BITWISE OPERATION TESTS
// ============================================================================

mod bitwise_tests {
    use super::*;

    /// Test AND operation
    #[test]
    fn test_and_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x0F },
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 0x0F
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("AND proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("AND verification failed");
    }

    /// Test OR operation
    #[test]
    fn test_or_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xF0 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x0F },
            Instruction::Or { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 0xFF
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("OR proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("OR verification failed");
    }

    /// Test XOR operation
    #[test]
    fn test_xor_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0xAA },
            Instruction::Xor { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 0x55
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("XOR proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("XOR verification failed");
    }

    /// Test ANDI (AND immediate)
    #[test]
    fn test_andi_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Andi { rd: Register::R2, rs1: Register::R1, imm: 0x0F },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("ANDI proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("ANDI verification failed");
    }

    /// Test ORI (OR immediate)
    #[test]
    fn test_ori_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xF0 },
            Instruction::Ori { rd: Register::R2, rs1: Register::R1, imm: 0x0F },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("ORI proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("ORI verification failed");
    }

    /// Test XORI (XOR immediate)
    #[test]
    fn test_xori_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Xori { rd: Register::R2, rs1: Register::R1, imm: 0xAA },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("XORI proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("XORI verification failed");
    }

    /// Test combined bitwise operations
    #[test]
    fn test_combined_bitwise() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xAB },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0xCD },
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Or { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Xor { rd: Register::R5, rs1: Register::R3, rs2: Register::R4 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Combined bitwise proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Combined bitwise verification failed");
    }
}

// ============================================================================
// SHIFT OPERATION TESTS
// ============================================================================

mod shift_tests {
    use super::*;

    /// Test SLL (shift left logical)
    #[test]
    fn test_sll_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 4 },
            Instruction::Sll { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 1 << 4 = 16
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SLL proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SLL verification failed");
    }

    /// Test SRL (shift right logical)
    #[test]
    fn test_srl_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 256 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 4 },
            Instruction::Srl { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 256 >> 4 = 16
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SRL proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SRL verification failed");
    }

    /// Test SLLI (shift left logical immediate)
    #[test]
    fn test_slli_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 3 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 2 }, // 3 << 2 = 12
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SLLI proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SLLI verification failed");
    }

    /// Test SRLI (shift right logical immediate)
    #[test]
    fn test_srli_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 64 },
            Instruction::Srli { rd: Register::R2, rs1: Register::R1, shamt: 3 }, // 64 >> 3 = 8
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SRLI proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SRLI verification failed");
    }

    /// Test shift by zero (should not change value)
    #[test]
    fn test_shift_by_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 0 }, // 42 << 0 = 42
            Instruction::Srli { rd: Register::R3, rs1: Register::R1, shamt: 0 }, // 42 >> 0 = 42
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Shift by zero proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Shift by zero verification failed");
    }
}

// ============================================================================
// COMPARISON OPERATION TESTS
// ============================================================================

mod comparison_tests {
    use super::*;

    /// Test SLT (set less than)
    #[test]
    fn test_slt_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 5 < 10 = 1
            Instruction::Slt { rd: Register::R4, rs1: Register::R2, rs2: Register::R1 }, // 10 < 5 = 0
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SLT proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SLT verification failed");
    }

    /// Test SLTU (set less than unsigned)
    #[test]
    fn test_sltu_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 3 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },
            Instruction::Sltu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 3 < 7 = 1
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SLTU proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SLTU verification failed");
    }

    /// Test SEQ (set equal)
    #[test]
    fn test_seq_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 10 },
            Instruction::Seq { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 5 == 5 = 1
            Instruction::Seq { rd: Register::R5, rs1: Register::R1, rs2: Register::R3 }, // 5 == 10 = 0
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SEQ proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SEQ verification failed");
    }

    /// Test SNE (set not equal)
    #[test]
    fn test_sne_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Sne { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 5 != 10 = 1
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("SNE proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("SNE verification failed");
    }

    /// Test simple subtraction (without underflow)
    #[test]
    fn test_simple_subtraction() {
        // Only test subtraction without underflow (larger - smaller)
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Sub { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 10 - 5 = 5
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Subtraction proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Subtraction verification failed");
    }
}

// ============================================================================
// HIGH REGISTER TESTS (R10-R15)
// ============================================================================

mod high_register_tests {
    use super::*;

    /// Test using all high registers (R10-R15)
    #[test]
    fn test_all_high_registers() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R10, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R11, rs1: Register::R0, imm: 11 },
            Instruction::Addi { rd: Register::R12, rs1: Register::R0, imm: 12 },
            Instruction::Addi { rd: Register::R13, rs1: Register::R0, imm: 13 },
            Instruction::Addi { rd: Register::R14, rs1: Register::R0, imm: 14 },
            Instruction::Addi { rd: Register::R15, rs1: Register::R0, imm: 15 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("High registers proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("High registers verification failed");
    }

    /// Test arithmetic between high and low registers
    #[test]
    fn test_high_low_register_interaction() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R15, rs1: Register::R0, imm: 50 },
            Instruction::Add { rd: Register::R10, rs1: Register::R1, rs2: Register::R15 }, // 150
            Instruction::Sub { rd: Register::R11, rs1: Register::R10, rs2: Register::R15 }, // 100
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("High-low interaction proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("High-low interaction verification failed");
    }

    /// Test using R15 as source and destination
    #[test]
    fn test_r15_operations() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R15, rs1: Register::R0, imm: 25 },
            Instruction::Addi { rd: Register::R14, rs1: Register::R0, imm: 25 },
            Instruction::Add { rd: Register::R13, rs1: Register::R15, rs2: Register::R14 }, // 50
            Instruction::Add { rd: Register::R1, rs1: Register::R13, rs2: Register::R0 }, // Copy to R1
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("R15 operations proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("R15 operations verification failed");
    }
}

// ============================================================================
// PROOF SERIALIZATION TESTS
// ============================================================================

mod serialization_tests {
    use super::*;

    /// Test proof serialization and deserialization
    #[test]
    fn test_proof_serialization_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 100 },
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let original_proof = backend.prove(&witness).expect("Proof generation failed");

        // Serialize
        let serialized = original_proof.to_bytes().expect("Serialization failed");

        // Deserialize
        let deserialized_proof = zkir_prover::backend::proof::Proof::from_bytes(&serialized)
            .expect("Deserialization failed");

        // Verify the deserialized proof
        backend.verify(&deserialized_proof, &deserialized_proof.verifying_key)
            .expect("Deserialized proof verification failed");
    }

    /// Test verifying key serialization
    #[test]
    fn test_vk_serialization_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 77 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Proof generation failed");

        // Serialize VK
        let vk_bytes = proof.verifying_key.to_bytes().expect("VK serialization failed");

        // Deserialize VK
        let deserialized_vk = zkir_prover::backend::proof::VerifyingKey::from_bytes(&vk_bytes)
            .expect("VK deserialization failed");

        // Verify with deserialized VK
        backend.verify(&proof, &deserialized_vk)
            .expect("Verification with deserialized VK failed");
    }

    /// Test proof metadata preservation
    #[test]
    fn test_metadata_preservation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 2 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 3 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Proof generation failed");

        // Check metadata
        assert_eq!(proof.metadata.backend_name, "Plonky3");
        assert!(proof.metadata.num_cycles > 0, "num_cycles should be > 0");
        assert!(proof.metadata.trace_width > 0, "trace_width should be > 0");
        assert!(proof.metadata.trace_height > 0, "trace_height should be > 0");
        assert!(proof.metadata.proof_size > 0, "proof_size should be > 0");
        // Note: test_config() uses reduced security for faster tests
        assert!(proof.metadata.security_bits > 0, "security_bits should be > 0");
        assert!(proof.metadata.rap_challenge.is_some(), "rap_challenge should be set");
    }
}

// ============================================================================
// COMPLEX PROGRAM TESTS
// ============================================================================

mod complex_program_tests {
    use super::*;

    /// Test Fibonacci-like computation
    #[test]
    fn test_fibonacci_sequence() {
        let instructions = vec![
            // Initialize: R1 = 1, R2 = 1
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            // R3 = R1 + R2 = 2
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            // R4 = R2 + R3 = 3
            Instruction::Add { rd: Register::R4, rs1: Register::R2, rs2: Register::R3 },
            // R5 = R3 + R4 = 5
            Instruction::Add { rd: Register::R5, rs1: Register::R3, rs2: Register::R4 },
            // R6 = R4 + R5 = 8
            Instruction::Add { rd: Register::R6, rs1: Register::R4, rs2: Register::R5 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Fibonacci proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Fibonacci verification failed");
    }

    /// Test simple addition chain
    #[test]
    fn test_simple_add_chain() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 3 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 4 },
            // R3 = R1 + R2 = 7
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            // R4 = R3 + R1 = 10
            Instruction::Add { rd: Register::R4, rs1: Register::R3, rs2: Register::R1 },
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Add chain proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Add chain verification failed");
    }

    /// Test mixed arithmetic and bitwise
    #[test]
    fn test_mixed_arithmetic_bitwise() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 15 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },
            // Arithmetic
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 22
            Instruction::Sub { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 8
            // Bitwise
            Instruction::And { rd: Register::R5, rs1: Register::R3, rs2: Register::R4 }, // 22 & 8 = 0
            Instruction::Or { rd: Register::R6, rs1: Register::R3, rs2: Register::R4 },  // 22 | 8 = 30
            Instruction::Xor { rd: Register::R7, rs1: Register::R5, rs2: Register::R6 }, // 0 ^ 30 = 30
            Instruction::Ebreak,
        ];

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Mixed ops proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Mixed ops verification failed");
    }

    /// Test multiple registers used in sequence
    #[test]
    fn test_multiple_registers_sequence() {
        let mut instructions = Vec::new();

        // Initialize registers R1-R8 with their index (staying in a reasonable range)
        let registers = [
            Register::R1, Register::R2, Register::R3, Register::R4,
            Register::R5, Register::R6, Register::R7, Register::R8,
        ];

        for (i, &reg) in registers.iter().enumerate() {
            instructions.push(Instruction::Addi { rd: reg, rs1: Register::R0, imm: (i + 1) as i32 });
        }

        // Add some registers together
        instructions.push(Instruction::Add { rd: Register::R9, rs1: Register::R1, rs2: Register::R2 });
        instructions.push(Instruction::Add { rd: Register::R10, rs1: Register::R3, rs2: Register::R4 });
        instructions.push(Instruction::Add { rd: Register::R11, rs1: Register::R9, rs2: Register::R10 });
        instructions.push(Instruction::Ebreak);

        let witness = run_program_and_get_witness(instructions);
        let backend = Plonky3Backend::test_config();
        let proof = backend.prove(&witness).expect("Multiple registers proof failed");
        backend.verify(&proof, &proof.verifying_key).expect("Multiple registers verification failed");
    }
}
