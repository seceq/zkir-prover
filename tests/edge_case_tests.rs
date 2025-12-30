//! Edge Case and Advanced Scenario Tests
//!
//! Tests for:
//! - Boundary values (max/min for limb sizes)
//! - Overflow behavior
//! - Signed arithmetic edge cases
//! - Complex control flow (loops, nested branches)
//! - Register pressure scenarios
//! - Memory alignment edge cases

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_main_witness;
use zkir_prover::witness::MainWitness;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

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

fn prove_and_verify(instructions: Vec<Instruction>, test_name: &str) {
    let witness = run_program_and_get_witness(instructions);
    let backend = Plonky3Backend::fast_test_config();
    let proof = backend.prove(&witness).expect(&format!("{} proof failed", test_name));
    backend.verify(&proof, &proof.verifying_key)
        .expect(&format!("{} verification failed", test_name));
}

// ============================================================================
// BOUNDARY VALUE TESTS
// ============================================================================

mod boundary_tests {
    use super::*;

    /// Test maximum 20-bit limb value (default config)
    #[test]
    fn test_max_limb_value() {
        let max_20bit = (1 << 20) - 1; // 0xFFFFF = 1048575
        let instructions = vec![
            // Load max value using shifts and OR
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFFFF }, // 16 bits
            Instruction::Slli { rd: Register::R1, rs1: Register::R1, shamt: 4 },    // Shift left 4
            Instruction::Ori { rd: Register::R1, rs1: Register::R1, imm: 0xF },     // OR in bottom 4 bits
            // Now R1 = 0xFFFFF (max 20-bit value)
            Instruction::Add { rd: Register::R2, rs1: Register::R1, rs2: Register::R0 }, // Copy
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Max limb value");
    }

    /// Test zero value operations
    #[test]
    fn test_zero_operations() {
        let instructions = vec![
            // All operations with zero
            Instruction::Add { rd: Register::R1, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Sub { rd: Register::R2, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Mul { rd: Register::R3, rs1: Register::R0, rs2: Register::R0 },
            Instruction::And { rd: Register::R4, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Or { rd: Register::R5, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Xor { rd: Register::R6, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Sll { rd: Register::R7, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Srl { rd: Register::R8, rs1: Register::R0, rs2: Register::R0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Zero operations");
    }

    /// Test power of two values
    #[test]
    fn test_powers_of_two() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 1 },   // 2
            Instruction::Slli { rd: Register::R3, rs1: Register::R1, shamt: 4 },   // 16
            Instruction::Slli { rd: Register::R4, rs1: Register::R1, shamt: 8 },   // 256
            Instruction::Slli { rd: Register::R5, rs1: Register::R1, shamt: 16 },  // 65536
            Instruction::Slli { rd: Register::R6, rs1: Register::R1, shamt: 19 },  // 524288 (max safe for 20-bit)
            // Verify with multiplication
            Instruction::Mul { rd: Register::R7, rs1: Register::R2, rs2: Register::R3 }, // 2 * 16 = 32
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Powers of two");
    }

    /// Test alternating bit patterns
    #[test]
    fn test_alternating_bits() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x5555 }, // 0101...
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x2AAA }, // Shifted pattern
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Or { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Xor { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Alternating bits");
    }
}

// ============================================================================
// SIGNED ARITHMETIC TESTS
// ============================================================================

mod signed_tests {
    use super::*;

    /// Test signed comparison with equal values
    #[test]
    fn test_signed_equal_comparison() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 42 },
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 0 (not less)
            Instruction::Sge { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },  // 1 (greater or equal)
            Instruction::Seq { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 },  // 1 (equal)
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Signed equal comparison");
    }

    /// Test signed less than with various values
    #[test]
    fn test_signed_less_than() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },
            Instruction::Slt { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },  // 5 < 10 = 1
            Instruction::Slt { rd: Register::R5, rs1: Register::R2, rs2: Register::R1 },  // 10 < 5 = 0
            Instruction::Slt { rd: Register::R6, rs1: Register::R0, rs2: Register::R3 },  // 0 < 1 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Signed less than");
    }

    /// Test signed division
    #[test]
    fn test_signed_division() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },
            Instruction::Div { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 100 / 7 = 14
            Instruction::Rem { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },  // 100 % 7 = 2
            // Verify: quotient * divisor + remainder = dividend
            Instruction::Mul { rd: Register::R5, rs1: Register::R3, rs2: Register::R2 },  // 14 * 7 = 98
            Instruction::Add { rd: Register::R6, rs1: Register::R5, rs2: Register::R4 },  // 98 + 2 = 100
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Signed division");
    }
}

// ============================================================================
// CONTROL FLOW TESTS
// ============================================================================

mod control_flow_tests {
    use super::*;

    /// Test simple conditional execution (no backwards branch for now)
    #[test]
    fn test_conditional_sequence() {
        let instructions = vec![
            // Initialize values
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 3 },
            // If R1 > R2, add them
            Instruction::Blt { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Skip if R1 < R2
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 5 + 3 = 8
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 1 }, // Mark that we executed
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Conditional sequence");
    }

    /// Test nested branches
    #[test]
    fn test_nested_branches() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 15 },
            // If R1 > R2 (10 > 5)
            Instruction::Bge { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Branch if R1 >= R2
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 0 },    // Not taken
            // If R1 < R3 (10 < 15)
            Instruction::Blt { rs1: Register::R1, rs2: Register::R3, offset: 8 }, // Branch if R1 < R3
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 1 },    // Not taken
            // Both conditions met
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 2 },    // Taken
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Nested branches");
    }

    /// Test branch not taken
    #[test]
    fn test_branch_not_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            // R1 < R2, so BGE should NOT be taken
            Instruction::Bge { rs1: Register::R1, rs2: Register::R2, offset: 8 },
            // This should execute
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Branch not taken");
    }

    /// Test forward jump over multiple instructions
    #[test]
    fn test_forward_jump() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Jal { rd: Register::R5, offset: 16 }, // Jump forward 4 instructions
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 2 }, // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 3 }, // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 4 }, // Skipped
            Instruction::Addi { rd: Register::R6, rs1: Register::R0, imm: 42 }, // Jump target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Forward jump");
    }
}

// ============================================================================
// REGISTER TESTS
// ============================================================================

mod register_tests {
    use super::*;

    /// Test using a few registers with simple operations
    #[test]
    fn test_few_registers() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 30
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Few registers");
    }

    /// Test high registers (R10-R15)
    #[test]
    fn test_high_registers() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R10, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R11, rs1: Register::R0, imm: 200 },
            Instruction::Add { rd: Register::R12, rs1: Register::R10, rs2: Register::R11 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "High registers");
    }
}

// ============================================================================
// MEMORY TESTS
// ============================================================================

mod memory_tests {
    use super::*;

    /// Test store and load at different offsets
    #[test]
    fn test_memory_offsets() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x100 }, // Base address
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 11 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 22 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 33 },
            // Store at different offsets
            Instruction::Sw { rs1: Register::R1, rs2: Register::R2, imm: 0 },
            Instruction::Sw { rs1: Register::R1, rs2: Register::R3, imm: 4 },
            Instruction::Sw { rs1: Register::R1, rs2: Register::R4, imm: 8 },
            // Load back
            Instruction::Lw { rd: Register::R5, rs1: Register::R1, imm: 0 },
            Instruction::Lw { rd: Register::R6, rs1: Register::R1, imm: 4 },
            Instruction::Lw { rd: Register::R7, rs1: Register::R1, imm: 8 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Memory offsets");
    }

    /// Test byte-level memory operations
    #[test]
    fn test_byte_memory() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x1000 }, // Base
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x41 },   // 'A'
            // Store and load back same byte
            Instruction::Sb { rs1: Register::R1, rs2: Register::R2, imm: 0 },
            Instruction::Lbu { rd: Register::R3, rs1: Register::R1, imm: 0 },
            // Store another byte at different offset
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 0x42 },   // 'B'
            Instruction::Sb { rs1: Register::R1, rs2: Register::R4, imm: 4 },       // Different word
            Instruction::Lbu { rd: Register::R5, rs1: Register::R1, imm: 4 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Byte memory");
    }

    /// Test halfword memory operations
    #[test]
    fn test_halfword_memory() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x1000 }, // Base
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1234 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0x5678 },
            // Store halfwords
            Instruction::Sh { rs1: Register::R1, rs2: Register::R2, imm: 0 },
            Instruction::Sh { rs1: Register::R1, rs2: Register::R3, imm: 2 },
            // Load back
            Instruction::Lh { rd: Register::R4, rs1: Register::R1, imm: 0 },
            Instruction::Lh { rd: Register::R5, rs1: Register::R1, imm: 2 },
            Instruction::Lhu { rd: Register::R6, rs1: Register::R1, imm: 0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Halfword memory");
    }
}

// ============================================================================
// ARITHMETIC EDGE CASES
// ============================================================================

mod arithmetic_edge_cases {
    use super::*;

    /// Test multiplication overflow handling
    #[test]
    fn test_multiplication_large_values() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1000 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1000 },
            Instruction::Mul { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 1,000,000
            Instruction::Mulh { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // Upper bits
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Large multiplication");
    }

    /// Test division by 1
    #[test]
    fn test_division_by_one() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 12345 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 12345
            Instruction::Remu { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Division by one");
    }

    /// Test division with equal values
    #[test]
    fn test_division_equal_values() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 42 },
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 1
            Instruction::Remu { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Division equal values");
    }

    /// Test subtraction resulting in zero
    #[test]
    fn test_subtraction_to_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Sub { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 }, // 0
            Instruction::Seq { rd: Register::R3, rs1: Register::R2, rs2: Register::R0 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Subtraction to zero");
    }

    /// Test XOR self (should be zero)
    #[test]
    fn test_xor_self() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xABCD },
            Instruction::Xor { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 }, // 0
            Instruction::Seq { rd: Register::R3, rs1: Register::R2, rs2: Register::R0 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XOR self");
    }
}

// ============================================================================
// CONDITIONAL MOVE TESTS
// ============================================================================

mod conditional_move_tests {
    use super::*;

    /// Test CMOV with zero condition
    #[test]
    fn test_cmov_zero_condition() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 }, // Value to move
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },  // Original value
            // Condition is zero, so R2 should NOT change
            Instruction::Cmov { rd: Register::R2, rs1: Register::R1, rs2: Register::R0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOV zero condition");
    }

    /// Test CMOV with non-zero condition
    #[test]
    fn test_cmov_nonzero_condition() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 }, // Value to move
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },  // Original value
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },   // Non-zero condition
            // Condition is non-zero, so R2 should become R1 (100)
            Instruction::Cmov { rd: Register::R2, rs1: Register::R1, rs2: Register::R3 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOV nonzero condition");
    }

    /// Test CMOVZ
    #[test]
    fn test_cmovz() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 }, // Value to move
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },  // Original value
            // CMOVZ: move if condition is zero
            Instruction::Cmovz { rd: Register::R2, rs1: Register::R1, rs2: Register::R0 }, // Should move
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOVZ");
    }

    /// Test CMOVNZ
    #[test]
    fn test_cmovnz() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 }, // Value to move
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },  // Original value
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 7 },   // Non-zero condition
            // CMOVNZ: move if condition is non-zero
            Instruction::Cmovnz { rd: Register::R2, rs1: Register::R1, rs2: Register::R3 }, // Should move
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOVNZ");
    }
}

// ============================================================================
// SHIFT EDGE CASES
// ============================================================================

mod shift_tests {
    use super::*;

    /// Test shift by zero
    #[test]
    fn test_shift_by_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xABCD },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 0 }, // Same value
            Instruction::Srli { rd: Register::R3, rs1: Register::R1, shamt: 0 }, // Same value
            Instruction::Srai { rd: Register::R4, rs1: Register::R1, shamt: 0 }, // Same value
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Shift by zero");
    }

    /// Test shift by maximum amount
    #[test]
    fn test_shift_max() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 19 }, // Max for 20-bit
            Instruction::Srli { rd: Register::R3, rs1: Register::R2, shamt: 19 }, // Back to 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Shift max amount");
    }

    /// Test register-based shifts
    #[test]
    fn test_register_shifts() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 4 },
            Instruction::Sll { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 0xFF << 4
            Instruction::Srl { rd: Register::R4, rs1: Register::R3, rs2: Register::R2 }, // Back to 0xFF
            Instruction::Sra { rd: Register::R5, rs1: Register::R3, rs2: Register::R2 }, // Arithmetic shift
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Register shifts");
    }
}
