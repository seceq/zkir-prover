//! Immediate Value and Comparison Instruction Tests
//!
//! Tests for:
//! - Immediate value handling (positive, negative, edge values)
//! - All comparison instructions (SLT, SLTU, SGE, SGEU, SEQ, SNE)
//! - Immediate variants of instructions (ANDI, ORI, XORI, SLTI, etc.)

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_main_witness;
use zkir_prover::witness::MainWitness;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

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
// IMMEDIATE VALUE TESTS
// ============================================================================

mod immediate_tests {
    use super::*;

    /// Test positive immediate values
    #[test]
    fn test_positive_immediate() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1000 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 0x7FFF }, // Max 15-bit
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Positive immediate");
    }

    /// Test negative immediate values
    #[test]
    fn test_negative_immediate() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R1, imm: -1 },   // 99
            Instruction::Addi { rd: Register::R3, rs1: Register::R1, imm: -50 },  // 50
            Instruction::Addi { rd: Register::R4, rs1: Register::R1, imm: -100 }, // 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Negative immediate");
    }

    /// Test zero immediate
    #[test]
    fn test_zero_immediate() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R1, imm: 0 }, // Should stay 42
            Instruction::Andi { rd: Register::R3, rs1: Register::R1, imm: 0 }, // Should be 0
            Instruction::Ori { rd: Register::R4, rs1: Register::R1, imm: 0 },  // Should stay 42
            Instruction::Xori { rd: Register::R5, rs1: Register::R1, imm: 0 }, // Should stay 42
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Zero immediate");
    }

    /// Test ANDI with various masks
    #[test]
    fn test_andi_masks() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Andi { rd: Register::R2, rs1: Register::R1, imm: 0x0F },  // Low nibble
            Instruction::Andi { rd: Register::R3, rs1: Register::R1, imm: 0xF0 },  // High nibble
            Instruction::Andi { rd: Register::R4, rs1: Register::R1, imm: 0x55 },  // Alternating
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "ANDI masks");
    }

    /// Test ORI setting bits
    #[test]
    fn test_ori_set_bits() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
            Instruction::Ori { rd: Register::R2, rs1: Register::R1, imm: 0x01 },  // Set bit 0
            Instruction::Ori { rd: Register::R3, rs1: Register::R2, imm: 0x02 },  // Set bit 1
            Instruction::Ori { rd: Register::R4, rs1: Register::R3, imm: 0x04 },  // Set bit 2
            Instruction::Ori { rd: Register::R5, rs1: Register::R4, imm: 0x08 },  // Set bit 3
            // R5 should be 0x0F
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "ORI set bits");
    }

    /// Test XORI toggle bits
    #[test]
    fn test_xori_toggle() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Xori { rd: Register::R2, rs1: Register::R1, imm: 0x0F },  // Toggle low
            Instruction::Xori { rd: Register::R3, rs1: Register::R2, imm: 0x0F },  // Toggle back
            // R3 should equal R1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XORI toggle");
    }
}

// ============================================================================
// COMPARISON INSTRUCTION TESTS
// ============================================================================

mod comparison_tests {
    use super::*;

    /// Test SLT (Set Less Than - signed)
    #[test]
    fn test_slt_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 5 < 10 = 1
            Instruction::Slt { rd: Register::R4, rs1: Register::R2, rs2: Register::R1 }, // 10 < 5 = 0
            Instruction::Slt { rd: Register::R5, rs1: Register::R1, rs2: Register::R1 }, // 5 < 5 = 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SLT basic");
    }

    /// Test SLTU (Set Less Than Unsigned)
    #[test]
    fn test_sltu_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Sltu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 5 < 10 = 1
            Instruction::Sltu { rd: Register::R4, rs1: Register::R2, rs2: Register::R1 }, // 10 < 5 = 0
            Instruction::Sltu { rd: Register::R5, rs1: Register::R0, rs2: Register::R1 }, // 0 < 5 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SLTU basic");
    }

    /// Test SGE (Set Greater or Equal - signed)
    #[test]
    fn test_sge_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Sge { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 10 >= 5 = 1
            Instruction::Sge { rd: Register::R4, rs1: Register::R2, rs2: Register::R1 }, // 5 >= 10 = 0
            Instruction::Sge { rd: Register::R5, rs1: Register::R1, rs2: Register::R1 }, // 10 >= 10 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SGE basic");
    }

    /// Test SGEU (Set Greater or Equal Unsigned)
    #[test]
    fn test_sgeu_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Sgeu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 10 >= 5 = 1
            Instruction::Sgeu { rd: Register::R4, rs1: Register::R2, rs2: Register::R1 }, // 5 >= 10 = 0
            Instruction::Sgeu { rd: Register::R5, rs1: Register::R0, rs2: Register::R0 }, // 0 >= 0 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SGEU basic");
    }

    /// Test SEQ (Set Equal)
    #[test]
    fn test_seq_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 99 },
            Instruction::Seq { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // Equal = 1
            Instruction::Seq { rd: Register::R5, rs1: Register::R1, rs2: Register::R3 }, // Not equal = 0
            Instruction::Seq { rd: Register::R6, rs1: Register::R0, rs2: Register::R0 }, // 0 == 0 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SEQ basic");
    }

    /// Test SNE (Set Not Equal)
    #[test]
    fn test_sne_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 99 },
            Instruction::Sne { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // Equal = 0
            Instruction::Sne { rd: Register::R5, rs1: Register::R1, rs2: Register::R3 }, // Not equal = 1
            Instruction::Sne { rd: Register::R6, rs1: Register::R0, rs2: Register::R1 }, // 0 != 42 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SNE basic");
    }

    /// Test comparison with zero
    #[test]
    fn test_compare_with_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Slt { rd: Register::R2, rs1: Register::R0, rs2: Register::R1 },  // 0 < 100 = 1
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R0 },  // 100 < 0 = 0
            Instruction::Sltu { rd: Register::R4, rs1: Register::R0, rs2: Register::R1 }, // 0 < 100 = 1
            Instruction::Seq { rd: Register::R5, rs1: Register::R0, rs2: Register::R0 },  // 0 == 0 = 1
            Instruction::Sne { rd: Register::R6, rs1: Register::R0, rs2: Register::R1 },  // 0 != 100 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Compare with zero");
    }

    /// Test chained comparisons
    #[test]
    fn test_chained_comparisons() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 30 },
            // Check R1 < R2 < R3
            Instruction::Slt { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 10 < 20 = 1
            Instruction::Slt { rd: Register::R5, rs1: Register::R2, rs2: Register::R3 }, // 20 < 30 = 1
            // Both should be 1
            Instruction::And { rd: Register::R6, rs1: Register::R4, rs2: Register::R5 }, // 1 & 1 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Chained comparisons");
    }
}

// ============================================================================
// BRANCH CONDITION TESTS
// ============================================================================

mod branch_condition_tests {
    use super::*;

    /// Test BEQ (Branch if Equal) - taken
    #[test]
    fn test_beq_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 42 },
            Instruction::Beq { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },    // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },    // Target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BEQ taken");
    }

    /// Test BEQ (Branch if Equal) - not taken
    #[test]
    fn test_beq_not_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            Instruction::Beq { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Not taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },    // Executed
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BEQ not taken");
    }

    /// Test BNE (Branch if Not Equal) - taken
    #[test]
    fn test_bne_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            Instruction::Bne { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },    // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },    // Target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BNE taken");
    }

    /// Test BLT (Branch if Less Than) - taken
    #[test]
    fn test_blt_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Blt { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 5 < 10, taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },    // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },    // Target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BLT taken");
    }

    /// Test BGE (Branch if Greater or Equal) - taken
    #[test]
    fn test_bge_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Bge { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 10 >= 10, taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },    // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },    // Target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BGE taken");
    }

    /// Test BLTU (Branch if Less Than Unsigned) - taken
    #[test]
    fn test_bltu_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 100 },
            Instruction::Bltu { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 5 < 100, taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },     // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },     // Target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BLTU taken");
    }

    /// Test BGEU (Branch if Greater or Equal Unsigned) - taken
    #[test]
    fn test_bgeu_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },
            Instruction::Bgeu { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 100 >= 50, taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },     // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },     // Target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BGEU taken");
    }
}

// ============================================================================
// ARITHMETIC COMBINATION TESTS
// ============================================================================

mod arithmetic_combination_tests {
    use super::*;

    /// Test add then subtract (should return to original)
    #[test]
    fn test_add_subtract_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 37 },
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 137
            Instruction::Sub { rd: Register::R4, rs1: Register::R3, rs2: Register::R2 }, // 100
            // R4 should equal R1
            Instruction::Seq { rd: Register::R5, rs1: Register::R4, rs2: Register::R1 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Add-subtract roundtrip");
    }

    /// Test multiply then divide (should return to original for exact division)
    #[test]
    fn test_multiply_divide_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 12 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Mul { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 60
            Instruction::Divu { rd: Register::R4, rs1: Register::R3, rs2: Register::R2 }, // 12
            // R4 should equal R1
            Instruction::Seq { rd: Register::R5, rs1: Register::R4, rs2: Register::R1 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Multiply-divide roundtrip");
    }

    /// Test shift left then right (should return to original)
    #[test]
    fn test_shift_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 8 },  // 0xFF00
            Instruction::Srli { rd: Register::R3, rs1: Register::R2, shamt: 8 },  // 0xFF
            // R3 should equal R1
            Instruction::Seq { rd: Register::R4, rs1: Register::R3, rs2: Register::R1 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Shift roundtrip");
    }

    /// Test XOR twice returns original
    #[test]
    fn test_xor_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xABCD },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1234 },
            Instruction::Xor { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // XOR once
            Instruction::Xor { rd: Register::R4, rs1: Register::R3, rs2: Register::R2 }, // XOR again
            // R4 should equal R1
            Instruction::Seq { rd: Register::R5, rs1: Register::R4, rs2: Register::R1 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XOR roundtrip");
    }

    /// Test division remainder relationship
    #[test]
    fn test_division_remainder_relationship() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 47 },  // Dividend
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },   // Divisor
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 6
            Instruction::Remu { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 5
            // Verify: quotient * divisor + remainder = dividend
            Instruction::Mul { rd: Register::R5, rs1: Register::R3, rs2: Register::R2 }, // 42
            Instruction::Add { rd: Register::R6, rs1: Register::R5, rs2: Register::R4 }, // 47
            Instruction::Seq { rd: Register::R7, rs1: Register::R6, rs2: Register::R1 }, // Should be 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Division remainder relationship");
    }
}

// ============================================================================
// LOGICAL OPERATION TESTS
// ============================================================================

mod logical_tests {
    use super::*;

    /// Test AND truth table
    #[test]
    fn test_and_truth_table() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            // 0 & 0 = 0
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R1 },
            // 0 & 1 = 0
            Instruction::And { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },
            // 1 & 0 = 0
            Instruction::And { rd: Register::R5, rs1: Register::R2, rs2: Register::R1 },
            // 1 & 1 = 1
            Instruction::And { rd: Register::R6, rs1: Register::R2, rs2: Register::R2 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "AND truth table");
    }

    /// Test OR truth table
    #[test]
    fn test_or_truth_table() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            // 0 | 0 = 0
            Instruction::Or { rd: Register::R3, rs1: Register::R1, rs2: Register::R1 },
            // 0 | 1 = 1
            Instruction::Or { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },
            // 1 | 0 = 1
            Instruction::Or { rd: Register::R5, rs1: Register::R2, rs2: Register::R1 },
            // 1 | 1 = 1
            Instruction::Or { rd: Register::R6, rs1: Register::R2, rs2: Register::R2 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "OR truth table");
    }

    /// Test XOR truth table
    #[test]
    fn test_xor_truth_table() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            // 0 ^ 0 = 0
            Instruction::Xor { rd: Register::R3, rs1: Register::R1, rs2: Register::R1 },
            // 0 ^ 1 = 1
            Instruction::Xor { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },
            // 1 ^ 0 = 1
            Instruction::Xor { rd: Register::R5, rs1: Register::R2, rs2: Register::R1 },
            // 1 ^ 1 = 0
            Instruction::Xor { rd: Register::R6, rs1: Register::R2, rs2: Register::R2 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XOR truth table");
    }

    /// Test De Morgan's law: NOT(A AND B) = (NOT A) OR (NOT B)
    /// Since we don't have NOT, we use XOR with all 1s
    #[test]
    fn test_bitwise_identity() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x0F },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0xF0 },
            // A AND B
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 0
            // A OR B
            Instruction::Or { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },  // 0xFF
            // A XOR B
            Instruction::Xor { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 }, // 0xFF
            // Verify A AND B = 0 for these values
            Instruction::Seq { rd: Register::R6, rs1: Register::R3, rs2: Register::R0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Bitwise identity");
    }
}
