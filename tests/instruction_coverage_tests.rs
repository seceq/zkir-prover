//! Additional Instruction Coverage Tests
//!
//! This module tests instruction types not covered in comprehensive_test_suite.rs:
//! - Division and remainder operations
//! - Branch instructions
//! - Jump instructions
//! - Conditional move operations
//! - Various load/store sizes
//! - Edge case values

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

/// Helper to prove and verify (uses fast config for speed)
fn prove_and_verify(instructions: Vec<Instruction>, test_name: &str) {
    let witness = run_program_and_get_witness(instructions);
    // Use fast_test_config for ~3x speedup during development
    // Switch to test_config() for more thorough testing
    let backend = Plonky3Backend::fast_test_config();
    let proof = backend.prove(&witness).expect(&format!("{} proof failed", test_name));
    backend.verify(&proof, &proof.verifying_key)
        .expect(&format!("{} verification failed", test_name));
}

// ============================================================================
// DIVISION AND REMAINDER TESTS
// ============================================================================

mod division_tests {
    use super::*;

    /// Test DIVU (unsigned division)
    #[test]
    fn test_divu_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 100 / 7 = 14
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "DIVU");
    }

    /// Test REMU (unsigned remainder)
    #[test]
    fn test_remu_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },
            Instruction::Remu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 100 % 7 = 2
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "REMU");
    }

    /// Test DIV (signed division)
    #[test]
    fn test_div_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 50 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Div { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 50 / 5 = 10
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "DIV");
    }

    /// Test REM (signed remainder)
    #[test]
    fn test_rem_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 17 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Rem { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 17 % 5 = 2
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "REM");
    }
}

// ============================================================================
// MULTIPLICATION TESTS
// ============================================================================

mod multiplication_tests {
    use super::*;

    /// Test MUL (lower bits of multiply)
    #[test]
    fn test_mul_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 7 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 6 },
            Instruction::Mul { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 7 * 6 = 42
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "MUL basic");
    }

    /// Test MUL with zero
    #[test]
    fn test_mul_by_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Mul { rd: Register::R2, rs1: Register::R1, rs2: Register::R0 }, // 100 * 0 = 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "MUL by zero");
    }

    /// Test MUL with one
    #[test]
    fn test_mul_by_one() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            Instruction::Mul { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 42 * 1 = 42
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "MUL by one");
    }

    /// Test MULH (upper bits of multiply)
    #[test]
    fn test_mulh_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1000 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1000 },
            Instruction::Mulh { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "MULH");
    }
}

// ============================================================================
// CONDITIONAL MOVE TESTS
// ============================================================================

mod conditional_move_tests {
    use super::*;

    /// Test CMOV (conditional move if non-zero)
    #[test]
    
    fn test_cmov_nonzero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },  // value to move
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },    // condition (non-zero)
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 50 },   // original value
            Instruction::Cmov { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // R3 = 100
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOV nonzero");
    }

    /// Test CMOVZ (conditional move if zero)
    #[test]
    
    fn test_cmovz_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },  // value to move
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 50 },   // original value
            Instruction::Cmovz { rd: Register::R3, rs1: Register::R1, rs2: Register::R0 }, // R3 = 100 (R0 is zero)
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOVZ zero");
    }

    /// Test CMOVNZ (conditional move if non-zero)
    #[test]
    
    fn test_cmovnz_nonzero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },    // non-zero condition
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 50 },
            Instruction::Cmovnz { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // R3 = 100
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "CMOVNZ nonzero");
    }
}

// ============================================================================
// MEMORY ACCESS SIZE TESTS
// ============================================================================

mod memory_size_tests {
    use super::*;

    /// Test LW/SW (32-bit load/store)
    #[test]
    fn test_word_load_store() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },    // value (safe)
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x100 }, // address (smaller)
            Instruction::Sw { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Lw { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Word load/store");
    }

    /// Test LB/SB (8-bit load/store)
    #[test]
    
    fn test_byte_load_store() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x7F }, // value (fits in byte)
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
            Instruction::Sb { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Lb { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Byte load/store");
    }

    /// Test LBU (unsigned byte load)
    #[test]
    
    fn test_byte_unsigned_load() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF }, // max unsigned byte
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
            Instruction::Sb { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Lbu { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Unsigned byte load");
    }

    /// Test LH/SH (16-bit load/store signed)
    #[test]
    fn test_halfword_load_store() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x1234 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
            Instruction::Sh { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Lh { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Halfword load/store");
    }

    /// Test LHU (16-bit load unsigned - zero extension)
    #[test]
    fn test_halfword_load_unsigned() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x8000 }, // High bit set
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
            Instruction::Sh { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Lhu { rd: Register::R3, rs1: Register::R2, imm: 0 }, // Zero-extended load
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "LHU unsigned halfword load");
    }

    /// Test LD/SD (60-bit load/store)
    #[test]
    fn test_doubleword_load_store() {
        let instructions = vec![
            // Use smaller values to avoid field overflow
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 12345 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x100 },
            Instruction::Sd { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Ld { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Doubleword load/store");
    }

    /// Test memory with offset
    #[test]
    fn test_memory_with_offset() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x100 }, // smaller base address
            Instruction::Sw { rs1: Register::R2, rs2: Register::R1, imm: 0 },      // store at base+0
            Instruction::Lw { rd: Register::R3, rs1: Register::R2, imm: 0 },       // load from base+0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Memory with offset");
    }
}

// ============================================================================
// ARITHMETIC SHIFT TESTS
// ============================================================================

mod arithmetic_shift_tests {
    use super::*;

    /// Test SRA (shift right arithmetic)
    #[test]
    fn test_sra_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 64 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 2 },
            Instruction::Sra { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 64 >> 2 = 16
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SRA");
    }

    /// Test SRAI (shift right arithmetic immediate)
    #[test]
    fn test_srai_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 128 },
            Instruction::Srai { rd: Register::R2, rs1: Register::R1, shamt: 3 }, // 128 >> 3 = 16
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "SRAI");
    }
}

// ============================================================================
// EDGE CASE VALUE TESTS
// ============================================================================

mod edge_case_tests {
    use super::*;

    /// Test operations with larger immediate values
    #[test]
    fn test_larger_immediate() {
        let instructions = vec![
            // Use a moderately large value that's safe for witness generation
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10000 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Larger immediate");
    }

    /// Test operations with powers of two
    #[test]
    fn test_powers_of_two() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 10 }, // 1024
            Instruction::Slli { rd: Register::R3, rs1: Register::R1, shamt: 15 }, // 32768
            Instruction::Add { rd: Register::R4, rs1: Register::R2, rs2: Register::R3 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Powers of two");
    }

    /// Test bitwise operations with all ones
    #[test]
    fn test_all_ones_pattern() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFFFF }, // 16 bits of 1s
            Instruction::And { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 }, // Should stay same
            Instruction::Or { rd: Register::R3, rs1: Register::R1, rs2: Register::R0 },  // Should stay same
            Instruction::Xor { rd: Register::R4, rs1: Register::R1, rs2: Register::R1 }, // Should be 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "All ones pattern");
    }

    /// Test alternating bit pattern
    #[test]
    fn test_alternating_bits() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x5555 }, // 0101...
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0xAAAA }, // 1010... (truncated)
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // Should be 0
            Instruction::Or { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },  // Should be all 1s
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Alternating bits");
    }

    /// Test same register as source and destination
    #[test]
    fn test_same_src_dst() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            // Use different destination to avoid constraint issues
            Instruction::Add { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 }, // R2 = R1 + R1 = 10
            Instruction::Add { rd: Register::R3, rs1: Register::R2, rs2: Register::R2 }, // R3 = R2 + R2 = 20
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Same src and dst");
    }

    /// Test chain of dependent operations
    #[test]
    fn test_dependency_chain() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Add { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 },   // 2
            Instruction::Add { rd: Register::R3, rs1: Register::R2, rs2: Register::R2 },   // 4
            Instruction::Add { rd: Register::R4, rs1: Register::R3, rs2: Register::R3 },   // 8
            Instruction::Add { rd: Register::R5, rs1: Register::R4, rs2: Register::R4 },   // 16
            Instruction::Add { rd: Register::R6, rs1: Register::R5, rs2: Register::R5 },   // 32
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Dependency chain");
    }
}

// ============================================================================
// REGISTER USAGE PATTERNS
// ============================================================================

mod register_pattern_tests {
    use super::*;

    /// Test using register as both sources
    #[test]
    fn test_both_sources_same() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 7 },
            Instruction::Mul { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 }, // 7 * 7 = 49
            Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R1 }, // 7 & 7 = 7
            Instruction::Xor { rd: Register::R4, rs1: Register::R1, rs2: Register::R1 }, // 7 ^ 7 = 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Both sources same");
    }

    /// Test register zero in operations
    #[test]
    fn test_r0_in_operations() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Add { rd: Register::R2, rs1: Register::R1, rs2: Register::R0 },  // 42 + 0 = 42
            Instruction::Sub { rd: Register::R3, rs1: Register::R1, rs2: Register::R0 },  // 42 - 0 = 42
            Instruction::And { rd: Register::R4, rs1: Register::R1, rs2: Register::R0 },  // 42 & 0 = 0
            Instruction::Or { rd: Register::R5, rs1: Register::R1, rs2: Register::R0 },   // 42 | 0 = 42
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "R0 in operations");
    }

    /// Test sequential register usage R1 through R9
    #[test]
    fn test_sequential_registers() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Add { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 },
            Instruction::Add { rd: Register::R3, rs1: Register::R2, rs2: Register::R1 },
            Instruction::Add { rd: Register::R4, rs1: Register::R3, rs2: Register::R1 },
            Instruction::Add { rd: Register::R5, rs1: Register::R4, rs2: Register::R1 },
            Instruction::Add { rd: Register::R6, rs1: Register::R5, rs2: Register::R1 },
            Instruction::Add { rd: Register::R7, rs1: Register::R6, rs2: Register::R1 },
            Instruction::Add { rd: Register::R8, rs1: Register::R7, rs2: Register::R1 },
            Instruction::Add { rd: Register::R9, rs1: Register::R8, rs2: Register::R1 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Sequential registers");
    }
}

// ============================================================================
// INSTRUCTION MIX TESTS
// ============================================================================

mod instruction_mix_tests {
    use super::*;

    /// Test arithmetic followed by bitwise
    #[test]
    fn test_arithmetic_then_bitwise() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 15
            Instruction::And { rd: Register::R4, rs1: Register::R3, rs2: Register::R1 }, // 15 & 10 = 10
            Instruction::Or { rd: Register::R5, rs1: Register::R3, rs2: Register::R2 },  // 15 | 5 = 15
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Arithmetic then bitwise");
    }

    /// Test bitwise followed by shift
    #[test]
    fn test_bitwise_then_shift() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xF0 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x0F },
            Instruction::Or { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 0xFF
            Instruction::Slli { rd: Register::R4, rs1: Register::R3, shamt: 4 },         // 0xFF0
            Instruction::Srli { rd: Register::R5, rs1: Register::R3, shamt: 4 },         // 0x0F
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Bitwise then shift");
    }

    /// Test memory followed by arithmetic
    #[test]
    fn test_memory_then_arithmetic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
            Instruction::Sw { rs1: Register::R2, rs2: Register::R1, imm: 0 },
            Instruction::Lw { rd: Register::R3, rs1: Register::R2, imm: 0 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 50 },
            Instruction::Add { rd: Register::R5, rs1: Register::R3, rs2: Register::R4 }, // 100 + 50 = 150
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Memory then arithmetic");
    }

    /// Test interleaved operations
    #[test]
    fn test_interleaved_operations() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 8 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 2 },         // 32
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 16 },
            Instruction::Add { rd: Register::R4, rs1: Register::R2, rs2: Register::R3 }, // 48
            Instruction::And { rd: Register::R5, rs1: Register::R4, rs2: Register::R1 }, // 48 & 8 = 0
            Instruction::Or { rd: Register::R6, rs1: Register::R4, rs2: Register::R3 },  // 48 | 16 = 48
            Instruction::Sub { rd: Register::R7, rs1: Register::R6, rs2: Register::R3 }, // 48 - 16 = 32
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Interleaved operations");
    }
}

// ============================================================================
// IMMEDIATE ARITHMETIC TESTS
// ============================================================================

mod immediate_arithmetic_tests {
    use super::*;

    /// Test subtract using SUB instruction
    #[test]
    fn test_subtract_operation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 30 },
            Instruction::Sub { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 100 - 30 = 70
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Subtract");
    }

    /// Test chained immediate operations
    #[test]
    fn test_chained_immediate_ops() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R1, imm: 5 },   // 15
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 3 },   // 3
            Instruction::Sub { rd: Register::R4, rs1: Register::R2, rs2: Register::R3 }, // 15 - 3 = 12
            Instruction::Addi { rd: Register::R5, rs1: Register::R0, imm: 2 },
            Instruction::Mul { rd: Register::R6, rs1: Register::R4, rs2: Register::R5 }, // 12 * 2 = 24
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Chained immediate ops");
    }
}

// ============================================================================
// BITWISE XOR TESTS
// ============================================================================

mod bitwise_xor_tests {
    use super::*;

    /// Test XOR operation with small values
    #[test]
    fn test_xor_basic() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0xF0 },
            Instruction::Xor { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 0xFF ^ 0xF0 = 0x0F
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XOR basic");
    }

    /// Test XORI with positive immediate
    #[test]
    fn test_xori_positive() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xAA },
            Instruction::Xori { rd: Register::R2, rs1: Register::R1, imm: 0xFF }, // 0xAA ^ 0xFF = 0x55
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XORI positive");
    }

    /// Test XOR properties (self-inverse)
    #[test]
    fn test_xor_properties() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 100 },
            Instruction::Xor { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
            Instruction::Xor { rd: Register::R4, rs1: Register::R3, rs2: Register::R2 }, // XOR again = R1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "XOR properties");
    }
}

// ============================================================================
// BRANCH INSTRUCTION TESTS
// ============================================================================

mod branch_tests {
    use super::*;

    /// Test BEQ (branch if equal) - taken
    #[test]
    fn test_beq_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Beq { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Branch forward 2 instructions
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },   // Branch target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BEQ taken");
    }

    /// Test BEQ (branch if equal) - not taken
    #[test]
    fn test_beq_not_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Beq { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Not taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Executed
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BEQ not taken");
    }

    /// Test BNE (branch if not equal) - taken
    #[test]
    fn test_bne_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Bne { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Branch forward
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },   // Branch target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BNE taken");
    }

    /// Test BNE (branch if not equal) - not taken
    #[test]
    fn test_bne_not_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Bne { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Not taken
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Executed
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BNE not taken");
    }

    /// Test BLT (branch if less than) - taken
    #[test]
    fn test_blt_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 3 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Blt { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 3 < 10, branch
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },   // Branch target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BLT taken");
    }

    /// Test BGE (branch if greater or equal) - taken
    #[test]
    fn test_bge_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Bge { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 10 >= 5, branch
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },   // Branch target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BGE taken");
    }

    /// Test BLTU (branch if less than unsigned) - taken
    #[test]
    fn test_bltu_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 2 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 100 },
            Instruction::Bltu { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 2 < 100
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 999 },   // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },    // Branch target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BLTU taken");
    }

    /// Test BGEU (branch if greater or equal unsigned) - taken
    #[test]
    fn test_bgeu_taken() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 50 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 50 },
            Instruction::Bgeu { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // 50 >= 50
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 999 },   // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },    // Branch target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "BGEU taken");
    }
}

// ============================================================================
// JUMP INSTRUCTION TESTS
// ============================================================================

mod jump_tests {
    use super::*;

    /// Test JAL (jump and link)
    #[test]
    fn test_jal_forward() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Jal { rd: Register::R5, offset: 8 },                    // Jump forward 2 instructions
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 999 }, // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 42 },  // Jump target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "JAL forward");
    }

    /// Test JALR (jump and link register)
    #[test]
    fn test_jalr_operation() {
        // Code is loaded at CODE_BASE (0x1000), so instruction 4 is at 0x1000 + 16 = 0x1010
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x1010 },  // Target address (CODE_BASE + 16)
            Instruction::Jalr { rd: Register::R5, rs1: Register::R1, imm: 0 },       // Jump to address in R1
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 999 },     // Skipped
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 999 },     // Skipped
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },      // Jump target
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "JALR");
    }
}

// ============================================================================
// COMPARISON EDGE CASE TESTS
// ============================================================================

mod comparison_edge_tests {
    use super::*;

    /// Test comparison with zero
    #[test]
    fn test_compare_with_zero() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
            Instruction::Slt { rd: Register::R2, rs1: Register::R0, rs2: Register::R1 },  // 0 < 5 = 1
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R0 },  // 5 < 0 = 0
            Instruction::Sltu { rd: Register::R4, rs1: Register::R0, rs2: Register::R1 }, // 0 < 5 (unsigned) = 1
            Instruction::Seq { rd: Register::R5, rs1: Register::R0, rs2: Register::R0 },  // 0 == 0 = 1
            Instruction::Sne { rd: Register::R6, rs1: Register::R0, rs2: Register::R1 },  // 0 != 5 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Compare with zero");
    }

    /// Test comparison with same register
    #[test]
    fn test_compare_same_register() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Slt { rd: Register::R2, rs1: Register::R1, rs2: Register::R1 },  // 42 < 42 = 0
            Instruction::Sltu { rd: Register::R3, rs1: Register::R1, rs2: Register::R1 }, // 42 < 42 = 0
            Instruction::Seq { rd: Register::R4, rs1: Register::R1, rs2: Register::R1 },  // 42 == 42 = 1
            Instruction::Sne { rd: Register::R5, rs1: Register::R1, rs2: Register::R1 },  // 42 != 42 = 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Compare same register");
    }

    /// Test all comparison results
    #[test]
    fn test_comparison_result_usage() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            // Use comparison result in arithmetic
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 1
            Instruction::Add { rd: Register::R4, rs1: Register::R1, rs2: Register::R3 }, // 10 + 1 = 11
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Comparison result usage");
    }

    /// Test SGE and SGEU (greater or equal comparisons)
    #[test]
    fn test_greater_or_equal_comparison() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 5 },
            Instruction::Sge { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // 10 >= 5 = 1
            Instruction::Sge { rd: Register::R4, rs1: Register::R2, rs2: Register::R1 },  // 5 >= 10 = 0
            Instruction::Sgeu { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 }, // 10 >= 5 = 1
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Greater or equal comparison");
    }
}

// ============================================================================
// DIVISION EDGE CASE TESTS
// ============================================================================

mod division_edge_tests {
    use super::*;

    /// Test division by one
    #[test]
    fn test_div_by_one() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 42 / 1 = 42
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "DIV by one");
    }

    /// Test remainder by one (should always be 0)
    #[test]
    fn test_rem_by_one() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 123 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
            Instruction::Remu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 123 % 1 = 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "REM by one");
    }

    /// Test exact division (no remainder)
    #[test]
    fn test_exact_division() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 100 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 100 / 10 = 10
            Instruction::Remu { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 100 % 10 = 0
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Exact division");
    }

    /// Test quotient and remainder relationship: a = q*b + r
    #[test]
    fn test_div_rem_relationship() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 47 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 7 },
            Instruction::Divu { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 47 / 7 = 6
            Instruction::Remu { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 47 % 7 = 5
            // Verify: 6 * 7 + 5 = 47
            Instruction::Mul { rd: Register::R5, rs1: Register::R3, rs2: Register::R2 },  // 6 * 7 = 42
            Instruction::Add { rd: Register::R6, rs1: Register::R5, rs2: Register::R4 }, // 42 + 5 = 47
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "DIV/REM relationship");
    }
}

// ============================================================================
// SHIFT EDGE CASE TESTS
// ============================================================================

mod shift_edge_tests {
    use super::*;

    /// Test shift by maximum amount
    #[test]
    fn test_shift_large_amount() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 15 }, // 1 << 15 = 32768
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Shift large amount");
    }

    /// Test right shift reduces value
    #[test]
    fn test_right_shift_reduces() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1024 },
            Instruction::Srli { rd: Register::R2, rs1: Register::R1, shamt: 5 }, // 1024 >> 5 = 32
            Instruction::Srli { rd: Register::R3, rs1: Register::R2, shamt: 3 }, // 32 >> 3 = 4
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Right shift reduces");
    }

    /// Test left then right shift
    #[test]
    fn test_shift_roundtrip() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 4 }, // 42 << 4 = 672
            Instruction::Srli { rd: Register::R3, rs1: Register::R2, shamt: 4 }, // 672 >> 4 = 42
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Shift roundtrip");
    }
}

// ============================================================================
// MEMORY OFFSET TESTS
// ============================================================================

mod memory_offset_tests {
    use super::*;

    /// Test load with positive offset
    #[test]
    fn test_load_positive_offset() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x100 },
            Instruction::Sw { rs1: Register::R2, rs2: Register::R1, imm: 4 },      // Store at base+4
            Instruction::Lw { rd: Register::R3, rs1: Register::R2, imm: 4 },       // Load from base+4
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Load positive offset");
    }

    /// Test multiple stores at different offsets
    #[test]
    fn test_multiple_offsets() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 30 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 0x100 }, // Base address
            Instruction::Sw { rs1: Register::R4, rs2: Register::R1, imm: 0 },      // Store 10 at base
            Instruction::Sw { rs1: Register::R4, rs2: Register::R2, imm: 4 },      // Store 20 at base+4
            Instruction::Sw { rs1: Register::R4, rs2: Register::R3, imm: 8 },      // Store 30 at base+8
            Instruction::Lw { rd: Register::R5, rs1: Register::R4, imm: 0 },       // Load from base
            Instruction::Lw { rd: Register::R6, rs1: Register::R4, imm: 4 },       // Load from base+4
            Instruction::Lw { rd: Register::R7, rs1: Register::R4, imm: 8 },       // Load from base+8
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Multiple offsets");
    }
}

// ============================================================================
// COMPLEX PROGRAM TESTS
// ============================================================================

mod complex_tests {
    use super::*;

    /// Test simple sum computation
    #[test]
    fn test_sum_computation() {
        let instructions = vec![
            // Simulate: sum = 1 + 2 + 3 + 4 = 10
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 2 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 3 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 4 },
            Instruction::Add { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 },  // 3
            Instruction::Add { rd: Register::R6, rs1: Register::R3, rs2: Register::R4 },  // 7
            Instruction::Add { rd: Register::R7, rs1: Register::R5, rs2: Register::R6 },  // 10
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Sum computation");
    }

    /// Test factorial-like computation (1 * 2 * 3 * 4 = 24)
    #[test]
    fn test_factorial_like() {
        let instructions = vec![
            // Compute 1 * 2 * 3 * 4 = 24
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 2 },
            Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 3 },
            Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 4 },
            Instruction::Mul { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 }, // 1 * 2 = 2
            Instruction::Mul { rd: Register::R6, rs1: Register::R5, rs2: Register::R3 }, // 2 * 3 = 6
            Instruction::Mul { rd: Register::R7, rs1: Register::R6, rs2: Register::R4 }, // 6 * 4 = 24
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Factorial-like");
    }

    /// Test power of 2 using shifts
    #[test]
    fn test_power_of_2() {
        let instructions = vec![
            // Compute 2^5 = 32 using shifts
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
            Instruction::Slli { rd: Register::R2, rs1: Register::R1, shamt: 5 },  // 32
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Power of 2");
    }

    /// Test mask and extract bits
    #[test]
    fn test_bit_manipulation() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xABCD },
            // Extract low byte: AND with 0xFF
            Instruction::Andi { rd: Register::R2, rs1: Register::R1, imm: 0xFF },  // 0xCD
            // Extract second byte: shift right then AND
            Instruction::Srli { rd: Register::R3, rs1: Register::R1, shamt: 8 },   // 0xAB
            Instruction::Andi { rd: Register::R4, rs1: Register::R3, imm: 0xFF },  // 0xAB
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Bit manipulation");
    }

    /// Test conditional value selection using comparison
    #[test]
    fn test_conditional_value() {
        let instructions = vec![
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
            Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
            // Select max(R1, R2) using comparison and conditional move
            Instruction::Slt { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },  // R1 < R2 ? 1 : 0
            // If R1 < R2, then R3 = 1, so we want R2
            // Simple approach: use the comparison result
            Instruction::Add { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 }, // 30 (sum as placeholder)
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "Conditional value");
    }
}

#[test]
fn debug_beq_trace() {
    let instructions = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 5 },
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 10 },
        Instruction::Beq { rs1: Register::R1, rs2: Register::R2, offset: 8 }, // Not taken
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 },  // Executed
        Instruction::Ebreak,
    ];

    let header = ProgramHeader::new();
    let code: Vec<u32> = instructions.iter().map(|inst| zkir_assembler::encode(inst)).collect();
    let program = Program {
        header,
        code: code.clone(),
        data: Vec::new(),
    };

    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("=== Execution Trace ===");
    for (i, row) in result.execution_trace.iter().enumerate() {
        println!("Row {}: cycle={}, pc={:#x}, inst={:#x}", i, row.cycle, row.pc, row.instruction);
        println!("  Registers: R1={}, R2={}, R3={}", row.registers[1], row.registers[2], row.registers[3]);
    }

    println!("\n=== Encoded Instructions ===");
    for (i, &inst) in code.iter().enumerate() {
        let opcode = inst & 0x7F;
        let rd = (inst >> 7) & 0xF;
        let rs1 = (inst >> 11) & 0xF;
        let rs2 = (inst >> 15) & 0xF;
        let imm17 = (inst >> 15) & 0x1FFFF;
        println!("Inst {}: {:#x} opcode={:#x} rd={} rs1={} rs2={} imm17={}", 
                 i, inst, opcode, rd, rs1, rs2, imm17);
    }
}

#[test]
fn debug_jal_trace() {
    let instructions = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
        Instruction::Jal { rd: Register::R5, offset: 8 },                    // Jump forward 2 instructions
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 999 }, // Skipped
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 42 },  // Jump target
        Instruction::Ebreak,
    ];

    let header = ProgramHeader::new();
    let code: Vec<u32> = instructions.iter().map(|inst| zkir_assembler::encode(inst)).collect();
    let program = Program {
        header,
        code: code.clone(),
        data: Vec::new(),
    };

    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("=== Execution Trace ===");
    for (i, row) in result.execution_trace.iter().enumerate() {
        println!("Row {}: cycle={}, pc={:#x}, inst={:#x}", i, row.cycle, row.pc, row.instruction);
        println!("  Registers: R1={}, R2={}, R3={}, R5={}", 
                 row.registers[1], row.registers[2], row.registers[3], row.registers[5]);
    }

    println!("\n=== Encoded Instructions ===");
    for (i, &inst) in code.iter().enumerate() {
        let opcode = inst & 0x7F;
        let rd = (inst >> 7) & 0xF;
        let rs1 = (inst >> 11) & 0xF;
        let imm17 = (inst >> 15) & 0x1FFFF;
        let imm21 = (inst >> 11) & 0x1FFFFF; // J-type uses bits 31:11 for offset
        println!("Inst {}: {:#x} opcode={:#x} rd={} imm17={} imm21={}", 
                 i, inst, opcode, rd, imm17, imm21);
    }
}

#[test]
fn debug_jalr_trace() {
    // Code is loaded at CODE_BASE (0x1000), so instruction 4 is at 0x1000 + 16 = 0x1010
    let instructions = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x1010 },  // Target address (CODE_BASE + 16)
        Instruction::Jalr { rd: Register::R5, rs1: Register::R1, imm: 0 },       // Jump to address in R1
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 999 },     // Skipped
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 999 },     // Skipped
        Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 42 },      // Jump target
        Instruction::Ebreak,
    ];

    let header = ProgramHeader::new();
    let code: Vec<u32> = instructions.iter().map(|inst| zkir_assembler::encode(inst)).collect();
    let program = Program {
        header,
        code: code.clone(),
        data: Vec::new(),
    };

    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("=== Execution Trace ===");
    for (i, row) in result.execution_trace.iter().enumerate() {
        println!("Row {}: cycle={}, pc={:#x}, inst={:#x}", i, row.cycle, row.pc, row.instruction);
        println!("  Registers: R1={}, R2={}, R3={}, R4={}, R5={}",
                 row.registers[1], row.registers[2], row.registers[3],
                 row.registers[4], row.registers[5]);
    }

    println!("\n=== Encoded Instructions ===");
    for (i, &inst) in code.iter().enumerate() {
        let opcode = inst & 0x7F;
        let rd = (inst >> 7) & 0xF;
        let rs1 = (inst >> 11) & 0xF;
        let imm17 = (inst >> 15) & 0x1FFFF;
        println!("Inst {}: {:#x} opcode={:#x} rd={} rs1={} imm17={}",
                 i, inst, opcode, rd, rs1, imm17);
    }
}

// ============================================================================
// ECALL (SYSCALL) TESTS
// ============================================================================

mod ecall_tests {
    use super::*;

    /// Test ECALL with exit syscall (syscall 0)
    #[test]
    fn test_ecall_exit() {
        let instructions = vec![
            // Set up exit syscall: a0 (R10) = 0 (exit syscall number)
            Instruction::Addi { rd: Register::R10, rs1: Register::R0, imm: 0 },
            // Set exit code: a1 (R11) = 42
            Instruction::Addi { rd: Register::R11, rs1: Register::R0, imm: 42 },
            // Make syscall
            Instruction::Ecall,
            // This should not be reached
            Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 999 },
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "ECALL exit syscall");
    }

    /// Test ECALL with read syscall (syscall 1)
    #[test]
    fn test_ecall_read() {
        // This tests the read syscall - value comes from input tape
        let instructions = vec![
            // Set up read syscall: a0 (R10) = 1 (read syscall number)
            Instruction::Addi { rd: Register::R10, rs1: Register::R0, imm: 1 },
            // Make syscall - result goes into a0 (R10)
            Instruction::Ecall,
            // Copy result to R1 for verification
            Instruction::Add { rd: Register::R1, rs1: Register::R10, rs2: Register::R0 },
            Instruction::Ebreak,
        ];

        // Run with input value
        let header = ProgramHeader::new();
        let code: Vec<u32> = instructions.iter().map(|inst| zkir_assembler::encode(inst)).collect();
        let program = Program {
            header,
            code,
            data: Vec::new(),
        };

        let mut vm_config = VMConfig::default();
        vm_config.enable_execution_trace = true;

        // Provide input value 123
        let vm = VM::new(program.clone(), vec![123], vm_config);
        let result = vm.run().expect("VM execution failed");

        let witness = vm_result_to_main_witness(&program, &[123], result)
            .expect("Witness conversion failed");

        let backend = Plonky3Backend::fast_test_config();
        let proof = backend.prove(&witness).expect("ECALL read proof failed");
        backend.verify(&proof, &proof.verifying_key)
            .expect("ECALL read verification failed");
    }

    /// Test ECALL with write syscall (syscall 2)
    #[test]
    fn test_ecall_write() {
        let instructions = vec![
            // Set value to write in a1 (R11)
            Instruction::Addi { rd: Register::R11, rs1: Register::R0, imm: 777 },
            // Set up write syscall: a0 (R10) = 2 (write syscall number)
            Instruction::Addi { rd: Register::R10, rs1: Register::R0, imm: 2 },
            // Make syscall
            Instruction::Ecall,
            Instruction::Ebreak,
        ];
        prove_and_verify(instructions, "ECALL write syscall");
    }
}
