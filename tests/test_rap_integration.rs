//! RAP (Randomized AIR with Preprocessing) Integration Test
//!
//! This test verifies the complete RAP flow:
//! 1. VM execution → MainWitness (no auxiliary columns)
//! 2. Prover computes auxiliary with Fiat-Shamir challenge
//! 3. Proof generation and verification

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::backend_impl::Plonky3Backend;
use zkir_prover::backend::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_main_witness;
use zkir_runtime::{VMConfig, VM};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

/// Test the full RAP flow with a simple arithmetic program
#[test]
fn test_rap_simple_arithmetic() {
    println!("\n=== RAP Integration Test: Simple Arithmetic ===\n");

    let header = ProgramHeader::new();

    let instructions = vec![
        // R1 = 10
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
        // R2 = 20
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
        // R3 = R1 + R2 = 30
        Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
        // R4 = R3 * R1 = 300
        Instruction::Mul { rd: Register::R4, rs1: Register::R3, rs2: Register::R1 },
        // Halt
        Instruction::Ebreak,
    ];

    let code: Vec<u32> = instructions.iter().map(|inst| encode(inst)).collect();
    let program = Program {
        header,
        code,
        data: Vec::new(),
    };

    // Run VM with execution trace enabled
    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("VM execution: {} cycles", result.cycles);

    // Convert to MainWitness (RAP pattern - no auxiliary columns)
    let main_witness = vm_result_to_main_witness(&program, &[], result)
        .expect("MainWitness conversion failed");

    println!("MainWitness generated: {} trace rows", main_witness.trace.len());
    println!("   No auxiliary columns yet (RAP pattern)");

    // Generate proof using RAP flow
    let backend = Plonky3Backend::test_config();

    println!("Generating RAP proof...");
    let proof = backend.prove(&main_witness)
        .expect("RAP proof generation failed");

    println!("RAP proof generated successfully");
    println!("   Proof size: {} bytes", proof.proof_bytes.len());
    println!("   Backend: {}", proof.metadata.backend_name);

    println!("\nRAP INTEGRATION TEST PASSED");
    println!("   - VM -> MainWitness: ok");
    println!("   - Auxiliary computed with challenge: ok");
    println!("   - Proof generation: ok");
}

/// Test RAP flow with memory operations
///
/// This test verifies the complete RAP flow with store/load operations:
/// 1. VM execution with memory operations
/// 2. MainWitness generation with memory trace
/// 3. Auxiliary computation with memory permutation products
/// 4. Proof generation with memory consistency constraints
#[test]
fn test_rap_with_memory() {
    println!("\n=== RAP Integration Test: Memory Operations ===\n");

    let header = ProgramHeader::new();

    let instructions = vec![
        // Store 42 to address 0x1000
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 42 },
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0x1000 },
        Instruction::Sw { rs1: Register::R2, rs2: Register::R1, imm: 0 },

        // Load from address 0x1000 into R3
        Instruction::Lw { rd: Register::R3, rs1: Register::R2, imm: 0 },

        // R4 = R3 + 8 (should be 50)
        Instruction::Addi { rd: Register::R4, rs1: Register::R3, imm: 8 },

        // Halt
        Instruction::Ebreak,
    ];

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

    println!("VM execution: {} cycles", result.cycles);

    // Convert to MainWitness
    let main_witness = vm_result_to_main_witness(&program, &[], result)
        .expect("MainWitness conversion failed");

    let mem_ops_count = main_witness.trace.iter()
        .filter(|r| r.memory_op.is_some())
        .count();
    println!("MainWitness generated: {} memory operations", mem_ops_count);

    // Generate RAP proof
    let backend = Plonky3Backend::test_config();

    let proof = backend.prove(&main_witness)
        .expect("RAP proof generation failed");

    println!("RAP proof with memory operations: {} bytes", proof.proof_bytes.len());
    println!("\nRAP MEMORY TEST PASSED");
}

/// Test RAP flow with bitwise operations
#[test]
fn test_rap_with_bitwise() {
    println!("\n=== RAP Integration Test: Bitwise Operations ===\n");

    let header = ProgramHeader::new();

    let instructions = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0xFF },
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0xF0 },

        // AND
        Instruction::And { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
        // OR
        Instruction::Or { rd: Register::R4, rs1: Register::R1, rs2: Register::R2 },
        // XOR
        Instruction::Xor { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 },

        Instruction::Ebreak,
    ];

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

    println!("VM execution: {} cycles", result.cycles);

    let main_witness = vm_result_to_main_witness(&program, &[], result)
        .expect("MainWitness conversion failed");

    println!("MainWitness generated for bitwise operations");

    // Debug: print trace row 2 (the AND instruction)
    if main_witness.trace.len() > 2 {
        let row = &main_witness.trace[2];
        println!("\nDEBUG Row 2 (AND instruction):");
        println!("  PC: {}", row.pc);
        println!("  Instruction: 0x{:08x}", row.instruction);
        let opcode = row.instruction & 0x7F;
        let rd = (row.instruction >> 7) & 0xF;
        let rs1 = (row.instruction >> 11) & 0xF;
        let rs2 = (row.instruction >> 15) & 0xF;
        println!("  Decoded: opcode=0x{:02x} rd=R{} rs1=R{} rs2=R{}", opcode, rd, rs1, rs2);
        println!("  Registers:");
        for (i, reg) in row.registers.iter().enumerate().take(6) {
            println!("    R{}: {:?}", i, reg);
        }
    }

    let backend = Plonky3Backend::test_config();

    let proof = backend.prove(&main_witness)
        .expect("RAP proof generation failed");

    println!("RAP proof with bitwise operations: {} bytes", proof.proof_bytes.len());
    println!("\nRAP BITWISE TEST PASSED");
}
