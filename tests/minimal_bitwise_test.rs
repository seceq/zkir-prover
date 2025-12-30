//! Minimal bitwise test - no ADDI, just pure bitwise operation
//! This test checks if bitwise constraints work in isolation

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::r#trait::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_witness;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

#[test]
fn test_minimal_and() {
    // Create a program with ONLY AND and EBREAK
    // We'll rely on registers being initialized to specific values somehow
    // OR we can use a program that does: and r1, r0, r0 (which should give 0 & 0 = 0)
    let header = ProgramHeader::new();

    let instructions = vec![
        // AND R1, R0, R0  -> R1 = 0 & 0 = 0
        // This is safe because R0 is always zero
        Instruction::And {
            rd: Register::R1,
            rs1: Register::R0,
            rs2: Register::R0,
        },
        Instruction::Ebreak,
    ];

    let code: Vec<u32> = instructions.iter().map(|inst| encode(inst)).collect();

    let program = Program {
        header,
        code,
        data: Vec::new(),
    };

    println!("\n=== Minimal AND Test ===");
    println!("Program: AND R1, R0, R0 (should compute 0 & 0 = 0)");

    let inputs = vec![];
    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), inputs.clone(), vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("VM executed {} cycles", result.cycles);

    let witness = vm_result_to_witness(&program, &inputs, result)
        .expect("Witness conversion failed");

    println!("Witness has {} trace rows", witness.trace.len());

    // Print trace details
    for (i, row) in witness.trace.iter().enumerate() {
        let opcode = row.instruction & 0x7F;
        let rd = (row.instruction >> 7) & 0xF;
        let rs1 = (row.instruction >> 11) & 0xF;
        let rs2 = (row.instruction >> 15) & 0xF;
        println!("\nRow {}: inst=0x{:08X}, opcode=0x{:02X}, rd={}, rs1={}, rs2={}",
                 i, row.instruction, opcode, rd, rs1, rs2);
        println!("  R0={:?}, R1={:?}, R2={:?}",
                 row.registers.get(0),
                 row.registers.get(1),
                 row.registers.get(2));
    }

    // Try to generate proof
    let backend = Plonky3Backend::test_config();
    let proof = backend
        .prove(&witness)
        .expect("Proof generation failed");

    backend
        .verify(&proof, &proof.verifying_key)
        .expect("Proof verification failed");

    println!("\nMinimal AND test passed!");
}
