//! Compare ADD (which works) vs ADDI+AND (which fails)

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::r#trait::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_witness;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

#[test]
fn test_just_addi() {
    // Test with JUST ADDI, no bitwise
    let header = ProgramHeader::new();

    let instructions = vec![
        Instruction::Addi {
            rd: Register::R3,
            rs1: Register::R0,
            imm: 12,
        },
        Instruction::Ebreak,
    ];

    let code: Vec<u32> = instructions.iter().map(|inst| encode(inst)).collect();

    let program = Program {
        header,
        code,
        data: Vec::new(),
    };

    println!("\n=== Test: Just ADDI R3, R0, 12 ===");

    let inputs = vec![42, 100];  // Provide inputs like the working test
    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), inputs.clone(), vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("VM executed {} cycles", result.cycles);

    let witness = vm_result_to_witness(&program, &inputs, result)
        .expect("Witness conversion failed");

    println!("Witness has {} rows", witness.trace.len());

    if !witness.trace.is_empty() {
        let row = &witness.trace[0];
        println!("Row 0: opcode=0x{:02X}", row.instruction & 0x7F);
        if row.registers.len() > 3 {
            println!("  R2: [{}, {}]", row.registers[2][0], row.registers[2][1]);
            println!("  R3: [{}, {}]", row.registers[3][0], row.registers[3][1]);
        }
    }

    let backend = Plonky3Backend::test_config();
    let proof = backend
        .prove(&witness)
        .expect("Proof generation failed");

    backend
        .verify(&proof, &proof.verifying_key)
        .expect("Proof verification failed");

    println!("Just ADDI test passed!\n");
}

#[test]
fn test_add_then_ebreak() {
    // Test with ADD (which we know works)
    let header = ProgramHeader::new();

    let instructions = vec![
        Instruction::Add {
            rd: Register::R3,
            rs1: Register::R0,
            rs2: Register::R1,
        },
        Instruction::Ebreak,
    ];

    let code: Vec<u32> = instructions.iter().map(|inst| encode(inst)).collect();

    let program = Program {
        header,
        code,
        data: Vec::new(),
    };

    println!("\n=== Test: ADD R3, R0, R1 ===");

    let inputs = vec![42, 100];  // Provide inputs like the working test
    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), inputs.clone(), vm_config);
    let result = vm.run().expect("VM execution failed");

    println!("VM executed {} cycles", result.cycles);

    let witness = vm_result_to_witness(&program, &inputs, result)
        .expect("Witness conversion failed");

    println!("Witness has {} rows", witness.trace.len());

    if !witness.trace.is_empty() {
        let row = &witness.trace[0];
        println!("Row 0: opcode=0x{:02X}", row.instruction & 0x7F);
        if row.registers.len() > 3 {
            println!("  R2: [{}, {}]", row.registers[2][0], row.registers[2][1]);
            println!("  R3: [{}, {}]", row.registers[3][0], row.registers[3][1]);
        }
    }

    let backend = Plonky3Backend::test_config();
    let proof = backend
        .prove(&witness)
        .expect("Proof generation failed");

    backend
        .verify(&proof, &proof.verifying_key)
        .expect("Proof verification failed");

    println!("ADD test passed!\n");
}
