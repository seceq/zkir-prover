//! End-to-End Proving Example
//!
//! This example demonstrates the complete workflow for proving ZKIR programs:
//! 1. Compile a program
//! 2. Execute it with inputs
//! 3. Generate a cryptographic proof
//! 4. Verify the proof
//!
//! This showcases the new high-level API that makes proving ZKIR programs
//! as simple as calling `prove_program()`.

use zkir_prover::vm_integration::VMProver;
use zkir_spec::{Instruction, Program, Register};

fn main() {
    println!("=== ZKIR End-to-End Proving Example ===\n");

    // Create a simple program: compute sum of two numbers
    let program = create_sum_program();
    println!("Program created: Sum two numbers");
    println!("  Instructions: {}", program.code.len());

    // Set up inputs
    let inputs = vec![42, 100];
    println!("\nInputs: {:?}", inputs);

    // Create prover (using fast test config for this example)
    println!("\nInitializing prover (fast test configuration)...");
    let prover = VMProver::fast_test_config();

    // Prove the program execution
    println!("Executing program and generating proof...");
    let start = std::time::Instant::now();
    let (proof, vk) = prover
        .prove_program(&program, &inputs)
        .expect("Proof generation failed");
    let prove_time = start.elapsed();

    println!("Proof generated successfully");
    println!("  Time: {:?}", prove_time);
    println!("  Proof size: {} bytes", bincode::serialize(&proof).unwrap().len());

    // Verify the proof
    println!("\nVerifying proof...");
    let start = std::time::Instant::now();
    let verified = prover.verify(&proof, &vk).expect("Verification failed");
    let verify_time = start.elapsed();

    println!("Proof verified successfully");
    println!("  Time: {:?}", verify_time);
    println!("  Valid: {}", verified);

    // Display proof statistics
    println!("\nProof statistics:");
    println!("  Cycles: {}", proof.metadata.num_cycles);
    println!("  Trace height: {}", proof.metadata.trace_height);
    println!("  Public inputs: {} values", proof.public_inputs.len());
    println!("  Public outputs: {} values", proof.public_outputs.len());

    println!("\n=== Example Complete ===");
    println!("\nKey takeaways:");
    println!("  - VM integration enables automated witness collection");
    println!("  - High-level API simplifies proving: just call prove_program()");
    println!("  - Proof generation and verification are fast");
    println!("  - Proofs can be serialized and verified independently");
}

/// Create a program that computes the sum of two numbers
fn create_sum_program() -> Program {
    let instructions = vec![
        // R1 = 10
        Instruction::Addi {
            rd: Register::R1,
            rs1: Register::R0,
            imm: 10,
        },
        // R2 = 20
        Instruction::Addi {
            rd: Register::R2,
            rs1: Register::R0,
            imm: 20,
        },
        // R3 = R1 + R2 (= 30)
        Instruction::Add {
            rd: Register::R3,
            rs1: Register::R1,
            rs2: Register::R2,
        },
        // Exit
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
