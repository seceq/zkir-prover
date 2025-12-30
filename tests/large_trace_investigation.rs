//! Investigation of large-trace verification failure
//!
//! This test investigates the OodEvaluationMismatch error that occurs
//! when proving programs with ~7200+ cycles (in specific cases).

use zkir_prover::vm_integration::VMProver;
use zkir_spec::{Instruction, Program, Register};

fn create_accumulator_program(n: u32) -> Program {
    let mut instructions = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: n as i32 },
    ];

    let loop_start = instructions.len();
    instructions.push(Instruction::Add { rd: Register::R1, rs1: Register::R1, rs2: Register::R2 });
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R2, imm: 1 });
    instructions.push(Instruction::Addi { rd: Register::R4, rs1: Register::R3, imm: 1 });

    let current = instructions.len();
    // Branch offset is relative to the PC of the branch instruction
    // Target PC = loop_start * 4, Branch PC = current * 4
    // Offset = target - branch_pc = (loop_start - current) * 4
    let offset = ((loop_start as i32) - (current as i32)) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R2, rs2: Register::R4, offset });

    instructions.push(Instruction::Ebreak);

    let mut program = Program::new();
    program.code = instructions
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program.header.code_size = (program.code.len() * 4) as u32;
    program
}

/// Test to understand if the issue is related to register VALUE size
#[test]
fn test_value_size_hypothesis() {
    let prover = VMProver::fast_test_config();

    println!("Testing if the issue is related to accumulator VALUE size:");
    println!("{:>10} {:>15} {:>10} {:>10} {:>10}",
             "Iterations", "Final Sum", "Cycles", "Trace Ht", "Result");
    println!("{}", "-".repeat(60));

    // The accumulator computes sum = 1 + 2 + 3 + ... + n = n*(n+1)/2
    // At n=1440, sum = 1440*1441/2 = 1,037,520 (fits in 20 bits: 2^20 = 1,048,576)
    // At n=1450, sum = 1450*1451/2 = 1,051,975 (exceeds 20 bits!)

    for &n in &[1430, 1440, 1445, 1450, 1455, 1460] {
        let final_sum = n as u64 * (n as u64 + 1) / 2;
        let program = create_accumulator_program(n);
        let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
        let result = prover.verify(&proof, &vk);

        println!("{:>10} {:>15} {:>10} {:>10} {:>10}",
                 n, final_sum, proof.metadata.num_cycles, proof.metadata.trace_height,
                 if result.is_ok() { "PASS" } else { "FAIL" });
    }

    println!("\n20-bit max value: {}", (1u64 << 20) - 1);
    println!("21-bit max value: {}", (1u64 << 21) - 1);
}

/// Test with values that stay within 20 bits but many cycles
#[test]
fn test_many_cycles_small_values() {
    let prover = VMProver::fast_test_config();

    // Create a program that runs many cycles but keeps values small
    // by resetting the counter periodically
    let mut instructions = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },  // outer counter
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0 },  // inner counter
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 100 }, // inner limit
        Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 100 }, // outer limit
    ];

    // Outer loop
    let outer_loop_start = instructions.len();

    // Inner loop - increment R2 from 0 to 100
    let inner_loop_start = instructions.len();
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R2, imm: 1 });
    let current = instructions.len();
    let offset = ((inner_loop_start as i32) - (current as i32)) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R2, rs2: Register::R3, offset });

    // Reset inner counter, increment outer counter
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0 });
    instructions.push(Instruction::Addi { rd: Register::R1, rs1: Register::R1, imm: 1 });

    // Outer loop branch
    let current = instructions.len();
    let offset = ((outer_loop_start as i32) - (current as i32)) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R1, rs2: Register::R4, offset });

    instructions.push(Instruction::Ebreak);

    let mut program = Program::new();
    program.code = instructions
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program.header.code_size = (program.code.len() * 4) as u32;

    println!("Testing nested loop with small values (max 100):");
    let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
    println!("  Cycles: {}, Trace Height: {}", proof.metadata.num_cycles, proof.metadata.trace_height);

    let result = prover.verify(&proof, &vk);
    println!("  Result: {:?}", result);
}

/// Test to confirm: simple counter that stays in range works at high cycles
#[test]
fn test_simple_counter_high_cycles() {
    let prover = VMProver::fast_test_config();

    // Simple counter: just increment R1 many times but reset every 1000
    let mut instructions = vec![];

    instructions.push(Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 });
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0 }); // iteration counter
    // Set limit to 8000 using Addi in a loop (build up the value)
    instructions.push(Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 2000 });
    // R3 = 2000, let's add more to get to 8000
    instructions.push(Instruction::Add { rd: Register::R3, rs1: Register::R3, rs2: Register::R3 }); // 4000
    instructions.push(Instruction::Add { rd: Register::R3, rs1: Register::R3, rs2: Register::R3 }); // 8000

    let loop_start = instructions.len();
    // Increment R1, but wrap around using AND
    instructions.push(Instruction::Addi { rd: Register::R1, rs1: Register::R1, imm: 1 });
    // Keep R1 small by masking with 0x3FF (1023)
    instructions.push(Instruction::Andi { rd: Register::R1, rs1: Register::R1, imm: 0x3FF });
    // Increment counter
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R2, imm: 1 });

    let current = instructions.len();
    // Branch offset is relative to the PC of the branch instruction
    // Target PC = loop_start * 4, Branch PC = current * 4
    // Offset = target - branch_pc = (loop_start - current) * 4
    let offset = ((loop_start as i32) - (current as i32)) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R2, rs2: Register::R3, offset });

    instructions.push(Instruction::Ebreak);

    let mut program = Program::new();
    program.code = instructions
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program.header.code_size = (program.code.len() * 4) as u32;

    println!("Testing masked counter with 8000 iterations (values stay < 1024):");
    let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
    println!("  Cycles: {}, Trace Height: {}", proof.metadata.num_cycles, proof.metadata.trace_height);

    let result = prover.verify(&proof, &vk);
    println!("  Result: {:?}", result);
}

/// Test that confirms the issue is value overflow past 20 bits
#[test]
fn test_confirm_20bit_overflow_is_the_issue() {
    let prover = VMProver::fast_test_config();

    println!("\n=== CONFIRMING 20-BIT OVERFLOW HYPOTHESIS ===\n");

    // Test 1: Accumulator that stays just under 2^20
    // n*(n+1)/2 < 2^20 => n < ~1448
    println!("Test 1: Accumulator sum just under 2^20");
    let program1 = create_accumulator_program(1440);
    let (proof1, vk1) = prover.prove_program(&program1, &[]).expect("Proof failed");
    let result1 = prover.verify(&proof1, &vk1);
    let sum1 = 1440u64 * 1441 / 2;
    println!("  n=1440, sum={}, bits needed={}, result: {:?}",
             sum1, 64 - sum1.leading_zeros(), result1);

    // Test 2: Accumulator that goes just over 2^20
    println!("\nTest 2: Accumulator sum just over 2^20");
    let program2 = create_accumulator_program(1450);
    let (proof2, vk2) = prover.prove_program(&program2, &[]).expect("Proof failed");
    let result2 = prover.verify(&proof2, &vk2);
    let sum2 = 1450u64 * 1451 / 2;
    println!("  n=1450, sum={}, bits needed={}, result: {:?}",
             sum2, 64 - sum2.leading_zeros(), result2);

    // Test 3: Direct large value - shift left to create 2^20
    println!("\nTest 3: Create large value via shift");
    let instructions3 = vec![
        // Start with 1
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
        // Shift left by 20 bits to get 2^20 = 1,048,576
        Instruction::Slli { rd: Register::R1, rs1: Register::R1, shamt: 20 },
        Instruction::Ebreak,
    ];

    let mut program3 = Program::new();
    program3.code = instructions3
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program3.header.code_size = (program3.code.len() * 4) as u32;

    let (proof3, vk3) = prover.prove_program(&program3, &[]).expect("Proof failed");
    let result3 = prover.verify(&proof3, &vk3);
    println!("  SLLI by 20 (value=2^20), result: {:?}", result3);

    // Test 4: Value that definitely overflows - 2^21
    println!("\nTest 4: Very large value via shift (2^21)");
    let instructions4 = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1 },
        Instruction::Slli { rd: Register::R1, rs1: Register::R1, shamt: 21 },
        Instruction::Ebreak,
    ];

    let mut program4 = Program::new();
    program4.code = instructions4
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program4.header.code_size = (program4.code.len() * 4) as u32;

    let (proof4, vk4) = prover.prove_program(&program4, &[]).expect("Proof failed");
    let result4 = prover.verify(&proof4, &vk4);
    println!("  SLLI by 21 (value=2^21), result: {:?}", result4);

    // Test 5: Use MUL to create a large value
    println!("\nTest 5: Large value via MUL");
    let instructions5 = vec![
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 1024 }, // 2^10
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1024 }, // 2^10
        Instruction::Mul { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 }, // 2^20
        Instruction::Ebreak,
    ];

    let mut program5 = Program::new();
    program5.code = instructions5
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program5.header.code_size = (program5.code.len() * 4) as u32;

    let (proof5, vk5) = prover.prove_program(&program5, &[]).expect("Proof failed");
    let result5 = prover.verify(&proof5, &vk5);
    println!("  MUL 1024*1024 (value=2^20), result: {:?}", result5);
}

/// Find exact 20-bit boundary
#[test]
fn test_find_exact_overflow_point() {
    let prover = VMProver::fast_test_config();

    println!("Finding exact overflow point:");
    println!("2^20 = {}", 1u64 << 20);

    // Binary search for exact n where sum exceeds 2^20
    let mut low = 1440u32;
    let mut high = 1450u32;

    while high - low > 1 {
        let mid = (low + high) / 2;
        let sum = mid as u64 * (mid as u64 + 1) / 2;
        if sum < (1u64 << 20) {
            low = mid;
        } else {
            high = mid;
        }
    }

    println!("Exact boundary: n={} gives sum={} (< 2^20)", low, low as u64 * (low as u64 + 1) / 2);
    println!("                n={} gives sum={} (>= 2^20)", high, high as u64 * (high as u64 + 1) / 2);

    // Test both
    for &n in &[low, high] {
        let program = create_accumulator_program(n);
        let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
        let result = prover.verify(&proof, &vk);
        let sum = n as u64 * (n as u64 + 1) / 2;
        println!("  n={}: sum={}, bits={}, result: {:?}",
                 n, sum, 64 - sum.leading_zeros(), result);
    }
}
