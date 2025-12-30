//! Stress Test for ZKIR Prover
//!
//! Tests the prover with increasingly large programs to identify performance
//! bottlenecks and scalability limits.

use std::time::Instant;
use zkir_prover::vm_integration::VMProver;
use zkir_spec::{Instruction, Program, Register};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              ZKIR Prover Stress Test                              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Test with increasing program sizes
    let sizes = [10, 50, 100, 200, 500, 1000, 2000];

    println!("Testing with accumulator programs of increasing loop iterations:\n");
    println!("{:>10} {:>10} {:>12} {:>12} {:>12} {:>10} {:>12}",
             "Iterations", "Cycles", "Trace Ht", "Prove (ms)", "Verify (ms)",
             "Proof KB", "µs/cycle");
    println!("{}", "-".repeat(85));

    for &n in &sizes {
        let result = test_accumulator(n);
        println!("{:>10} {:>10} {:>12} {:>12.2} {:>12.2} {:>10.1} {:>12.2}",
                 n, result.cycles, result.trace_height,
                 result.prove_time_ms, result.verify_time_ms,
                 result.proof_size_kb, result.us_per_cycle);
    }

    println!("\n");
    println!("Testing memory-intensive program (multiple store/load operations):\n");
    test_memory_intensive();

    println!("\n");
    println!("Testing branch-heavy program:\n");
    test_branch_heavy();

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    PERFORMANCE ANALYSIS                           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    analyze_performance(&sizes);
}

struct TestResult {
    cycles: usize,
    trace_height: usize,
    prove_time_ms: f64,
    verify_time_ms: f64,
    proof_size_kb: f64,
    us_per_cycle: f64,
}

fn test_accumulator(n: u32) -> TestResult {
    let program = create_accumulator_program(n);
    let prover = VMProver::fast_test_config();

    let start = Instant::now();
    let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
    let prove_time = start.elapsed();

    let start = Instant::now();
    let _verified = prover.verify(&proof, &vk).expect("Verify failed");
    let verify_time = start.elapsed();

    let proof_bytes = bincode::serialize(&proof).unwrap();

    TestResult {
        cycles: proof.metadata.num_cycles,
        trace_height: proof.metadata.trace_height,
        prove_time_ms: prove_time.as_micros() as f64 / 1000.0,
        verify_time_ms: verify_time.as_micros() as f64 / 1000.0,
        proof_size_kb: proof_bytes.len() as f64 / 1024.0,
        us_per_cycle: prove_time.as_micros() as f64 / proof.metadata.num_cycles as f64,
    }
}

fn test_memory_intensive() {
    println!("{:>15} {:>10} {:>12} {:>12} {:>10}",
             "Mem Ops", "Cycles", "Prove (ms)", "Verify (ms)", "Proof KB");
    println!("{}", "-".repeat(65));

    for &n in &[10, 50, 100, 200] {
        let program = create_memory_program(n);
        let prover = VMProver::fast_test_config();

        let start = Instant::now();
        let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
        let prove_time = start.elapsed();

        let start = Instant::now();
        let _verified = prover.verify(&proof, &vk).expect("Verify failed");
        let verify_time = start.elapsed();

        let proof_bytes = bincode::serialize(&proof).unwrap();

        println!("{:>15} {:>10} {:>12.2} {:>12.2} {:>10.1}",
                 n, proof.metadata.num_cycles,
                 prove_time.as_micros() as f64 / 1000.0,
                 verify_time.as_micros() as f64 / 1000.0,
                 proof_bytes.len() as f64 / 1024.0);
    }
}

fn test_branch_heavy() {
    println!("{:>15} {:>10} {:>12} {:>12} {:>10}",
             "Branches", "Cycles", "Prove (ms)", "Verify (ms)", "Proof KB");
    println!("{}", "-".repeat(65));

    for &n in &[10, 50, 100] {
        let program = create_branch_program(n);
        let prover = VMProver::fast_test_config();

        let start = Instant::now();
        let (proof, vk) = prover.prove_program(&program, &[]).expect("Proof failed");
        let prove_time = start.elapsed();

        let start = Instant::now();
        let _verified = prover.verify(&proof, &vk).expect("Verify failed");
        let verify_time = start.elapsed();

        let proof_bytes = bincode::serialize(&proof).unwrap();

        println!("{:>15} {:>10} {:>12.2} {:>12.2} {:>10.1}",
                 n, proof.metadata.num_cycles,
                 prove_time.as_micros() as f64 / 1000.0,
                 verify_time.as_micros() as f64 / 1000.0,
                 proof_bytes.len() as f64 / 1024.0);
    }
}

fn analyze_performance(sizes: &[u32]) {
    println!("BOTTLENECK ANALYSIS:");
    println!("───────────────────────────────────────────────────────────────────\n");

    println!("1. PROOF GENERATION SCALING:");
    println!("   The prover scales roughly O(n log n) with trace size due to FFT");
    println!("   operations in the polynomial commitment scheme.");
    println!();

    println!("2. MEMORY OVERHEAD:");
    println!("   - Trace matrix: ~{} bytes per cycle × {} columns",
             std::mem::size_of::<u32>(), 50); // Rough estimate
    println!("   - For 1000 cycles: ~{} MB in-memory trace",
             (1000 * 50 * 4) as f64 / (1024.0 * 1024.0));
    println!();

    println!("3. VERIFICATION PERFORMANCE:");
    println!("   - Verification is O(log n) - very efficient");
    println!("   - Dominated by FRI query verification");
    println!();

    println!("4. POWER-OF-2 PADDING:");
    println!("   - Trace height must be power of 2 for FFT");
    println!("   - Worst case: 2x overhead (e.g., 513 cycles → 1024 trace)");
    println!();

    println!("5. RECOMMENDATIONS:");
    println!("   a) Batch small programs to fill trace height efficiently");
    println!("   b) Consider parallel proving for independent programs");
    println!("   c) GPU acceleration would help polynomial operations");
    println!("   d) Memory mapping for very large traces (>100K cycles)");
}

// Program builders

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
    let offset = -((current - loop_start + 1) as i32) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R2, rs2: Register::R4, offset });

    instructions.push(Instruction::Ebreak);

    build_program(instructions)
}

fn create_memory_program(n: u32) -> Program {
    let mut instructions = vec![
        // Base address
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0x1000 },
        // Counter
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 0 },
        // Limit
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: n as i32 },
    ];

    let loop_start = instructions.len();

    // Store counter to memory
    instructions.push(Instruction::Sw {
        rs1: Register::R1,
        rs2: Register::R2,
        imm: 0,
    });

    // Load back from memory
    instructions.push(Instruction::Lw {
        rd: Register::R4,
        rs1: Register::R1,
        imm: 0,
    });

    // Increment address by 4
    instructions.push(Instruction::Addi { rd: Register::R1, rs1: Register::R1, imm: 4 });

    // Increment counter
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R2, imm: 1 });

    // Branch back
    let current = instructions.len();
    let offset = -((current - loop_start + 1) as i32) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R2, rs2: Register::R3, offset });

    instructions.push(Instruction::Ebreak);

    build_program(instructions)
}

fn create_branch_program(n: u32) -> Program {
    let mut instructions = vec![
        // Counter
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
        // Limit
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: n as i32 },
        // Accumulator
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 0 },
        // Constant 2 for modulo check
        Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: 2 },
    ];

    let loop_start = instructions.len();

    // Check if counter is even (simplified: always add, just to have branch logic)
    // This creates a conditional pattern
    instructions.push(Instruction::Add { rd: Register::R5, rs1: Register::R1, rs2: Register::R0 });
    instructions.push(Instruction::Beq {
        rs1: Register::R5,
        rs2: Register::R0,
        offset: 8, // Skip next instruction
    });
    instructions.push(Instruction::Add { rd: Register::R3, rs1: Register::R3, rs2: Register::R1 });
    // Increment counter
    instructions.push(Instruction::Addi { rd: Register::R1, rs1: Register::R1, imm: 1 });

    // Branch back
    let current = instructions.len();
    let offset = -((current - loop_start + 1) as i32) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R1, rs2: Register::R2, offset });

    instructions.push(Instruction::Ebreak);

    build_program(instructions)
}

fn build_program(instructions: Vec<Instruction>) -> Program {
    let mut program = Program::new();
    program.code = instructions
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program.header.code_size = (program.code.len() * 4) as u32;
    program
}
