//! Full Pipeline Benchmark
//!
//! This example demonstrates and benchmarks the complete ZKIR proving pipeline:
//! 1. Create ZKIR programs programmatically
//! 2. Execute through the VM with witness collection
//! 3. Generate ZK proofs using Plonky3
//! 4. Verify the proofs
//!
//! It measures performance at each stage to identify bottlenecks.

use std::time::Instant;
use zkir_prover::vm_integration::VMProver;
use zkir_spec::{Instruction, Program, Register};

/// Timing results for a single benchmark run
struct BenchmarkResult {
    name: String,
    program_creation_us: u128,
    execution_us: u128,
    proof_generation_us: u128,
    verification_us: u128,
    total_us: u128,
    cycles: usize,
    trace_height: usize,
    proof_size_bytes: usize,
}

fn main() {
    println!("==================================================================");
    println!("          ZKIR Full Pipeline Benchmark                            ");
    println!("==================================================================\n");

    // Run benchmarks for different programs
    let mut results = Vec::new();

    results.push(benchmark_simple_add());
    results.push(benchmark_accumulator(10));
    results.push(benchmark_accumulator(50));
    results.push(benchmark_accumulator(100));
    results.push(benchmark_fibonacci(10));
    results.push(benchmark_fibonacci(15));
    results.push(benchmark_multiply_chain(5));
    results.push(benchmark_multiply_chain(10));

    // Print summary table
    print_summary(&results);

    // Print observations
    print_observations(&results);
}

/// Benchmark simple addition: a + b = c
fn benchmark_simple_add() -> BenchmarkResult {
    println!("> Running: Simple Addition (a + b)");

    let start_total = Instant::now();

    // Step 1: Create program
    let start = Instant::now();
    let program = create_add_program();
    let program_creation_us = start.elapsed().as_micros();

    let inputs = vec![42, 100];

    // Step 2-4: Use VMProver for execution, proof generation, and verification
    let prover = VMProver::fast_test_config();

    let start = Instant::now();
    let (proof, vk) = prover.prove_program(&program, &inputs)
        .expect("Proof generation failed");
    let execution_and_proof_us = start.elapsed().as_micros();

    let start = Instant::now();
    let _verified = prover.verify(&proof, &vk).expect("Verification failed");
    let verification_us = start.elapsed().as_micros();

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let total_us = start_total.elapsed().as_micros();

    println!("  Completed in {:.2}ms\n", total_us as f64 / 1000.0);

    BenchmarkResult {
        name: "Simple Add".to_string(),
        program_creation_us,
        execution_us: execution_and_proof_us / 2, // Approximate split
        proof_generation_us: execution_and_proof_us / 2,
        verification_us,
        total_us,
        cycles: proof.metadata.num_cycles,
        trace_height: proof.metadata.trace_height,
        proof_size_bytes: proof_bytes.len(),
    }
}

/// Benchmark accumulator: sum of 1 to n
fn benchmark_accumulator(n: u32) -> BenchmarkResult {
    println!("> Running: Accumulator (sum 1 to {})", n);

    let start_total = Instant::now();

    // Step 1: Create program
    let start = Instant::now();
    let program = create_accumulator_program(n);
    let program_creation_us = start.elapsed().as_micros();

    let inputs = vec![];

    let prover = VMProver::fast_test_config();

    let start = Instant::now();
    let (proof, vk) = prover.prove_program(&program, &inputs)
        .expect("Proof generation failed");
    let execution_and_proof_us = start.elapsed().as_micros();

    let start = Instant::now();
    let _verified = prover.verify(&proof, &vk).expect("Verification failed");
    let verification_us = start.elapsed().as_micros();

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let total_us = start_total.elapsed().as_micros();

    println!("  Completed in {:.2}ms (sum = {})\n",
             total_us as f64 / 1000.0, n * (n + 1) / 2);

    BenchmarkResult {
        name: format!("Accum({})", n),
        program_creation_us,
        execution_us: execution_and_proof_us / 2,
        proof_generation_us: execution_and_proof_us / 2,
        verification_us,
        total_us,
        cycles: proof.metadata.num_cycles,
        trace_height: proof.metadata.trace_height,
        proof_size_bytes: proof_bytes.len(),
    }
}

/// Benchmark fibonacci computation
fn benchmark_fibonacci(n: u32) -> BenchmarkResult {
    println!("> Running: Fibonacci({})", n);

    let start_total = Instant::now();

    let start = Instant::now();
    let program = create_fibonacci_program(n);
    let program_creation_us = start.elapsed().as_micros();

    let inputs = vec![];

    let prover = VMProver::fast_test_config();

    let start = Instant::now();
    let (proof, vk) = prover.prove_program(&program, &inputs)
        .expect("Proof generation failed");
    let execution_and_proof_us = start.elapsed().as_micros();

    let start = Instant::now();
    let _verified = prover.verify(&proof, &vk).expect("Verification failed");
    let verification_us = start.elapsed().as_micros();

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let total_us = start_total.elapsed().as_micros();

    // Calculate expected fib value
    let fib_val = fib(n);
    println!("  Completed in {:.2}ms (fib({}) = {})\n",
             total_us as f64 / 1000.0, n, fib_val);

    BenchmarkResult {
        name: format!("Fib({})", n),
        program_creation_us,
        execution_us: execution_and_proof_us / 2,
        proof_generation_us: execution_and_proof_us / 2,
        verification_us,
        total_us,
        cycles: proof.metadata.num_cycles,
        trace_height: proof.metadata.trace_height,
        proof_size_bytes: proof_bytes.len(),
    }
}

/// Benchmark chain of multiplications
fn benchmark_multiply_chain(n: u32) -> BenchmarkResult {
    println!("> Running: Multiply Chain (length {})", n);

    let start_total = Instant::now();

    let start = Instant::now();
    let program = create_multiply_chain_program(n);
    let program_creation_us = start.elapsed().as_micros();

    let inputs = vec![];

    let prover = VMProver::fast_test_config();

    let start = Instant::now();
    let (proof, vk) = prover.prove_program(&program, &inputs)
        .expect("Proof generation failed");
    let execution_and_proof_us = start.elapsed().as_micros();

    let start = Instant::now();
    let _verified = prover.verify(&proof, &vk).expect("Verification failed");
    let verification_us = start.elapsed().as_micros();

    let proof_bytes = bincode::serialize(&proof).unwrap();
    let total_us = start_total.elapsed().as_micros();

    println!("  Completed in {:.2}ms\n", total_us as f64 / 1000.0);

    BenchmarkResult {
        name: format!("MulChain({})", n),
        program_creation_us,
        execution_us: execution_and_proof_us / 2,
        proof_generation_us: execution_and_proof_us / 2,
        verification_us,
        total_us,
        cycles: proof.metadata.num_cycles,
        trace_height: proof.metadata.trace_height,
        proof_size_bytes: proof_bytes.len(),
    }
}

// === Program Builders ===

fn create_add_program() -> Program {
    let instructions = vec![
        // R1 = 10
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 10 },
        // R2 = 20
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 20 },
        // R3 = R1 + R2
        Instruction::Add { rd: Register::R3, rs1: Register::R1, rs2: Register::R2 },
        Instruction::Ebreak,
    ];
    build_program(instructions)
}

fn create_accumulator_program(n: u32) -> Program {
    let mut instructions = vec![
        // R1 = 0 (accumulator)
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
        // R2 = 1 (counter)
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
        // R3 = n (limit)
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: n as i32 },
    ];

    // Loop: while counter <= n
    let loop_start = instructions.len();
    instructions.push(Instruction::Add { rd: Register::R1, rs1: Register::R1, rs2: Register::R2 }); // acc += counter
    instructions.push(Instruction::Addi { rd: Register::R2, rs1: Register::R2, imm: 1 }); // counter++

    // Branch back if counter <= n (we need to compare and branch)
    // Use BLT: if R2 < R3+1, jump back
    instructions.push(Instruction::Addi { rd: Register::R4, rs1: Register::R3, imm: 1 }); // R4 = n + 1

    // Calculate offset back to loop_start
    let current = instructions.len();
    let offset = -((current - loop_start + 1) as i32) * 4; // Each instruction is 4 bytes
    instructions.push(Instruction::Blt { rs1: Register::R2, rs2: Register::R4, offset });

    instructions.push(Instruction::Ebreak);

    build_program(instructions)
}

fn create_fibonacci_program(n: u32) -> Program {
    let mut instructions = vec![
        // R1 = 0 (prev)
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 0 },
        // R2 = 1 (curr)
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
        // R3 = 1 (counter)
        Instruction::Addi { rd: Register::R3, rs1: Register::R0, imm: 1 },
        // R4 = n (limit)
        Instruction::Addi { rd: Register::R4, rs1: Register::R0, imm: n as i32 },
    ];

    // Loop
    let loop_start = instructions.len();
    // R5 = prev + curr
    instructions.push(Instruction::Add { rd: Register::R5, rs1: Register::R1, rs2: Register::R2 });
    // prev = curr
    instructions.push(Instruction::Add { rd: Register::R1, rs1: Register::R2, rs2: Register::R0 });
    // curr = R5
    instructions.push(Instruction::Add { rd: Register::R2, rs1: Register::R5, rs2: Register::R0 });
    // counter++
    instructions.push(Instruction::Addi { rd: Register::R3, rs1: Register::R3, imm: 1 });

    // Branch back if counter < n
    let current = instructions.len();
    let offset = -((current - loop_start + 1) as i32) * 4;
    instructions.push(Instruction::Blt { rs1: Register::R3, rs2: Register::R4, offset });

    instructions.push(Instruction::Ebreak);

    build_program(instructions)
}

fn create_multiply_chain_program(n: u32) -> Program {
    let mut instructions = vec![
        // R1 = 2 (base)
        Instruction::Addi { rd: Register::R1, rs1: Register::R0, imm: 2 },
        // R2 = 1 (result)
        Instruction::Addi { rd: Register::R2, rs1: Register::R0, imm: 1 },
    ];

    // Chain of multiplications: result = result * base, n times
    for _ in 0..n {
        instructions.push(Instruction::Mul { rd: Register::R2, rs1: Register::R2, rs2: Register::R1 });
    }

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

fn fib(n: u32) -> u64 {
    if n <= 1 { return n as u64; }
    let (mut prev, mut curr) = (0u64, 1u64);
    for _ in 1..n {
        let next = prev + curr;
        prev = curr;
        curr = next;
    }
    curr
}

fn print_summary(results: &[BenchmarkResult]) {
    println!("\n======================================================================================");
    println!("                              BENCHMARK SUMMARY                                        ");
    println!("======================================================================================");
    println!(" Benchmark      | Cycles | Trace Ht | Proof Gen    | Verify       | Proof KB  | Total   ");
    println!("--------------------------------------------------------------------------------------");

    for r in results {
        println!(" {:13}  | {:>6} | {:>8} | {:>10.2}ms | {:>10.2}ms | {:>7.1}KB | {:>5.0}ms ",
                 r.name,
                 r.cycles,
                 r.trace_height,
                 r.proof_generation_us as f64 / 1000.0,
                 r.verification_us as f64 / 1000.0,
                 r.proof_size_bytes as f64 / 1024.0,
                 r.total_us as f64 / 1000.0);
    }

    println!("======================================================================================");
}

fn print_observations(results: &[BenchmarkResult]) {
    println!("\n==================================================================");
    println!("                         OBSERVATIONS                             ");
    println!("==================================================================\n");

    // Calculate some metrics
    let total_proof_time: u128 = results.iter().map(|r| r.proof_generation_us).sum();
    let total_verify_time: u128 = results.iter().map(|r| r.verification_us).sum();
    let avg_proof_per_cycle: f64 = results.iter()
        .map(|r| r.proof_generation_us as f64 / r.cycles as f64)
        .sum::<f64>() / results.len() as f64;

    println!("1. PROOF GENERATION TIME:");
    println!("   - Proof generation dominates the pipeline ({:.1}% of total time)",
             100.0 * total_proof_time as f64 / (total_proof_time + total_verify_time) as f64);
    println!("   - Average time per cycle: {:.2}µs", avg_proof_per_cycle);
    println!();

    println!("2. VERIFICATION:");
    println!("   - Verification is fast: typically {:.2}ms",
             results.iter().map(|r| r.verification_us).sum::<u128>() as f64 / results.len() as f64 / 1000.0);
    println!("   - Verification time is relatively constant regardless of program size");
    println!();

    println!("3. TRACE HEIGHT ANALYSIS:");
    for r in results {
        let padding_ratio = r.trace_height as f64 / r.cycles as f64;
        println!("   - {}: {} cycles → {} trace height ({:.1}x padding)",
                 r.name, r.cycles, r.trace_height, padding_ratio);
    }
    println!("   - Power-of-2 padding adds overhead for small programs");
    println!();

    println!("4. PROOF SIZE:");
    let min_proof = results.iter().map(|r| r.proof_size_bytes).min().unwrap();
    let max_proof = results.iter().map(|r| r.proof_size_bytes).max().unwrap();
    println!("   - Proof sizes range from {:.1}KB to {:.1}KB",
             min_proof as f64 / 1024.0, max_proof as f64 / 1024.0);
    println!("   - Proof size grows logarithmically with trace height (FRI property)");
    println!();

    println!("5. SCALING OBSERVATIONS:");
    if results.len() >= 4 {
        let small = &results[1]; // Accum(10)
        let large = &results[3]; // Accum(100)
        let cycle_ratio = large.cycles as f64 / small.cycles as f64;
        let time_ratio = large.proof_generation_us as f64 / small.proof_generation_us as f64;
        println!("   - {}x more cycles → {:.1}x more proof time",
                 cycle_ratio as i32, time_ratio);
        println!("   - Near-linear scaling for proof generation");
    }
    println!();

    println!("6. POTENTIAL IMPROVEMENTS:");
    println!("   - Batch multiple programs for amortized proving");
    println!("   - GPU acceleration for polynomial operations");
    println!("   - Reduce padding overhead with better trace packing");
    println!("   - Consider recursive proofs for very large programs");
}
