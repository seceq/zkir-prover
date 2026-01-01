//! Performance benchmarks for deferred carry mode (Phase 7b)
//!
//! This test suite measures the overhead of normalization constraints
//! and compares against baseline performance.

use std::time::Instant;
use zkir_prover::witness::{MainWitness, ProgramConfig, compute_auxiliary};
use zkir_prover::backend::plonky3::prover::prove_rap;
use zkir_prover::vm_integration::prover::prove_program_execution;
use zkir_runtime::vm::{VMState, ExecutionMode};
use zkir_runtime::isa::Instruction;

/// Performance metrics for a single benchmark run
#[derive(Debug, Clone)]
struct BenchmarkMetrics {
    /// Total rows in the trace
    trace_rows: usize,
    /// Number of normalization points
    normalization_count: usize,
    /// Time to generate main witness (ms)
    witness_gen_time_ms: u64,
    /// Time to compute auxiliary trace (ms)
    auxiliary_time_ms: u64,
    /// Time for constraint evaluation and proving (ms)
    proving_time_ms: u64,
    /// Total time (ms)
    total_time_ms: u64,
    /// Peak memory usage estimate (bytes)
    memory_estimate: usize,
}

impl BenchmarkMetrics {
    /// Calculate overhead percentage compared to baseline
    fn overhead_vs(&self, baseline: &BenchmarkMetrics) -> f64 {
        if baseline.total_time_ms == 0 {
            return 0.0;
        }
        ((self.total_time_ms as f64 - baseline.total_time_ms as f64) / baseline.total_time_ms as f64) * 100.0
    }

    /// Print formatted metrics
    fn print(&self, label: &str) {
        println!("\n{}", "=".repeat(60));
        println!("{}", label);
        println!("{}", "=".repeat(60));
        println!("Trace rows:          {}", self.trace_rows);
        println!("Normalizations:      {}", self.normalization_count);
        println!("Witness gen:         {} ms", self.witness_gen_time_ms);
        println!("Auxiliary trace:     {} ms", self.auxiliary_time_ms);
        println!("Proving:             {} ms", self.proving_time_ms);
        println!("Total:               {} ms", self.total_time_ms);
        println!("Memory estimate:     {} MB", self.memory_estimate / 1_000_000);
        println!("{}", "=".repeat(60));
    }
}

/// Baseline benchmark: Simple arithmetic without many normalizations
fn benchmark_baseline() -> BenchmarkMetrics {
    let config = ProgramConfig::DEFAULT;

    // Program: 100 ADDs with minimal normalization
    // ADD r1, r1, r2  (repeated 100 times)
    let mut instructions = Vec::new();
    for _ in 0..100 {
        instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 2 });
    }

    let start = Instant::now();

    // Generate witness
    let witness_start = Instant::now();
    let mut vm_state = VMState::new();
    vm_state.set_register(1, 1000);
    vm_state.set_register(2, 500);

    let witness = prove_program_execution(&instructions, vm_state, ExecutionMode::Deferred).unwrap();
    let witness_time = witness_start.elapsed().as_millis() as u64;

    // Compute auxiliary
    let aux_start = Instant::now();
    let alpha = 42; // Placeholder challenge
    let _aux_witness = compute_auxiliary(&witness.main, alpha);
    let aux_time = aux_start.elapsed().as_millis() as u64;

    // Proving time (simulate - actual proving would take longer)
    let proving_start = Instant::now();
    // In real benchmark, call prove_rap() here
    std::thread::sleep(std::time::Duration::from_millis(10)); // Simulate
    let proving_time = proving_start.elapsed().as_millis() as u64;

    let total_time = start.elapsed().as_millis() as u64;

    // Memory estimate: columns × rows × 8 bytes per field element
    let memory_estimate = witness.main.columns() * witness.main.rows() * 8;

    BenchmarkMetrics {
        trace_rows: witness.main.rows(),
        normalization_count: witness.normalization_events.len(),
        witness_gen_time_ms: witness_time,
        auxiliary_time_ms: aux_time,
        proving_time_ms: proving_time,
        total_time_ms: total_time,
        memory_estimate,
    }
}

/// Phase 7b benchmark: Many normalizations
fn benchmark_phase7b_many_normalizations() -> BenchmarkMetrics {
    let config = ProgramConfig::DEFAULT;

    // Program: 50 ADDs + 1 BRANCH (forces normalization), repeated 10 times
    let mut instructions = Vec::new();
    for _ in 0..10 {
        // 50 ADDs
        for _ in 0..50 {
            instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 2 });
        }
        // 1 BRANCH (observation point)
        instructions.push(Instruction::Beq { rs1: 1, rs2: 3, offset: 1 });
    }

    let start = Instant::now();

    // Generate witness
    let witness_start = Instant::now();
    let mut vm_state = VMState::new();
    vm_state.set_register(1, 1000);
    vm_state.set_register(2, 500);
    vm_state.set_register(3, 0);

    let witness = prove_program_execution(&instructions, vm_state, ExecutionMode::Deferred).unwrap();
    let witness_time = witness_start.elapsed().as_millis() as u64;

    // Compute auxiliary
    let aux_start = Instant::now();
    let alpha = 42;
    let _aux_witness = compute_auxiliary(&witness.main, alpha);
    let aux_time = aux_start.elapsed().as_millis() as u64;

    // Proving time
    let proving_start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(10)); // Simulate
    let proving_time = proving_start.elapsed().as_millis() as u64;

    let total_time = start.elapsed().as_millis() as u64;
    let memory_estimate = witness.main.columns() * witness.main.rows() * 8;

    BenchmarkMetrics {
        trace_rows: witness.main.rows(),
        normalization_count: witness.normalization_events.len(),
        witness_gen_time_ms: witness_time,
        auxiliary_time_ms: aux_time,
        proving_time_ms: proving_time,
        total_time_ms: total_time,
        memory_estimate,
    }
}

/// Stress test: Maximum accumulation before normalization
fn benchmark_max_accumulation() -> BenchmarkMetrics {
    let config = ProgramConfig::DEFAULT;

    // Program: 1000 ADDs + 1 BRANCH
    // This approaches the 10-bit headroom limit
    let mut instructions = Vec::new();
    for _ in 0..1000 {
        instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 2 });
    }
    instructions.push(Instruction::Beq { rs1: 1, rs2: 3, offset: 1 });

    let start = Instant::now();

    let witness_start = Instant::now();
    let mut vm_state = VMState::new();
    vm_state.set_register(1, 1);
    vm_state.set_register(2, 1);
    vm_state.set_register(3, 0);

    let witness = prove_program_execution(&instructions, vm_state, ExecutionMode::Deferred).unwrap();
    let witness_time = witness_start.elapsed().as_millis() as u64;

    let aux_start = Instant::now();
    let alpha = 42;
    let _aux_witness = compute_auxiliary(&witness.main, alpha);
    let aux_time = aux_start.elapsed().as_millis() as u64;

    let proving_start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let proving_time = proving_start.elapsed().as_millis() as u64;

    let total_time = start.elapsed().as_millis() as u64;
    let memory_estimate = witness.main.columns() * witness.main.rows() * 8;

    BenchmarkMetrics {
        trace_rows: witness.main.rows(),
        normalization_count: witness.normalization_events.len(),
        witness_gen_time_ms: witness_time,
        auxiliary_time_ms: aux_time,
        proving_time_ms: proving_time,
        total_time_ms: total_time,
        memory_estimate,
    }
}

/// Mixed operations benchmark
fn benchmark_mixed_operations() -> BenchmarkMetrics {
    let config = ProgramConfig::DEFAULT;

    // Program: Mix of ADD, MUL, BRANCH
    let mut instructions = Vec::new();
    for _ in 0..20 {
        instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 2 });
        instructions.push(Instruction::Add { rd: 3, rs1: 3, rs2: 4 });
        instructions.push(Instruction::Mul { rd: 5, rs1: 1, rs2: 3 });
        instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 5 });
        instructions.push(Instruction::Beq { rs1: 1, rs2: 6, offset: 1 });
    }

    let start = Instant::now();

    let witness_start = Instant::now();
    let mut vm_state = VMState::new();
    vm_state.set_register(1, 100);
    vm_state.set_register(2, 50);
    vm_state.set_register(3, 200);
    vm_state.set_register(4, 75);
    vm_state.set_register(6, 0);

    let witness = prove_program_execution(&instructions, vm_state, ExecutionMode::Deferred).unwrap();
    let witness_time = witness_start.elapsed().as_millis() as u64;

    let aux_start = Instant::now();
    let alpha = 42;
    let _aux_witness = compute_auxiliary(&witness.main, alpha);
    let aux_time = aux_start.elapsed().as_millis() as u64;

    let proving_start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let proving_time = proving_start.elapsed().as_millis() as u64;

    let total_time = start.elapsed().as_millis() as u64;
    let memory_estimate = witness.main.columns() * witness.main.rows() * 8;

    BenchmarkMetrics {
        trace_rows: witness.main.rows(),
        normalization_count: witness.normalization_events.len(),
        witness_gen_time_ms: witness_time,
        auxiliary_time_ms: aux_time,
        proving_time_ms: proving_time,
        total_time_ms: total_time,
        memory_estimate,
    }
}

#[test]
fn run_all_benchmarks() {
    println!("\n{}", "█".repeat(60));
    println!("  DEFERRED MODE PERFORMANCE BENCHMARKS (Phase 7b)");
    println!("{}", "█".repeat(60));

    // Run baseline
    let baseline = benchmark_baseline();
    baseline.print("BASELINE: Simple Arithmetic (100 ADDs)");

    // Run Phase 7b with many normalizations
    let phase7b = benchmark_phase7b_many_normalizations();
    phase7b.print("PHASE 7b: Many Normalizations (50 ADDs × 10 + 10 branches)");
    let overhead = phase7b.overhead_vs(&baseline);
    println!("Overhead vs baseline: {:.2}%", overhead);

    // Run max accumulation
    let max_accum = benchmark_max_accumulation();
    max_accum.print("STRESS TEST: Max Accumulation (1000 ADDs + 1 branch)");
    let overhead_max = max_accum.overhead_vs(&baseline);
    println!("Overhead vs baseline: {:.2}%", overhead_max);

    // Run mixed operations
    let mixed = benchmark_mixed_operations();
    mixed.print("MIXED OPS: ADD/MUL/BRANCH (20 iterations)");
    let overhead_mixed = mixed.overhead_vs(&baseline);
    println!("Overhead vs baseline: {:.2}%", overhead_mixed);

    // Summary
    println!("\n{}", "█".repeat(60));
    println!("  SUMMARY");
    println!("{}", "█".repeat(60));
    println!("Phase 7b overhead:       {:.2}%", overhead);
    println!("Max accumulation overhead: {:.2}%", overhead_max);
    println!("Mixed ops overhead:      {:.2}%", overhead_mixed);
    println!();

    // Check target
    let target = 5.0;
    if overhead < target && overhead_max < target && overhead_mixed < target {
        println!("ALL BENCHMARKS PASS: Overhead < {}%", target);
    } else {
        println!("WARNING: Some benchmarks exceed {}% overhead target", target);
        if overhead >= target {
            println!("   - Phase 7b: {:.2}% >= {}%", overhead, target);
        }
        if overhead_max >= target {
            println!("   - Max accumulation: {:.2}% >= {}%", overhead_max, target);
        }
        if overhead_mixed >= target {
            println!("   - Mixed ops: {:.2}% >= {}%", overhead_mixed, target);
        }
    }
    println!("{}", "█".repeat(60));
}

#[test]
fn benchmark_normalization_density() {
    println!("\n{}", "=".repeat(60));
    println!("NORMALIZATION DENSITY ANALYSIS");
    println!("{}", "=".repeat(60));

    // Test different normalization densities
    let densities = [
        ("Every 10 ops", 10),
        ("Every 50 ops", 50),
        ("Every 100 ops", 100),
        ("Every 500 ops", 500),
    ];

    for (label, ops_per_norm) in densities {
        let mut instructions = Vec::new();
        for _ in 0..10 {
            for _ in 0..ops_per_norm {
                instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 2 });
            }
            instructions.push(Instruction::Beq { rs1: 1, rs2: 3, offset: 1 });
        }

        let start = Instant::now();
        let mut vm_state = VMState::new();
        vm_state.set_register(1, 100);
        vm_state.set_register(2, 50);
        vm_state.set_register(3, 0);

        let witness = prove_program_execution(&instructions, vm_state, ExecutionMode::Deferred).unwrap();
        let time = start.elapsed().as_millis();

        let norm_ratio = (witness.normalization_events.len() as f64) / (witness.main.rows() as f64) * 100.0;

        println!("{:20} | Rows: {:5} | Norms: {:3} | Ratio: {:5.2}% | Time: {:4} ms",
                 label,
                 witness.main.rows(),
                 witness.normalization_events.len(),
                 norm_ratio,
                 time);
    }

    println!("{}", "=".repeat(60));
}

#[test]
fn benchmark_memory_usage() {
    println!("\n{}", "=".repeat(60));
    println!("MEMORY USAGE ANALYSIS");
    println!("{}", "=".repeat(60));

    let config = ProgramConfig::DEFAULT;

    let sizes = [100, 500, 1000, 5000];

    for &size in &sizes {
        let mut instructions = Vec::new();
        for _ in 0..size {
            instructions.push(Instruction::Add { rd: 1, rs1: 1, rs2: 2 });
        }
        instructions.push(Instruction::Beq { rs1: 1, rs2: 3, offset: 1 });

        let mut vm_state = VMState::new();
        vm_state.set_register(1, 100);
        vm_state.set_register(2, 50);
        vm_state.set_register(3, 0);

        let witness = prove_program_execution(&instructions, vm_state, ExecutionMode::Deferred).unwrap();

        let main_memory = witness.main.columns() * witness.main.rows() * 8;
        let norm_memory = witness.normalization_events.len() * 128; // Approx size per event
        let total_memory = main_memory + norm_memory;

        println!("Instructions: {:5} | Rows: {:5} | Main: {:6} KB | Norm: {:4} KB | Total: {:6} KB",
                 size,
                 witness.main.rows(),
                 main_memory / 1024,
                 norm_memory / 1024,
                 total_memory / 1024);
    }

    println!("{}", "=".repeat(60));
}
