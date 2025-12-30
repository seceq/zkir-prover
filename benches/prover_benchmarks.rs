//! Performance Benchmarks for zkir-prover
//!
//! Run with: cargo bench
//!
//! These benchmarks measure:
//! - Proof generation time for various trace sizes
//! - Verification time
//! - Witness construction time
//! - Auxiliary witness computation time
//! - Single-commit vs double-commit performance comparison

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zkir_prover::backend::plonky3::backend_impl::Plonky3Backend;
use zkir_prover::backend::plonky3::Plonky3Prover;
use zkir_prover::backend::ProverBackend;
use zkir_prover::witness::{
    MainWitness, MainWitnessBuilder, MainTraceRow, ProgramConfig, ValueBound,
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Create a trace row with given values
fn create_trace_row(
    cycle: u64,
    pc: u64,
    instruction: u32,
    reg_values: &[u32],
    config: &ProgramConfig,
) -> MainTraceRow {
    let data_limbs = config.data_limbs as usize;
    let mut registers = vec![vec![0u32; data_limbs]; 16];

    for (i, &val) in reg_values.iter().enumerate().take(16) {
        registers[i][0] = val;
    }

    let bounds = vec![ValueBound::zero(); 16];
    MainTraceRow::new(cycle, pc, instruction, registers, bounds)
}

/// Create a witness with N rows of ADDI instructions
fn create_benchmark_witness(num_rows: usize) -> MainWitness {
    let config = ProgramConfig::DEFAULT;
    let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);
    let mut reg_values = vec![0u32; 16];

    for i in 0..num_rows {
        let rd = ((i % 15) + 1) as u32; // R1-R15
        let imm = (i as u32 + 1) % 1000;
        let inst = 0x01 | (rd << 7) | (0 << 11) | (imm << 15); // ADDI
        reg_values[rd as usize] = imm;
        builder.add_trace_row(create_trace_row(i as u64, (i * 4) as u64, inst, &reg_values, &config));
    }

    builder.build()
}

/// Create a witness with mixed operations
fn create_mixed_operations_witness(num_rows: usize) -> MainWitness {
    let config = ProgramConfig::DEFAULT;
    let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);
    let mut reg_values = vec![0u32; 16];

    // Initialize R1 and R2
    reg_values[1] = 10;
    reg_values[2] = 5;

    for i in 0..num_rows {
        let inst = if i < 2 {
            // First two rows: ADDI to initialize
            let rd = (i + 1) as u32;
            let imm = if i == 0 { 10 } else { 5 };
            0x01 | (rd << 7) | (0 << 11) | (imm << 15)
        } else {
            // Alternate between ADD, SUB, MUL
            let rd = ((i % 13) + 3) as u32;
            let opcode = match i % 3 {
                0 => 0x00, // ADD
                1 => 0x02, // SUB
                _ => 0x04, // MUL
            };
            let result = match i % 3 {
                0 => reg_values[1] + reg_values[2],
                1 => reg_values[1].saturating_sub(reg_values[2]),
                _ => (reg_values[1] * reg_values[2]) & 0xFFFFF, // Mask to 20 bits
            };
            reg_values[rd as usize] = result;
            opcode | (rd << 7) | (1 << 11) | (2 << 15)
        };

        builder.add_trace_row(create_trace_row(i as u64, (i * 4) as u64, inst, &reg_values, &config));
    }

    builder.build()
}

// ============================================================================
// BENCHMARKS
// ============================================================================

fn bench_proof_generation(c: &mut Criterion) {
    let backend = Plonky3Backend::test_config();

    let mut group = c.benchmark_group("proof_generation");
    group.sample_size(10); // Reduce sample size for slower benchmarks

    for size in [4, 8, 16, 32, 64].iter() {
        let witness = create_benchmark_witness(*size);

        group.bench_with_input(
            BenchmarkId::new("simple_addi", size),
            size,
            |b, _| {
                b.iter(|| {
                    let result = backend.prove(black_box(&witness));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let backend = Plonky3Backend::test_config();

    let mut group = c.benchmark_group("verification");
    group.sample_size(20);

    for size in [4, 8, 16, 32].iter() {
        let witness = create_benchmark_witness(*size);
        let proof = backend.prove(&witness).expect("Proof generation failed");

        group.bench_with_input(
            BenchmarkId::new("verify", size),
            size,
            |b, _| {
                b.iter(|| {
                    let result = backend.verify(black_box(&proof), black_box(&proof.verifying_key));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_witness_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("witness_construction");

    for size in [4, 8, 16, 32, 64, 128].iter() {
        group.bench_with_input(
            BenchmarkId::new("build_witness", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let witness = create_benchmark_witness(size);
                    black_box(witness)
                });
            },
        );
    }

    group.finish();
}

fn bench_mixed_operations(c: &mut Criterion) {
    let backend = Plonky3Backend::test_config();

    let mut group = c.benchmark_group("mixed_operations");
    group.sample_size(10);

    for size in [8, 16, 32].iter() {
        let witness = create_mixed_operations_witness(*size);

        group.bench_with_input(
            BenchmarkId::new("prove_mixed", size),
            size,
            |b, _| {
                b.iter(|| {
                    let result = backend.prove(black_box(&witness));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let backend = Plonky3Backend::test_config();

    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(10);

    for size in [4, 8, 16, 32].iter() {
        group.bench_with_input(
            BenchmarkId::new("prove_and_verify", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let witness = create_benchmark_witness(size);
                    let proof = backend.prove(&witness).expect("Proof failed");
                    let result = backend.verify(&proof, &proof.verifying_key);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark comparing single-commit vs double-commit prover implementations
///
/// This benchmark measures the performance improvement from eliminating the
/// double commitment in the RAP prover. The single-commit version should be
/// ~1.3-1.5x faster than the double-commit version.
fn bench_single_vs_double_commit(c: &mut Criterion) {
    let prover = Plonky3Prover::test_config();

    let mut group = c.benchmark_group("commit_optimization");
    group.sample_size(10);

    for size in [8, 16, 32, 64].iter() {
        let witness = create_benchmark_witness(*size);

        // Benchmark single-commit (optimized)
        group.bench_with_input(
            BenchmarkId::new("single_commit", size),
            size,
            |b, _| {
                b.iter(|| {
                    let result = prover.prove_rap_single_commit(black_box(&witness));
                    black_box(result)
                });
            },
        );

        // Benchmark double-commit (legacy)
        group.bench_with_input(
            BenchmarkId::new("double_commit", size),
            size,
            |b, _| {
                b.iter(|| {
                    let result = prover.prove_rap_double_commit(black_box(&witness));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark for larger trace sizes to measure scalability
fn bench_large_traces(c: &mut Criterion) {
    let prover = Plonky3Prover::test_config();

    let mut group = c.benchmark_group("large_traces");
    group.sample_size(10);

    for size in [64, 128, 256].iter() {
        let witness = create_benchmark_witness(*size);

        group.bench_with_input(
            BenchmarkId::new("single_commit_large", size),
            size,
            |b, _| {
                b.iter(|| {
                    let result = prover.prove_rap_single_commit(black_box(&witness));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_proof_generation,
    bench_proof_verification,
    bench_witness_construction,
    bench_mixed_operations,
    bench_end_to_end,
    bench_single_vs_double_commit,
    bench_large_traces,
);

criterion_main!(benches);
