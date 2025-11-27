//! Benchmarks for the ZK IR prover

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use zkir_prover::{ExecutionTrace, Prover, ProverConfig};
use zkir_prover::trace::Step;

/// Create a dummy execution trace with the given number of steps
fn create_dummy_trace(num_steps: usize) -> ExecutionTrace {
    let mut trace = ExecutionTrace::new([0u8; 32]);

    for i in 0..num_steps {
        trace.steps.push(Step {
            pc: (i * 4) as u32,
            cycle: i as u64,
            opcode: 0b0110011, // ALU
            rd: 1,
            rs1: 2,
            rs2: 3,
            imm: 0,
            funct: 0,
            registers: [0u32; 32],
        });
    }

    trace
}

fn bench_trace_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_generation");

    for size in [1 << 10, 1 << 14, 1 << 16] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let trace = create_dummy_trace(size);
            let prover = Prover::new(ProverConfig::fast());

            b.iter(|| {
                let _ = black_box(prover.prove(&trace));
            });
        });
    }

    group.finish();
}

fn bench_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving");
    group.sample_size(10); // Proving is slow, use fewer samples

    for size in [1 << 10, 1 << 14] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let trace = create_dummy_trace(size);
            let prover = Prover::new(ProverConfig::fast());

            b.iter(|| {
                let proof = prover.prove(&trace).unwrap();
                black_box(proof)
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_trace_generation, bench_proving);
criterion_main!(benches);
