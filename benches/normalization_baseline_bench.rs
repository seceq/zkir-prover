//! Baseline performance benchmark for Phase 7b comparison
//!
//! This benchmark establishes baseline metrics before Phase 7b implementation.
//! After Phase 7b, re-run to measure performance impact.

use std::time::Instant;
use zkir_prover::vm_integration::VMProver;
use zkir_spec::{Instruction, Program, Register};

fn create_test_program(instructions: Vec<Instruction>) -> Program {
    let mut program = Program::new();
    let code: Vec<u32> = instructions
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program.code = code;
    program.header.code_size = (program.code.len() * 4) as u32;
    program
}

fn benchmark_simple_arithmetic() -> u128 {
    // Simple arithmetic program
    let instructions = vec![
        Instruction::Addi {
            rd: Register::R1,
            rs1: Register::R0,
            imm: 100,
        },
        Instruction::Addi {
            rd: Register::R2,
            rs1: Register::R0,
            imm: 200,
        },
        Instruction::Add {
            rd: Register::R3,
            rs1: Register::R1,
            rs2: Register::R2,
        },
        Instruction::Addi {
            rd: Register::R10,
            rs1: Register::R0,
            imm: 0,
        },
        Instruction::Addi {
            rd: Register::R11,
            rs1: Register::R0,
            imm: 0,
        },
        Instruction::Ecall,
    ];

    let program = create_test_program(instructions);

    // Benchmark full proof generation (VM + prover)
    let prover = VMProver::fast_test_config();
    let start = Instant::now();
    let _result = prover.prove_program(&program, &[]).expect("Proof generation failed");
    start.elapsed().as_micros()
}

fn benchmark_with_observation_points() -> u128 {
    // Program with observation points (branches)
    let instructions = vec![
        Instruction::Addi {
            rd: Register::R1,
            rs1: Register::R0,
            imm: 100,
        },
        Instruction::Addi {
            rd: Register::R2,
            rs1: Register::R0,
            imm: 200,
        },
        Instruction::Add {
            rd: Register::R3,
            rs1: Register::R1,
            rs2: Register::R2,
        },
        // Observation point 1
        Instruction::Beq {
            rs1: Register::R3,
            rs2: Register::R3,
            offset: 0,
        },
        Instruction::Addi {
            rd: Register::R4,
            rs1: Register::R0,
            imm: 300,
        },
        Instruction::Add {
            rd: Register::R5,
            rs1: Register::R3,
            rs2: Register::R4,
        },
        // Observation point 2
        Instruction::Bne {
            rs1: Register::R5,
            rs2: Register::R0,
            offset: 0,
        },
        Instruction::Addi {
            rd: Register::R10,
            rs1: Register::R0,
            imm: 0,
        },
        Instruction::Addi {
            rd: Register::R11,
            rs1: Register::R0,
            imm: 0,
        },
        Instruction::Ecall,
    ];

    let program = create_test_program(instructions);

    let prover = VMProver::fast_test_config();
    let start = Instant::now();
    let _result = prover.prove_program(&program, &[]).expect("Proof generation failed");
    start.elapsed().as_micros()
}

fn benchmark_larger_program() -> u128 {
    // Larger program with 20 operations
    let mut instructions = vec![];

    // Initialize registers
    for i in 1..10 {
        instructions.push(Instruction::Addi {
            rd: Register::from_index(i).unwrap(),
            rs1: Register::R0,
            imm: (i as i32) * 10,
        });
    }

    // Arithmetic operations
    for i in 1..5 {
        instructions.push(Instruction::Add {
            rd: Register::from_index(i + 5).unwrap(),
            rs1: Register::from_index(i).unwrap(),
            rs2: Register::from_index(i + 1).unwrap(),
        });
    }

    // Branches (observation points)
    for i in 6..9 {
        instructions.push(Instruction::Beq {
            rs1: Register::from_index(i).unwrap(),
            rs2: Register::from_index(i).unwrap(),
            offset: 0,
        });
    }

    // Exit
    instructions.push(Instruction::Addi {
        rd: Register::R10,
        rs1: Register::R0,
        imm: 0,
    });
    instructions.push(Instruction::Addi {
        rd: Register::R11,
        rs1: Register::R0,
        imm: 0,
    });
    instructions.push(Instruction::Ecall);

    let program = create_test_program(instructions);

    let prover = VMProver::fast_test_config();
    let start = Instant::now();
    let _result = prover.prove_program(&program, &[]).expect("Proof generation failed");
    start.elapsed().as_micros()
}

#[test]
fn test_baseline_performance() {
    println!("\n=== Phase 7 Baseline Performance (Before Phase 7b) ===\n");

    // Run each benchmark 3 times and take average
    let mut simple_times = vec![];

    println!("Benchmarking simple arithmetic...");
    for _ in 0..3 {
        let time = benchmark_simple_arithmetic();
        simple_times.push(time);
    }

    let avg_simple: u128 = simple_times.iter().sum::<u128>() / 3;
    println!("  Total: {} μs\n", avg_simple);

    // Benchmark with observation points
    let mut obs_times = vec![];

    println!("Benchmarking with observation points...");
    for _ in 0..3 {
        let time = benchmark_with_observation_points();
        obs_times.push(time);
    }

    let avg_obs: u128 = obs_times.iter().sum::<u128>() / 3;
    println!("  Total: {} μs\n", avg_obs);

    // Benchmark larger program
    let mut large_times = vec![];

    println!("Benchmarking larger program...");
    for _ in 0..3 {
        let time = benchmark_larger_program();
        large_times.push(time);
    }

    let avg_large: u128 = large_times.iter().sum::<u128>() / 3;
    println!("  Total: {} μs\n", avg_large);

    println!("=== Summary (Before Phase 7b) ===");
    println!("Simple arithmetic: {} μs", avg_simple);
    println!("With branches: {} μs", avg_obs);
    println!("Larger program: {} μs", avg_large);
    println!("\n(Save these values for Phase 7b comparison)");
    println!("Expected impact after Phase 7b: <5% increase");
}
