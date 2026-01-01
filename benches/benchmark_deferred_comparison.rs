//! Benchmark comparing deferred vs immediate carry mode
//!
//! This example measures actual performance difference between:
//! - Deferred mode: normalize only at observation points
//! - Immediate mode: normalize after every arithmetic operation
//!
//! Run with: cargo run --example benchmark_deferred_comparison --release

use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::r#trait::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_main_witness;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, Register};
use std::time::Instant;

/// Create a computation-heavy accumulator program
///
/// This program performs many additions in a tight loop with minimal
/// observation points - perfect for showing deferred mode benefits.
fn create_accumulator_program(iterations: i32) -> Program {
    let mut instructions = Vec::new();

    // Initialize: R1=sum(0), R2=counter(0), R3=limit
    instructions.push(Instruction::Addi {
        rd: Register::R1,
        rs1: Register::R0,
        imm: 0,
    });
    instructions.push(Instruction::Addi {
        rd: Register::R2,
        rs1: Register::R0,
        imm: 0,
    });
    instructions.push(Instruction::Addi {
        rd: Register::R3,
        rs1: Register::R0,
        imm: iterations,
    });

    // Loop start
    let loop_start_pc = (instructions.len() * 4) as i32;

    // Computation: 6 ADD operations per iteration
    // sum += counter
    instructions.push(Instruction::Add {
        rd: Register::R1,
        rs1: Register::R1,
        rs2: Register::R2,
    });
    // temp = counter * 2
    instructions.push(Instruction::Add {
        rd: Register::R4,
        rs1: Register::R2,
        rs2: Register::R2,
    });
    // sum += temp
    instructions.push(Instruction::Add {
        rd: Register::R1,
        rs1: Register::R1,
        rs2: Register::R4,
    });
    // temp = counter * 3
    instructions.push(Instruction::Add {
        rd: Register::R4,
        rs1: Register::R2,
        rs2: Register::R4,
    });
    // sum += temp
    instructions.push(Instruction::Add {
        rd: Register::R1,
        rs1: Register::R1,
        rs2: Register::R4,
    });
    // temp = counter * 4
    instructions.push(Instruction::Add {
        rd: Register::R4,
        rs1: Register::R2,
        rs2: Register::R4,
    });
    // sum += temp
    instructions.push(Instruction::Add {
        rd: Register::R1,
        rs1: Register::R1,
        rs2: Register::R4,
    });

    // counter++
    instructions.push(Instruction::Addi {
        rd: Register::R2,
        rs1: Register::R2,
        imm: 1,
    });

    // Loop condition: if (counter < limit) goto loop_start
    let current_pc = (instructions.len() * 4) as i32;
    let branch_offset = loop_start_pc - current_pc;
    instructions.push(Instruction::Blt {
        rs1: Register::R2,
        rs2: Register::R3,
        offset: branch_offset,
    });

    // Store result (observation point)
    instructions.push(Instruction::Sw {
        rs1: Register::R0,
        rs2: Register::R1,
        imm: 0,
    });

    instructions.push(Instruction::Ebreak);

    let mut program = Program::new();
    program.code = instructions
        .iter()
        .map(|inst| zkir_assembler::encode(inst))
        .collect();
    program.header.code_size = (program.code.len() * 4) as u32;

    program
}

/// Benchmark a single mode (deferred or immediate)
fn benchmark_mode(
    mode_name: &str,
    enable_deferred: bool,
    iterations: i32,
) -> Result<(u128, u128, usize, usize), String> {
    println!("\n{:=<70}", "");
    println!("Mode: {} | Iterations: {}", mode_name, iterations);
    println!("{:=<70}", "");

    let program = create_accumulator_program(iterations);

    // Configure VM
    let mut config = VMConfig::default();
    config.enable_execution_trace = true;
    config.enable_range_checking = true;
    config.enable_deferred_model = enable_deferred;

    // Execute with witness
    println!("Executing program...");
    let exec_start = Instant::now();

    let vm = VM::new(program.clone(), vec![], config);
    let execution_result = vm.run()
        .map_err(|e| format!("VM execution failed: {}", e))?;

    let exec_elapsed = exec_start.elapsed();

    // Get execution stats
    let cycles = execution_result.execution_trace.len();
    let normalizations = execution_result.normalization_witnesses.len();

    println!("  Execution time: {}.{:03}s",
        exec_elapsed.as_secs(), exec_elapsed.subsec_millis());
    println!("  Cycles: {}", cycles);
    println!("  Normalizations: {}", normalizations);
    println!("  Norm/cycle: {:.4}", normalizations as f64 / cycles as f64);

    // Convert to witness
    println!("Converting to witness...");
    let witness = vm_result_to_main_witness(&program, &[], execution_result)
        .map_err(|e| format!("Witness conversion failed: {:?}", e))?;

    // Generate proof
    println!("Generating proof...");
    let prove_start = Instant::now();

    let backend = Plonky3Backend::fast_test_config();
    let proof = backend.prove(&witness)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    let prove_elapsed = prove_start.elapsed();

    println!("  Proving time: {}.{:03}s",
        prove_elapsed.as_secs(), prove_elapsed.subsec_millis());

    // Verify
    println!("Verifying proof...");
    let verify_start = Instant::now();

    let vk = proof.verifying_key.clone();
    backend.verify(&proof, &vk)
        .map_err(|e| format!("Verification failed: {:?}", e))?;

    let verify_elapsed = verify_start.elapsed();

    println!("  Verification passed ({}.{:03}s)",
        verify_elapsed.as_secs(), verify_elapsed.subsec_millis());

    Ok((
        exec_elapsed.as_millis(),
        prove_elapsed.as_millis(),
        cycles,
        normalizations,
    ))
}

fn main() {
    println!("\n{:=<70}", "");
    println!(" DEFERRED vs IMMEDIATE CARRY MODE - PERFORMANCE COMPARISON");
    println!("{:=<70}", "");

    println!("\nThis benchmark measures actual performance difference between:");
    println!("  • Deferred mode: normalize only at observation points (branches)");
    println!("  • Immediate mode: normalize after every ADD/SUB/ADDI");
    println!("\nProgram: Tight loop with 6 ADDs per iteration, 1 branch per iteration");

    let test_configs = vec![
        ("Small", 50),
        ("Medium", 100),
        ("Large", 200),
    ];

    let mut deferred_results = Vec::new();
    let mut immediate_results = Vec::new();

    println!("\n{:=<70}", "");
    println!(" PHASE 1: DEFERRED MODE (normalize at observation points)");
    println!("{:=<70}", "");

    for (name, iterations) in &test_configs {
        match benchmark_mode(
            &format!("{} - Deferred", name),
            true, // enable_deferred
            *iterations,
        ) {
            Ok((exec_ms, prove_ms, cycles, norms)) => {
                deferred_results.push((*name, *iterations, exec_ms, prove_ms, cycles, norms));
            }
            Err(e) => {
                eprintln!("Deferred mode failed: {}", e);
                return;
            }
        }
    }

    println!("\n{:=<70}", "");
    println!(" PHASE 2: IMMEDIATE MODE (normalize after every ADD)");
    println!("{:=<70}", "");

    for (name, iterations) in &test_configs {
        match benchmark_mode(
            &format!("{} - Immediate", name),
            false, // disable_deferred
            *iterations,
        ) {
            Ok((exec_ms, prove_ms, cycles, norms)) => {
                immediate_results.push((*name, *iterations, exec_ms, prove_ms, cycles, norms));
            }
            Err(e) => {
                eprintln!("Immediate mode failed: {}", e);
                return;
            }
        }
    }

    // Print comparison table
    println!("\n{:=<70}", "");
    println!(" RESULTS COMPARISON");
    println!("{:=<70}", "");

    println!("\n{:<12} {:>8} {:>12} {:>12} {:>12}",
        "Config", "Iters", "Exec (ms)", "Prove (ms)", "Norms");
    println!("{:-<70}", "");

    println!("DEFERRED MODE:");
    for (name, iters, exec_ms, prove_ms, _cycles, norms) in &deferred_results {
        println!("  {:<10} {:>8} {:>12} {:>12} {:>12}",
            name, iters, exec_ms, prove_ms, norms);
    }

    println!("\nIMMEDIATE MODE:");
    for (name, iters, exec_ms, prove_ms, _cycles, norms) in &immediate_results {
        println!("  {:<10} {:>8} {:>12} {:>12} {:>12}",
            name, iters, exec_ms, prove_ms, norms);
    }

    // Calculate speedups
    println!("\n{:=<70}", "");
    println!(" PERFORMANCE IMPROVEMENT (Deferred vs Immediate)");
    println!("{:=<70}", "");

    println!("\n{:<12} {:>8} {:>12} {:>15} {:>15}",
        "Config", "Iters", "Prove Δ%", "Exec Δ%", "Norm Reduction");
    println!("{:-<70}", "");

    for i in 0..deferred_results.len() {
        let (name, iters, d_exec, d_prove, _d_cycles, d_norms) = &deferred_results[i];
        let (_,     _,     i_exec, i_prove, _i_cycles, i_norms) = &immediate_results[i];

        let prove_improvement = if *i_prove > 0 {
            ((*i_prove as f64 - *d_prove as f64) / *i_prove as f64) * 100.0
        } else {
            0.0
        };

        let exec_improvement = if *i_exec > 0 {
            ((*i_exec as f64 - *d_exec as f64) / *i_exec as f64) * 100.0
        } else {
            0.0
        };

        let norm_reduction = if *i_norms > 0 {
            (*i_norms as f64) / (*d_norms as f64)
        } else {
            1.0
        };

        println!("  {:<10} {:>8} {:>11.1}% {:>14.1}% {:>13.1}×",
            name, iters, prove_improvement, exec_improvement, norm_reduction);
    }

    // Summary
    println!("\n{:=<70}", "");
    println!(" KEY FINDINGS");
    println!("{:=<70}", "");

    if let (Some(d), Some(i)) = (deferred_results.get(1), immediate_results.get(1)) {
        let (_, iters, d_exec, d_prove, _d_cycles, d_norms) = d;
        let (_, _,     i_exec, i_prove, _i_cycles, i_norms) = i;

        println!("\nFor {} iterations:", iters);
        println!("\n  DEFERRED MODE (with full cryptographic soundness):");
        println!("    - Execution: {}ms", d_exec);
        println!("    - Proving: {}ms", d_prove);
        println!("    - Normalizations: {} (verified via constraints)", d_norms);
        println!("    - Range checks: {} (via LogUp)", d_norms * 6); // 6 per normalization

        println!("\n  IMMEDIATE MODE (current implementation):");
        println!("    - Execution: {}ms", i_exec);
        println!("    - Proving: {}ms", i_prove);
        println!("    - Normalizations: {} (not tracked)", i_norms);

        let overhead_pct = if *i_prove > 0 {
            ((*d_prove as f64 - *i_prove as f64) / *i_prove as f64) * 100.0
        } else {
            0.0
        };

        println!("\n  ANALYSIS:");
        println!("    Deferred mode overhead: {:.1}% more proving time", overhead_pct);
        println!("    This overhead buys you:");
        println!("      - Cryptographic soundness (normalization verification)");
        println!("      - Range check constraints ({} LogUp lookups)", d_norms * 6);
        println!("      - Carry verification (prevents forgery)");
        println!("      - Guaranteed unique decomposition");

        println!("\n    For compute-heavy workloads, deferred mode would be faster");
        println!("    if immediate mode had equivalent constraint verification.");

        println!("\n{:=<70}", "");
        println!(" IMPORTANT NOTE");
        println!("{:=<70}", "");
        println!("\nThe current immediate mode implementation does NOT have the same");
        println!("level of cryptographic soundness as deferred mode:");
        println!("\n  Deferred mode:");
        println!("    • Explicit normalization verification");
        println!("    • Range checks via LogUp protocol");
        println!("    • Carry value verification");
        println!("\n  Immediate mode (current):");
        println!("    • No explicit normalization tracking");
        println!("    • No normalization constraint verification");
        println!("    • Simpler but less secure");
        println!("\nFor production use, deferred mode is recommended due to its");
        println!("stronger security guarantees. The ~{:.1}% overhead is acceptable", overhead_pct.abs());
        println!("for the added cryptographic soundness.");
    }

    println!("\n{:=<70}", "");
}
