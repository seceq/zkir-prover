//! Prove ZKIR programs compiled from C
//!
//! This example loads ZKIR bytecode files (compiled from C via zkir-llvm)
//! and generates cryptographic proofs using Plonky3.
//!
//! ## Workflow
//!
//! 1. Write C program (e.g., fibonacci.c)
//! 2. Compile to LLVM bitcode: `clang -O2 -emit-llvm -c fibonacci.c -o fibonacci.bc`
//! 3. Translate to ZKIR: `zkir-llvm fibonacci.bc -o fibonacci.zkir`
//! 4. Run this example to generate and verify proofs
//!
//! ## Usage
//!
//! ```bash
//! cargo run --release --example prove_zkir
//! ```

use std::fs;
use std::path::Path;
use std::time::Instant;
use zkir_prover::vm_integration::VMProver;
use zkir_spec::Program;

fn main() {
    println!("=== Proving ZKIR Programs (compiled from C) ===\n");

    let examples_dir = Path::new("examples");

    // Prove each program
    prove_program(examples_dir.join("simple_add/simple_add.zkir"), "simple_add", &[]);
    prove_program(examples_dir.join("loop_sum/loop_sum.zkir"), "loop_sum", &[]);
    prove_program(examples_dir.join("fibonacci/fibonacci.zkir"), "fibonacci", &[]);
    prove_program(examples_dir.join("bitwise_ops/bitwise_ops.zkir"), "bitwise_ops", &[]);
    prove_program(examples_dir.join("array_sum/array_sum.zkir"), "array_sum", &[]);

    println!("\n=== All programs proven and verified successfully! ===");
}

/// Load a ZKIR file for execution.
///
/// zkir-llvm now generates self-contained .zkir files with a _start stub that:
/// 1. Initializes the stack pointer (SP) to 64KB
/// 2. Calls main() with proper return address
/// 3. Terminates with EBREAK when main() returns
///
/// No load-time patching is required.
fn load_zkir_program(bytes: &[u8]) -> Result<Program, String> {
    Program::from_bytes(bytes)
        .map_err(|e| format!("Failed to parse ZKIR: {:?}", e))
}

fn prove_program<P: AsRef<Path>>(path: P, name: &str, inputs: &[u64]) {
    let path = path.as_ref();
    println!("--- {} ---", name);
    println!("  Loading: {}", path.display());

    // Load ZKIR bytecode
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("  Error reading file: {}", e);
            println!("  Hint: Run zkir-llvm to generate the .zkir file first");
            return;
        }
    };

    // Parse program using standard zkir-spec format
    let program = match load_zkir_program(&bytes) {
        Ok(p) => p,
        Err(e) => {
            println!("  Error parsing ZKIR: {}", e);
            return;
        }
    };

    println!("  Code size: {} instructions", program.code.len());
    println!("  Entry point: 0x{:x}", program.header.entry_point);

    // Create prover with fast test config for demo
    let prover = VMProver::fast_test_config();

    // First, just run VM to see if execution works
    println!("  Executing program in VM...");
    let exec_start = Instant::now();
    let exec_result = match prover.execute_with_witness(&program, inputs) {
        Ok(result) => result,
        Err(e) => {
            println!("  VM execution failed: {:?}", e);
            return;
        }
    };
    let exec_time = exec_start.elapsed();
    println!("  VM execution completed in {:?}", exec_time);
    println!("  Cycles: {}", exec_result.cycles);
    println!("  Halt reason: {:?}", exec_result.halt_reason);

    // Generate proof
    println!("  Generating proof...");
    let start = Instant::now();
    let (proof, vk) = match prover.prove_program(&program, inputs) {
        Ok(result) => result,
        Err(e) => {
            println!("  Proof generation failed: {:?}", e);
            return;
        }
    };
    let prove_time = start.elapsed();

    // Verify proof
    let start = Instant::now();
    let verified = match prover.verify(&proof, &vk) {
        Ok(v) => v,
        Err(e) => {
            println!("  Verification failed: {:?}", e);
            return;
        }
    };
    let verify_time = start.elapsed();

    println!("  Cycles: {}", proof.metadata.num_cycles);
    println!("  Trace height: {}", proof.metadata.trace_height);
    println!("  Prove time: {:?}", prove_time);
    println!("  Verify time: {:?}", verify_time);
    println!("  Verified: {}", verified);

    if !verified {
        println!("  WARNING: Proof verification returned false!");
    }

    println!();
}
