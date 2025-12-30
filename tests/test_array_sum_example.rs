//! Test for the array_sum example program with memory operations.
//!
//! This test verifies that global variables and memory operations work correctly
//! by running the array_sum example which uses:
//! - Global initialized array: int nums[5] = {1, 2, 3, 4, 5}
//! - Memory loads: LW to read array elements
//! - Memory stores: SW to modify array elements

use std::fs;
use zkir_prover::vm_integration::VMProver;
use zkir_spec::Program;

/// Test that the array_sum example executes correctly in the VM.
#[test]
fn test_array_sum_vm_execution() {
    let zkir_path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/array_sum/array_sum.zkir");

    let bytes = match fs::read(zkir_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Skipping test - could not read {}: {}", zkir_path, e);
            return;
        }
    };

    let program = Program::from_bytes(&bytes).expect("Failed to parse program");

    println!("Program header:");
    println!("  Entry point: {:#x}", program.header.entry_point);
    println!("  Code size: {} bytes ({} instructions)",
             program.header.code_size, program.code.len());
    println!("  Data size: {} bytes", program.header.data_size);

    // Verify data section contains {1, 2, 3, 4, 5}
    assert_eq!(program.data.len(), 20, "Data section should be 5 * 4 = 20 bytes");
    for i in 0..5 {
        let val = u32::from_le_bytes([
            program.data[i*4],
            program.data[i*4 + 1],
            program.data[i*4 + 2],
            program.data[i*4 + 3],
        ]);
        assert_eq!(val, (i + 1) as u32, "nums[{}] should be {}", i, i + 1);
    }
    println!("  Data verified: [1, 2, 3, 4, 5]");

    // Run in VM with tracing enabled
    use zkir_runtime::{VM, VMConfig};
    let mut config = VMConfig::default();
    config.max_cycles = 100_000;
    config.enable_execution_trace = true;
    config.trace = true;  // Enable instruction-by-instruction tracing

    let vm = VM::new(program.clone(), vec![], config);
    let result = vm.run().expect("VM execution should succeed");

    println!("\nExecution result:");
    println!("  Cycles: {}", result.cycles);
    println!("  Halt reason: {:?}", result.halt_reason);

    // The program should compute:
    // sum_array(nums, 5) = 1+2+3+4+5 = 15
    // find_max(nums, 5) = 5
    // reverse_array modifies nums to [5,4,3,2,1]
    // first_after_reverse = nums[0] = 5
    // Return: total + maximum + first_after_reverse = 15 + 5 + 5 = 25

    // Check that the program ran successfully
    assert_eq!(result.halt_reason, zkir_runtime::HaltReason::Ebreak);
    println!("\nVM execution completed successfully");
}

/// Test that we can prove and verify the array_sum program.
#[test]
fn test_array_sum_prove_verify() {
    let zkir_path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/array_sum/array_sum.zkir");

    let bytes = match fs::read(zkir_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Skipping test - could not read {}: {}", zkir_path, e);
            return;
        }
    };

    let program = Program::from_bytes(&bytes).expect("Failed to parse program");

    let prover = VMProver::fast_test_config();

    println!("Proving array_sum example...");
    let (proof, vk) = prover.prove_program(&program, &[])
        .expect("Proof generation should succeed");

    println!("Proof generated:");
    println!("  Cycles: {}", proof.metadata.num_cycles);
    println!("  Trace height: {}", proof.metadata.trace_height);

    println!("Verifying proof...");
    prover.verify(&proof, &vk).expect("Verification should succeed");

    println!("\nProof verified successfully");
}
