//! Test for simple array access.

use std::fs;
use zkir_spec::Program;
use zkir_runtime::{VM, VMConfig};

#[test]
fn test_simple_array() {
    let zkir_path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/array_sum/simple_array.zkir");

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

    // Verify data section
    println!("\nData section:");
    for i in 0..program.data.len().min(20) / 4 {
        let val = u32::from_le_bytes([
            program.data[i*4],
            program.data[i*4 + 1],
            program.data[i*4 + 2],
            program.data[i*4 + 3],
        ]);
        println!("  [{}] = {}", i, val);
    }

    // Print code
    println!("\nCode (hex):");
    for (i, inst) in program.code.iter().enumerate() {
        let pc = program.header.entry_point + (i * 4) as u32;
        println!("  {:#06x}: {:#010x}", pc, inst);
    }

    // Run in VM with trace
    let mut config = VMConfig::default();
    config.max_cycles = 100;
    config.trace = true;  // Enable instruction trace output
    config.enable_execution_trace = true;  // Enable detailed trace

    let vm = VM::new(program.clone(), vec![], config);
    match vm.run() {
        Ok(result) => {
            println!("\nExecution succeeded!");
            println!("  Cycles: {}", result.cycles);
            println!("  Halt reason: {:?}", result.halt_reason);
        }
        Err(e) => {
            println!("\nExecution failed: {:?}", e);
            panic!("VM execution should succeed: {:?}", e);
        }
    }
}
