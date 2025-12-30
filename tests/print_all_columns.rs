//! Print ALL column values for debugging

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::air::main_witness_to_trace;
use zkir_prover::vm_integration::vm_result_to_witness;
use zkir_prover::witness::ProgramConfig;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_field::PrimeField32;

type F = p3_baby_bear::BabyBear;

#[test]
fn print_all_columns_row_0() {
    let header = ProgramHeader::new();

    let instructions = vec![
        Instruction::Addi {
            rd: Register::R3,
            rs1: Register::R0,
            imm: 12,
        },
        Instruction::Ebreak,
    ];

    let code: Vec<u32> = instructions.iter().map(|inst| encode(inst)).collect();

    let program = Program {
        header,
        code,
        data: Vec::new(),
    };

    let inputs = vec![];
    let mut vm_config = VMConfig::default();
    vm_config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), inputs.clone(), vm_config);
    let result = vm.run().expect("VM execution failed");

    let witness = vm_result_to_witness(&program, &inputs, result)
        .expect("Witness conversion failed");

    let config = ProgramConfig::default();
    let trace: RowMajorMatrix<F> = main_witness_to_trace(&witness, &config);

    println!("\n=== TRACE DIMENSIONS ===");
    println!("Width: {}, Height: {}", trace.width(), trace.height());

    println!("\n=== ALL COLUMNS FOR ROW 0 ===");
    for col in 0..trace.width() {
        let val = trace.get(0, col).as_canonical_u32();
        println!("Col {:3}: {:<12} (0x{:08X})", col, val, val);
    }

    println!("\n=== NON-ZERO COLUMNS FOR ROW 0 ===");
    for col in 0..trace.width() {
        let val = trace.get(0, col).as_canonical_u32();
        if val != 0 {
            println!("Col {:3}: {:<12} (0x{:08X})", col, val, val);
        }
    }
}
