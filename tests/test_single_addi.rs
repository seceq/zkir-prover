//! Test single ADDI instruction to debug constraint failure

use zkir_assembler::encode;
use zkir_prover::backend::plonky3::Plonky3Backend;
use zkir_prover::backend::r#trait::ProverBackend;
use zkir_prover::vm_integration::vm_result_to_witness;
use zkir_runtime::{VM, VMConfig};
use zkir_spec::{Instruction, Program, ProgramHeader, Register};

#[test]
fn test_single_addi() {
    let header = ProgramHeader::new();

    let instructions = vec![
        Instruction::Addi {
            rd: Register::R1,
            rs1: Register::R0,
            imm: 5,
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

    eprintln!("VM executed {} cycles", result.cycles);

    let witness = vm_result_to_witness(&program, &inputs, result).expect("Witness conversion failed");

    eprintln!("Witness has {} rows", witness.trace.len());

    if !witness.trace.is_empty() {
        let row0 = &witness.trace[0];
        eprintln!("Row 0 instruction: 0x{:08x}", row0.instruction);
        eprintln!("Row 0 opcode (from instruction): {}", row0.instruction & 0x7F);
        eprintln!("Row 0 rd: {}", (row0.instruction >> 7) & 0xF);
        eprintln!("Row 0 rs1: {}", (row0.instruction >> 11) & 0xF);
        eprintln!("Row 0 imm: {}", (row0.instruction >> 15) & 0x1FFFF);
        eprintln!("Row 0 r1: {:?}", row0.registers[1]);
        if witness.trace.len() > 1 {
            eprintln!("Row 1 r1: {:?}", witness.trace[1].registers[1]);
        }
    }

    // Generate and verify proof
    let backend = Plonky3Backend::test_config();
    let _proof = backend.prove(&witness).expect("Proof generation should succeed");

    eprintln!("Single ADDI test passed!");
}
