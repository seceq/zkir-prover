//! Integration test for normalization witness conversion
//!
//! Tests Phase 7a: Witness Data Flow from zkir-runtime to zkir-prover

use zkir_prover::vm_integration::VMWitnessConverter;
use zkir_runtime::{VM, VMConfig};
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

#[test]
fn test_normalization_witness_conversion() {
    // Create a program that triggers normalization (ADD followed by branch)
    let instructions = vec![
        // R1 = 100
        Instruction::Addi {
            rd: Register::R1,
            rs1: Register::R0,
            imm: 100,
        },
        // R2 = 200
        Instruction::Addi {
            rd: Register::R2,
            rs1: Register::R0,
            imm: 200,
        },
        // R3 = R1 + R2 (deferred)
        Instruction::Add {
            rd: Register::R3,
            rs1: Register::R1,
            rs2: Register::R2,
        },
        // R4 = 300
        Instruction::Addi {
            rd: Register::R4,
            rs1: Register::R0,
            imm: 300,
        },
        // BEQ R3, R4 (observation point - triggers normalization)
        Instruction::Beq {
            rs1: Register::R3,
            rs2: Register::R4,
            offset: 8,
        },
        // Exit
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

    // Run with deferred model enabled
    let mut config = VMConfig::default();
    config.enable_deferred_model = true;
    config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], config);
    let vm_result = vm.run().expect("VM execution failed");

    // Verify VM collected normalization witnesses
    assert!(
        !vm_result.normalization_witnesses.is_empty(),
        "VM should have collected normalization witnesses"
    );

    // Convert to prover witness
    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result.clone())
        .expect("Witness conversion failed");

    // Verify prover witness includes normalization events
    assert_eq!(
        prover_witness.normalization_events.len(),
        vm_result.normalization_witnesses.len(),
        "Prover should have same number of normalization events as VM"
    );

    // Verify witness data matches
    for (vm_norm, prover_norm) in vm_result
        .normalization_witnesses
        .iter()
        .zip(prover_witness.normalization_events.iter())
    {
        assert_eq!(prover_norm.cycle, vm_norm.witness.cycle);
        assert_eq!(prover_norm.register, vm_norm.witness.register as u8);
        assert_eq!(prover_norm.accumulated, vm_norm.witness.accumulated_limbs);
        assert_eq!(prover_norm.normalized, vm_norm.witness.normalized_limbs);
        assert_eq!(prover_norm.carries, vm_norm.witness.carries);
    }
}

#[test]
fn test_normalization_witness_with_carry() {
    // Create a program with multiple ADDs to build up accumulated values
    let instructions = vec![
        // R1 = 1000
        Instruction::Addi {
            rd: Register::R1,
            rs1: Register::R0,
            imm: 1000,
        },
        // R2 = 2000
        Instruction::Addi {
            rd: Register::R2,
            rs1: Register::R0,
            imm: 2000,
        },
        // R3 = R1 + R2 (deferred)
        Instruction::Add {
            rd: Register::R3,
            rs1: Register::R1,
            rs2: Register::R2,
        },
        // R4 = 5000
        Instruction::Addi {
            rd: Register::R4,
            rs1: Register::R0,
            imm: 5000,
        },
        // R5 = R3 + R4 (deferred accumulation)
        Instruction::Add {
            rd: Register::R5,
            rs1: Register::R3,
            rs2: Register::R4,
        },
        // Store R5 (observation point - forces normalization)
        Instruction::Sw {
            rs1: Register::R0,
            rs2: Register::R5,
            imm: 0x10000,
        },
        // Exit
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

    let mut config = VMConfig::default();
    config.enable_deferred_model = true;
    config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], config);
    let vm_result = vm.run().expect("VM execution failed");

    // Verify normalization witnesses were collected
    assert!(
        !vm_result.normalization_witnesses.is_empty(),
        "VM should collect normalization witnesses"
    );

    // Convert to prover witness
    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result.clone())
        .expect("Witness conversion failed");

    // Verify conversion
    assert_eq!(
        prover_witness.normalization_events.len(),
        vm_result.normalization_witnesses.len()
    );

    // With normal values (< 2^20), carries should be zero
    // Just verify that the conversion preserves all carry data
    for (vm_norm, prover_norm) in vm_result
        .normalization_witnesses
        .iter()
        .zip(prover_witness.normalization_events.iter())
    {
        assert_eq!(prover_norm.carries, vm_norm.witness.carries);
    }
}

#[test]
fn test_no_normalization_without_deferred_model() {
    // Same program as test 1, but without deferred model
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

    // Run without deferred model
    let mut config = VMConfig::default();
    config.enable_deferred_model = false;
    config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], config);
    let vm_result = vm.run().expect("VM execution failed");

    // Verify no normalization witnesses without deferred model
    assert!(
        vm_result.normalization_witnesses.is_empty(),
        "VM should not collect normalization witnesses when deferred model is disabled"
    );

    // Convert to prover witness
    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result)
        .expect("Witness conversion failed");

    // Prover witness should also have no normalization events
    assert!(
        prover_witness.normalization_events.is_empty(),
        "Prover witness should have no normalization events"
    );
}

#[test]
fn test_witness_builder_normalization() {
    // Test that MainWitnessBuilder correctly builds with normalization events
    use zkir_prover::witness::{MainWitnessBuilder, NormalizationWitness, ProgramConfig};

    let config = ProgramConfig::DEFAULT;
    let program_hash = [0u8; 32];

    let mut builder = MainWitnessBuilder::new(config, program_hash);

    // Add a normalization event
    let norm_witness = NormalizationWitness {
        cycle: 42,
        register: 3,
        accumulated: [500, 0],
        normalized: [500, 0],
        carries: [0, 0],
    };

    builder.add_normalization(norm_witness.clone());

    let witness = builder.build();

    assert_eq!(witness.normalization_events.len(), 1);
    assert_eq!(witness.normalization_events[0].cycle, 42);
    assert_eq!(witness.normalization_events[0].register, 3);
    assert_eq!(witness.normalization_events[0].accumulated, [500, 0]);
    assert_eq!(witness.normalization_events[0].normalized, [500, 0]);
    assert_eq!(witness.normalization_events[0].carries, [0, 0]);
}
