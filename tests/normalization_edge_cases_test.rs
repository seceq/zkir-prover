//! Edge case tests for normalization witness conversion
//!
//! Tests various edge cases and boundary conditions for Phase 7a

use zkir_prover::vm_integration::VMWitnessConverter;
use zkir_prover::witness::{NormalizationWitness, ProgramConfig};
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
fn test_empty_program_no_normalization() {
    // Minimal program with no arithmetic operations
    let instructions = vec![
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

    // No arithmetic means no normalization
    assert_eq!(vm_result.normalization_witnesses.len(), 0);

    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result)
        .expect("Conversion failed");

    assert_eq!(prover_witness.normalization_events.len(), 0);
}

#[test]
fn test_multiple_observation_points() {
    // Program with multiple observation points in sequence
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
        // BEQ R3, R3 (observation point 1 - normalizes R3)
        Instruction::Beq {
            rs1: Register::R3,
            rs2: Register::R3,
            offset: 0,
        },
        // R4 = R3 + R1 (deferred again)
        Instruction::Add {
            rd: Register::R4,
            rs1: Register::R3,
            rs2: Register::R1,
        },
        // BNE R4, R0 (observation point 2 - normalizes R4 and R0)
        Instruction::Bne {
            rs1: Register::R4,
            rs2: Register::R0,
            offset: 0,
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

    // Should have multiple normalization events
    assert!(
        vm_result.normalization_witnesses.len() >= 2,
        "Should have at least 2 normalization events from observation points"
    );

    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result.clone())
        .expect("Conversion failed");

    // All VM witnesses should be converted
    assert_eq!(
        prover_witness.normalization_events.len(),
        vm_result.normalization_witnesses.len()
    );

    // Verify all witnesses maintain data integrity
    for (vm_norm, prover_norm) in vm_result
        .normalization_witnesses
        .iter()
        .zip(prover_witness.normalization_events.iter())
    {
        assert_eq!(prover_norm.cycle, vm_norm.witness.cycle);
        assert_eq!(prover_norm.register, vm_norm.witness.register as u8);
    }
}

#[test]
fn test_normalization_witness_serialization() {
    // Test that NormalizationWitness can be serialized/deserialized
    let witness = NormalizationWitness {
        cycle: 42,
        register: 5,
        accumulated: [1000, 500],
        normalized: [1000, 500],
        carries: [0, 0],
    };

    let serialized = bincode::serialize(&witness).expect("Serialization failed");
    let deserialized: NormalizationWitness =
        bincode::deserialize(&serialized).expect("Deserialization failed");

    assert_eq!(deserialized.cycle, 42);
    assert_eq!(deserialized.register, 5);
    assert_eq!(deserialized.accumulated, [1000, 500]);
    assert_eq!(deserialized.normalized, [1000, 500]);
    assert_eq!(deserialized.carries, [0, 0]);
}

#[test]
fn test_r0_never_normalized() {
    // R0 is hardwired to zero and should never need normalization
    let instructions = vec![
        // Try to trigger R0 normalization (shouldn't happen)
        Instruction::Beq {
            rs1: Register::R0,
            rs2: Register::R0,
            offset: 0,
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

    // R0 should never be in normalization witnesses
    for norm_event in &vm_result.normalization_witnesses {
        assert_ne!(
            norm_event.witness.register,
            Register::R0,
            "R0 should never be normalized"
        );
    }

    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result)
        .expect("Conversion failed");

    // Double check in prover witness
    for norm_event in &prover_witness.normalization_events {
        assert_ne!(norm_event.register, 0, "R0 should never be normalized");
    }
}

#[test]
fn test_all_registers_can_be_normalized() {
    // Test that normalization works for all registers R1-R15
    let mut instructions = vec![];

    // Initialize all registers R1-R9 (R10-R11 reserved for syscall)
    for i in 1..10 {
        instructions.push(Instruction::Addi {
            rd: Register::from_index(i).unwrap(),
            rs1: Register::R0,
            imm: (i as i32) * 100,
        });
    }

    // Trigger normalization for each via comparison
    for i in 1..10 {
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

    let mut config = VMConfig::default();
    config.enable_deferred_model = true;
    config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], config);
    let vm_result = vm.run().expect("VM execution failed");

    // Should have normalization events for multiple registers
    assert!(
        vm_result.normalization_witnesses.len() > 0,
        "Should have normalization events"
    );

    // Verify all register indices are valid (1-15)
    for norm_event in &vm_result.normalization_witnesses {
        let reg_idx = norm_event.witness.register as u8;
        assert!(reg_idx > 0 && reg_idx < 16, "Invalid register index");
    }

    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result)
        .expect("Conversion failed");

    // Verify conversion preserves valid register indices
    for norm_event in &prover_witness.normalization_events {
        assert!(
            norm_event.register > 0 && norm_event.register < 16,
            "Invalid register index after conversion"
        );
    }
}

#[test]
fn test_witness_cycle_ordering() {
    // Verify that normalization witnesses are ordered by cycle
    let instructions = vec![
        // Multiple operations with observation points
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
            rs1: Register::R4,
            rs2: Register::R3,
        },
        // Observation point 2
        Instruction::Beq {
            rs1: Register::R5,
            rs2: Register::R5,
            offset: 0,
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

    if vm_result.normalization_witnesses.len() > 1 {
        // Verify witnesses are ordered by cycle
        for i in 1..vm_result.normalization_witnesses.len() {
            assert!(
                vm_result.normalization_witnesses[i].witness.cycle
                    >= vm_result.normalization_witnesses[i - 1].witness.cycle,
                "Normalization witnesses should be ordered by cycle"
            );
        }
    }

    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result)
        .expect("Conversion failed");

    if prover_witness.normalization_events.len() > 1 {
        // Verify ordering is preserved after conversion
        for i in 1..prover_witness.normalization_events.len() {
            assert!(
                prover_witness.normalization_events[i].cycle
                    >= prover_witness.normalization_events[i - 1].cycle,
                "Ordering should be preserved after conversion"
            );
        }
    }
}

#[test]
fn test_config_compatibility() {
    // Verify that ProgramConfig is correctly passed through
    let instructions = vec![
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
    config.enable_execution_trace = true;

    let vm = VM::new(program.clone(), vec![], config);
    let vm_result = vm.run().expect("VM execution failed");

    let converter = VMWitnessConverter::new(&program, &[]);
    let prover_witness = converter
        .convert_to_main_witness(vm_result)
        .expect("Conversion failed");

    // Verify config uses 30+30 architecture
    assert_eq!(prover_witness.config, ProgramConfig::DEFAULT);
    assert_eq!(prover_witness.config.limb_bits, 30);
    assert_eq!(prover_witness.config.normalized_bits, 20);
    assert_eq!(prover_witness.config.data_limbs, 2);
}
