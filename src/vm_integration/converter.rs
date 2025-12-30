//! VM ExecutionResult to Prover Witness Converter
//!
//! This module handles the conversion from VM execution results to the witness
//! format expected by the prover.
//!
//! ## Architecture: Execution-Trace-Only
//!
//! The VM uses an execution-trace-only architecture where all execution state,
//! including memory operations, is captured in a single execution trace.
//! Each trace row contains:
//! - Cycle number, PC, instruction
//! - Register states and bounds
//! - Optional memory operation (if the cycle performed memory access)
//!
//! This design eliminates the need for separate memory_trace collection and
//! ensures consistency between execution state and memory operations.

use crate::backend::r#trait::{ProofError, ProofResult};
use crate::types::extract_stype_rs2;
use crate::witness::{
    MainWitness, MainTraceRow, MainWitnessBuilder,
    MemoryOp, ProgramConfig, RangeCheckWitness, ValueBound,
};
use zkir_runtime::ExecutionResult as VMExecutionResult;
use zkir_spec::{MemoryOp as VMMemoryOp, Program, Value};

/// Converter from VM execution result to prover witness
pub struct VMWitnessConverter<'a> {
    program: &'a Program,
    inputs: &'a [u64],
}

impl<'a> VMWitnessConverter<'a> {
    /// Create a new converter
    pub fn new(program: &'a Program, inputs: &'a [u64]) -> Self {
        Self { program, inputs }
    }

    /// Convert VM execution result to main witness (RAP pattern)
    ///
    /// This produces a MainWitness containing only execution data (no auxiliary columns).
    /// Auxiliary columns (LogUp sums, memory permutation products) are computed separately
    /// using `compute_auxiliary()` after deriving the Fiat-Shamir challenge.
    ///
    /// Use this method for production-quality proofs with proper Fiat-Shamir security.
    pub fn convert_to_main_witness(&self, vm_result: VMExecutionResult) -> ProofResult<MainWitness> {
        // Extract program configuration
        let vm_config = self.program.config();
        let prover_config = self.vm_config_to_prover_config(vm_config);

        // Compute program hash
        let program_hash = self.compute_program_hash();

        // Create main witness builder
        let mut builder = MainWitnessBuilder::new(prover_config, program_hash);

        // Set public inputs
        let public_inputs = self.convert_inputs(prover_config);
        builder.set_inputs(public_inputs);

        // Set public outputs
        let public_outputs = self.convert_outputs(&vm_result.outputs, prover_config);
        builder.set_outputs(public_outputs);

        // Add range check witnesses
        for vm_rc in &vm_result.range_check_witnesses {
            let prover_rcs = self.convert_range_check(vm_rc, prover_config)?;
            for prover_rc in prover_rcs {
                builder.add_range_check(prover_rc);
            }
        }

        // Convert execution trace from VM format to prover format
        if !vm_result.execution_trace.is_empty() {
            for vm_trace_row in &vm_result.execution_trace {
                let main_row = self.convert_to_main_trace_row(vm_trace_row, prover_config)?;

                // Extract and add memory operations for auxiliary computation
                if let Some(ref mem_op) = main_row.memory_op {
                    builder.add_memory_op(mem_op.clone());
                }

                builder.add_trace_row(main_row);
            }
        } else {
            // Fallback to synthetic trace if VM didn't collect trace
            self.generate_main_trace_rows(&mut builder, &vm_result, prover_config)?;
        }

        // Set the cycle count from VM execution result
        builder.set_cycle_count(vm_result.cycles);

        // Build the main witness
        let mut main_witness = builder.build();

        // Pad trace to power of 2 for FFT (minimum 4 rows for CirclePcs)
        let len = main_witness.trace.len();
        let next_pow2 = len.next_power_of_two().max(4);

        if len < next_pow2 {
            if let Some(last_row) = main_witness.trace.last().cloned() {
                for _ in len..next_pow2 {
                    main_witness.trace.push(last_row.clone());
                }
            }
        }

        Ok(main_witness)
    }

    /// Convert VM trace row to MainTraceRow (for RAP pattern)
    fn convert_to_main_trace_row(
        &self,
        vm_row: &zkir_spec::TraceRow,
        config: ProgramConfig,
    ) -> ProofResult<MainTraceRow> {
        // Convert register values to limb format
        let mut registers = Vec::new();
        for reg_value in &vm_row.registers {
            registers.push(self.value_to_limbs(*reg_value, config));
        }

        // Convert bounds
        let bounds: Vec<ValueBound> = vm_row
            .bounds
            .iter()
            .map(|vm_bound| ValueBound::new(vm_bound.max_bits, true))
            .collect();

        // Create main trace row
        let mut row = MainTraceRow::new(
            vm_row.cycle,
            vm_row.pc,
            vm_row.instruction,
            registers,
            bounds,
        );

        // Extract memory operation from trace row
        if let Some(vm_mem_op) = vm_row.memory_ops.first() {
            let prover_mem_op = self.convert_memory_op(vm_mem_op, vm_row, config)?;
            row.memory_op = Some(prover_mem_op);
        }

        Ok(row)
    }

    /// Generate synthetic main trace rows (fallback when VM trace not available)
    fn generate_main_trace_rows(
        &self,
        builder: &mut MainWitnessBuilder,
        vm_result: &VMExecutionResult,
        config: ProgramConfig,
    ) -> ProofResult<()> {
        let data_limbs = config.data_limbs as usize;

        for cycle in 0..vm_result.cycles {
            let pc = cycle * 4;
            let instruction = 0x00000013; // NOP

            let registers = vec![vec![0u32; data_limbs]; 16];
            let bounds = vec![ValueBound::zero(); 16];

            let row = MainTraceRow::new(cycle, pc, instruction, registers, bounds);
            builder.add_trace_row(row);
        }

        Ok(())
    }

    /// Convert VM program config to prover config
    fn vm_config_to_prover_config(&self, vm_config: zkir_spec::Config) -> ProgramConfig {
        ProgramConfig {
            limb_bits: vm_config.limb_bits,
            data_limbs: vm_config.data_limbs,
            addr_limbs: vm_config.addr_limbs,
        }
    }

    /// Convert inputs to limb representation
    fn convert_inputs(&self, config: ProgramConfig) -> Vec<Vec<u32>> {
        self.inputs
            .iter()
            .map(|&val| self.value_to_limbs(val, config))
            .collect()
    }

    /// Convert outputs to limb representation
    fn convert_outputs(&self, outputs: &[u64], config: ProgramConfig) -> Vec<Vec<u32>> {
        outputs
            .iter()
            .map(|&val| self.value_to_limbs(val, config))
            .collect()
    }

    /// Convert a 64-bit value to limbs
    fn value_to_limbs(&self, value: u64, config: ProgramConfig) -> Vec<u32> {
        let limb_mask = (1u64 << config.limb_bits) - 1;
        let mut limbs = Vec::new();

        let mut val = value;
        for _ in 0..config.data_limbs {
            limbs.push((val & limb_mask) as u32);
            val >>= config.limb_bits;
        }

        limbs
    }

    /// Convert VM memory operation to prover format
    fn convert_memory_op(
        &self,
        vm_op: &VMMemoryOp,
        vm_row: &zkir_spec::TraceRow,
        config: ProgramConfig,
    ) -> ProofResult<MemoryOp> {
        let address = self.value_to_limbs(vm_op.address, config);

        // Extract value based on operation type
        // For STORE: value comes from source register (rs2)
        // For LOAD: value comes from memory (vm_op.value)
        let value = if vm_op.op_type == zkir_spec::MemOpType::Write {
            // Store operation: extract rs2 from instruction using S-type encoding
            let inst = vm_row.instruction;
            let rs2_idx = extract_stype_rs2(inst) as usize;

            // Get value from rs2 register
            let rs2_value = vm_row.registers.get(rs2_idx)
                .ok_or_else(|| ProofError::InvalidWitness(
                    format!("Store instruction references invalid register R{}", rs2_idx)
                ))?;

            self.value_to_limbs(*rs2_value, config)
        } else {
            // Load operation: value comes from memory
            self.value_to_limbs(vm_op.value, config)
        };

        let timestamp = vm_op.timestamp;
        let is_write = vm_op.op_type == zkir_spec::MemOpType::Write;

        // Convert value bound
        let bound = ValueBound::new(vm_op.bound.max_bits, true);

        Ok(MemoryOp::new(address, value, timestamp, is_write, bound))
    }

    /// Convert VM range check witness to prover format
    fn convert_range_check(
        &self,
        vm_rc: &zkir_runtime::RangeCheckWitness,
        _config: ProgramConfig,
    ) -> ProofResult<Vec<RangeCheckWitness>> {
        // The VM provides chunk decomposition for multiple values
        // Convert each check to prover format
        let mut prover_checks = Vec::new();

        for (value, chunks, pc) in vm_rc.checks() {
            // Reconstruct limb from value
            let limb = (*value).to_u64() as u32;

            // Create prover range check witness
            // Note: chunks should be exactly 2 chunks (for 20-bit limbs: 2x10-bit chunks)
            let prover_rc = RangeCheckWitness {
                cycle: *pc,
                limb,
                chunks: [
                    *chunks.get(0).unwrap_or(&0),
                    *chunks.get(1).unwrap_or(&0),
                ],
            };

            prover_checks.push(prover_rc);
        }

        Ok(prover_checks)
    }

    /// Compute program hash (simplified - just hash the code section)
    fn compute_program_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Hash the program code
        for instruction in &self.program.code {
            hasher.update(&instruction.to_le_bytes());
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkir_spec::{MemOpType, ProgramHeader};

    fn create_test_program() -> Program {
        let mut header = ProgramHeader::new();
        header.limb_bits = 20;
        header.data_limbs = 2;
        header.addr_limbs = 2;
        header.entry_point = 0x1000;

        Program {
            header,
            code: vec![0x00000013], // NOP
            data: Vec::new(),
        }
    }

    #[test]
    fn test_vm_config_conversion() {
        let program = create_test_program();
        let converter = VMWitnessConverter::new(&program, &[]);

        let vm_config = program.config();
        let prover_config = converter.vm_config_to_prover_config(vm_config);

        assert_eq!(prover_config.limb_bits, 20);
        assert_eq!(prover_config.data_limbs, 2);
        assert_eq!(prover_config.addr_limbs, 2);
    }

    #[test]
    fn test_value_to_limbs() {
        let program = create_test_program();
        let converter = VMWitnessConverter::new(&program, &[]);
        let config = ProgramConfig::default();

        // Test: 0x12345 = 74565 decimal
        // With 20-bit limbs: [0x12345 & 0xFFFFF, 0x12345 >> 20]
        let limbs = converter.value_to_limbs(0x12345, config);
        assert_eq!(limbs.len(), 2);
        assert_eq!(limbs[0], 0x12345); // Fits in one limb
        assert_eq!(limbs[1], 0);
    }

    #[test]
    fn test_inputs_conversion() {
        let program = create_test_program();
        let inputs = vec![42, 100];
        let converter = VMWitnessConverter::new(&program, &inputs);
        let config = ProgramConfig::default();

        let converted = converter.convert_inputs(config);
        assert_eq!(converted.len(), 2);
        assert_eq!(converted[0][0], 42);
        assert_eq!(converted[1][0], 100);
    }

    #[test]
    fn test_memory_op_conversion() {
        let program = create_test_program();
        let converter = VMWitnessConverter::new(&program, &[]);
        let config = ProgramConfig::default();

        let vm_op = zkir_spec::MemoryOp {
            address: 0x1000,
            value: 42,
            timestamp: 10,
            op_type: MemOpType::Write,
            bound: zkir_spec::ValueBound {
                max_bits: 32,
                source: zkir_spec::BoundSource::ProgramWidth,
            },
            width: 4,
        };

        // Create a mock trace row with register R1 = 42 for store operation
        // ZKIR v3.4 S-type encoding (7-bit opcode): [opcode:7][rs1:4][rs2:4][imm:17]
        // SW opcode = 0x3A, rs1=R3 (base address), rs2=R1 (value to store), imm=0
        // Encoding: 0x3A | (3 << 7) | (1 << 11) | (0 << 15) = 0x3A | 0x180 | 0x800 = 0x09BA
        let vm_row = zkir_spec::TraceRow {
            cycle: 0,
            pc: 0x1000,
            instruction: 0x000009BA,  // SW instruction: rs1=R3, rs2=R1
            registers: [0, 42, 0, 0x1000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  // R1=42, R3=0x1000
            bounds: [zkir_spec::ValueBound {
                max_bits: 32,
                source: zkir_spec::BoundSource::ProgramWidth,
            }; 16],
            memory_ops: vec![],
        };

        let prover_op = converter.convert_memory_op(&vm_op, &vm_row, config).unwrap();
        assert_eq!(prover_op.timestamp, 10);
        assert!(prover_op.is_write);
        assert_eq!(prover_op.value[0], 42);  // Value should come from R1=42 (rs2)
    }

    #[test]
    fn test_program_hash() {
        let program = create_test_program();
        let converter = VMWitnessConverter::new(&program, &[]);

        let hash = converter.compute_program_hash();
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]); // Should be non-zero
    }
}
