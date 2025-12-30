//! Witness verification utilities

use super::trace::{MainWitness, MemoryOp};
use thiserror::Error;

/// Witness verification errors
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Empty trace")]
    EmptyTrace,

    #[error("Cycle ordering error at index {0}: expected {1}, got {2}")]
    CycleOrdering(usize, u64, u64),

    #[error("PC discontinuity at cycle {0}: jumped from {1} to {2} without jump instruction")]
    PcDiscontinuity(u64, u64, u64),

    #[error("Memory inconsistency at address {0:?}, cycle {1}: read value {2:?} doesn't match last write {3:?}")]
    MemoryInconsistency(Vec<u32>, u64, Vec<u32>, Vec<u32>),

    #[error("Memory timestamp ordering error: cycle {0} comes before {1} for same address")]
    MemoryTimestampError(u64, u64),

    #[error("Range check failed for limb {0} at cycle {1}: chunk decomposition invalid")]
    RangeCheckFailed(u32, u64),

    #[error("Invalid register count: expected {0}, got {1}")]
    InvalidRegisterCount(usize, usize),

    #[error("Invalid bound: value bits {0} exceeds bound {1}")]
    InvalidBound(u32, u32),

    #[error("Configuration mismatch: {0}")]
    ConfigMismatch(String),
}

/// Verify an execution witness for consistency
pub fn verify_witness(witness: &MainWitness) -> Result<(), VerifyError> {
    verify_trace_consistency(witness)?;
    verify_memory_consistency(witness)?;
    verify_range_checks(witness)?;
    verify_bounds(witness)?;
    Ok(())
}

/// Verify trace consistency (cycle ordering, PC values)
fn verify_trace_consistency(witness: &MainWitness) -> Result<(), VerifyError> {
    if witness.trace.is_empty() {
        return Err(VerifyError::EmptyTrace);
    }

    let expected_reg_count = 16; // ZKIR has 16 registers

    for (i, row) in witness.trace.iter().enumerate() {
        // Check register count
        if row.registers.len() != expected_reg_count {
            return Err(VerifyError::InvalidRegisterCount(
                expected_reg_count,
                row.registers.len(),
            ));
        }

        if row.bounds.len() != expected_reg_count {
            return Err(VerifyError::InvalidRegisterCount(
                expected_reg_count,
                row.bounds.len(),
            ));
        }

        // Check cycle ordering (should be monotonically increasing)
        if i > 0 {
            let prev_cycle = witness.trace[i - 1].cycle;
            if row.cycle < prev_cycle {
                return Err(VerifyError::CycleOrdering(i, prev_cycle + 1, row.cycle));
            }
        }

        // Verify each register has correct number of limbs
        for (reg_idx, reg_limbs) in row.registers.iter().enumerate() {
            if reg_limbs.len() != witness.config.data_limbs as usize {
                return Err(VerifyError::ConfigMismatch(format!(
                    "Register {} at cycle {} has {} limbs, expected {}",
                    reg_idx,
                    row.cycle,
                    reg_limbs.len(),
                    witness.config.data_limbs
                )));
            }
        }
    }

    Ok(())
}

/// Verify memory consistency (read-after-write)
fn verify_memory_consistency(witness: &MainWitness) -> Result<(), VerifyError> {
    if witness.memory_ops.is_empty() {
        return Ok(()); // No memory operations is valid
    }

    // Sort memory trace by (address, timestamp)
    let mut sorted_trace = witness.memory_ops.clone();
    sorted_trace.sort();

    // Track last write to each address
    let mut last_writes: std::collections::HashMap<Vec<u32>, &MemoryOp> =
        std::collections::HashMap::new();

    for op in &sorted_trace {
        // Verify timestamp ordering for same address
        if let Some(last_op) = last_writes.get(&op.address) {
            if op.timestamp < last_op.timestamp {
                return Err(VerifyError::MemoryTimestampError(
                    op.timestamp,
                    last_op.timestamp,
                ));
            }
        }

        if op.is_write {
            // Record the write
            last_writes.insert(op.address.clone(), op);
        } else {
            // Verify read sees the correct value
            if let Some(last_write) = last_writes.get(&op.address) {
                if op.value != last_write.value {
                    return Err(VerifyError::MemoryInconsistency(
                        op.address.clone(),
                        op.timestamp,
                        op.value.clone(),
                        last_write.value.clone(),
                    ));
                }
            } else {
                // Reading from uninitialized memory - should be zero
                if !op.value.iter().all(|&v| v == 0) {
                    return Err(VerifyError::MemoryInconsistency(
                        op.address.clone(),
                        op.timestamp,
                        op.value.clone(),
                        vec![0; op.value.len()],
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Verify range check witnesses
fn verify_range_checks(witness: &MainWitness) -> Result<(), VerifyError> {
    let chunk_bits = witness.config.chunk_bits() as usize;

    for check in &witness.range_checks {
        if !check.verify(chunk_bits) {
            return Err(VerifyError::RangeCheckFailed(check.limb, check.cycle));
        }
    }

    Ok(())
}

/// Verify bounds are consistent
fn verify_bounds(witness: &MainWitness) -> Result<(), VerifyError> {
    let limb_bits = witness.config.limb_bits as u32;
    let limb_mask = (1u64 << limb_bits) - 1;

    for row in &witness.trace {
        for (reg_idx, (limbs, bound)) in row.registers.iter().zip(&row.bounds).enumerate() {
            // Check each limb is within limb_bits range
            for (limb_idx, &limb) in limbs.iter().enumerate() {
                if (limb as u64) > limb_mask {
                    return Err(VerifyError::ConfigMismatch(format!(
                        "Register {} limb {} at cycle {} exceeds limb_bits ({}): value {}",
                        reg_idx, limb_idx, row.cycle, limb_bits, limb
                    )));
                }
            }

            // Verify bound is reasonable (tight bounds should be accurate)
            if bound.is_tight {
                let max_value_from_bound = (1u64 << bound.max_bits) - 1;
                let actual_value = limbs_to_u64(limbs);

                if actual_value > max_value_from_bound {
                    return Err(VerifyError::InvalidBound(
                        actual_value as u32,
                        bound.max_bits,
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Helper to convert limbs to u64 for bound checking
fn limbs_to_u64(limbs: &[u32]) -> u64 {
    limbs
        .iter()
        .enumerate()
        .fold(0u64, |acc, (i, &limb)| acc | ((limb as u64) << (i * 20)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::trace::{ProgramConfig, MainTraceRow, MainWitnessBuilder, ValueBound};

    #[test]
    fn test_verify_empty_trace() {
        let config = ProgramConfig::DEFAULT;
        let witness = MainWitnessBuilder::new(config, [0u8; 32]).build();

        let result = verify_witness(&witness);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifyError::EmptyTrace));
    }

    #[test]
    fn test_verify_valid_trace() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        // Add valid trace rows
        for i in 0..5 {
            let row = MainTraceRow::new(i, i * 4, 0x12345678, registers.clone(), bounds.clone());
            builder.add_trace_row(row);
        }

        let witness = builder.build();
        assert!(verify_witness(&witness).is_ok());
    }

    #[test]
    fn test_verify_cycle_ordering() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        // Add rows with wrong ordering
        builder.add_trace_row(MainTraceRow::new(
            0,
            0,
            0,
            registers.clone(),
            bounds.clone(),
        ));
        builder.add_trace_row(MainTraceRow::new(
            2,
            4,
            0,
            registers.clone(),
            bounds.clone(),
        ));
        builder.add_trace_row(MainTraceRow::new(
            1,
            8,
            0,
            registers.clone(),
            bounds.clone(),
        )); // Out of order!

        let witness = builder.build();
        let result = verify_witness(&witness);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifyError::CycleOrdering(..)));
    }

    #[test]
    fn test_verify_memory_consistency_valid() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        builder.add_trace_row(MainTraceRow::new(
            0,
            0,
            0,
            registers.clone(),
            bounds.clone(),
        ));

        // Write then read
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![42, 0],
            0,
            true,
            ValueBound::tight(32),
        ));
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![42, 0],
            1,
            false,
            ValueBound::tight(32),
        ));

        let witness = builder.build();
        assert!(verify_witness(&witness).is_ok());
    }

    #[test]
    fn test_verify_memory_consistency_invalid() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        builder.add_trace_row(MainTraceRow::new(
            0,
            0,
            0,
            registers.clone(),
            bounds.clone(),
        ));

        // Write then read with wrong value
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![42, 0],
            0,
            true,
            ValueBound::tight(32),
        ));
        builder.add_memory_op(MemoryOp::new(
            vec![0x100, 0],
            vec![99, 0], // Wrong value!
            1,
            false,
            ValueBound::tight(32),
        ));

        let witness = builder.build();
        let result = verify_witness(&witness);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifyError::MemoryInconsistency(..)
        ));
    }

    #[test]
    fn test_verify_range_checks() {
        use crate::witness::trace::RangeCheckWitness;

        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 16];
        let bounds = vec![ValueBound::zero(); 16];

        builder.add_trace_row(MainTraceRow::new(
            0,
            0,
            0,
            registers.clone(),
            bounds.clone(),
        ));

        // Add valid range check
        builder.add_range_check(RangeCheckWitness::new(0, 0x12345, 10));

        let witness = builder.build();
        assert!(verify_witness(&witness).is_ok());
    }

    #[test]
    fn test_verify_bounds() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let mut registers = vec![vec![0u32, 0u32]; 16];
        let mut bounds = vec![ValueBound::zero(); 16];

        // Set a value with correct tight bound
        registers[5] = vec![0xFF, 0x00]; // 255 in low limb
        bounds[5] = ValueBound::tight(8); // 8-bit value

        builder.add_trace_row(MainTraceRow::new(0, 0, 0, registers, bounds));

        let witness = builder.build();
        assert!(verify_witness(&witness).is_ok());
    }

    #[test]
    fn test_verify_invalid_register_count() {
        let config = ProgramConfig::DEFAULT;
        let mut builder = MainWitnessBuilder::new(config, [0u8; 32]);

        let registers = vec![vec![0u32, 0u32]; 10]; // Wrong count!
        let bounds = vec![ValueBound::zero(); 16];

        builder.add_trace_row(MainTraceRow::new(0, 0, 0, registers, bounds));

        let witness = builder.build();
        let result = verify_witness(&witness);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerifyError::InvalidRegisterCount(..)
        ));
    }
}
