//! Auxiliary witness computation for RAP pattern
//!
//! This module computes auxiliary trace columns (LogUp sums, memory permutation products)
//! using the real Fiat-Shamir challenge derived from the committed main trace.

use p3_field::Field;
use std::collections::HashMap;

use crate::constraints::challenges::RapChallenges;
use crate::types::{
    Opcode, OPCODE_MASK, RD_SHIFT, RS1_SHIFT, RS2_SHIFT, REGISTER_MASK,
    extract_opcode,
};
use super::trace::{MainWitness, MainTraceRow, ProgramConfig};
use super::table_sums::TableSums;
use super::multiplicity::LogUpMultiplicities;

/// Auxiliary witness data (computed with real Fiat-Shamir challenge)
///
/// This represents the "auxiliary trace" in RAP (Randomized AIR with Preprocessing).
/// These columns depend on the Fiat-Shamir challenge α, which is only available
/// AFTER committing the main trace.
///
/// Column layout matches AIR auxiliary columns:
/// - Memory permutation: exec, sorted (2 columns)
/// - LogUp queries: AND, OR, XOR, range (4 columns)
/// - LogUp tables: AND, OR, XOR, range (4 columns)
/// Total: 10 auxiliary columns
#[derive(Clone, Debug)]
pub struct AuxWitness<F: Field> {
    /// Memory permutation execution-order product (∏(α - encoded_mem_op))
    pub mem_perm_exec: Vec<F>,

    /// Memory permutation sorted-order product (∏(α - encoded_mem_op))
    pub mem_perm_sorted: Vec<F>,

    /// LogUp AND operation running sum (∑ 1/(α - encoded_lookup))
    pub logup_and: Vec<F>,

    /// LogUp OR operation running sum (∑ 1/(α - encoded_lookup))
    pub logup_or: Vec<F>,

    /// LogUp XOR operation running sum (∑ 1/(α - encoded_lookup))
    pub logup_xor: Vec<F>,

    /// LogUp range check running sum (∑ 1/(α - chunk))
    pub logup_range: Vec<F>,

    /// LogUp AND table-side sum (∑ m/(α - encoded_table_entry))
    pub logup_and_table: Vec<F>,

    /// LogUp OR table-side sum (∑ m/(α - encoded_table_entry))
    pub logup_or_table: Vec<F>,

    /// LogUp XOR table-side sum (∑ m/(α - encoded_table_entry))
    pub logup_xor_table: Vec<F>,

    /// LogUp range check table-side sum (∑ m/(α - encoded_table_entry))
    pub logup_range_table: Vec<F>,
}

impl<F: Field> AuxWitness<F> {
    /// Create an empty auxiliary witness with the given size
    pub fn new(size: usize) -> Self {
        Self {
            mem_perm_exec: vec![F::ONE; size],
            mem_perm_sorted: vec![F::ONE; size],
            logup_and: vec![F::ZERO; size],
            logup_or: vec![F::ZERO; size],
            logup_xor: vec![F::ZERO; size],
            logup_range: vec![F::ZERO; size],
            logup_and_table: vec![F::ZERO; size],
            logup_or_table: vec![F::ZERO; size],
            logup_xor_table: vec![F::ZERO; size],
            logup_range_table: vec![F::ZERO; size],
        }
    }
}

/// Memory operation for auxiliary computation
#[derive(Clone, Debug)]
pub struct MemoryOperation {
    /// Address (reconstructed from limbs)
    pub addr: u64,
    /// Timestamp (PC value)
    pub timestamp: u64,
    /// Value (reconstructed from limbs)
    pub value: u64,
    /// Is this a write operation?
    pub is_write: bool,
    /// Original row index in execution trace
    pub row_index: usize,
}

impl MemoryOperation {
    pub fn new(addr: u64, timestamp: u64, value: u64, is_write: bool, row_index: usize) -> Self {
        Self {
            addr,
            timestamp,
            value,
            is_write,
            row_index,
        }
    }
}

/// Compute auxiliary witness from main witness with real Fiat-Shamir challenge
///
/// This is the core RAP computation: after committing the main trace and deriving
/// the challenge α from the transcript, we compute all auxiliary columns.
///
/// # Arguments
/// * `main` - Main witness (execution data without auxiliary columns)
/// * `challenge` - Fiat-Shamir challenge from transcript (α)
/// * `padded_rows` - Number of rows after padding to power of 2
///
/// # Returns
/// Auxiliary witness with all running sums and products computed
pub fn compute_auxiliary<F: Field>(
    main: &MainWitness,
    challenge: F,
    padded_rows: usize,
) -> AuxWitness<F> {
    let config = &main.config;
    let actual_rows = main.trace.len();

    // Initialize auxiliary witness
    let mut aux = AuxWitness::new(padded_rows);

    // Compute LogUp table sums using real challenge
    let table_sums = TableSums::compute(&main.multiplicities, challenge, config);

    // Populate table sums (constant per trace)
    // Table sums are precomputed based on multiplicities and don't change per row
    for i in 0..actual_rows {
        aux.logup_and_table[i] = table_sums.and_sum;
        aux.logup_or_table[i] = table_sums.or_sum;
        aux.logup_xor_table[i] = table_sums.xor_sum;
        aux.logup_range_table[i] = table_sums.range_sum;
    }

    // Compute LogUp running sums for range checks and bitwise operations
    compute_logup_sums(&main, challenge, &mut aux, actual_rows, config);

    // Compute memory permutation products
    compute_memory_permutation(&main, challenge, &mut aux, actual_rows, config);

    // Pad auxiliary columns to power of 2
    pad_auxiliary(&mut aux, actual_rows, padded_rows);

    aux
}

/// Compute auxiliary witness with separate challenges for different operations
///
/// This is the preferred function for RAP pattern as it uses the correct challenge
/// for each operation type:
/// - memory_permutation for memory consistency
/// - logup_bitwise for bitwise LogUp (AND, OR, XOR)
/// - logup_range for range check LogUp
pub fn compute_auxiliary_with_challenges<F: Field>(
    main: &MainWitness,
    challenges: &RapChallenges<F>,
    padded_rows: usize,
) -> AuxWitness<F> {
    let config = &main.config;
    let actual_rows = main.trace.len();

    // Initialize auxiliary witness
    let mut aux = AuxWitness::new(padded_rows);

    // Compute multiplicities from trace (if not already populated)
    // This ensures table sums match query sums even if multiplicities weren't tracked during witness generation
    let multiplicities = compute_multiplicities_from_main_trace(main);

    // Compute LogUp table sums using bitwise challenge
    let table_sums = TableSums::compute(&multiplicities, challenges.logup_bitwise, config);

    // Populate table sums (constant per trace)
    for i in 0..actual_rows {
        aux.logup_and_table[i] = table_sums.and_sum;
        aux.logup_or_table[i] = table_sums.or_sum;
        aux.logup_xor_table[i] = table_sums.xor_sum;
        aux.logup_range_table[i] = table_sums.range_sum;
    }

    // Compute LogUp running sums using bitwise challenge for bitwise ops
    compute_logup_sums(main, challenges.logup_bitwise, &mut aux, actual_rows, config);

    // Compute memory permutation using memory challenge
    compute_memory_permutation(main, challenges.memory_permutation, &mut aux, actual_rows, config);

    // Pad auxiliary columns to power of 2
    pad_auxiliary(&mut aux, actual_rows, padded_rows);

    aux
}

/// Compute LogUp running sums for range checks and bitwise operations
fn compute_logup_sums<F: Field>(
    main: &MainWitness,
    challenge: F,
    aux: &mut AuxWitness<F>,
    actual_rows: usize,
    config: &ProgramConfig,
) {
    let mut and_sum = F::ZERO;
    let mut or_sum = F::ZERO;
    let mut xor_sum = F::ZERO;
    let mut range_sum = F::ZERO; // Updated at normalization points

    let chunk_bits = config.normalized_bits / 2;  // 10-bit for 30+30 architecture
    let chunk_mask = (1u32 << chunk_bits) - 1;
    let shift_10 = F::from_canonical_u32(1 << 10);
    let shift_20 = F::from_canonical_u32(1 << 20);

    // For each trace row, accumulate LogUp sums
    for (idx, trace_row) in main.trace.iter().enumerate().take(actual_rows) {
        // Store OLD values (before this row's operation)
        // This matches the constraint which checks: delta = next - local
        aux.logup_and[idx] = and_sum;
        aux.logup_or[idx] = or_sum;
        aux.logup_xor[idx] = xor_sum;
        aux.logup_range[idx] = range_sum;

        // Decode instruction to check if it's a bitwise operation
        // ZKIR v3.4 uses 7-bit opcodes (values 0x00-0x51)
        let inst = trace_row.instruction;
        let opcode = extract_opcode(inst);
        let rd = ((inst >> RD_SHIFT) & REGISTER_MASK) as usize;
        let rs1 = ((inst >> RS1_SHIFT) & REGISTER_MASK) as usize;
        let rs2 = ((inst >> RS2_SHIFT) & REGISTER_MASK) as usize;

        // Bitwise operations: AND, OR, XOR
        let is_and = opcode == Opcode::And.to_u8() as u32;
        let is_or = opcode == Opcode::Or.to_u8() as u32;
        let is_xor = opcode == Opcode::Xor.to_u8() as u32;

        if is_and || is_or || is_xor {
            // IMPORTANT: Only compute LogUp contribution for limb 0
            // The constraint system only checks limb 0 (see execution.rs:429)
            // If we accumulate for all limbs, the delta won't match!
            for limb_idx in 0..1 {  // Only limb 0
                // Get register limbs
                let rs1_limb = trace_row.registers.get(rs1)
                    .and_then(|r| r.get(limb_idx))
                    .copied()
                    .unwrap_or(0);
                let rs2_limb = trace_row.registers.get(rs2)
                    .and_then(|r| r.get(limb_idx))
                    .copied()
                    .unwrap_or(0);
                let rd_limb = trace_row.registers.get(rd)
                    .and_then(|r| r.get(limb_idx))
                    .copied()
                    .unwrap_or(0);

                // Split into chunks
                let rs1_chunk0 = rs1_limb & chunk_mask;
                let rs1_chunk1 = rs1_limb >> chunk_bits;
                let rs2_chunk0 = rs2_limb & chunk_mask;
                let rs2_chunk1 = rs2_limb >> chunk_bits;
                let rd_chunk0 = rd_limb & chunk_mask;
                let rd_chunk1 = rd_limb >> chunk_bits;

                // Encode lookups: encoded = rs1_chunk + rs2_chunk*2^10 + rd_chunk*2^20
                let encoded_0 = F::from_canonical_u32(rs1_chunk0)
                    + F::from_canonical_u32(rs2_chunk0) * shift_10
                    + F::from_canonical_u32(rd_chunk0) * shift_20;
                let encoded_1 = F::from_canonical_u32(rs1_chunk1)
                    + F::from_canonical_u32(rs2_chunk1) * shift_10
                    + F::from_canonical_u32(rd_chunk1) * shift_20;

                // LogUp contribution: 1 / (challenge - encoded)
                let diff_0 = challenge - encoded_0;
                let diff_1 = challenge - encoded_1;

                // Add to appropriate accumulator
                // Note: need to invert diff, but we can use the batch inversion trick
                // For now, compute directly (will be slow but correct)
                let inv_0 = diff_0.try_inverse().unwrap_or(F::ZERO);
                let inv_1 = diff_1.try_inverse().unwrap_or(F::ZERO);

                if is_and {
                    and_sum = and_sum + inv_0 + inv_1;
                } else if is_or {
                    or_sum = or_sum + inv_0 + inv_1;
                } else if is_xor {
                    xor_sum = xor_sum + inv_0 + inv_1;
                }
            }
        }

        // Phase 7b: Range check LogUp for normalized values (deferred carry model)
        //
        // At normalization points, add LogUp queries for:
        // - Normalized limb chunks (2 per limb)
        // - Carry values (1 per limb)
        let current_cycle = trace_row.cycle;
        let norm_events: Vec<_> = main.normalization_events.iter()
            .filter(|event| event.cycle == current_cycle)
            .collect();
        for norm_event in norm_events {
            // Range check normalized limb chunks
            for &normalized_limb in &norm_event.normalized {
                let chunk_0 = normalized_limb & chunk_mask;
                let chunk_1 = normalized_limb >> chunk_bits;
                let diff_0 = challenge - F::from_canonical_u32(chunk_0);
                let diff_1 = challenge - F::from_canonical_u32(chunk_1);
                let inv_0 = diff_0.try_inverse().unwrap_or(F::ZERO);
                let inv_1 = diff_1.try_inverse().unwrap_or(F::ZERO);
                range_sum = range_sum + inv_0 + inv_1;
            }
            // CRITICAL: Range check carries (prevents forged normalized values)
            for &carry in &norm_event.carries {
                let diff = challenge - F::from_canonical_u32(carry);
                let inv = diff.try_inverse().unwrap_or(F::ZERO);
                range_sum = range_sum + inv;
            }
        }
    }
}

/// Compute memory permutation running products
fn compute_memory_permutation<F: Field>(
    main: &MainWitness,
    challenge: F,
    aux: &mut AuxWitness<F>,
    actual_rows: usize,
    config: &ProgramConfig,
) {
    // Collect memory operations and reconstruct full addresses/values
    let mut memory_ops = Vec::new();

    for (row_idx, trace_row) in main.trace.iter().enumerate().take(actual_rows) {
        if let Some(ref mem_op) = trace_row.memory_op {
            // Address: reconstructed with limb_bits (30-bit, from trace)
            let addr_limb_base = 1u64 << config.limb_bits;
            let mut addr = 0u64;
            for (i, limb) in mem_op.address.iter().enumerate() {
                addr += (*limb as u64) * addr_limb_base.pow(i as u32);
            }

            // Value: reconstructed with normalized_bits (20-bit, stores are normalized)
            let value_limb_base = 1u64 << config.normalized_bits;
            let mut value = 0u64;
            for (i, limb) in mem_op.value.iter().enumerate() {
                value += (*limb as u64) * value_limb_base.pow(i as u32);
            }

            memory_ops.push(MemoryOperation::new(
                addr,
                trace_row.pc,
                value,
                mem_op.is_write,
                row_idx,
            ));
        }
    }

    // Sort by (address, timestamp) for sorted-order product
    let mut sorted_ops = memory_ops.clone();
    sorted_ops.sort_by_key(|op| (op.addr, op.timestamp));

    // Verify read-write consistency in sorted order
    verify_memory_consistency(&sorted_ops);

    // Compute execution-order running product
    let mut exec_product = F::ONE;
    for (idx, trace_row) in main.trace.iter().enumerate().take(actual_rows) {
        if let Some(ref mem_op) = trace_row.memory_op {
            // Encode: addr + α(timestamp + α(value + α*is_write))
            let encoded = encode_memory_operation(
                &mem_op.address,
                trace_row.pc,
                &mem_op.value,
                mem_op.is_write,
                challenge,
                config,
            );

            // Product update: product *= (challenge - encoded)
            exec_product = exec_product * (challenge - encoded);
        }
        aux.mem_perm_exec[idx] = exec_product;
    }

    // Compute sorted-order running product
    let mut sorted_product = F::ONE;
    let mut sorted_products = vec![F::ONE; actual_rows];

    for op in &sorted_ops {
        // Find the memory operation in main witness
        let mem_op = &main.trace[op.row_index].memory_op.as_ref().unwrap();

        // Encode with same scheme
        let encoded = encode_memory_operation(
            &mem_op.address,
            op.timestamp,
            &mem_op.value,
            op.is_write,
            challenge,
            config,
        );

        // Product update
        sorted_product = sorted_product * (challenge - encoded);
        sorted_products[op.row_index] = sorted_product;
    }

    // Save final sorted product for last row and padding
    let final_sorted_product = sorted_product;

    // Populate sorted products in auxiliary witness
    for idx in 0..actual_rows {
        let is_last_row = idx == actual_rows - 1;
        aux.mem_perm_sorted[idx] = if is_last_row {
            final_sorted_product
        } else {
            sorted_products[idx]
        };
    }
}

/// Encode a memory operation using Horner's method
///
/// Encoding: addr + α(timestamp + α(value + α*is_write))
///
/// IMPORTANT: In the deferred carry model:
/// - Addresses come from trace (accumulated, 30-bit limbs) → use limb_bits
/// - Values in memory ops are NORMALIZED (stores trigger normalization) → use normalized_bits
fn encode_memory_operation<F: Field>(
    addr_limbs: &[u32],
    timestamp: u64,
    value_limbs: &[u32],
    is_write: bool,
    challenge: F,
    config: &ProgramConfig,
) -> F {
    // Address limbs are from trace (accumulated, 30-bit packing)
    let addr_limb_base = F::from_canonical_u64(1u64 << config.limb_bits);

    // Reconstruct address from limbs (using limb_bits = 30)
    let mut addr = F::ZERO;
    for (i, limb) in addr_limbs.iter().enumerate() {
        let power = addr_limb_base.exp_u64(i as u64);
        addr = addr + F::from_canonical_u32(*limb) * power;
    }

    // Value limbs are NORMALIZED (stores trigger normalization, 20-bit packing)
    let value_limb_base = F::from_canonical_u64(1u64 << config.normalized_bits);

    // Reconstruct value from limbs (using normalized_bits = 20)
    let mut value = F::ZERO;
    for (i, limb) in value_limbs.iter().enumerate() {
        let power = value_limb_base.exp_u64(i as u64);
        value = value + F::from_canonical_u32(*limb) * power;
    }

    // Encode: addr + α(timestamp + α(value + α*is_write))
    let is_write_f = if is_write { F::ONE } else { F::ZERO };
    let timestamp_f = F::from_canonical_u64(timestamp);

    let inner = value + challenge * is_write_f;
    let middle = timestamp_f + challenge * inner;
    let encoded = addr + challenge * middle;

    encoded
}

/// Verify read-write consistency in sorted memory operations
fn verify_memory_consistency(sorted_ops: &[MemoryOperation]) {
    let mut last_write_value: HashMap<u64, u64> = HashMap::new();

    for op in sorted_ops {
        if op.is_write {
            // Record this write for future reads
            last_write_value.insert(op.addr, op.value);
        } else {
            // Verify read sees correct value
            // For the first read from an address (no prior write in trace),
            // treat the read value as the initial memory content (from code/data sections)
            if let Some(&expected) = last_write_value.get(&op.addr) {
                if op.value != expected {
                    panic!(
                        "Memory consistency violation at addr={:#x}, timestamp={}: \
                         read value {:#x} but expected {:#x} from last write",
                        op.addr, op.timestamp, op.value, expected
                    );
                }
            } else {
                // First read from this address - record it as the initial value
                last_write_value.insert(op.addr, op.value);
            }
        }
    }
}

/// Pad auxiliary columns with final values
fn pad_auxiliary<F: Field>(
    aux: &mut AuxWitness<F>,
    actual_rows: usize,
    padded_rows: usize,
) {
    if actual_rows >= padded_rows {
        return;
    }

    // Get final values from last actual row
    let final_mem_exec = aux.mem_perm_exec[actual_rows - 1];
    let final_mem_sorted = aux.mem_perm_sorted[actual_rows - 1];
    let final_and = aux.logup_and[actual_rows - 1];
    let final_or = aux.logup_or[actual_rows - 1];
    let final_xor = aux.logup_xor[actual_rows - 1];
    let final_range = aux.logup_range[actual_rows - 1];
    let final_and_table = aux.logup_and_table[actual_rows - 1];
    let final_or_table = aux.logup_or_table[actual_rows - 1];
    let final_xor_table = aux.logup_xor_table[actual_rows - 1];
    let final_range_table = aux.logup_range_table[actual_rows - 1];

    // Pad with final values
    for i in actual_rows..padded_rows {
        aux.mem_perm_exec[i] = final_mem_exec;
        aux.mem_perm_sorted[i] = final_mem_sorted;
        aux.logup_and[i] = final_and;
        aux.logup_or[i] = final_or;
        aux.logup_xor[i] = final_xor;
        aux.logup_range[i] = final_range;
        aux.logup_and_table[i] = final_and_table;
        aux.logup_or_table[i] = final_or_table;
        aux.logup_xor_table[i] = final_xor_table;
        aux.logup_range_table[i] = final_range_table;
    }
}

/// Compute LogUp multiplicities from main trace
///
/// This scans the main witness trace for bitwise operations and records each
/// lookup into the multiplicity tracker. Used when multiplicities weren't
/// tracked during witness generation.
fn compute_multiplicities_from_main_trace(
    main: &MainWitness,
) -> LogUpMultiplicities {
    let mut multiplicities = LogUpMultiplicities::new();
    let config = &main.config;
    let chunk_bits = config.normalized_bits / 2;  // 10-bit for 30+30 architecture
    let chunk_mask = (1u32 << chunk_bits) - 1;

    for trace_row in &main.trace {
        // Decode instruction with 7-bit opcode format
        let inst = trace_row.instruction;
        let opcode = extract_opcode(inst);
        let rd = ((inst >> RD_SHIFT) & REGISTER_MASK) as usize;
        let rs1 = ((inst >> RS1_SHIFT) & REGISTER_MASK) as usize;
        let rs2 = ((inst >> RS2_SHIFT) & REGISTER_MASK) as usize;

        // Check if this is a bitwise operation (AND, OR, XOR)
        let is_and = opcode == Opcode::And.to_u8() as u32;
        let is_or = opcode == Opcode::Or.to_u8() as u32;
        let is_xor = opcode == Opcode::Xor.to_u8() as u32;

        if is_and || is_or || is_xor {
            // Only process limb 0 to match constraint behavior
            for limb_idx in 0..1 {
                let rs1_limb = trace_row.registers.get(rs1)
                    .and_then(|r| r.get(limb_idx))
                    .copied()
                    .unwrap_or(0);
                let rs2_limb = trace_row.registers.get(rs2)
                    .and_then(|r| r.get(limb_idx))
                    .copied()
                    .unwrap_or(0);
                let rd_limb = trace_row.registers.get(rd)
                    .and_then(|r| r.get(limb_idx))
                    .copied()
                    .unwrap_or(0);

                // Split into chunks
                let rs1_chunk0 = rs1_limb & chunk_mask;
                let rs1_chunk1 = rs1_limb >> chunk_bits;
                let rs2_chunk0 = rs2_limb & chunk_mask;
                let rs2_chunk1 = rs2_limb >> chunk_bits;
                let rd_chunk0 = rd_limb & chunk_mask;
                let rd_chunk1 = rd_limb >> chunk_bits;

                // Record lookups for both chunks
                if is_and {
                    multiplicities.record_and(rs1_chunk0, rs2_chunk0, rd_chunk0, chunk_bits as u32);
                    multiplicities.record_and(rs1_chunk1, rs2_chunk1, rd_chunk1, chunk_bits as u32);
                } else if is_or {
                    multiplicities.record_or(rs1_chunk0, rs2_chunk0, rd_chunk0, chunk_bits as u32);
                    multiplicities.record_or(rs1_chunk1, rs2_chunk1, rd_chunk1, chunk_bits as u32);
                } else if is_xor {
                    multiplicities.record_xor(rs1_chunk0, rs2_chunk0, rd_chunk0, chunk_bits as u32);
                    multiplicities.record_xor(rs1_chunk1, rs2_chunk1, rd_chunk1, chunk_bits as u32);
                }
            }
        }

        // TODO(30+30): Range check multiplicity tracking temporarily disabled
        // In the deferred model, register limbs can contain accumulated values (up to 30 bits),
        // which cannot be decomposed into 10-bit chunks. Range check multiplicities should only
        // be recorded AFTER normalization at observation points.
        //
        // DISABLED: Normalization multiplicity tracking (must match disabled query accumulation)
        // Range check: Track normalized limbs and carries at normalization points
        // Using dense array (4 KB) that fits in L1 cache!
        let current_cycle = trace_row.cycle;
        let norm_events: Vec<_> = main.normalization_events.iter()
            .filter(|event| event.cycle == current_cycle)
            .collect();
        for norm_event in norm_events {
            // Range check normalized limb chunks (2 chunks per limb)
            for &normalized_limb in &norm_event.normalized {
                let chunk_0 = normalized_limb & chunk_mask;
                let chunk_1 = normalized_limb >> chunk_bits;
                multiplicities.record_range_check(chunk_0);
                multiplicities.record_range_check(chunk_1);
            }
            // CRITICAL: Range check carries (prevents forged normalized values)
            for &carry in &norm_event.carries {
                multiplicities.record_range_check(carry);
            }
        }
    }

    multiplicities
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::FieldAlgebra;
    use p3_mersenne_31::Mersenne31;
    use crate::witness::trace::{MainTraceRow, ValueBound, PublicIO};
    use crate::witness::multiplicity::LogUpMultiplicities;

    type F = Mersenne31;

    #[test]
    fn test_aux_witness_creation() {
        let aux = AuxWitness::<F>::new(8);
        assert_eq!(aux.mem_perm_exec.len(), 8);
        assert_eq!(aux.mem_perm_sorted.len(), 8);
        assert_eq!(aux.logup_and.len(), 8);
        assert_eq!(aux.logup_or.len(), 8);
        assert_eq!(aux.logup_xor.len(), 8);
        assert_eq!(aux.logup_range.len(), 8);
        assert_eq!(aux.logup_and_table.len(), 8);
        assert_eq!(aux.logup_or_table.len(), 8);
        assert_eq!(aux.logup_xor_table.len(), 8);
        assert_eq!(aux.logup_range_table.len(), 8);

        // Check initial values
        assert_eq!(aux.mem_perm_exec[0], F::ONE);
        assert_eq!(aux.logup_and[0], F::ZERO);
    }

    #[test]
    fn test_memory_operation() {
        let op = MemoryOperation::new(0x1000, 42, 0x5678, true, 5);
        assert_eq!(op.addr, 0x1000);
        assert_eq!(op.timestamp, 42);
        assert_eq!(op.value, 0x5678);
        assert!(op.is_write);
        assert_eq!(op.row_index, 5);
    }

    #[test]
    fn test_compute_auxiliary_simple() {
        let config = ProgramConfig::default();
        let program_hash = [0u8; 32];

        // Create simple main witness with one trace row
        let mut builder = MainWitness::builder(config, program_hash);
        builder.add_trace_row(MainTraceRow::new(
            0,
            0,
            0,
            vec![vec![0; 2]; 16],
            vec![ValueBound::zero(); 16],
        ));
        let main = builder.build();

        // Compute auxiliary with challenge
        let challenge = F::from_canonical_u32(200_000_000);
        let aux = compute_auxiliary(&main, challenge, 4);

        assert_eq!(aux.logup_range.len(), 4);
        assert_eq!(aux.mem_perm_exec.len(), 4);
    }
}
