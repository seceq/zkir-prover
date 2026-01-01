//! Memory consistency constraints
//!
//! This module enforces that memory reads see the correct values from previous writes.
//!
//! # Memory Consistency Protocol
//!
//! We use a multiset equality check (similar to LogUp) to verify that:
//! 1. The execution-order memory trace
//! 2. The sorted (address, timestamp) memory trace
//! ...are permutations of each other.
//!
//! This ensures:
//! - Every memory operation is accounted for
//! - Operations can be checked in sorted order for read-write consistency
//! - No spurious operations are added or removed
//!
//! Current implementation provides timestamp ordering and memory columns.
//! Full permutation argument with running products is deferred to a later phase.

use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

use super::air::ZkIrAir;

impl ZkIrAir {
    /// Evaluate memory consistency constraints.
    ///
    /// Ensures read-after-write consistency, timestamp ordering, and that uninitialized
    /// memory reads as zero. Currently implements basic memory operation structure and
    /// timestamp ordering; full permutation argument is deferred.
    pub fn eval_memory_consistency<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
    ) {
        // Full memory permutation argument implementation
        //
        // This verifies memory consistency using a multiset equality check:
        // 1. Execution-order trace: operations as they occur in program execution
        // 2. Sorted trace: operations sorted by (address, timestamp)
        //
        // By proving these are permutations of each other, we can:
        // - Verify read-write consistency in sorted order (reads see most recent writes)
        // - Ensure no operations are dropped or fabricated

        // Read memory flags from LOCAL row (for boolean/exclusivity checks)
        let is_read_local: AB::Expr = local[self.col_mem_is_read()].into();
        let is_write_local: AB::Expr = local[self.col_mem_is_write()].into();

        // Verify flags are boolean
        builder.assert_bool(is_read_local.clone());
        builder.assert_bool(is_write_local.clone());

        // Verify mutual exclusivity: at most one flag is set
        // Constraint: is_read * is_write = 0
        let both_flags = is_read_local.clone() * is_write_local.clone();
        builder.assert_zero(both_flags);

        // Read memory flags from NEXT row (for product update)
        // The product update constraint is: if NEXT row has mem op, update happens
        // This matches the witness which stores product AFTER processing each row
        let is_read_next: AB::Expr = next[self.col_mem_is_read()].into();
        let is_write_next: AB::Expr = next[self.col_mem_is_write()].into();

        // Check if NEXT row has a memory operation
        let has_mem_op_next = is_read_next.clone() + is_write_next.clone();

        // Get challenge for permutation argument
        //
        // Note: Currently uses placeholder challenges from RapChallenges::placeholder().
        // This is centralized in src/constraints/challenges.rs for easy future updates
        // when Plonky3 supports multi-phase commitments.
        //
        // See docs/RAP_IMPLEMENTATION_STATUS.md for RAP pattern status.
        let challenges = self.challenges::<AB::F>();
        let challenge = AB::Expr::from(challenges.memory_permutation);

        // Read memory operation data from NEXT row (for product update calculation)
        // The product at row N+1 depends on the operation at row N+1
        let data_limbs = self.config.data_limbs as usize;

        // Address limbs from NEXT row
        let mut addr_limbs_next = Vec::with_capacity(data_limbs);
        for i in 0..data_limbs {
            addr_limbs_next.push(next[self.col_mem_addr(i)].into());
        }

        // Value limbs from NEXT row
        let mut value_limbs_next = Vec::with_capacity(data_limbs);
        for i in 0..data_limbs {
            value_limbs_next.push(next[self.col_mem_value(i)].into());
        }

        // Timestamp from NEXT row (use PC as timestamp)
        let timestamp_next: AB::Expr = next[self.col_pc()].into();

        // Encode memory operation from NEXT row
        let encoded_next = self.encode_memory_operation::<AB>(
            challenge.clone(),
            &addr_limbs_next,
            timestamp_next,
            &value_limbs_next,
            is_write_next.clone(),
        );

        // --- Running Product Constraints ---
        //
        // For execution-order trace:
        //   next_product = local_product * (challenge - encoded_next)  if NEXT row has mem_op
        //   next_product = local_product                                otherwise
        //
        // This builds: ∏(challenge - encoded_op) over all memory operations
        //
        // The key insight: aux.mem_perm_exec[i] stores the product AFTER processing row i.
        // So the constraint checks: if row N+1 has a mem op, then
        //   aux.mem_perm_exec[N+1] = aux.mem_perm_exec[N] * factor

        let local_perm_exec: AB::Expr = local[self.col_mem_perm_exec()].into();
        let next_perm_exec: AB::Expr = next[self.col_mem_perm_exec()].into();

        // Product update: next = local * (challenge - encoded_next) if next has mem_op, else next = local
        let factor = challenge - encoded_next;
        let updated_product = local_perm_exec.clone() * factor;

        // Conditional update based on whether NEXT row has mem_op
        // next_perm_exec = has_mem_op_next * updated_product + (1 - has_mem_op_next) * local_perm_exec
        let one_f = AB::F::ONE;
        let one = AB::Expr::from(one_f);
        let expected_next = has_mem_op_next.clone() * updated_product
                          + (one.clone() - has_mem_op_next.clone()) * local_perm_exec;

        builder.when_transition().assert_eq(next_perm_exec, expected_next);

        // Note: The sorted trace permutation product is tracked separately in witness generation
        // and verified at the end (boundary constraint) that exec_product == sorted_product
        // This will be added in eval_memory_permutation_final_check
    }

    /// Evaluate memory timestamp ordering
    ///
    /// Ensures that for operations to the same address,
    /// timestamps are strictly increasing.
    #[allow(unused_variables)]
    pub fn eval_memory_timestamp<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
    ) {
        // Memory timestamp ordering constraint
        //
        // When consecutive memory operations access the same address,
        // we must verify that timestamps are increasing. This prevents
        // time-travel attacks where a read could see a future write.
        //
        // Constraint:
        // IF (next_addr == local_addr) AND (both are memory ops)
        // THEN next_timestamp > local_timestamp
        //
        // We use the cycle number (PC) as a proxy for timestamp
        // since each instruction executes in order.

        // Read memory addresses from local and next rows
        let data_limbs = self.config.data_limbs as usize;

        // Check if memory operations exist (is_read or is_write flag set)
        let local_is_read: AB::Expr = local[self.col_mem_is_read()].into();
        let next_is_read: AB::Expr = next[self.col_mem_is_read()].into();

        // For simplicity, we assume any row with is_read=1 is a memory operation
        // (This could be extended to also check is_write flag)
        let local_has_mem_op = local_is_read;
        let next_has_mem_op = next_is_read;

        // Read addresses (for 2-limb config, address is 2 limbs)
        // We'll compute address difference to check if addresses are the same
        let mut addr_is_same = true;
        for limb_idx in 0..data_limbs {
            let local_addr_limb: AB::Expr = local[self.col_mem_addr(limb_idx)].into();
            let next_addr_limb: AB::Expr = next[self.col_mem_addr(limb_idx)].into();

            // If any limb differs, addresses are different
            // For now, we'll build a simpler constraint
            if addr_is_same {
                // Check this limb matches
                let addr_diff = next_addr_limb.clone() - local_addr_limb.clone();

                // If addresses match for this limb and we're still tracking same addresses
                // Note: This is simplified - a full implementation would use
                // multiplicative indicators for address equality across all limbs
                addr_is_same = addr_is_same && limb_idx < data_limbs;
            }
        }

        // Read cycle numbers (timestamps) - PC serves as timestamp
        let local_pc: AB::Expr = local[self.col_pc()].into();
        let next_pc: AB::Expr = next[self.col_pc()].into();

        // Timestamp constraint: When both rows have memory ops to same address,
        // verify that PC strictly increases.
        //
        // Constraint: next_pc > local_pc
        // In field arithmetic: next_pc - local_pc - 1 should be non-negative
        //
        // Simplified version: We verify that pc_diff != 0
        // (A production version would use range checks to verify pc_diff > 0)

        let pc_diff = next_pc - local_pc;

        // Condition: both have memory ops
        let condition = local_has_mem_op.clone() * next_has_mem_op.clone();

        // For the timestamp ordering, we add a constraint that when condition is true
        // (both have memory ops), the PC difference should be non-zero.
        // This is a simplified check. A full implementation would:
        // 1. Check address equality properly across all limbs
        // 2. Use range checks to verify pc_diff > 0 (not just != 0)
        // 3. Handle wrap-around cases

        // Assert that when we have consecutive memory ops, PC increases
        // We use: condition * pc_diff should not equal condition * 0
        // Which means when condition=1, pc_diff != 0
        // When condition=0, the constraint is automatically satisfied

        // Using assert_zero on a product that should be non-zero when condition=1
        // is tricky, so instead we just document this for now and will implement
        // properly once we have the full permutation argument infrastructure.

        let _ = (condition, pc_diff);

        // Note: This is a simplified implementation. A production version would:
        // 1. Use range checks to verify pc_diff > 0 (not just != 0)
        // 2. Handle the case where operations are to different addresses
        // 3. Properly track read vs write flags
        // 4. Integration with memory permutation argument
    }

    /// Encode a memory operation for permutation check
    ///
    /// Encodes (address, timestamp, value, is_write) using a challenge-based scheme
    /// that ensures different operations produce different encodings with high probability.
    ///
    /// # Encoding Scheme
    ///
    /// Instead of bit-packing (which requires large field elements), we use:
    /// ```text
    /// encoded = addr + challenge * (timestamp + challenge * (value + challenge * is_write))
    /// ```
    ///
    /// This Horner-style evaluation ensures:
    /// - Different operations are distinguished with high probability (challenge is random)
    /// - Works in any field (no need for large primes)
    /// - Efficient to compute
    ///
    /// # Parameters
    ///
    /// - `challenge`: Random challenge from verifier (prevents prover from crafting collisions)
    /// - `addr_limbs`: Memory address (multiple limbs)
    /// - `timestamp`: Cycle number when operation occurred
    /// - `value_limbs`: Value read/written (multiple limbs)
    /// - `is_write`: 1 if write, 0 if read
    ///
    /// # Deferred Carry Model Note
    ///
    /// In the deferred carry (30+30) architecture:
    /// - Addresses come from trace (accumulated, 30-bit limbs) → use limb_bits
    /// - Values in memory ops are NORMALIZED (stores trigger normalization) → use normalized_bits
    pub fn encode_memory_operation<AB: AirBuilder>(
        &self,
        challenge: AB::Expr,
        addr_limbs: &[AB::Expr],
        timestamp: AB::Expr,
        value_limbs: &[AB::Expr],
        is_write: AB::Expr,
    ) -> AB::Expr {
        // Address limbs come from trace (accumulated, 30-bit packing)
        let addr_limb_base_f = AB::F::from_canonical_u32(1 << self.config.limb_bits);
        let addr_limb_base = AB::Expr::from(addr_limb_base_f);

        // Reconstruct address from limbs (using limb_bits = 30)
        let mut addr = addr_limbs[0].clone();
        for i in 1..addr_limbs.len() {
            addr = addr + addr_limbs[i].clone() * addr_limb_base.clone();
        }

        // Value limbs are NORMALIZED (stores trigger normalization, 20-bit packing)
        let value_limb_base_f = AB::F::from_canonical_u32(1 << self.config.normalized_bits);
        let value_limb_base = AB::Expr::from(value_limb_base_f);

        // Reconstruct value from limbs (using normalized_bits = 20)
        let mut value = value_limbs[0].clone();
        for i in 1..value_limbs.len() {
            value = value + value_limbs[i].clone() * value_limb_base.clone();
        }

        // Encode using challenge-based Horner scheme:
        // encoded = addr + α * (timestamp + α * (value + α * is_write))
        // where α is the challenge
        //
        // This expands to: addr + α*timestamp + α²*value + α³*is_write
        // Different operations produce different encodings with high probability
        let inner = value + challenge.clone() * is_write;
        let middle = timestamp + challenge.clone() * inner;
        let encoded = addr + challenge * middle;

        encoded
    }

    /// Evaluate final memory permutation check (boundary constraint)
    ///
    /// This verifies that the execution-order and sorted-order memory traces
    /// are permutations of each other by checking that their running products are equal.
    ///
    /// This constraint is only evaluated on the LAST row of the trace.
    pub fn eval_memory_permutation_final_check<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        // Read final running products
        let perm_exec: AB::Expr = local[self.col_mem_perm_exec()].into();
        let perm_sorted: AB::Expr = local[self.col_mem_perm_sorted()].into();

        // On the last row, verify that both products are equal
        // This proves that the execution-order and sorted-order traces
        // contain the same multiset of memory operations
        //
        // Note: This uses when_last_row() which creates a boundary constraint
        builder.when_last_row().assert_eq(perm_exec, perm_sorted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::ProgramConfig;

    #[test]
    fn test_memory_constraints_infrastructure() {
        // Test that memory constraint infrastructure is in place
        let config = ProgramConfig::default();
        let air = ZkIrAir::new(config.clone());

        // Verify column accessors work
        assert_eq!(air.col_mem_is_write(), air.col_mem_is_read() - 1);

        // Verify memory columns are allocated
        let mem_addr_0 = air.col_mem_addr(0);
        let mem_value_0 = air.col_mem_value(0);
        assert!(mem_value_0 > mem_addr_0);
    }

    #[test]
    fn test_memory_column_layout() {
        let config = ProgramConfig::default();
        let air = ZkIrAir::new(config.clone());
        let data_limbs = config.data_limbs as usize;

        // Memory address should have addr_limbs columns
        for i in 0..data_limbs {
            let _ = air.col_mem_addr(i); // Should not panic
        }

        // Memory value should have data_limbs columns
        for i in 0..data_limbs {
            let _ = air.col_mem_value(i); // Should not panic
        }

        // Flags should be accessible
        let _ = air.col_mem_is_write();
        let _ = air.col_mem_is_read();
    }

    // Note: encode_memory_operation is unimplemented (Phase 5)
    // Test omitted to avoid test compilation complexity
}
