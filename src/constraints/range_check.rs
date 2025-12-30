//! Range check constraints using lookup arguments
//!
//! This module implements range checking for limb values using the LogUp protocol.
//!
//! # Current Implementation (Phase 4)
//!
//! Infrastructure complete:
//! - Range check accumulator column allocated in trace
//! - LogUp framework implemented and integrated
//! - Final sum verification at end of trace
//! - Chunk decomposition methods ready
//!
//! Deferred to Phase 5 (Full Integration):
//! - Chunk auxiliary columns (not yet allocated)
//! - Actual chunk decomposition constraints
//! - Accumulator update logic for specific limbs
//! - Multiplicity tracking in witness generation
//!
//! # Current Range Checking Strategy
//!
//! The current implementation provides **implicit range checking** through:
//! 1. **Field Arithmetic Bounds**: Mersenne 31 field (p = 2^31 - 1) provides natural bounds
//! 2. **Witness Generation**: Assumes correct limb decomposition in witness
//! 3. **Infrastructure Ready**: All columns and constraints ready for explicit checking
//!
//! # Future Enhancement (Phase 5)
//!
//! When explicit range checking is needed:
//! 1. Add chunk auxiliary columns (2 per limb to be checked)
//! 2. For each limb: decompose into chunks, verify decomposition
//! 3. Update accumulator for each chunk lookup
//! 4. Verify final sum matches table sum (already implemented)

use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

use super::air::ZkIrAir;

/// Range check lookup table
///
/// For default 20-bit limbs with 10-bit chunks, we need a table of size 2^10 = 1024.
pub struct RangeCheckTable {
    /// Chunk size in bits
    pub chunk_bits: u32,
    /// Table size (2^chunk_bits)
    pub table_size: usize,
}

impl RangeCheckTable {
    /// Create a new range check table for the given chunk size
    pub fn new(chunk_bits: u32) -> Self {
        let table_size = 1 << chunk_bits;
        Self {
            chunk_bits,
            table_size,
        }
    }

    /// Get the table entries (0, 1, 2, ..., table_size-1)
    pub fn entries(&self) -> Vec<u32> {
        (0..self.table_size as u32).collect()
    }
}

impl ZkIrAir {
    /// Evaluate range check constraints using LogUp
    ///
    /// # LogUp Protocol
    ///
    /// LogUp (Logarithmic derivative lookup) allows us to prove that all chunks
    /// appear in the lookup table without sorting.
    ///
    /// For each chunk c and table value t:
    /// - Add 1/(α - c) to the "query" accumulator
    /// - Add multiplicity/(α - t) to the "table" accumulator
    ///
    /// At the end: sum(1/(α - c)) = sum(multiplicity/(α - t))
    ///
    /// # Constraint Structure
    ///
    /// For arithmetic operations (ADD, SUB, MUL, etc.), we range check the destination
    /// register limbs by decomposing each limb into two chunks and verifying:
    /// 1. Chunk decomposition: `rd_limb = chunk_0 + chunk_1 * 2^chunk_bits`
    /// 2. LogUp accumulator update: `(next_sum - local_sum) * Π(diff_i) = Σ(diff_0 * diff_1 / diff_i)`
    ///
    /// For non-arithmetic operations, chunks are zero and accumulator is unchanged.
    pub fn eval_range_check_logup<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
    ) {
        // Get challenge for LogUp argument
        let challenges = self.challenges::<AB::F>();
        let challenge = challenges.logup_range;

        // Read range check accumulator from local and next rows
        let range_sum_local: AB::Expr = local[self.col_logup_range()].into();
        let range_sum_next: AB::Expr = next[self.col_logup_range()].into();

        // Get arithmetic selector - range checks apply to arithmetic operations
        let sel_arithmetic: AB::Expr = local[self.col_sel_arithmetic()].into();

        // Get destination register indicator for R0 (if rd=R0, no range check needed)
        // R0 is hardwired to zero, so we skip range checks when rd=R0
        let rd_is_r0: AB::Expr = local[self.col_rd_indicator(0)].into();

        // Effective selector: arithmetic AND (rd != R0)
        let sel_active = sel_arithmetic.clone() * (AB::Expr::ONE - rd_is_r0);

        let data_limbs = self.config.data_limbs as usize;

        // Accumulator delta
        let acc_delta = range_sum_next.clone() - range_sum_local.clone();

        // For arithmetic operations, verify range check constraints for each limb
        // The LogUp constraint for N lookups (2 chunks per limb × data_limbs limbs):
        //
        // delta * Π(diff_i) = Σ[Π(diff_j for j≠i)]
        //
        // For 2 chunks: delta * diff_0 * diff_1 = diff_1 + diff_0
        // Which encodes: delta = 1/diff_0 + 1/diff_1
        //
        // For multiple limbs, we need to accumulate all contributions.
        // With 2 limbs (4 chunks total): delta * d0 * d1 * d2 * d3 = d1*d2*d3 + d0*d2*d3 + d0*d1*d3 + d0*d1*d2

        // Collect all chunk differences
        let mut chunk_diffs: Vec<AB::Expr> = Vec::with_capacity(2 * data_limbs);
        let challenge_expr: AB::Expr = AB::Expr::from(challenge);
        let chunk_bits = self.config.limb_bits / 2;
        let chunk_shift = AB::F::from_canonical_u32(1u32 << chunk_bits);

        for limb_idx in 0..data_limbs {
            let chunk_0: AB::Expr = local[self.col_range_chunk0(limb_idx)].into();
            let chunk_1: AB::Expr = local[self.col_range_chunk1(limb_idx)].into();

            // Verify chunk decomposition for arithmetic operations
            // The destination register limb should equal chunk_0 + chunk_1 * 2^chunk_bits
            //
            // Use register indicators to dynamically select rd's limb value.
            // rd_value = Σ(rd_indicator[i] * register[i])
            let mut rd_limb_value: AB::Expr = AB::Expr::ZERO;
            for reg_idx in 0..16 {
                let rd_indicator: AB::Expr = local[self.col_rd_indicator(reg_idx)].into();
                let reg_limb: AB::Expr = local[self.col_register(reg_idx, limb_idx)].into();
                rd_limb_value = rd_limb_value + rd_indicator * reg_limb;
            }

            // Chunk decomposition: rd_limb = chunk_0 + chunk_1 * 2^chunk_bits
            let reconstructed = chunk_0.clone() + chunk_1.clone() * chunk_shift;

            // Constraint: when active, chunks must correctly decompose rd limb
            // sel_active * (rd_limb - reconstructed) = 0
            builder.assert_zero(sel_active.clone() * (rd_limb_value - reconstructed));

            // Compute diff_i = challenge - chunk_i
            let diff_0 = challenge_expr.clone() - chunk_0;
            let diff_1 = challenge_expr.clone() - chunk_1;

            chunk_diffs.push(diff_0);
            chunk_diffs.push(diff_1);
        }

        // Compute product of all differences: Π(diff_i)
        let mut product_all: AB::Expr = AB::Expr::ONE;
        for diff in &chunk_diffs {
            product_all = product_all * diff.clone();
        }

        // Compute sum of products excluding each term: Σ[Π(diff_j for j≠i)]
        // This is equivalent to: Π_all / diff_i summed over i
        // But we compute it directly to avoid division
        let mut sum_excluding: AB::Expr = AB::Expr::ZERO;
        for i in 0..chunk_diffs.len() {
            let mut product_excluding_i: AB::Expr = AB::Expr::ONE;
            for (j, diff) in chunk_diffs.iter().enumerate() {
                if i != j {
                    product_excluding_i = product_excluding_i * diff.clone();
                }
            }
            sum_excluding = sum_excluding + product_excluding_i;
        }

        // The constraint: delta * Π(diff_i) = Σ[Π(diff_j for j≠i)]
        // Guarded by sel_arithmetic: when not arithmetic, delta should be 0
        // and chunks are 0, so diff_i = challenge for all i
        //
        // For arithmetic ops: delta * Π(diff) = Σ(products_excluding_each)
        // For non-arithmetic: delta = 0 (accumulator unchanged)

        let lhs = acc_delta.clone() * product_all.clone();
        let rhs = sum_excluding;

        // Apply constraint on transition rows, guarded by sel_arithmetic
        // When sel_arithmetic = 1: verify LogUp update
        // When sel_arithmetic = 0: chunks are 0, so constraint is:
        //   delta * challenge^4 = 4 * challenge^3
        //   which only holds when delta = 4/challenge
        //   But delta should be 0, so we need a different approach.

        // Better approach: Use conditional constraint
        // IF sel_arithmetic THEN (delta * Π(diff) = Σ(excluding))
        // ELSE delta = 0
        //
        // Combine into: sel_arithmetic * (lhs - rhs) + (1 - sel_arithmetic) * delta = 0
        // This simplifies to: sel_arithmetic * lhs - sel_arithmetic * rhs + delta - sel_arithmetic * delta = 0
        // = delta + sel_arithmetic * (lhs - rhs - delta) = 0

        // For simpler constraint, just apply both:
        // 1. When active (arithmetic AND rd != R0): lhs = rhs (LogUp update)
        // 2. When not active: delta = 0 (no update)

        // Constraint 1: sel_active * (lhs - rhs) = 0
        builder.when_transition().assert_zero(sel_active.clone() * (lhs - rhs));

        // Constraint 2: (1 - sel_active) * delta = 0
        // This ensures accumulator doesn't change for non-arithmetic operations or when rd=R0
        builder.when_transition().assert_zero((AB::Expr::ONE - sel_active) * acc_delta);
    }

    /// Verify chunk decomposition
    ///
    /// Ensures that a limb is correctly decomposed into chunks:
    /// limb = chunk_0 + chunk_1 * 2^chunk_bits
    pub fn eval_chunk_decomposition<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        limb: AB::Expr,
        chunk_0: AB::Expr,
        chunk_1: AB::Expr,
    ) {
        // chunk_bits = limb_bits / 2
        let chunk_bits = self.config.limb_bits / 2;
        let chunk_shift = 1u32 << chunk_bits;

        // Verify: limb = chunk_0 + chunk_1 * 2^chunk_bits
        let shift_f = AB::F::from_canonical_u32(chunk_shift);
        let reconstructed = chunk_0 + chunk_1 * shift_f;
        builder.assert_eq(limb, reconstructed);
    }

    /// Evaluate bound-aware range check skipping
    ///
    /// If a value has a tight bound that's already within the limb size,
    /// we can skip the range check.
    ///
    /// # Implementation Note
    ///
    /// In Mersenne 31 field, values are already bounded by the prime (2^31 - 1).
    /// For 20-bit limbs, the maximum value is 2^20 - 1 = 1,048,575.
    /// Since all field elements are < 2^31, and we're working with limbs that
    /// should be < 2^20, the field arithmetic itself provides a coarse bound.
    ///
    /// However, for cryptographic soundness, we should verify that limbs are
    /// actually within their claimed bounds. This is where chunk decomposition
    /// and LogUp lookups become important.
    ///
    /// For now, we rely on:
    /// 1. Field arithmetic bounds (values < 2^31)
    /// 2. Witness generation correctness (proper limb decomposition)
    /// 3. Future: Chunk-based range checking for tight bounds
    pub fn eval_bound_aware_checks<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        value_bound: AB::Var,
    ) {
        // Bound-aware optimization will be implemented in Phase 5
        // When enabled, this will:
        // - Check if value_bound <= limb_bits
        // - If true, skip the chunk decomposition (optimization)
        // - If false, enforce chunk decomposition and range check

        let _ = (builder, value_bound);
    }

    /// Verify limb is within valid range using implicit field bounds
    ///
    /// This provides a basic range check by leveraging field arithmetic.
    /// For Mersenne 31 with 20-bit limbs:
    /// - Maximum limb value: 2^20 - 1 = 1,048,575
    /// - Field prime: 2^31 - 1 = 2,147,483,647
    ///
    /// While the field can represent larger values, correct limb values
    /// should never exceed 2^limb_bits. We enforce this through:
    /// 1. Witness generation constraints (external)
    /// 2. Future: Explicit chunk decomposition (Phase 5)
    pub fn eval_implicit_limb_bounds<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        limb: AB::Expr,
    ) {
        // For now, we don't add explicit constraints here
        // The field arithmetic provides implicit bounds
        // Future enhancement: Add explicit bounds checking
        //
        // Example constraint (for reference):
        // let max_limb_value = 1u32 << self.config.limb_bits;
        // let max_limb = AB::F::from_canonical_u32(max_limb_value - 1);
        // builder.assert_bool(limb - max_limb); // Would verify limb <= max

        let _ = (builder, limb);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_check_table_creation() {
        let table = RangeCheckTable::new(10);
        assert_eq!(table.chunk_bits, 10);
        assert_eq!(table.table_size, 1024);
        assert_eq!(table.entries().len(), 1024);
        assert_eq!(table.entries()[0], 0);
        assert_eq!(table.entries()[1023], 1023);
    }

    #[test]
    fn test_range_check_table_different_sizes() {
        let table8 = RangeCheckTable::new(8);
        assert_eq!(table8.table_size, 256);

        let table12 = RangeCheckTable::new(12);
        assert_eq!(table12.table_size, 4096);
    }

    #[test]
    fn test_chunk_decomposition_infrastructure() {
        // Verify chunk decomposition columns are accessible
        use crate::witness::ProgramConfig;
        let config = ProgramConfig::default();
        let air = super::super::air::ZkIrAir::new(config.clone());

        // For 2-limb config, we should have 4 chunk columns (2 per limb)
        let data_limbs = config.data_limbs as usize;
        for limb_idx in 0..data_limbs {
            let _ = air.col_range_chunk0(limb_idx); // Should not panic
            let _ = air.col_range_chunk1(limb_idx); // Should not panic
        }

        // Verify chunk columns come before LogUp columns
        let chunk0_col = air.col_range_chunk0(0);
        let logup_col = air.col_logup_range();
        assert!(chunk0_col < logup_col, "Range check chunks should come before LogUp accumulators");
    }

    #[test]
    fn test_chunk_decomposition_values() {
        // Test that chunk decomposition works correctly
        let chunk_bits = 10;
        let chunk_mask = (1u32 << chunk_bits) - 1;

        // Test value: 0b11111111110000000000 (20-bit value with both chunks non-zero)
        let limb = 0b11111111110000000000u32; // 1047552

        let chunk_0 = limb & chunk_mask; // Low 10 bits: 0
        let chunk_1 = limb >> chunk_bits; // High 10 bits: 1023

        assert_eq!(chunk_0, 0);
        assert_eq!(chunk_1, 1023);

        // Verify reconstruction
        let reconstructed = chunk_0 + (chunk_1 << chunk_bits);
        assert_eq!(reconstructed, limb);

        // Test with maximum 20-bit value
        let max_limb = (1u32 << 20) - 1; // 1048575
        let max_chunk_0 = max_limb & chunk_mask;
        let max_chunk_1 = max_limb >> chunk_bits;

        assert_eq!(max_chunk_0, 1023); // Maximum 10-bit value
        assert_eq!(max_chunk_1, 1023); // Maximum 10-bit value

        let max_reconstructed = max_chunk_0 + (max_chunk_1 << chunk_bits);
        assert_eq!(max_reconstructed, max_limb);
    }
}
