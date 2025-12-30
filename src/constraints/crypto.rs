//! Cryptographic syscall constraints
//!
//! This module defines constraints for cryptographic operations (SHA-256, Poseidon2, etc.)

use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

use super::air::ZkIrAir;
use crate::witness::CryptoType;

impl ZkIrAir {
    /// Evaluate SHA-256 syscall constraints
    ///
    /// SHA-256 operates on 32-bit words with 64 rounds of compression.
    ///
    /// # Adaptive Internal Representation
    ///
    /// SHA-256 uses 44-bit internal representation (32-bit algorithm + 12-bit headroom)
    /// to allow deferred range checking for all 320 additions across 64 rounds.
    ///
    /// # Constraints
    ///
    /// 1. **Message schedule**: Verify W[i] computation for rounds 16-63
    /// 2. **Compression function**: Verify state updates for all 64 rounds
    /// 3. **Output bounds**: SHA-256 outputs are bounded to 32 bits (tight)
    pub fn eval_sha256<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        // TODO: Implement SHA-256 constraints
        //
        // Steps:
        // 1. Verify input padding and message schedule
        // 2. For each of 64 rounds:
        //    - Verify W[i] computation
        //    - Verify compression function (Ch, Maj, Σ0, Σ1)
        //    - Verify state updates (a, b, c, d, e, f, g, h)
        // 3. Verify final addition and output bounds
        //
        // All operations use 44-bit internal representation with deferred range checks.
        // Single range check at output to verify 32-bit bound.

        let _ = (builder, local);
    }

    /// Evaluate Poseidon2 syscall constraints
    ///
    /// Poseidon2 operates on field elements in Mersenne-31.
    ///
    /// # Adaptive Internal Representation
    ///
    /// Poseidon2 uses 40-bit internal representation (31-bit algorithm + 9-bit headroom)
    /// for ~200 additions across the permutation.
    pub fn eval_poseidon2<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        // TODO: Implement Poseidon2 constraints
        //
        // Poseidon2 permutation:
        // 1. Add round constants
        // 2. Apply S-box (x^5 in our case)
        // 3. Apply MDS matrix
        //
        // Uses 40-bit internal representation with deferred range checks.

        let _ = (builder, local);
    }

    /// Evaluate Keccak-256 syscall constraints
    ///
    /// Keccak-256 operates on 64-bit lanes with 24 rounds.
    ///
    /// # Adaptive Internal Representation
    ///
    /// Keccak-256 requires 80-bit internal representation (64-bit algorithm + 16-bit headroom)
    /// for XOR-heavy operations.
    ///
    /// Note: In 40-bit programs, Keccak outputs need truncation and range checks.
    pub fn eval_keccak256<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        // TODO: Implement Keccak-256 constraints
        //
        // Keccak-f[1600] permutation:
        // 1. θ (theta): XOR columns
        // 2. ρ (rho): Rotate lanes
        // 3. π (pi): Permute lanes
        // 4. χ (chi): Non-linear mixing
        // 5. ι (iota): Add round constant

        let _ = (builder, local);
    }

    /// Evaluate crypto output bound constraints
    ///
    /// Verifies that crypto syscall outputs have the correct bounds based on
    /// the algorithm and program configuration.
    ///
    /// # Range Check Requirements
    ///
    /// - If algorithm_bits <= program_bits: No range check needed (free!)
    /// - If algorithm_bits > program_bits: Range check required (truncation)
    ///
    /// Examples (40-bit program):
    /// - SHA-256 (32-bit): No range check (32 <= 40)
    /// - Keccak-256 (64-bit): Range check required (64 > 40)
    pub fn eval_crypto_output_bounds<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        crypto_type: CryptoType,
        output: AB::Var,
    ) {
        let program_bits = self.config.data_bits();
        let algorithm_bits = crypto_type.algorithm_bits();

        // If algorithm_bits > program_bits, we need a range check
        // Otherwise, the output is guaranteed to fit (no check needed)
        if algorithm_bits > program_bits {
            // TODO: Add range check constraint for truncated output
        }

        let _ = (builder, output);
    }

    /// Evaluate post-crypto headroom
    ///
    /// After a crypto syscall, the output has known bounds which may provide
    /// headroom for subsequent deferred operations.
    ///
    /// Examples (40-bit program):
    /// - SHA-256 output: 32 bits → 8 bits headroom (256 deferred ops)
    /// - Poseidon2 output: 31 bits → 9 bits headroom (512 deferred ops)
    pub fn eval_post_crypto_headroom<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        crypto_type: CryptoType,
        output_bound: AB::Var,
    ) {
        let program_bits = self.config.data_bits();
        let algorithm_bits = crypto_type.algorithm_bits();

        // Post-crypto headroom = program_bits - algorithm_bits
        let headroom = program_bits.saturating_sub(algorithm_bits);

        // Verify the output bound is set correctly
        let expected_bound = AB::F::from_canonical_u32(algorithm_bits);
        builder.assert_eq(output_bound, expected_bound);

        let _ = headroom;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::ProgramConfig;

    #[test]
    fn test_crypto_bounds() {
        // SHA-256 in 40-bit program
        assert_eq!(CryptoType::Sha256.algorithm_bits(), 32);
        assert!(!CryptoType::Sha256.needs_range_check_after_output(40));
        assert_eq!(CryptoType::Sha256.post_crypto_headroom(40), 8);

        // Keccak-256 in 40-bit program
        assert_eq!(CryptoType::Keccak256.algorithm_bits(), 64);
        assert!(CryptoType::Keccak256.needs_range_check_after_output(40));
        assert_eq!(CryptoType::Keccak256.post_crypto_headroom(40), 0);
    }

    #[test]
    fn test_crypto_internal_bits() {
        let config = ProgramConfig::DEFAULT; // 40-bit
        let program_bits = config.data_bits();

        // SHA-256: Uses max(44, 40) = 44 bits internally
        assert_eq!(CryptoType::Sha256.internal_bits(program_bits), 44);

        // Poseidon2: Uses max(40, 40) = 40 bits internally
        assert_eq!(CryptoType::Poseidon2.internal_bits(program_bits), 40);

        // Keccak-256: Uses max(80, 40) = 80 bits internally
        assert_eq!(CryptoType::Keccak256.internal_bits(program_bits), 80);
    }
}
