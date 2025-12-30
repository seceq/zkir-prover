//! Challenge management for RAP (Randomized AIR with Preprocessing)
//!
//! This module centralizes challenge value management for constraint evaluation.
//! Currently uses placeholder values, but designed to be easily updated when
//! Plonky3 provides multi-phase commitment APIs.

use p3_field::FieldAlgebra;

/// RAP Challenges used in constraint evaluation
///
/// In proper RAP, these challenges are derived from the Fiat-Shamir transcript
/// AFTER committing the main trace. Currently, they are placeholders that are
/// consistent between witness generation and constraint evaluation.
///
/// ## Current State (Placeholder)
///
/// - `memory_permutation`: 200M (used for memory consistency via permutation argument)
/// - `logup_bitwise`: 100M (used for bitwise operation lookups)
/// - `logup_range`: 100M (used for range check lookups)
///
/// ## Future State (True RAP)
///
/// These will be derived from the transcript via:
/// ```ignore
/// let challenge = builder.challenge(); // When Plonky3 supports this
/// ```
///
/// Or passed explicitly after main trace commitment:
/// ```ignore
/// // In prover:
/// let main_commitment = commit(&main_trace);
/// transcript.observe(main_commitment);
/// let challenge = transcript.sample();
/// let challenges = RapChallenges { memory_permutation: challenge, ... };
/// // Pass to Air
/// ```
#[derive(Clone, Copy, Debug)]
pub struct RapChallenges<F> {
    /// Challenge for memory permutation argument
    ///
    /// Used in Horner encoding: `addr + α(timestamp + α(value + α*is_write))`
    pub memory_permutation: F,

    /// Challenge for bitwise LogUp lookups (AND, OR, XOR)
    ///
    /// Used for lookup encoding: `rs1_chunk + α(rs2_chunk + α*rd_chunk)`
    pub logup_bitwise: F,

    /// Challenge for range check LogUp lookups
    ///
    /// Used for chunk lookups: `1/(α - chunk)`
    pub logup_range: F,
}

impl<F: FieldAlgebra> RapChallenges<F> {
    /// Create challenges with placeholder values
    ///
    /// **Security Warning:** These are placeholder values for development.
    /// In production, challenges MUST be derived from the Fiat-Shamir transcript
    /// after committing the main trace.
    ///
    /// Current placeholders:
    /// - Memory permutation: 200,000,000
    /// - LogUp bitwise: 100,000,000
    /// - LogUp range: 100,000,000
    ///
    /// These values are chosen to be:
    /// 1. Large enough to avoid accidental collisions
    /// 2. Within the field size (Mersenne31 = 2^31 - 1)
    /// 3. Easy to identify in debugging
    pub fn placeholder() -> Self {
        Self {
            memory_permutation: F::from_canonical_u32(200_000_000),
            logup_bitwise: F::from_canonical_u32(100_000_000),
            logup_range: F::from_canonical_u32(100_000_000),
        }
    }

    /// Create challenges from explicit values
    ///
    /// This will be used in the future when Plonky3 provides the actual
    /// Fiat-Shamir challenges from the transcript.
    ///
    /// # Arguments
    ///
    /// * `memory_permutation` - Challenge α for memory permutation
    /// * `logup_bitwise` - Challenge for bitwise lookups
    /// * `logup_range` - Challenge for range checks
    pub fn from_values(memory_permutation: F, logup_bitwise: F, logup_range: F) -> Self {
        Self {
            memory_permutation,
            logup_bitwise,
            logup_range,
        }
    }

    /// Create challenges using a single value for all
    ///
    /// This is a common pattern where the same challenge is reused.
    /// In production RAP, you might derive different challenges for
    /// different purposes, but using the same base challenge is also valid.
    pub fn from_single(challenge: F) -> Self
    where
        F: Clone,
    {
        Self {
            memory_permutation: challenge.clone(),
            logup_bitwise: challenge.clone(),
            logup_range: challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_mersenne_31::Mersenne31;

    type F = Mersenne31;

    #[test]
    fn test_placeholder_challenges() {
        let challenges = RapChallenges::<F>::placeholder();

        assert_eq!(challenges.memory_permutation, F::from_canonical_u32(200_000_000));
        assert_eq!(challenges.logup_bitwise, F::from_canonical_u32(100_000_000));
        assert_eq!(challenges.logup_range, F::from_canonical_u32(100_000_000));
    }

    #[test]
    fn test_from_values() {
        let challenges = RapChallenges::from_values(
            F::from_canonical_u32(111),
            F::from_canonical_u32(222),
            F::from_canonical_u32(333),
        );

        assert_eq!(challenges.memory_permutation, F::from_canonical_u32(111));
        assert_eq!(challenges.logup_bitwise, F::from_canonical_u32(222));
        assert_eq!(challenges.logup_range, F::from_canonical_u32(333));
    }

    #[test]
    fn test_from_single() {
        let challenge = F::from_canonical_u32(42);
        let challenges = RapChallenges::from_single(challenge);

        assert_eq!(challenges.memory_permutation, challenge);
        assert_eq!(challenges.logup_bitwise, challenge);
        assert_eq!(challenges.logup_range, challenge);
    }
}
