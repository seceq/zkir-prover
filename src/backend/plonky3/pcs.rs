//! Polynomial Commitment Scheme (PCS) setup for Plonky3
//!
//! This module configures the CirclePcs-based polynomial commitment scheme
//! for Mersenne 31 field. We use CirclePcs because Mersenne 31 lacks a large
//! two-adic subgroup required for TwoAdicFriPcs.
//!
//! **Components:**
//! - Field: Mersenne31 (p = 2^31 - 1)
//! - Extension: BinomialExtensionField<Mersenne31, 3>
//! - Hash: Poseidon2 (both width-16 compression and width-24 sponge)
//! - PCS: CirclePcs with FRI
//! - Challenger: DuplexChallenger with Poseidon2

use std::marker::PhantomData;

use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriConfig;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::{Mersenne31, Poseidon2Mersenne31};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_challenger::DuplexChallenger;
use p3_uni_stark::StarkConfig;

use crate::backend::plonky3::config::StarkConfiguration;

/// Mersenne 31 field type
pub type Val = Mersenne31;

/// Extension field for FRI challenges (degree 3 for Mersenne 31)
pub type Challenge = BinomialExtensionField<Val, 3>;

/// Poseidon2 permutation with width 16 (for compression)
pub type Perm16 = Poseidon2Mersenne31<16>;

/// Poseidon2 permutation with width 24 (for sponge hashing)
pub type Perm24 = Poseidon2Mersenne31<24>;

/// Poseidon2 sponge hash function
pub type Poseidon2Sponge = PaddingFreeSponge<Perm24, 24, 16, 8>;

/// Poseidon2 compression function
pub type Poseidon2Compression = TruncatedPermutation<Perm16, 2, 8, 16>;

/// Merkle tree MMCS with Poseidon2
pub type Poseidon2MerkleMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    Poseidon2Sponge,
    Poseidon2Compression,
    8,
>;

/// Extension MMCS for challenge field
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Poseidon2MerkleMmcs>;

/// Circle PCS for Mersenne 31
pub type Pcs = CirclePcs<Val, Poseidon2MerkleMmcs, ChallengeMmcs>;

/// Duplex challenger with Poseidon2
pub type Challenger = DuplexChallenger<Val, Perm24, 24, 16>;

/// Complete STARK configuration with PCS and challenger
pub type MyStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// PCS configuration components
pub struct PcsComponents {
    /// Poseidon2 permutation (width 16) for compression
    pub perm16: Perm16,
    /// Poseidon2 permutation (width 24) for sponge
    pub perm24: Perm24,
    /// FRI blowup factor
    pub log_blowup: usize,
    /// Number of FRI queries
    pub num_queries: usize,
    /// Proof of work bits
    pub pow_bits: usize,
}

impl PcsComponents {
    /// Create PCS components from STARK configuration
    pub fn from_stark_config(config: &StarkConfiguration) -> Self {
        use rand::{SeedableRng, rngs::StdRng};

        // IMPORTANT: Use deterministic seed for reproducible Poseidon2 parameters
        // Both prover and verifier must use the same parameters
        let seed = [42u8; 32]; // Fixed seed ensures prover and verifier use identical parameters
        let mut rng = StdRng::from_seed(seed);

        // Create Poseidon2 permutations with deterministic parameters
        let perm16 = Perm16::new_from_rng_128(&mut rng);
        let perm24 = Perm24::new_from_rng_128(&mut rng);

        Self {
            perm16,
            perm24,
            log_blowup: config.log_blowup,
            num_queries: config.num_queries,
            pow_bits: config.pow_bits,
        }
    }

    /// Create value MMCS with Poseidon2
    pub fn create_val_mmcs(&self) -> Poseidon2MerkleMmcs {
        let hash = Poseidon2Sponge::new(self.perm24.clone());
        let compress = Poseidon2Compression::new(self.perm16.clone());
        MerkleTreeMmcs::new(hash, compress)
    }

    /// Create challenge MMCS
    pub fn create_challenge_mmcs(&self) -> ChallengeMmcs {
        ExtensionMmcs::new(self.create_val_mmcs())
    }

    /// Create FRI configuration
    pub fn create_fri_config(&self) -> FriConfig<ChallengeMmcs> {
        FriConfig {
            log_blowup: self.log_blowup,
            log_final_poly_len: 0, // CirclePcs uses 0
            num_queries: self.num_queries,
            proof_of_work_bits: self.pow_bits,
            mmcs: self.create_challenge_mmcs(),
        }
    }

    /// Create Circle PCS
    pub fn create_pcs(&self) -> Pcs {
        Pcs {
            mmcs: self.create_val_mmcs(),
            fri_config: self.create_fri_config(),
            _phantom: PhantomData,
        }
    }

    /// Create a fresh challenger for proving
    pub fn create_challenger(&self) -> Challenger {
        DuplexChallenger::new(self.perm24.clone())
    }

    /// Create STARK config from PCS
    pub fn create_stark_config(&self) -> MyStarkConfig {
        StarkConfig::new(self.create_pcs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::ProgramConfig;

    #[test]
    fn test_pcs_components_creation() {
        let stark_config = StarkConfiguration::new(ProgramConfig::default(), 100);
        let pcs_components = PcsComponents::from_stark_config(&stark_config);

        // Verify parameters match
        assert_eq!(pcs_components.log_blowup, 1);
        assert_eq!(pcs_components.num_queries, 100);
        assert_eq!(pcs_components.pow_bits, 16);
    }

    #[test]
    fn test_fri_config_creation() {
        let stark_config = StarkConfiguration::new(ProgramConfig::default(), 100);
        let pcs_components = PcsComponents::from_stark_config(&stark_config);

        // Should be able to create FRI config
        let fri_config = pcs_components.create_fri_config();
        assert_eq!(fri_config.log_blowup, 1);
        assert_eq!(fri_config.num_queries, 100);
        assert_eq!(fri_config.proof_of_work_bits, 16);
        assert_eq!(fri_config.log_final_poly_len, 0);
    }

    #[test]
    fn test_challenger_creation() {
        let stark_config = StarkConfiguration::new(ProgramConfig::default(), 50);
        let pcs_components = PcsComponents::from_stark_config(&stark_config);

        // Should be able to create challengers
        let _challenger1 = pcs_components.create_challenger();
        let _challenger2 = pcs_components.create_challenger();
    }

    #[test]
    fn test_pcs_creation() {
        let stark_config = StarkConfiguration::new(ProgramConfig::default(), 100);
        let pcs_components = PcsComponents::from_stark_config(&stark_config);

        // Should be able to create PCS
        let _pcs = pcs_components.create_pcs();
    }

    #[test]
    fn test_stark_config_creation() {
        let stark_config = StarkConfiguration::new(ProgramConfig::default(), 100);
        let pcs_components = PcsComponents::from_stark_config(&stark_config);

        // Should be able to create StarkConfig
        let _config = pcs_components.create_stark_config();
    }
}
