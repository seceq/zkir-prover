//! ProverBackend trait implementation for Plonky3
//!
//! This module implements the generic ProverBackend trait for the Plonky3 backend,
//! allowing it to be used interchangeably with other backends.
//!
//! ## RAP Pattern
//!
//! Uses RAP (Randomized AIR with Preprocessing) for cryptographic security:
//! 1. Build main trace from MainWitness
//! 2. Commit main trace → derive Fiat-Shamir challenge from transcript
//! 3. Build auxiliary trace using real challenge
//! 4. Complete proof

use crate::backend::plonky3::{Plonky3Prover, Plonky3Verifier, StarkConfiguration};
use crate::backend::proof::{Proof, VerifyingKey};
use crate::backend::r#trait::{ProofResult, ProverBackend};
use crate::witness::MainWitness;

/// Plonky3 backend implementation
///
/// This wraps the Plonky3Prover and Plonky3Verifier to implement the
/// generic ProverBackend trait.
pub struct Plonky3Backend {
    prover: Plonky3Prover,
    verifier: Plonky3Verifier,
}

impl Plonky3Backend {
    /// Create a new Plonky3 backend with the given configuration
    pub fn new(config: StarkConfiguration) -> Self {
        Self {
            prover: Plonky3Prover::new(config.clone()),
            verifier: Plonky3Verifier::new(config),
        }
    }

    /// Create a backend with default configuration
    pub fn default_config() -> Self {
        Self {
            prover: Plonky3Prover::default_config(),
            verifier: Plonky3Verifier::default_config(),
        }
    }

    /// Create a backend with test configuration
    pub fn test_config() -> Self {
        Self {
            prover: Plonky3Prover::test_config(),
            verifier: Plonky3Verifier::test_config(),
        }
    }

    /// Create a backend with fast test configuration (minimal security, very fast)
    /// Use this for rapid iteration during development
    pub fn fast_test_config() -> Self {
        Self {
            prover: Plonky3Prover::fast_test_config(),
            verifier: Plonky3Verifier::fast_test_config(),
        }
    }
}

impl ProverBackend for Plonky3Backend {
    fn prove(&self, main_witness: &MainWitness) -> ProofResult<Proof> {
        self.prover.prove_rap(main_witness)
    }

    fn verify(&self, proof: &Proof, vk: &VerifyingKey) -> ProofResult<()> {
        self.verifier.verify(proof, vk)
    }

    fn name(&self) -> &str {
        "Plonky3"
    }

    fn config_info(&self) -> String {
        self.prover.config().summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{MainWitness, MainTraceRow, ValueBound, PublicIO, ProgramConfig};

    fn create_test_main_witness() -> MainWitness {
        let config = ProgramConfig::default();
        let data_limbs = config.data_limbs as usize;

        let mut trace = Vec::new();
        for i in 0..10u64 {
            let row = MainTraceRow::new(
                i,
                i * 4,
                0x00024000, // ADD r0, r1, r2
                vec![vec![0; data_limbs]; 16],
                vec![ValueBound::zero(); 16],
            );
            trace.push(row);
        }

        MainWitness {
            trace,
            cycle_count: 10,
            memory_ops: Vec::new(),
            range_checks: Vec::new(),
            crypto_ops: Vec::new(),
            public_io: PublicIO {
                program_hash: [0u8; 32],
                inputs: vec![vec![42, 0]],
                outputs: vec![vec![84, 0]],
            },
            config,
            multiplicities: crate::witness::LogUpMultiplicities::new(),
        }
    }

    #[test]
    fn test_backend_creation() {
        let backend = Plonky3Backend::default_config();
        assert_eq!(backend.name(), "Plonky3");
    }

    #[test]
    fn test_backend_config_info() {
        let backend = Plonky3Backend::default_config();
        let info = backend.config_info();

        assert!(info.contains("Plonky3"));
        assert!(info.contains("Mersenne 31"));
        assert!(info.contains("100 bits"));
    }

    #[test]
    fn test_prove_and_verify() {
        let backend = Plonky3Backend::test_config();
        let main_witness = create_test_main_witness();

        // Generate proof
        let proof = backend.prove(&main_witness).unwrap();

        // Verify proof
        let result = backend.verify(&proof, &proof.verifying_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prove_generates_vk() {
        let backend = Plonky3Backend::test_config();
        let main_witness = create_test_main_witness();

        let proof = backend.prove(&main_witness).unwrap();

        // Check VK has correct metadata
        assert_eq!(proof.verifying_key.metadata.backend_name, "Plonky3");
        assert_eq!(proof.verifying_key.program_params.trace_width, 257); // 247 main (with Option A imm limbs) + 10 aux
        assert_eq!(proof.verifying_key.stark_config.field_prime, crate::types::MERSENNE31_PRIME as u64);
    }

    #[test]
    fn test_end_to_end_workflow() {
        let backend = Plonky3Backend::test_config();
        let main_witness = create_test_main_witness();

        // Prove
        let proof = backend.prove(&main_witness).unwrap();

        // Check proof metadata
        assert_eq!(proof.metadata.backend_name, "Plonky3");
        assert!(!proof.proof_bytes.is_empty());

        // Verify
        assert!(backend.verify(&proof, &proof.verifying_key).is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let backend = Plonky3Backend::test_config();
        let main_witness = create_test_main_witness();

        let proof = backend.prove(&main_witness).unwrap();

        // Serialize
        let proof_bytes = proof.to_bytes().unwrap();
        let vk_bytes = proof.verifying_key.to_bytes().unwrap();

        // Deserialize
        let proof2 = Proof::from_bytes(&proof_bytes).unwrap();
        let vk2 = VerifyingKey::from_bytes(&vk_bytes).unwrap();

        // Verify deserialized proof
        assert!(backend.verify(&proof2, &vk2).is_ok());
    }
}
