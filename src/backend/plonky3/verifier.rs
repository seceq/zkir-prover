//! Plonky3 proof verification
//!
//! This module implements STARK proof verification using Plonky3.
//! It takes a proof and verifying key and checks that the proof is valid.

use p3_uni_stark::verify;

use crate::backend::proof::{Proof, VerifyingKey};
use crate::backend::r#trait::{ProofError, ProofResult};
use crate::backend::plonky3::config::StarkConfiguration;
use crate::backend::plonky3::pcs::PcsComponents;
use crate::backend::plonky3::air::ZkIrAirAdapter;
use crate::witness::ProgramConfig;

/// Plonky3 STARK verifier
///
/// This structure provides methods for verifying STARK proofs generated
/// by the Plonky3 prover.
pub struct Plonky3Verifier {
    /// STARK configuration
    config: StarkConfiguration,
}

impl Plonky3Verifier {
    /// Create a new Plonky3 verifier
    ///
    /// # Arguments
    ///
    /// * `config` - STARK configuration (must match prover config)
    ///
    /// # Returns
    ///
    /// Returns a configured verifier ready to verify proofs.
    pub fn new(config: StarkConfiguration) -> Self {
        Self { config }
    }

    /// Create a verifier with default configuration
    pub fn default_config() -> Self {
        Self::new(StarkConfiguration::default_config())
    }

    /// Create a verifier with test configuration
    pub fn test_config() -> Self {
        Self::new(StarkConfiguration::test_config())
    }

    /// Create a verifier with fast test configuration (minimal security, very fast)
    pub fn fast_test_config() -> Self {
        Self::new(StarkConfiguration::fast_test_config())
    }

    /// Verify a STARK proof
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `vk` - The verifying key (contains program parameters)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the proof is valid, `Err(ProofError)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `ProofError` if:
    /// - The proof format is invalid
    /// - The verifying key doesn't match the proof
    /// - The cryptographic verification fails
    /// - Public inputs/outputs don't match
    pub fn verify(&self, proof: &Proof, vk: &VerifyingKey) -> ProofResult<()> {
        // Check proof metadata matches VK
        self.check_metadata_compatibility(proof, vk)?;

        // Verify cryptographic proof (pass full proof for access to rap_challenge)
        self.verify_cryptographic_proof(proof, vk)?;

        // Verify public inputs/outputs are consistent
        self.verify_public_values(proof, vk)?;

        Ok(())
    }

    /// Check that proof metadata is compatible with verifying key
    fn check_metadata_compatibility(&self, proof: &Proof, vk: &VerifyingKey) -> ProofResult<()> {
        // Check trace dimensions match
        if proof.metadata.trace_width != vk.program_params.trace_width {
            return Err(ProofError::VerificationFailed(format!(
                "Trace width mismatch: proof has {}, VK expects {}",
                proof.metadata.trace_width, vk.program_params.trace_width
            )));
        }

        // Check field parameters match
        if vk.stark_config.field_prime != crate::types::MERSENNE31_PRIME as u64 {
            return Err(ProofError::VerificationFailed(format!(
                "Field mismatch: VK uses prime {}, expected {}",
                vk.stark_config.field_prime,
                crate::types::MERSENNE31_PRIME
            )));
        }

        // Check security level is sufficient
        if proof.metadata.security_bits < vk.stark_config.security_bits {
            return Err(ProofError::VerificationFailed(format!(
                "Insufficient security: proof has {} bits, VK requires {}",
                proof.metadata.security_bits, vk.stark_config.security_bits
            )));
        }

        Ok(())
    }

    /// Verify the cryptographic STARK proof
    ///
    /// This is where we call Plonky3's verification algorithm.
    fn verify_cryptographic_proof(
        &self,
        proof: &Proof,
        vk: &VerifyingKey,
    ) -> ProofResult<()> {
        // Deserialize the inner proof
        let inner_proof = bincode::deserialize(&proof.proof_bytes).map_err(|e| {
            ProofError::VerificationFailed(format!("Failed to deserialize proof: {}", e))
        })?;

        // Create program config from VK
        let program_config = ProgramConfig {
            limb_bits: vk.program_params.limb_bits as u8,
            data_limbs: vk.program_params.data_limbs as u8,
            addr_limbs: vk.program_params.data_limbs as u8, // Use same as data_limbs
        };

        // Create AIR adapter with the same RAP challenge used during proving
        // This is critical for constraint evaluation to match the prover's evaluation
        let air = match proof.metadata.rap_challenge {
            Some(challenge) => ZkIrAirAdapter::new_with_challenge(program_config, challenge),
            None => ZkIrAirAdapter::new(program_config),
        };

        // Create PCS components
        let pcs_components = PcsComponents::from_stark_config(&self.config);

        // Create STARK configuration with PCS
        let stark_config = pcs_components.create_stark_config();

        // Create fresh challenger for verification
        let mut challenger = pcs_components.create_challenger();

        // Public values (empty for now - we'll add them in a future version)
        let public_values = vec![];

        // Verify the proof using Plonky3's verify function
        verify(&stark_config, &air, &mut challenger, &inner_proof, &public_values).map_err(|e| {
            ProofError::VerificationFailed(format!("Plonky3 verification failed: {:?}", e))
        })?;

        Ok(())
    }

    /// Verify public input/output values are consistent
    fn verify_public_values(&self, proof: &Proof, vk: &VerifyingKey) -> ProofResult<()> {
        // Check public input count matches VK specification
        let expected_input_count = vk.program_params.public_input_indices.len();
        if proof.public_inputs.len() != expected_input_count && expected_input_count > 0 {
            return Err(ProofError::VerificationFailed(format!(
                "Public input count mismatch: proof has {}, VK expects {}",
                proof.public_inputs.len(),
                expected_input_count
            )));
        }

        // Check public output count matches VK specification
        let expected_output_count = vk.program_params.public_output_indices.len();
        if proof.public_outputs.len() != expected_output_count && expected_output_count > 0 {
            return Err(ProofError::VerificationFailed(format!(
                "Public output count mismatch: proof has {}, VK expects {}",
                proof.public_outputs.len(),
                expected_output_count
            )));
        }

        // All values are within field bounds (Mersenne 31)
        for &input in &proof.public_inputs {
            if input >= crate::types::MERSENNE31_PRIME {
                return Err(ProofError::VerificationFailed(format!(
                    "Public input {} exceeds field prime",
                    input
                )));
            }
        }

        for &output in &proof.public_outputs {
            if output >= crate::types::MERSENNE31_PRIME {
                return Err(ProofError::VerificationFailed(format!(
                    "Public output {} exceeds field prime",
                    output
                )));
            }
        }

        Ok(())
    }

    /// Get the verifier configuration
    pub fn config(&self) -> &StarkConfiguration {
        &self.config
    }

    /// Quick check if a proof looks valid (format check only)
    pub fn quick_check(&self, proof: &Proof) -> bool {
        // Basic sanity checks
        !proof.proof_bytes.is_empty()
            && proof.metadata.trace_width > 0
            && proof.metadata.trace_height > 0
            && proof.metadata.security_bits >= 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::proof::{ProofMetadata, ProgramParams, StarkConfig, VkMetadata};

    fn create_test_proof() -> Proof {
        let vk = create_test_vk();
        Proof::new(
            b"ZKIR-PROOF-PLACEHOLDER:88x10:10cycles".to_vec(),
            vec![0, 42, 0], // Initial PC + input limbs
            vec![36, 84, 0], // Final PC + output limbs
            ProofMetadata {
                backend_name: "Plonky3".to_string(),
                backend_version: "0.1.0".to_string(),
                num_cycles: 10,
                trace_width: 93, // Was 88, now 93 with table accumulators
                trace_height: 10,
                proof_size: 38,
                security_bits: 100,
                timestamp: 1234567890,
                rap_challenge: None,
            },
            vk,
        )
    }

    fn create_test_vk() -> VerifyingKey {
        VerifyingKey::new(
            vec![1, 2, 3, 4], // Dummy VK bytes
            ProgramParams {
                num_cycles: 10,
                trace_width: 93, // Was 88, now 93 with table accumulators
                data_limbs: 2,
                limb_bits: 20,
                public_input_indices: vec![0, 1, 2],
                public_output_indices: vec![0, 1, 2],
            },
            StarkConfig {
                field_prime: crate::types::MERSENNE31_PRIME as u64,
                fri_blowup: 2,
                fri_queries: 100,
                fri_folding_factor: 4,
                hash_function: "Poseidon2".to_string(),
                security_bits: 100,
            },
            VkMetadata {
                backend_name: "Plonky3".to_string(),
                backend_version: "0.1.0".to_string(),
                program_hash: Some([0u8; 32]),
                timestamp: 1234567890,
            },
        )
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = Plonky3Verifier::default_config();
        assert_eq!(verifier.config().security_bits, 100);
    }

    #[test]
    fn test_verifier_test_config() {
        let verifier = Plonky3Verifier::test_config();
        assert_eq!(verifier.config().security_bits, 50);
    }

    #[test]
    fn test_quick_check_valid() {
        let verifier = Plonky3Verifier::default_config();
        let proof = create_test_proof();

        assert!(verifier.quick_check(&proof));
    }

    #[test]
    fn test_quick_check_empty_proof() {
        let verifier = Plonky3Verifier::default_config();
        let mut proof = create_test_proof();
        proof.proof_bytes.clear();

        assert!(!verifier.quick_check(&proof));
    }

    #[test]
    fn test_verify_placeholder_proof() {
        let verifier = Plonky3Verifier::default_config();
        let proof = create_test_proof();
        let vk = create_test_vk();

        // Placeholder proofs should fail cryptographic verification
        // (they're not real Plonky3 proofs, just dummy data)
        let result = verifier.verify(&proof, &vk);
        assert!(result.is_err());

        // The error should be a deserialization failure
        match result {
            Err(ProofError::VerificationFailed(msg)) => {
                assert!(msg.contains("Failed to deserialize proof"));
            }
            _ => panic!("Expected VerificationFailed error"),
        }
    }

    #[test]
    fn test_verify_trace_width_mismatch() {
        let verifier = Plonky3Verifier::default_config();
        let proof = create_test_proof();
        let mut vk = create_test_vk();
        vk.program_params.trace_width = 100; // Wrong width

        let result = verifier.verify(&proof, &vk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProofError::VerificationFailed(_)
        ));
    }

    #[test]
    fn test_verify_field_mismatch() {
        let verifier = Plonky3Verifier::default_config();
        let proof = create_test_proof();
        let mut vk = create_test_vk();
        vk.stark_config.field_prime = 2013265921; // Baby Bear instead of Mersenne 31

        let result = verifier.verify(&proof, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_proof_format() {
        let verifier = Plonky3Verifier::default_config();
        let mut proof = create_test_proof();
        proof.proof_bytes = b"INVALID-FORMAT".to_vec();
        let vk = create_test_vk();

        let result = verifier.verify(&proof, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_public_input_out_of_field() {
        let verifier = Plonky3Verifier::default_config();
        let mut proof = create_test_proof();
        proof.public_inputs[0] = crate::types::MERSENNE31_PRIME; // Out of field
        let vk = create_test_vk();

        let result = verifier.verify(&proof, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_public_output_out_of_field() {
        let verifier = Plonky3Verifier::default_config();
        let mut proof = create_test_proof();
        proof.public_outputs[0] = crate::types::MERSENNE31_PRIME + 1; // Out of field
        let vk = create_test_vk();

        let result = verifier.verify(&proof, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_compatibility_check() {
        let verifier = Plonky3Verifier::default_config();
        let proof = create_test_proof();
        let vk = create_test_vk();

        let result = verifier.check_metadata_compatibility(&proof, &vk);
        assert!(result.is_ok());
    }

    #[test]
    fn test_insufficient_security() {
        let verifier = Plonky3Verifier::default_config();
        let mut proof = create_test_proof();
        proof.metadata.security_bits = 50; // Too low
        let vk = create_test_vk(); // Expects 100 bits

        let result = verifier.check_metadata_compatibility(&proof, &vk);
        assert!(result.is_err());
    }
}
