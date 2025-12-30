//! Proof backend trait definition
//!
//! This module defines the `ProverBackend` trait, which provides a clean abstraction
//! over different STARK proof systems. This allows the ZKIR prover to support multiple
//! backends (Plonky3, etc.) with a unified interface.
//!
//! ## RAP Pattern
//!
//! The prover uses the RAP (Randomized AIR with Preprocessing) pattern:
//! 1. Build main trace from MainWitness
//! 2. Commit main trace → derive Fiat-Shamir challenge from transcript
//! 3. Build auxiliary trace using real challenge
//! 4. Complete proof

use crate::witness::MainWitness;
use super::proof::{Proof, VerifyingKey};

/// Result type for proof operations
pub type ProofResult<T> = Result<T, ProofError>;

/// Errors that can occur during proof generation or verification
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProofError {
    /// Witness is invalid or malformed
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Verification failed (proof is invalid)
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Backend-specific error
    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Proof backend abstraction
///
/// This trait defines the interface for generating and verifying STARK proofs
/// for ZKIR v3.4 programs. Different backends (e.g., Plonky3, Winterfell)
/// can implement this trait to provide proof generation capabilities.
///
/// # Example
///
/// ```ignore
/// use zkir_prover::backend::{ProverBackend, Plonky3Backend};
/// use zkir_prover::vm_integration::vm_result_to_main_witness;
///
/// // Run VM and convert to witness
/// let main_witness = vm_result_to_main_witness(&program, &inputs, result)?;
///
/// // Create backend and generate proof
/// let backend = Plonky3Backend::default_config();
/// let proof = backend.prove(&main_witness)?;
///
/// // Verify proof
/// backend.verify(&proof, &proof.verifying_key)?;
/// ```
pub trait ProverBackend {
    /// Generate a STARK proof for a main witness
    ///
    /// Uses RAP (Randomized AIR with Preprocessing) pattern:
    /// 1. Build main trace from MainWitness
    /// 2. Commit main trace → derive Fiat-Shamir challenge from transcript
    /// 3. Build auxiliary trace using real challenge
    /// 4. Complete proof
    ///
    /// # Arguments
    ///
    /// * `main_witness` - Main witness containing execution data
    ///
    /// # Returns
    ///
    /// Returns a `Proof` with proper cryptographic security.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The witness is invalid or malformed
    /// - Proof generation fails
    /// - Internal backend error occurs
    ///
    /// # Security
    ///
    /// This method uses proper Fiat-Shamir challenge derivation, making the
    /// proof cryptographically secure against polynomial forgery attacks.
    ///
    /// # Performance
    ///
    /// Proof generation is the most expensive operation in the system.
    /// Expected performance: <200ms for 1K-cycle programs.
    fn prove(&self, main_witness: &MainWitness) -> ProofResult<Proof>;

    /// Verify a STARK proof
    ///
    /// Verifies that a proof is valid for the given verifying key.
    /// This is a fast operation (typically <10ms) compared to proof generation.
    ///
    /// # Arguments
    ///
    /// * `proof` - The STARK proof to verify
    /// * `vk` - The verifying key (must match the program that generated the proof)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the proof is valid, or an error if verification fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The proof is invalid
    /// - The verifying key doesn't match
    /// - The proof is malformed
    ///
    /// # Performance
    ///
    /// Expected performance: <10ms for typical proofs.
    fn verify(&self, proof: &Proof, vk: &VerifyingKey) -> ProofResult<()>;

    /// Get the backend name for debugging/logging
    fn name(&self) -> &str;

    /// Get backend-specific configuration information
    fn config_info(&self) -> String {
        format!("Backend: {}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_error_display() {
        let err = ProofError::InvalidWitness("test error".to_string());
        assert_eq!(err.to_string(), "Invalid witness: test error");

        let err = ProofError::ProofGenerationFailed("failed".to_string());
        assert_eq!(err.to_string(), "Proof generation failed: failed");

        let err = ProofError::VerificationFailed("invalid".to_string());
        assert_eq!(err.to_string(), "Verification failed: invalid");
    }
}
