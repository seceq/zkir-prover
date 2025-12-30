//! Proof and verifying key data structures
//!
//! This module defines the core data structures for STARK proofs and verifying keys.
//! These structures are backend-agnostic and can be serialized/deserialized for
//! storage and transmission.

use serde::{Deserialize, Serialize};

/// A STARK proof for ZKIR v3.4 program execution
///
/// This structure contains all the cryptographic commitments and openings
/// needed to verify that a program executed correctly. The proof is
/// zero-knowledge: it reveals nothing about the execution except that
/// it satisfied all constraints.
///
/// # Structure
///
/// The proof consists of:
/// - **Commitments**: Merkle tree roots committing to trace polynomials
/// - **FRI proof**: Low-degree testing proof for polynomial commitments
/// - **Query openings**: Evaluations at random challenge points
/// - **Public values**: Public inputs/outputs (not hidden)
///
/// # Size
///
/// Typical proof size: 40-100 KB for 1K-cycle programs
///
/// # Serialization
///
/// Proofs can be serialized to bytes using `bincode` for storage or transmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Serialized proof bytes (backend-specific format)
    ///
    /// This contains the complete proof in the backend's native format.
    /// For Plonky3, this includes FRI commitments, query proofs, etc.
    pub proof_bytes: Vec<u8>,

    /// Public inputs to the program
    ///
    /// These are values that are known to both prover and verifier.
    /// For example: initial PC, final PC, public I/O values.
    pub public_inputs: Vec<u32>,

    /// Public outputs from the program
    ///
    /// These are values computed during execution that are revealed.
    /// For example: final register values, return value, exit code.
    pub public_outputs: Vec<u32>,

    /// Metadata about the proof
    pub metadata: ProofMetadata,

    /// Verifying key for this proof
    ///
    /// The VK is bundled with the proof for convenience. Alternatively,
    /// it can be stored separately and matched by program hash.
    pub verifying_key: VerifyingKey,
}

/// Metadata about a proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Backend that generated this proof
    pub backend_name: String,

    /// Backend version
    pub backend_version: String,

    /// Number of execution cycles proven
    pub num_cycles: usize,

    /// Trace width (number of columns)
    pub trace_width: usize,

    /// Trace height (number of rows, power-of-2)
    pub trace_height: usize,

    /// Proof size in bytes
    pub proof_size: usize,

    /// Security level in bits (e.g., 100-bit security)
    pub security_bits: usize,

    /// Timestamp when proof was generated
    pub timestamp: u64,

    /// RAP challenge (Fiat-Shamir derived)
    ///
    /// This challenge is derived from the main trace commitment and used
    /// for auxiliary column computation. The verifier must use the same
    /// challenge when evaluating constraints.
    pub rap_challenge: Option<u32>,
}

/// Verifying key for STARK proofs
///
/// The verifying key contains program-specific parameters needed to verify
/// proofs. It is generated once per program and can be reused to verify
/// any number of proofs for that program.
///
/// # Security
///
/// The verifying key is a public parameter and does not need to be kept secret.
/// It can be distributed to anyone who needs to verify proofs.
///
/// # Size
///
/// Typical VK size: 1-10 KB
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// Serialized verifying key bytes (backend-specific format)
    pub vk_bytes: Vec<u8>,

    /// Program-specific parameters
    pub program_params: ProgramParams,

    /// STARK configuration parameters
    pub stark_config: StarkConfig,

    /// Metadata about the verifying key
    pub metadata: VkMetadata,
}

/// Program-specific parameters
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProgramParams {
    /// Number of execution cycles (may be padded to power-of-2)
    pub num_cycles: usize,

    /// Trace width (number of columns)
    pub trace_width: usize,

    /// Number of limbs for data values
    pub data_limbs: usize,

    /// Bits per limb
    pub limb_bits: usize,

    /// Public input indices (which trace columns are public)
    pub public_input_indices: Vec<usize>,

    /// Public output indices
    pub public_output_indices: Vec<usize>,
}

/// STARK configuration parameters
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StarkConfig {
    /// Field prime (e.g., Baby Bear: 2^31 - 2^27 + 1)
    pub field_prime: u64,

    /// FRI blowup factor (typically 2-4)
    pub fri_blowup: usize,

    /// Number of FRI queries (affects security level)
    pub fri_queries: usize,

    /// FRI folding factor
    pub fri_folding_factor: usize,

    /// Hash function used (e.g., "Poseidon2", "Keccak-256")
    pub hash_function: String,

    /// Security level in bits
    pub security_bits: usize,
}

/// Verifying key metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VkMetadata {
    /// Backend that generated this VK
    pub backend_name: String,

    /// Backend version
    pub backend_version: String,

    /// Program hash/identifier (for matching proofs to VKs)
    pub program_hash: Option<[u8; 32]>,

    /// Timestamp when VK was generated
    pub timestamp: u64,
}

impl Proof {
    /// Create a new proof
    pub fn new(
        proof_bytes: Vec<u8>,
        public_inputs: Vec<u32>,
        public_outputs: Vec<u32>,
        metadata: ProofMetadata,
        verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            proof_bytes,
            public_inputs,
            public_outputs,
            metadata,
            verifying_key,
        }
    }

    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get proof size in bytes (excluding metadata)
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Get total size including all fields
    pub fn total_size(&self) -> usize {
        self.to_bytes().map(|b| b.len()).unwrap_or(0)
    }
}

impl VerifyingKey {
    /// Create a new verifying key
    pub fn new(
        vk_bytes: Vec<u8>,
        program_params: ProgramParams,
        stark_config: StarkConfig,
        metadata: VkMetadata,
    ) -> Self {
        Self {
            vk_bytes,
            program_params,
            stark_config,
            metadata,
        }
    }

    /// Serialize verifying key to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize verifying key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get VK size in bytes
    pub fn size(&self) -> usize {
        self.vk_bytes.len()
    }

    /// Check if this VK matches the given program parameters
    pub fn matches_program(&self, num_cycles: usize, trace_width: usize) -> bool {
        self.program_params.num_cycles == num_cycles
            && self.program_params.trace_width == trace_width
    }
}

impl Default for ProofMetadata {
    fn default() -> Self {
        Self {
            backend_name: "unknown".to_string(),
            backend_version: "0.0.0".to_string(),
            num_cycles: 0,
            trace_width: 0,
            trace_height: 0,
            proof_size: 0,
            security_bits: 100,
            timestamp: 0,
            rap_challenge: None,
        }
    }
}

impl Default for VkMetadata {
    fn default() -> Self {
        Self {
            backend_name: "unknown".to_string(),
            backend_version: "0.0.0".to_string(),
            program_hash: None,
            timestamp: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization() {
        let metadata = ProofMetadata {
            backend_name: "test".to_string(),
            backend_version: "1.0.0".to_string(),
            num_cycles: 100,
            trace_width: 88,
            trace_height: 128,
            proof_size: 1024,
            security_bits: 100,
            timestamp: 1234567890,
            rap_challenge: None,
        };

        let vk = VerifyingKey::new(
            vec![],
            ProgramParams::default(),
            StarkConfig::default(),
            VkMetadata::default(),
        );

        let proof = Proof::new(
            vec![1, 2, 3, 4],
            vec![10, 20],
            vec![30, 40],
            metadata,
            vk,
        );

        // Test serialization round-trip
        let bytes = proof.to_bytes().unwrap();
        let deserialized = Proof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.proof_bytes, deserialized.proof_bytes);
        assert_eq!(proof.public_inputs, deserialized.public_inputs);
        assert_eq!(proof.public_outputs, deserialized.public_outputs);
        assert_eq!(proof.metadata.num_cycles, deserialized.metadata.num_cycles);
    }

    #[test]
    fn test_verifying_key_serialization() {
        let program_params = ProgramParams {
            num_cycles: 100,
            trace_width: 88,
            data_limbs: 2,
            limb_bits: 20,
            public_input_indices: vec![0, 1],
            public_output_indices: vec![2, 3],
        };

        let stark_config = StarkConfig {
            field_prime: 2113929217, // Baby Bear
            fri_blowup: 2,
            fri_queries: 100,
            fri_folding_factor: 4,
            hash_function: "Poseidon2".to_string(),
            security_bits: 100,
        };

        let vk = VerifyingKey::new(
            vec![5, 6, 7, 8],
            program_params,
            stark_config,
            VkMetadata::default(),
        );

        // Test serialization round-trip
        let bytes = vk.to_bytes().unwrap();
        let deserialized = VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(vk.vk_bytes, deserialized.vk_bytes);
        assert_eq!(vk.program_params.num_cycles, deserialized.program_params.num_cycles);
        assert_eq!(vk.stark_config.field_prime, deserialized.stark_config.field_prime);
    }

    #[test]
    fn test_vk_matches_program() {
        let program_params = ProgramParams {
            num_cycles: 100,
            trace_width: 88,
            data_limbs: 2,
            limb_bits: 20,
            public_input_indices: vec![],
            public_output_indices: vec![],
        };

        let vk = VerifyingKey::new(
            vec![],
            program_params,
            StarkConfig {
                field_prime: 2113929217,
                fri_blowup: 2,
                fri_queries: 100,
                fri_folding_factor: 4,
                hash_function: "Poseidon2".to_string(),
                security_bits: 100,
            },
            VkMetadata::default(),
        );

        assert!(vk.matches_program(100, 88));
        assert!(!vk.matches_program(200, 88));
        assert!(!vk.matches_program(100, 90));
    }

    #[test]
    fn test_proof_size() {
        let vk = VerifyingKey::new(
            vec![],
            ProgramParams::default(),
            StarkConfig::default(),
            VkMetadata::default(),
        );

        let proof = Proof::new(
            vec![1, 2, 3, 4, 5],
            vec![],
            vec![],
            ProofMetadata::default(),
            vk,
        );

        assert_eq!(proof.size(), 5);
        assert!(proof.total_size() > 5); // Includes metadata
    }
}
