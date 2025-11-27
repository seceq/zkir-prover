//! Proof types and serialization

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// STARK proof for ZK IR execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Commitments to trace polynomials
    pub trace_commitments: Vec<TraceCommitment>,

    /// FRI proof
    pub fri_proof: FriProof,

    /// Opening proofs for evaluations
    pub openings: Vec<Opening>,

    /// Public inputs and outputs
    pub public_inputs: PublicInputs,

    /// Prover configuration used
    pub config: ProofConfig,
}

impl Proof {
    /// Load a proof from a file
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let proof: Self = bincode::deserialize(&data)?;
        Ok(proof)
    }

    /// Save the proof to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Size of the serialized proof in bytes
    pub fn size_bytes(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
}

/// Commitment to a trace polynomial
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceCommitment {
    /// Chip name this commitment is for
    pub chip: String,
    /// Merkle root of the committed polynomial
    pub root: [u8; 32],
}

/// FRI proof for low-degree testing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProof {
    /// Commitments to each FRI layer
    pub layer_commitments: Vec<[u8; 32]>,
    /// Final polynomial coefficients
    pub final_poly: Vec<u64>,
    /// Query round proofs
    pub query_proofs: Vec<FriQueryProof>,
    /// Proof of work nonce (grinding)
    pub pow_nonce: u64,
}

/// Proof for a single FRI query
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriQueryProof {
    /// Query index
    pub index: usize,
    /// Values at queried positions
    pub values: Vec<u64>,
    /// Merkle authentication paths
    pub merkle_paths: Vec<Vec<[u8; 32]>>,
}

/// Opening proof for polynomial evaluations
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opening {
    /// Evaluation point
    pub point: u64,
    /// Values of polynomials at this point
    pub values: Vec<u64>,
    /// Merkle authentication path
    pub merkle_path: Vec<[u8; 32]>,
}

/// Public inputs and outputs for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Hash of the program being proven
    pub program_hash: [u8; 32],
    /// Public inputs to the program
    pub inputs: Vec<u32>,
    /// Public outputs from the program
    pub outputs: Vec<u32>,
    /// Number of execution cycles
    pub num_cycles: u64,
}

/// Proof configuration metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofConfig {
    /// Log2 of LDE blowup factor
    pub log_blowup: usize,
    /// Number of FRI queries
    pub num_queries: usize,
    /// Proof of work bits
    pub pow_bits: usize,
}
