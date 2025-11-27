//! STARK prover implementation

use anyhow::Result;
use thiserror::Error;
use tracing::info;

use crate::machine::ZkIrMachine;
use crate::proof::{Proof, ProofConfig, PublicInputs};
use crate::trace::ExecutionTrace;

/// Prover errors
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Empty trace: no execution steps")]
    EmptyTrace,

    #[error("Trace too large: {0} steps exceeds maximum")]
    TraceTooLarge(usize),

    #[error("Invalid trace: {0}")]
    InvalidTrace(String),

    #[error("Proving failed: {0}")]
    ProvingFailed(String),
}

/// Prover configuration
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// Log2 of LDE blowup factor (2 = 4x, 3 = 8x, 4 = 16x)
    pub log_blowup: usize,
    /// Number of FRI queries
    pub num_queries: usize,
    /// Proof of work bits for grinding
    pub pow_bits: usize,
}

impl ProverConfig {
    /// Fast configuration for testing (~80 bits security)
    pub fn fast() -> Self {
        Self {
            log_blowup: 2,  // 4x
            num_queries: 20,
            pow_bits: 8,
        }
    }

    /// Default configuration (~100 bits security)
    pub fn default() -> Self {
        Self {
            log_blowup: 3,  // 8x
            num_queries: 28,
            pow_bits: 16,
        }
    }

    /// High security configuration (~128 bits)
    pub fn high() -> Self {
        Self {
            log_blowup: 4,  // 16x
            num_queries: 50,
            pow_bits: 20,
        }
    }
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self::default()
    }
}

/// STARK prover for ZK IR
pub struct Prover {
    /// Prover configuration
    config: ProverConfig,
    /// Multi-chip machine
    machine: ZkIrMachine,
}

impl Prover {
    /// Create a new prover with the given configuration
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
            machine: ZkIrMachine::new(),
        }
    }

    /// Generate a STARK proof from an execution trace
    pub fn prove(&self, trace: &ExecutionTrace) -> Result<Proof, ProverError> {
        // Validate trace
        if trace.steps.is_empty() {
            return Err(ProverError::EmptyTrace);
        }

        info!("Generating traces for {} steps", trace.steps.len());

        // Generate chip traces
        let traces = self.machine.generate_traces(trace);

        info!(
            "Generated traces - CPU: {}x{}, Memory: {}x{}, Range: {}x{}",
            traces.cpu.height(),
            traces.cpu.width(),
            traces.memory.height(),
            traces.memory.width(),
            traces.range.height(),
            traces.range.width(),
        );

        // Build public inputs
        let public_inputs = PublicInputs {
            program_hash: trace.program_hash,
            inputs: trace.inputs.clone(),
            outputs: trace.outputs.clone(),
            num_cycles: trace.num_cycles(),
        };

        // TODO: Implement actual STARK proving
        // 1. Commit to trace polynomials
        // 2. Compute constraint polynomials
        // 3. Commit to quotient polynomial
        // 4. Run FRI protocol
        // 5. Open at random points

        // Placeholder proof
        let proof = Proof {
            trace_commitments: vec![],
            fri_proof: crate::proof::FriProof {
                layer_commitments: vec![],
                final_poly: vec![],
                query_proofs: vec![],
                pow_nonce: 0,
            },
            openings: vec![],
            public_inputs,
            config: ProofConfig {
                log_blowup: self.config.log_blowup,
                num_queries: self.config.num_queries,
                pow_bits: self.config.pow_bits,
            },
        };

        Ok(proof)
    }
}

/// Trait for objects that can compute their trace width
pub trait TraceWidth {
    fn width(&self) -> usize;
    fn height(&self) -> usize;
}

impl<F: p3_field::Field> TraceWidth for p3_matrix::dense::RowMajorMatrix<F> {
    fn width(&self) -> usize {
        p3_matrix::Matrix::width(self)
    }

    fn height(&self) -> usize {
        p3_matrix::Matrix::height(self)
    }
}
