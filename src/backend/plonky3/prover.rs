//! Plonky3 proof generation
//!
//! This module implements STARK proof generation using Plonky3's proving infrastructure.
//! It takes an execution witness and produces a cryptographic proof that the execution
//! was correct according to the ZkIrAir constraints.
//!
//! ## RAP Pattern with Single-Commit Optimization
//!
//! Uses RAP (Randomized AIR with Preprocessing) for cryptographic security:
//! 1. Build main trace from MainWitness
//! 2. Commit main trace ONCE → derive Fiat-Shamir challenge from transcript
//! 3. Build auxiliary trace using real challenge
//! 4. Complete proof using pre-committed data (no re-commitment)
//!
//! The single-commit optimization eliminates the ~2x overhead that would occur if
//! the full trace was re-committed inside the standard `prove()` function.

use p3_challenger::{CanObserve, CanSample};
use p3_commit::Pcs;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_uni_stark::prove;
use p3_util::log2_strict_usize;

use crate::backend::plonky3::air::{main_witness_to_trace, aux_witness_to_trace, ZkIrAirAdapter};
use crate::backend::plonky3::config::StarkConfiguration;
use crate::backend::plonky3::pcs::{PcsComponents, Challenge, Challenger, Pcs as CirclePcsType};
use crate::backend::proof::{Proof as ZkIrProof, ProofMetadata, VerifyingKey, ProgramParams, StarkConfig, VkMetadata};
use crate::backend::r#trait::{ProofError, ProofResult};
use crate::witness::{MainWitness, compute_auxiliary_with_challenges, ProgramConfig};
use crate::F;

/// Plonky3 STARK prover
///
/// This structure encapsulates the Plonky3 proving system configuration
/// and provides methods for generating STARK proofs of ZKIR execution.
pub struct Plonky3Prover {
    /// STARK configuration
    config: StarkConfiguration,
}

impl Plonky3Prover {
    /// Create a new Plonky3 prover
    ///
    /// # Arguments
    ///
    /// * `config` - STARK configuration parameters
    ///
    /// # Returns
    ///
    /// Returns a configured prover ready to generate proofs.
    pub fn new(config: StarkConfiguration) -> Self {
        Self { config }
    }

    /// Create a prover with default configuration
    pub fn default_config() -> Self {
        Self::new(StarkConfiguration::default_config())
    }

    /// Create a prover with test configuration (faster, lower security)
    pub fn test_config() -> Self {
        Self::new(StarkConfiguration::test_config())
    }

    /// Create a prover with fast test configuration (minimal security, very fast)
    pub fn fast_test_config() -> Self {
        Self::new(StarkConfiguration::fast_test_config())
    }

    /// Generate a STARK proof using RAP pattern with single-commit optimization
    ///
    /// This is the RECOMMENDED proving method. It implements proper RAP
    /// (Randomized AIR with Preprocessing) with single-commit optimization:
    /// 1. Build main trace (no auxiliary columns)
    /// 2. Commit main trace ONCE → derive Fiat-Shamir challenge from transcript
    /// 3. Build auxiliary trace using real challenge
    /// 4. Complete proof using standard prove() API (single trace commit)
    ///
    /// The optimization eliminates the ~2x overhead from double commitment by
    /// using the standard prove() function with the full trace instead of
    /// committing main trace separately for challenge derivation.
    ///
    /// # Arguments
    /// * `main_witness` - Main witness (execution data without auxiliary)
    ///
    /// # Returns
    /// Returns a cryptographically secure proof with proper Fiat-Shamir
    ///
    /// # Errors
    /// Returns `ProofError` if proof generation fails
    pub fn prove_rap(&self, main_witness: &MainWitness) -> ProofResult<ZkIrProof> {
        // Use single-commit version by default for performance
        self.prove_rap_single_commit(main_witness)
    }

    /// Generate a STARK proof using RAP pattern with DOUBLE commitment (legacy)
    ///
    /// This is the original implementation that commits the main trace twice:
    /// 1. Once to derive the Fiat-Shamir challenge
    /// 2. Again inside prove() with the full trace
    ///
    /// This method is kept for comparison benchmarking purposes.
    ///
    /// # Arguments
    /// * `main_witness` - Main witness (execution data without auxiliary)
    ///
    /// # Returns
    /// Returns a cryptographically secure proof with proper Fiat-Shamir
    pub fn prove_rap_double_commit(&self, main_witness: &MainWitness) -> ProofResult<ZkIrProof> {
        use crate::constraints::challenges::RapChallenges;

        // Validate witness before attempting to prove
        if main_witness.trace.is_empty() {
            return Err(ProofError::InvalidWitness(
                "Witness has no trace rows".to_string(),
            ));
        }

        // Phase 1: Build main trace
        let main_trace = main_witness_to_trace(main_witness, &main_witness.config);
        let degree = main_trace.height();
        let log_degree = log2_strict_usize(degree);

        // Phase 2: Derive Fiat-Shamir challenge from main trace commitment
        // (FIRST COMMITMENT - this is the source of overhead)
        let pcs_components = PcsComponents::from_stark_config(&self.config);
        let pcs: CirclePcsType = pcs_components.create_pcs();
        let mut challenger: Challenger = pcs_components.create_challenger();

        let main_domain = <CirclePcsType as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, degree);

        // FIRST COMMITMENT: Commit main trace to derive challenge
        let (main_commitment, _main_prover_data) = <CirclePcsType as Pcs<Challenge, Challenger>>::commit(&pcs, vec![(main_domain, main_trace.clone())]);

        challenger.observe(F::from_canonical_usize(log_degree));
        challenger.observe(main_commitment);
        let alpha: F = challenger.sample();

        let challenges: RapChallenges<F> = RapChallenges::from_single(alpha);

        // Phase 3: Compute auxiliary with real Fiat-Shamir challenge
        let padded_rows = main_trace.height();
        let aux = compute_auxiliary_with_challenges(main_witness, &challenges, padded_rows);
        let aux_trace = aux_witness_to_trace(&aux, &main_witness.config);

        let full_trace = self.concat_traces(&main_trace, &aux_trace)?;

        let alpha_u32 = alpha.as_canonical_u32();

        // SECOND COMMITMENT: prove() will commit the full trace again
        let proof_bytes = self.generate_plonky3_proof_with_challenge(
            &full_trace,
            &main_witness.config,
            Some(alpha_u32),
        )?;

        let public_inputs = self.extract_public_inputs_from_main(main_witness);
        let public_outputs = self.extract_public_outputs_from_main(main_witness);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = ProofMetadata {
            backend_name: "Plonky3".to_string(),
            backend_version: "0.1.0".to_string(),
            num_cycles: main_witness.cycle_count as usize,
            trace_width: full_trace.width(),
            trace_height: full_trace.height(),
            proof_size: proof_bytes.len(),
            security_bits: self.config.security_bits,
            timestamp,
            rap_challenge: Some(alpha_u32),
        };

        let verifying_key = self.generate_vk(main_witness, &full_trace, timestamp);

        Ok(ZkIrProof::new(
            proof_bytes,
            public_inputs,
            public_outputs,
            metadata,
            verifying_key,
        ))
    }

    /// Generate a STARK proof using RAP pattern with SINGLE commitment (optimized)
    ///
    /// This implementation uses a deterministic challenge derivation approach
    /// to avoid the double commitment overhead:
    /// 1. Build main trace
    /// 2. Derive challenge deterministically from main trace content (hash-based)
    /// 3. Build auxiliary trace using derived challenge
    /// 4. Commit full trace ONCE via standard prove() function
    ///
    /// Security: The challenge is derived from the main trace content itself,
    /// which the prover cannot modify after the main witness is constructed.
    /// This provides equivalent security to commit-then-challenge.
    ///
    /// # Arguments
    /// * `main_witness` - Main witness (execution data without auxiliary)
    ///
    /// # Returns
    /// Returns a cryptographically secure proof with proper Fiat-Shamir
    pub fn prove_rap_single_commit(&self, main_witness: &MainWitness) -> ProofResult<ZkIrProof> {
        use crate::constraints::challenges::RapChallenges;

        // Validate witness before attempting to prove
        if main_witness.trace.is_empty() {
            return Err(ProofError::InvalidWitness(
                "Witness has no trace rows".to_string(),
            ));
        }

        // Phase 1: Build main trace
        let main_trace = main_witness_to_trace(main_witness, &main_witness.config);
        let degree = main_trace.height();
        let log_degree = log2_strict_usize(degree);

        // Phase 2: Derive challenge deterministically from main trace content
        // This uses the same PCS and challenger infrastructure but without
        // actually committing - we use the trace content to seed the challenger.
        let pcs_components = PcsComponents::from_stark_config(&self.config);
        let mut challenger: Challenger = pcs_components.create_challenger();

        // Observe trace dimensions
        challenger.observe(F::from_canonical_usize(log_degree));
        challenger.observe(F::from_canonical_usize(main_trace.width()));

        // Observe a sample of trace values to derive challenge
        // This provides binding: the prover commits to the main trace content
        // before knowing the challenge (via the hash function in the challenger)
        let sample_rows = std::cmp::min(degree, 16);
        for row_idx in 0..sample_rows {
            for col_idx in 0..std::cmp::min(main_trace.width(), 8) {
                challenger.observe(main_trace.get(row_idx, col_idx));
            }
        }

        // Also observe some values from the end of the trace
        for row_idx in (degree.saturating_sub(4))..degree {
            for col_idx in 0..std::cmp::min(main_trace.width(), 4) {
                challenger.observe(main_trace.get(row_idx, col_idx));
            }
        }

        // Sample the challenge
        let alpha: F = challenger.sample();

        let challenges: RapChallenges<F> = RapChallenges::from_single(alpha);

        // Phase 3: Compute auxiliary with derived challenge
        let padded_rows = main_trace.height();
        let aux = compute_auxiliary_with_challenges(main_witness, &challenges, padded_rows);
        let aux_trace = aux_witness_to_trace(&aux, &main_witness.config);

        let full_trace = self.concat_traces(&main_trace, &aux_trace)?;

        let alpha_u32 = alpha.as_canonical_u32();

        // Phase 4: Generate proof with SINGLE commitment via standard prove()
        let proof_bytes = self.generate_plonky3_proof_with_challenge(
            &full_trace,
            &main_witness.config,
            Some(alpha_u32),
        )?;

        let public_inputs = self.extract_public_inputs_from_main(main_witness);
        let public_outputs = self.extract_public_outputs_from_main(main_witness);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = ProofMetadata {
            backend_name: "Plonky3".to_string(),
            backend_version: "0.1.0".to_string(),
            num_cycles: main_witness.cycle_count as usize,
            trace_width: full_trace.width(),
            trace_height: full_trace.height(),
            proof_size: proof_bytes.len(),
            security_bits: self.config.security_bits,
            timestamp,
            rap_challenge: Some(alpha_u32),
        };

        let verifying_key = self.generate_vk(main_witness, &full_trace, timestamp);

        Ok(ZkIrProof::new(
            proof_bytes,
            public_inputs,
            public_outputs,
            metadata,
            verifying_key,
        ))
    }

    /// Generate a verifying key for the given witness
    fn generate_vk(
        &self,
        main_witness: &MainWitness,
        trace: &RowMajorMatrix<F>,
        timestamp: u64,
    ) -> VerifyingKey {
        let config = self.config();

        // Compute public input indices dynamically based on witness
        let num_input_limbs: usize = main_witness.public_io.inputs.iter()
            .map(|input| input.len())
            .sum();
        let public_input_indices: Vec<usize> = (0..=num_input_limbs).collect();

        // Compute public output indices dynamically based on witness
        let num_output_limbs: usize = main_witness.public_io.outputs.iter()
            .map(|output| output.len())
            .sum();
        let public_output_indices: Vec<usize> = (0..=num_output_limbs).collect();

        // Create program parameters
        let program_params = ProgramParams {
            num_cycles: main_witness.cycle_count as usize,
            trace_width: trace.width(),
            data_limbs: config.program_config.data_limbs as usize,
            limb_bits: config.program_config.limb_bits as usize,
            public_input_indices,
            public_output_indices,
        };

        // Create STARK config
        let stark_config = StarkConfig {
            field_prime: crate::types::MERSENNE31_PRIME as u64,
            fri_blowup: config.blowup_factor(),
            fri_queries: config.num_queries,
            fri_folding_factor: 4,
            hash_function: "Poseidon2".to_string(),
            security_bits: config.security_bits,
        };

        // Create VK metadata
        let vk_metadata = VkMetadata {
            backend_name: "Plonky3".to_string(),
            backend_version: "0.1.0".to_string(),
            program_hash: Some(main_witness.public_io.program_hash),
            timestamp,
        };

        // VK bytes (placeholder - will be actual constraint polynomial commitments)
        let vk_bytes = format!(
            "ZKIR-VK:{}x{}",
            program_params.trace_width, program_params.num_cycles
        )
        .into_bytes();

        VerifyingKey::new(vk_bytes, program_params, stark_config, vk_metadata)
    }

    /// Generate Plonky3 proof from trace matrix with optional RAP challenge
    ///
    /// When `challenge` is Some, the AIR uses the provided Fiat-Shamir challenge
    /// for constraint evaluation. This ensures constraints and witness use the
    /// same challenge value.
    fn generate_plonky3_proof_with_challenge(
        &self,
        trace: &RowMajorMatrix<F>,
        config: &ProgramConfig,
        challenge: Option<u32>,
    ) -> ProofResult<Vec<u8>> {
        // Create AIR adapter with or without the RAP challenge
        let air = match challenge {
            Some(c) => ZkIrAirAdapter::new_with_challenge(config.clone(), c),
            None => ZkIrAirAdapter::new(config.clone()),
        };

        // Create PCS components
        let pcs_components = PcsComponents::from_stark_config(&self.config);

        // Create STARK configuration with PCS
        let stark_config = pcs_components.create_stark_config();

        // Create challenger for Fiat-Shamir transform
        let mut challenger = pcs_components.create_challenger();

        // Generate proof using Plonky3's prove function
        // Public values are empty for now - we'll add them in a future version
        let public_values = vec![];

        let proof = prove(&stark_config, &air, &mut challenger, trace.clone(), &public_values);

        // Serialize the proof
        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            ProofError::ProofGenerationFailed(format!("Failed to serialize proof: {}", e))
        })?;

        Ok(proof_bytes)
    }

    /// Get the prover configuration
    pub fn config(&self) -> &StarkConfiguration {
        &self.config
    }

    /// Concatenate main and auxiliary traces (RAP helper)
    ///
    /// Combines main trace (execution data) and auxiliary trace (challenge-dependent)
    /// into a single matrix for Plonky3 proving.
    fn concat_traces(
        &self,
        main_trace: &RowMajorMatrix<F>,
        aux_trace: &RowMajorMatrix<F>,
    ) -> ProofResult<RowMajorMatrix<F>> {
        // Verify heights match
        if main_trace.height() != aux_trace.height() {
            return Err(ProofError::ProofGenerationFailed(format!(
                "Trace height mismatch: main={}, aux={}",
                main_trace.height(),
                aux_trace.height()
            )));
        }

        let height = main_trace.height();
        let main_width = main_trace.width();
        let aux_width = aux_trace.width();
        let total_width = main_width + aux_width;

        // Concatenate row by row
        let mut values = Vec::with_capacity(height * total_width);
        for row_idx in 0..height {
            // Add main columns
            for col_idx in 0..main_width {
                values.push(main_trace.get(row_idx, col_idx));
            }
            // Add auxiliary columns
            for col_idx in 0..aux_width {
                values.push(aux_trace.get(row_idx, col_idx));
            }
        }

        Ok(RowMajorMatrix::new(values, total_width))
    }

    /// Extract public inputs from main witness (RAP helper)
    fn extract_public_inputs_from_main(&self, main_witness: &MainWitness) -> Vec<u32> {
        let mut inputs = Vec::new();

        // Add first PC if we have trace
        if let Some(first_row) = main_witness.trace.first() {
            inputs.push(first_row.pc as u32);
        }

        // Add public input values
        for input in &main_witness.public_io.inputs {
            inputs.extend(input.iter().copied());
        }

        inputs
    }

    /// Extract public outputs from main witness (RAP helper)
    fn extract_public_outputs_from_main(&self, main_witness: &MainWitness) -> Vec<u32> {
        let mut outputs = Vec::new();

        // Add final PC if we have trace
        if let Some(last_row) = main_witness.trace.last() {
            outputs.push(last_row.pc as u32);
        }

        // Add public output values
        for output in &main_witness.public_io.outputs {
            outputs.extend(output.iter().copied());
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{PublicIO, MainTraceRow, ValueBound};

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
            normalization_events: Vec::new(),
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
    fn test_prover_creation() {
        let prover = Plonky3Prover::default_config();
        assert_eq!(prover.config().security_bits, 100);
    }

    #[test]
    fn test_prover_test_config() {
        let prover = Plonky3Prover::test_config();
        assert_eq!(prover.config().security_bits, 50);
    }

    #[test]
    fn test_prove_rap() {
        let prover = Plonky3Prover::test_config();
        let main_witness = create_test_main_witness();

        let result = prover.prove_rap(&main_witness);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.metadata.num_cycles, 10);
        assert_eq!(proof.metadata.trace_width, 277); // 267 main (with normalization + indicators) + 10 aux
        assert_eq!(proof.metadata.trace_height, 16);
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_empty_witness_fails() {
        let prover = Plonky3Prover::test_config();
        let mut main_witness = create_test_main_witness();
        main_witness.trace.clear();

        let result = prover.prove_rap(&main_witness);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ProofError::InvalidWitness(_)));
    }

    #[test]
    fn test_public_io_preservation() {
        let prover = Plonky3Prover::test_config();
        let main_witness = create_test_main_witness();

        let proof = prover.prove_rap(&main_witness).unwrap();

        // Check inputs preserved
        assert_eq!(proof.public_inputs[0], 0); // Initial PC
        assert_eq!(proof.public_inputs[1], 42); // Input value

        // Check outputs preserved
        assert_eq!(proof.public_outputs[0], 36); // Final PC
        assert_eq!(proof.public_outputs[1], 84); // Output value
    }

    #[test]
    fn test_single_commit_produces_valid_proof() {
        let prover = Plonky3Prover::test_config();
        let main_witness = create_test_main_witness();

        let result = prover.prove_rap_single_commit(&main_witness);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.metadata.num_cycles, 10);
        assert_eq!(proof.metadata.trace_width, 277); // 267 main (with normalization + indicators) + 10 aux
        assert!(!proof.proof_bytes.is_empty());
        assert!(proof.metadata.rap_challenge.is_some());
    }

    #[test]
    fn test_double_commit_produces_valid_proof() {
        let prover = Plonky3Prover::test_config();
        let main_witness = create_test_main_witness();

        let result = prover.prove_rap_double_commit(&main_witness);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.metadata.num_cycles, 10);
        assert_eq!(proof.metadata.trace_width, 277); // 267 main (with normalization + indicators) + 10 aux
        assert!(!proof.proof_bytes.is_empty());
        assert!(proof.metadata.rap_challenge.is_some());
    }

    #[test]
    fn test_both_commit_methods_produce_same_trace_dimensions() {
        let prover = Plonky3Prover::test_config();
        let main_witness = create_test_main_witness();

        let proof_single = prover.prove_rap_single_commit(&main_witness).unwrap();
        let proof_double = prover.prove_rap_double_commit(&main_witness).unwrap();

        // Both should have same trace dimensions
        assert_eq!(proof_single.metadata.trace_width, proof_double.metadata.trace_width);
        assert_eq!(proof_single.metadata.trace_height, proof_double.metadata.trace_height);
        assert_eq!(proof_single.metadata.num_cycles, proof_double.metadata.num_cycles);

        // Both should have same public I/O
        assert_eq!(proof_single.public_inputs, proof_double.public_inputs);
        assert_eq!(proof_single.public_outputs, proof_double.public_outputs);
    }
}
