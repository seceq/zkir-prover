//! Plonky3 STARK configuration
//!
//! This module defines the configuration parameters for the Plonky3 STARK backend,
//! including field choice, FRI parameters, and hash function selection.

use p3_mersenne_31::Mersenne31;
use crate::witness::ProgramConfig;

/// Our field type: Mersenne 31 (p = 2^31 - 1)
pub type Val = Mersenne31;

/// Re-export Mersenne 31 field prime from zkir-spec
pub use crate::types::MERSENNE31_PRIME;

/// Plonky3 STARK configuration
///
/// This structure holds all the configuration parameters needed for
/// proof generation and verification with Plonky3.
#[derive(Clone, Debug)]
pub struct StarkConfiguration {
    /// FRI blowup factor (log2 scale)
    /// 1 = 2x blowup, 2 = 4x blowup, etc.
    pub log_blowup: usize,

    /// Number of FRI queries (affects security level)
    pub num_queries: usize,

    /// Proof of work bits (optional additional security)
    pub pow_bits: usize,

    /// Security level in bits
    pub security_bits: usize,

    /// Program configuration (limb counts, etc.)
    pub program_config: ProgramConfig,
}

impl StarkConfiguration {
    /// Create a new STARK configuration
    ///
    /// # Arguments
    ///
    /// * `program_config` - Program-specific configuration (limbs, etc.)
    /// * `security_bits` - Desired security level (default: 100 bits)
    ///
    /// # Returns
    ///
    /// Returns a configured `StarkConfiguration` ready for proof generation.
    pub fn new(program_config: ProgramConfig, security_bits: usize) -> Self {
        Self {
            log_blowup: 1,  // 2x blowup factor
            num_queries: Self::compute_num_queries(security_bits),
            pow_bits: 16,    // 16-bit proof of work
            security_bits,
            program_config,
        }
    }

    /// Create a default configuration with standard security
    pub fn default_config() -> Self {
        Self::new(ProgramConfig::default(), 100)
    }

    /// Create a configuration for testing (lower security, faster)
    pub fn test_config() -> Self {
        Self::new(ProgramConfig::default(), 50)
    }

    /// Create a fast configuration for quick tests (minimal security, very fast)
    /// Use this for rapid iteration during development
    pub fn fast_test_config() -> Self {
        Self {
            log_blowup: 1,
            num_queries: 20,  // Minimal queries for speed
            pow_bits: 8,      // Reduced PoW
            security_bits: 20,
            program_config: ProgramConfig::default(),
        }
    }

    /// Compute the number of FRI queries needed for target security
    ///
    /// Formula: num_queries ≈ security_bits / log2(blowup_factor)
    /// For 2x blowup (log_blowup = 1), we need ~100 queries for 100-bit security
    fn compute_num_queries(security_bits: usize) -> usize {
        // Conservative estimate: 1 query per security bit with 2x blowup
        // This gives us a safety margin
        security_bits.max(20)  // Lowered minimum from 50 to 20 for fast tests
    }

    /// Get the trace width for this configuration
    pub fn trace_width(&self) -> usize {
        // Use ZkIrAir's calculation to ensure consistency
        // This avoids manual calculation drift as new columns are added
        use crate::constraints::air::ZkIrAir;
        let air = ZkIrAir::new(self.program_config.clone());
        air.num_columns
    }

    /// Get trace height (next power of 2 above cycle count)
    pub fn trace_height(&self, num_cycles: usize) -> usize {
        num_cycles.next_power_of_two()
    }

    /// Get blowup factor
    pub fn blowup_factor(&self) -> usize {
        1 << self.log_blowup
    }

    /// Get configuration summary as string
    pub fn summary(&self) -> String {
        format!(
            "Plonky3 STARK Config:\n\
             - Field: Mersenne 31 (p = 2^31 - 1)\n\
             - Security: {} bits\n\
             - FRI blowup: {}x (log = {})\n\
             - FRI queries: {}\n\
             - PoW bits: {}\n\
             - Hash: Poseidon2\n\
             - Trace width: {} columns\n\
             - Limbs: {} data, {} addr\n\
             - Limb bits: {}",
            self.security_bits,
            self.blowup_factor(),
            self.log_blowup,
            self.num_queries,
            self.pow_bits,
            self.trace_width(),
            self.program_config.data_limbs,
            self.program_config.addr_limbs,
            self.program_config.limb_bits
        )
    }
}

impl Default for StarkConfiguration {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_config_creation() {
        let config = StarkConfiguration::default_config();

        assert_eq!(config.security_bits, 100);
        assert_eq!(config.log_blowup, 1); // 2x blowup
        assert_eq!(config.blowup_factor(), 2);
        assert!(config.num_queries >= 50);
        assert_eq!(config.trace_width(), 257); // 247 main (with Option A imm limbs) + 10 aux
    }

    #[test]
    fn test_trace_width_scaling() {
        // 2-limb config
        let config2 = StarkConfiguration::new(
            ProgramConfig {
                limb_bits: 20,
                data_limbs: 2,
                addr_limbs: 2,
            },
            100,
        );
        assert_eq!(config2.trace_width(), 257); // 247 main (with Option A imm limbs) + 10 aux

        // 3-limb config
        let config3 = StarkConfiguration::new(
            ProgramConfig {
                limb_bits: 20,
                data_limbs: 3,
                addr_limbs: 3,
            },
            100,
        );
        assert_eq!(config3.trace_width(), 345); // 335 main (with Option A: 2 imm_limb + 2 add_trunc_carry for 3-limb) + 10 aux
    }

    #[test]
    fn test_trace_height_power_of_2() {
        let config = StarkConfiguration::default_config();

        assert_eq!(config.trace_height(100), 128);
        assert_eq!(config.trace_height(128), 128);
        assert_eq!(config.trace_height(129), 256);
        assert_eq!(config.trace_height(1000), 1024);
    }

    #[test]
    fn test_num_queries_calculation() {
        let config50 = StarkConfiguration::new(ProgramConfig::default(), 50);
        let config100 = StarkConfiguration::new(ProgramConfig::default(), 100);
        let config128 = StarkConfiguration::new(ProgramConfig::default(), 128);

        assert_eq!(config50.num_queries, 50);
        assert_eq!(config100.num_queries, 100);
        assert_eq!(config128.num_queries, 128);
    }

    #[test]
    fn test_mersenne_31_prime() {
        // MERSENNE31_PRIME is now imported from zkir-spec
        assert_eq!(MERSENNE31_PRIME, 2_147_483_647);
        assert_eq!(MERSENNE31_PRIME, ((1u64 << 31) - 1) as u32);
    }

    #[test]
    fn test_config_summary() {
        let config = StarkConfiguration::default_config();
        let summary = config.summary();

        assert!(summary.contains("Mersenne 31"));
        assert!(summary.contains("100 bits"));
        assert!(summary.contains("Poseidon2"));
        assert!(summary.contains("257 columns")); // 247 main (with Option A imm limbs) + 10 aux
    }

    #[test]
    fn test_blowup_factor() {
        let config = StarkConfiguration::default_config();
        assert_eq!(config.blowup_factor(), 2);

        let mut config2 = config.clone();
        config2.log_blowup = 2;
        assert_eq!(config2.blowup_factor(), 4);
    }
}
