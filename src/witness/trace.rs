//! Trace data structures for ZKIR v3.4 witness generation

use serde::{Deserialize, Serialize};
use super::multiplicity::LogUpMultiplicities;

/// Value bound information for optimization
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueBound {
    /// Maximum number of bits needed to represent this value
    pub max_bits: u32,
    /// Whether this is a tight bound (known exact) or conservative
    pub is_tight: bool,
}

impl ValueBound {
    /// Create a new bound
    pub fn new(max_bits: u32, is_tight: bool) -> Self {
        Self { max_bits, is_tight }
    }

    /// Create a tight bound for a known value
    pub fn tight(max_bits: u32) -> Self {
        Self {
            max_bits,
            is_tight: true,
        }
    }

    /// Create a conservative bound (default: full data width)
    pub fn conservative(max_bits: u32) -> Self {
        Self {
            max_bits,
            is_tight: false,
        }
    }

    /// Bound for constant zero
    pub fn zero() -> Self {
        Self::tight(0)
    }

    /// Bound for boolean values (0 or 1)
    pub fn boolean() -> Self {
        Self::tight(1)
    }

    /// Check if a range check is needed for this bound
    pub fn needs_range_check(&self, target_bits: u32) -> bool {
        self.max_bits > target_bits
    }
}

/// Main trace row (for RAP pattern - no auxiliary columns)
///
/// This represents the "main trace" in RAP (Randomized AIR with Preprocessing).
/// It contains all execution data but NO running products or LogUp sums.
/// Auxiliary columns (LogUp sums, memory permutation products) are computed
/// separately after deriving the Fiat-Shamir challenge from the main trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MainTraceRow {
    /// Cycle number
    pub cycle: u64,
    /// Program counter
    pub pc: u64,
    /// Encoded instruction (32-bit)
    pub instruction: u32,
    /// Register state (16 registers × limb values)
    /// For 40-bit config: each register is 2 limbs of 20 bits
    pub registers: Vec<Vec<u32>>,
    /// Bounds for each register value
    pub bounds: Vec<ValueBound>,
    /// Optional memory operation (raw data only, no permutation product)
    pub memory_op: Option<MemoryOp>,
}

impl MainTraceRow {
    /// Create a new main trace row
    pub fn new(
        cycle: u64,
        pc: u64,
        instruction: u32,
        registers: Vec<Vec<u32>>,
        bounds: Vec<ValueBound>,
    ) -> Self {
        Self {
            cycle,
            pc,
            instruction,
            registers,
            bounds,
            memory_op: None,
        }
    }
}


/// Memory operation record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryOp {
    /// Memory address (as limbs)
    pub address: Vec<u32>,
    /// Value read or written (as limbs)
    pub value: Vec<u32>,
    /// Timestamp (cycle number)
    pub timestamp: u64,
    /// Read (false) or write (true)
    pub is_write: bool,
    /// Bound on the value
    pub bound: ValueBound,
}

impl MemoryOp {
    /// Create a new memory operation
    pub fn new(
        address: Vec<u32>,
        value: Vec<u32>,
        timestamp: u64,
        is_write: bool,
        bound: ValueBound,
    ) -> Self {
        Self {
            address,
            value,
            timestamp,
            is_write,
            bound,
        }
    }
}

impl PartialEq for MemoryOp {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.timestamp == other.timestamp
    }
}

impl Eq for MemoryOp {}

impl Ord for MemoryOp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Sort by (address, timestamp) for memory consistency checking
        self.address
            .iter()
            .zip(&other.address)
            .find_map(|(a, b)| match a.cmp(b) {
                std::cmp::Ordering::Equal => None,
                ord => Some(ord),
            })
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(self.timestamp.cmp(&other.timestamp))
    }
}

impl PartialOrd for MemoryOp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Range check witness for a value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeCheckWitness {
    /// Cycle when range check was performed
    pub cycle: u64,
    /// Limb value being checked
    pub limb: u32,
    /// Chunk decomposition (2 chunks per limb)
    pub chunks: [u16; 2],
}

impl RangeCheckWitness {
    /// Create a new range check witness
    pub fn new(cycle: u64, limb: u32, chunk_bits: usize) -> Self {
        let mask = (1u32 << chunk_bits) - 1;
        let chunk0 = (limb & mask) as u16;
        let chunk1 = ((limb >> chunk_bits) & mask) as u16;

        Self {
            cycle,
            limb,
            chunks: [chunk0, chunk1],
        }
    }

    /// Verify the decomposition is correct
    pub fn verify(&self, chunk_bits: usize) -> bool {
        let reconstructed =
            (self.chunks[0] as u32) | ((self.chunks[1] as u32) << chunk_bits);
        reconstructed == self.limb
    }
}

/// Normalization witness for deferred carry model
///
/// Records normalization events where accumulated values are converted
/// to normalized form by extracting carries.
///
/// Verification constraint:
/// ```text
/// accumulated[i] = normalized[i] + carry[i] * 2^normalized_bits
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizationWitness {
    /// Cycle where normalization occurred
    pub cycle: u64,
    /// Register that was normalized (0-15)
    pub register: u8,
    /// Accumulated limbs before normalization [limb0, limb1]
    pub accumulated: [u64; 2],
    /// Normalized limbs after normalization [limb0, limb1]
    pub normalized: [u32; 2],
    /// Carries extracted [carry0, carry1]
    pub carries: [u32; 2],
}

/// Cryptographic syscall witness
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoWitness {
    /// Cycle when syscall was invoked
    pub cycle: u64,
    /// Syscall type (SHA256, Poseidon2, etc.)
    pub syscall_type: CryptoType,
    /// Input data
    pub inputs: Vec<u8>,
    /// Output data (in limb representation)
    pub outputs: Vec<Vec<u32>>,
    /// Bounds on output values
    pub output_bounds: Vec<ValueBound>,
}

/// Cryptographic syscall types
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoType {
    /// SHA-256 (32-bit operations, outputs 32-bit values)
    Sha256,
    /// Poseidon2 (31-bit operations)
    Poseidon2,
    /// Keccak-256 (64-bit operations)
    Keccak256,
    /// Blake3 (32-bit operations)
    Blake3,
}

impl CryptoType {
    /// Algorithm bit width (semantic width required by the algorithm)
    pub fn algorithm_bits(&self) -> u32 {
        match self {
            CryptoType::Sha256 => 32,
            CryptoType::Blake3 => 32,
            CryptoType::Poseidon2 => 31,
            CryptoType::Keccak256 => 64,
        }
    }

    /// Minimum internal representation to avoid intermediate range checks
    pub fn min_internal_bits(&self) -> u32 {
        match self {
            CryptoType::Sha256 => 44,    // 12 bits headroom for 320 adds
            CryptoType::Blake3 => 44,    // 12 bits headroom for 400 adds
            CryptoType::Poseidon2 => 40, // 9 bits headroom for 200 adds
            CryptoType::Keccak256 => 80, // 16 bits headroom for XOR-heavy ops
        }
    }

    /// Calculate internal bits for this crypto operation given program config
    pub fn internal_bits(&self, program_bits: u32) -> u32 {
        self.min_internal_bits().max(program_bits)
    }

    /// Check if range check is needed after crypto output
    pub fn needs_range_check_after_output(&self, program_bits: u32) -> bool {
        self.algorithm_bits() > program_bits
    }

    /// Calculate headroom available after crypto output
    pub fn post_crypto_headroom(&self, program_bits: u32) -> u32 {
        program_bits.saturating_sub(self.algorithm_bits())
    }
}

/// Public inputs and outputs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicIO {
    /// Program hash
    pub program_hash: [u8; 32],
    /// Public input values
    pub inputs: Vec<Vec<u32>>,
    /// Public output values
    pub outputs: Vec<Vec<u32>>,
}

/// Main witness (for RAP pattern - no auxiliary data)
///
/// This represents the "main witness" in RAP (Randomized AIR with Preprocessing).
/// It contains all execution data needed to compute the main trace, but NO
/// auxiliary columns (LogUp sums, memory permutation products).
///
/// The auxiliary witness is computed separately using `compute_auxiliary()`
/// after deriving the Fiat-Shamir challenge from the committed main trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MainWitness {
    /// Core execution trace (main columns only)
    pub trace: Vec<MainTraceRow>,
    /// Total cycle count
    pub cycle_count: u64,
    /// Memory operations (unsorted, for auxiliary computation)
    pub memory_ops: Vec<MemoryOp>,
    /// Range check witnesses
    pub range_checks: Vec<RangeCheckWitness>,
    /// Cryptographic syscall witnesses
    pub crypto_ops: Vec<CryptoWitness>,
    /// Normalization events for deferred carry model
    pub normalization_events: Vec<NormalizationWitness>,
    /// Public inputs and outputs
    pub public_io: PublicIO,
    /// Program configuration
    pub config: ProgramConfig,
    /// LogUp multiplicity tracking (for auxiliary computation)
    #[serde(skip)]
    pub multiplicities: LogUpMultiplicities,
}

impl MainWitness {
    /// Create a new main witness builder
    pub fn builder(config: ProgramConfig, program_hash: [u8; 32]) -> MainWitnessBuilder {
        MainWitnessBuilder::new(config, program_hash)
    }
}


/// ZKIR v3.4 program configuration
///
/// Uses the 30+30 limb architecture for efficient deferred range checks:
/// - Each limb can STORE up to 30 bits (for accumulation during deferred ops)
/// - Normalized values are 20 bits per limb (canonical form)
/// - 10-bit structural headroom allows 1024 deferred ADD/SUB without tracking
/// - Uniform 10-bit chunk decomposition for all range checks
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramConfig {
    /// Limb storage capacity in bits (30 for 30+30 architecture)
    pub limb_bits: u8,
    /// Normalized value bits per limb (20 for 30+30 architecture)
    pub normalized_bits: u8,
    /// Number of limbs for data values (1-4)
    pub data_limbs: u8,
    /// Number of limbs for addresses (1-2)
    pub addr_limbs: u8,
}

impl ProgramConfig {
    /// Default configuration: 30+30 architecture (30-bit storage, 20-bit normalized)
    ///
    /// This enables:
    /// - 1024 deferred ADD/SUB operations without tracking
    /// - Uniform 10-bit lookup tables for all range checks
    /// - 33% fewer constraints per ADD vs immediate-carry design
    pub const DEFAULT: Self = Self {
        limb_bits: 30,
        normalized_bits: 20,
        data_limbs: 2,
        addr_limbs: 2,
    };

    /// Create a new configuration with custom parameters
    pub fn new(limb_bits: u8, normalized_bits: u8, data_limbs: u8, addr_limbs: u8) -> Result<Self, ConfigError> {
        let config = Self {
            limb_bits,
            normalized_bits,
            data_limbs,
            addr_limbs,
        };
        config.validate()?;
        Ok(config)
    }

    /// Create a 30+30 configuration (recommended default)
    pub fn new_30_30() -> Self {
        Self::DEFAULT
    }

    /// Total data bits (using normalized value size)
    pub fn data_bits(&self) -> u32 {
        self.normalized_bits as u32 * self.data_limbs as u32
    }

    /// Total address bits (using normalized value size)
    pub fn addr_bits(&self) -> u32 {
        self.normalized_bits as u32 * self.addr_limbs as u32
    }

    /// Chunk size for range checks (normalized_bits / 2)
    /// Always 10 bits for 30+30 architecture (uniform lookup tables)
    pub fn chunk_bits(&self) -> u32 {
        self.normalized_bits as u32 / 2
    }

    /// Structural headroom bits per limb (limb_bits - normalized_bits)
    /// For 30+30: 30 - 20 = 10 bits of headroom
    pub fn structural_headroom(&self) -> u32 {
        (self.limb_bits - self.normalized_bits) as u32
    }

    /// Maximum deferred ADD/SUB operations without normalization
    /// For 30+30: 2^10 = 1024 operations
    pub fn max_deferred_ops(&self) -> u32 {
        1u32 << self.structural_headroom()
    }

    /// Maximum limb value during accumulation (2^limb_bits - 1)
    pub fn limb_max(&self) -> u32 {
        (1u32 << self.limb_bits) - 1
    }

    /// Maximum normalized value per limb (2^normalized_bits - 1)
    pub fn normalized_max(&self) -> u32 {
        (1u32 << self.normalized_bits) - 1
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Limb storage must be in range
        if self.limb_bits < 16 || self.limb_bits > 30 {
            return Err(ConfigError::InvalidLimbBits(self.limb_bits));
        }

        // Normalized bits must be even (for symmetric chunk decomposition)
        if self.normalized_bits % 2 != 0 {
            return Err(ConfigError::OddLimbBits(self.normalized_bits));
        }

        // Normalized bits must be <= limb_bits (can't store more than capacity)
        if self.normalized_bits > self.limb_bits {
            return Err(ConfigError::InvalidLimbBits(self.normalized_bits));
        }

        // Normalized bits must be >= 16 for reasonable value range
        if self.normalized_bits < 16 {
            return Err(ConfigError::InvalidLimbBits(self.normalized_bits));
        }

        // Data limbs: 1-4
        if self.data_limbs < 1 || self.data_limbs > 4 {
            return Err(ConfigError::InvalidDataLimbs(self.data_limbs));
        }

        // Address limbs: 1-2
        if self.addr_limbs < 1 || self.addr_limbs > 2 {
            return Err(ConfigError::InvalidAddrLimbs(self.addr_limbs));
        }

        Ok(())
    }
}

impl Default for ProgramConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Configuration validation errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid limb bits {0}, must be 16-30")]
    InvalidLimbBits(u8),

    #[error("Limb bits {0} must be even")]
    OddLimbBits(u8),

    #[error("Invalid data limbs {0}, must be 1-4")]
    InvalidDataLimbs(u8),

    #[error("Invalid address limbs {0}, must be 1-2")]
    InvalidAddrLimbs(u8),
}


/// Builder for constructing MainWitness incrementally
pub struct MainWitnessBuilder {
    config: ProgramConfig,
    program_hash: [u8; 32],
    trace: Vec<MainTraceRow>,
    memory_ops: Vec<MemoryOp>,
    range_checks: Vec<RangeCheckWitness>,
    crypto_ops: Vec<CryptoWitness>,
    normalization_events: Vec<NormalizationWitness>,
    inputs: Vec<Vec<u32>>,
    outputs: Vec<Vec<u32>>,
    multiplicities: LogUpMultiplicities,
    explicit_cycle_count: Option<u64>,
}

impl MainWitnessBuilder {
    /// Create a new builder
    pub fn new(config: ProgramConfig, program_hash: [u8; 32]) -> Self {
        Self {
            config,
            program_hash,
            trace: Vec::new(),
            memory_ops: Vec::new(),
            range_checks: Vec::new(),
            crypto_ops: Vec::new(),
            normalization_events: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            multiplicities: LogUpMultiplicities::new(),
            explicit_cycle_count: None,
        }
    }

    /// Add a main trace row
    pub fn add_trace_row(&mut self, row: MainTraceRow) {
        self.trace.push(row);
    }

    /// Add a memory operation
    pub fn add_memory_op(&mut self, op: MemoryOp) {
        self.memory_ops.push(op);
    }

    /// Add a range check
    pub fn add_range_check(&mut self, check: RangeCheckWitness) {
        self.range_checks.push(check);
    }

    /// Add a crypto operation
    pub fn add_crypto_op(&mut self, op: CryptoWitness) {
        self.crypto_ops.push(op);
    }

    /// Add a normalization event
    pub fn add_normalization(&mut self, event: NormalizationWitness) {
        self.normalization_events.push(event);
    }

    /// Set public inputs
    pub fn set_inputs(&mut self, inputs: Vec<Vec<u32>>) {
        self.inputs = inputs;
    }

    /// Set public outputs
    pub fn set_outputs(&mut self, outputs: Vec<Vec<u32>>) {
        self.outputs = outputs;
    }

    /// Get mutable reference to multiplicities for tracking
    pub fn multiplicities_mut(&mut self) -> &mut LogUpMultiplicities {
        &mut self.multiplicities
    }

    /// Set the cycle count explicitly
    pub fn set_cycle_count(&mut self, cycle_count: u64) {
        self.explicit_cycle_count = Some(cycle_count);
    }

    /// Build the final main witness
    pub fn build(self) -> MainWitness {
        let cycle_count = self.explicit_cycle_count
            .unwrap_or_else(|| self.trace.last().map(|r| r.cycle + 1).unwrap_or(0));

        MainWitness {
            trace: self.trace,
            cycle_count,
            memory_ops: self.memory_ops,
            range_checks: self.range_checks,
            crypto_ops: self.crypto_ops,
            normalization_events: self.normalization_events,
            public_io: PublicIO {
                program_hash: self.program_hash,
                inputs: self.inputs,
                outputs: self.outputs,
            },
            config: self.config,
            multiplicities: self.multiplicities,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_config_default() {
        // 30+30 architecture: 30-bit storage, 20-bit normalized
        let config = ProgramConfig::DEFAULT;
        assert_eq!(config.limb_bits, 30);
        assert_eq!(config.normalized_bits, 20);
        assert_eq!(config.data_limbs, 2);
        assert_eq!(config.addr_limbs, 2);
        assert_eq!(config.data_bits(), 40);  // 20 * 2 = 40 bits of value
        assert_eq!(config.addr_bits(), 40);  // 20 * 2 = 40 bits of address
        assert_eq!(config.chunk_bits(), 10); // 20 / 2 = 10-bit chunks
        assert_eq!(config.structural_headroom(), 10); // 30 - 20 = 10 bits
        assert_eq!(config.max_deferred_ops(), 1024);  // 2^10 = 1024 ops
    }

    #[test]
    fn test_program_config_validation() {
        // Valid configs: new(limb_bits, normalized_bits, data_limbs, addr_limbs)
        assert!(ProgramConfig::new(30, 20, 2, 2).is_ok()); // 30+30 default
        assert!(ProgramConfig::new(20, 20, 2, 2).is_ok()); // legacy 20+20
        assert!(ProgramConfig::new(24, 20, 2, 2).is_ok()); // custom headroom
        assert!(ProgramConfig::new(30, 20, 4, 2).is_ok()); // more data limbs

        // Invalid limb_bits (must be 16-30)
        assert!(ProgramConfig::new(14, 14, 2, 2).is_err());
        assert!(ProgramConfig::new(32, 20, 2, 2).is_err());

        // Invalid normalized_bits (must be even)
        assert!(ProgramConfig::new(30, 19, 2, 2).is_err()); // odd

        // Invalid: normalized > limb (can't store more than capacity)
        assert!(ProgramConfig::new(20, 24, 2, 2).is_err());

        // Invalid data/addr limbs
        assert!(ProgramConfig::new(30, 20, 0, 2).is_err());
        assert!(ProgramConfig::new(30, 20, 5, 2).is_err());
        assert!(ProgramConfig::new(30, 20, 2, 0).is_err());
        assert!(ProgramConfig::new(30, 20, 2, 3).is_err());
    }

    #[test]
    fn test_range_check_witness() {
        let witness = RangeCheckWitness::new(0, 0x12345, 10);
        assert_eq!(witness.limb, 0x12345);
        assert_eq!(witness.chunks[0], 0x345); // low 10 bits
        assert_eq!(witness.chunks[1], 0x048); // next 10 bits
        assert!(witness.verify(10));
    }

    #[test]
    fn test_value_bound() {
        let bound = ValueBound::tight(32);
        assert!(bound.is_tight);
        assert_eq!(bound.max_bits, 32);
        assert!(!bound.needs_range_check(40));
        assert!(bound.needs_range_check(30));

        let bool_bound = ValueBound::boolean();
        assert_eq!(bool_bound.max_bits, 1);
        assert!(bool_bound.is_tight);
    }

    #[test]
    fn test_crypto_type_bounds() {
        let sha256 = CryptoType::Sha256;
        assert_eq!(sha256.algorithm_bits(), 32);
        assert_eq!(sha256.min_internal_bits(), 44);
        assert_eq!(sha256.internal_bits(40), 44); // uses min
        assert_eq!(sha256.internal_bits(60), 60); // uses program
        assert!(!sha256.needs_range_check_after_output(40)); // 32 <= 40
        assert!(sha256.needs_range_check_after_output(30)); // 32 > 30
        assert_eq!(sha256.post_crypto_headroom(40), 8); // 40 - 32
    }

    #[test]
    fn test_witness_builder() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [0u8; 32];

        let mut builder = MainWitnessBuilder::new(config, program_hash);

        let row = MainTraceRow::new(
            0,
            0,
            0x12345678,
            vec![vec![0, 0]; 16],
            vec![ValueBound::zero(); 16],
        );
        builder.add_trace_row(row);

        builder.set_inputs(vec![vec![1, 2]]);
        builder.set_outputs(vec![vec![3, 4]]);

        let witness = builder.build();
        assert_eq!(witness.trace.len(), 1);
        assert_eq!(witness.public_io.inputs.len(), 1);
        assert_eq!(witness.public_io.outputs.len(), 1);
    }

    #[test]
    fn test_memory_op_ordering() {
        let op1 = MemoryOp::new(vec![0, 0], vec![1], 0, false, ValueBound::tight(32));
        let op2 = MemoryOp::new(vec![0, 0], vec![2], 1, false, ValueBound::tight(32));
        let op3 = MemoryOp::new(vec![0, 1], vec![3], 0, false, ValueBound::tight(32));

        assert!(op1 < op2); // same address, earlier timestamp
        assert!(op1 < op3); // earlier address
        assert!(op2 < op3); // earlier address (despite later timestamp)
    }

    #[test]
    fn test_witness_serialization() {
        let config = ProgramConfig::DEFAULT;
        let program_hash = [1u8; 32];
        let witness = MainWitness::builder(config, program_hash).build();

        // Test round-trip
        let serialized = bincode::serialize(&witness).unwrap();
        let deserialized: MainWitness = bincode::deserialize(&serialized).unwrap();

        assert_eq!(witness.config.limb_bits, deserialized.config.limb_bits);
        assert_eq!(witness.public_io.program_hash, deserialized.public_io.program_hash);
    }
}
