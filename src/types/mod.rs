//! Unified type exports from zkir-spec and prover-specific types
//!
//! This module provides a single point of import for all types used in the prover.
//! Types from zkir-spec are re-exported here as the single source of truth.
//!
//! # Usage
//!
//! ```ignore
//! use zkir_prover::types::{Config, Opcode, CryptoType, NUM_REGISTERS};
//! ```

// ============================================================================
// Re-exports from zkir-spec (single source of truth)
// ============================================================================

// Configuration
pub use zkir_spec::{Config, ConfigError};

// Registers
pub use zkir_spec::{Register, NUM_REGISTERS};

// Instructions and opcodes
pub use zkir_spec::{Instruction, Opcode, InstructionFamily};

// Field arithmetic
pub use zkir_spec::{Mersenne31, MERSENNE31_PRIME};

// Bounds and crypto
pub use zkir_spec::{BoundSource, CryptoType, ValueBound};

// Program format
pub use zkir_spec::{Program, ProgramHeader, MAGIC, VERSION};

// Memory layout
pub use zkir_spec::memory::{
    CODE_BASE, CODE_SIZE, DATA_BASE, DATA_SIZE, DEFAULT_HEAP_SIZE, DEFAULT_STACK_SIZE, HEAP_BASE,
    RESERVED_BASE, RESERVED_SIZE, STACK_TOP,
};

// Instruction size
pub use zkir_spec::INSTRUCTION_SIZE;

// Instruction encoding helpers
pub use zkir_spec::encoding::{
    // Bit position constants
    OPCODE_SHIFT, RD_SHIFT, RS1_SHIFT, RS2_SHIFT, IMM_SHIFT, FUNCT_SHIFT, OFFSET_SHIFT,
    // Field masks
    OPCODE_MASK, REGISTER_MASK, IMM_MASK, FUNCT_MASK, OFFSET_MASK,
    // Sign extension
    IMM_SIGN_BIT, IMM_SIGN_EXTEND,
    // Extraction functions
    extract_opcode, extract_rd, extract_rs1, extract_rs2, extract_imm, extract_imm_signed,
    extract_funct, extract_offset, extract_offset_signed,
    // S-type/B-type specific
    extract_stype_rs1, extract_stype_rs2, extract_stype_imm,
    // Encoding functions
    encode_rtype, encode_itype, encode_stype, encode_btype, encode_jtype,
    // Type detection
    is_stype, is_btype, is_jtype, is_itype, is_rtype,
};

// ============================================================================
// Type aliases for backward compatibility
// ============================================================================

/// Alias for Config (was ProgramConfig in prover)
///
/// This alias maintains backward compatibility with code that used `ProgramConfig`.
/// New code should prefer using `Config` directly.
pub type ProgramConfig = Config;

// ============================================================================
// Prover-specific types
// ============================================================================

/// Prover configuration options (not in zkir-spec)
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// Security level in bits (default: 100)
    pub security_bits: usize,

    /// FRI blowup factor log2 (default: 1 for 2x blowup)
    pub log_blowup: usize,

    /// Number of FRI queries (computed from security_bits)
    pub num_queries: usize,

    /// Proof of work bits (default: 16)
    pub pow_bits: usize,

    /// Enable debug output
    pub debug: bool,

    /// Enable profiling
    pub profile: bool,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            security_bits: 100,
            log_blowup: 1,
            num_queries: 100,
            pow_bits: 16,
            debug: false,
            profile: false,
        }
    }
}

impl ProverConfig {
    /// Create a new prover configuration with specified security level
    pub fn with_security(security_bits: usize) -> Self {
        Self {
            security_bits,
            num_queries: security_bits.max(20),
            ..Default::default()
        }
    }

    /// Create a fast test configuration (low security, quick proofs)
    pub fn fast_test() -> Self {
        Self {
            security_bits: 20,
            log_blowup: 1,
            num_queries: 20,
            pow_bits: 8,
            debug: false,
            profile: false,
        }
    }

    /// Get blowup factor
    pub fn blowup_factor(&self) -> usize {
        1 << self.log_blowup
    }
}

// ============================================================================
// Column layout constants
// ============================================================================

/// Constants for column layout in the trace
pub mod columns {
    use super::NUM_REGISTERS;

    // Core columns
    pub const PC_COLUMNS: usize = 1;
    pub const INSTRUCTION_COLUMNS: usize = 1;

    // Register bounds (one per register)
    pub const REGISTER_BOUND_COLUMNS: usize = NUM_REGISTERS;

    // Memory flags
    pub const MEMORY_FLAG_COLUMNS: usize = 2; // is_write, is_read

    // Instruction decode columns
    pub const OPCODE_COLUMN: usize = 1;
    pub const REGISTER_FIELD_COLUMNS: usize = 3; // rd, rs1, rs2
    pub const IMM_FUNCT_COLUMN: usize = 1;
    pub const IS_IMM_COLUMN: usize = 1;
    pub const IMM_SIGN_COLUMN: usize = 1;

    pub const INSTRUCTION_DECODE_COLUMNS: usize =
        OPCODE_COLUMN + REGISTER_FIELD_COLUMNS + IMM_FUNCT_COLUMN + IS_IMM_COLUMN + IMM_SIGN_COLUMN;

    // Family selector columns
    pub const FAMILY_SELECTOR_COLUMNS: usize = 10;

    // Opcode indicator columns by family
    pub const BITWISE_INDICATOR_COLUMNS: usize = 7; // AND,OR,XOR,NOT,ANDI,ORI,XORI
    pub const LOAD_INDICATOR_COLUMNS: usize = 6; // LB,LBU,LH,LHU,LW,LD
    pub const STORE_INDICATOR_COLUMNS: usize = 4; // SB,SH,SW,SD
    pub const ARITHMETIC_INDICATOR_COLUMNS: usize = 8; // ADD,SUB,MUL,ADDI,SUBI,MULI,DIV,REM
    pub const SHIFT_INDICATOR_COLUMNS: usize = 6; // SLL,SRL,SRA,SLLI,SRLI,SRAI
    pub const CMOV_INDICATOR_COLUMNS: usize = 3; // CMOV,CMOVZ,CMOVNZ
    pub const COMPARE_INDICATOR_COLUMNS: usize = 4; // SLT,SLTU,SEQ,SNE

    pub const TOTAL_OPCODE_INDICATORS: usize = BITWISE_INDICATOR_COLUMNS
        + LOAD_INDICATOR_COLUMNS
        + STORE_INDICATOR_COLUMNS
        + ARITHMETIC_INDICATOR_COLUMNS
        + SHIFT_INDICATOR_COLUMNS
        + CMOV_INDICATOR_COLUMNS
        + COMPARE_INDICATOR_COLUMNS;

    // Register indicator columns (for dynamic register selection)
    pub const REGISTER_INDICATOR_COLUMNS: usize = NUM_REGISTERS * 3; // 48 (rd + rs1 + rs2)

    // Auxiliary trace columns
    pub const MEMORY_PERM_COLUMNS: usize = 2; // exec + sorted order
    pub const LOGUP_QUERY_COLUMNS: usize = 4; // AND, OR, XOR, range
    pub const LOGUP_TABLE_COLUMNS: usize = 4; // AND, OR, XOR, range

    pub const TOTAL_AUX_COLUMNS: usize =
        MEMORY_PERM_COLUMNS + LOGUP_QUERY_COLUMNS + LOGUP_TABLE_COLUMNS;

    // Config-dependent column counts

    /// Register value columns (16 registers * data_limbs)
    #[inline]
    pub const fn register_value_columns(data_limbs: usize) -> usize {
        NUM_REGISTERS * data_limbs
    }

    /// Memory address columns
    #[inline]
    pub const fn memory_addr_columns(addr_limbs: usize) -> usize {
        addr_limbs
    }

    /// Memory value columns
    #[inline]
    pub const fn memory_value_columns(data_limbs: usize) -> usize {
        data_limbs
    }

    /// Division quotient columns
    #[inline]
    pub const fn div_quotient_columns(data_limbs: usize) -> usize {
        data_limbs
    }

    /// Division remainder columns
    #[inline]
    pub const fn div_remainder_columns(data_limbs: usize) -> usize {
        data_limbs
    }

    /// Comparison less-than flag columns
    #[inline]
    pub const fn cmp_lt_flag_columns(data_limbs: usize) -> usize {
        data_limbs
    }

    /// Comparison equality flag columns
    #[inline]
    pub const fn cmp_eq_flag_columns(data_limbs: usize) -> usize {
        data_limbs
    }

    /// Shift carry columns (data_limbs - 1)
    #[inline]
    pub const fn shift_carry_columns(data_limbs: usize) -> usize {
        if data_limbs > 1 {
            data_limbs - 1
        } else {
            0
        }
    }

    /// Bitwise chunk columns (6 chunks per limb for rs1, rs2, rd decomposition)
    #[inline]
    pub const fn bitwise_chunk_columns(data_limbs: usize) -> usize {
        6 * data_limbs
    }

    /// Range check chunk columns (2 chunks per limb)
    #[inline]
    pub const fn range_chunk_columns(data_limbs: usize) -> usize {
        2 * data_limbs
    }

    /// Branch condition column
    pub const BRANCH_CONDITION_COLUMN: usize = 1;

    /// Zero detection flag column (for CMOVZ/CMOVNZ)
    pub const ZERO_FLAG_COLUMN: usize = 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_alias() {
        let config: ProgramConfig = Config::DEFAULT;
        assert_eq!(config.limb_bits, 20);
        assert_eq!(config.data_limbs, 2);
    }

    #[test]
    fn test_prover_config_default() {
        let config = ProverConfig::default();
        assert_eq!(config.security_bits, 100);
        assert_eq!(config.blowup_factor(), 2);
    }

    #[test]
    fn test_prover_config_fast() {
        let config = ProverConfig::fast_test();
        assert_eq!(config.security_bits, 20);
        assert_eq!(config.num_queries, 20);
    }

    #[test]
    fn test_column_constants() {
        use columns::*;

        assert_eq!(FAMILY_SELECTOR_COLUMNS, 10);
        assert_eq!(REGISTER_INDICATOR_COLUMNS, 48);
        assert_eq!(TOTAL_AUX_COLUMNS, 10);

        // With default config (2 data limbs)
        assert_eq!(register_value_columns(2), 32);
        assert_eq!(bitwise_chunk_columns(2), 12);
        assert_eq!(range_chunk_columns(2), 4);
    }

    #[test]
    fn test_opcode_from_spec() {
        // Verify we can use Opcode from zkir-spec
        assert_eq!(Opcode::Add.to_u8(), 0x00);
        assert_eq!(Opcode::And.to_u8(), 0x10);
        assert!(Opcode::Add.is_arithmetic());
        assert!(Opcode::And.is_logical());
    }

    #[test]
    fn test_instruction_family() {
        assert_eq!(InstructionFamily::COUNT, 10);
        assert_eq!(Opcode::Add.family(), InstructionFamily::Arithmetic);
    }
}
