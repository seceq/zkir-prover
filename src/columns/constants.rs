//! Named constants for column group sizes
//!
//! These constants replace magic numbers throughout the codebase, making the
//! column layout self-documenting and easier to maintain.

use crate::types::NUM_REGISTERS;

// ============================================================================
// Core Columns
// ============================================================================

/// Program counter column (1 column)
pub const PC_COLUMNS: usize = 1;

/// Instruction word column (1 column)
pub const INSTRUCTION_COLUMNS: usize = 1;

/// Core columns total (PC + instruction)
pub const CORE_COLUMNS: usize = PC_COLUMNS + INSTRUCTION_COLUMNS;

// ============================================================================
// Register Columns
// ============================================================================

/// Number of registers (from zkir-spec)
pub const REGISTER_COUNT: usize = NUM_REGISTERS;

/// Register bound columns (one per register, storing max_bits)
pub const REGISTER_BOUND_COLUMNS: usize = REGISTER_COUNT;

/// Register value columns (depends on data_limbs)
#[inline]
pub const fn register_value_columns(data_limbs: usize) -> usize {
    REGISTER_COUNT * data_limbs
}

// ============================================================================
// Memory Columns
// ============================================================================

/// Memory flag columns (is_write, is_read)
pub const MEMORY_FLAG_COLUMNS: usize = 2;

/// Memory address columns (depends on addr_limbs)
#[inline]
pub const fn memory_addr_columns(addr_limbs: usize) -> usize {
    addr_limbs
}

/// Memory value columns (depends on data_limbs)
#[inline]
pub const fn memory_value_columns(data_limbs: usize) -> usize {
    data_limbs
}

// ============================================================================
// Instruction Decode Columns
// ============================================================================

/// Decoded opcode column
pub const OPCODE_COLUMN: usize = 1;

/// Register field columns (rd, rs1, rs2)
pub const REGISTER_FIELD_COLUMNS: usize = 3;

/// Immediate/function field column
pub const IMM_FUNCT_COLUMN: usize = 1;

/// Is-immediate flag column
pub const IS_IMM_COLUMN: usize = 1;

/// Immediate sign bit column
pub const IMM_SIGN_COLUMN: usize = 1;

/// Total instruction decode columns
pub const INSTRUCTION_DECODE_COLUMNS: usize = OPCODE_COLUMN
    + REGISTER_FIELD_COLUMNS
    + IMM_FUNCT_COLUMN
    + IS_IMM_COLUMN
    + IMM_SIGN_COLUMN;

// ============================================================================
// Instruction Family Selector Columns
// ============================================================================

/// Number of instruction families
/// Arithmetic, Logical, Shift, Compare, Cmov, Load, Store, Branch, Jump, System
pub const INSTRUCTION_FAMILY_COUNT: usize = 10;

/// Family selector columns (one boolean per family)
pub const FAMILY_SELECTOR_COLUMNS: usize = INSTRUCTION_FAMILY_COUNT;

// ============================================================================
// Opcode Indicator Columns (Boolean flags per instruction within family)
// ============================================================================

/// Bitwise operation indicators: AND, OR, XOR, NOT, ANDI, ORI, XORI
pub const BITWISE_INDICATOR_COLUMNS: usize = 7;

/// Load operation indicators: LB, LBU, LH, LHU, LW, LD
pub const LOAD_INDICATOR_COLUMNS: usize = 6;

/// Store operation indicators: SB, SH, SW, SD
pub const STORE_INDICATOR_COLUMNS: usize = 4;

/// Arithmetic operation indicators: ADD, SUB, MUL, ADDI, SUBI, MULI, DIV, REM
pub const ARITHMETIC_INDICATOR_COLUMNS: usize = 8;

/// Shift operation indicators: SLL, SRL, SRA, SLLI, SRLI, SRAI
pub const SHIFT_INDICATOR_COLUMNS: usize = 6;

/// Conditional move indicators: CMOV, CMOVZ, CMOVNZ
pub const CMOV_INDICATOR_COLUMNS: usize = 3;

/// Comparison indicators: SLT, SLTU, SEQ, SNE
pub const COMPARE_INDICATOR_COLUMNS: usize = 4;

/// Total opcode indicator columns across all families
pub const TOTAL_OPCODE_INDICATORS: usize = BITWISE_INDICATOR_COLUMNS
    + LOAD_INDICATOR_COLUMNS
    + STORE_INDICATOR_COLUMNS
    + ARITHMETIC_INDICATOR_COLUMNS
    + SHIFT_INDICATOR_COLUMNS
    + CMOV_INDICATOR_COLUMNS
    + COMPARE_INDICATOR_COLUMNS;

// ============================================================================
// Register Indicator Columns (for dynamic register selection)
// ============================================================================

/// Register indicator columns per register field (rd, rs1, rs2)
/// Each field has NUM_REGISTERS boolean indicators
pub const INDICATORS_PER_FIELD: usize = REGISTER_COUNT;

/// Number of register fields (rd, rs1, rs2)
pub const REGISTER_FIELDS: usize = 3;

/// Total register indicator columns: 16 * 3 = 48
pub const REGISTER_INDICATOR_COLUMNS: usize = INDICATORS_PER_FIELD * REGISTER_FIELDS;

// ============================================================================
// Complex Operation Auxiliary Columns
// ============================================================================

/// DIV/REM quotient columns (depends on data_limbs)
#[inline]
pub const fn div_quotient_columns(data_limbs: usize) -> usize {
    data_limbs
}

/// DIV/REM remainder columns (depends on data_limbs)
#[inline]
pub const fn div_remainder_columns(data_limbs: usize) -> usize {
    data_limbs
}

// ============================================================================
// MUL Hierarchical Decomposition Columns
// ============================================================================
//
// For 2-limb (40-bit) MUL verification with 10-bit chunks:
// - Each 20-bit limb decomposes into 2 × 10-bit chunks
// - rs1 = (a0, a1) for limb0, (a2, a3) for limb1
// - rs2 = (b0, b1) for limb0, (b2, b3) for limb1
// - Partial products aᵢ×bⱼ = 20-bit, decomposed into (lo, hi) 10-bit each
// - Position carries have varying sizes: 10, 11, 12, 13 bits
//
// Column layout for 2-limb config:
// - Operand chunks: 4 chunks for rs1 + 4 chunks for rs2 = 8 columns
// - Partial product (lo, hi) pairs: depends on which products needed
// - Carry decomposition: uses hierarchical (10 + 2 + 1) pattern

/// Operand chunk columns for MUL
/// For 2-limb: rs1 has 4 chunks (2 per limb), rs2 has 4 chunks = 8 total
#[inline]
pub const fn mul_operand_chunk_columns(data_limbs: usize) -> usize {
    // 2 chunks per limb, 2 operands
    data_limbs * 2 * 2
}

/// Number of partial products for MUL
/// For chunk-based multiplication with 10-bit chunks:
/// - Each limb decomposes into 2 chunks (a0, a1 for limb 0, a2, a3 for limb 1)
/// - For 2-limb config: 4 chunks × 4 chunks = 16 partial products
/// - Each product a_i × b_j (10×10 = 20 bits) decomposes into lo, hi (10 bits each)
#[inline]
pub const fn mul_partial_product_count(data_limbs: usize) -> usize {
    // num_chunks = data_limbs * 2
    // total products = num_chunks^2 = (data_limbs * 2)^2
    let num_chunks = data_limbs * 2;
    num_chunks * num_chunks
}

/// Partial product decomposition columns (lo, hi for each product)
#[inline]
pub const fn mul_partial_product_columns(data_limbs: usize) -> usize {
    mul_partial_product_count(data_limbs) * 2
}

/// MUL position carry columns with hierarchical decomposition
/// Position carries grow with each position due to accumulation:
/// - Position 0: max 1 product → max carry ~10 bits
/// - Position 1: max 2 products + carry → max carry ~11 bits
/// - Position 2: max 3 products + carry → max carry ~12 bits
/// - Position 3: max 4 products + carry → max carry ~13 bits
/// Using hierarchical decomposition: 13-bit = 10 + 2 + 1 = 3 columns (worst case)
/// We need carries for positions 0 through num_chunks-2 (the last position doesn't carry out)
#[inline]
pub const fn mul_carry_columns(data_limbs: usize) -> usize {
    if data_limbs <= 1 {
        0
    } else {
        // For chunk-based multiplication:
        // num_chunks = data_limbs * 2
        // positions = num_chunks (for result chunks)
        // We need carries for positions 0 through num_chunks-2
        // Each carry uses up to 3 columns (10 + 2 + 1 for up to 13-bit)
        let num_chunks = data_limbs * 2;
        let carry_positions = num_chunks - 1;
        carry_positions * 3
    }
}

/// Total MUL auxiliary columns
#[inline]
pub const fn mul_aux_columns(data_limbs: usize) -> usize {
    mul_operand_chunk_columns(data_limbs)
        + mul_partial_product_columns(data_limbs)
        + mul_carry_columns(data_limbs)
}

// ============================================================================
// DIV/REM Hierarchical Decomposition Columns
// ============================================================================
//
// DIV/REM verification: dividend = quotient × divisor + remainder
// where 0 ≤ remainder < divisor
//
// Columns needed:
// - MUL verification columns (quotient × divisor) - reused
// - ADD carry for (product + remainder) - 1 column (boolean)
// - Comparison diff (divisor - remainder - 1) - 2 limbs × 2 chunks = 4 columns

/// DIV/REM comparison diff columns for remainder < divisor check
/// diff = divisor - remainder - 1, decomposed hierarchically
/// For 2-limb: 2 limbs × 2 chunks (10+10) = 4 columns
#[inline]
pub const fn div_cmp_diff_columns(data_limbs: usize) -> usize {
    data_limbs * 2  // 2 chunks per limb (10+10 for 20-bit)
}

/// DIV/REM product carry (for quotient × divisor + remainder = dividend)
pub const DIV_PRODUCT_CARRY_COLUMN: usize = 1;

/// Total DIV/REM specific auxiliary columns (excluding MUL reuse)
#[inline]
pub const fn div_aux_columns(data_limbs: usize) -> usize {
    div_cmp_diff_columns(data_limbs) + DIV_PRODUCT_CARRY_COLUMN
}

// ============================================================================
// SHIFT Hierarchical Decomposition Columns
// ============================================================================
//
// Shift operations move bits between limbs. The carry (bits crossing
// limb boundary) has size = shift amount (k bits, 0 ≤ k < limb_bits).
//
// For variable shift amounts, we use worst-case: 20-bit carry
// Decomposed as 10 + 10 = 2 columns per carry

/// Shift carry hierarchical decomposition columns
/// For 2-limb: 1 cross-limb carry, decomposed into 10+10 = 2 columns
#[inline]
pub const fn shift_carry_decomp_columns(data_limbs: usize) -> usize {
    if data_limbs <= 1 {
        0
    } else {
        // One carry per limb boundary, each decomposed into 2 chunks (10+10)
        (data_limbs - 1) * 2
    }
}

/// Comparison less-than flag columns (one per limb)
#[inline]
pub const fn cmp_lt_flag_columns(data_limbs: usize) -> usize {
    data_limbs
}

/// Comparison equality flag columns (one per limb)
#[inline]
pub const fn cmp_eq_flag_columns(data_limbs: usize) -> usize {
    data_limbs
}

/// Branch condition column (boolean result)
pub const BRANCH_CONDITION_COLUMN: usize = 1;

/// Shift carry columns (depends on data_limbs, limbs-1 for cross-limb carries)
#[inline]
pub const fn shift_carry_columns(data_limbs: usize) -> usize {
    if data_limbs > 1 {
        data_limbs - 1
    } else {
        0
    }
}

/// CMOV zero detection flag column
pub const ZERO_FLAG_COLUMN: usize = 1;

// ============================================================================
// Multi-Limb Arithmetic Carry/Borrow Columns
// ============================================================================

/// ADD/ADDI carry columns for multi-limb addition
/// For 2-limb arithmetic: 1 carry from limb[0] to limb[1]
/// General: data_limbs - 1 carry values (one between each adjacent pair of limbs)
#[inline]
pub const fn add_carry_columns(data_limbs: usize) -> usize {
    if data_limbs > 1 {
        data_limbs - 1
    } else {
        0
    }
}

/// SUB/SUBI borrow columns for multi-limb subtraction
/// Same count as carry columns: one between each pair of limbs
#[inline]
pub const fn sub_borrow_columns(data_limbs: usize) -> usize {
    if data_limbs > 1 {
        data_limbs - 1
    } else {
        0
    }
}

// ============================================================================
// Bitwise Chunk Decomposition Columns
// ============================================================================

/// Chunks per operand (rs1_chunk0, rs1_chunk1, rs2_chunk0, rs2_chunk1, rd_chunk0, rd_chunk1)
pub const CHUNKS_PER_LIMB: usize = 6;

/// Bitwise chunk columns (6 chunks per limb for 3 operands)
#[inline]
pub const fn bitwise_chunk_columns(data_limbs: usize) -> usize {
    CHUNKS_PER_LIMB * data_limbs
}

// ============================================================================
// Range Check Chunk Columns
// ============================================================================

/// Range check chunks per limb (lo and hi chunks)
pub const RANGE_CHUNKS_PER_LIMB: usize = 2;

/// Range check chunk columns (2 chunks per limb)
#[inline]
pub const fn range_chunk_columns(data_limbs: usize) -> usize {
    RANGE_CHUNKS_PER_LIMB * data_limbs
}

// ============================================================================
// Auxiliary Trace Columns (RAP pattern - challenge-dependent)
// ============================================================================

/// Memory permutation accumulator columns (execution order + sorted order)
pub const MEMORY_PERM_COLUMNS: usize = 2;

/// LogUp query accumulator columns (AND, OR, XOR, range)
pub const LOGUP_QUERY_COLUMNS: usize = 4;

/// LogUp table accumulator columns (AND, OR, XOR, range)
pub const LOGUP_TABLE_COLUMNS: usize = 4;

/// Total auxiliary columns
pub const TOTAL_AUX_COLUMNS: usize =
    MEMORY_PERM_COLUMNS + LOGUP_QUERY_COLUMNS + LOGUP_TABLE_COLUMNS;

// ============================================================================
// Column Count Calculations
// ============================================================================

/// Calculate total main trace columns for a given configuration
#[inline]
pub const fn main_column_count(data_limbs: usize, addr_limbs: usize) -> usize {
    let mut count = 0;

    // Core
    count += CORE_COLUMNS;

    // Registers (values + bounds)
    count += register_value_columns(data_limbs);
    count += REGISTER_BOUND_COLUMNS;

    // Memory
    count += memory_addr_columns(addr_limbs);
    count += memory_value_columns(data_limbs);
    count += MEMORY_FLAG_COLUMNS;

    // Instruction decode
    count += INSTRUCTION_DECODE_COLUMNS;

    // Selectors and indicators
    count += FAMILY_SELECTOR_COLUMNS;
    count += TOTAL_OPCODE_INDICATORS;
    count += REGISTER_INDICATOR_COLUMNS;

    // Complex operation auxiliaries
    count += div_quotient_columns(data_limbs);
    count += div_remainder_columns(data_limbs);
    count += cmp_lt_flag_columns(data_limbs);
    count += cmp_eq_flag_columns(data_limbs);
    count += BRANCH_CONDITION_COLUMN;
    count += shift_carry_columns(data_limbs);
    count += ZERO_FLAG_COLUMN;

    // Multi-limb arithmetic carry/borrow
    count += add_carry_columns(data_limbs);
    count += sub_borrow_columns(data_limbs);

    // Chunk decomposition
    count += bitwise_chunk_columns(data_limbs);
    count += range_chunk_columns(data_limbs);

    // MUL hierarchical decomposition
    count += mul_aux_columns(data_limbs);

    // DIV/REM hierarchical decomposition
    count += div_aux_columns(data_limbs);

    // SHIFT hierarchical decomposition
    count += shift_carry_decomp_columns(data_limbs);

    count
}

/// Calculate total auxiliary trace columns
#[inline]
pub const fn aux_column_count() -> usize {
    TOTAL_AUX_COLUMNS
}

/// Calculate total trace columns (main + auxiliary)
#[inline]
pub const fn total_column_count(data_limbs: usize, addr_limbs: usize) -> usize {
    main_column_count(data_limbs, addr_limbs) + aux_column_count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_column_count() {
        // Default config: data_limbs=2, addr_limbs=2
        let main = main_column_count(2, 2);
        let aux = aux_column_count();
        let total = total_column_count(2, 2);

        assert_eq!(aux, 10);
        assert_eq!(total, main + aux);

        // Main columns breakdown:
        // - Core: 2
        // - Registers: 32 + 16 = 48
        // - Memory: 2 + 2 + 2 = 6
        // - Decode: 7
        // - Selectors: 10
        // - Opcode indicators: 38
        // - Register indicators: 48
        // - Complex ops: 2 + 2 + 2 + 2 + 1 + 1 + 1 = 11
        // - Bitwise chunks: 12
        // - Range chunks: 4
        // Total main: 2 + 48 + 6 + 7 + 10 + 38 + 48 + 11 + 12 + 4 = 186
        // Plus aux: 10
        // Grand total: 196
        println!("Main columns: {}", main);
        println!("Aux columns: {}", aux);
        println!("Total columns: {}", total);
    }

    #[test]
    fn test_opcode_indicators_sum() {
        let expected = 7 + 6 + 4 + 8 + 6 + 3 + 4; // 38
        assert_eq!(TOTAL_OPCODE_INDICATORS, expected);
        assert_eq!(TOTAL_OPCODE_INDICATORS, 38);
    }

    #[test]
    fn test_register_indicators() {
        assert_eq!(REGISTER_INDICATOR_COLUMNS, 48);
        assert_eq!(REGISTER_INDICATOR_COLUMNS, NUM_REGISTERS * 3);
    }

    #[test]
    fn test_family_count() {
        assert_eq!(INSTRUCTION_FAMILY_COUNT, 10);
    }
}
