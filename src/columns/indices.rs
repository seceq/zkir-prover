//! Pre-computed column indices for efficient access
//!
//! The `ColumnIndices` struct computes all column offsets once at initialization,
//! eliminating runtime calculations in constraint evaluation.

use super::constants::*;
use crate::witness::ProgramConfig;

/// Pre-computed column indices for a specific configuration
///
/// All offsets are computed once when this struct is created, making
/// column access O(1) without repeated arithmetic.
#[derive(Clone, Debug)]
pub struct ColumnIndices {
    // ========== Core Columns ==========
    /// Program counter column
    pub pc: usize,
    /// Instruction word column
    pub instruction: usize,

    // ========== Register Columns ==========
    /// Base index for register value columns
    pub registers_base: usize,
    /// Base index for register bound columns
    pub register_bounds_base: usize,

    // ========== Memory Columns ==========
    /// Base index for memory address columns
    pub mem_addr_base: usize,
    /// Base index for memory value columns
    pub mem_value_base: usize,
    /// Memory write flag column
    pub mem_is_write: usize,
    /// Memory read flag column
    pub mem_is_read: usize,

    // ========== Instruction Decode Columns ==========
    /// Decoded opcode column
    pub decoded_opcode: usize,
    /// Decoded rd (destination register) column
    pub decoded_rd: usize,
    /// Decoded rs1 (source register 1) column
    pub decoded_rs1: usize,
    /// Decoded rs2 (source register 2) column
    pub decoded_rs2: usize,
    /// Decoded immediate/function field column
    pub decoded_imm_funct: usize,
    /// Is-immediate flag column
    pub is_imm: usize,
    /// Immediate sign bit column
    pub imm_sign_bit: usize,

    // ========== Family Selector Columns ==========
    /// Base index for family selector columns
    pub family_selectors_base: usize,

    // ========== Opcode Indicator Columns ==========
    /// Base index for bitwise indicators (AND, OR, XOR, NOT, ANDI, ORI, XORI)
    pub bitwise_indicators_base: usize,
    /// Base index for load indicators (LB, LBU, LH, LHU, LW, LD)
    pub load_indicators_base: usize,
    /// Base index for store indicators (SB, SH, SW, SD)
    pub store_indicators_base: usize,
    /// Base index for arithmetic indicators (ADD, SUB, MUL, ADDI, SUBI, MULI, DIV, REM)
    pub arithmetic_indicators_base: usize,
    /// Base index for shift indicators (SLL, SRL, SRA, SLLI, SRLI, SRAI)
    pub shift_indicators_base: usize,
    /// Base index for cmov indicators (CMOV, CMOVZ, CMOVNZ)
    pub cmov_indicators_base: usize,
    /// Base index for comparison indicators (SLT, SLTU, SEQ, SNE)
    pub compare_indicators_base: usize,

    // ========== Complex Operation Columns ==========
    /// Base index for DIV quotient columns
    pub div_quotient_base: usize,
    /// Base index for DIV remainder columns
    pub div_remainder_base: usize,
    /// Base index for comparison lt flag columns
    pub cmp_lt_flags_base: usize,
    /// Base index for comparison eq flag columns
    pub cmp_eq_flags_base: usize,
    /// Branch condition column
    pub branch_condition: usize,
    /// Base index for shift carry columns
    pub shift_carry_base: usize,
    /// Zero detection flag column
    pub zero_flag: usize,

    // ========== Multi-Limb Arithmetic Carry/Borrow Columns ==========
    /// Base index for ADD/ADDI carry columns
    pub add_carry_base: usize,
    /// Base index for SUB/SUBI borrow columns
    pub sub_borrow_base: usize,

    // ========== Chunk Decomposition Columns ==========
    /// Base index for bitwise chunk columns
    pub bitwise_chunks_base: usize,
    /// Base index for range check chunk columns
    pub range_chunks_base: usize,

    // ========== MUL Hierarchical Decomposition Columns ==========
    /// Base index for MUL operand chunk columns (rs1 and rs2 decomposition)
    pub mul_operand_chunks_base: usize,
    /// Base index for MUL partial product columns (lo, hi pairs)
    pub mul_partial_products_base: usize,
    /// Base index for MUL carry columns (hierarchical decomposition)
    pub mul_carries_base: usize,

    // ========== DIV/REM Hierarchical Decomposition Columns ==========
    /// Base index for DIV comparison diff columns (divisor - remainder - 1)
    pub div_cmp_diff_base: usize,
    /// DIV product carry column (for product + remainder = dividend)
    pub div_product_carry: usize,

    // ========== SHIFT Hierarchical Decomposition Columns ==========
    /// Base index for shift carry decomposition columns (10+10 per carry)
    pub shift_carry_decomp_base: usize,

    // ========== Register Indicator Columns ==========
    /// Base index for rd indicator columns (16 columns)
    pub rd_indicators_base: usize,
    /// Base index for rs1 indicator columns (16 columns)
    pub rs1_indicators_base: usize,
    /// Base index for rs2 indicator columns (16 columns)
    pub rs2_indicators_base: usize,

    // ========== Auxiliary Trace Columns ==========
    /// Start of auxiliary columns
    pub aux_start: usize,
    /// Memory permutation (execution order) column
    pub mem_perm_exec: usize,
    /// Memory permutation (sorted order) column
    pub mem_perm_sorted: usize,
    /// LogUp query accumulator for AND
    pub logup_and: usize,
    /// LogUp query accumulator for OR
    pub logup_or: usize,
    /// LogUp query accumulator for XOR
    pub logup_xor: usize,
    /// LogUp query accumulator for range check
    pub logup_range: usize,
    /// LogUp table accumulator for AND
    pub logup_and_table: usize,
    /// LogUp table accumulator for OR
    pub logup_or_table: usize,
    /// LogUp table accumulator for XOR
    pub logup_xor_table: usize,
    /// LogUp table accumulator for range check
    pub logup_range_table: usize,

    // ========== Totals ==========
    /// Total main trace columns
    pub main_columns: usize,
    /// Total auxiliary trace columns
    pub aux_columns: usize,
    /// Total columns (main + aux)
    pub total_columns: usize,

    // ========== Config (for dynamic calculations) ==========
    /// Data limbs from config
    data_limbs: usize,
    /// Address limbs from config
    addr_limbs: usize,
}

impl ColumnIndices {
    /// Create new column indices for the given configuration
    pub fn new(config: &ProgramConfig) -> Self {
        let data_limbs = config.data_limbs as usize;
        let addr_limbs = config.addr_limbs as usize;

        let mut offset = 0;

        // Core columns
        let pc = offset;
        offset += 1;
        let instruction = offset;
        offset += 1;

        // Register value columns (16 * data_limbs)
        let registers_base = offset;
        offset += register_value_columns(data_limbs);

        // Register bound columns (16)
        let register_bounds_base = offset;
        offset += REGISTER_BOUND_COLUMNS;

        // Memory address columns
        let mem_addr_base = offset;
        offset += memory_addr_columns(addr_limbs);

        // Memory value columns
        let mem_value_base = offset;
        offset += memory_value_columns(data_limbs);

        // Memory flags
        let mem_is_write = offset;
        offset += 1;
        let mem_is_read = offset;
        offset += 1;

        // Instruction decode columns
        let decoded_opcode = offset;
        offset += 1;
        let decoded_rd = offset;
        offset += 1;
        let decoded_rs1 = offset;
        offset += 1;
        let decoded_rs2 = offset;
        offset += 1;
        let decoded_imm_funct = offset;
        offset += 1;
        let is_imm = offset;
        offset += 1;
        let imm_sign_bit = offset;
        offset += 1;

        // Family selector columns
        let family_selectors_base = offset;
        offset += FAMILY_SELECTOR_COLUMNS;

        // Opcode indicator columns
        let bitwise_indicators_base = offset;
        offset += BITWISE_INDICATOR_COLUMNS;
        let load_indicators_base = offset;
        offset += LOAD_INDICATOR_COLUMNS;
        let store_indicators_base = offset;
        offset += STORE_INDICATOR_COLUMNS;
        let arithmetic_indicators_base = offset;
        offset += ARITHMETIC_INDICATOR_COLUMNS;
        let shift_indicators_base = offset;
        offset += SHIFT_INDICATOR_COLUMNS;
        let cmov_indicators_base = offset;
        offset += CMOV_INDICATOR_COLUMNS;
        let compare_indicators_base = offset;
        offset += COMPARE_INDICATOR_COLUMNS;

        // Complex operation columns
        let div_quotient_base = offset;
        offset += div_quotient_columns(data_limbs);
        let div_remainder_base = offset;
        offset += div_remainder_columns(data_limbs);
        let cmp_lt_flags_base = offset;
        offset += cmp_lt_flag_columns(data_limbs);
        let cmp_eq_flags_base = offset;
        offset += cmp_eq_flag_columns(data_limbs);
        let branch_condition = offset;
        offset += 1;
        let shift_carry_base = offset;
        offset += shift_carry_columns(data_limbs);
        let zero_flag = offset;
        offset += 1;

        // Multi-limb arithmetic carry/borrow columns
        let add_carry_base = offset;
        offset += add_carry_columns(data_limbs);
        let sub_borrow_base = offset;
        offset += sub_borrow_columns(data_limbs);

        // Chunk decomposition columns
        let bitwise_chunks_base = offset;
        offset += bitwise_chunk_columns(data_limbs);
        let range_chunks_base = offset;
        offset += range_chunk_columns(data_limbs);

        // MUL hierarchical decomposition columns
        let mul_operand_chunks_base = offset;
        offset += mul_operand_chunk_columns(data_limbs);
        let mul_partial_products_base = offset;
        offset += mul_partial_product_columns(data_limbs);
        let mul_carries_base = offset;
        offset += mul_carry_columns(data_limbs);

        // DIV/REM hierarchical decomposition columns
        let div_cmp_diff_base = offset;
        offset += div_cmp_diff_columns(data_limbs);
        let div_product_carry = offset;
        offset += DIV_PRODUCT_CARRY_COLUMN;

        // SHIFT hierarchical decomposition columns
        let shift_carry_decomp_base = offset;
        offset += shift_carry_decomp_columns(data_limbs);

        // Register indicator columns
        let rd_indicators_base = offset;
        offset += REGISTER_COUNT;
        let rs1_indicators_base = offset;
        offset += REGISTER_COUNT;
        let rs2_indicators_base = offset;
        offset += REGISTER_COUNT;

        // End of main columns
        let main_columns = offset;
        let aux_start = offset;

        // Auxiliary columns
        let mem_perm_exec = offset;
        offset += 1;
        let mem_perm_sorted = offset;
        offset += 1;
        let logup_and = offset;
        offset += 1;
        let logup_or = offset;
        offset += 1;
        let logup_xor = offset;
        offset += 1;
        let logup_range = offset;
        offset += 1;
        let logup_and_table = offset;
        offset += 1;
        let logup_or_table = offset;
        offset += 1;
        let logup_xor_table = offset;
        offset += 1;
        let logup_range_table = offset;
        offset += 1;

        let aux_columns = offset - aux_start;
        let total_columns = offset;

        Self {
            pc,
            instruction,
            registers_base,
            register_bounds_base,
            mem_addr_base,
            mem_value_base,
            mem_is_write,
            mem_is_read,
            decoded_opcode,
            decoded_rd,
            decoded_rs1,
            decoded_rs2,
            decoded_imm_funct,
            is_imm,
            imm_sign_bit,
            family_selectors_base,
            bitwise_indicators_base,
            load_indicators_base,
            store_indicators_base,
            arithmetic_indicators_base,
            shift_indicators_base,
            cmov_indicators_base,
            compare_indicators_base,
            div_quotient_base,
            div_remainder_base,
            cmp_lt_flags_base,
            cmp_eq_flags_base,
            branch_condition,
            shift_carry_base,
            zero_flag,
            add_carry_base,
            sub_borrow_base,
            bitwise_chunks_base,
            range_chunks_base,
            mul_operand_chunks_base,
            mul_partial_products_base,
            mul_carries_base,
            div_cmp_diff_base,
            div_product_carry,
            shift_carry_decomp_base,
            rd_indicators_base,
            rs1_indicators_base,
            rs2_indicators_base,
            aux_start,
            mem_perm_exec,
            mem_perm_sorted,
            logup_and,
            logup_or,
            logup_xor,
            logup_range,
            logup_and_table,
            logup_or_table,
            logup_xor_table,
            logup_range_table,
            main_columns,
            aux_columns,
            total_columns,
            data_limbs,
            addr_limbs,
        }
    }

    // ========== Dynamic Index Methods ==========

    /// Get register value column index
    #[inline]
    pub fn register(&self, reg_idx: usize, limb_idx: usize) -> usize {
        debug_assert!(reg_idx < REGISTER_COUNT);
        debug_assert!(limb_idx < self.data_limbs);
        self.registers_base + reg_idx * self.data_limbs + limb_idx
    }

    /// Get register bound column index
    #[inline]
    pub fn register_bound(&self, reg_idx: usize) -> usize {
        debug_assert!(reg_idx < REGISTER_COUNT);
        self.register_bounds_base + reg_idx
    }

    /// Get memory address column index
    #[inline]
    pub fn mem_addr(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.addr_limbs);
        self.mem_addr_base + limb_idx
    }

    /// Get memory value column index
    #[inline]
    pub fn mem_value(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.mem_value_base + limb_idx
    }

    /// Get family selector column index
    #[inline]
    pub fn family_selector(&self, family_idx: usize) -> usize {
        debug_assert!(family_idx < INSTRUCTION_FAMILY_COUNT);
        self.family_selectors_base + family_idx
    }

    /// Get DIV quotient column index
    #[inline]
    pub fn div_quotient(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.div_quotient_base + limb_idx
    }

    /// Get DIV remainder column index
    #[inline]
    pub fn div_remainder(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.div_remainder_base + limb_idx
    }

    /// Get comparison lt flag column index
    #[inline]
    pub fn cmp_lt_flag(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.cmp_lt_flags_base + limb_idx
    }

    /// Get comparison eq flag column index
    #[inline]
    pub fn cmp_eq_flag(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.cmp_eq_flags_base + limb_idx
    }

    /// Get shift carry column index
    #[inline]
    pub fn shift_carry(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs.saturating_sub(1));
        self.shift_carry_base + limb_idx
    }

    /// Get ADD/ADDI carry column index for a specific limb boundary
    ///
    /// carry[i] is the carry from limb[i] to limb[i+1]
    /// For 2-limb arithmetic, carry[0] is the carry from limb[0] to limb[1]
    #[inline]
    pub fn add_carry(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs.saturating_sub(1));
        self.add_carry_base + limb_idx
    }

    /// Get SUB/SUBI borrow column index for a specific limb boundary
    ///
    /// borrow[i] is the borrow from limb[i+1] to limb[i]
    /// For 2-limb arithmetic, borrow[0] is the borrow from limb[1] to limb[0]
    #[inline]
    pub fn sub_borrow(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs.saturating_sub(1));
        self.sub_borrow_base + limb_idx
    }

    /// Get bitwise rs1 chunk0 column index
    #[inline]
    pub fn bitwise_rs1_chunk0(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.bitwise_chunks_base + limb_idx * 6
    }

    /// Get bitwise rs1 chunk1 column index
    #[inline]
    pub fn bitwise_rs1_chunk1(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.bitwise_chunks_base + limb_idx * 6 + 1
    }

    /// Get bitwise rs2 chunk0 column index
    #[inline]
    pub fn bitwise_rs2_chunk0(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.bitwise_chunks_base + limb_idx * 6 + 2
    }

    /// Get bitwise rs2 chunk1 column index
    #[inline]
    pub fn bitwise_rs2_chunk1(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.bitwise_chunks_base + limb_idx * 6 + 3
    }

    /// Get bitwise rd chunk0 column index
    #[inline]
    pub fn bitwise_rd_chunk0(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.bitwise_chunks_base + limb_idx * 6 + 4
    }

    /// Get bitwise rd chunk1 column index
    #[inline]
    pub fn bitwise_rd_chunk1(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.bitwise_chunks_base + limb_idx * 6 + 5
    }

    /// Get range check chunk0 column index
    #[inline]
    pub fn range_chunk0(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.range_chunks_base + limb_idx * 2
    }

    /// Get range check chunk1 column index
    #[inline]
    pub fn range_chunk1(&self, limb_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        self.range_chunks_base + limb_idx * 2 + 1
    }

    // ========== MUL Hierarchical Column Accessors ==========

    /// Get MUL operand chunk column for rs1
    /// For 2-limb: rs1 has chunks at indices 0-3 (2 per limb)
    #[inline]
    pub fn mul_rs1_chunk(&self, limb_idx: usize, chunk_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        debug_assert!(chunk_idx < 2);
        self.mul_operand_chunks_base + limb_idx * 2 + chunk_idx
    }

    /// Get MUL operand chunk column for rs2
    /// For 2-limb: rs2 has chunks at indices after rs1 chunks
    #[inline]
    pub fn mul_rs2_chunk(&self, limb_idx: usize, chunk_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        debug_assert!(chunk_idx < 2);
        let rs2_offset = self.data_limbs * 2; // Skip rs1 chunks
        self.mul_operand_chunks_base + rs2_offset + limb_idx * 2 + chunk_idx
    }

    /// Get MUL partial product lo column
    /// Products are indexed as (i, j) for a_i × b_j
    #[inline]
    pub fn mul_partial_lo(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.data_limbs * 2); // 2 chunks per limb
        debug_assert!(j < self.data_limbs * 2);
        let product_idx = i * (self.data_limbs * 2) + j;
        self.mul_partial_products_base + product_idx * 2
    }

    /// Get MUL partial product hi column
    #[inline]
    pub fn mul_partial_hi(&self, i: usize, j: usize) -> usize {
        self.mul_partial_lo(i, j) + 1
    }

    /// Get MUL position carry column with hierarchical decomposition
    /// Each position has up to 3 columns (10 + 2 + 1 for 13-bit max)
    /// Carries exist for positions 0 through num_chunks-2 (num_chunks = data_limbs * 2)
    #[inline]
    pub fn mul_carry(&self, position: usize, chunk_idx: usize) -> usize {
        let num_chunks = self.data_limbs * 2;
        let carry_positions = num_chunks.saturating_sub(1);
        debug_assert!(position < carry_positions, "position {} >= carry_positions {}", position, carry_positions);
        debug_assert!(chunk_idx < 3);
        self.mul_carries_base + position * 3 + chunk_idx
    }

    // ========== DIV/REM Hierarchical Column Accessors ==========

    /// Get DIV comparison diff chunk column
    /// diff = divisor - remainder - 1, decomposed as 10+10 per limb
    #[inline]
    pub fn div_cmp_diff_chunk(&self, limb_idx: usize, chunk_idx: usize) -> usize {
        debug_assert!(limb_idx < self.data_limbs);
        debug_assert!(chunk_idx < 2);
        self.div_cmp_diff_base + limb_idx * 2 + chunk_idx
    }

    // ========== SHIFT Hierarchical Column Accessors ==========

    /// Get shift carry decomposition chunk column
    /// For variable shift, carry is 20-bit max, decomposed as 10+10
    #[inline]
    pub fn shift_carry_chunk(&self, boundary_idx: usize, chunk_idx: usize) -> usize {
        debug_assert!(boundary_idx < self.data_limbs.saturating_sub(1));
        debug_assert!(chunk_idx < 2);
        self.shift_carry_decomp_base + boundary_idx * 2 + chunk_idx
    }

    /// Get rd indicator column index
    #[inline]
    pub fn rd_indicator(&self, reg_idx: usize) -> usize {
        debug_assert!(reg_idx < REGISTER_COUNT);
        self.rd_indicators_base + reg_idx
    }

    /// Get rs1 indicator column index
    #[inline]
    pub fn rs1_indicator(&self, reg_idx: usize) -> usize {
        debug_assert!(reg_idx < REGISTER_COUNT);
        self.rs1_indicators_base + reg_idx
    }

    /// Get rs2 indicator column index
    #[inline]
    pub fn rs2_indicator(&self, reg_idx: usize) -> usize {
        debug_assert!(reg_idx < REGISTER_COUNT);
        self.rs2_indicators_base + reg_idx
    }

    // ========== Individual Opcode Indicator Accessors ==========

    /// Get bitwise AND indicator column
    #[inline]
    pub fn is_and(&self) -> usize {
        self.bitwise_indicators_base
    }

    /// Get bitwise OR indicator column
    #[inline]
    pub fn is_or(&self) -> usize {
        self.bitwise_indicators_base + 1
    }

    /// Get bitwise XOR indicator column
    #[inline]
    pub fn is_xor(&self) -> usize {
        self.bitwise_indicators_base + 2
    }

    /// Get bitwise NOT indicator column
    #[inline]
    pub fn is_not(&self) -> usize {
        self.bitwise_indicators_base + 3
    }

    /// Get ANDI indicator column
    #[inline]
    pub fn is_andi(&self) -> usize {
        self.bitwise_indicators_base + 4
    }

    /// Get ORI indicator column
    #[inline]
    pub fn is_ori(&self) -> usize {
        self.bitwise_indicators_base + 5
    }

    /// Get XORI indicator column
    #[inline]
    pub fn is_xori(&self) -> usize {
        self.bitwise_indicators_base + 6
    }

    // Load indicators
    #[inline]
    pub fn is_lb(&self) -> usize {
        self.load_indicators_base
    }
    #[inline]
    pub fn is_lbu(&self) -> usize {
        self.load_indicators_base + 1
    }
    #[inline]
    pub fn is_lh(&self) -> usize {
        self.load_indicators_base + 2
    }
    #[inline]
    pub fn is_lhu(&self) -> usize {
        self.load_indicators_base + 3
    }
    #[inline]
    pub fn is_lw(&self) -> usize {
        self.load_indicators_base + 4
    }
    #[inline]
    pub fn is_ld(&self) -> usize {
        self.load_indicators_base + 5
    }

    // Store indicators
    #[inline]
    pub fn is_sb(&self) -> usize {
        self.store_indicators_base
    }
    #[inline]
    pub fn is_sh(&self) -> usize {
        self.store_indicators_base + 1
    }
    #[inline]
    pub fn is_sw(&self) -> usize {
        self.store_indicators_base + 2
    }
    #[inline]
    pub fn is_sd(&self) -> usize {
        self.store_indicators_base + 3
    }

    // Arithmetic indicators
    #[inline]
    pub fn is_add(&self) -> usize {
        self.arithmetic_indicators_base
    }
    #[inline]
    pub fn is_sub(&self) -> usize {
        self.arithmetic_indicators_base + 1
    }
    #[inline]
    pub fn is_mul(&self) -> usize {
        self.arithmetic_indicators_base + 2
    }
    #[inline]
    pub fn is_addi(&self) -> usize {
        self.arithmetic_indicators_base + 3
    }
    #[inline]
    pub fn is_subi(&self) -> usize {
        self.arithmetic_indicators_base + 4
    }
    #[inline]
    pub fn is_muli(&self) -> usize {
        self.arithmetic_indicators_base + 5
    }
    #[inline]
    pub fn is_div(&self) -> usize {
        self.arithmetic_indicators_base + 6
    }
    #[inline]
    pub fn is_rem(&self) -> usize {
        self.arithmetic_indicators_base + 7
    }

    // Shift indicators
    #[inline]
    pub fn is_sll(&self) -> usize {
        self.shift_indicators_base
    }
    #[inline]
    pub fn is_srl(&self) -> usize {
        self.shift_indicators_base + 1
    }
    #[inline]
    pub fn is_sra(&self) -> usize {
        self.shift_indicators_base + 2
    }
    #[inline]
    pub fn is_slli(&self) -> usize {
        self.shift_indicators_base + 3
    }
    #[inline]
    pub fn is_srli(&self) -> usize {
        self.shift_indicators_base + 4
    }
    #[inline]
    pub fn is_srai(&self) -> usize {
        self.shift_indicators_base + 5
    }

    // Cmov indicators
    #[inline]
    pub fn is_cmov(&self) -> usize {
        self.cmov_indicators_base
    }
    #[inline]
    pub fn is_cmovz(&self) -> usize {
        self.cmov_indicators_base + 1
    }
    #[inline]
    pub fn is_cmovnz(&self) -> usize {
        self.cmov_indicators_base + 2
    }

    // Comparison indicators
    #[inline]
    pub fn is_slt(&self) -> usize {
        self.compare_indicators_base
    }
    #[inline]
    pub fn is_sltu(&self) -> usize {
        self.compare_indicators_base + 1
    }
    #[inline]
    pub fn is_seq(&self) -> usize {
        self.compare_indicators_base + 2
    }
    #[inline]
    pub fn is_sne(&self) -> usize {
        self.compare_indicators_base + 3
    }

    // ========== Family Selector Accessors ==========

    #[inline]
    pub fn sel_arithmetic(&self) -> usize {
        self.family_selectors_base
    }
    #[inline]
    pub fn sel_bitwise(&self) -> usize {
        self.family_selectors_base + 1
    }
    #[inline]
    pub fn sel_shift(&self) -> usize {
        self.family_selectors_base + 2
    }
    #[inline]
    pub fn sel_comparison(&self) -> usize {
        self.family_selectors_base + 3
    }
    #[inline]
    pub fn sel_cmov(&self) -> usize {
        self.family_selectors_base + 4
    }
    #[inline]
    pub fn sel_load(&self) -> usize {
        self.family_selectors_base + 5
    }
    #[inline]
    pub fn sel_store(&self) -> usize {
        self.family_selectors_base + 6
    }
    #[inline]
    pub fn sel_branch(&self) -> usize {
        self.family_selectors_base + 7
    }
    #[inline]
    pub fn sel_jump(&self) -> usize {
        self.family_selectors_base + 8
    }
    #[inline]
    pub fn sel_system(&self) -> usize {
        self.family_selectors_base + 9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_indices() {
        let config = ProgramConfig::DEFAULT;
        let idx = ColumnIndices::new(&config);

        // Verify basic indices
        assert_eq!(idx.pc, 0);
        assert_eq!(idx.instruction, 1);
        assert_eq!(idx.registers_base, 2);

        // Verify totals
        assert_eq!(idx.aux_columns, 10);
        assert_eq!(idx.total_columns, idx.main_columns + idx.aux_columns);

        println!("Main columns: {}", idx.main_columns);
        println!("Aux columns: {}", idx.aux_columns);
        println!("Total columns: {}", idx.total_columns);
    }

    #[test]
    fn test_register_indices() {
        let config = ProgramConfig::DEFAULT;
        let idx = ColumnIndices::new(&config);

        // R0 limb 0 should be at registers_base
        assert_eq!(idx.register(0, 0), idx.registers_base);
        // R0 limb 1 should be next
        assert_eq!(idx.register(0, 1), idx.registers_base + 1);
        // R1 limb 0 should be after R0
        assert_eq!(idx.register(1, 0), idx.registers_base + 2);
    }

    #[test]
    fn test_indicator_indices() {
        let config = ProgramConfig::DEFAULT;
        let idx = ColumnIndices::new(&config);

        // Verify indicator column ordering
        assert!(idx.rd_indicators_base < idx.rs1_indicators_base);
        assert!(idx.rs1_indicators_base < idx.rs2_indicators_base);

        // Verify rd indicator for R5
        assert_eq!(idx.rd_indicator(5), idx.rd_indicators_base + 5);
    }

    #[test]
    fn test_aux_columns() {
        let config = ProgramConfig::DEFAULT;
        let idx = ColumnIndices::new(&config);

        // Aux columns should start after main
        assert_eq!(idx.aux_start, idx.main_columns);

        // Memory permutation columns
        assert_eq!(idx.mem_perm_exec, idx.aux_start);
        assert_eq!(idx.mem_perm_sorted, idx.aux_start + 1);

        // LogUp columns
        assert_eq!(idx.logup_and, idx.aux_start + 2);
    }
}
