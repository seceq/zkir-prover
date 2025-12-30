//! Algebraic Intermediate Representation (AIR) framework for ZKIR v3.4

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;

use crate::columns::ColumnIndices;
use crate::witness::ProgramConfig;

/// Main trace columns (for RAP pattern)
///
/// These columns contain execution data that does NOT depend on the
/// Fiat-Shamir challenge. They are committed first to derive the challenge.
#[derive(Clone, Debug)]
pub struct MainColumns {
    /// Number of main trace columns
    pub count: usize,
}

impl MainColumns {
    /// Calculate number of main columns based on config
    pub fn calculate_count(config: &ProgramConfig) -> usize {
        let mut cols = 0;

        // PC + Instruction
        cols += 2;

        // Registers (16 × data_limbs) + bounds (16)
        cols += 16 * config.data_limbs as usize + 16;

        // Memory columns (address + value + flags)
        cols += config.addr_limbs as usize + config.data_limbs as usize + 2;

        // Instruction decoding (opcode + rd/rs1/rs2 + imm/funct + flags)
        cols += 1 + 3 + 1 + 1 + 1;

        // Selector columns (10 instruction families)
        cols += 10;

        // Boolean opcode indicators:
        // - bitwise: 7 [AND,OR,XOR,NOT,ANDI,ORI,XORI]
        // - load: 6 [LB,LBU,LH,LHU,LW,LD]
        // - store: 4 [SB,SH,SW,SD]
        // - arithmetic: 6 [ADD,SUB,MUL,ADDI,SUBI,MULI] + 2 [DIV,REM]
        // - shift: 6 [SLL,SRL,SRA,SLLI,SRLI,SRAI]
        // - cmov: 3 [CMOV,CMOVZ,CMOVNZ]
        // - comparison: 4 [SLT,SLTU,SEQ,SNE]
        cols += 7 + 6 + 4 + 8 + 6 + 3 + 4;

        // Complex operation auxiliaries
        cols += 2 * config.data_limbs as usize; // DIV/REM
        cols += config.data_limbs as usize;     // Comparison lt flags
        cols += config.data_limbs as usize;     // Comparison eq flags
        cols += 1;                               // Branch condition
        if config.data_limbs > 1 {
            cols += (config.data_limbs - 1) as usize; // Shift carries
        }
        cols += 1;                               // CMOV zero detection

        // Multi-limb arithmetic carry/borrow columns
        if config.data_limbs > 1 {
            cols += (config.data_limbs - 1) as usize; // ADD/ADDI carries
            cols += (config.data_limbs - 1) as usize; // SUB/SUBI borrows
        }

        // Bitwise chunk decomposition (6 chunks per limb)
        cols += 6 * config.data_limbs as usize;

        // Range check chunks (2 chunks per limb)
        cols += 2 * config.data_limbs as usize;

        // MUL hierarchical decomposition columns
        // Operand chunks: data_limbs * 2 (chunks per limb) * 2 (operands)
        cols += config.data_limbs as usize * 2 * 2;
        // Partial products: num_chunks^2 products × 2 (lo, hi for each)
        // num_chunks = data_limbs * 2
        let num_chunks = config.data_limbs as usize * 2;
        cols += num_chunks * num_chunks * 2;
        // Carries: (num_chunks - 1) positions × 3 hierarchical columns
        if num_chunks > 1 {
            cols += 3 * (num_chunks - 1);
        }

        // DIV/REM hierarchical decomposition columns
        // Comparison diff: data_limbs × 2 chunks
        cols += 2 * config.data_limbs as usize;
        // Product carry: 1 column
        cols += 1;

        // SHIFT hierarchical decomposition columns
        // Carry decomposition: (data_limbs - 1) × 2 chunks
        if config.data_limbs > 1 {
            cols += 2 * (config.data_limbs - 1) as usize;
        }

        // Register indicators (48: 16 rd + 16 rs1 + 16 rs2)
        cols += 48;

        cols
    }

    pub fn new(config: &ProgramConfig) -> Self {
        Self {
            count: Self::calculate_count(config),
        }
    }
}

/// Auxiliary trace columns (for RAP pattern)
///
/// These columns depend on the Fiat-Shamir challenge α and are computed
/// AFTER committing the main trace. They contain running products and sums
/// for LogUp and permutation arguments.
#[derive(Clone, Debug)]
pub struct AuxColumns {
    /// Number of auxiliary trace columns
    pub count: usize,
}

impl AuxColumns {
    /// Calculate number of auxiliary columns
    pub fn calculate_count(_config: &ProgramConfig) -> usize {
        let mut cols = 0;

        // Memory permutation products (execution + sorted)
        cols += 2;

        // LogUp query accumulators (AND, OR, XOR, range)
        cols += 4;

        // LogUp table accumulators (AND, OR, XOR, range)
        cols += 4;

        cols
    }

    pub fn new(config: &ProgramConfig) -> Self {
        Self {
            count: Self::calculate_count(config),
        }
    }
}

/// Main AIR for ZKIR v3.4 execution
///
/// This structure defines the trace columns and constraints for proving
/// correct execution of ZKIR programs.
///
/// ## RAP Pattern Support
///
/// The AIR now supports separation of main and auxiliary columns for proper
/// Fiat-Shamir challenge derivation:
/// - Main columns: Execution data (committed first)
/// - Auxiliary columns: Challenge-dependent accumulators (committed second)
///
/// ## Challenge Storage
///
/// When using true Fiat-Shamir (`prove_rap()`), the derived challenge is stored
/// here so that constraints use the same challenge as witness generation.
///
/// ## Column Access
///
/// Column indices are pre-computed once at construction time via `ColumnIndices`.
/// The `col_*` methods delegate to these cached indices for O(1) access.
#[derive(Clone, Debug)]
pub struct ZkIrAir {
    /// Program configuration (limb sizes, etc.)
    pub config: ProgramConfig,
    /// Main trace columns
    pub main_cols: MainColumns,
    /// Auxiliary trace columns
    pub aux_cols: AuxColumns,
    /// Total number of trace columns (main + aux, for backward compatibility)
    pub num_columns: usize,
    /// Optional RAP challenge (stored as u32 for type flexibility)
    /// When Some, this overrides the placeholder challenge.
    /// When None, placeholder challenges are used (legacy mode).
    pub rap_challenge: Option<u32>,
    /// Pre-computed column indices for efficient access
    indices: ColumnIndices,
}

impl ZkIrAir {
    /// Create a new ZKIR AIR with the given configuration
    ///
    /// Uses placeholder challenges (legacy mode). For production use with
    /// true Fiat-Shamir, use `new_with_challenge()`.
    pub fn new(config: ProgramConfig) -> Self {
        let main_cols = MainColumns::new(&config);
        let aux_cols = AuxColumns::new(&config);
        let num_columns = main_cols.count + aux_cols.count;
        let indices = ColumnIndices::new(&config);

        Self {
            config,
            main_cols,
            aux_cols,
            num_columns,
            rap_challenge: None,
            indices,
        }
    }

    /// Create a new ZKIR AIR with a true Fiat-Shamir challenge
    ///
    /// This constructor should be used by `prove_rap()` to ensure constraints
    /// use the same challenge that was used for auxiliary witness generation.
    ///
    /// # Arguments
    /// * `config` - Program configuration
    /// * `challenge` - The Fiat-Shamir challenge derived from main trace commitment
    pub fn new_with_challenge(config: ProgramConfig, challenge: u32) -> Self {
        let main_cols = MainColumns::new(&config);
        let aux_cols = AuxColumns::new(&config);
        let num_columns = main_cols.count + aux_cols.count;
        let indices = ColumnIndices::new(&config);

        Self {
            config,
            main_cols,
            aux_cols,
            num_columns,
            rap_challenge: Some(challenge),
            indices,
        }
    }

    /// Get access to pre-computed column indices
    ///
    /// Use this for direct access to column indices without method call overhead.
    #[inline]
    pub fn indices(&self) -> &ColumnIndices {
        &self.indices
    }

    /// Get the width of the main trace (RAP pattern)
    pub fn main_trace_width(&self) -> usize {
        self.main_cols.count
    }

    /// Get the width of the auxiliary trace (RAP pattern)
    pub fn aux_trace_width(&self) -> usize {
        self.aux_cols.count
    }

    /// Get the total width (main + auxiliary, for backward compatibility)
    pub fn total_width(&self) -> usize {
        self.num_columns
    }

    /// Get RAP challenges for constraint evaluation
    ///
    /// ## Behavior
    ///
    /// If `rap_challenge` is set (via `new_with_challenge()`), uses the stored
    /// Fiat-Shamir challenge for all challenge values. This ensures constraints
    /// use the same challenge as witness generation in `prove_rap()`.
    ///
    /// If `rap_challenge` is None, returns placeholder challenges (legacy mode).
    ///
    /// ## Example
    ///
    /// ```ignore
    /// // Legacy mode (placeholder challenges)
    /// let air = ZkIrAir::new(config);
    /// let challenges = air.challenges::<F>(); // Returns placeholders
    ///
    /// // RAP mode (true Fiat-Shamir)
    /// let air = ZkIrAir::new_with_challenge(config, alpha_u32);
    /// let challenges = air.challenges::<F>(); // Returns RapChallenges::from_single(alpha)
    /// ```
    pub fn challenges<F: FieldAlgebra>(&self) -> crate::constraints::challenges::RapChallenges<F> {
        match self.rap_challenge {
            Some(challenge) => {
                // Use the stored Fiat-Shamir challenge
                crate::constraints::challenges::RapChallenges::from_single(
                    F::from_canonical_u32(challenge)
                )
            }
            None => {
                // Fall back to placeholder challenges (legacy mode)
                crate::constraints::challenges::RapChallenges::placeholder()
            }
        }
    }

    /// Calculate the total number of trace columns needed
    ///
    /// Note: This function is kept for documentation purposes. The actual column
    /// count is computed by `MainColumns::calculate_count` and `AuxColumns::calculate_count`.
    ///
    /// Trace layout:
    /// - 1 column: PC (program counter)
    /// - 1 column: instruction (32-bit encoded)
    /// - 16 × data_limbs columns: registers (16 registers × limbs each)
    /// - 16 columns: register bounds (max_bits encoded as field element)
    /// - Memory operation columns
    /// - Auxiliary columns for instruction decoding
    /// - Auxiliary columns for complex operations
    #[allow(dead_code)]
    fn calculate_num_columns(config: &ProgramConfig) -> usize {
        let mut cols = 0;

        // PC
        cols += 1;

        // Instruction (32-bit encoded)
        cols += 1;

        // Registers (16 registers × limbs)
        cols += 16 * config.data_limbs as usize;

        // Register bounds (16 registers)
        cols += 16;

        // Memory address (addr_limbs)
        cols += config.addr_limbs as usize;

        // Memory value (data_limbs)
        cols += config.data_limbs as usize;

        // Memory flags (is_write, is_read)
        cols += 2;

        // --- Auxiliary columns for instruction decoding ---

        // Opcode (7 bits)
        cols += 1;

        // Decoded register indices (rd, rs1, rs2 - each 4 bits)
        cols += 3;

        // Immediate/funct field (17 bits for immediate values)
        // Store as single field element
        cols += 1;

        // Immediate flag (is_imm - indicates if instruction uses immediate)
        cols += 1;

        // Immediate sign bit (for sign extension)
        cols += 1;

        // --- Selector columns (instruction family indicators) ---

        // 10 boolean selectors (one per instruction family)
        // Arithmetic, Bitwise, Shift, Comparison, Cmov, Load, Store, Branch, Jump, System
        cols += 10;

        // --- Boolean opcode indicator columns ---

        // Bitwise indicators (7 columns: AND, OR, XOR, NOT, ANDI, ORI, XORI)
        cols += 7;

        // Load indicators (6 columns: LB, LBU, LH, LHU, LW, LD)
        cols += 6;

        // Store indicators (4 columns: SB, SH, SW, SD)
        cols += 4;

        // Arithmetic indicators (6 columns: ADD, SUB, MUL, ADDI, SUBI, MULI)
        cols += 6;

        // --- Auxiliary columns for complex operations ---

        // DIV/REM: quotient and remainder (data_limbs each)
        cols += 2 * config.data_limbs as usize;

        // Comparison flags: per-limb less-than flags (data_limbs)
        cols += config.data_limbs as usize;

        // Comparison flags: per-limb equality flags (data_limbs)
        cols += config.data_limbs as usize;

        // Branch condition result (boolean)
        cols += 1;

        // Shift operation: cross-limb carry values (data_limbs - 1)
        if config.data_limbs > 1 {
            cols += (config.data_limbs - 1) as usize;
        }

        // CMOVZ/CMOVNZ: zero detection flag
        cols += 1;

        // --- Auxiliary columns for bitwise operations ---

        // Chunk decomposition for bitwise ops (AND, OR, XOR)
        // Each limb needs 2 chunks for decomposition
        // For 3 operands (rs1, rs2, rd), we need 6 chunk columns per limb
        // Total: 6 * data_limbs
        cols += 6 * config.data_limbs as usize;

        // --- Range check chunk auxiliary columns ---

        // For range checking destination register values in arithmetic operations
        // Each limb needs 2 chunks (chunk_0, chunk_1) for decomposition
        // Total: 2 * data_limbs columns
        cols += 2 * config.data_limbs as usize;

        // --- Memory permutation accumulator columns ---

        // Running products for memory permutation argument (multiset equality)
        // - Execution order permutation: ∏(challenge - encoded_op) for ops in execution order
        // - Sorted order permutation: ∏(challenge - encoded_op) for ops in sorted order
        // At end of trace, these products should be equal (proving same multiset)
        // Total: 2 columns
        cols += 2;

        // --- LogUp accumulator columns ---

        // Query accumulators: Running sums for operation lookups
        // One accumulator per operation type (AND, OR, XOR, range check)
        // Each accumulator tracks: running_sum = Σ(1/(challenge - lookup_value))
        // Total: 4 columns (3 bitwise + 1 range check)
        cols += 4;

        // Table accumulators: Running sums for table side
        // One accumulator per lookup table (AND, OR, XOR, range check)
        // Each accumulator tracks: running_sum = Σ(multiplicity/(challenge - table_entry))
        // Total: 4 columns (3 bitwise + 1 range check)
        cols += 4;

        // --- Register indicator columns ---

        // Boolean indicators for dynamic register selection
        // For each instruction field (rd, rs1, rs2), we have 16 indicators
        // indicating which register is selected
        // Total: 48 columns (16 rd + 16 rs1 + 16 rs2)
        cols += 48;

        cols
    }

    /// Get column index for PC
    #[inline]
    pub fn col_pc(&self) -> usize {
        self.indices.pc
    }

    /// Get column index for instruction
    #[inline]
    pub fn col_instruction(&self) -> usize {
        self.indices.instruction
    }

    /// Get column index for register i, limb j
    #[inline]
    pub fn col_register(&self, reg_idx: usize, limb_idx: usize) -> usize {
        self.indices.register(reg_idx, limb_idx)
    }

    /// Get column index for register i's bound
    #[inline]
    pub fn col_register_bound(&self, reg_idx: usize) -> usize {
        self.indices.register_bound(reg_idx)
    }

    /// Get column index for memory address limb j
    #[inline]
    pub fn col_mem_addr(&self, limb_idx: usize) -> usize {
        self.indices.mem_addr(limb_idx)
    }

    /// Get column index for memory value limb j
    #[inline]
    pub fn col_mem_value(&self, limb_idx: usize) -> usize {
        self.indices.mem_value(limb_idx)
    }

    /// Get column index for memory write flag
    #[inline]
    pub fn col_mem_is_write(&self) -> usize {
        self.indices.mem_is_write
    }

    /// Get column index for memory read flag
    #[inline]
    pub fn col_mem_is_read(&self) -> usize {
        self.indices.mem_is_read
    }

    // --- Auxiliary columns for instruction decoding ---

    /// Get column index for decoded opcode (6 bits)
    #[inline]
    pub fn col_decoded_opcode(&self) -> usize {
        self.indices.decoded_opcode
    }

    /// Get column index for decoded rd (destination register, 4 bits)
    #[inline]
    pub fn col_decoded_rd(&self) -> usize {
        self.indices.decoded_rd
    }

    /// Get column index for decoded rs1 (source register 1, 4 bits)
    #[inline]
    pub fn col_decoded_rs1(&self) -> usize {
        self.indices.decoded_rs1
    }

    /// Get column index for decoded rs2 (source register 2, 4 bits)
    #[inline]
    pub fn col_decoded_rs2(&self) -> usize {
        self.indices.decoded_rs2
    }

    /// Get column index for immediate/funct field (17 bits)
    #[inline]
    pub fn col_decoded_imm_funct(&self) -> usize {
        self.indices.decoded_imm_funct
    }

    /// Get column index for is_imm flag (indicates if instruction uses immediate)
    #[inline]
    pub fn col_is_imm(&self) -> usize {
        self.indices.is_imm
    }

    /// Get column index for immediate sign bit (for sign extension)
    #[inline]
    pub fn col_imm_sign_bit(&self) -> usize {
        self.indices.imm_sign_bit
    }

    // --- Selector columns (instruction family indicators) ---

    /// Get column index for arithmetic instruction family selector
    /// Active (1) for: Add, Sub, Mul, Div, Rem, AddI, SubI, MulI (opcodes 0x00-0x07)
    #[inline]
    pub fn col_sel_arithmetic(&self) -> usize {
        self.indices.sel_arithmetic()
    }

    /// Get column index for bitwise instruction family selector
    /// Active (1) for: And, Or, Xor, Not, AndI, OrI, XorI (opcodes 0x10-0x16)
    #[inline]
    pub fn col_sel_bitwise(&self) -> usize {
        self.indices.sel_bitwise()
    }

    /// Get column index for shift instruction family selector
    /// Active (1) for: Sll, Srl, Sra, SllI, SrlI, SraI (opcodes 0x20-0x25)
    #[inline]
    pub fn col_sel_shift(&self) -> usize {
        self.indices.sel_shift()
    }

    /// Get column index for comparison instruction family selector
    /// Active (1) for: Slt, Sltu, Seq, Sne, SltI, SltuI (opcodes 0x30-0x35)
    #[inline]
    pub fn col_sel_comparison(&self) -> usize {
        self.indices.sel_comparison()
    }

    /// Get column index for conditional move instruction family selector
    /// Active (1) for: Cmov, Cmovz, Cmovnz (opcodes 0x40-0x42)
    #[inline]
    pub fn col_sel_cmov(&self) -> usize {
        self.indices.sel_cmov()
    }

    /// Get column index for load instruction family selector
    /// Active (1) for: Lb, Lbu, Lh, Lhu, Lw, Ld (opcodes 0x50-0x55)
    #[inline]
    pub fn col_sel_load(&self) -> usize {
        self.indices.sel_load()
    }

    /// Get column index for store instruction family selector
    /// Active (1) for: Sb, Sh, Sw, Sd (opcodes 0x58-0x5B)
    #[inline]
    pub fn col_sel_store(&self) -> usize {
        self.indices.sel_store()
    }

    /// Get column index for branch instruction family selector
    /// Active (1) for: Beq, Bne, Blt, Bge, Bltu, Bgeu (opcodes 0x60-0x65)
    #[inline]
    pub fn col_sel_branch(&self) -> usize {
        self.indices.sel_branch()
    }

    /// Get column index for jump instruction family selector
    /// Active (1) for: Jal, Jalr (opcodes 0x68-0x69)
    #[inline]
    pub fn col_sel_jump(&self) -> usize {
        self.indices.sel_jump()
    }

    /// Get column index for system instruction family selector
    /// Active (1) for: Ecall, Ebreak (opcodes 0x70-0x71)
    #[inline]
    pub fn col_sel_system(&self) -> usize {
        self.indices.sel_system()
    }

    // --- Boolean opcode indicator columns ---
    // These provide unambiguous opcode identification within instruction families
    // Each indicator is a boolean (0 or 1) set during witness generation

    /// Get column index for AND opcode indicator (boolean)
    #[inline]
    pub fn col_is_and(&self) -> usize {
        self.indices.is_and()
    }

    /// Get column index for OR opcode indicator (boolean)
    #[inline]
    pub fn col_is_or(&self) -> usize {
        self.indices.is_or()
    }

    /// Get column index for XOR opcode indicator (boolean)
    #[inline]
    pub fn col_is_xor(&self) -> usize {
        self.indices.is_xor()
    }

    /// Get column index for NOT opcode indicator (boolean)
    #[inline]
    pub fn col_is_not(&self) -> usize {
        self.indices.is_not()
    }

    /// Get column index for ANDI opcode indicator (boolean)
    #[inline]
    pub fn col_is_andi(&self) -> usize {
        self.indices.is_andi()
    }

    /// Get column index for ORI opcode indicator (boolean)
    #[inline]
    pub fn col_is_ori(&self) -> usize {
        self.indices.is_ori()
    }

    /// Get column index for XORI opcode indicator (boolean)
    #[inline]
    pub fn col_is_xori(&self) -> usize {
        self.indices.is_xori()
    }

    /// Get column index for LB opcode indicator (boolean)
    #[inline]
    pub fn col_is_lb(&self) -> usize {
        self.indices.is_lb()
    }

    /// Get column index for LBU opcode indicator (boolean)
    #[inline]
    pub fn col_is_lbu(&self) -> usize {
        self.indices.is_lbu()
    }

    /// Get column index for LH opcode indicator (boolean)
    #[inline]
    pub fn col_is_lh(&self) -> usize {
        self.indices.is_lh()
    }

    /// Get column index for LHU opcode indicator (boolean)
    #[inline]
    pub fn col_is_lhu(&self) -> usize {
        self.indices.is_lhu()
    }

    /// Get column index for LW opcode indicator (boolean)
    #[inline]
    pub fn col_is_lw(&self) -> usize {
        self.indices.is_lw()
    }

    /// Get column index for LD opcode indicator (boolean)
    #[inline]
    pub fn col_is_ld(&self) -> usize {
        self.indices.is_ld()
    }

    /// Get column index for SB opcode indicator (boolean)
    #[inline]
    pub fn col_is_sb(&self) -> usize {
        self.indices.is_sb()
    }

    /// Get column index for SH opcode indicator (boolean)
    #[inline]
    pub fn col_is_sh(&self) -> usize {
        self.indices.is_sh()
    }

    /// Get column index for SW opcode indicator (boolean)
    #[inline]
    pub fn col_is_sw(&self) -> usize {
        self.indices.is_sw()
    }

    /// Get column index for SD opcode indicator (boolean)
    #[inline]
    pub fn col_is_sd(&self) -> usize {
        self.indices.is_sd()
    }

    /// Get column index for ADD opcode indicator (boolean)
    #[inline]
    pub fn col_is_add(&self) -> usize {
        self.indices.is_add()
    }

    /// Get column index for SUB opcode indicator (boolean)
    #[inline]
    pub fn col_is_sub(&self) -> usize {
        self.indices.is_sub()
    }

    /// Get column index for MUL opcode indicator (boolean)
    #[inline]
    pub fn col_is_mul(&self) -> usize {
        self.indices.is_mul()
    }

    /// Get column index for ADDI opcode indicator (boolean)
    #[inline]
    pub fn col_is_addi(&self) -> usize {
        self.indices.is_addi()
    }

    /// Get column index for SUBI opcode indicator (boolean)
    #[inline]
    pub fn col_is_subi(&self) -> usize {
        self.indices.is_subi()
    }

    /// Get column index for MULI opcode indicator (boolean)
    #[inline]
    pub fn col_is_muli(&self) -> usize {
        self.indices.is_muli()
    }

    /// Get column index for DIV opcode indicator (boolean)
    #[inline]
    pub fn col_is_div(&self) -> usize {
        self.indices.is_div()
    }

    /// Get column index for REM opcode indicator (boolean)
    #[inline]
    pub fn col_is_rem(&self) -> usize {
        self.indices.is_rem()
    }

    /// Get column index for SLL opcode indicator (boolean)
    #[inline]
    pub fn col_is_sll(&self) -> usize {
        self.indices.is_sll()
    }

    /// Get column index for SRL opcode indicator (boolean)
    #[inline]
    pub fn col_is_srl(&self) -> usize {
        self.indices.is_srl()
    }

    /// Get column index for SRA opcode indicator (boolean)
    #[inline]
    pub fn col_is_sra(&self) -> usize {
        self.indices.is_sra()
    }

    /// Get column index for SLLI opcode indicator (boolean)
    #[inline]
    pub fn col_is_slli(&self) -> usize {
        self.indices.is_slli()
    }

    /// Get column index for SRLI opcode indicator (boolean)
    #[inline]
    pub fn col_is_srli(&self) -> usize {
        self.indices.is_srli()
    }

    /// Get column index for SRAI opcode indicator (boolean)
    #[inline]
    pub fn col_is_srai(&self) -> usize {
        self.indices.is_srai()
    }

    /// Get column index for CMOV opcode indicator (boolean)
    #[inline]
    pub fn col_is_cmov(&self) -> usize {
        self.indices.is_cmov()
    }

    /// Get column index for CMOVZ opcode indicator (boolean)
    #[inline]
    pub fn col_is_cmovz(&self) -> usize {
        self.indices.is_cmovz()
    }

    /// Get column index for CMOVNZ opcode indicator (boolean)
    #[inline]
    pub fn col_is_cmovnz(&self) -> usize {
        self.indices.is_cmovnz()
    }

    /// Get column index for SLT opcode indicator (boolean)
    #[inline]
    pub fn col_is_slt(&self) -> usize {
        self.indices.is_slt()
    }

    /// Get column index for SLTU opcode indicator (boolean)
    #[inline]
    pub fn col_is_sltu(&self) -> usize {
        self.indices.is_sltu()
    }

    /// Get column index for SEQ opcode indicator (boolean)
    #[inline]
    pub fn col_is_seq(&self) -> usize {
        self.indices.is_seq()
    }

    /// Get column index for SNE opcode indicator (boolean)
    #[inline]
    pub fn col_is_sne(&self) -> usize {
        self.indices.is_sne()
    }

    // --- Auxiliary columns for complex operations ---

    /// Get column index for division quotient limb j
    #[inline]
    pub fn col_div_quotient(&self, limb_idx: usize) -> usize {
        self.indices.div_quotient(limb_idx)
    }

    /// Get column index for division remainder limb j
    #[inline]
    pub fn col_div_remainder(&self, limb_idx: usize) -> usize {
        self.indices.div_remainder(limb_idx)
    }

    /// Get column index for per-limb less-than flag
    #[inline]
    pub fn col_cmp_lt_flag(&self, limb_idx: usize) -> usize {
        self.indices.cmp_lt_flag(limb_idx)
    }

    /// Get column index for per-limb equality flag
    #[inline]
    pub fn col_cmp_eq_flag(&self, limb_idx: usize) -> usize {
        self.indices.cmp_eq_flag(limb_idx)
    }

    /// Get column index for branch condition result (boolean)
    #[inline]
    pub fn col_branch_condition(&self) -> usize {
        self.indices.branch_condition
    }

    /// Get column index for shift cross-limb carry value
    #[inline]
    pub fn col_shift_carry(&self, limb_idx: usize) -> usize {
        self.indices.shift_carry(limb_idx)
    }

    /// Get column index for zero detection flag (CMOVZ/CMOVNZ)
    #[inline]
    pub fn col_zero_flag(&self) -> usize {
        self.indices.zero_flag
    }

    // --- Multi-limb arithmetic carry/borrow columns ---

    /// Get column index for ADD/ADDI carry at limb boundary
    ///
    /// carry[i] represents the carry from limb[i] to limb[i+1] during addition.
    /// For 2-limb arithmetic with 20-bit limbs:
    /// - carry[0] ∈ {0, 1}: set to 1 when rs1[0] + rs2[0] ≥ 2^20
    ///
    /// Constraint (for limb 0):
    ///   rd[0] + carry[0] * 2^20 = rs1[0] + rs2[0]
    ///
    /// Constraint (for limb 1):
    ///   rd[1] = rs1[1] + rs2[1] + carry[0]
    #[inline]
    pub fn col_add_carry(&self, limb_idx: usize) -> usize {
        self.indices.add_carry(limb_idx)
    }

    /// Get column index for SUB/SUBI borrow at limb boundary
    ///
    /// borrow[i] represents the borrow needed when rs1[i] < rs2[i].
    /// For 2-limb arithmetic with 20-bit limbs:
    /// - borrow[0] ∈ {0, 1}: set to 1 when rs1[0] < rs2[0]
    ///
    /// Constraint (for limb 0):
    ///   rd[0] = rs1[0] - rs2[0] + borrow[0] * 2^20
    ///
    /// Constraint (for limb 1):
    ///   rd[1] = rs1[1] - rs2[1] - borrow[0]
    #[inline]
    pub fn col_sub_borrow(&self, limb_idx: usize) -> usize {
        self.indices.sub_borrow(limb_idx)
    }

    // --- Auxiliary columns for bitwise operations ---

    /// Get column index for rs1 chunk 0 (low chunk) for given limb
    #[inline]
    pub fn col_bitwise_rs1_chunk0(&self, limb_idx: usize) -> usize {
        self.indices.bitwise_rs1_chunk0(limb_idx)
    }

    /// Get column index for rs1 chunk 1 (high chunk) for given limb
    #[inline]
    pub fn col_bitwise_rs1_chunk1(&self, limb_idx: usize) -> usize {
        self.indices.bitwise_rs1_chunk1(limb_idx)
    }

    /// Get column index for rs2 chunk 0 (low chunk) for given limb
    #[inline]
    pub fn col_bitwise_rs2_chunk0(&self, limb_idx: usize) -> usize {
        self.indices.bitwise_rs2_chunk0(limb_idx)
    }

    /// Get column index for rs2 chunk 1 (high chunk) for given limb
    #[inline]
    pub fn col_bitwise_rs2_chunk1(&self, limb_idx: usize) -> usize {
        self.indices.bitwise_rs2_chunk1(limb_idx)
    }

    /// Get column index for rd chunk 0 (low chunk) for given limb
    #[inline]
    pub fn col_bitwise_rd_chunk0(&self, limb_idx: usize) -> usize {
        self.indices.bitwise_rd_chunk0(limb_idx)
    }

    /// Get column index for rd chunk 1 (high chunk) for given limb
    #[inline]
    pub fn col_bitwise_rd_chunk1(&self, limb_idx: usize) -> usize {
        self.indices.bitwise_rd_chunk1(limb_idx)
    }

    // --- Range check chunk auxiliary columns ---

    /// Get column index for range check chunk 0 (low chunk) for given limb
    ///
    /// Used to decompose destination register limb values for range checking.
    /// For a 20-bit limb with 10-bit chunks: limb = chunk_0 + chunk_1 * 2^10
    #[inline]
    pub fn col_range_chunk0(&self, limb_idx: usize) -> usize {
        self.indices.range_chunk0(limb_idx)
    }

    /// Get column index for range check chunk 1 (high chunk) for given limb
    ///
    /// Used to decompose destination register limb values for range checking.
    /// For a 20-bit limb with 10-bit chunks: limb = chunk_0 + chunk_1 * 2^10
    #[inline]
    pub fn col_range_chunk1(&self, limb_idx: usize) -> usize {
        self.indices.range_chunk1(limb_idx)
    }

    // --- Memory permutation accumulator columns (AUXILIARY TRACE) ---

    /// Get column index for memory permutation accumulator (execution order)
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    ///
    /// Tracks running product: ∏(challenge - encoded_op) for memory operations
    /// in execution order. Used for multiset equality verification.
    #[inline]
    pub fn col_mem_perm_exec(&self) -> usize {
        self.indices.mem_perm_exec
    }

    /// Get column index for memory permutation accumulator (sorted order)
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    ///
    /// Tracks running product: ∏(challenge - encoded_op) for memory operations
    /// in sorted (address, timestamp) order. Should equal execution order product.
    #[inline]
    pub fn col_mem_perm_sorted(&self) -> usize {
        self.indices.mem_perm_sorted
    }

    // --- LogUp accumulator columns (AUXILIARY TRACE) ---

    /// Get column index for AND operation LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    #[inline]
    pub fn col_logup_and(&self) -> usize {
        self.indices.logup_and
    }

    /// Get column index for OR operation LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    #[inline]
    pub fn col_logup_or(&self) -> usize {
        self.indices.logup_or
    }

    /// Get column index for XOR operation LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    #[inline]
    pub fn col_logup_xor(&self) -> usize {
        self.indices.logup_xor
    }

    /// Get column index for range check LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    ///
    /// This column tracks the running sum for range check lookups:
    /// `sum += 1/(α - value)` for each value that needs range verification.
    ///
    /// Range checks verify that values are in [0, 2^limb_bits).
    #[inline]
    pub fn col_logup_range(&self) -> usize {
        self.indices.logup_range
    }

    // --- Table accumulator columns (AUXILIARY TRACE) ---

    /// Get column index for AND table LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    ///
    /// This column tracks the table side running sum:
    /// `sum += multiplicity/(α - encode(entry))` for all AND table entries.
    #[inline]
    pub fn col_logup_and_table(&self) -> usize {
        self.indices.logup_and_table
    }

    /// Get column index for OR table LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    #[inline]
    pub fn col_logup_or_table(&self) -> usize {
        self.indices.logup_or_table
    }

    /// Get column index for XOR table LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    #[inline]
    pub fn col_logup_xor_table(&self) -> usize {
        self.indices.logup_xor_table
    }

    /// Get column index for range check table LogUp accumulator
    ///
    /// **RAP Pattern**: This is an auxiliary column computed AFTER main trace commitment.
    ///
    /// This column tracks the table side running sum for range checks:
    /// `sum += multiplicity/(α - value)` for all valid range values [0, 2^limb_bits).
    #[inline]
    pub fn col_logup_range_table(&self) -> usize {
        self.indices.logup_range_table
    }

    // --- Register indicator columns (48 total: 16 × 3) ---

    /// Get column index for rd (destination register) indicator
    ///
    /// For each register index 0-15, there's a boolean column indicating
    /// whether that register is the destination for the current instruction.
    /// Exactly one indicator per row should be 1, the rest 0.
    ///
    /// # Arguments
    /// * `reg_idx` - Register index (0-15)
    ///
    /// # Returns
    /// Column index for rd_indicator[reg_idx]
    #[inline]
    pub fn col_rd_indicator(&self, reg_idx: usize) -> usize {
        self.indices.rd_indicator(reg_idx)
    }

    /// Get column index for rs1 (source register 1) indicator
    ///
    /// For each register index 0-15, there's a boolean column indicating
    /// whether that register is the first source for the current instruction.
    ///
    /// # Arguments
    /// * `reg_idx` - Register index (0-15)
    ///
    /// # Returns
    /// Column index for rs1_indicator[reg_idx]
    #[inline]
    pub fn col_rs1_indicator(&self, reg_idx: usize) -> usize {
        self.indices.rs1_indicator(reg_idx)
    }

    /// Get column index for rs2 (source register 2) indicator
    ///
    /// For each register index 0-15, there's a boolean column indicating
    /// whether that register is the second source for the current instruction.
    ///
    /// # Arguments
    /// * `reg_idx` - Register index (0-15)
    ///
    /// # Returns
    /// Column index for rs2_indicator[reg_idx]
    #[inline]
    pub fn col_rs2_indicator(&self, reg_idx: usize) -> usize {
        self.indices.rs2_indicator(reg_idx)
    }

    // --- MUL hierarchical decomposition columns ---

    /// Get column index for MUL rs1 operand chunk
    ///
    /// Each 20-bit limb is decomposed into two 10-bit chunks for MUL verification.
    ///
    /// # Arguments
    /// * `limb_idx` - Limb index (0..data_limbs)
    /// * `chunk_idx` - Chunk index (0 = low 10 bits, 1 = high 10 bits)
    #[inline]
    pub fn col_mul_rs1_chunk(&self, limb_idx: usize, chunk_idx: usize) -> usize {
        self.indices.mul_rs1_chunk(limb_idx, chunk_idx)
    }

    /// Get column index for MUL rs2 operand chunk
    ///
    /// Each 20-bit limb is decomposed into two 10-bit chunks for MUL verification.
    ///
    /// # Arguments
    /// * `limb_idx` - Limb index (0..data_limbs)
    /// * `chunk_idx` - Chunk index (0 = low 10 bits, 1 = high 10 bits)
    #[inline]
    pub fn col_mul_rs2_chunk(&self, limb_idx: usize, chunk_idx: usize) -> usize {
        self.indices.mul_rs2_chunk(limb_idx, chunk_idx)
    }

    /// Get column index for MUL partial product low part
    ///
    /// Each partial product aᵢ × bⱼ (20-bit) is decomposed into lo (10-bit) and hi (10-bit).
    ///
    /// # Arguments
    /// * `i` - Chunk index for rs1 (0..data_limbs*2)
    /// * `j` - Chunk index for rs2 (0..data_limbs*2)
    #[inline]
    pub fn col_mul_partial_lo(&self, i: usize, j: usize) -> usize {
        self.indices.mul_partial_lo(i, j)
    }

    /// Get column index for MUL partial product high part
    ///
    /// # Arguments
    /// * `i` - Chunk index for rs1 (0..data_limbs*2)
    /// * `j` - Chunk index for rs2 (0..data_limbs*2)
    #[inline]
    pub fn col_mul_partial_hi(&self, i: usize, j: usize) -> usize {
        self.indices.mul_partial_hi(i, j)
    }

    /// Get column index for MUL position carry chunk
    ///
    /// Carries between positions use hierarchical decomposition (up to 13 bits = 10+2+1).
    ///
    /// # Arguments
    /// * `position` - Position index (0..data_limbs)
    /// * `chunk_idx` - Chunk within carry (0 = 10-bit, 1 = 2-bit, 2 = 1-bit)
    #[inline]
    pub fn col_mul_carry(&self, position: usize, chunk_idx: usize) -> usize {
        self.indices.mul_carry(position, chunk_idx)
    }

    // --- DIV/REM hierarchical decomposition columns ---

    /// Get column index for DIV comparison diff chunk
    ///
    /// For verifying remainder < divisor: diff = divisor - remainder - 1
    /// Each 20-bit limb is decomposed into two 10-bit chunks.
    ///
    /// # Arguments
    /// * `limb_idx` - Limb index (0..data_limbs)
    /// * `chunk_idx` - Chunk index (0 = low 10 bits, 1 = high 10 bits)
    #[inline]
    pub fn col_div_cmp_diff_chunk(&self, limb_idx: usize, chunk_idx: usize) -> usize {
        self.indices.div_cmp_diff_chunk(limb_idx, chunk_idx)
    }

    /// Get column index for DIV product carry
    ///
    /// Boolean carry for (quotient × divisor) + remainder = dividend
    #[inline]
    pub fn col_div_product_carry(&self) -> usize {
        self.indices.div_product_carry
    }

    // --- SHIFT hierarchical decomposition columns ---

    /// Get column index for SHIFT carry chunk
    ///
    /// For variable shift amounts, the carry (bits crossing limb boundary) can be up to 20 bits.
    /// Decomposed as 10+10 per limb boundary.
    ///
    /// # Arguments
    /// * `boundary_idx` - Limb boundary index (0..data_limbs-1)
    /// * `chunk_idx` - Chunk index (0 = low 10 bits, 1 = high 10 bits)
    #[inline]
    pub fn col_shift_carry_chunk(&self, boundary_idx: usize, chunk_idx: usize) -> usize {
        self.indices.shift_carry_chunk(boundary_idx, chunk_idx)
    }
}

impl<F: Field> BaseAir<F> for ZkIrAir {
    fn width(&self) -> usize {
        self.num_columns
    }
}

impl<AB: AirBuilder> Air<AB> for ZkIrAir {
    fn eval(&self, builder: &mut AB) {
        // Get main trace
        let main = builder.main();
        let local = main.row_slice(0);
        let _local: &[AB::Var] = (*local).borrow();

        // Get next row for transition constraints
        let next = main.row_slice(1);
        let _next: &[AB::Var] = (*next).borrow();

        // Note: Actual constraint evaluation is handled by ZkIrAirAdapter
        // which calls the individual eval_* methods on ZkIrAir.
        // This impl exists for trait compliance but is not used directly.
        let _ = builder;
    }
}

impl ZkIrAir {
    /// Evaluate selector column constraints
    ///
    /// This ensures that:
    /// 1. Each selector is boolean (0 or 1)
    /// 2. At most one selector is active per row
    pub fn eval_selector_constraints<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        // Read all selector columns
        let sel_arithmetic: AB::Expr = local[self.col_sel_arithmetic()].into();
        let sel_bitwise: AB::Expr = local[self.col_sel_bitwise()].into();
        let sel_shift: AB::Expr = local[self.col_sel_shift()].into();
        let sel_comparison: AB::Expr = local[self.col_sel_comparison()].into();
        let sel_cmov: AB::Expr = local[self.col_sel_cmov()].into();
        let sel_load: AB::Expr = local[self.col_sel_load()].into();
        let sel_store: AB::Expr = local[self.col_sel_store()].into();
        let sel_branch: AB::Expr = local[self.col_sel_branch()].into();
        let sel_jump: AB::Expr = local[self.col_sel_jump()].into();
        let sel_system: AB::Expr = local[self.col_sel_system()].into();

        // 1. Boolean constraints: each selector s must satisfy s * (s - 1) = 0
        builder.assert_bool(sel_arithmetic.clone());
        builder.assert_bool(sel_bitwise.clone());
        builder.assert_bool(sel_shift.clone());
        builder.assert_bool(sel_comparison.clone());
        builder.assert_bool(sel_cmov.clone());
        builder.assert_bool(sel_load.clone());
        builder.assert_bool(sel_store.clone());
        builder.assert_bool(sel_branch.clone());
        builder.assert_bool(sel_jump.clone());
        builder.assert_bool(sel_system.clone());

        // 2. Mutual exclusion: at most one selector active
        // Sum all selectors and ensure the sum is also boolean (0 or 1)
        let total = sel_arithmetic + sel_bitwise + sel_shift + sel_comparison + sel_cmov
            + sel_load + sel_store + sel_branch + sel_jump + sel_system;
        builder.assert_bool(total);
    }

    /// Evaluate R0 hardwired-to-zero constraint (RISC-V compliance)
    ///
    /// RISC-V specification requires that R0 always reads as zero, and writes to R0 are ignored.
    /// This constraint enforces that R0 remains zero in both the current row and next row.
    ///
    /// For each limb of R0:
    /// - R0[limb] = 0 (current row)
    /// - R0[limb] = 0 (next row)
    pub fn eval_r0_zero_constraint<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
    ) {
        // Enforce R0 = 0 for all limbs in current row
        for limb_idx in 0..self.config.data_limbs as usize {
            let r0_col = self.col_register(0, limb_idx);
            let r0_local: AB::Expr = local[r0_col].into();
            builder.assert_zero(r0_local);
        }

        // Enforce R0 = 0 for all limbs in next row (transition constraint)
        for limb_idx in 0..self.config.data_limbs as usize {
            let r0_col = self.col_register(0, limb_idx);
            let r0_next: AB::Expr = next[r0_col].into();
            builder.assert_zero(r0_next);
        }
    }

    /// Evaluate execution constraints (instruction semantics)
    pub fn eval_execution_constraints<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
    ) {
        // Extract opcode from decoded instruction auxiliary column
        let opcode = local[self.col_decoded_opcode()];

        // Evaluate all instruction constraint families
        // Each method checks if the current opcode matches its instructions
        // and applies the appropriate constraints
        self.eval_arithmetic(builder, opcode, local, next);
        self.eval_logical(builder, opcode, local, next);
        self.eval_shift(builder, opcode, local, next);
        self.eval_comparison(builder, opcode, local, next);
        self.eval_cmov(builder, opcode, local, next);
        self.eval_load(builder, opcode, local, next);
        self.eval_store(builder, opcode, local, next);
        self.eval_branch(builder, opcode, local, next);
        self.eval_jump(builder, opcode, local, next);
        self.eval_syscall(builder, opcode, local, next);
    }

    /// Evaluate memory consistency constraints
    pub fn eval_memory_constraints<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
    ) {
        // Memory consistency constraints
        //
        // 1. Timestamp ordering: Operations to same address are chronologically ordered
        // 2. Read-write consistency: Reads see values from most recent write (TODO)
        // 3. Memory permutation: Verify all operations are accounted for (TODO)

        // Evaluate timestamp ordering constraints
        self.eval_memory_timestamp(builder, local, next);

        // Phase 2.1: Enable basic memory consistency constraints
        // This verifies:
        // - Memory flags are boolean (0 or 1)
        // - At most one of is_read/is_write is set per row
        // Full permutation argument (running products) will be added next
        self.eval_memory_consistency(builder, local, next);
    }

    /// Evaluate LogUp final sum verification (boundary constraint)
    ///
    /// This verifies that at the last row of the trace, the query accumulator
    /// matches the table accumulator for each lookup table (AND, OR, XOR, range check).
    ///
    /// **LogUp Protocol Final Check:**
    ///
    /// At the end of the trace, we must verify:
    /// ```text
    /// query_sum == table_sum
    /// ```
    ///
    /// Where:
    /// - `query_sum` = Σ(1/(α - encode(query))) over all queries
    /// - `table_sum` = Σ(multiplicity/(α - encode(entry))) over all table entries
    ///
    /// Current implementation:
    /// - Query accumulators tracked in 4 trace columns (updated in bitwise.rs, range_check.rs)
    /// - Table accumulator columns added (4 columns for AND, OR, XOR, range check)
    /// - Final sum verification constraints in place
    ///
    /// When fully implemented, this ensures that every query corresponds to a valid
    /// table entry, no queries were forged or modified, and the verification is
    /// cryptographically sound (based on Schwartz-Zippel lemma).
    ///
    /// TODO: Witness generation still needs to count multiplicity for each table entry,
    /// compute table sums, and update table accumulator columns throughout the trace.
    pub fn eval_logup_final_check<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        // Extract query sums from accumulator columns
        // These track the running sum of 1/(α - encode(query)) for all queries
        let query_sum_and: AB::Expr = local[self.col_logup_and()].into();
        let query_sum_or: AB::Expr = local[self.col_logup_or()].into();
        let query_sum_xor: AB::Expr = local[self.col_logup_xor()].into();
        let query_sum_range: AB::Expr = local[self.col_logup_range()].into();

        // Extract table sums from table accumulator columns
        // These track: table_sum = Σ(multiplicity/(α - encode(entry)))
        // where multiplicity is the number of times each table entry was queried
        let table_sum_and: AB::Expr = local[self.col_logup_and_table()].into();
        let table_sum_or: AB::Expr = local[self.col_logup_or_table()].into();
        let table_sum_xor: AB::Expr = local[self.col_logup_xor_table()].into();
        let table_sum_range: AB::Expr = local[self.col_logup_range_table()].into();

        // Verify that at the last row, query sums match table sums
        //
        // This is the core LogUp verification:
        // IF we're at the last row THEN query_sum MUST equal table_sum
        //
        // The `when_last_row()` method returns a FilteredAirBuilder that only
        // applies constraints on the final row of the trace.
        builder.when_last_row().assert_eq(query_sum_and, table_sum_and);
        builder.when_last_row().assert_eq(query_sum_or, table_sum_or);
        builder.when_last_row().assert_eq(query_sum_xor, table_sum_xor);
        builder.when_last_row().assert_eq(query_sum_range, table_sum_range);
    }
}

/// Builder for constructing constraints
///
/// This provides a high-level API for adding constraints to the AIR.
pub struct ConstraintBuilder<'a, AB: AirBuilder> {
    builder: &'a mut AB,
    air: &'a ZkIrAir,
}

impl<'a, AB: AirBuilder> ConstraintBuilder<'a, AB> {
    /// Create a new constraint builder
    #[allow(dead_code)]
    pub fn new(builder: &'a mut AB, air: &'a ZkIrAir) -> Self {
        Self { builder, air }
    }

    /// Assert that two expressions are equal
    #[allow(dead_code)]
    pub fn assert_eq<I1: Into<AB::Expr>, I2: Into<AB::Expr>>(&mut self, x: I1, y: I2) {
        self.builder.assert_eq(x, y);
    }

    /// Assert that an expression is zero
    #[allow(dead_code)]
    pub fn assert_zero<I: Into<AB::Expr>>(&mut self, x: I) {
        self.builder.assert_zero(x);
    }

    /// Assert that a value is boolean (0 or 1)
    #[allow(dead_code)]
    pub fn assert_bool<I: Into<AB::Expr>>(&mut self, x: I) {
        self.builder.assert_bool(x);
    }

    /// Get the AIR configuration
    #[allow(dead_code)]
    pub fn air(&self) -> &ZkIrAir {
        self.air
    }

    /// Get the underlying builder
    #[allow(dead_code)]
    pub fn builder(&mut self) -> &mut AB {
        self.builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::ProgramConfig;

    #[test]
    fn test_zkir_air_creation() {
        let config = ProgramConfig::DEFAULT;
        let air = ZkIrAir::new(config);

        assert_eq!(air.config.limb_bits, 20);
        assert_eq!(air.config.data_limbs, 2);
        assert!(air.num_columns > 0);
    }

    #[test]
    fn test_column_indices() {
        let config = ProgramConfig::DEFAULT;
        let air = ZkIrAir::new(config);

        // PC and instruction
        assert_eq!(air.col_pc(), 0);
        assert_eq!(air.col_instruction(), 1);

        // Registers
        assert_eq!(air.col_register(0, 0), 2);
        assert_eq!(air.col_register(0, 1), 3);
        assert_eq!(air.col_register(1, 0), 4);

        // Register bounds
        let bound_col = air.col_register_bound(0);
        assert!(bound_col > air.col_register(15, 1));
    }

    #[test]
    fn test_num_columns_calculation() {
        let config = ProgramConfig::DEFAULT;
        let air = ZkIrAir::new(config);

        // With default config (20-bit limbs, 2 data limbs, 2 addr limbs):
        // Base columns:
        //   1 (PC) + 1 (instruction) + 16*2 (registers) + 16 (bounds) +
        //   2 (mem addr) + 2 (mem value) + 2 (mem flags) = 56
        // Instruction decoding aux columns:
        //   1 (opcode) + 3 (rd,rs1,rs2) + 1 (imm/funct) + 1 (sign bit) = 6
        // Complex operation aux columns:
        //   2*2 (div quotient+remainder) + 2 (cmp lt flags) + 2 (cmp eq flags) +
        //   1 (branch cond) + 1 (shift carry for 2 limbs) + 1 (zero flag) = 11
        // Bitwise operation aux columns (chunk decomposition):
        //   6*2 (6 chunks per limb × 2 limbs) = 12
        // LogUp query accumulator columns: 4 (AND, OR, XOR, Range)
        // LogUp table accumulator columns: 4 (AND, OR, XOR, Range)
        // Selector columns: 10 (one per instruction family)
        // Boolean indicators: 19 (3 bitwise + 6 load + 4 store + 6 arithmetic)
        // Total: 56 + 7 + 10 + 11 + 12 + 2 + 4 + 4 + 19 = 125 (actual: 167 main + 10 aux = 177)
        // Plus MUL hierarchical columns: 8 operand + 32 partial products (4^2×2) + 9 carries ((4-1)×3) = 49
        // Plus DIV/REM hierarchical columns: 4 diff chunks + 1 product carry = 5
        // Plus SHIFT hierarchical columns: 2 carry decomp = 2
        // Total additional: 49 + 5 + 2 = 56
        assert_eq!(air.num_columns, 254); // +56 hierarchical decomposition columns (chunk-based MUL)
    }

    #[test]
    fn test_different_config() {
        let config = ProgramConfig::new(24, 3, 2).unwrap();
        let air = ZkIrAir::new(config);

        // Base columns (NOTE: addr_limbs = 2, data_limbs = 3):
        //   1 (PC) + 1 (instruction) + 16*3 (registers) + 16 (bounds) +
        //   2 (mem addr) + 3 (mem value) + 2 (mem flags) = 73
        // Instruction decoding aux columns: 7 (opcode, rd, rs1, rs2, imm, is_imm, sign_bit)
        // Complex operation aux columns with 3 data limbs:
        //   2*3 (div quotient+remainder) + 3 (cmp lt flags) + 3 (cmp eq flags) +
        //   1 (branch cond) + 2 (shift carry for 3 limbs) + 1 (zero flag) = 16
        // Bitwise operation aux columns (chunk decomposition):
        //   6*3 (6 chunks per limb × 3 limbs) = 18
        // Range check aux columns (chunk decomposition):
        //   2*3 (2 chunks per limb × 3 limbs) = 6
        // Memory permutation accumulators: 2 (execution + sorted order)
        // LogUp query accumulator columns: 4 (AND, OR, XOR, Range)
        // LogUp table accumulator columns: 4 (AND, OR, XOR, Range)
        // Selector columns: 10 (one per instruction family)
        // Boolean indicators: 13 (3 bitwise + 6 load + 4 store)
        // Total: 73 + 7 + 10 + 16 + 18 + 6 + 2 + 4 + 4 + 13 + 48 = 201
        // Plus MUL hierarchical columns: 12 operand + 72 partial (6^2×2) + 15 carries ((6-1)×3) = 99
        // Plus DIV/REM hierarchical columns: 6 diff chunks + 1 product carry = 7
        // Plus SHIFT hierarchical columns: 4 carry decomp = 4
        // Total additional: 99 + 7 + 4 = 110 (+ 1 extra for addr_limbs)
        // Note: addr_limbs = 2 here, so 1 fewer column than config with addr_limbs = 3
        assert_eq!(air.num_columns, 340); // +86 hierarchical decomposition columns for 3-limb (chunk-based MUL)
    }

    #[test]
    fn test_auxiliary_column_indices() {
        let config = ProgramConfig::DEFAULT; // 2 data limbs
        let air = ZkIrAir::new(config);

        // Test instruction decoding columns
        let opcode_col = air.col_decoded_opcode();
        let rd_col = air.col_decoded_rd();
        let rs1_col = air.col_decoded_rs1();
        let rs2_col = air.col_decoded_rs2();
        let imm_col = air.col_decoded_imm_funct();
        let sign_col = air.col_imm_sign_bit();

        // These should be sequential
        assert_eq!(rd_col, opcode_col + 1);
        assert_eq!(rs1_col, opcode_col + 2);
        assert_eq!(rs2_col, opcode_col + 3);
        assert_eq!(imm_col, opcode_col + 4);
        // is_imm is at opcode_col + 5 (not tested here, but exists)
        assert_eq!(sign_col, opcode_col + 6); // Was +5, now +6 with is_imm column

        // Test complex operation columns
        let quot_0 = air.col_div_quotient(0);
        let quot_1 = air.col_div_quotient(1);
        let rem_0 = air.col_div_remainder(0);
        let rem_1 = air.col_div_remainder(1);

        assert_eq!(quot_1, quot_0 + 1);
        assert_eq!(rem_0, quot_1 + 1);
        assert_eq!(rem_1, rem_0 + 1);

        // Test comparison flags
        let lt_0 = air.col_cmp_lt_flag(0);
        let lt_1 = air.col_cmp_lt_flag(1);
        let eq_0 = air.col_cmp_eq_flag(0);
        let eq_1 = air.col_cmp_eq_flag(1);

        assert_eq!(lt_1, lt_0 + 1);
        assert_eq!(eq_0, lt_1 + 1);
        assert_eq!(eq_1, eq_0 + 1);

        // Test branch condition
        let branch_cond = air.col_branch_condition();
        assert!(branch_cond > eq_1);

        // Test shift carry (for 2 limbs, should have 1 carry column)
        let shift_carry_0 = air.col_shift_carry(0);
        assert!(shift_carry_0 > branch_cond);

        // Test zero flag
        let zero_flag = air.col_zero_flag();
        assert!(zero_flag > shift_carry_0);
    }

    #[test]
    fn test_auxiliary_columns_ordering() {
        let config = ProgramConfig::DEFAULT;
        let air = ZkIrAir::new(config);

        // Verify all columns are in expected order and within bounds
        let mem_read = air.col_mem_is_read();
        let opcode = air.col_decoded_opcode();
        let sign_bit = air.col_imm_sign_bit();
        let zero_flag = air.col_zero_flag();

        // Auxiliary columns come after memory columns
        assert!(opcode > mem_read);

        // Instruction decoding columns come before complex operation columns
        assert!(sign_bit < air.col_div_quotient(0));

        // Zero flag comes before bitwise chunk columns
        assert!(zero_flag < air.col_bitwise_rs1_chunk0(0));

        // LogUp accumulator columns should be the last (8 total: 4 query + 4 table)
        let last_logup_query = air.col_logup_range();
        let last_logup_table = air.col_logup_range_table();
        assert_eq!(last_logup_table, air.num_columns - 1);

        // Bitwise chunk columns come before LogUp
        let last_bitwise = air.col_bitwise_rd_chunk1(air.config.data_limbs as usize - 1);
        assert!(last_bitwise < last_logup_query);

        // Query accumulators come before table accumulators
        assert!(last_logup_query < last_logup_table);
    }
}
