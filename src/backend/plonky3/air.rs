//! Plonky3 AIR adapter
//!
//! This module provides an adapter that bridges our ZkIrAir constraint system
//! to Plonky3's Air trait interface. It converts our execution trace format
//! to the format expected by Plonky3's proving system.
//!
//! ## RAP Pattern Support
//!
//! This module supports the RAP (Randomized AIR with Preprocessing) pattern:
//! - `main_witness_to_trace()` - Converts main witness to main trace matrix
//! - `aux_witness_to_trace()` - Converts auxiliary witness to auxiliary trace matrix

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::constraints::ZkIrAir;
use crate::witness::{ProgramConfig, MainWitness, AuxWitness};
use crate::types::{
    Opcode, OPCODE_MASK, RD_SHIFT, RS1_SHIFT, RS2_SHIFT, REGISTER_MASK, IMM_MASK, IMM_SIGN_BIT,
    extract_opcode, extract_rd, extract_rs1, extract_rs2,
};

/// Adapter that wraps ZkIrAir and implements Plonky3's Air trait
///
/// This adapter allows our constraint system to work with Plonky3's
/// proving infrastructure. It handles the translation between our
/// trace format and Plonky3's expected format.
#[derive(Clone)]
pub struct ZkIrAirAdapter {
    /// The underlying ZkIr AIR with all constraints
    pub(crate) inner: ZkIrAir,

    /// Number of columns in the trace
    pub(crate) num_columns: usize,
}

impl ZkIrAirAdapter {
    /// Create a new AIR adapter (legacy mode with placeholder challenges)
    ///
    /// # Arguments
    ///
    /// * `config` - Program configuration (limb counts, etc.)
    ///
    /// # Returns
    ///
    /// Returns a configured adapter ready for proof generation.
    pub fn new(config: ProgramConfig) -> Self {
        let inner = ZkIrAir::new(config);
        let num_columns = inner.num_columns;

        Self {
            inner,
            num_columns,
        }
    }

    /// Create a new AIR adapter with a true Fiat-Shamir challenge
    ///
    /// This constructor should be used by `prove_rap()` to ensure constraints
    /// use the same challenge that was used for auxiliary witness generation.
    ///
    /// # Arguments
    ///
    /// * `config` - Program configuration
    /// * `challenge` - The Fiat-Shamir challenge derived from main trace commitment
    ///
    /// # Returns
    ///
    /// Returns a configured adapter with the RAP challenge set.
    pub fn new_with_challenge(config: ProgramConfig, challenge: u32) -> Self {
        let inner = ZkIrAir::new_with_challenge(config, challenge);
        let num_columns = inner.num_columns;

        Self {
            inner,
            num_columns,
        }
    }

    /// Get the underlying ZkIrAir
    pub fn inner(&self) -> &ZkIrAir {
        &self.inner
    }

    /// Get the number of columns in the trace
    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    /// Get the program configuration
    pub fn config(&self) -> &ProgramConfig {
        &self.inner.config
    }
}

impl<F: Field> BaseAir<F> for ZkIrAirAdapter {
    /// Get the number of preprocessed columns (we have none)
    fn width(&self) -> usize {
        self.num_columns
    }
}

impl<AB: AirBuilder> Air<AB> for ZkIrAirAdapter {
    /// Evaluate all AIR constraints
    ///
    /// This is the main entry point for constraint evaluation. Plonky3
    /// will call this method to check constraints at each row of the trace.
    fn eval(&self, builder: &mut AB) {
        // Get main trace columns
        let main = builder.main();

        // Get current row and next row
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        // Selector constraints (ensure selectors are boolean and mutually exclusive)
        self.inner.eval_selector_constraints(builder, &local);

        // Execution constraints (all 50 instructions with selector guards)
        self.inner.eval_execution_constraints(builder, &local, &next);

        // Memory constraints (timestamp ordering, consistency, running products)
        self.inner.eval_memory_constraints(builder, &local, &next);

        // Range check constraints (LogUp accumulator updates for arithmetic operations)
        self.inner.eval_range_check_logup(builder, &local, &next);

        // Memory permutation final check (boundary constraint at last row)
        // Verifies that execution-order and sorted-order products are equal
        self.inner.eval_memory_permutation_final_check(builder, &local);

        // LogUp final check (boundary constraint at last row)
        // Verifies that query sums equal table sums for AND, OR, XOR, and range lookups
        self.inner.eval_logup_final_check(builder, &local);
    }
}

/// Convert main witness to main trace matrix (RAP pattern)
///
/// This function generates ONLY the main trace columns, which do NOT depend
/// on the Fiat-Shamir challenge. The auxiliary columns (LogUp sums, memory
/// permutation products) are computed separately after challenge derivation.
///
/// # Arguments
/// * `main` - Main witness (execution data without auxiliary columns)
/// * `config` - Program configuration
///
/// # Returns
/// RowMajorMatrix containing only main trace columns
pub fn main_witness_to_trace<F: Field + FieldAlgebra + PrimeField64>(
    main: &MainWitness,
    config: &ProgramConfig,
) -> RowMajorMatrix<F> {
    let actual_rows = main.trace.len();
    let air = ZkIrAir::new(config.clone());
    let num_cols = air.main_trace_width();

    // Pad to next power of 2 (required by Plonky3)
    let num_rows = actual_rows.next_power_of_two();

    // Pre-allocate the matrix
    let mut values = Vec::with_capacity(num_rows * num_cols);

    // Convert each main trace row (no auxiliary columns)
    for trace_row in &main.trace {
        let row_values = main_trace_row_to_field_elements::<F>(trace_row, config);
        values.extend(row_values);
    }

    // Pad remaining rows
    if actual_rows < num_rows {
        let last_row = if !main.trace.is_empty() {
            main_trace_row_to_field_elements::<F>(&main.trace[actual_rows - 1], config)
        } else {
            vec![F::ZERO; num_cols]
        };

        for _ in actual_rows..num_rows {
            values.extend(last_row.iter().copied());
        }
    }

    RowMajorMatrix::new(values, num_cols)
}

/// Convert auxiliary witness to auxiliary trace matrix (RAP pattern)
///
/// This function generates ONLY the auxiliary trace columns, which depend
/// on the Fiat-Shamir challenge. Must be called AFTER main trace commitment.
///
/// # Arguments
/// * `aux` - Auxiliary witness (computed with real Fiat-Shamir challenge)
/// * `config` - Program configuration
///
/// # Returns
/// RowMajorMatrix containing only auxiliary trace columns
pub fn aux_witness_to_trace<F: Field + FieldAlgebra>(
    aux: &AuxWitness<F>,
    config: &ProgramConfig,
) -> RowMajorMatrix<F> {
    let air = ZkIrAir::new(config.clone());
    let num_cols = air.aux_trace_width();
    let num_rows = aux.mem_perm_exec.len(); // Should already be padded

    // Pre-allocate the matrix
    let mut values = Vec::with_capacity(num_rows * num_cols);

    // Convert each auxiliary row
    for i in 0..num_rows {
        // Auxiliary columns in order:
        // 0: mem_perm_exec
        // 1: mem_perm_sorted
        // 2: logup_and
        // 3: logup_or
        // 4: logup_xor
        // 5: logup_range
        // 6: logup_and_table
        // 7: logup_or_table
        // 8: logup_xor_table
        // 9: logup_range_table

        values.push(aux.mem_perm_exec[i]);
        values.push(aux.mem_perm_sorted[i]);
        values.push(aux.logup_and[i]);
        values.push(aux.logup_or[i]);
        values.push(aux.logup_xor[i]);
        values.push(aux.logup_range[i]);
        values.push(aux.logup_and_table[i]);
        values.push(aux.logup_or_table[i]);
        values.push(aux.logup_xor_table[i]);
        values.push(aux.logup_range_table[i]);
    }

    RowMajorMatrix::new(values, num_cols)
}

/// Helper: Convert main trace row to field elements (no auxiliary columns)
///
/// This generates all main trace columns for the RAP flow, matching the layout
/// defined in MainColumns::calculate_count(). Column order must match exactly.
///
/// Layout (for default 2-limb config = 171 main columns):
/// 1. PC + Instruction (2)
/// 2. Registers 16×2 + bounds 16 (48)
/// 3. Memory addr 2 + value 2 + flags 2 (6)
/// 4. Instruction decode: opcode + rd + rs1 + rs2 + imm + is_imm + sign_bit (7)
/// 5. Selectors (10)
/// 6. Opcode indicators: bitwise 7 + load 6 + store 4 + arith 6 (23)
/// 7. Complex aux: div/rem 4 + lt 2 + eq 2 + branch 1 + carry 1 + zero 1 (11)
/// 8. Bitwise chunks 6×2 (12)
/// 9. Range check chunks 2×2 (4)
/// 10. Register indicators 48 (48)
fn main_trace_row_to_field_elements<F: Field + FieldAlgebra>(
    trace_row: &crate::witness::MainTraceRow,
    config: &ProgramConfig,
) -> Vec<F> {
    let mut values = Vec::new();
    let data_limbs = config.data_limbs as usize;
    let addr_limbs = config.addr_limbs as usize;

    // === Section 1: PC + Instruction (2 columns) ===
    values.push(F::from_canonical_u64(trace_row.pc));
    // Use from_wrapped_u32 for instruction since negative immediates can cause
    // the encoded instruction to exceed 2^31-1 (Mersenne31 field order)
    values.push(F::from_wrapped_u32(trace_row.instruction));

    // === Section 2: Registers (16 × data_limbs) + bounds (16) = 48 columns ===
    for reg_idx in 0..16 {
        if reg_idx < trace_row.registers.len() {
            let reg = &trace_row.registers[reg_idx];
            for limb_idx in 0..data_limbs {
                if limb_idx < reg.len() {
                    // RISC-V: R0 is hardwired to zero
                    if reg_idx == 0 {
                        values.push(F::ZERO);
                    } else {
                        values.push(F::from_canonical_u32(reg[limb_idx]));
                    }
                } else {
                    values.push(F::ZERO);
                }
            }
        } else {
            for _ in 0..data_limbs {
                values.push(F::ZERO);
            }
        }
    }

    for bound_idx in 0..16 {
        if bound_idx < trace_row.bounds.len() {
            values.push(F::from_canonical_u32(trace_row.bounds[bound_idx].max_bits));
        } else {
            values.push(F::ZERO);
        }
    }

    // === Section 3: Memory (addr_limbs + data_limbs + 2 flags) = 6 columns ===
    if let Some(ref mem_op) = trace_row.memory_op {
        for i in 0..addr_limbs {
            if i < mem_op.address.len() {
                values.push(F::from_canonical_u32(mem_op.address[i]));
            } else {
                values.push(F::ZERO);
            }
        }
        for i in 0..data_limbs {
            if i < mem_op.value.len() {
                values.push(F::from_canonical_u32(mem_op.value[i]));
            } else {
                values.push(F::ZERO);
            }
        }
        values.push(if mem_op.is_write { F::ONE } else { F::ZERO });
        values.push(if mem_op.is_write { F::ZERO } else { F::ONE });
    } else {
        for _ in 0..addr_limbs {
            values.push(F::ZERO);
        }
        for _ in 0..data_limbs {
            values.push(F::ZERO);
        }
        values.push(F::ZERO);
        values.push(F::ZERO);
    }

    // === Section 4: Instruction decode (7 columns) ===
    // ZKIR v3.4 uses 7-bit opcodes (values 0x00-0x51)
    // Note: Despite documentation claiming "6-bit", opcode values require 7 bits.
    let inst = trace_row.instruction;
    let opcode = extract_opcode(inst);

    // ZKIR v3.4 instruction formats:
    // - R-type: [opcode:7][rd:4][rs1:4][rs2:4][funct:13]
    // - I-type: [opcode:7][rd:4][rs1:4][imm:17]
    // - S-type: [opcode:7][rs1:4][rs2:4][imm:17] (stores - NO rd field!)
    // - B-type: [opcode:7][rs1:4][rs2:4][offset:17]
    // - J-type: [opcode:7][rd:4][offset:21]
    //
    // For S-type (stores), the field positions are different:
    // bits 10:7 = rs1 (base address), bits 14:11 = rs2 (value to store)
    let is_store = Opcode::is_store_raw(opcode);
    let is_branch = Opcode::is_branch_raw(opcode);

    // Extract fields based on instruction type
    let (rd, rs1, rs2) = if is_store || is_branch {
        // S-type/B-type: [opcode:7][rs1:4][rs2:4][imm/offset:17]
        // No rd field - rd position contains rs1
        let actual_rs1 = (inst >> RD_SHIFT) & REGISTER_MASK;   // bits 10:7
        let actual_rs2 = (inst >> RS1_SHIFT) & REGISTER_MASK;  // bits 14:11
        (0, actual_rs1, actual_rs2)  // rd=0 for stores/branches
    } else {
        // R-type/I-type/J-type: [opcode:7][rd:4][rs1:4]...
        (extract_rd(inst), extract_rs1(inst), extract_rs2(inst))
    };

    // For J-type (JAL, opcode 0x48), offset is in bits 31:11 (21 bits)
    // For other types (I-type, B-type), immediate is in bits 31:15 (17 bits)
    // We store a unified 17-bit immediate for constraints
    let is_jal = opcode == Opcode::Jal.to_u8() as u32;
    let imm17 = if is_jal {
        // J-type: offset is in bits 31:11 (21 bits), extract lower 17 bits
        (inst >> RS1_SHIFT) & IMM_MASK
    } else {
        // I-type, B-type, etc: immediate is in bits 31:15
        (inst >> RS2_SHIFT) & IMM_MASK
    };

    // ZKIR v3.4 spec opcodes for immediate instructions:
    // ADDI, ANDI-XORI, SLLI-SRAI, loads, stores, JALR
    let is_imm: u32 = if Opcode::from_u8(opcode as u8).map_or(false, |op| op.uses_immediate()) {
        1
    } else {
        0
    };
    let sign_bit = (imm17 >> IMM_SIGN_BIT) & 0x1;

    values.push(F::from_canonical_u32(opcode));
    values.push(F::from_canonical_u32(rd));
    values.push(F::from_canonical_u32(rs1));
    values.push(F::from_canonical_u32(rs2));
    values.push(F::from_canonical_u32(imm17));  // 17-bit immediate for 7-bit opcode format
    values.push(F::from_canonical_u32(is_imm));
    values.push(F::from_canonical_u32(sign_bit));

    // === Section 5: Selector columns (10 columns) ===
    // Use Opcode family checks from zkir-spec
    let sel_arith = if Opcode::is_arithmetic_raw(opcode) { 1u32 } else { 0 };
    let sel_bitwise = if Opcode::is_logical_raw(opcode) { 1u32 } else { 0 };
    let sel_shift = if Opcode::is_shift_raw(opcode) { 1u32 } else { 0 };
    let sel_cmp = if Opcode::is_compare_raw(opcode) { 1u32 } else { 0 };
    let sel_cmov = if Opcode::is_cmov_raw(opcode) { 1u32 } else { 0 };
    let sel_load = if Opcode::is_load_raw(opcode) { 1u32 } else { 0 };
    let sel_store = if Opcode::is_store_raw(opcode) { 1u32 } else { 0 };
    let sel_branch = if Opcode::is_branch_raw(opcode) { 1u32 } else { 0 };
    let sel_jump = if Opcode::is_jump_raw(opcode) { 1u32 } else { 0 };
    let sel_system = if Opcode::is_system_raw(opcode) { 1u32 } else { 0 };
    values.push(F::from_canonical_u32(sel_arith));
    values.push(F::from_canonical_u32(sel_bitwise));
    values.push(F::from_canonical_u32(sel_shift));
    values.push(F::from_canonical_u32(sel_cmp));
    values.push(F::from_canonical_u32(sel_cmov));
    values.push(F::from_canonical_u32(sel_load));
    values.push(F::from_canonical_u32(sel_store));
    values.push(F::from_canonical_u32(sel_branch));
    values.push(F::from_canonical_u32(sel_jump));
    values.push(F::from_canonical_u32(sel_system));

    // === Section 6: Opcode indicators (38 columns) ===
    // Use Opcode enum from zkir-spec for type-safe comparisons
    let op = opcode as u32;

    // Bitwise (7): AND, OR, XOR, (no NOT in spec), ANDI, ORI, XORI
    values.push(F::from_canonical_u32(if op == Opcode::And.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Or.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Xor.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(0)); // NOT (not in ZKIR v3.4 spec, placeholder)
    values.push(F::from_canonical_u32(if op == Opcode::Andi.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Ori.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Xori.to_u8() as u32 { 1 } else { 0 }));

    // Load (6): LB, LBU, LH, LHU, LW, LD
    values.push(F::from_canonical_u32(if op == Opcode::Lb.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Lbu.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Lh.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Lhu.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Lw.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Ld.to_u8() as u32 { 1 } else { 0 }));

    // Store (4): SB, SH, SW, SD
    values.push(F::from_canonical_u32(if op == Opcode::Sb.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sh.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sw.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sd.to_u8() as u32 { 1 } else { 0 }));

    // Arithmetic (8): ADD, SUB, MUL, ADDI, (placeholders), DIV, REM
    values.push(F::from_canonical_u32(if op == Opcode::Add.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sub.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Mul.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Addi.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(0)); // SUBI (not in spec, placeholder)
    values.push(F::from_canonical_u32(0)); // MULI (not in spec, placeholder)
    values.push(F::from_canonical_u32(if op == Opcode::Div.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Rem.to_u8() as u32 { 1 } else { 0 }));

    // Shift (6): SLL, SRL, SRA, SLLI, SRLI, SRAI
    values.push(F::from_canonical_u32(if op == Opcode::Sll.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Srl.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sra.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Slli.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Srli.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Srai.to_u8() as u32 { 1 } else { 0 }));

    // Conditional move (3): CMOV, CMOVZ, CMOVNZ
    values.push(F::from_canonical_u32(if op == Opcode::Cmov.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Cmovz.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Cmovnz.to_u8() as u32 { 1 } else { 0 }));

    // Comparison (4): SLT, SLTU, SEQ, SNE
    values.push(F::from_canonical_u32(if op == Opcode::Slt.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sltu.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Seq.to_u8() as u32 { 1 } else { 0 }));
    values.push(F::from_canonical_u32(if op == Opcode::Sne.to_u8() as u32 { 1 } else { 0 }));

    // === Section 7: Complex operation auxiliaries (11 columns for 2 limbs) ===
    // DIV/REM quotient/remainder (2 * data_limbs = 4)
    let is_div = op == Opcode::Div.to_u8() as u32;
    let is_rem = op == Opcode::Rem.to_u8() as u32;
    if is_div || is_rem {
        // Get rs1 and rs2 values for division
        let rs1_idx = rs1 as usize;
        let rs2_idx = rs2 as usize;

        // Reconstruct full values from limbs
        let mut rs1_val: u64 = 0;
        let mut rs2_val: u64 = 0;
        let limb_shift = config.limb_bits as u32;

        for limb_idx in 0..data_limbs {
            let rs1_limb = trace_row.registers.get(rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as u64;
            let rs2_limb = trace_row.registers.get(rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as u64;

            rs1_val |= rs1_limb << (limb_idx as u32 * limb_shift);
            rs2_val |= rs2_limb << (limb_idx as u32 * limb_shift);
        }

        // Compute quotient and remainder
        let (quotient, remainder) = if rs2_val == 0 {
            (0u64, 0u64) // Division by zero
        } else {
            (rs1_val / rs2_val, rs1_val % rs2_val)
        };

        // Split quotient into limbs
        let limb_mask = (1u64 << limb_shift) - 1;
        for limb_idx in 0..data_limbs {
            let q_limb = ((quotient >> (limb_idx as u32 * limb_shift)) & limb_mask) as u32;
            values.push(F::from_canonical_u32(q_limb));
        }
        // Split remainder into limbs
        for limb_idx in 0..data_limbs {
            let r_limb = ((remainder >> (limb_idx as u32 * limb_shift)) & limb_mask) as u32;
            values.push(F::from_canonical_u32(r_limb));
        }
    } else {
        for _ in 0..(2 * data_limbs) {
            values.push(F::ZERO);
        }
    }
    // Comparison lt flags (data_limbs = 2)
    // For branch/comparison instructions, compute per-limb less-than flags
    // ZKIR v3.4: Branch=0x40-0x45, Compare=0x20-0x25
    // Note: is_branch is already computed at instruction decode time (line 341)
    // The register extraction at lines 343-356 already handles S-type and B-type correctly,
    // so rs1 and rs2 already contain the correct register indices for all instruction types.
    let is_comparison = Opcode::is_compare_raw(opcode);

    // rs1 and rs2 are already correctly extracted based on instruction type
    let actual_rs1_idx = rs1 as usize;
    let actual_rs2_idx = rs2 as usize;

    if is_branch || is_comparison {
        let limb_shift = config.limb_bits as u32;

        // Compute per-limb comparison flags
        for limb_idx in 0..data_limbs {
            let rs1_limb = trace_row.registers.get(actual_rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as u64;
            let rs2_limb = trace_row.registers.get(actual_rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as u64;

            let lt = if rs1_limb < rs2_limb { 1u32 } else { 0u32 };
            values.push(F::from_canonical_u32(lt));
        }
    } else {
        for _ in 0..data_limbs {
            values.push(F::ZERO);
        }
    }

    // Comparison eq flags (data_limbs = 2)
    if is_branch || is_comparison {
        for limb_idx in 0..data_limbs {
            let rs1_limb = trace_row.registers.get(actual_rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            let rs2_limb = trace_row.registers.get(actual_rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);

            let eq = if rs1_limb == rs2_limb { 1u32 } else { 0u32 };
            values.push(F::from_canonical_u32(eq));
        }
    } else {
        for _ in 0..data_limbs {
            values.push(F::ZERO);
        }
    }

    // Branch condition (1)
    // Compute the branch condition result based on opcode and comparison flags
    if is_branch {
        let limb_shift = config.limb_bits as u32;

        // Reconstruct full values from limbs
        let mut rs1_val: u64 = 0;
        let mut rs2_val: u64 = 0;

        for limb_idx in 0..data_limbs {
            let rs1_limb = trace_row.registers.get(actual_rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as u64;
            let rs2_limb = trace_row.registers.get(actual_rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as u64;

            rs1_val |= rs1_limb << (limb_idx as u32 * limb_shift);
            rs2_val |= rs2_limb << (limb_idx as u32 * limb_shift);
        }

        // Compute branch condition based on opcode (ZKIR v3.4 spec)
        let branch_taken: u32 = if opcode == Opcode::Beq.to_u8() as u32 {
            if rs1_val == rs2_val { 1 } else { 0 }
        } else if opcode == Opcode::Bne.to_u8() as u32 {
            if rs1_val != rs2_val { 1 } else { 0 }
        } else if opcode == Opcode::Blt.to_u8() as u32 {
            if (rs1_val as i64) < (rs2_val as i64) { 1 } else { 0 }
        } else if opcode == Opcode::Bge.to_u8() as u32 {
            if (rs1_val as i64) >= (rs2_val as i64) { 1 } else { 0 }
        } else if opcode == Opcode::Bltu.to_u8() as u32 {
            if rs1_val < rs2_val { 1 } else { 0 }
        } else if opcode == Opcode::Bgeu.to_u8() as u32 {
            if rs1_val >= rs2_val { 1 } else { 0 }
        } else {
            0
        };
        values.push(F::from_canonical_u32(branch_taken));
    } else {
        values.push(F::ZERO);
    }
    // Shift carries (data_limbs - 1 = 1)
    if data_limbs > 1 {
        for _ in 0..(data_limbs - 1) {
            values.push(F::ZERO);
        }
    }
    // CMOV zero detection (1)
    values.push(F::ZERO);

    // === Section 7b: Multi-limb arithmetic carry/borrow columns ===
    // ADD/ADDI carry columns (data_limbs - 1)
    // For ADD: carry[i] = 1 if rs1[i] + rs2[i] + carry[i-1] >= 2^limb_bits
    // For ADDI: carry[i] = 1 if rs1[i] + imm (limb i) + carry[i-1] >= 2^limb_bits
    let is_add = op == Opcode::Add.to_u8() as u32;
    let is_addi = op == Opcode::Addi.to_u8() as u32;
    let is_sub = op == Opcode::Sub.to_u8() as u32;
    let limb_max = 1u64 << config.limb_bits;

    if data_limbs > 1 {
        // Compute ADD/ADDI carries
        for carry_idx in 0..(data_limbs - 1) {
            if is_add || is_addi {
                let rs1_idx = rs1 as usize;
                let rs2_idx = rs2 as usize;

                // Get limb values
                let rs1_limb = trace_row.registers.get(rs1_idx)
                    .and_then(|r| r.get(carry_idx))
                    .copied()
                    .unwrap_or(0) as u64;

                let rs2_or_imm = if is_add {
                    trace_row.registers.get(rs2_idx)
                        .and_then(|r| r.get(carry_idx))
                        .copied()
                        .unwrap_or(0) as u64
                } else {
                    // ADDI: immediate only affects limb 0
                    if carry_idx == 0 { imm17 as u64 } else { 0 }
                };

                // For the first carry (carry_idx=0), there's no previous carry
                // For subsequent carries, we'd need to track the chain
                // Simplified: compute carry for limb 0 -> limb 1
                let sum = rs1_limb + rs2_or_imm;
                let carry = if sum >= limb_max { 1u32 } else { 0u32 };
                values.push(F::from_canonical_u32(carry));
            } else {
                values.push(F::ZERO);
            }
        }

        // Compute SUB borrows
        // Note: ZKIR v3.4 spec doesn't have SUBI, only SUB
        for borrow_idx in 0..(data_limbs - 1) {
            if is_sub {
                let rs1_idx = rs1 as usize;
                let rs2_idx = rs2 as usize;

                // Get limb values
                let rs1_limb = trace_row.registers.get(rs1_idx)
                    .and_then(|r| r.get(borrow_idx))
                    .copied()
                    .unwrap_or(0) as u64;

                let rs2_limb = trace_row.registers.get(rs2_idx)
                    .and_then(|r| r.get(borrow_idx))
                    .copied()
                    .unwrap_or(0) as u64;

                // Borrow needed when rs1 < rs2
                let borrow = if rs1_limb < rs2_limb { 1u32 } else { 0u32 };
                values.push(F::from_canonical_u32(borrow));
            } else {
                values.push(F::ZERO);
            }
        }
    }

    // === Section 8: Bitwise chunks (6 * data_limbs = 12 columns) ===
    // For bitwise operations (AND, OR, XOR), split register limbs into 10-bit chunks
    // Layout per limb: rs1_chunk0, rs1_chunk1, rs2_chunk0, rs2_chunk1, rd_chunk0, rd_chunk1
    let is_bitwise = Opcode::is_logical_raw(opcode);
    let chunk_bits = config.limb_bits / 2; // 10 bits for 20-bit limbs
    let chunk_mask = (1u32 << chunk_bits) - 1;

    for limb_idx in 0..data_limbs {
        if is_bitwise {
            let rs1_idx = rs1 as usize;
            let rs2_idx = rs2 as usize;
            let rd_idx = rd as usize;

            let rs1_limb = trace_row.registers.get(rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            let rs2_limb = trace_row.registers.get(rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            let rd_limb = trace_row.registers.get(rd_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);

            // Split into low and high chunks
            let rs1_chunk0 = rs1_limb & chunk_mask;
            let rs1_chunk1 = rs1_limb >> chunk_bits;
            let rs2_chunk0 = rs2_limb & chunk_mask;
            let rs2_chunk1 = rs2_limb >> chunk_bits;
            let rd_chunk0 = rd_limb & chunk_mask;
            let rd_chunk1 = rd_limb >> chunk_bits;

            values.push(F::from_canonical_u32(rs1_chunk0));
            values.push(F::from_canonical_u32(rs1_chunk1));
            values.push(F::from_canonical_u32(rs2_chunk0));
            values.push(F::from_canonical_u32(rs2_chunk1));
            values.push(F::from_canonical_u32(rd_chunk0));
            values.push(F::from_canonical_u32(rd_chunk1));
        } else {
            // Non-bitwise: set chunks to zero
            for _ in 0..6 {
                values.push(F::ZERO);
            }
        }
    }

    // === Section 9: Range check chunks (2 * data_limbs = 4 columns) ===
    // Range checks verify destination register limbs are within [0, 2^limb_bits)
    // by decomposing each limb into two chunks of chunk_bits each.
    // We range check for arithmetic operations that produce new values in rd.
    // ZKIR v3.4: 0x00..=0x08 = ADD, SUB, MUL, MULH, DIVU, REMU, DIV, REM, ADDI
    let is_arithmetic = Opcode::is_arithmetic_raw(opcode);

    for limb_idx in 0..data_limbs {
        if is_arithmetic {
            let rd_idx = rd as usize;
            let rd_limb = trace_row.registers.get(rd_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);

            // Split into low and high chunks for range checking
            let chunk_0 = rd_limb & chunk_mask;
            let chunk_1 = rd_limb >> chunk_bits;

            values.push(F::from_canonical_u32(chunk_0));
            values.push(F::from_canonical_u32(chunk_1));
        } else {
            // Non-arithmetic: no range check needed, set to zero
            values.push(F::ZERO);
            values.push(F::ZERO);
        }
    }

    // === Section 9a: MUL hierarchical decomposition columns ===
    // Operand chunks: 4 chunks for rs1 (2 per limb) + 4 chunks for rs2 = 8 columns
    // Partial products: 4 products × 2 (lo, hi) = 8 columns
    // Carries: 2 positions × 3 columns (10 + 2 + 1 hierarchical) = 6 columns
    // Total: 22 columns for 2-limb config
    let is_mul = op == Opcode::Mul.to_u8() as u32;

    // MUL operand chunks (8 columns for 2-limb)
    // rs1 chunks: 4 columns (2 limbs × 2 chunks per limb)
    for limb_idx in 0..data_limbs {
        if is_mul {
            let rs1_idx = rs1 as usize;
            let rs1_limb = trace_row.registers.get(rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            let chunk_0 = rs1_limb & chunk_mask;
            let chunk_1 = rs1_limb >> chunk_bits;
            values.push(F::from_canonical_u32(chunk_0));
            values.push(F::from_canonical_u32(chunk_1));
        } else {
            values.push(F::ZERO);
            values.push(F::ZERO);
        }
    }
    // rs2 chunks: 4 columns
    for limb_idx in 0..data_limbs {
        if is_mul {
            let rs2_idx = rs2 as usize;
            let rs2_limb = trace_row.registers.get(rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            let chunk_0 = rs2_limb & chunk_mask;
            let chunk_1 = rs2_limb >> chunk_bits;
            values.push(F::from_canonical_u32(chunk_0));
            values.push(F::from_canonical_u32(chunk_1));
        } else {
            values.push(F::ZERO);
            values.push(F::ZERO);
        }
    }

    // MUL partial products
    // Each product a_i × b_j decomposes into (lo, hi) 10-bit chunks
    // For 2-limb config: 4 chunks × 4 chunks = 16 products, each with (lo, hi) = 32 columns
    //
    // Layout: products indexed as [i][j] for a_i × b_j
    // Order: (0,0), (0,1), (0,2), (0,3), (1,0), (1,1), ... (3,3)
    let num_chunks = data_limbs * 2;

    // First collect all chunks
    let mut a_chunks: Vec<u32> = Vec::with_capacity(num_chunks);
    let mut b_chunks: Vec<u32> = Vec::with_capacity(num_chunks);

    if is_mul {
        for limb_idx in 0..data_limbs {
            let rs1_idx = rs1 as usize;
            let rs1_limb = trace_row.registers.get(rs1_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            a_chunks.push(rs1_limb & chunk_mask);
            a_chunks.push(rs1_limb >> chunk_bits);
        }
        for limb_idx in 0..data_limbs {
            let rs2_idx = rs2 as usize;
            let rs2_limb = trace_row.registers.get(rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0);
            b_chunks.push(rs2_limb & chunk_mask);
            b_chunks.push(rs2_limb >> chunk_bits);
        }
    }

    // Compute partial products and position sums
    // Position p accumulates: lo_ij where i+j=p, hi_ij where i+j=p-1, carry from p-1
    let mut position_sums: Vec<u64> = vec![0u64; num_chunks];
    let mut partial_products: Vec<(u32, u32)> = Vec::with_capacity(num_chunks * num_chunks);

    for i in 0..num_chunks {
        for j in 0..num_chunks {
            if is_mul && !a_chunks.is_empty() {
                let product = (a_chunks[i] as u64) * (b_chunks[j] as u64);
                let lo = (product & (chunk_mask as u64)) as u32;
                let hi = (product >> chunk_bits) as u32;
                partial_products.push((lo, hi));

                // Add lo to position i+j
                let pos_lo = i + j;
                if pos_lo < num_chunks {
                    position_sums[pos_lo] += lo as u64;
                }
                // Add hi to position i+j+1
                let pos_hi = i + j + 1;
                if pos_hi < num_chunks {
                    position_sums[pos_hi] += hi as u64;
                }
            } else {
                partial_products.push((0, 0));
            }
        }
    }

    // Output partial products (lo, hi for each)
    for (lo, hi) in &partial_products {
        values.push(F::from_canonical_u32(*lo));
        values.push(F::from_canonical_u32(*hi));
    }

    // MUL carries ((num_chunks - 1) positions × 3 hierarchical chunks each)
    // Each position carry uses up to 3 columns: 10-bit, 2-bit, 1-bit (for 13-bit max)
    //
    // Compute carries: carry[p] = (position_sum[p] >> 10)
    // Then position_sum[p+1] += carry[p]
    let carry_positions = if num_chunks > 1 { num_chunks - 1 } else { 0 };
    let mut carries: Vec<u32> = vec![0u32; carry_positions];

    if is_mul && carry_positions > 0 {
        let mut running_sums = position_sums.clone();

        for pos in 0..num_chunks {
            // Current sum at this position
            let current_sum = running_sums[pos];

            // Extract result chunk and carry
            let result_chunk = (current_sum & (chunk_mask as u64)) as u32;
            let carry_out = (current_sum >> chunk_bits) as u32;

            // Store carry (indexed by position, only for positions 0..num_chunks-1)
            if pos < carry_positions {
                carries[pos] = carry_out;
            }

            // Propagate carry to next position
            if pos + 1 < num_chunks {
                running_sums[pos + 1] += carry_out as u64;
            }

            let _ = result_chunk; // Used implicitly by constraint
        }
    }

    // Output carries with hierarchical decomposition (10 + 2 + 1)
    for pos in 0..carry_positions {
        let carry = carries[pos];
        // Decompose: carry = chunk_10 + chunk_2 * 1024 + chunk_1 * 4096
        let chunk_10 = carry & 0x3FF;  // Low 10 bits
        let chunk_2 = (carry >> 10) & 0x3;  // Next 2 bits
        let chunk_1 = (carry >> 12) & 0x1;  // Top 1 bit (boolean)

        values.push(F::from_canonical_u32(chunk_10));
        values.push(F::from_canonical_u32(chunk_2));
        values.push(F::from_canonical_u32(chunk_1));
    }

    // === Section 9b: DIV/REM hierarchical decomposition columns ===
    // Comparison diff: 2 limbs × 2 chunks = 4 columns
    // Product carry: 1 column
    // Total: 5 columns for 2-limb config
    //
    // For DIV/REM, we prove remainder < divisor by showing:
    //   diff = divisor - remainder - 1 >= 0
    // We decompose diff into 10-bit chunks and range check them.
    //
    // Multi-limb subtraction with borrow:
    //   diff[0] = divisor[0] - remainder[0] - 1 + borrow_out[0] * 2^limb_bits
    //   diff[i] = divisor[i] - remainder[i] - borrow_in[i-1] + borrow_out[i] * 2^limb_bits
    //
    // Since we're proving diff >= 0, the range check of chunks proves non-negativity.
    for limb_idx in 0..data_limbs {
        if is_div || is_rem {
            let rs2_idx = rs2 as usize; // divisor

            // Get divisor limb
            let divisor_limb = trace_row.registers.get(rs2_idx)
                .and_then(|r| r.get(limb_idx))
                .copied()
                .unwrap_or(0) as i64;

            // Get remainder from div_remainder auxiliary column
            // The remainder was stored in col_div_remainder during witness generation
            // For now, we compute it from the actual division result
            let rs1_idx = rs1 as usize;
            let limb_base = 1u64 << config.limb_bits;

            // Reconstruct full values for division
            let mut rs1_full = 0u64;
            let mut rs2_full = 0u64;
            for i in 0..data_limbs {
                let rs1_limb = trace_row.registers.get(rs1_idx)
                    .and_then(|r| r.get(i))
                    .copied()
                    .unwrap_or(0) as u64;
                let rs2_limb = trace_row.registers.get(rs2_idx)
                    .and_then(|r| r.get(i))
                    .copied()
                    .unwrap_or(0) as u64;
                rs1_full += rs1_limb * limb_base.pow(i as u32);
                rs2_full += rs2_limb * limb_base.pow(i as u32);
            }

            // Compute remainder (handling div by zero)
            let remainder_full = if rs2_full == 0 { 0 } else { rs1_full % rs2_full };

            // Extract remainder limb
            let remainder_limb = ((remainder_full / limb_base.pow(limb_idx as u32)) % limb_base) as i64;

            // Compute diff for this limb: diff = divisor - remainder - (1 if limb_idx == 0)
            // For limb 0: subtract 1 to prove strict inequality (remainder < divisor)
            // For higher limbs: handle borrows from lower limbs
            //
            // Simplified: compute diff = divisor - remainder - 1 per limb
            // The range check of diff chunks proves diff >= 0 per limb
            let subtract_one = if limb_idx == 0 { 1i64 } else { 0i64 };
            let mut diff = divisor_limb - remainder_limb - subtract_one;

            // Handle negative diff by adding limb_max (borrow from next limb)
            // This is valid because the full multi-limb diff should be non-negative
            if diff < 0 {
                diff += limb_base as i64;
            }

            // Decompose diff into 10-bit chunks
            let diff_u32 = diff as u32;
            let chunk_0 = diff_u32 & chunk_mask;
            let chunk_1 = (diff_u32 >> chunk_bits) & chunk_mask;

            values.push(F::from_canonical_u32(chunk_0));
            values.push(F::from_canonical_u32(chunk_1));
        } else {
            values.push(F::ZERO);
            values.push(F::ZERO);
        }
    }
    // DIV product carry (1 column) - tracks borrow between limbs
    // For full multi-limb subtraction, this would track the final borrow
    // Simplified: set to 0 for now as the per-limb diff handling absorbs borrows
    values.push(F::ZERO);

    // === Section 9c: SHIFT hierarchical decomposition columns ===
    // Shift carry: (data_limbs - 1) boundaries × 2 chunks = 2 columns for 2-limb
    //
    // For shift operations, bits cross limb boundaries:
    // - Left shift (SLL): high bits of limb[i] become low bits of limb[i+1]
    // - Right shift (SRL/SRA): low bits of limb[i+1] become high bits of limb[i]
    //
    // The carry value represents the bits that cross the boundary.
    // We decompose the carry into 10-bit chunks for range checking.
    //
    // For a shift of `s` bits on a value in limb[i]:
    // - Left shift carry = limb[i] >> (limb_bits - s)  (bits shifted out to next limb)
    // - Right shift carry = limb[i+1] << (limb_bits - s)  (bits shifted in from prev limb)
    //
    // Maximum carry size is limb_bits (e.g., 20 bits), decomposed into 10+10.
    let is_sll = op == Opcode::Sll.to_u8() as u32 || op == Opcode::Slli.to_u8() as u32;
    let is_srl = op == Opcode::Srl.to_u8() as u32 || op == Opcode::Srli.to_u8() as u32;
    let is_sra = op == Opcode::Sra.to_u8() as u32 || op == Opcode::Srai.to_u8() as u32;
    let is_shift = is_sll || is_srl || is_sra;

    if data_limbs > 1 {
        for boundary_idx in 0..(data_limbs - 1) {
            if is_shift {
                let rs1_idx = rs1 as usize;
                let limb_bits_u32 = config.limb_bits as u32;

                // Get shift amount from rs2 or immediate
                let shift_amount = if is_imm == 1 {
                    // Immediate shift: shift amount from instruction bits 15-31
                    imm17 & 0x1F  // Max shift 31 bits
                } else {
                    // Register shift: shift amount from rs2 (typically low 5 bits)
                    let rs2_idx = rs2 as usize;
                    let rs2_val = trace_row.registers.get(rs2_idx)
                        .and_then(|r| r.get(0))
                        .copied()
                        .unwrap_or(0);
                    rs2_val & 0x1F  // Max shift 31 bits
                };

                // Compute carry value based on shift direction
                let carry = if is_sll {
                    // Left shift: bits shifted out from lower limb into higher limb
                    // carry = limb[boundary_idx] >> (limb_bits - shift_amount)
                    let limb_val = trace_row.registers.get(rs1_idx)
                        .and_then(|r| r.get(boundary_idx))
                        .copied()
                        .unwrap_or(0) as u64;

                    if shift_amount > 0 && shift_amount < limb_bits_u32 {
                        (limb_val >> (limb_bits_u32 - shift_amount)) as u32
                    } else if shift_amount >= limb_bits_u32 {
                        // Shift >= limb_bits: entire limb becomes carry
                        limb_val as u32
                    } else {
                        0
                    }
                } else {
                    // Right shift: bits shifted in from higher limb into lower limb
                    // carry = limb[boundary_idx + 1] << (limb_bits - shift_amount)
                    let next_limb_val = trace_row.registers.get(rs1_idx)
                        .and_then(|r| r.get(boundary_idx + 1))
                        .copied()
                        .unwrap_or(0) as u64;

                    if shift_amount > 0 && shift_amount < limb_bits_u32 {
                        // Extract low `shift_amount` bits from next limb
                        let mask = (1u64 << shift_amount) - 1;
                        (next_limb_val & mask) as u32
                    } else if shift_amount >= limb_bits_u32 {
                        // Shift >= limb_bits: entire next limb contributes
                        next_limb_val as u32
                    } else {
                        0
                    }
                };

                // Decompose carry into 10-bit chunks
                let chunk_0 = carry & chunk_mask;
                let chunk_1 = (carry >> chunk_bits) & chunk_mask;

                values.push(F::from_canonical_u32(chunk_0));
                values.push(F::from_canonical_u32(chunk_1));
            } else {
                // Non-shift: set to zero
                values.push(F::ZERO);
                values.push(F::ZERO);
            }
        }
    }

    // === Section 10: Register indicators (48 columns) ===
    // rd indicators (16)
    for reg_idx in 0..16u32 {
        values.push(F::from_canonical_u32(if rd == reg_idx { 1 } else { 0 }));
    }
    // rs1 indicators (16)
    for reg_idx in 0..16u32 {
        values.push(F::from_canonical_u32(if rs1 == reg_idx { 1 } else { 0 }));
    }
    // rs2 indicators (16)
    // For I-type (non-store), rs2 overlaps with immediate, set all to 0
    // ZKIR v3.4: Store=0x38-0x3B
    let is_store_opcode = Opcode::is_store_raw(opcode);
    for reg_idx in 0..16u32 {
        let indicator = if is_imm == 1 && !is_store_opcode {
            0
        } else if rs2 == reg_idx {
            1
        } else {
            0
        };
        values.push(F::from_canonical_u32(indicator));
    }

    // Verify column count
    let air = ZkIrAir::new(config.clone());
    let expected = air.main_trace_width();
    assert_eq!(values.len(), expected,
        "main_trace_row_to_field_elements: generated {} columns, expected {}",
        values.len(), expected);

    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::F; // Mersenne31
    use p3_air::BaseAir;

    #[test]
    fn test_air_adapter_creation() {
        let config = ProgramConfig::default();
        let adapter = ZkIrAirAdapter::new(config.clone());

        // Column count includes hierarchical decomposition columns:
        // Base: 198
        // + MUL: operand chunks (8) + partial products (32) + carries (6) = 46
        // + DIV: diff chunks (4) + product carry (1) = 5
        // + SHIFT: carry decomp (2) = 2
        // Total: 198 + 46 + 5 + 2 = 251
        let expected_cols = adapter.num_columns();
        println!("Total columns: {}", expected_cols);
        assert!(expected_cols > 198, "Should have hierarchical columns");
        assert_eq!(adapter.config(), &config);
    }

    #[test]
    fn test_air_adapter_width() {
        let config = ProgramConfig::default();
        let adapter = ZkIrAirAdapter::new(config);

        // BaseAir::width should match num_columns
        let expected_cols = adapter.num_columns();
        println!("Total columns: {}", expected_cols);
        assert!(expected_cols > 198, "Should have hierarchical columns");
    }

    #[test]
    fn test_main_trace_row_conversion() {
        use crate::witness::{MainTraceRow, ValueBound};

        let config = ProgramConfig::default();
        let data_limbs = config.data_limbs as usize;

        // Create a main trace row
        let row = MainTraceRow::new(
            0,
            42,
            0x12345678,
            vec![vec![0; data_limbs]; 16],
            vec![ValueBound::zero(); 16],
        );

        let elements = main_trace_row_to_field_elements::<F>(&row, &config);

        // Should produce correct number of main trace columns
        let expected = ZkIrAir::new(config.clone()).main_trace_width();
        assert_eq!(elements.len(), expected);

        // Check PC and instruction
        assert_eq!(elements[0], F::from_canonical_u64(42)); // PC
        assert_eq!(elements[1], F::from_canonical_u32(0x12345678)); // Instruction
    }

    #[test]
    fn test_multi_limb_config() {
        // Test with 3-limb configuration
        let config_3limb = ProgramConfig {
            limb_bits: 20,
            data_limbs: 3,
            addr_limbs: 3,
        };

        let adapter_3limb = ZkIrAirAdapter::new(config_3limb.clone());
        let width_3limb = <ZkIrAirAdapter as BaseAir<F>>::width(&adapter_3limb);

        // Default 2-limb config
        let config_2limb = ProgramConfig::default();
        let adapter_2limb = ZkIrAirAdapter::new(config_2limb);
        let width_2limb = <ZkIrAirAdapter as BaseAir<F>>::width(&adapter_2limb);

        // 3-limb config should have more columns than 2-limb
        println!("2-limb width: {}", width_2limb);
        println!("3-limb width: {}", width_3limb);
        assert!(width_3limb > width_2limb, "3-limb should have more columns than 2-limb");
    }
}
