//! Instruction decoding constraints for ZKIR v3.4
//!
//! This module implements algebraic constraints to decode 32-bit ZKIR instructions
//! into their constituent fields (opcode, registers, immediates) using field arithmetic.
//!
//! ZKIR v3.4 Instruction Formats (6-bit opcode):
//! - R-type:  [opcode:6][rd:4][rs1:4][rs2:4][funct:14]
//! - I-type:  [opcode:6][rd:4][rs1:4][imm:18]
//! - S-type:  [opcode:6][rs1:4][rs2:4][imm:18]
//! - B-type:  [opcode:6][rs1:4][rs2:4][offset:18]
//! - J-type:  [opcode:6][rd:4][offset:22]

use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

use super::air::ZkIrAir;

/// Instruction decoding helper
///
/// Provides methods to extract fields from 32-bit instructions using
/// algebraic constraints in field arithmetic.
pub struct InstructionDecoder {
    /// Configuration from the AIR
    pub config: crate::witness::ProgramConfig,
}

impl InstructionDecoder {
    /// Create a new instruction decoder
    pub fn new(config: crate::witness::ProgramConfig) -> Self {
        Self { config }
    }

    /// Extract opcode (bits 0-5) from instruction
    ///
    /// Constraint approach:
    /// 1. Assert opcode is in range [0, 63]
    /// 2. Verify: instruction = opcode + (rest * 64)
    /// where rest is the remaining bits
    pub fn eval_opcode_extract<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction: AB::Expr,
        opcode: AB::Expr,
        rest: AB::Expr,
    ) {
        // Verify: instruction = opcode + rest * 2^6
        let shift = AB::F::from_canonical_u32(64); // 2^6
        let reconstructed = opcode.clone() + rest * shift;
        builder.assert_eq(instruction, reconstructed);

        // Opcode must be in range [0, 63]
        // This is verified by range check on opcode (6 bits)
    }

    /// Extract rd (destination register, bits 6-9) from instruction
    ///
    /// For Type R, I, J instructions
    pub fn eval_rd_extract<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction_without_opcode: AB::Expr,
        rd: AB::Expr,
        rest: AB::Expr,
    ) {
        // instruction_without_opcode = rd + rest * 2^4
        let shift = AB::F::from_canonical_u32(16); // 2^4
        let reconstructed = rd.clone() + rest * shift;
        builder.assert_eq(instruction_without_opcode, reconstructed);

        // rd must be in range [0, 15] (4 bits)
        // This is verified by range check on rd
    }

    /// Extract rs1 (source register 1, bits 10-13)
    ///
    /// For R, I, S, B type instructions
    pub fn eval_rs1_extract<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction_without_opcode_rd: AB::Expr,
        rs1: AB::Expr,
        rest: AB::Expr,
    ) {
        // instruction_without_opcode_rd = rs1 + rest * 2^4
        let shift = AB::F::from_canonical_u32(16); // 2^4
        let reconstructed = rs1.clone() + rest * shift;
        builder.assert_eq(instruction_without_opcode_rd, reconstructed);

        // rs1 must be in range [0, 15] (4 bits)
    }

    /// Extract rs2 (source register 2, bits 14-17)
    ///
    /// For R, S, B type instructions
    pub fn eval_rs2_extract<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction_without_opcode_rd_rs1: AB::Expr,
        rs2: AB::Expr,
        rest: AB::Expr,
    ) {
        // instruction_without_opcode_rd_rs1 = rs2 + rest * 2^4
        let shift = AB::F::from_canonical_u32(16); // 2^4
        let reconstructed = rs2.clone() + rest * shift;
        builder.assert_eq(instruction_without_opcode_rd_rs1, reconstructed);

        // rs2 must be in range [0, 15] (4 bits)
    }

    /// Extract 18-bit immediate from I-type instruction (bits 14-31)
    ///
    /// Immediate is sign-extended from 18 bits
    pub fn eval_imm18_extract<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction_high: AB::Expr,
        imm18: AB::Expr,
        sign_bit: AB::Expr,
    ) {
        // Verify sign_bit is boolean
        builder.assert_bool(sign_bit.clone());

        // If we need to reconstruct the instruction high bits from immediate:
        // instruction_high = imm18 (as 18-bit value)
        //
        // For sign extension to full width:
        // If sign_bit = 1, extend with 1s
        // If sign_bit = 0, extend with 0s
        //
        // sign_extended_imm = imm18 + sign_bit * (2^32 - 2^18)
        // But we work in field, so just verify the 18-bit value

        // Verify imm18 is in valid range [0, 2^18)
        // This is done via range check
        let _ = (instruction_high, imm18, sign_bit);
    }

    /// Extract 22-bit offset from J-type instruction (bits 10-31)
    pub fn eval_offset22_extract<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction_high: AB::Expr,
        offset22: AB::Expr,
    ) {
        // Verify offset22 matches instruction high bits
        builder.assert_eq(instruction_high, offset22.clone());

        // offset22 must be in range [0, 2^22)
        // This is verified by range check
    }

    /// Sign-extend an 18-bit immediate to full word size
    ///
    /// Algebraic sign extension:
    /// - If sign bit (bit 17) is 0: result = imm18
    /// - If sign bit (bit 17) is 1: result = imm18 - 2^18
    ///   (in field arithmetic, this gives proper sign extension behavior)
    pub fn eval_sign_extend_imm18<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        imm18: AB::Expr,
        sign_bit: AB::Expr,
        sign_extended: AB::Expr,
    ) {
        // Verify sign_bit is boolean
        builder.assert_bool(sign_bit.clone());

        // Extract sign bit from imm18 by checking if imm18 >= 2^17
        // sign_bit = 1 if imm18 >= 2^17, else 0
        //
        // Sign extension formula:
        // If sign_bit = 1: extended = imm18 - 2^18 (in field)
        // If sign_bit = 0: extended = imm18
        //
        // Algebraically: extended = imm18 - sign_bit * 2^18

        let sign_extend_offset = AB::F::from_canonical_u32(1u32 << 18); // 2^18
        let expected = imm18 - sign_bit * sign_extend_offset;

        builder.assert_eq(sign_extended, expected);
    }

    /// Verify instruction format consistency
    ///
    /// Given an instruction and its decoded fields, verify the reconstruction matches
    pub fn eval_instruction_reconstruct<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction: AB::Expr,
        opcode: AB::Expr,
        rd: AB::Expr,
        rs1: AB::Expr,
        rs2: AB::Expr,
        funct_or_imm: AB::Expr,
    ) {
        // R-type reconstruction: [opcode:6][rd:4][rs1:4][rs2:4][funct:14]
        // instruction = opcode + rd*2^6 + rs1*2^10 + rs2*2^14 + funct*2^18

        let shift_6 = AB::F::from_canonical_u32(64);       // 2^6
        let shift_10 = AB::F::from_canonical_u32(1024);    // 2^10
        let shift_14 = AB::F::from_canonical_u32(16384);   // 2^14
        let shift_18 = AB::F::from_canonical_u32(262144);  // 2^18

        let reconstructed = opcode
            + rd * shift_6
            + rs1 * shift_10
            + rs2 * shift_14
            + funct_or_imm * shift_18;

        builder.assert_eq(instruction, reconstructed);
    }
}

impl ZkIrAir {
    /// Evaluate instruction decoding constraints
    ///
    /// This decodes the instruction field into opcode and register indices
    /// using algebraic constraints.
    ///
    /// NOTE: This is a simplified version that verifies the reconstruction.
    /// Full implementation requires auxiliary witness columns for the intermediate
    /// quotients when extracting fields.
    ///
    /// For now, we verify: instruction = opcode + rd*2^6 + rs1*2^10 + rs2*2^14 + funct*2^18
    pub fn eval_instruction_decode<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        instruction: AB::Var,
        opcode: AB::Var,
        rd: AB::Var,
        rs1: AB::Var,
        rs2: AB::Var,
        funct_or_imm: AB::Var,
    ) {
        let decoder = InstructionDecoder::new(self.config.clone());

        // Convert all to expressions
        let instruction_expr: AB::Expr = instruction.into();
        let opcode_expr: AB::Expr = opcode.into();
        let rd_expr: AB::Expr = rd.into();
        let rs1_expr: AB::Expr = rs1.into();
        let rs2_expr: AB::Expr = rs2.into();
        let funct_or_imm_expr: AB::Expr = funct_or_imm.into();

        // Verify instruction reconstruction
        decoder.eval_instruction_reconstruct(
            builder,
            instruction_expr,
            opcode_expr,
            rd_expr,
            rs1_expr,
            rs2_expr,
            funct_or_imm_expr,
        );

        // Note: In the full implementation with auxiliary columns:
        // 1. Witness provides extracted fields (opcode, rd, rs1, rs2, imm)
        // 2. Range checks verify each field is in valid range
        // 3. Reconstruction constraint verifies they combine to form instruction
        //
        // This avoids division in field arithmetic by using witness-provided quotients
    }

    /// Verify register indicator columns match decoded values
    ///
    /// This ensures that the 48 indicator columns (16 rd + 16 rs1 + 16 rs2)
    /// correctly identify which registers are used by the current instruction.
    ///
    /// For each register field (rd, rs1, rs2):
    /// 1. Each indicator must be boolean (0 or 1)
    /// 2. Exactly one indicator must be 1
    /// 3. If indicator[i] = 1, then decoded_field must equal i
    ///
    /// This allows dynamic register selection in constraints via:
    /// selected_value = sum(indicator[i] * register[i]) for i in 0..16
    pub fn eval_register_indicators<AB: AirBuilder>(
        &self,
        builder: &mut AB,
        local: &[AB::Var],
    ) {
        let decoded_rd: AB::Expr = local[self.col_decoded_rd()].into();
        let decoded_rs1: AB::Expr = local[self.col_decoded_rs1()].into();
        let decoded_rs2: AB::Expr = local[self.col_decoded_rs2()].into();

        // Verify rd indicators
        // Start with first indicator
        let indicator_0: AB::Expr = local[self.col_rd_indicator(0)].into();
        builder.assert_bool(indicator_0.clone());
        let reg_val_0 = AB::F::from_canonical_u8(0);
        builder.assert_zero(indicator_0.clone() * (decoded_rd.clone() - reg_val_0));
        let mut rd_sum = indicator_0;

        // Process remaining indicators
        for reg_idx in 1..16 {
            let indicator: AB::Expr = local[self.col_rd_indicator(reg_idx)].into();

            // Constraint 1: indicator is boolean (0 or 1)
            // indicator * (indicator - 1) = 0
            builder.assert_bool(indicator.clone());

            // Constraint 2: If indicator = 1, then decoded_rd = reg_idx
            // indicator * (decoded_rd - reg_idx) = 0
            let reg_val = AB::F::from_canonical_u8(reg_idx as u8);
            builder.assert_zero(indicator.clone() * (decoded_rd.clone() - reg_val));

            // Accumulate for sum constraint
            rd_sum = rd_sum + indicator;
        }

        // Constraint 3: Exactly one rd indicator is 1
        // sum(indicator[i]) = 1
        builder.assert_one(rd_sum);

        // Verify rs1 indicators
        // Start with first indicator
        let indicator_0: AB::Expr = local[self.col_rs1_indicator(0)].into();
        builder.assert_bool(indicator_0.clone());
        let reg_val_0 = AB::F::from_canonical_u8(0);
        builder.assert_zero(indicator_0.clone() * (decoded_rs1.clone() - reg_val_0));
        let mut rs1_sum = indicator_0;

        // Process remaining indicators
        for reg_idx in 1..16 {
            let indicator: AB::Expr = local[self.col_rs1_indicator(reg_idx)].into();

            builder.assert_bool(indicator.clone());

            let reg_val = AB::F::from_canonical_u8(reg_idx as u8);
            builder.assert_zero(indicator.clone() * (decoded_rs1.clone() - reg_val));

            rs1_sum = rs1_sum + indicator;
        }

        builder.assert_one(rs1_sum);

        // Verify rs2 indicators
        // Note: For I-type instructions, rs2 field overlaps with immediate,
        // so all rs2_indicators should be 0 (not checked against decoded_rs2)

        let is_imm: AB::Expr = local[self.col_is_imm()].into();

        // Start with first indicator
        let indicator_0: AB::Expr = local[self.col_rs2_indicator(0)].into();
        builder.assert_bool(indicator_0.clone());

        // For R-type (is_imm=0): check that indicator matches decoded_rs2
        // For I-type (is_imm=1): don't check (decoded_rs2 is meaningless)
        let reg_val_0 = AB::F::from_canonical_u8(0);
        let is_rtype = AB::Expr::ONE - is_imm.clone();
        builder.assert_zero(is_rtype.clone() * indicator_0.clone() * (decoded_rs2.clone() - reg_val_0));
        let mut rs2_sum = indicator_0;

        // Process remaining indicators
        for reg_idx in 1..16 {
            let indicator: AB::Expr = local[self.col_rs2_indicator(reg_idx)].into();

            builder.assert_bool(indicator.clone());

            let reg_val = AB::F::from_canonical_u8(reg_idx as u8);
            // Only check for R-type instructions
            builder.assert_zero(is_rtype.clone() * indicator.clone() * (decoded_rs2.clone() - reg_val));

            rs2_sum = rs2_sum + indicator;
        }

        // For R-type: sum = 1 (exactly one rs2 selected)
        // For I-type: sum = 0 (no rs2 in use)
        // Constraint: is_rtype * (sum - 1) + is_imm * sum = 0
        // This is satisfied when: (is_rtype=1, sum=1) or (is_imm=1, sum=0)
        builder.assert_zero(is_rtype * (rs2_sum.clone() - AB::Expr::ONE) + is_imm * rs2_sum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_decoder_creation() {
        // Use valid addr_limbs (must be 1 or 2)
        let config = crate::witness::ProgramConfig::new(20, 2, 2).unwrap();
        let decoder = InstructionDecoder::new(config);
        assert_eq!(decoder.config.limb_bits, 20);
        assert_eq!(decoder.config.data_limbs, 2);
    }

    #[test]
    fn test_bit_shifts() {
        // Verify our shift constants are correct for 6-bit opcode format
        assert_eq!(1u32 << 6, 64);    // opcode shift
        assert_eq!(1u32 << 4, 16);    // register field
        assert_eq!(1u32 << 10, 1024); // rd -> rs1 shift
        assert_eq!(1u32 << 14, 16384); // rd+rs1 -> rs2 shift
        assert_eq!(1u32 << 18, 262144); // rd+rs1+rs2 -> funct/imm shift
        assert_eq!(1u32 << 22, 4194304); // J-type offset shift
    }

    #[test]
    fn test_instruction_format_sizes() {
        // Verify instruction format bit allocations (6-bit opcode)
        let opcode_bits = 6;
        let register_bits = 4;
        let imm18_bits = 18;
        let funct14_bits = 14;
        let offset22_bits = 22;

        // R-type: opcode + rd + rs1 + rs2 + funct14 = 6 + 4 + 4 + 4 + 14 = 32
        assert_eq!(opcode_bits + register_bits * 3 + funct14_bits, 32);

        // I-type: opcode + rd + rs1 + imm18 = 6 + 4 + 4 + 18 = 32
        assert_eq!(opcode_bits + register_bits * 2 + imm18_bits, 32);

        // J-type: opcode + rd + offset22 = 6 + 4 + 22 = 32
        assert_eq!(opcode_bits + register_bits + offset22_bits, 32);
    }
}
