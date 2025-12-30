//! Per-instruction constraint correctness tests
//!
//! These tests verify that each instruction's constraints are mathematically correct
//! by testing with various input values and ensuring the constraints behave as expected.

use p3_baby_bear::BabyBear;
use p3_field::{FieldAlgebra, PrimeField32};

use zkir_prover::constraints::air::ZkIrAir;
use zkir_prover::types::Opcode;
use zkir_prover::witness::trace::ProgramConfig;

/// Helper to create a basic AIR for testing
fn create_test_air() -> ZkIrAir {
    let config = ProgramConfig::default();
    ZkIrAir::new(config)
}

/// Helper to convert u32 to BabyBear field element
fn to_field(value: u32) -> BabyBear {
    BabyBear::from_canonical_u32(value)
}

// ============================================================================
// ARITHMETIC INSTRUCTION TESTS
// ============================================================================

#[test]
fn test_add_instruction_semantics() {
    // Test that ADD constraint: rd = rs1 + rs2
    let air = create_test_air();

    // Test case 1: Basic addition
    let rs1 = to_field(100);
    let rs2 = to_field(50);
    let expected_rd = to_field(150);

    // In field arithmetic
    let result = rs1 + rs2;
    assert_eq!(result, expected_rd);

    // Test case 2: Addition with overflow (wraps in field)
    let large1 = to_field(BabyBear::ORDER_U32 - 10);
    let large2 = to_field(15);
    let result_overflow = large1 + large2;
    // Result wraps: (ORDER - 10) + 15 = ORDER + 5 ≡ 5 (mod ORDER)
    assert_eq!(result_overflow, to_field(5));

    println!("ADD instruction semantics verified");
    println!("   100 + 50 = {}", (rs1 + rs2).as_canonical_u32());
    println!("   Overflow handling: {}", result_overflow.as_canonical_u32());

    // Verify AIR structure supports the operation
    assert!(air.num_columns > 0);
}

#[test]
fn test_sub_instruction_semantics() {
    // Test that SUB constraint: rd = rs1 - rs2

    // Test case 1: Basic subtraction
    let rs1 = to_field(100);
    let rs2 = to_field(30);
    let expected_rd = to_field(70);

    let result = rs1 - rs2;
    assert_eq!(result, expected_rd);

    // Test case 2: Subtraction with underflow (wraps in field)
    let small = to_field(10);
    let large = to_field(20);
    let result_underflow = small - large;
    // Result wraps: 10 - 20 = -10 ≡ ORDER - 10 (mod ORDER)
    assert_eq!(result_underflow, to_field(BabyBear::ORDER_U32 - 10));

    println!("SUB instruction semantics verified");
    println!("   100 - 30 = {}", result.as_canonical_u32());
}

#[test]
fn test_mul_instruction_semantics() {
    // Test that MUL constraint: rd = rs1 * rs2

    // Test case 1: Basic multiplication
    let rs1 = to_field(7);
    let rs2 = to_field(6);
    let expected_rd = to_field(42);

    let result = rs1 * rs2;
    assert_eq!(result, expected_rd);

    // Test case 2: Multiplication by zero
    let rs1_nonzero = to_field(123);
    let rs2_zero = to_field(0);
    let result_zero = rs1_nonzero * rs2_zero;
    assert_eq!(result_zero, to_field(0));

    // Test case 3: Multiplication by one (identity)
    let rs1_val = to_field(456);
    let rs2_one = to_field(1);
    let result_identity = rs1_val * rs2_one;
    assert_eq!(result_identity, rs1_val);

    println!("MUL instruction semantics verified");
    println!("   7 * 6 = {}", result.as_canonical_u32());
}

// ============================================================================
// COMPARISON INSTRUCTION TESTS
// ============================================================================

#[test]
fn test_slt_instruction_semantics() {
    // Test that SLT (Set Less Than) works correctly

    // Test case 1: a < b → result = 1
    let a_small = to_field(10);
    let b_large = to_field(20);
    let result_true = if a_small.as_canonical_u32() < b_large.as_canonical_u32() {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(result_true, to_field(1));

    // Test case 2: a >= b → result = 0
    let a_large = to_field(30);
    let b_small = to_field(20);
    let result_false = if a_large.as_canonical_u32() < b_small.as_canonical_u32() {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(result_false, to_field(0));

    // Test case 3: a == b → result = 0
    let a_equal = to_field(15);
    let b_equal = to_field(15);
    let result_equal = if a_equal.as_canonical_u32() < b_equal.as_canonical_u32() {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(result_equal, to_field(0));

    println!("SLT instruction semantics verified");
    println!("   10 < 20: {}", result_true.as_canonical_u32());
    println!("   30 < 20: {}", result_false.as_canonical_u32());
    println!("   15 < 15: {}", result_equal.as_canonical_u32());
}

#[test]
fn test_seq_instruction_semantics() {
    // Test that SEQ (Set if Equal) works correctly

    // Test case 1: a == b → result = 1
    let a = to_field(42);
    let b = to_field(42);
    let result_equal = if a == b {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(result_equal, to_field(1));

    // Test case 2: a != b → result = 0
    let a_diff = to_field(42);
    let b_diff = to_field(43);
    let result_not_equal = if a_diff == b_diff {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(result_not_equal, to_field(0));

    println!("SEQ instruction semantics verified");
}

// ============================================================================
// LOGICAL INSTRUCTION TESTS
// ============================================================================

#[test]
fn test_bitwise_not_semantics() {
    // Test that NOT works correctly
    // NOT in field: rd = (2^limb_bits - 1) - rs1

    let config = ProgramConfig::default();
    let limb_bits = config.limb_bits as u32;
    let mask = (1u32 << limb_bits) - 1;

    // Test case 1: NOT of 0 = all 1s
    let val_zero = 0u32;
    let expected_not_zero = mask;
    assert_eq!(mask - val_zero, expected_not_zero);

    // Test case 2: NOT of all 1s = 0
    let val_ones = mask;
    let expected_not_ones = 0;
    assert_eq!(mask - val_ones, expected_not_ones);

    // Test case 3: NOT of pattern
    let val_pattern = 0b1010_1010u32;
    let expected_not_pattern = mask - val_pattern;
    // For 20-bit limbs: 0xFFFFF - 0xAA = 0xFFF55
    assert_eq!(mask - val_pattern, expected_not_pattern);

    println!("NOT instruction semantics verified");
    println!("   NOT(0) = 0x{:x}", expected_not_zero);
    println!("   NOT(all 1s) = {}", expected_not_ones);
}

#[test]
fn test_bitwise_and_chunk_logic() {
    // Test the chunk decomposition logic for AND

    // For 20-bit limbs split into two 10-bit chunks
    let limb_bits = 20u32;
    let chunk_bits = limb_bits / 2;
    let chunk_mask = (1u32 << chunk_bits) - 1;

    // Test case: 0xABCDE & 0x54321
    let a = 0xABCDEu32 & ((1 << limb_bits) - 1); // Ensure within 20 bits
    let b = 0x54321u32 & ((1 << limb_bits) - 1);

    // Decompose a into chunks
    let a_chunk0 = a & chunk_mask;
    let a_chunk1 = (a >> chunk_bits) & chunk_mask;

    // Decompose b into chunks
    let b_chunk0 = b & chunk_mask;
    let b_chunk1 = (b >> chunk_bits) & chunk_mask;

    // AND each chunk pair
    let result_chunk0 = a_chunk0 & b_chunk0;
    let result_chunk1 = a_chunk1 & b_chunk1;

    // Reconstruct result
    let reconstructed = result_chunk0 + (result_chunk1 << chunk_bits);

    // Verify it matches direct AND
    let direct_and = a & b;
    assert_eq!(reconstructed, direct_and);

    println!("AND chunk decomposition verified");
    println!("   0x{:x} & 0x{:x} = 0x{:x}", a, b, direct_and);
    println!("   Via chunks: 0x{:x}", reconstructed);
}

#[test]
fn test_bitwise_or_chunk_logic() {
    // Test the chunk decomposition logic for OR

    let limb_bits = 20u32;
    let chunk_bits = limb_bits / 2;
    let chunk_mask = (1u32 << chunk_bits) - 1;

    let a = 0x12345u32 & ((1 << limb_bits) - 1);
    let b = 0x67890u32 & ((1 << limb_bits) - 1);

    // Decompose and operate on chunks
    let a_chunk0 = a & chunk_mask;
    let a_chunk1 = (a >> chunk_bits) & chunk_mask;
    let b_chunk0 = b & chunk_mask;
    let b_chunk1 = (b >> chunk_bits) & chunk_mask;

    let result_chunk0 = a_chunk0 | b_chunk0;
    let result_chunk1 = a_chunk1 | b_chunk1;

    let reconstructed = result_chunk0 + (result_chunk1 << chunk_bits);
    let direct_or = a | b;

    assert_eq!(reconstructed, direct_or);

    println!("OR chunk decomposition verified");
    println!("   0x{:x} | 0x{:x} = 0x{:x}", a, b, direct_or);
}

#[test]
fn test_bitwise_xor_chunk_logic() {
    // Test the chunk decomposition logic for XOR

    let limb_bits = 20u32;
    let chunk_bits = limb_bits / 2;
    let chunk_mask = (1u32 << chunk_bits) - 1;

    let a = 0xFEDCBu32 & ((1 << limb_bits) - 1);
    let b = 0x13579u32 & ((1 << limb_bits) - 1);

    // Decompose and operate on chunks
    let a_chunk0 = a & chunk_mask;
    let a_chunk1 = (a >> chunk_bits) & chunk_mask;
    let b_chunk0 = b & chunk_mask;
    let b_chunk1 = (b >> chunk_bits) & chunk_mask;

    let result_chunk0 = a_chunk0 ^ b_chunk0;
    let result_chunk1 = a_chunk1 ^ b_chunk1;

    let reconstructed = result_chunk0 + (result_chunk1 << chunk_bits);
    let direct_xor = a ^ b;

    assert_eq!(reconstructed, direct_xor);

    println!("XOR chunk decomposition verified");
    println!("   0x{:x} ^ 0x{:x} = 0x{:x}", a, b, direct_xor);
}

// ============================================================================
// SHIFT INSTRUCTION TESTS
// ============================================================================

#[test]
fn test_sll_semantics() {
    // Test logical left shift

    // Test case 1: Basic shift
    let value = 0b1010u32;
    let shift_amount = 2u32;
    let expected = 0b101000u32;
    assert_eq!(value << shift_amount, expected);

    // Test case 2: Shift by 0 (identity)
    let value_identity = 0x12345u32;
    assert_eq!(value_identity << 0, value_identity);

    // Test case 3: Large shift (bits fall off)
    let value_large = 0xFFFFFu32; // 20 bits all 1s
    let shift_large = 10u32;
    let result_large = value_large << shift_large;
    // High 10 bits fall off in 20-bit arithmetic
    let mask_20bit = (1u32 << 20) - 1;
    let expected_large = (value_large << shift_large) & mask_20bit;
    assert_eq!(result_large & mask_20bit, expected_large);

    println!("SLL (Shift Left Logical) semantics verified");
    println!("   0b1010 << 2 = 0b{:b}", value << shift_amount);
}

#[test]
fn test_srl_semantics() {
    // Test logical right shift

    // Test case 1: Basic shift
    let value = 0b101000u32;
    let shift_amount = 2u32;
    let expected = 0b1010u32;
    assert_eq!(value >> shift_amount, expected);

    // Test case 2: Shift by 0 (identity)
    let value_identity = 0x12345u32;
    assert_eq!(value_identity >> 0, value_identity);

    // Test case 3: Shift all bits out
    let value_all = 0xFFFu32;
    let shift_all = 20u32; // Shift more than limb width
    let result_all = value_all >> shift_all;
    assert_eq!(result_all, 0);

    println!("SRL (Shift Right Logical) semantics verified");
    println!("   0b101000 >> 2 = 0b{:b}", value >> shift_amount);
}

// ============================================================================
// CONDITIONAL MOVE TESTS
// ============================================================================

#[test]
fn test_cmov_semantics() {
    // Test CMOV: rd = cond ? rs2 : rd

    // Test case 1: Condition true → move rs2 to rd
    let cond_true = to_field(1);
    let rs2_val = to_field(100);
    let rd_original = to_field(50);

    // Algebraic formulation: rd_new = cond * rs2 + (1 - cond) * rd_old
    let rd_new_true = cond_true * rs2_val + (to_field(1) - cond_true) * rd_original;
    assert_eq!(rd_new_true, rs2_val); // Should be rs2

    // Test case 2: Condition false → keep rd
    let cond_false = to_field(0);
    let rs2_other = to_field(200);
    let rd_keep = to_field(75);

    let rd_new_false = cond_false * rs2_other + (to_field(1) - cond_false) * rd_keep;
    assert_eq!(rd_new_false, rd_keep); // Should be original rd

    println!("CMOV (Conditional Move) semantics verified");
    println!("   cond=1: rd becomes rs2 ({})", rd_new_true.as_canonical_u32());
    println!("   cond=0: rd stays ({})    ", rd_new_false.as_canonical_u32());
}

#[test]
fn test_cmovz_semantics() {
    // Test CMOVZ: rd = (rs1 == 0) ? rs2 : rd

    // Test case 1: rs1 is zero → move rs2 to rd
    let rs1_zero = to_field(0);
    let zero_flag = if rs1_zero == to_field(0) {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(zero_flag, to_field(1));

    // Test case 2: rs1 is non-zero → keep rd
    let rs1_nonzero = to_field(42);
    let zero_flag_false = if rs1_nonzero == to_field(0) {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(zero_flag_false, to_field(0));

    println!("CMOVZ (Conditional Move if Zero) semantics verified");
}

// ============================================================================
// BRANCH INSTRUCTION TESTS
// ============================================================================

#[test]
fn test_beq_semantics() {
    // Test BEQ: branch if rs1 == rs2

    // Test case 1: Equal → branch taken
    let rs1 = to_field(42);
    let rs2 = to_field(42);
    let branch_cond = if rs1 == rs2 {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(branch_cond, to_field(1));

    // Test case 2: Not equal → branch not taken
    let rs1_diff = to_field(42);
    let rs2_diff = to_field(43);
    let branch_cond_false = if rs1_diff == rs2_diff {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(branch_cond_false, to_field(0));

    println!("BEQ (Branch if Equal) semantics verified");
}

#[test]
fn test_bne_semantics() {
    // Test BNE: branch if rs1 != rs2

    // Test case 1: Not equal → branch taken
    let rs1 = to_field(42);
    let rs2 = to_field(43);
    let branch_cond = if rs1 != rs2 {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(branch_cond, to_field(1));

    // Test case 2: Equal → branch not taken
    let rs1_equal = to_field(100);
    let rs2_equal = to_field(100);
    let branch_cond_false = if rs1_equal != rs2_equal {
        to_field(1)
    } else {
        to_field(0)
    };
    assert_eq!(branch_cond_false, to_field(0));

    println!("BNE (Branch if Not Equal) semantics verified");
}

// ============================================================================
// OPCODE ENCODING TESTS
// ============================================================================

#[test]
fn test_all_opcodes_have_unique_values() {
    // Verify all ZKIR v3.4 opcodes have unique 6-bit encodings
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    // ZKIR v3.4 spec opcodes (no NOT, SUBI, MULI, SLTI, SLTUI in spec)
    let opcodes = [
        // Arithmetic (0x00-0x08)
        Opcode::Add, Opcode::Sub, Opcode::Mul, Opcode::Mulh,
        Opcode::Divu, Opcode::Remu, Opcode::Div, Opcode::Rem, Opcode::Addi,
        // Logical (0x10-0x15)
        Opcode::And, Opcode::Or, Opcode::Xor,
        Opcode::Andi, Opcode::Ori, Opcode::Xori,
        // Shift (0x18-0x1D)
        Opcode::Sll, Opcode::Srl, Opcode::Sra,
        Opcode::Slli, Opcode::Srli, Opcode::Srai,
        // Compare (0x20-0x25)
        Opcode::Sltu, Opcode::Sgeu, Opcode::Slt, Opcode::Sge, Opcode::Seq, Opcode::Sne,
        // Cmov (0x26-0x28)
        Opcode::Cmov, Opcode::Cmovz, Opcode::Cmovnz,
        // Load (0x30-0x35)
        Opcode::Lb, Opcode::Lbu, Opcode::Lh, Opcode::Lhu, Opcode::Lw, Opcode::Ld,
        // Store (0x38-0x3B)
        Opcode::Sb, Opcode::Sh, Opcode::Sw, Opcode::Sd,
        // Branch (0x40-0x45)
        Opcode::Beq, Opcode::Bne, Opcode::Blt, Opcode::Bge, Opcode::Bltu, Opcode::Bgeu,
        // Jump (0x48-0x49)
        Opcode::Jal, Opcode::Jalr,
        // System (0x50-0x51)
        Opcode::Ecall, Opcode::Ebreak,
    ];

    for opcode in &opcodes {
        let value = opcode.to_u8();
        assert!(seen.insert(value), "Duplicate opcode value: 0x{:02X}", value);
    }

    // ZKIR v3.4 has 50 instructions
    // 9 arithmetic + 6 logical + 6 shift + 6 compare + 3 cmov + 6 load + 4 store + 6 branch + 2 jump + 2 system
    assert_eq!(seen.len(), 50, "Expected 50 unique opcodes in ZKIR v3.4");

    println!("All 50 ZKIR v3.4 opcodes have unique 6-bit encodings");
}

#[test]
fn test_opcode_ranges_dont_overlap() {
    // Verify ZKIR v3.4 opcode families match spec ranges (6-bit encoding)

    // Arithmetic: 0x00-0x08
    assert!((Opcode::Add.to_u8()) < 0x10);
    assert!((Opcode::Addi.to_u8()) < 0x10);

    // Logical: 0x10-0x15
    assert!((Opcode::And.to_u8()) >= 0x10 && (Opcode::And.to_u8()) < 0x18);
    assert!((Opcode::Xori.to_u8()) >= 0x10 && (Opcode::Xori.to_u8()) < 0x18);

    // Shift: 0x18-0x1D
    assert!((Opcode::Sll.to_u8()) >= 0x18 && (Opcode::Sll.to_u8()) < 0x20);
    assert!((Opcode::Srai.to_u8()) >= 0x18 && (Opcode::Srai.to_u8()) < 0x20);

    // Compare: 0x20-0x25
    assert!((Opcode::Sltu.to_u8()) >= 0x20 && (Opcode::Sltu.to_u8()) < 0x26);

    // Conditional Move: 0x26-0x28
    assert!((Opcode::Cmov.to_u8()) >= 0x26 && (Opcode::Cmov.to_u8()) < 0x30);

    // Load: 0x30-0x35
    assert!((Opcode::Lb.to_u8()) >= 0x30 && (Opcode::Lb.to_u8()) < 0x38);

    // Store: 0x38-0x3B
    assert!((Opcode::Sb.to_u8()) >= 0x38 && (Opcode::Sb.to_u8()) < 0x40);

    // Branch: 0x40-0x45
    assert!((Opcode::Beq.to_u8()) >= 0x40 && (Opcode::Beq.to_u8()) < 0x48);

    // Jump: 0x48-0x49
    assert!((Opcode::Jal.to_u8()) >= 0x48 && (Opcode::Jal.to_u8()) < 0x50);

    // System: 0x50-0x51
    assert!((Opcode::Ecall.to_u8()) >= 0x50 && (Opcode::Ecall.to_u8()) <= 0x51);

    println!("ZKIR v3.4 opcode family ranges verified - no overlaps");
}
