//! Trace through LogUp calculation step by step

use p3_mersenne_31::Mersenne31;
use p3_field::{Field, FieldAlgebra, PrimeField64};

#[test]
fn trace_logup_for_and() {
    type F = Mersenne31;

    // From debug output: r2=8, r3=12, r4=10
    // With data_limbs=2, limb_bits=20:
    // r3 = 12: limb0=12, limb1=0
    // r4 = 10: limb0=10, limb1=0
    // r2 = 8:  limb0=8, limb1=0

    let challenge = F::from_canonical_u32(100_000_000);

    eprintln!("=== LIMB 0 ===");
    // Chunk decomposition for limb 0
    let rs1_chunk0 = 12 & 0x3FF; // 12
    let rs2_chunk0 = 10 & 0x3FF; // 10
    let rd_chunk0 = 8 & 0x3FF;   // 8

    let rs1_chunk1 = 12 >> 10;   // 0
    let rs2_chunk1 = 10 >> 10;   // 0
    let rd_chunk1 = 8 >> 10;     // 0

    eprintln!("rs1_chunk0={}, rs2_chunk0={}, rd_chunk0={}", rs1_chunk0, rs2_chunk0, rd_chunk0);
    eprintln!("rs1_chunk1={}, rs2_chunk1={}, rd_chunk1={}", rs1_chunk1, rs2_chunk1, rd_chunk1);

    // Encode
    let encoded_0 = rs1_chunk0 + rs2_chunk0 * 1024 + rd_chunk0 * 1048576;
    let encoded_1 = rs1_chunk1 + rs2_chunk1 * 1024 + rd_chunk1 * 1048576;

    eprintln!("encoded_0 = {} + {} * 1024 + {} * 1048576 = {}", rs1_chunk0, rs2_chunk0, rd_chunk0, encoded_0);
    eprintln!("encoded_1 = {} + {} * 1024 + {} * 1048576 = {}", rs1_chunk1, rs2_chunk1, rd_chunk1, encoded_1);

    let diff_0 = challenge - F::from_canonical_u32(encoded_0);
    let diff_1 = challenge - F::from_canonical_u32(encoded_1);

    eprintln!("diff_0 = 100000000 - {} = {}", encoded_0, diff_0.as_canonical_u64());
    eprintln!("diff_1 = 100000000 - {} = {}", encoded_1, diff_1.as_canonical_u64());

    let inv_0 = diff_0.inverse();
    let inv_1 = diff_1.inverse();

    eprintln!("inv_0 = 1/diff_0 = {}", inv_0.as_canonical_u64());
    eprintln!("inv_1 = 1/diff_1 = {}", inv_1.as_canonical_u64());

    let limb0_contribution = inv_0 + inv_1;
    eprintln!("Limb 0 contribution: {} + {} = {}", inv_0.as_canonical_u64(), inv_1.as_canonical_u64(), limb0_contribution.as_canonical_u64());

    eprintln!("\n=== LIMB 1 ===");
    // Limb 1: all values are 0
    let rs1_limb1 = 0;
    let rs2_limb1 = 0;
    let rd_limb1 = 0;

    let rs1_chunk0_limb1 = rs1_limb1 & 0x3FF;
    let rs2_chunk0_limb1 = rs2_limb1 & 0x3FF;
    let rd_chunk0_limb1 = rd_limb1 & 0x3FF;

    let rs1_chunk1_limb1 = rs1_limb1 >> 10;
    let rs2_chunk1_limb1 = rs2_limb1 >> 10;
    let rd_chunk1_limb1 = rd_limb1 >> 10;

    eprintln!("rs1_chunk0={}, rs2_chunk0={}, rd_chunk0={}", rs1_chunk0_limb1, rs2_chunk0_limb1, rd_chunk0_limb1);
    eprintln!("rs1_chunk1={}, rs2_chunk1={}, rd_chunk1={}", rs1_chunk1_limb1, rs2_chunk1_limb1, rd_chunk1_limb1);

    let encoded_0_limb1 = rs1_chunk0_limb1 + rs2_chunk0_limb1 * 1024 + rd_chunk0_limb1 * 1048576;
    let encoded_1_limb1 = rs1_chunk1_limb1 + rs2_chunk1_limb1 * 1024 + rd_chunk1_limb1 * 1048576;

    eprintln!("encoded_0 = {}", encoded_0_limb1);
    eprintln!("encoded_1 = {}", encoded_1_limb1);

    let diff_0_limb1 = challenge - F::from_canonical_u32(encoded_0_limb1);
    let diff_1_limb1 = challenge - F::from_canonical_u32(encoded_1_limb1);

    eprintln!("diff_0 = {}", diff_0_limb1.as_canonical_u64());
    eprintln!("diff_1 = {}", diff_1_limb1.as_canonical_u64());

    let inv_0_limb1 = diff_0_limb1.inverse();
    let inv_1_limb1 = diff_1_limb1.inverse();

    eprintln!("inv_0 = {}", inv_0_limb1.as_canonical_u64());
    eprintln!("inv_1 = {}", inv_1_limb1.as_canonical_u64());

    let limb1_contribution = inv_0_limb1 + inv_1_limb1;
    eprintln!("Limb 1 contribution: {} + {} = {}", inv_0_limb1.as_canonical_u64(), inv_1_limb1.as_canonical_u64(), limb1_contribution.as_canonical_u64());

    eprintln!("\n=== TOTAL ===");
    let total_delta = limb0_contribution + limb1_contribution;
    eprintln!("Total delta: {} + {} = {}", limb0_contribution.as_canonical_u64(), limb1_contribution.as_canonical_u64(), total_delta.as_canonical_u64());
    eprintln!("Expected from witness: 1067734286");
    eprintln!("Difference: {} - {} = {}", 1067734286u64, total_delta.as_canonical_u64(), 1067734286u64.wrapping_sub(total_delta.as_canonical_u64()));

    // What if the witness is doubling limb 0's contribution?
    let doubled_limb0 = limb0_contribution + limb0_contribution;
    eprintln!("\n=== IF LIMB 0 COUNTED TWICE ===");
    eprintln!("2 * limb0: {}", doubled_limb0.as_canonical_u64());
    eprintln!("2 * limb0 + limb1: {}", (doubled_limb0 + limb1_contribution).as_canonical_u64());

    // Or what if it's counting BOTH limbs' contributions twice?
    let doubled_total = total_delta + total_delta;
    eprintln!("\n=== IF TOTAL COUNTED TWICE ===");
    eprintln!("2 * total: {}", doubled_total.as_canonical_u64());
}
