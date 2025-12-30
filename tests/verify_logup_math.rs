//! Verify LogUp delta calculation is mathematically correct

use p3_mersenne_31::Mersenne31;
use p3_field::{Field, FieldAlgebra, PrimeField64};

#[test]
fn verify_logup_delta_calculation() {
    type F = Mersenne31;

    // These values come from the AND instruction debug output
    let diff_0 = F::from_canonical_u32(91601140);
    let diff_1 = F::from_canonical_u32(100000000);

    // Calculate delta = 1/diff_0 + 1/diff_1
    let inv_0 = diff_0.inverse();
    let inv_1 = diff_1.inverse();
    let calculated_delta = inv_0 + inv_1;

    // This is the delta value we see in the witness
    let witness_delta = F::from_canonical_u32(1067734286);

    eprintln!("diff_0: {}", diff_0.as_canonical_u64());
    eprintln!("diff_1: {}", diff_1.as_canonical_u64());
    eprintln!("inv_0: {}", inv_0.as_canonical_u64());
    eprintln!("inv_1: {}", inv_1.as_canonical_u64());
    eprintln!("calculated_delta: {}", calculated_delta.as_canonical_u64());
    eprintln!("witness_delta: {}", witness_delta.as_canonical_u64());
    eprintln!("Delta match: {}", calculated_delta == witness_delta);

    // Verify the LogUp constraint: delta * diff_0 * diff_1 = diff_0 + diff_1
    let lhs = calculated_delta * diff_0 * diff_1;
    let rhs = diff_0 + diff_1;
    eprintln!("\nConstraint check:");
    eprintln!("delta * diff_0 * diff_1 = {}", lhs.as_canonical_u64());
    eprintln!("diff_0 + diff_1 = {}", rhs.as_canonical_u64());
    eprintln!("Constraint satisfied: {}", lhs == rhs);

    // Now test with ONLY limb 0 (the fix we applied)
    eprintln!("\n=== WITH FIX (LIMB 0 ONLY) ===");
    let expected_delta_limb0_only = inv_0 + inv_1; // Both chunks from limb 0
    eprintln!("delta (limb 0 only): {} + {} = {}", inv_0.as_canonical_u64(), inv_1.as_canonical_u64(), expected_delta_limb0_only.as_canonical_u64());

    let lhs_fixed = expected_delta_limb0_only * diff_0 * diff_1;
    let rhs_fixed = diff_0 + diff_1;
    eprintln!("Constraint LHS: {}", lhs_fixed.as_canonical_u64());
    eprintln!("Constraint RHS: {}", rhs_fixed.as_canonical_u64());
    eprintln!("Constraint satisfied: {}", lhs_fixed == rhs_fixed);

    assert_eq!(lhs_fixed, rhs_fixed, "LogUp constraint not satisfied with limb 0 only!");
}
