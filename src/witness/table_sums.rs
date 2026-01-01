//! Table sum computation for LogUp verification
//!
//! This module computes the table-side running sums needed for LogUp verification:
//! table_sum = Σ(multiplicity/(α - encode(entry)))

use super::multiplicity::LogUpMultiplicities;
use crate::witness::ProgramConfig;
use p3_field::Field;

/// Compute table sum for a lookup table given multiplicities
///
/// For each entry in the table with non-zero multiplicity:
/// sum += multiplicity / (challenge - encoded_entry)
///
/// # Arguments
/// * `multiplicities` - Map from encoded entries to their multiplicities
/// * `challenge` - Fiat-Shamir challenge value α
///
/// # Returns
/// The table-side LogUp sum
pub fn compute_table_sum<F: Field>(
    multiplicities: &[(u32, u32)], // (encoded_entry, multiplicity)
    challenge: F,
) -> F {
    let mut sum = F::ZERO;

    for &(encoded_entry, multiplicity) in multiplicities {
        if multiplicity == 0 {
            continue;
        }

        // Compute: multiplicity / (challenge - encoded_entry)
        // Rearranged as: multiplicity * (1 / (challenge - encoded_entry))
        let encoded_f = F::from_canonical_u32(encoded_entry);
        let diff = challenge - encoded_f;

        // Compute inverse
        let diff_inv = diff.try_inverse().expect("Challenge collision with table entry");

        // Add multiplicity * (1/diff) to sum
        let mult_f = F::from_canonical_u32(multiplicity);
        sum += mult_f * diff_inv;
    }

    sum
}

/// Table sums for all LogUp tables
#[derive(Clone, Debug)]
pub struct TableSums<F: Field> {
    /// AND table sum
    pub and_sum: F,
    /// OR table sum
    pub or_sum: F,
    /// XOR table sum
    pub xor_sum: F,
    /// Range check table sum
    pub range_sum: F,
}

impl<F: Field> TableSums<F> {
    /// Create new table sums (all initialized to zero)
    pub fn zero() -> Self {
        Self {
            and_sum: F::ZERO,
            or_sum: F::ZERO,
            xor_sum: F::ZERO,
            range_sum: F::ZERO,
        }
    }

    /// Compute table sums from multiplicities
    ///
    /// # Arguments
    /// * `multiplicities` - The multiplicity trackers
    /// * `challenge` - The Fiat-Shamir challenge α
    /// * `config` - Program configuration (for chunk size)
    pub fn compute(
        multiplicities: &LogUpMultiplicities,
        challenge: F,
        _config: &ProgramConfig,
    ) -> Self {
        // Compute AND table sum
        let and_entries = multiplicities.and_table.non_zero_entries();
        let and_sum = compute_table_sum(&and_entries, challenge);

        // Compute OR table sum
        let or_entries = multiplicities.or_table.non_zero_entries();
        let or_sum = compute_table_sum(&or_entries, challenge);

        // Compute XOR table sum
        let xor_entries = multiplicities.xor_table.non_zero_entries();
        let xor_sum = compute_table_sum(&xor_entries, challenge);

        // Compute range check table sum
        let range_entries: Vec<(u32, u32)> = multiplicities.range_table.iter_non_zero().collect();
        let range_sum = compute_table_sum(&range_entries, challenge);

        Self {
            and_sum,
            or_sum,
            xor_sum,
            range_sum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::F; // Mersenne31
    use p3_field::FieldAlgebra;

    #[test]
    fn test_compute_table_sum_empty() {
        let multiplicities = vec![];
        let challenge = F::from_canonical_u32(100_000_000); // Well below M31 prime
        let sum = compute_table_sum(&multiplicities, challenge);
        assert_eq!(sum, F::ZERO);
    }

    #[test]
    fn test_compute_table_sum_single_entry() {
        // Single entry with multiplicity 1
        let multiplicities = vec![(42, 1)];
        let challenge = F::from_canonical_u32(1000);

        let sum = compute_table_sum(&multiplicities, challenge);

        // Expected: 1 / (1000 - 42) = 1 / 958
        let expected_diff = F::from_canonical_u32(1000 - 42);
        let expected = expected_diff.try_inverse().unwrap();

        assert_eq!(sum, expected);
    }

    #[test]
    fn test_compute_table_sum_with_multiplicity() {
        // Entry queried 3 times
        let multiplicities = vec![(42, 3)];
        let challenge = F::from_canonical_u32(1000);

        let sum = compute_table_sum(&multiplicities, challenge);

        // Expected: 3 / (1000 - 42) = 3 / 958
        let diff = F::from_canonical_u32(1000 - 42);
        let diff_inv = diff.try_inverse().unwrap();
        let expected = F::from_canonical_u32(3) * diff_inv;

        assert_eq!(sum, expected);
    }

    #[test]
    fn test_compute_table_sum_multiple_entries() {
        // Multiple entries with different multiplicities
        let multiplicities = vec![
            (10, 2), // 2 queries for entry 10
            (20, 1), // 1 query for entry 20
            (30, 3), // 3 queries for entry 30
        ];
        let challenge = F::from_canonical_u32(1000);

        let sum = compute_table_sum(&multiplicities, challenge);

        // Expected: 2/(1000-10) + 1/(1000-20) + 3/(1000-30)
        let term1 = F::from_canonical_u32(2) * F::from_canonical_u32(990).try_inverse().unwrap();
        let term2 = F::from_canonical_u32(1) * F::from_canonical_u32(980).try_inverse().unwrap();
        let term3 = F::from_canonical_u32(3) * F::from_canonical_u32(970).try_inverse().unwrap();
        let expected = term1 + term2 + term3;

        assert_eq!(sum, expected);
    }

    #[test]
    fn test_table_sums_compute() {
        let mut mults = LogUpMultiplicities::new();

        // Record some operations
        mults.record_and(5, 3, 1, 10); // AND
        mults.record_and(5, 3, 1, 10); // Same AND (multiplicity 2)
        mults.record_or(10, 6, 14, 10); // OR
        mults.record_xor(15, 10, 5, 10); // XOR
        mults.record_range_check(42); // Range check

        let config = ProgramConfig::default();
        let challenge = F::from_canonical_u32(100_000_000); // Well below M31 prime

        let sums = TableSums::compute(&mults, challenge, &config);

        // AND table should have one entry with multiplicity 2
        assert_ne!(sums.and_sum, F::ZERO);

        // OR and XOR tables should have one entry each with multiplicity 1
        assert_ne!(sums.or_sum, F::ZERO);
        assert_ne!(sums.xor_sum, F::ZERO);

        // Range check should have one entry with multiplicity 1
        assert_ne!(sums.range_sum, F::ZERO);
    }

    #[test]
    fn test_table_sums_zero() {
        let sums: TableSums<F> = TableSums::zero();
        assert_eq!(sums.and_sum, F::ZERO);
        assert_eq!(sums.or_sum, F::ZERO);
        assert_eq!(sums.xor_sum, F::ZERO);
        assert_eq!(sums.range_sum, F::ZERO);
    }

    #[test]
    fn test_table_sum_with_zero_multiplicity() {
        // Entry with zero multiplicity should be skipped
        let multiplicities = vec![
            (10, 2),
            (20, 0), // This should be skipped
            (30, 1),
        ];
        let challenge = F::from_canonical_u32(1000);

        let sum = compute_table_sum(&multiplicities, challenge);

        // Should only include entries 10 and 30
        let term1 = F::from_canonical_u32(2) * F::from_canonical_u32(990).try_inverse().unwrap();
        let term3 = F::from_canonical_u32(1) * F::from_canonical_u32(970).try_inverse().unwrap();
        let expected = term1 + term3;

        assert_eq!(sum, expected);
    }
}
