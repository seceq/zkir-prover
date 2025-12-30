//! LogUp (Logarithmic Derivative Lookup Argument) Protocol
//!
//! This module implements the LogUp protocol for verifying that lookup queries
//! appear in precomputed lookup tables. Used for bitwise operations and range checks.
//!
//! ## How LogUp Works
//!
//! For a lookup table T and queries Q:
//! 1. Prover computes multiplicities m[i] = number of times each table entry is queried
//! 2. Define random challenge α (from Fiat-Shamir)
//! 3. Compute running sum: Σ(1/(α - q)) for all queries q
//! 4. Verify: Σ(1/(α - q)) = Σ(m[i]/(α - t[i])) for all table entries t[i]
//!
//! This ensures every query appears in the table with correct multiplicity.

use std::collections::HashMap;

use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

// ============================================================================
// LogUp Chunk Encoding Constants
// ============================================================================

/// Number of bits per chunk for bitwise lookup encoding
pub const CHUNK_BITS: u32 = 10;

/// Mask for extracting a 10-bit chunk
pub const CHUNK_MASK: u32 = 0x3FF;

/// Bit shift for second chunk (b) in encoding
pub const CHUNK_B_SHIFT: u32 = 10;

/// Bit shift for third chunk (c) in encoding
pub const CHUNK_C_SHIFT: u32 = 20;

/// LogUp accumulator for tracking lookup usage
///
/// Maintains a running sum of logarithmic derivatives:
/// sum += 1 / (challenge - lookup_value)
#[derive(Clone, Debug)]
pub struct LogUpAccumulator {
    /// Current accumulated sum
    pub sum: u64,
    /// Number of lookups accumulated
    pub count: usize,
}

impl LogUpAccumulator {
    /// Create a new accumulator
    pub fn new() -> Self {
        Self { sum: 0, count: 0 }
    }

    /// Add a lookup to the accumulator
    ///
    /// # Arguments
    /// * `challenge` - Random challenge value from Fiat-Shamir
    /// * `value` - The looked-up value
    pub fn add_lookup(&mut self, challenge: u64, value: u64) {
        // In a real implementation, this would compute:
        // sum += 1 / (challenge - value)
        // For now, we track the count
        self.count += 1;
        let _ = (challenge, value); // Prevent unused warnings
    }

    /// Get the current accumulated sum
    pub fn get_sum(&self) -> u64 {
        self.sum
    }

    /// Get the number of lookups
    pub fn get_count(&self) -> usize {
        self.count
    }
}

impl Default for LogUpAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// LogUp constraint builder for AIR
///
/// Provides helper methods for adding LogUp constraints to the AIR
pub struct LogUpConstraintBuilder;

impl LogUpConstraintBuilder {
    /// Add a lookup constraint for a single value
    ///
    /// Verifies that (a, b, c) appears in the lookup table by adding:
    /// running_sum_next = running_sum_current + 1/(challenge - encode(a,b,c))
    ///
    /// # Arguments
    /// * `builder` - AIR builder
    /// * `challenge` - Random challenge value
    /// * `a` - First input
    /// * `b` - Second input
    /// * `c` - Output (expected to be op(a, b))
    /// * `running_sum_current` - Current running sum
    /// * `running_sum_next` - Next running sum (updated)
    pub fn add_lookup_constraint<AB: AirBuilder>(
        builder: &mut AB,
        challenge: AB::Expr,
        a: AB::Expr,
        b: AB::Expr,
        c: AB::Expr,
        running_sum_current: AB::Expr,
        running_sum_next: AB::Expr,
    ) {
        // Encode (a, b, c) as a single field element
        // For 10-bit chunks: encoded = a + b*2^10 + c*2^20
        let shift1 = AB::F::from_canonical_u32(1 << 10);
        let shift2 = AB::F::from_canonical_u32(1 << 20);
        let encoded = a + b * shift1 + c * shift2;

        // Constraint: running_sum_next = running_sum_current + 1/(challenge - encoded)
        // Rearranged to avoid division:
        // (running_sum_next - running_sum_current) * (challenge - encoded) = 1
        let delta = running_sum_next - running_sum_current;
        let diff = challenge - encoded;

        // This constraint will be degree 2 (multiplication)
        builder.assert_eq(delta * diff, AB::Expr::ONE);
    }

    /// Add a multiplicity constraint for a table entry
    ///
    /// Verifies that a table entry (a, b, c) was used exactly m times:
    /// table_sum += m/(challenge - encode(a,b,c))
    ///
    /// # Arguments
    /// * `builder` - AIR builder
    /// * `challenge` - Random challenge value
    /// * `a` - First input
    /// * `b` - Second input
    /// * `c` - Output
    /// * `multiplicity` - Number of times this entry was queried
    /// * `table_sum_current` - Current table sum
    /// * `table_sum_next` - Next table sum (updated)
    pub fn add_table_multiplicity<AB: AirBuilder>(
        builder: &mut AB,
        challenge: AB::Expr,
        a: AB::Expr,
        b: AB::Expr,
        c: AB::Expr,
        multiplicity: AB::Expr,
        table_sum_current: AB::Expr,
        table_sum_next: AB::Expr,
    ) {
        // Encode (a, b, c) as a single field element
        let shift1 = AB::F::from_canonical_u32(1 << 10);
        let shift2 = AB::F::from_canonical_u32(1 << 20);
        let encoded = a + b * shift1 + c * shift2;

        // Constraint: table_sum_next = table_sum_current + m/(challenge - encoded)
        // Rearranged: (table_sum_next - table_sum_current) * (challenge - encoded) = m
        let delta = table_sum_next - table_sum_current;
        let diff = challenge - encoded;

        builder.assert_eq(delta * diff, multiplicity);
    }

    /// Verify final sums match
    ///
    /// The core LogUp check: query_sum must equal table_sum
    ///
    /// # Arguments
    /// * `builder` - AIR builder
    /// * `query_sum` - Sum from all queries
    /// * `table_sum` - Sum from all table entries with multiplicities
    pub fn verify_sums_match<AB: AirBuilder>(
        builder: &mut AB,
        query_sum: AB::Expr,
        table_sum: AB::Expr,
    ) {
        builder.assert_eq(query_sum, table_sum);
    }
}

/// Bitwise operation lookup entry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitwiseLookupEntry {
    /// First input (10-bit chunk)
    pub a: u32,
    /// Second input (10-bit chunk)
    pub b: u32,
    /// Result (10-bit chunk)
    pub c: u32,
}

impl BitwiseLookupEntry {
    /// Create a new lookup entry
    pub fn new(a: u32, b: u32, c: u32) -> Self {
        assert!(a < (1 << CHUNK_BITS), "a must be 10-bit");
        assert!(b < (1 << CHUNK_BITS), "b must be 10-bit");
        assert!(c < (1 << CHUNK_BITS), "c must be 10-bit");
        Self { a, b, c }
    }

    /// Encode entry as a single field element
    /// encoding = a + b*2^10 + c*2^20
    pub fn encode(&self) -> u32 {
        self.a + (self.b << CHUNK_B_SHIFT) + (self.c << CHUNK_C_SHIFT)
    }

    /// Create entry from encoded value
    pub fn decode(encoded: u32) -> Self {
        let a = encoded & CHUNK_MASK;
        let b = (encoded >> CHUNK_B_SHIFT) & CHUNK_MASK;
        let c = (encoded >> CHUNK_C_SHIFT) & CHUNK_MASK;
        Self { a, b, c }
    }

    /// Create AND entry
    pub fn and(a: u32, b: u32) -> Self {
        Self::new(a, b, a & b)
    }

    /// Create OR entry
    pub fn or(a: u32, b: u32) -> Self {
        Self::new(a, b, a | b)
    }

    /// Create XOR entry
    pub fn xor(a: u32, b: u32) -> Self {
        Self::new(a, b, a ^ b)
    }
}

/// Multiplicity tracker for lookup tables
///
/// Tracks how many times each table entry is queried during execution
/// Uses a HashMap for sparse storage (most entries are never queried)
#[derive(Clone, Debug)]
pub struct MultiplicityTracker {
    /// Multiplicities for each encoded table entry
    /// Key = encoded value, Value = count
    pub counts: HashMap<u32, u32>,
}

impl MultiplicityTracker {
    /// Create a new tracker for 10-bit chunks
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    /// Record a lookup query
    pub fn record_lookup(&mut self, entry: BitwiseLookupEntry) {
        let encoded = entry.encode();
        *self.counts.entry(encoded).or_insert(0) += 1;
    }

    /// Get multiplicity for an entry
    pub fn get_multiplicity(&self, entry: BitwiseLookupEntry) -> u32 {
        let encoded = entry.encode();
        self.counts.get(&encoded).copied().unwrap_or(0)
    }

    /// Get all non-zero multiplicities
    pub fn get_non_zero_entries(&self) -> Vec<(BitwiseLookupEntry, u32)> {
        self.counts
            .iter()
            .map(|(&encoded, &count)| (BitwiseLookupEntry::decode(encoded), count))
            .collect()
    }

    /// Get total number of lookups
    pub fn total_lookups(&self) -> u64 {
        self.counts.values().map(|&c| c as u64).sum()
    }
}

impl Default for MultiplicityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_creation() {
        let acc = LogUpAccumulator::new();
        assert_eq!(acc.get_count(), 0);
        assert_eq!(acc.get_sum(), 0);
    }

    #[test]
    fn test_accumulator_add_lookup() {
        let mut acc = LogUpAccumulator::new();
        acc.add_lookup(12345, 67890);
        assert_eq!(acc.get_count(), 1);

        acc.add_lookup(11111, 22222);
        assert_eq!(acc.get_count(), 2);
    }

    #[test]
    fn test_lookup_entry_encoding() {
        let entry = BitwiseLookupEntry::new(0x3FF, 0x2AA, 0x155);
        let encoded = entry.encode();

        // Verify encoding: a + b*2^10 + c*2^20
        let expected = 0x3FF + (0x2AA << 10) + (0x155 << 20);
        assert_eq!(encoded, expected);

        // Verify decode
        let decoded = BitwiseLookupEntry::decode(encoded);
        assert_eq!(decoded, entry);
    }

    #[test]
    fn test_lookup_entry_and() {
        let entry = BitwiseLookupEntry::and(0b1010, 0b1100);
        assert_eq!(entry.a, 0b1010);
        assert_eq!(entry.b, 0b1100);
        assert_eq!(entry.c, 0b1000); // 1010 & 1100 = 1000
    }

    #[test]
    fn test_lookup_entry_or() {
        let entry = BitwiseLookupEntry::or(0b1010, 0b1100);
        assert_eq!(entry.a, 0b1010);
        assert_eq!(entry.b, 0b1100);
        assert_eq!(entry.c, 0b1110); // 1010 | 1100 = 1110
    }

    #[test]
    fn test_lookup_entry_xor() {
        let entry = BitwiseLookupEntry::xor(0b1010, 0b1100);
        assert_eq!(entry.a, 0b1010);
        assert_eq!(entry.b, 0b1100);
        assert_eq!(entry.c, 0b0110); // 1010 ^ 1100 = 0110
    }

    #[test]
    fn test_multiplicity_tracker() {
        let mut tracker = MultiplicityTracker::new();

        let entry1 = BitwiseLookupEntry::and(5, 3);
        let entry2 = BitwiseLookupEntry::and(5, 3); // Same as entry1
        let entry3 = BitwiseLookupEntry::and(7, 2); // Different

        tracker.record_lookup(entry1);
        tracker.record_lookup(entry2);
        tracker.record_lookup(entry3);

        assert_eq!(tracker.get_multiplicity(entry1), 2);
        assert_eq!(tracker.get_multiplicity(entry3), 1);
        assert_eq!(tracker.total_lookups(), 3);
    }

    #[test]
    fn test_multiplicity_tracker_non_zero() {
        let mut tracker = MultiplicityTracker::new();

        tracker.record_lookup(BitwiseLookupEntry::and(1, 2));
        tracker.record_lookup(BitwiseLookupEntry::and(1, 2));
        tracker.record_lookup(BitwiseLookupEntry::and(3, 4));

        let non_zero = tracker.get_non_zero_entries();
        assert_eq!(non_zero.len(), 2); // Two distinct entries

        // Verify multiplicities
        let mut found_1_2 = false;
        let mut found_3_4 = false;

        for (entry, count) in non_zero {
            if entry.a == 1 && entry.b == 2 {
                assert_eq!(count, 2);
                found_1_2 = true;
            } else if entry.a == 3 && entry.b == 4 {
                assert_eq!(count, 1);
                found_3_4 = true;
            }
        }

        assert!(found_1_2 && found_3_4, "All entries should be found");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for a in 0..10 {
            for b in 0..10 {
                for c in 0..10 {
                    let entry = BitwiseLookupEntry::new(a, b, c);
                    let encoded = entry.encode();
                    let decoded = BitwiseLookupEntry::decode(encoded);
                    assert_eq!(entry, decoded);
                }
            }
        }
    }
}
