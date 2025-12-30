//! LogUp multiplicity tracking for lookup tables
//!
//! This module tracks how many times each table entry is queried during execution,
//! which is needed to compute the table-side LogUp accumulators.

use std::collections::HashMap;

/// Multiplicity tracker for a single lookup table
///
/// Tracks how many times each encoded entry is queried during execution.
/// For bitwise operations: encode(a, b, c) = a + b*2^10 + c*2^20
/// For range checks: encode(value) = value
#[derive(Clone, Debug)]
pub struct MultiplicityTracker {
    /// Map from encoded entry to count
    multiplicities: HashMap<u32, u32>,
}

impl MultiplicityTracker {
    /// Create a new empty tracker
    pub fn new() -> Self {
        Self {
            multiplicities: HashMap::new(),
        }
    }

    /// Record a query for an encoded entry
    pub fn record_query(&mut self, encoded_entry: u32) {
        *self.multiplicities.entry(encoded_entry).or_insert(0) += 1;
    }

    /// Get the multiplicity for an encoded entry (0 if never queried)
    pub fn get_multiplicity(&self, encoded_entry: u32) -> u32 {
        self.multiplicities.get(&encoded_entry).copied().unwrap_or(0)
    }

    /// Get all entries with non-zero multiplicity
    pub fn non_zero_entries(&self) -> Vec<(u32, u32)> {
        self.multiplicities.iter().map(|(&k, &v)| (k, v)).collect()
    }

    /// Total number of queries (sum of all multiplicities)
    pub fn total_queries(&self) -> u32 {
        self.multiplicities.values().sum()
    }

    /// Number of distinct entries queried
    pub fn distinct_entries(&self) -> usize {
        self.multiplicities.len()
    }
}

impl Default for MultiplicityTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Multiplicity trackers for all lookup tables
#[derive(Clone, Debug, Default)]
pub struct LogUpMultiplicities {
    /// AND operation lookups
    pub and_table: MultiplicityTracker,
    /// OR operation lookups
    pub or_table: MultiplicityTracker,
    /// XOR operation lookups
    pub xor_table: MultiplicityTracker,
    /// Range check lookups
    pub range_table: MultiplicityTracker,
}

impl LogUpMultiplicities {
    /// Create new multiplicity trackers
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a bitwise AND lookup
    ///
    /// # Arguments
    /// * `a` - First operand chunk
    /// * `b` - Second operand chunk
    /// * `c` - Result chunk (should be a & b)
    /// * `chunk_bits` - Chunk size in bits (default: 10)
    pub fn record_and(&mut self, a: u32, b: u32, c: u32, chunk_bits: u32) {
        let encoded = encode_bitwise_triple(a, b, c, chunk_bits);
        self.and_table.record_query(encoded);
    }

    /// Record a bitwise OR lookup
    pub fn record_or(&mut self, a: u32, b: u32, c: u32, chunk_bits: u32) {
        let encoded = encode_bitwise_triple(a, b, c, chunk_bits);
        self.or_table.record_query(encoded);
    }

    /// Record a bitwise XOR lookup
    pub fn record_xor(&mut self, a: u32, b: u32, c: u32, chunk_bits: u32) {
        let encoded = encode_bitwise_triple(a, b, c, chunk_bits);
        self.xor_table.record_query(encoded);
    }

    /// Record a range check lookup
    ///
    /// # Arguments
    /// * `value` - The chunk value being range checked
    pub fn record_range_check(&mut self, value: u32) {
        self.range_table.record_query(value);
    }

    /// Print statistics about multiplicities
    pub fn print_stats(&self) {
        println!("LogUp Multiplicity Statistics:");
        println!("  AND:   {} queries, {} distinct entries",
            self.and_table.total_queries(),
            self.and_table.distinct_entries());
        println!("  OR:    {} queries, {} distinct entries",
            self.or_table.total_queries(),
            self.or_table.distinct_entries());
        println!("  XOR:   {} queries, {} distinct entries",
            self.xor_table.total_queries(),
            self.xor_table.distinct_entries());
        println!("  Range: {} queries, {} distinct entries",
            self.range_table.total_queries(),
            self.range_table.distinct_entries());
    }
}

/// Encode a bitwise operation triple (a, b, c) into a single value
///
/// Encoding: encode(a, b, c) = a + b*2^chunk_bits + c*2^(2*chunk_bits)
///
/// For 10-bit chunks: encode(a, b, c) = a + b*1024 + c*1048576
/// This packs three 10-bit values into a single 30-bit value.
pub fn encode_bitwise_triple(a: u32, b: u32, c: u32, chunk_bits: u32) -> u32 {
    let shift_1 = 1u32 << chunk_bits;
    let shift_2 = 1u32 << (2 * chunk_bits);
    a + b * shift_1 + c * shift_2
}

/// Decode a bitwise triple back to (a, b, c)
pub fn decode_bitwise_triple(encoded: u32, chunk_bits: u32) -> (u32, u32, u32) {
    let mask = (1u32 << chunk_bits) - 1;
    let a = encoded & mask;
    let b = (encoded >> chunk_bits) & mask;
    let c = (encoded >> (2 * chunk_bits)) & mask;
    (a, b, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplicity_tracker_basic() {
        let mut tracker = MultiplicityTracker::new();

        // No queries yet
        assert_eq!(tracker.get_multiplicity(42), 0);
        assert_eq!(tracker.total_queries(), 0);

        // Record some queries
        tracker.record_query(42);
        assert_eq!(tracker.get_multiplicity(42), 1);

        tracker.record_query(42);
        assert_eq!(tracker.get_multiplicity(42), 2);

        tracker.record_query(100);
        assert_eq!(tracker.get_multiplicity(100), 1);

        // Check totals
        assert_eq!(tracker.total_queries(), 3);
        assert_eq!(tracker.distinct_entries(), 2);
    }

    #[test]
    fn test_encode_decode_bitwise() {
        let chunk_bits = 10;

        // Test encoding
        let encoded = encode_bitwise_triple(5, 3, 1, chunk_bits);
        assert_eq!(encoded, 5 + 3 * 1024 + 1 * 1048576);

        // Test decoding
        let (a, b, c) = decode_bitwise_triple(encoded, chunk_bits);
        assert_eq!(a, 5);
        assert_eq!(b, 3);
        assert_eq!(c, 1);
    }

    #[test]
    fn test_encode_decode_max_values() {
        let chunk_bits = 10;
        let max_chunk = (1u32 << chunk_bits) - 1; // 1023 for 10-bit

        let encoded = encode_bitwise_triple(max_chunk, max_chunk, max_chunk, chunk_bits);
        let (a, b, c) = decode_bitwise_triple(encoded, chunk_bits);

        assert_eq!(a, max_chunk);
        assert_eq!(b, max_chunk);
        assert_eq!(c, max_chunk);
    }

    #[test]
    fn test_logup_multiplicities() {
        let mut mults = LogUpMultiplicities::new();

        // Record some AND operations
        mults.record_and(5, 3, 1, 10); // 0101 & 0011 = 0001
        mults.record_and(5, 3, 1, 10); // Same query again
        mults.record_and(15, 10, 10, 10); // 1111 & 1010 = 1010

        assert_eq!(mults.and_table.total_queries(), 3);
        assert_eq!(mults.and_table.distinct_entries(), 2);

        // Record some range checks
        mults.record_range_check(42);
        mults.record_range_check(100);
        mults.record_range_check(42); // Duplicate

        assert_eq!(mults.range_table.total_queries(), 3);
        assert_eq!(mults.range_table.distinct_entries(), 2);
    }

    #[test]
    fn test_bitwise_operation_correctness() {
        let mut mults = LogUpMultiplicities::new();

        // Verify AND encoding is correct
        let a = 0b1010u32;
        let b = 0b1100u32;
        let c = a & b; // 0b1000

        mults.record_and(a, b, c, 10);

        let encoded = encode_bitwise_triple(a, b, c, 10);
        let (decoded_a, decoded_b, decoded_c) = decode_bitwise_triple(encoded, 10);

        assert_eq!(decoded_a, a);
        assert_eq!(decoded_b, b);
        assert_eq!(decoded_c, c);
        assert_eq!(decoded_c, decoded_a & decoded_b);
    }
}
