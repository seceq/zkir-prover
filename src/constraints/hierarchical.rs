//! Hierarchical lookup table decomposition utilities
//!
//! This module provides a universal approach for decomposing values of arbitrary
//! bit widths into optimal hierarchical chunks for range checking via LogUp.
//!
//! # Hierarchical Table Sizes
//!
//! | Table | Entries | Size | Primary Use |
//! |-------|---------|------|-------------|
//! | 10-bit | 1,024 | 4 KB | Primary chunk size |
//! | 8-bit | 256 | 1 KB | Common byte operations |
//! | 4-bit | 16 | 64 B | Nibble operations |
//! | 2-bit | 4 | 16 B | Small fragments |
//! | 1-bit | N/A | 0 | Boolean constraint: x(1-x)=0 |
//!
//! # Efficiency
//!
//! Hierarchical decomposition is 4x more efficient than boolean decomposition
//! for typical carry sizes (10-13 bits). For example:
//!
//! | Approach | Columns for 13-bit | Constraints |
//! |----------|-------------------|-------------|
//! | Boolean decomposition | 13 (one per bit) | 13 boolean + 1 reconstruction |
//! | Hierarchical lookup | 3 (10 + 2 + 1) | 2 lookups + 1 boolean |
//!
//! # Usage
//!
//! ```ignore
//! // Get optimal decomposition for a 13-bit value
//! let chunks = hierarchical_decomposition(13);
//! assert_eq!(chunks, vec![10, 2, 1]);
//!
//! // Get number of columns needed
//! let columns = decomposition_column_count(13);
//! assert_eq!(columns, 3);
//! ```

use p3_air::AirBuilder;
use p3_field::FieldAlgebra;

/// Available lookup table sizes in descending order
pub const TABLE_SIZES: [usize; 4] = [10, 8, 4, 2];

/// Chunk descriptor for hierarchical decomposition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInfo {
    /// Bit width of this chunk
    pub bits: usize,
    /// Bit offset from LSB where this chunk starts
    pub offset: usize,
}

/// Result of hierarchical decomposition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HierarchicalDecomposition {
    /// Chunks in order from LSB to MSB
    pub chunks: Vec<ChunkInfo>,
    /// Total bit width being decomposed
    pub total_bits: usize,
    /// Number of 1-bit boolean chunks (at the end)
    pub boolean_bits: usize,
}

impl HierarchicalDecomposition {
    /// Number of auxiliary columns needed for this decomposition
    pub fn column_count(&self) -> usize {
        self.chunks.len()
    }

    /// Number of LogUp lookups needed (excludes 1-bit booleans)
    pub fn lookup_count(&self) -> usize {
        self.chunks.iter().filter(|c| c.bits > 1).count()
    }

    /// Number of boolean constraints needed (1-bit chunks)
    pub fn boolean_count(&self) -> usize {
        self.boolean_bits
    }

    /// Get shift multiplier for a chunk (2^offset)
    pub fn chunk_shift(&self, chunk_idx: usize) -> u64 {
        1u64 << self.chunks[chunk_idx].offset
    }
}

/// Compute optimal hierarchical decomposition for a value of N bits
///
/// Returns the decomposition as a list of chunk sizes from LSB to MSB.
///
/// # Algorithm
///
/// Greedily selects the largest available table that fits the remaining bits:
/// - 10-bit for ≥10 remaining
/// - 8-bit for ≥8 remaining
/// - 4-bit for ≥4 remaining
/// - 2-bit for ≥2 remaining
/// - 1-bit (boolean) for remaining 1 bit
///
/// # Examples
///
/// ```ignore
/// hierarchical_decomposition(20) // [10, 10]
/// hierarchical_decomposition(17) // [10, 4, 2, 1]
/// hierarchical_decomposition(13) // [10, 2, 1]
/// hierarchical_decomposition(7)  // [4, 2, 1]
/// hierarchical_decomposition(1)  // [1] (boolean only)
/// ```
pub fn hierarchical_decomposition(bits: usize) -> HierarchicalDecomposition {
    let mut remaining = bits;
    let mut chunks = Vec::new();
    let mut offset = 0;
    let mut boolean_bits = 0;

    while remaining > 0 {
        // Find the largest table that fits
        let chunk_bits = TABLE_SIZES
            .iter()
            .find(|&&size| remaining >= size)
            .copied()
            .unwrap_or(1); // Fall back to 1-bit boolean

        if chunk_bits == 1 {
            boolean_bits += 1;
        }

        chunks.push(ChunkInfo {
            bits: chunk_bits,
            offset,
        });

        offset += chunk_bits;
        remaining -= chunk_bits;
    }

    HierarchicalDecomposition {
        chunks,
        total_bits: bits,
        boolean_bits,
    }
}

/// Get the number of auxiliary columns needed for a given bit width
pub fn decomposition_column_count(bits: usize) -> usize {
    hierarchical_decomposition(bits).column_count()
}

/// Get the decomposition as a simple list of chunk sizes
pub fn decomposition_sizes(bits: usize) -> Vec<usize> {
    hierarchical_decomposition(bits)
        .chunks
        .iter()
        .map(|c| c.bits)
        .collect()
}

/// Build reconstruction expression: value = Σ(chunk_i * 2^offset_i)
///
/// This constraint ensures the chunks correctly reconstruct the original value.
pub fn reconstruction_constraint<AB: AirBuilder>(
    decomposition: &HierarchicalDecomposition,
    chunk_values: &[AB::Expr],
) -> AB::Expr {
    assert_eq!(
        chunk_values.len(),
        decomposition.chunks.len(),
        "Chunk count mismatch"
    );

    let mut reconstructed = AB::Expr::ZERO;

    for (i, chunk_info) in decomposition.chunks.iter().enumerate() {
        let shift = AB::F::from_canonical_u64(1u64 << chunk_info.offset);
        reconstructed = reconstructed + chunk_values[i].clone() * shift;
    }

    reconstructed
}

/// Apply boolean constraints for 1-bit chunks: x * (1 - x) = 0
///
/// This ensures each 1-bit chunk is actually boolean (0 or 1).
pub fn apply_boolean_constraints<AB: AirBuilder>(
    builder: &mut AB,
    decomposition: &HierarchicalDecomposition,
    chunk_values: &[AB::Expr],
    selector: AB::Expr,
) {
    for (i, chunk_info) in decomposition.chunks.iter().enumerate() {
        if chunk_info.bits == 1 {
            let x = chunk_values[i].clone();
            // x * (1 - x) = 0 ensures x ∈ {0, 1}
            builder.assert_zero(selector.clone() * x.clone() * (AB::Expr::ONE - x));
        }
    }
}

/// Get the lookup table index for a chunk size
///
/// Returns which table to use for LogUp:
/// - 0 = 10-bit table (1024 entries)
/// - 1 = 8-bit table (256 entries)
/// - 2 = 4-bit table (16 entries)
/// - 3 = 2-bit table (4 entries)
/// - None = 1-bit (use boolean constraint, no lookup)
pub fn table_index_for_bits(bits: usize) -> Option<usize> {
    match bits {
        10 => Some(0),
        8 => Some(1),
        4 => Some(2),
        2 => Some(3),
        1 => None, // Boolean constraint, no lookup
        _ => panic!("Invalid chunk size: {} (must be 10, 8, 4, 2, or 1)", bits),
    }
}

/// Decompose a concrete value into chunks according to the hierarchical scheme
///
/// Used in witness generation to compute the chunk values.
pub fn decompose_value(value: u64, bits: usize) -> Vec<u64> {
    let decomposition = hierarchical_decomposition(bits);
    let mut chunks = Vec::with_capacity(decomposition.chunks.len());

    for chunk_info in &decomposition.chunks {
        let mask = (1u64 << chunk_info.bits) - 1;
        let chunk_value = (value >> chunk_info.offset) & mask;
        chunks.push(chunk_value);
    }

    chunks
}

/// Verify that chunks correctly reconstruct a value (for testing)
pub fn verify_decomposition(value: u64, bits: usize, chunks: &[u64]) -> bool {
    let decomposition = hierarchical_decomposition(bits);
    if chunks.len() != decomposition.chunks.len() {
        return false;
    }

    let mut reconstructed = 0u64;
    for (i, chunk_info) in decomposition.chunks.iter().enumerate() {
        reconstructed += chunks[i] << chunk_info.offset;
    }

    reconstructed == value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decomposition_20_bits() {
        let d = hierarchical_decomposition(20);
        assert_eq!(d.total_bits, 20);
        assert_eq!(d.chunks.len(), 2);
        assert_eq!(d.chunks[0].bits, 10);
        assert_eq!(d.chunks[0].offset, 0);
        assert_eq!(d.chunks[1].bits, 10);
        assert_eq!(d.chunks[1].offset, 10);
        assert_eq!(d.boolean_bits, 0);
    }

    #[test]
    fn test_decomposition_17_bits() {
        let d = hierarchical_decomposition(17);
        assert_eq!(d.total_bits, 17);
        let sizes: Vec<_> = d.chunks.iter().map(|c| c.bits).collect();
        assert_eq!(sizes, vec![10, 4, 2, 1]);
        assert_eq!(d.boolean_bits, 1);
    }

    #[test]
    fn test_decomposition_13_bits() {
        let d = hierarchical_decomposition(13);
        let sizes: Vec<_> = d.chunks.iter().map(|c| c.bits).collect();
        assert_eq!(sizes, vec![10, 2, 1]);
        assert_eq!(d.boolean_bits, 1);
        assert_eq!(d.lookup_count(), 2); // 10-bit + 2-bit
        assert_eq!(d.boolean_count(), 1); // 1-bit
    }

    #[test]
    fn test_decomposition_12_bits() {
        let d = hierarchical_decomposition(12);
        let sizes: Vec<_> = d.chunks.iter().map(|c| c.bits).collect();
        assert_eq!(sizes, vec![10, 2]);
        assert_eq!(d.boolean_bits, 0);
    }

    #[test]
    fn test_decomposition_11_bits() {
        let d = hierarchical_decomposition(11);
        let sizes: Vec<_> = d.chunks.iter().map(|c| c.bits).collect();
        assert_eq!(sizes, vec![10, 1]);
        assert_eq!(d.boolean_bits, 1);
    }

    #[test]
    fn test_decomposition_7_bits() {
        let d = hierarchical_decomposition(7);
        let sizes: Vec<_> = d.chunks.iter().map(|c| c.bits).collect();
        assert_eq!(sizes, vec![4, 2, 1]);
        assert_eq!(d.boolean_bits, 1);
    }

    #[test]
    fn test_decomposition_1_bit() {
        let d = hierarchical_decomposition(1);
        assert_eq!(d.chunks.len(), 1);
        assert_eq!(d.chunks[0].bits, 1);
        assert_eq!(d.boolean_bits, 1);
        assert_eq!(d.lookup_count(), 0);
    }

    #[test]
    fn test_decomposition_column_count() {
        assert_eq!(decomposition_column_count(20), 2);
        assert_eq!(decomposition_column_count(17), 4);
        assert_eq!(decomposition_column_count(13), 3);
        assert_eq!(decomposition_column_count(12), 2);
        assert_eq!(decomposition_column_count(7), 3);
        assert_eq!(decomposition_column_count(1), 1);
    }

    #[test]
    fn test_decompose_value_20_bits() {
        let value = 0b11111111110000000001u64; // 1,047,553
        let chunks = decompose_value(value, 20);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], 1); // Low 10 bits
        assert_eq!(chunks[1], 1023); // High 10 bits
        assert!(verify_decomposition(value, 20, &chunks));
    }

    #[test]
    fn test_decompose_value_13_bits() {
        let value = 0b1_01_1111111111u64; // 5119
        let chunks = decompose_value(value, 13);
        assert_eq!(chunks.len(), 3); // 10 + 2 + 1
        assert_eq!(chunks[0], 1023); // Low 10 bits: all 1s
        assert_eq!(chunks[1], 1); // Next 2 bits: 01
        assert_eq!(chunks[2], 1); // Top 1 bit: 1
        assert!(verify_decomposition(value, 13, &chunks));
    }

    #[test]
    fn test_decompose_value_exhaustive() {
        // Test all values for small bit widths
        for bits in 1..=10 {
            let max_value = (1u64 << bits) - 1;
            for value in 0..=max_value {
                let chunks = decompose_value(value, bits);
                assert!(
                    verify_decomposition(value, bits, &chunks),
                    "Failed for value {} with {} bits",
                    value,
                    bits
                );
            }
        }
    }

    #[test]
    fn test_offsets_correct() {
        let d = hierarchical_decomposition(17);
        assert_eq!(d.chunks[0].offset, 0); // 10-bit starts at 0
        assert_eq!(d.chunks[1].offset, 10); // 4-bit starts at 10
        assert_eq!(d.chunks[2].offset, 14); // 2-bit starts at 14
        assert_eq!(d.chunks[3].offset, 16); // 1-bit starts at 16
    }

    #[test]
    fn test_table_index() {
        assert_eq!(table_index_for_bits(10), Some(0));
        assert_eq!(table_index_for_bits(8), Some(1));
        assert_eq!(table_index_for_bits(4), Some(2));
        assert_eq!(table_index_for_bits(2), Some(3));
        assert_eq!(table_index_for_bits(1), None);
    }

    #[test]
    fn test_chunk_shift() {
        let d = hierarchical_decomposition(17);
        assert_eq!(d.chunk_shift(0), 1); // 2^0
        assert_eq!(d.chunk_shift(1), 1024); // 2^10
        assert_eq!(d.chunk_shift(2), 16384); // 2^14
        assert_eq!(d.chunk_shift(3), 65536); // 2^16
    }

    #[test]
    fn test_various_bit_widths() {
        // Test MUL carry sizes
        assert_eq!(decomposition_sizes(10), vec![10]); // Position 0 carry
        assert_eq!(decomposition_sizes(11), vec![10, 1]); // Position 1 carry
        assert_eq!(decomposition_sizes(12), vec![10, 2]); // Position 2 carry
        assert_eq!(decomposition_sizes(13), vec![10, 2, 1]); // Position 3 carry

        // Test shift carry sizes (variable k)
        assert_eq!(decomposition_sizes(1), vec![1]); // k=1
        assert_eq!(decomposition_sizes(3), vec![2, 1]); // k=3
        assert_eq!(decomposition_sizes(5), vec![4, 1]); // k=5
        assert_eq!(decomposition_sizes(6), vec![4, 2]); // k=6

        // Test full limb (20-bit)
        assert_eq!(decomposition_sizes(20), vec![10, 10]);

        // Test larger values (40-bit for 2-limb)
        assert_eq!(decomposition_sizes(40), vec![10, 10, 10, 10]);
    }
}
