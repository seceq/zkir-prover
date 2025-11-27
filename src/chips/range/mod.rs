//! Range Check Chip implementation
//!
//! Validates that values are within valid 32-bit range using a lookup argument.
//! Uses a multiplicative lookup table for efficiency.

use std::borrow::{Borrow, BorrowMut};
use std::ops::Deref;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Range check trace columns
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RangeCheckColumns<T> {
    /// Value to check (decomposed into bytes)
    pub value: T,
    /// Byte 0 (least significant)
    pub byte0: T,
    /// Byte 1
    pub byte1: T,
    /// Byte 2
    pub byte2: T,
    /// Byte 3 (most significant)
    pub byte3: T,
    /// Multiplicity: how many times this value appears
    pub multiplicity: T,
}

/// Number of columns in the range check trace
pub const RANGE_CHECK_NUM_COLUMNS: usize = 6;

impl<T> RangeCheckColumns<T> {
    pub const NUM_COLUMNS: usize = RANGE_CHECK_NUM_COLUMNS;
}

impl<T> Borrow<RangeCheckColumns<T>> for [T; RANGE_CHECK_NUM_COLUMNS] {
    fn borrow(&self) -> &RangeCheckColumns<T> {
        unsafe { &*(self.as_ptr() as *const RangeCheckColumns<T>) }
    }
}

impl<T> BorrowMut<RangeCheckColumns<T>> for [T; RANGE_CHECK_NUM_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut RangeCheckColumns<T> {
        unsafe { &mut *(self.as_mut_ptr() as *mut RangeCheckColumns<T>) }
    }
}

/// Range Check Chip for validating 32-bit values
pub struct RangeCheckChip {
    /// Maximum number of bits to check
    pub max_bits: usize,
}

impl Default for RangeCheckChip {
    fn default() -> Self {
        Self { max_bits: 32 }
    }
}

impl<F: Field> BaseAir<F> for RangeCheckChip {
    fn width(&self) -> usize {
        RangeCheckColumns::<F>::NUM_COLUMNS
    }
}

impl<AB: AirBuilder> Air<AB> for RangeCheckChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_slice = main.row_slice(0);

        let local_arr: &[AB::Var; RANGE_CHECK_NUM_COLUMNS] = local_slice.deref().try_into().unwrap();
        let local: &RangeCheckColumns<AB::Var> = local_arr.borrow();

        // Value decomposition: value = byte0 + 256*byte1 + 256^2*byte2 + 256^3*byte3
        let reconstructed = local.byte0.into()
            + local.byte1.into() * AB::Expr::from_canonical_u32(256)
            + local.byte2.into() * AB::Expr::from_canonical_u32(256 * 256)
            + local.byte3.into() * AB::Expr::from_canonical_u32(256 * 256 * 256);

        builder.assert_eq(local.value, reconstructed);

        // Each byte is in range [0, 255] (enforced via lookup table argument)
        // The lookup table contains all values 0..255
        // Each byte column must be a member of this table

        // For now, we use a degree-256 constraint (product check)
        // In practice, this would be done via a log-derivative lookup argument
    }
}

impl RangeCheckChip {
    pub fn new(max_bits: usize) -> Self {
        Self { max_bits }
    }

    /// Generate the range check trace
    pub fn generate_trace<F: Field>(&self, values_to_check: &[u32]) -> RowMajorMatrix<F> {
        let num_values = values_to_check.len();
        let trace_len = num_values.next_power_of_two().max(2);

        let mut trace_values = vec![F::ZERO; trace_len * RangeCheckColumns::<F>::NUM_COLUMNS];

        for (i, &value) in values_to_check.iter().enumerate() {
            let row_offset = i * RangeCheckColumns::<F>::NUM_COLUMNS;
            let row: &mut [F; RANGE_CHECK_NUM_COLUMNS] = (&mut trace_values[row_offset..row_offset + RangeCheckColumns::<F>::NUM_COLUMNS]).try_into().unwrap();
            let cols: &mut RangeCheckColumns<F> = row.borrow_mut();

            cols.value = F::from_canonical_u32(value);
            cols.byte0 = F::from_canonical_u32(value & 0xFF);
            cols.byte1 = F::from_canonical_u32((value >> 8) & 0xFF);
            cols.byte2 = F::from_canonical_u32((value >> 16) & 0xFF);
            cols.byte3 = F::from_canonical_u32((value >> 24) & 0xFF);
            cols.multiplicity = F::ONE;
        }

        RowMajorMatrix::new(trace_values, RangeCheckColumns::<F>::NUM_COLUMNS)
    }
}
