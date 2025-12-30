//! Column layout constants and indices for ZKIR v3.4 traces
//!
//! This module provides named constants for column group sizes and a `ColumnIndices`
//! struct that pre-computes all column offsets at initialization time.
//!
//! # Usage
//!
//! ```ignore
//! use zkir_prover::columns::{ColumnIndices, constants};
//! use zkir_prover::types::Config;
//!
//! let config = Config::DEFAULT;
//! let indices = ColumnIndices::new(&config);
//!
//! // Access columns by pre-computed indices
//! let pc_col = indices.pc;
//! let r5_limb0 = indices.register(5, 0);
//! ```

pub mod constants;
mod indices;

pub use constants::*;
pub use indices::ColumnIndices;
