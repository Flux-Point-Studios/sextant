//! Sextant — read-path verifying Cardano client.
//!
//! Decodes and (in later slices) verifies chain data on its own code path.
//! Byte providers supply input; Sextant never trusts them for a verdict.

pub mod header;
