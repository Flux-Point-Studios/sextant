//! Sextant — read-path verifying Cardano client.
//!
//! Decodes and (in later slices) verifies chain data on its own code path.
//! Byte providers supply input; Sextant never trusts them for a verdict.

mod curve;
pub mod ed25519;
pub mod header;
pub mod kes;
pub mod vrf;
