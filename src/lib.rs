//! Sextant — read-path verifying Cardano client.
//!
//! Decodes and (in later slices) verifies chain data on its own code path.
//! Byte providers supply input; Sextant never trusts them for a verdict.

pub mod chain;
mod curve;
pub mod ed25519;
pub mod ffi;
mod hash;
pub mod header;
pub mod inclusion;
pub mod kes;
#[cfg(feature = "mithril")]
pub mod mithril;
pub mod nonce;
pub mod utxo;
pub mod vrf;
pub mod window;
