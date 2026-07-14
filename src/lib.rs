//! Sextant — read-path verifying Cardano client.
//!
//! Decodes and (in later slices) verifies chain data on its own code path.
//! Byte providers supply input; Sextant never trusts them for a verdict.
//!
//! Default build is `std`; `--no-default-features` gives a `no_std + alloc`
//! graph for zkVM guests and other bare-metal consumers (rv32im-class targets;
//! `tools/guest-canary` is the compile gate). The C ABI (`ffi`) is host-only.
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

pub mod ancillary;
pub mod chain;
mod curve;
pub mod ed25519;
pub mod effects;
#[cfg(feature = "std")]
pub mod ffi;
pub mod follow;
mod hash;
pub mod header;
pub mod inclusion;
pub mod kes;
#[cfg(feature = "mithril")]
pub mod mithril;
pub mod nonce;
pub mod setfollow;
pub mod utxo;
pub mod utxoset;
pub mod vrf;
pub mod window;
