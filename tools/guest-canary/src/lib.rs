//! no_std consumption canary for the sextant default graph. Each shim touches a
//! verify entry point so the whole path (types + bodies) must compile for the
//! bare-metal rv32im target; none of them is meant to be *called* here.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// Praos header-segment verification (chain -> header -> opcert/VRF/KES).
pub fn segment(blocks: &[Vec<u8>], eta0: &[u8; 32]) -> bool {
    sextant::chain::verify_segment(blocks, eta0).is_ok()
}

/// Certified-transaction inclusion (MKMapProof/MMR recompute).
pub fn inclusion(proof_hex: &[u8], tx: &[u8; 32], root: &[u8; 32]) -> bool {
    sextant::inclusion::verify_tx_inclusion(proof_hex, tx, root).is_ok()
}

/// Nonce evolution primitives (epoch-nonce derivation).
pub fn nonce(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    sextant::nonce::combine(a, b)
}
