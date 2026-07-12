//! Shared Blake2 primitives for the verify paths.

use blake2::digest::{Update, VariableOutput};
use blake2::{VarBlake2b, VarBlake2s};

/// Blake2b with a 32-byte digest — Cardano's `Blake2b_256`. Used by the Praos
/// VRF input (`BE64(slot) ‖ eta0`) and the KES vk hash tree (`vk0 ‖ vk1`).
pub(crate) fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = VarBlake2b::new(32).expect("32 is a valid Blake2b output length");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(|res| out.copy_from_slice(res));
    out
}

/// Blake2s with a 32-byte digest — the node/leaf merge of mithril's Cardano-
/// transactions Merkle-Mountain-Range (`MergeMKTreeNode`). Used by the inclusion
/// verifier to recompute a certified transaction root.
pub(crate) fn blake2s256(data: &[u8]) -> [u8; 32] {
    let mut h = VarBlake2s::new(32).expect("32 is a valid Blake2s output length");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(|res| out.copy_from_slice(res));
    out
}
