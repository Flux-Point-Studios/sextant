//! Shared Blake2b-256 primitive for the verify paths.

use blake2::VarBlake2b;
use blake2::digest::{Update, VariableOutput};

/// Blake2b with a 32-byte digest — Cardano's `Blake2b_256`. Used by the Praos
/// VRF input (`BE64(slot) ‖ eta0`) and the KES vk hash tree (`vk0 ‖ vk1`).
pub(crate) fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = VarBlake2b::new(32).expect("32 is a valid Blake2b output length");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(|res| out.copy_from_slice(res));
    out
}
