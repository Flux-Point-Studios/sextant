//! Praos epoch-nonce evolution (Ouroboros Praos, Babbage+) on Sextant's own path.
//!
//! The nonce machinery is three byte-level primitives, each differentially
//! checked against pallas-crypto's independent implementation and its golden
//! vectors:
//!
//! * [`combine`] — the Praos nonce-combine `⭒`: `Blake2b256(a ‖ b)`, left 32
//!   bytes then right 32. It is both the rolling-fold step and the
//!   epoch-boundary combine, and it is not commutative.
//! * [`block_nonce_contribution`] — one applied block's contribution to the
//!   rolling nonce, `Blake2b256(Blake2b256(0x4E ‖ vrf_output))`. Both the `0x4E`
//!   domain tag and the *double* hash are the Praos-specific shape; the legacy
//!   TPraos rolling nonce omits them.
//! * [`evolve`] — fold one applied block in: `η_v' = η_v ⭒ contribution`.
//!
//! [`epoch_nonce`] is the epoch-boundary value `η0(e+1) = candidate ⭒
//! prevHashNonce`, folding a 32-byte extra-entropy nonce the same way when the
//! protocol sets one (neutral extra entropy is the identity — pass `None`).

use crate::hash::blake2b256;

/// Praos per-block nonce domain-separation tag (ASCII `'N'`), prepended to the
/// VRF output before the inner hash.
const NONCE_TAG: u8 = 0x4E;

/// The Praos nonce-combine `⭒`: `Blake2b256(a ‖ b)`. Left-associative when
/// folded; argument order is load-bearing (not commutative).
pub fn combine(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2b256(&buf)
}

/// One applied block's contribution to the rolling nonce:
/// `Blake2b256(Blake2b256(0x4E ‖ vrf_output))`, where `vrf_output` is the
/// certified 64-byte Praos VRF output on `HeaderView.vrf_output`.
pub fn block_nonce_contribution(vrf_output: &[u8; 64]) -> [u8; 32] {
    let mut tagged = [0u8; 65];
    tagged[0] = NONCE_TAG;
    tagged[1..].copy_from_slice(vrf_output);
    blake2b256(&blake2b256(&tagged))
}

/// Fold one applied block into the rolling nonce `η_v`:
/// `η_v' = η_v ⭒ block_nonce_contribution(vrf_output)`.
pub fn evolve(eta_v: &[u8; 32], vrf_output: &[u8; 64]) -> [u8; 32] {
    combine(eta_v, &block_nonce_contribution(vrf_output))
}

/// The epoch-boundary nonce `η0(e+1) = candidate ⭒ prevHashNonce`, folding a
/// 32-byte `extra_entropy` nonce on top when the protocol sets one. `None` is
/// neutral extra entropy — the identity — matching cardano-ledger's
/// short-circuit and pallas's `generate_epoch_nonce`.
pub fn epoch_nonce(
    candidate: &[u8; 32],
    prev_hash_nonce: &[u8; 32],
    extra_entropy: Option<&[u8; 32]>,
) -> [u8; 32] {
    let base = combine(candidate, prev_hash_nonce);
    match extra_entropy {
        Some(ee) => combine(&base, ee),
        None => base,
    }
}
