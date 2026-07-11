//! Ed25519 signature verification (RFC 8032 / EdDSA) on Sextant's own code
//! path, matching libsodium's `crypto_sign_ed25519_verify_detached` — the
//! producer of every Cardano signature this library checks.
//!
//! The accept/reject boundary is libsodium's default (strict cofactorless) row:
//! the cofactorless equation `[S]B = R + [k]A`, a canonical response scalar
//! `S < L`, and a canonical, non-small-order public key. Cardano's operational
//! certificate — and the KES leaf signatures a later slice adds — are plain
//! Ed25519 over raw messages (no pre-hashing), so this is the one primitive
//! both verdicts rest on.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::curve::decode_point;

/// Verify a detached Ed25519 signature `sig = R‖S` over `msg` under `pubkey`.
///
/// Mirrors libsodium's default verify: `k = SHA-512(R‖A‖M) mod L`, accept iff
/// `S·B − k·A` re-encodes to the exact `R` bytes. Rejects a non-canonical
/// `S ≥ L` (the `s + L` malleation), a non-canonical or small-order public key,
/// and any non-canonical `R` (the recomputed point's canonical encoding cannot
/// equal non-canonical `R` bytes). A canonical producer's signature always
/// passes; only adversarial encodings are turned away.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let a = match decode_point(pubkey) {
        Some(p) if !p.is_small_order() => p,
        _ => return false,
    };

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let s = match Scalar::from_canonical_bytes(s_bytes) {
        Some(s) => s,
        None => return false,
    };

    let hash = Sha512::new()
        .chain(&sig[..32]) // R
        .chain(&pubkey[..]) // A
        .chain(msg)
        .finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    let k = Scalar::from_bytes_mod_order_wide(&wide);

    // R' = S·B − k·A, the point the signer committed to as R.
    let r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-k), &a, &s);
    r.compress().as_bytes() == &sig[..32]
}
