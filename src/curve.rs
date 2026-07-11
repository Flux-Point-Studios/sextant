//! Shared curve25519 decode primitive for the verify paths.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

/// Decode a compressed Edwards point, returning `None` for off-curve or
/// non-canonical encodings. libsodium's `ge25519_is_canonical` rejects a
/// y-coordinate `≥ p`, but dalek's `decompress` silently accepts it, so we
/// enforce canonicity by requiring the point to re-compress to the exact input
/// bytes. A canonical producer never emits a non-canonical encoding, so this
/// only ever rejects adversarial bytes, never a real block. Shared by the VRF
/// (Gamma / VRF key) and Ed25519 (public key) verifiers.
pub(crate) fn decode_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    let compressed = CompressedEdwardsY::from_slice(bytes);
    let point = compressed.decompress()?;
    (point.compress() == compressed).then_some(point)
}
