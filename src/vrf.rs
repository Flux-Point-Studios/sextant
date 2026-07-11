//! Praos leader-election VRF (ECVRF-ED25519-SHA512-Elligator2, IETF draft-03 —
//! libsodium's `crypto_vrf_ietfdraft03`) on Sextant's own code path.
//!
//! This slice implements `proof_to_hash`: recomputing the 64-byte VRF output
//! (beta) from the 80-byte proof. It is nonce-independent — beta depends only
//! on the proof's Gamma point — so every real block's committed `vrf_output`
//! can be checked against it with no epoch nonce. The full alpha-binding
//! verify (which binds slot + epoch nonce and needs `hash_to_curve`) is a
//! later slice.

use cryptoxide::curve25519::Ge;
use cryptoxide::hashing::sha2::Sha512;

/// draft-03 suite string for ECVRF-ED25519-SHA512-Elligator2.
const SUITE: u8 = 0x04;
/// Domain-separation tag for `proof_to_hash` (draft-03 "THREE").
const THREE: u8 = 0x03;

/// Why a VRF operation failed. Byte providers are untrusted, so a malformed
/// proof is an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VrfError {
    /// The proof's Gamma component is not a valid Edwards curve point.
    InvalidGamma,
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VrfError::InvalidGamma => f.write_str("VRF proof Gamma is not a valid curve point"),
        }
    }
}

impl std::error::Error for VrfError {}

/// Recompute the 64-byte VRF output (beta) from an 80-byte draft-03 proof:
///
/// `beta = SHA-512( 0x04 || 0x03 || encode(8 * Gamma) )`
///
/// where `Gamma` is the first 32 bytes of the proof (a compressed Edwards
/// point) and `8 * Gamma` clears the cofactor. This is exactly libsodium's
/// `crypto_vrf_ietfdraft03_proof_to_hash`, so on a valid block the result
/// equals the `vrf_output` the producer committed on-chain.
pub fn proof_to_hash(proof: &[u8; 80]) -> Result<[u8; 64], VrfError> {
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&proof[..32]);

    // cryptoxide's `Ge::from_bytes` follows ref10's *negated* decode
    // (`ge25519_frombytes_negate_vartime`, what Ed25519 verification consumes)
    // and returns −P. ECVRF needs the true point P, so negate it back.
    let neg_gamma = Ge::from_bytes(&gamma_bytes).ok_or(VrfError::InvalidGamma)?;
    let gamma = (&Ge::ZERO - &neg_gamma.to_cached()).to_full();

    // Clear the cofactor: 8 * Gamma = three point doublings.
    let cofactor_gamma = gamma.double().double().double().to_bytes();

    let beta = Sha512::new()
        .update(&[SUITE, THREE])
        .update(&cofactor_gamma)
        .finalize();
    Ok(beta)
}
